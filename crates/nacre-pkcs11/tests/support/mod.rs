#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // Each test binary uses part of this module.
    dead_code
)]

//! A fresh SoftHSM token per test. SoftHSM reads `SOFTHSM2_CONF` once, at `C_Initialize`,
//! so each test reruns itself in a child process of the same test binary, the variable
//! set by `Command::env`: the parent environment never changes, and no token or PIN counter
//! is shared between tests.

use std::path::{Path, PathBuf};
use std::process::Command;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use der::{Decode, Encode};
use nacre_pkcs11::{Config, KeySelector, Pin};
use x509_cert::Certificate;

pub const PIN: &str = "472913";
pub const TOKEN_LABEL: &str = "nacre-test";
// Fictitious, for the throwaway token only.
const SO_PIN: &str = "88776655";
const CHILD: &str = "NACRE_PKCS11_TEST_TOKEN";
const P256_PARAMS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// A freshly initialized SoftHSM token with its user PIN set and nobody logged in.
pub struct Token {
    pub module: PathBuf,
    context: Pkcs11,
    slot: Slot,
}

/// Runs `body` on a fresh token, in a child process; `test` is the calling test's name.
pub fn in_token(test: &str, body: impl FnOnce(&Token)) {
    if std::env::var_os(CHILD).is_some() {
        body(&Token::create());
        return;
    }
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("nacre-pkcs11")
        .join(format!("{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            dir.join("tokens").display()
        ),
    )
    .unwrap();

    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            test,
            "--exact",
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SOFTHSM2_CONF", &conf)
        .env(CHILD, test)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child test failed\n{stdout}\n{stderr}"
    );
    // A misspelt name would run no test and still succeed.
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the child ran no test named {test}\n{stdout}"
    );
}

fn module() -> PathBuf {
    std::env::var_os("NACRE_SOFTHSM_MODULE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"))
}

impl Token {
    fn create() -> Self {
        let module = module();
        let context = Pkcs11::new(&module).unwrap();
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .unwrap();
        let free = context.get_slots_with_token().unwrap()[0];
        context
            .init_token(free, &AuthPin::from(SO_PIN), TOKEN_LABEL)
            .unwrap();
        // SoftHSM gives the initialized token a new slot id.
        let slot = context
            .get_slots_with_initialized_token()
            .unwrap()
            .into_iter()
            .find(|slot| context.get_token_info(*slot).unwrap().label() == TOKEN_LABEL)
            .unwrap();
        let session = context.open_rw_session(slot).unwrap();
        session
            .login(UserType::So, Some(&AuthPin::from(SO_PIN)))
            .unwrap();
        session.init_pin(&AuthPin::from(PIN)).unwrap();
        // Left logged in, the signer's `open` would meet `UserAlreadyLoggedIn`.
        session.logout().unwrap();
        session.close().unwrap();
        Self {
            module,
            context,
            slot,
        }
    }

    pub fn config(&self, key: KeySelector, issuers: Vec<Vec<u8>>) -> Config {
        Config {
            module: self.module.clone(),
            token_label: Some(TOKEN_LABEL.to_owned()),
            key,
            issuers,
        }
    }

    pub fn pin() -> Pin {
        Pin::new(PIN.to_owned())
    }

    /// Runs `f` in a user session, logged out and closed afterwards.
    fn as_user<T>(&self, f: impl FnOnce(&Session) -> T) -> T {
        let session = self.context.open_rw_session(self.slot).unwrap();
        session
            .login(UserType::User, Some(&AuthPin::from(PIN)))
            .unwrap();
        let result = f(&session);
        session.logout().unwrap();
        session.close().unwrap();
        result
    }

    /// Changes the user PIN from a session that does not log in, so the signer's login stays.
    pub fn change_pin(&self, old: &str, new: &str) {
        let session = self.context.open_rw_session(self.slot).unwrap();
        session
            .set_pin(&AuthPin::from(old), &AuthPin::from(new))
            .unwrap();
        session.close().unwrap();
    }

    /// Imports a P-256 private scalar.
    pub fn put_ec_key(&self, secret: &[u8; 32], label: &str, id: &[u8], always_auth: bool) {
        self.as_user(|session| {
            session
                .create_object(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::KeyType(KeyType::EC),
                    Attribute::EcParams(P256_PARAMS.to_vec()),
                    Attribute::Value(secret.to_vec()),
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Sign(true),
                    Attribute::AlwaysAuthenticate(always_auth),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::Id(id.to_vec()),
                ])
                .unwrap();
        });
    }

    pub fn put_certificate(&self, der: &[u8], label: &str, id: &[u8]) {
        let subject = Certificate::from_der(der)
            .unwrap()
            .tbs_certificate()
            .subject()
            .to_der()
            .unwrap();
        self.as_user(|session| {
            session
                .create_object(&[
                    Attribute::Class(ObjectClass::CERTIFICATE),
                    Attribute::CertificateType(CertificateType::X_509),
                    Attribute::Token(true),
                    Attribute::Subject(subject),
                    Attribute::Value(der.to_vec()),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::Id(id.to_vec()),
                ])
                .unwrap();
        });
    }

    /// Generates a 2048-bit RSA pair on the token.
    pub fn generate_rsa(&self, label: &str, id: &[u8]) {
        self.as_user(|session| {
            session
                .generate_key_pair(
                    &Mechanism::RsaPkcsKeyPairGen,
                    &[
                        Attribute::Token(true),
                        Attribute::Verify(true),
                        Attribute::ModulusBits(2048u64.into()),
                        Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
                        Attribute::Label(label.as_bytes().to_vec()),
                        Attribute::Id(id.to_vec()),
                    ],
                    &[
                        Attribute::Token(true),
                        Attribute::Private(true),
                        Attribute::Sensitive(true),
                        Attribute::Sign(true),
                        Attribute::Label(label.as_bytes().to_vec()),
                        Attribute::Id(id.to_vec()),
                    ],
                )
                .unwrap();
        });
    }

    /// Has the token check `signature` over `message` with the public key of `id` and its
    /// own SHA-256 DigestInfo. Handles do not outlive SoftHSM sessions: the key is looked up.
    pub fn verify_rsa_sha256(&self, id: &[u8], message: &[u8], signature: &[u8]) {
        let session = self.context.open_ro_session(self.slot).unwrap();
        let public = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::Id(id.to_vec()),
            ])
            .unwrap()[0];
        session
            .verify(&Mechanism::Sha256RsaPkcs, public, message, signature)
            .unwrap();
    }
}

/// The P-256 key of a DER certificate.
pub fn verifying_key(certificate: &[u8]) -> p256::ecdsa::VerifyingKey {
    let certificate = Certificate::from_der(certificate).unwrap();
    let key = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec();
    p256::ecdsa::VerifyingKey::from_sec1_bytes(&key).unwrap()
}
