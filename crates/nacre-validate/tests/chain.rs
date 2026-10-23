#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The chain API on its own, with no PDF: the certificates of `corpus/chain/`, written by
//! the cargo example `forge_chain_attacks`.

use std::str::FromStr;
use std::time::SystemTime;

use der::asn1::ObjectIdentifier;
use der::{DateTime, Encode};
use nacre_validate::{ChainDefect, Error, TrustAnchors, build_chain};
use p256::ecdsa::{DerSignature, SigningKey};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const ROOT: &[u8] = include_bytes!("corpus/chain/root.der");
const INTERMEDIATE: &[u8] = include_bytes!("corpus/chain/intermediate.der");
const LEAF: &[u8] = include_bytes!("corpus/chain/leaf.der");
const IMPOSTOR_ROOT: &[u8] = include_bytes!("corpus/chain/impostor-root.der");
/// The intermediate's key in `forge_chain_attacks`.
const INTERMEDIATE_SECRET: [u8; 32] = [0x32; 32];
const INTERMEDIATE_NAME: &str = "CN=Nacre chain intermediate,O=Nacre tests,C=FR";
const ROOT_NAME: &str = "CN=Nacre chain root,O=Nacre tests,C=FR";
const ATTACKER_NAME: &str = "CN=Nacre chain attacker CA,O=Nacre tests,C=FR";
/// A key no certificate of the corpus holds.
const ATTACKER_SECRET: [u8; 32] = [0x36; 32];

fn at() -> SystemTime {
    Time::from(DateTime::new(2026, 10, 22, 0, 0, 0).unwrap()).to_system_time()
}

fn anchors(certificates: &[&[u8]]) -> TrustAnchors {
    TrustAnchors::from_certificates(certificates.iter().copied()).unwrap()
}

#[test]
fn path_is_built_without_pdf() {
    let pool: &[&[u8]] = &[IMPOSTOR_ROOT, ROOT, INTERMEDIATE, INTERMEDIATE, LEAF];

    let path = build_chain(LEAF, pool, &anchors(&[ROOT]), at()).unwrap();
    assert_eq!(path.certificates, vec![LEAF, INTERMEDIATE, ROOT]);

    let none = build_chain(LEAF, pool, &TrustAnchors::default(), at());
    assert_eq!(none, Err(ChainDefect::NoPath));

    let impostor = build_chain(LEAF, &[INTERMEDIATE], &anchors(&[IMPOSTOR_ROOT]), at());
    assert_eq!(impostor, Err(ChainDefect::NoPath));
}

/// A CA named `subject`, issued under the name `issuer`.
struct Decoy {
    subject: &'static str,
    issuer: &'static str,
}

impl BuilderProfile for Decoy {
    fn get_issuer(&self, _subject: &Name) -> Name {
        Name::from_str(self.issuer).unwrap()
    }

    fn get_subject(&self) -> Name {
        Name::from_str(self.subject).unwrap()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let basic_constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        }
        .to_extension(tbs.subject(), &[])?;
        let key_usage = KeyUsage(KeyUsages::KeyCertSign.into())
            .to_extension(tbs.subject(), std::slice::from_ref(&basic_constraints))?;
        Ok(vec![basic_constraints, key_usage])
    }
}

/// `count` decoys holding the intermediate's public key, with its name, issued under
/// `issuer` and signed by `signer`.
fn decoys(count: u32, issuer: &'static str, signer: &[u8; 32]) -> Vec<Vec<u8>> {
    forge(
        count,
        INTERMEDIATE_NAME,
        issuer,
        &INTERMEDIATE_SECRET,
        signer,
    )
}

/// `count` CAs named `subject` holding the public key of `holder`, issued under `issuer`
/// and signed by `signer`.
fn forge(
    count: u32,
    subject: &'static str,
    issuer: &'static str,
    holder: &[u8; 32],
    signer: &[u8; 32],
) -> Vec<Vec<u8>> {
    let public = SigningKey::from_slice(holder).unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(public.verifying_key()).unwrap();
    let key = SigningKey::from_slice(signer).unwrap();
    let validity = Validity::new(
        Time::from(DateTime::new(2026, 1, 1, 0, 0, 0).unwrap()),
        Time::from(DateTime::new(2036, 1, 1, 0, 0, 0).unwrap()),
    );
    (100..100 + count)
        .map(|serial| {
            let profile = Decoy { subject, issuer };
            CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki.clone())
                .unwrap()
                .build::<_, DerSignature>(&key)
                .unwrap()
                .to_der()
                .unwrap()
        })
        .collect()
}

/// Self-issued with the intermediate's name and key: each one verifies the leaf and every
/// other one, so the search graph is complete.
#[test]
fn search_is_bounded() {
    let decoys = decoys(200, INTERMEDIATE_NAME, &INTERMEDIATE_SECRET);
    let pool: Vec<&[u8]> = decoys.iter().map(Vec::as_slice).collect();

    let result = build_chain(LEAF, &pool, &anchors(&[ROOT]), at());

    assert_eq!(result, Err(ChainDefect::NoPath));
}

/// Look-alikes of the intermediate placed ahead of it: each verifies the leaf, claims the
/// root as issuer and is signed by another key, so none reaches the anchor.
#[test]
fn look_alikes_do_not_hide_the_issuer() {
    let decoys = decoys(100, ROOT_NAME, &ATTACKER_SECRET);
    let mut pool: Vec<&[u8]> = decoys.iter().map(Vec::as_slice).collect();
    pool.push(INTERMEDIATE);

    let path = build_chain(LEAF, &pool, &anchors(&[ROOT]), at()).unwrap();

    assert_eq!(path.certificates, vec![LEAF, INTERMEDIATE, ROOT]);
}

/// A look-alike of the intermediate, which verifies the leaf, issued by an attacker CA
/// whose 200 self-issued copies verify each other: no anchor certifies any of them, but
/// tried as issuers their complete graph would use up the search before the real
/// intermediate at the end of the pool.
#[test]
fn uncertified_graph_does_not_hide_the_issuer() {
    let bridge = decoys(1, ATTACKER_NAME, &ATTACKER_SECRET);
    let graph = forge(
        200,
        ATTACKER_NAME,
        ATTACKER_NAME,
        &ATTACKER_SECRET,
        &ATTACKER_SECRET,
    );
    let mut pool: Vec<&[u8]> = bridge.iter().chain(&graph).map(Vec::as_slice).collect();
    pool.push(INTERMEDIATE);

    let path = build_chain(LEAF, &pool, &anchors(&[ROOT]), at()).unwrap();

    assert_eq!(path.certificates, vec![LEAF, INTERMEDIATE, ROOT]);
}

/// A copy of the intermediate with the same `tbsCertificate` and a broken signature,
/// placed ahead of it.
#[test]
fn broken_twin_does_not_hide_the_issuer() {
    let mut twin = INTERMEDIATE.to_vec();
    *twin.last_mut().unwrap() ^= 0x01;
    let pool: &[&[u8]] = &[&twin, INTERMEDIATE];

    let path = build_chain(LEAF, pool, &anchors(&[ROOT]), at()).unwrap();

    assert_eq!(path.certificates, vec![LEAF, INTERMEDIATE, ROOT]);
}

/// Unreadable and repeated entries do not count towards the 256 certificates read; past
/// them the pool is ignored, never refused.
#[test]
fn pool_is_capped() {
    let junk: Vec<Vec<u8>> = (0..300u16)
        .map(|i| {
            let [hi, lo] = i.to_be_bytes();
            vec![0x30, 0x04, 0x02, 0x02, hi, lo]
        })
        .collect();
    let mut noisy: Vec<&[u8]> = junk.iter().map(Vec::as_slice).collect();
    noisy.extend([IMPOSTOR_ROOT; 300]);
    noisy.push(INTERMEDIATE);
    let path = build_chain(LEAF, &noisy, &anchors(&[ROOT]), at()).unwrap();
    assert_eq!(path.certificates, vec![LEAF, INTERMEDIATE, ROOT]);

    let decoys = decoys(300, ROOT_NAME, &ATTACKER_SECRET);
    let mut first: Vec<&[u8]> = vec![INTERMEDIATE];
    first.extend(decoys.iter().map(Vec::as_slice));
    let path = build_chain(LEAF, &first, &anchors(&[ROOT]), at()).unwrap();
    assert_eq!(path.certificates, vec![LEAF, INTERMEDIATE, ROOT]);

    let mut last: Vec<&[u8]> = decoys.iter().take(256).map(Vec::as_slice).collect();
    last.push(INTERMEDIATE);
    let ignored = build_chain(LEAF, &last, &anchors(&[ROOT]), at());
    assert_eq!(ignored, Err(ChainDefect::NoPath));
}

/// A signer under the intermediate whose `extendedKeyUsage` holds `purposes`.
struct Signer {
    purposes: Vec<ObjectIdentifier>,
}

impl BuilderProfile for Signer {
    fn get_issuer(&self, _subject: &Name) -> Name {
        Name::from_str(INTERMEDIATE_NAME).unwrap()
    }

    fn get_subject(&self) -> Name {
        Name::from_str("CN=Nacre chain client signer,O=Nacre tests,C=FR").unwrap()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(vec![
            ExtendedKeyUsage(self.purposes.clone()).to_extension(tbs.subject(), &[])?,
        ])
    }
}

/// PIV and many qualified signing certificates name `id-kp-clientAuth` alone.
#[test]
fn client_auth_signer_is_accepted() {
    let client_auth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
    let holder = SigningKey::from_slice(&ATTACKER_SECRET).unwrap();
    let spki = SubjectPublicKeyInfoOwned::from_key(holder.verifying_key()).unwrap();
    let validity = Validity::new(
        Time::from(DateTime::new(2026, 1, 1, 0, 0, 0).unwrap()),
        Time::from(DateTime::new(2036, 1, 1, 0, 0, 0).unwrap()),
    );
    let profile = Signer {
        purposes: vec![client_auth],
    };
    let leaf = CertificateBuilder::new(profile, SerialNumber::from(200u32), validity, spki)
        .unwrap()
        .build::<_, DerSignature>(&SigningKey::from_slice(&INTERMEDIATE_SECRET).unwrap())
        .unwrap()
        .to_der()
        .unwrap();

    let path = build_chain(&leaf, &[INTERMEDIATE], &anchors(&[ROOT]), at()).unwrap();

    assert_eq!(path.certificates, vec![&leaf[..], INTERMEDIATE, ROOT]);
}

#[test]
fn pem_anchor_is_named() {
    let pem = b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    let error = TrustAnchors::from_certificates([&pem[..]]).unwrap_err();
    assert!(matches!(error, Error::TrustAnchorPem), "{error}");
    assert!(error.to_string().contains("PEM"));
}
