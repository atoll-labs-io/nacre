use std::cell::Cell;
use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use nacre_core::{SignatureAlgorithm, Signer};

use crate::convert::{DIGEST_INFO_SHA256, ecdsa_der};
use crate::error::pin_state;
use crate::raw::Module;
use crate::{Error, Pin, PinState};

/// DER of the P-256 curve OID, as `CKA_EC_PARAMS` holds it.
const P256_PARAMS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// How the private key is found on the token.
#[derive(Debug, Clone)]
pub enum KeySelector {
    /// By `CKA_LABEL`.
    Label(String),
    /// By `CKA_ID`.
    Id(Vec<u8>),
}

/// Where the key is and what completes its certificate chain.
#[derive(Debug, Clone)]
pub struct Config {
    /// Path of the PKCS#11 module, such as `/usr/lib/softhsm/libsofthsm2.so`.
    pub module: PathBuf,
    /// The token's label; `None` requires exactly one initialized token.
    pub token_label: Option<String>,
    /// The private key to sign with.
    pub key: KeySelector,
    /// The issuers of the key's certificate as DER, towards the trust anchor.
    pub issuers: Vec<Vec<u8>>,
}

/// A [`Signer`] whose private key stays on a PKCS#11 token.
///
/// It implements no `Debug`: it may hold the PIN.
pub struct Pkcs11Signer {
    session: Session,
    context: Pkcs11,
    slot: Slot,
    key: ObjectHandle,
    algorithm: SignatureAlgorithm,
    chain: Vec<Vec<u8>>,
    // Only for a key that asks for the PIN at every signature.
    reauth: Option<Reauth>,
}

struct Reauth {
    // Emptied, and the PIN zeroized, once the token refuses it: it is never sent again.
    pin: Cell<Option<Pin>>,
    module: Module,
}

impl Pkcs11Signer {
    /// Loads the module, logs in once with `pin`, and finds the key and its certificate.
    ///
    /// The certificate is the one carrying the key's `CKA_ID`; the chain is that certificate
    /// followed by `config.issuers`. A refused PIN is never tried again: the error carries
    /// the state the token reports. If this process is already logged in to the token, for
    /// instance through another signer, `open` fails with [`Error::AlreadyLoggedIn`]: the
    /// token would not check `pin`.
    pub fn open(config: &Config, pin: Pin) -> Result<Self, Error> {
        let context = Pkcs11::new(&config.module).map_err(|_| Error::ModuleUnavailable)?;
        match context.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(error) => return Err(Error::Pkcs11(error)),
        }
        let slot = find_token(&context, config.token_label.as_deref())?;
        if context
            .get_token_info(slot)
            .map_err(Error::Pkcs11)?
            .user_pin_locked()
        {
            return Err(Error::WrongPin(PinState::Locked));
        }

        let session = context.open_ro_session(slot).map_err(Error::Pkcs11)?;
        login(&context, slot, &session, UserType::User, &pin)?;

        let key = find_key(&session, &config.key)?;
        let (algorithm, id, always_authenticate) = describe_key(&session, key)?;
        let mut chain = vec![find_certificate(&session, id)?];
        chain.extend(config.issuers.iter().cloned());

        let reauth = if always_authenticate {
            Some(Reauth {
                module: Module::load(&config.module)?,
                pin: Cell::new(Some(pin)),
            })
        } else {
            drop(pin);
            None
        };
        Ok(Self {
            session,
            context,
            slot,
            key,
            algorithm,
            chain,
            reauth,
        })
    }

    fn sign(&self, digest: &[u8]) -> Result<Vec<u8>, Error> {
        let (mechanism, data) = match self.algorithm {
            SignatureAlgorithm::EcdsaP256Sha256 => (Mechanism::Ecdsa, digest.to_vec()),
            SignatureAlgorithm::RsaPkcs1v15Sha256 => (
                Mechanism::RsaPkcs,
                [DIGEST_INFO_SHA256.as_slice(), digest].concat(),
            ),
            _ => return Err(Error::UnsupportedKey),
        };
        let signature = match &self.reauth {
            None => self
                .session
                .sign(&mechanism, self.key, &data)
                .map_err(Error::Pkcs11)?,
            Some(reauth) => {
                let pin = reauth.pin.take().ok_or(Error::PinRefused)?;
                let ready = self
                    .session
                    .sign_init(&mechanism, self.key)
                    .map_err(Error::Pkcs11)
                    .and_then(|()| {
                        login(
                            &self.context,
                            self.slot,
                            &self.session,
                            UserType::ContextSpecific,
                            &pin,
                        )
                    });
                if !matches!(ready, Err(Error::WrongPin(_))) {
                    reauth.pin.set(Some(pin));
                }
                ready?;
                reauth
                    .module
                    .sign(self.session.handle(), &data)
                    .map_err(Error::Pkcs11)?
            }
        };
        match self.algorithm {
            SignatureAlgorithm::EcdsaP256Sha256 => ecdsa_der(&signature),
            _ => Ok(signature),
        }
    }
}

impl Signer for Pkcs11Signer {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, nacre_core::Error> {
        let expected = self.algorithm.digest().output_len();
        if digest.len() != expected {
            return Err(nacre_core::Error::DigestLength {
                expected,
                actual: digest.len(),
            });
        }
        self.sign(digest)
            .map_err(|error| nacre_core::Error::Signer(Box::new(error)))
    }
}

fn find_token(context: &Pkcs11, label: Option<&str>) -> Result<Slot, Error> {
    let mut found = Vec::new();
    for slot in context.get_slots_with_token().map_err(Error::Pkcs11)? {
        let info = context.get_token_info(slot).map_err(Error::Pkcs11)?;
        if info.token_initialized() && label.is_none_or(|label| info.label() == label) {
            found.push(slot);
        }
    }
    match (found.as_slice(), label) {
        ([slot], _) => Ok(*slot),
        ([], None) => Err(Error::NoToken),
        ([], Some(_)) => Err(Error::TokenNotFound),
        _ => Err(Error::SeveralTokens),
    }
}

/// Logs in once; a refused PIN becomes `WrongPin` with the state the token then reports.
fn login(
    context: &Pkcs11,
    slot: Slot,
    session: &Session,
    user: UserType,
    pin: &Pin,
) -> Result<(), Error> {
    match session.login(user, Some(&pin.auth())) {
        Ok(()) => Ok(()),
        Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) if matches!(user, UserType::User) => {
            Err(Error::AlreadyLoggedIn)
        }
        Err(CkError::Pkcs11(
            refused @ (RvError::PinIncorrect
            | RvError::PinInvalid
            | RvError::PinLenRange
            | RvError::PinLocked
            | RvError::PinExpired),
            _,
        )) => {
            let locked_rv = matches!(refused, RvError::PinLocked);
            // The refusal is the answer; a token that then fails to report its flags still
            // gets a `WrongPin`.
            let state = match context.get_token_info(slot) {
                Ok(info) => pin_state(
                    info.user_pin_count_low(),
                    info.user_pin_final_try(),
                    info.user_pin_locked(),
                    locked_rv,
                ),
                Err(_) => pin_state(false, false, false, locked_rv),
            };
            Err(Error::WrongPin(state))
        }
        Err(error) => Err(Error::Pkcs11(error)),
    }
}

fn find_key(session: &Session, selector: &KeySelector) -> Result<ObjectHandle, Error> {
    let by = match selector {
        KeySelector::Label(label) => Attribute::Label(label.as_bytes().to_vec()),
        KeySelector::Id(id) => Attribute::Id(id.clone()),
    };
    let found = session
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), by])
        .map_err(Error::Pkcs11)?;
    match found.as_slice() {
        [] => Err(Error::KeyNotFound),
        [key] => Ok(*key),
        _ => Err(Error::SeveralKeys),
    }
}

/// The key's algorithm, its `CKA_ID` and whether it asks for the PIN at every signature.
fn describe_key(
    session: &Session,
    key: ObjectHandle,
) -> Result<(SignatureAlgorithm, Vec<u8>, bool), Error> {
    let attributes = session
        .get_attributes(
            key,
            &[
                AttributeType::KeyType,
                AttributeType::Id,
                AttributeType::AlwaysAuthenticate,
                AttributeType::EcParams,
            ],
        )
        .map_err(Error::Pkcs11)?;
    let mut key_type = None;
    let mut id = Vec::new();
    let mut always_authenticate = false;
    let mut ec_params = None;
    for attribute in attributes {
        match attribute {
            Attribute::KeyType(value) => key_type = Some(value),
            Attribute::Id(value) => id = value,
            Attribute::AlwaysAuthenticate(value) => always_authenticate = value,
            Attribute::EcParams(value) => ec_params = Some(value),
            _ => {}
        }
    }
    let algorithm = match key_type {
        Some(KeyType::EC) if ec_params.as_deref() == Some(P256_PARAMS.as_slice()) => {
            SignatureAlgorithm::EcdsaP256Sha256
        }
        Some(KeyType::RSA) => SignatureAlgorithm::RsaPkcs1v15Sha256,
        _ => return Err(Error::UnsupportedKey),
    };
    Ok((algorithm, id, always_authenticate))
}

fn find_certificate(session: &Session, id: Vec<u8>) -> Result<Vec<u8>, Error> {
    let found = session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Id(id),
        ])
        .map_err(Error::Pkcs11)?;
    let certificate = found.first().ok_or(Error::CertificateNotFound)?;
    session
        .get_attributes(*certificate, &[AttributeType::Value])
        .map_err(Error::Pkcs11)?
        .into_iter()
        .find_map(|attribute| match attribute {
            Attribute::Value(der) => Some(der),
            _ => None,
        })
        .ok_or(Error::CertificateNotFound)
}
