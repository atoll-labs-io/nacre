use std::str::FromStr;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::builder::profile::cabf;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::{DateTime, Encode};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

use crate::{Error, SignatureAlgorithm, Signer};

const SUBJECT: &str = "CN=Nacre test signer,O=Nacre tests,C=FR";
// Fixed bounds: the crate never reads the clock.
const NOT_BEFORE: (u16, u8, u8) = (2026, 1, 1);
const NOT_AFTER: (u16, u8, u8) = (2036, 1, 1);

/// A software P-256 signer with a self-signed certificate, for tests only.
///
/// Never use it to sign anything that matters: its key comes from a caller-supplied
/// secret. It deliberately implements neither `Debug` nor `Display`.
pub struct TestSigner {
    key: SigningKey,
    chain: Vec<Vec<u8>>,
}

impl TestSigner {
    /// Builds a signer from a 32-byte P-256 secret scalar and self-signs its certificate.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, Error> {
        let key = SigningKey::from_slice(secret).map_err(signer_error)?;
        let profile = cabf::Root::new(false, Name::from_str(SUBJECT).map_err(signer_error)?)
            .map_err(signer_error)?;
        let validity = Validity::new(time(NOT_BEFORE)?, time(NOT_AFTER)?);
        let spki =
            SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).map_err(signer_error)?;
        let certificate =
            CertificateBuilder::new(profile, SerialNumber::from(1u32), validity, spki)
                .map_err(signer_error)?
                .build::<_, DerSignature>(&key)
                .map_err(signer_error)?
                .to_der()
                .map_err(signer_error)?;
        Ok(Self {
            key,
            chain: vec![certificate],
        })
    }
}

impl Signer for TestSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256Sha256
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, Error> {
        // ECDSA would accept any length (bits2field), so a wrong digest must be refused here.
        let expected = self.algorithm().digest().output_len();
        if digest.len() != expected {
            return Err(Error::DigestLength {
                expected,
                actual: digest.len(),
            });
        }
        let signature: DerSignature = self.key.sign_prehash(digest).map_err(signer_error)?;
        Ok(signature.as_bytes().to_vec())
    }
}

fn time((year, month, day): (u16, u8, u8)) -> Result<Time, Error> {
    DateTime::new(year, month, day, 0, 0, 0)
        .map(Time::from)
        .map_err(signer_error)
}

fn signer_error(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Signer(Box::new(error))
}
