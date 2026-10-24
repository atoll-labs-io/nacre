// Each test file uses its own part of this module.
#![allow(dead_code)]

pub mod forge;

use std::path::Path;

use nacre_core::{RevocationData, RevocationSource, SignatureAlgorithm, Signer};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::DecodePrivateKey;

/// The bench's `signer` key and its chain up to the intermediate, read from the PKI the
/// bench generates at start (`conformance/pki/README.md`). No `Debug`: it holds a key.
pub struct BenchSigner {
    key: SigningKey,
    chain: Vec<Vec<u8>>,
}

impl BenchSigner {
    pub fn load() -> Self {
        Self::load_as("signer")
    }

    /// The bench certificate `name` (`signer`, `revoked`) with its key.
    pub fn load_as(name: &str) -> Self {
        let key = bench_key(name);
        let chain = vec![
            bench_certificate(&format!("{name}.cert.pem")),
            bench_certificate("intermediate.cert.pem"),
        ];
        Self { key, chain }
    }
}

/// The private key of the bench's `name` (`intermediate`, `signer`, `revoked`), read from
/// the PKI the bench generates at start; never committed.
pub fn bench_key(name: &str) -> SigningKey {
    let dir = nacre_conformance::pki_dir();
    SigningKey::from_pkcs8_pem(&read(&dir, &format!("{name}.key.pem"))).unwrap()
}

/// The DER of the bench certificate `name`, read from its PEM file in the bench's PKI.
pub fn bench_certificate(name: &str) -> Vec<u8> {
    let pem = read(&nacre_conformance::pki_dir(), name);
    let (label, der) = der::pem::decode_vec(pem.as_bytes()).unwrap();
    assert_eq!(label, "CERTIFICATE");
    der
}

fn read(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read {}: {error}; start the bench: conformance/README.md",
            path.display()
        )
    })
}

impl Signer for BenchSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256Sha256
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, nacre_core::Error> {
        // ECDSA would accept any length (bits2field), so a wrong digest must be refused here.
        let expected = self.algorithm().digest().output_len();
        if digest.len() != expected {
            return Err(nacre_core::Error::DigestLength {
                expected,
                actual: digest.len(),
            });
        }
        let signature: DerSignature = self
            .key
            .sign_prehash(digest)
            .map_err(|error| nacre_core::Error::Signer(Box::new(error)))?;
        Ok(signature.as_bytes().to_vec())
    }
}

/// Answers each certificate with the CRL of its issuer, or fails.
pub struct Stub {
    pub intermediate: Vec<u8>,
    pub intermediate_crl: Vec<u8>,
    pub root_crl: Vec<u8>,
    pub failing: bool,
}

impl RevocationSource for Stub {
    fn revocation(
        &self,
        _certificate: &[u8],
        issuer: &[u8],
    ) -> Result<RevocationData, nacre_core::Error> {
        if self.failing {
            return Err(nacre_core::Error::revocation("unreachable"));
        }
        Ok(RevocationData::Crl(if issuer == self.intermediate {
            self.intermediate_crl.clone()
        } else {
            self.root_crl.clone()
        }))
    }
}
