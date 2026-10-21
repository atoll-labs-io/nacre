#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::Decode;
use nacre_core::{Error, SignatureAlgorithm, Signer, TestSigner};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

const SECRET: [u8; 32] = [0x11; 32];

#[test]
fn signature_verifies_with_chain_key() {
    let signer = TestSigner::from_secret(&SECRET).unwrap();
    assert_eq!(signer.algorithm(), SignatureAlgorithm::EcdsaP256Sha256);

    let certificate = Certificate::from_der(&signer.certificate_chain()[0]).unwrap();
    let spki = certificate.tbs_certificate().subject_public_key_info();
    let key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes()).unwrap();

    for message in [&b""[..], b"nacre", b"a document to sign"] {
        let digest = Sha256::digest(message);
        let output = signer.sign_digest(&digest).unwrap();
        let signature = Signature::from_der(&output).unwrap();
        key.verify_prehash(&digest, &signature).unwrap();
    }
}

#[test]
fn wrong_digest_length_is_refused() {
    let signer = TestSigner::from_secret(&SECRET).unwrap();
    let err = signer.sign_digest(&[0u8; 20]).unwrap_err();
    assert!(
        matches!(
            err,
            Error::DigestLength {
                expected: 32,
                actual: 20
            }
        ),
        "{err:?}"
    );
}
