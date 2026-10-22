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

fn render_all(error: &dyn std::error::Error) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let mut current: Option<&dyn std::error::Error> = Some(error);
    while let Some(e) = current {
        write!(out, "{e} {e:?} {e:#?} ").unwrap();
        current = e.source();
    }
    out
}

fn assert_no_secret(rendered: &str, byte: u8) {
    let hex = format!("{byte:02x}").repeat(32);
    let list = vec![byte.to_string(); 2].join(", ");
    let raw = String::from_utf8_lossy(&[byte; 4]).into_owned();
    let lowered = rendered.to_lowercase();
    assert!(!lowered.contains(&hex), "hex secret in {rendered}");
    assert!(!rendered.contains(&list), "byte list in {rendered}");
    assert!(!rendered.contains(&raw), "raw bytes in {rendered}");
}

#[test]
fn errors_never_show_the_secret() {
    let Err(refused) = TestSigner::from_secret(&[0xFF; 32]) else {
        panic!("a scalar above the P-256 order must be refused");
    };
    let mut rendered = render_all(&refused);
    rendered.push_str(&refused.kind().to_string());
    assert_no_secret(&rendered, 0xFF);

    let signer = TestSigner::from_secret(&[0x5A; 32]).unwrap();
    let wrong = signer.sign_digest(&[0u8; 31]).unwrap_err();
    let mut rendered = render_all(&wrong);
    rendered.push_str(&wrong.kind().to_string());
    assert_no_secret(&rendered, 0x5A);
}
