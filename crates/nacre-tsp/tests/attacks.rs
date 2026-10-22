#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::DateTime;
use nacre_core::DigestAlgorithm;
use nacre_tsp::{Error, Request, verify_response};
use sha2::{Digest, Sha256};

const DATA: &[u8] = include_bytes!("corpus/recorded/data.bin");
const NONCE: [u8; 8] = [0xd4, 0x1c, 0xbf, 0xf4, 0xfd, 0xed, 0x9d, 0x81];

fn verify(response: &[u8]) -> Result<nacre_tsp::VerifiedToken, Error> {
    let request = Request::new(DigestAlgorithm::Sha256, &Sha256::digest(DATA), &NONCE).unwrap();
    verify_response(response, &request)
}

#[test]
fn forged_baseline_verifies() {
    let verified = verify(include_bytes!("corpus/attacks/valid.tsr")).unwrap();
    // Forged with genTime 20261022092550.25Z: the fraction is read, then dropped.
    assert_eq!(
        verified.gen_time(),
        DateTime::new(2026, 10, 22, 9, 25, 50).unwrap()
    );
}

#[test]
fn replay_without_nonce_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/nonce-absent.tsr")),
        Err(Error::NonceMissing)
    ));
}

#[test]
fn token_of_another_imprint_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/imprint-other.tsr")),
        Err(Error::ImprintMismatch)
    ));
}

#[test]
fn certificate_without_timestamping_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/no-timestamping-eku.tsr")),
        Err(Error::NotTimestampingCertificate)
    ));
}

#[test]
fn altered_signature_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/signature-invalid.tsr")),
        Err(Error::Cms(nacre_cms::Error::SignatureInvalid))
    ));
}

#[test]
fn ess_v1_only_is_indeterminate() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/ess-v1-only.tsr")),
        Err(Error::SigningCertificateMissing)
    ));
}

#[test]
fn content_other_than_tst_info_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/content-type-other.tsr")),
        Err(Error::NotTstInfo)
    ));
}

#[test]
fn non_critical_timestamping_purpose_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/eku-not-critical.tsr")),
        Err(Error::NotTimestampingCertificate)
    ));
}

#[test]
fn timestamping_with_another_purpose_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/eku-extra-purpose.tsr")),
        Err(Error::NotTimestampingCertificate)
    ));
}

#[test]
fn imprint_of_another_hash_algorithm_is_rejected() {
    assert!(matches!(
        verify(include_bytes!("corpus/attacks/imprint-algorithm-other.tsr")),
        Err(Error::ImprintMismatch)
    ));
}

#[test]
fn hash_parameters_other_than_null_are_rejected() {
    assert!(matches!(
        verify(include_bytes!(
            "corpus/attacks/imprint-parameters-other.tsr"
        )),
        Err(Error::ImprintMismatch)
    ));
}
