#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::Decode;
use nacre_core::{DigestAlgorithm, ErrorKind};
use nacre_tsp::{Error, Request, oid, verify_response};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;

const DATA: &[u8] = include_bytes!("corpus/recorded/data.bin");
const BENCH: &[u8] = include_bytes!("corpus/recorded/bench.tsr");
const DIGICERT: &[u8] = include_bytes!("corpus/recorded/digicert.tsr");
const FREETSA: &[u8] = include_bytes!("corpus/recorded/freetsa.tsr");
const NONCE: [u8; 8] = [0xd4, 0x1c, 0xbf, 0xf4, 0xfd, 0xed, 0x9d, 0x81];

fn request() -> Request {
    Request::new(DigestAlgorithm::Sha256, &Sha256::digest(DATA), &NONCE).unwrap()
}

/// The token is the response's second element: its tail, after the status SEQUENCE.
fn embedded_token(response: &[u8]) -> &[u8] {
    // `30 82 len len` then the status `30 03 02 01 00`.
    &response[4 + 5..]
}

#[test]
fn bench_response_verifies() {
    let verified = verify_response(BENCH, &request()).unwrap();
    assert_eq!(verified.token(), embedded_token(BENCH));
    assert_eq!(verified.nonce(), Some(&NONCE[..]));
    let certificate = Certificate::from_der(verified.tsa_certificate()).unwrap();
    let (critical, usage) = certificate
        .tbs_certificate()
        .get_extension::<ExtendedKeyUsage>()
        .unwrap()
        .unwrap();
    assert!(critical);
    assert_eq!(usage.0, [oid::TIME_STAMPING]);
}

#[test]
fn digicert_response_verifies() {
    let verified = verify_response(DIGICERT, &request()).unwrap();
    assert_eq!(verified.token(), embedded_token(DIGICERT));
    let certificate = Certificate::from_der(verified.tsa_certificate()).unwrap();
    let key = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    // An RSA-4096 public key: modulus of 512 bytes inside its DER.
    assert!(key.len() > 512);
}

#[test]
fn freetsa_response_is_indeterminate() {
    let error = verify_response(FREETSA, &request()).unwrap_err();
    assert!(
        matches!(error, Error::Cms(nacre_cms::Error::UnsupportedAlgorithm(alg)) if alg == oid::SHA512),
        "{error:?}"
    );
    assert_eq!(error.kind(), ErrorKind::Indeterminate);
}

#[test]
fn other_nonce_is_rejected() {
    let mut other = NONCE;
    other[7] ^= 1;
    let request = Request::new(DigestAlgorithm::Sha256, &Sha256::digest(DATA), &other).unwrap();
    assert!(matches!(
        verify_response(BENCH, &request),
        Err(Error::NonceMismatch)
    ));
}

#[test]
fn refused_status_is_reported() {
    assert!(matches!(
        verify_response(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02], &request()),
        Err(Error::Refused {
            status: 2,
            fail_info: None
        })
    ));
}

#[test]
fn granted_without_token_is_rejected() {
    assert!(matches!(
        verify_response(&[0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00], &request()),
        Err(Error::TokenMissing)
    ));
}
