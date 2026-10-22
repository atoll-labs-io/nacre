#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_core::DigestAlgorithm;
use nacre_tsp::{Error, Request};
use sha2::{Digest, Sha256};

const DATA: &[u8] = include_bytes!("corpus/recorded/data.bin");
const REQUEST: &[u8] = include_bytes!("corpus/recorded/request.tsq");
// Drawn by `openssl ts -query` and read back with `openssl ts -query -in request.tsq -text`.
const NONCE: [u8; 8] = [0xd4, 0x1c, 0xbf, 0xf4, 0xfd, 0xed, 0x9d, 0x81];

#[test]
fn request_matches_openssl() {
    let request = Request::new(DigestAlgorithm::Sha256, &Sha256::digest(DATA), &NONCE).unwrap();
    assert_eq!(request.to_der().unwrap(), REQUEST);
}

#[test]
fn wrong_imprint_length_is_refused() {
    assert!(matches!(
        Request::new(DigestAlgorithm::Sha384, &Sha256::digest(DATA), &NONCE),
        Err(Error::DigestLength {
            expected: 48,
            actual: 32
        })
    ));
}
