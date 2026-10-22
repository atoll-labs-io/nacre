#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::{DecodePem, Encode};
use nacre_core::{DigestAlgorithm, TimestampAuthority};
use nacre_tsp::{HttpTsa, verify_token};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

const BENCH_TSA: &str = "http://127.0.0.1:18081/cgi-bin/tsa";

#[test]
#[ignore = "conformance"]
fn bench_tsa_returns_a_verified_token() {
    let imprint = Sha256::digest(b"nacre-tsp conformance");
    let token = HttpTsa::new(BENCH_TSA)
        .timestamp(DigestAlgorithm::Sha256, &imprint)
        .unwrap();
    let verified = verify_token(&token, DigestAlgorithm::Sha256, &imprint).unwrap();

    // The bench regenerates its PKI at every start: compare with today's TSA certificate.
    let pem = std::fs::read(nacre_conformance::pki_dir().join("tsa.cert.pem")).unwrap();
    let expected = Certificate::from_pem(&pem).unwrap().to_der().unwrap();
    assert_eq!(verified.tsa_certificate(), expected.as_slice());
}
