#![cfg(feature = "http")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Needs the conformance bench running (`conformance/README.md`, Run): its CRL server
//! serves the intermediate's CRL at the URL every bench leaf names.

use der::DateTime;
use nacre_core::{RevocationData, RevocationSource};
use nacre_revocation::{Crl, CrlReason, CrlStatus, HttpCrlSource};

fn certificate(name: &str) -> Vec<u8> {
    let pem = std::fs::read(nacre_conformance::pki_dir().join(name)).unwrap();
    der::pem::decode_vec(&pem).unwrap().1
}

fn status(source: &dyn RevocationSource, leaf: &[u8], intermediate: &[u8]) -> CrlStatus {
    let RevocationData::Crl(bytes) = source.revocation(leaf, intermediate).unwrap() else {
        panic!("a CRL source answered with something else");
    };
    let at = DateTime::new(2030, 1, 1, 0, 0, 0).unwrap().to_system_time();
    Crl::from_der(&bytes)
        .unwrap()
        .status(leaf, intermediate, at)
        .unwrap()
}

#[test]
#[ignore = "conformance"]
fn revoked_is_listed_and_signer_is_not_on_the_bench() {
    let intermediate = certificate("intermediate.cert.pem");
    // The bench serves its CRLs on 127.0.0.1, which the default source refuses.
    let source = HttpCrlSource::allowing_loopback();

    assert!(matches!(
        status(&source, &certificate("revoked.cert.pem"), &intermediate),
        CrlStatus::Revoked {
            reason: Some(CrlReason::KeyCompromise),
            ..
        }
    ));
    assert_eq!(
        status(&source, &certificate("signer.cert.pem"), &intermediate),
        CrlStatus::NotRevoked
    );
}
