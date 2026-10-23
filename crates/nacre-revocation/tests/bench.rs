#![cfg(feature = "http")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Needs the conformance bench running (`conformance/README.md`, Run): its CRL server
//! serves the intermediate's CRL, and its OCSP responder answers, at the URLs every bench
//! leaf names.

use der::DateTime;
use nacre_core::{RevocationData, RevocationSource};
use nacre_revocation::{
    Crl, CrlReason, CrlStatus, HttpCrlSource, HttpOcspSource, OcspResponse, OcspStatus,
};

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

/// The OCSP answer about `leaf`, judged at its own `thisUpdate`, which is also returned.
fn ocsp_status(leaf: &[u8], intermediate: &[u8]) -> (OcspStatus, std::time::SystemTime) {
    let source = HttpOcspSource::allowing_loopback();
    let RevocationData::Ocsp(bytes) = source.revocation(leaf, intermediate).unwrap() else {
        panic!("an OCSP source answered with something else");
    };
    let response = OcspResponse::from_der(&bytes).unwrap();
    let at = response.this_update().unwrap();
    (response.status(leaf, intermediate, at).unwrap(), at)
}

#[test]
#[ignore = "conformance"]
fn ocsp_says_revoked_and_good_on_the_bench() {
    let intermediate = certificate("intermediate.cert.pem");
    let revoked = certificate("revoked.cert.pem");

    let (status, at) = ocsp_status(&revoked, &intermediate);
    let OcspStatus::Revoked { date, .. } = status else {
        panic!("the revoked certificate is {status:?}");
    };
    // Keys and dates change at each bench start: compare with the CRL, read from the same
    // index, rather than with a fixed date.
    let RevocationData::Crl(crl) = HttpCrlSource::allowing_loopback()
        .revocation(&revoked, &intermediate)
        .unwrap()
    else {
        panic!("a CRL source answered with something else");
    };
    let CrlStatus::Revoked { date: crl_date, .. } = Crl::from_der(&crl)
        .unwrap()
        .status(&revoked, &intermediate, at)
        .unwrap()
    else {
        panic!("the CRL does not list the revoked certificate");
    };
    assert_eq!(date, crl_date);

    let (status, _) = ocsp_status(&certificate("signer.cert.pem"), &intermediate);
    assert_eq!(status, OcspStatus::Good);
}
