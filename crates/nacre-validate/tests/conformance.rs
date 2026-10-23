#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A PDF signed with the bench's `signer`, its chain judged against the bench root
//! (`conformance/README.md`). Only the PKI the bench generates is read; DSS is not called.

mod support;

use nacre_core::{Indication, SubIndication};
use nacre_pades::{DateTime, sign};
use nacre_validate::{TrustAnchors, validate_with_anchors};
use support::{BenchSigner, bench_certificate};

const UNSIGNED: &[u8] = include_bytes!("corpus/unsigned.pdf");

#[test]
#[ignore = "conformance"]
fn bench_chain_is_valid() {
    let pdf = sign(
        UNSIGNED,
        &BenchSigner::load(),
        DateTime::new(2026, 10, 22, 8, 0, 0).unwrap(),
    )
    .unwrap();
    let root = bench_certificate("root.cert.pem");
    let anchors = TrustAnchors::from_certificates([root.as_slice()]).unwrap();
    // Inside the bench certificates' validity, 2026-01-01 to 2046-01-01.
    let at = x509_cert::time::Time::from(der::DateTime::new(2026, 10, 22, 0, 0, 0).unwrap())
        .to_system_time();

    let results = validate_with_anchors(&pdf, &anchors, at).unwrap();

    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert!(result.defect.is_none(), "{:?}", result.defect);
    let chain = result.chain.as_ref().unwrap();
    assert_eq!(
        chain.certificates,
        vec![
            bench_certificate("signer.cert.pem"),
            bench_certificate("intermediate.cert.pem"),
            root,
        ]
    );
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::TryLater)
    );
}
