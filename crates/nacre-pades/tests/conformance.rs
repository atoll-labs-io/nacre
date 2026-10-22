#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! PDFs signed by `nacre_pades::sign` with the bench's `signer`, judged by the running DSS
//! (`conformance/README.md`).

mod support;

use nacre_conformance::{Dss, reports_dir};
use nacre_core::Indication;
use nacre_pades::{DateTime, sign};
use support::BenchSigner;

const UNSIGNED: &[u8] = include_bytes!("corpus/unsigned.pdf");

// Inside the bench certificates' validity, 2026-01-01 to 2046-01-01.
fn time() -> DateTime {
    DateTime::new(2026, 10, 22, 8, 0, 0).unwrap()
}

#[test]
#[ignore = "conformance"]
fn bench_signature_is_pades_baseline_b() {
    let report = reports_dir().join("s06-pades-b.xml");
    // A report left by an earlier run must not stand in for this one.
    let _ = std::fs::remove_file(&report);
    let signed = sign(UNSIGNED, &BenchSigner::load(), time()).unwrap();

    let reports = Dss::from_env()
        .unwrap()
        .validate("s06-pades-b", &signed)
        .unwrap();

    assert_eq!(reports.signatures.len(), 1);
    let verdict = &reports.signatures[0];
    assert_eq!(verdict.report.indication(), Indication::TotalPassed);
    assert_eq!(verdict.report.sub_indication(), None);
    assert_eq!(verdict.format, "PAdES-BASELINE-B");
    assert!(report.is_file());
}

#[test]
#[ignore = "conformance"]
fn both_bench_signatures_are_pades_baseline_b() {
    let signer = BenchSigner::load();
    let once = sign(UNSIGNED, &signer, time()).unwrap();
    let twice = sign(&once, &signer, time()).unwrap();

    let reports = Dss::from_env()
        .unwrap()
        .validate("s06-pades-b-twice", &twice)
        .unwrap();

    assert_eq!(reports.signatures.len(), 2);
    for verdict in &reports.signatures {
        assert_eq!(
            verdict.report.indication(),
            Indication::TotalPassed,
            "{}",
            verdict.id
        );
        assert_eq!(verdict.report.sub_indication(), None, "{}", verdict.id);
        assert_eq!(verdict.format, "PAdES-BASELINE-B", "{}", verdict.id);
    }
}
