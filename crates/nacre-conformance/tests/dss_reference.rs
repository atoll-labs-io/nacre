#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The bench's reference PDFs, signed at bench start with fresh keys, judged by the running
//! DSS (`conformance/README.md`). Only the verdict is asserted, never a key-dependent value.

use nacre_conformance::{Dss, SignatureVerdict, reference_dir, reports_dir};
use nacre_core::{Indication, SubIndication};

fn judge(name: &str) -> SignatureVerdict {
    let path = reference_dir().join(format!("{name}.pdf"));
    let document = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read {}: {error}; sign the references with conformance/reference/generate.sh",
            path.display()
        )
    });
    let mut reports = Dss::from_env().unwrap().validate(name, &document).unwrap();
    assert_eq!(reports.signatures.len(), 1);
    reports.signatures.remove(0)
}

#[test]
#[ignore = "conformance"]
fn reference_pdf_is_exactly_pades_baseline_b() {
    let report = reports_dir().join("pades-baseline-b.xml");
    // A report left by an earlier run must not stand in for this one.
    let _ = std::fs::remove_file(&report);

    let verdict = judge("pades-baseline-b");

    assert_eq!(verdict.report.indication(), Indication::TotalPassed);
    assert_eq!(verdict.report.sub_indication(), None);
    assert_eq!(verdict.format, "PAdES-BASELINE-B");
    assert!(report.is_file());
}

#[test]
#[ignore = "conformance"]
fn reference_pdf_signed_by_the_revoked_certificate_is_revoked_no_poe() {
    let verdict = judge("pades-baseline-b-revoked");

    assert_eq!(verdict.report.indication(), Indication::Indeterminate);
    assert_eq!(
        verdict.report.sub_indication(),
        Some(SubIndication::RevokedNoPoe)
    );
    assert_eq!(verdict.format, "PAdES-BASELINE-B");
}
