#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_conformance::{Error, level, parse_response};
use nacre_core::{Indication, SignatureForm, SignatureLevel, SignatureProfile, SubIndication};

const BASELINE_B: &[u8] = include_bytes!("corpus/dss-6.5.1-pades-baseline-b.json");
const REVOKED: &[u8] = include_bytes!("corpus/dss-6.5.1-pades-baseline-b-revoked.json");

#[test]
fn recorded_baseline_b_reads_total_passed_at_pades_baseline_b() {
    let reports = parse_response(BASELINE_B).unwrap();

    assert_eq!(reports.signatures.len(), 1);
    let signature = &reports.signatures[0];
    assert!(signature.id.starts_with("S-"));
    assert_eq!(signature.format, "PAdES-BASELINE-B");
    assert_eq!(signature.report.indication(), Indication::TotalPassed);
    assert_eq!(signature.report.sub_indication(), None);
    assert_eq!(
        signature.report.level(),
        Some(SignatureLevel {
            form: SignatureForm::PAdES,
            profile: SignatureProfile::BaselineB,
        })
    );
}

#[test]
fn recorded_revoked_keeps_its_exact_indication_and_sub_indication() {
    let reports = parse_response(REVOKED).unwrap();

    assert_eq!(reports.signatures.len(), 1);
    let report = &reports.signatures[0].report;
    assert_eq!(report.indication(), Indication::Indeterminate);
    assert_eq!(report.sub_indication(), Some(SubIndication::RevokedNoPoe));
}

fn recorded_with_signature_edit(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut response: serde_json::Value = serde_json::from_slice(BASELINE_B).unwrap();
    let signature = response["SimpleReport"]["signatureOrTimestampOrEvidenceRecord"][0]
        .get_mut("Signature")
        .unwrap();
    edit(signature);
    serde_json::to_vec(&response).unwrap()
}

#[test]
fn inconsistent_verdicts_are_errors_not_panics() {
    let without_indication = recorded_with_signature_edit(|signature| {
        signature.as_object_mut().unwrap().remove("Indication");
    });
    let passed_with_sub_indication = recorded_with_signature_edit(|signature| {
        signature["SubIndication"] = "REVOKED_NO_POE".into();
    });

    assert!(matches!(
        parse_response(&without_indication),
        Err(Error::Report(_))
    ));
    assert!(matches!(
        parse_response(&passed_with_sub_indication),
        Err(Error::Report(_))
    ));
}

#[test]
fn level_reads_form_and_profile_from_dss_format_names() {
    let at = |form, profile| Some(SignatureLevel { form, profile });

    assert_eq!(
        level("PAdES-BASELINE-LTA"),
        at(SignatureForm::PAdES, SignatureProfile::BaselineLta)
    );
    assert_eq!(
        level("CAdES-BASELINE-T"),
        at(SignatureForm::CAdES, SignatureProfile::BaselineT)
    );
    assert_eq!(
        level("XAdES-BASELINE-LT"),
        at(SignatureForm::XAdES, SignatureProfile::BaselineLt)
    );
    assert_eq!(
        level("PAdES-BES"),
        at(SignatureForm::PAdES, SignatureProfile::ExtendedBes)
    );
    assert_eq!(level("PDF-NOT-ETSI"), None);
}

#[test]
fn recorded_response_carries_the_etsi_validation_report() {
    let reports = parse_response(BASELINE_B).unwrap();

    assert!(reports.etsi_xml.starts_with("<?xml"));
    assert!(reports.etsi_xml.contains("ValidationReport"));
}
