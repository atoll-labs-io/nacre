#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_core::{
    Indication, SignatureForm, SignatureLevel, SignatureProfile, SubIndication, ValidationReport,
};

// Copied from DSS 6.5.1 `SubIndication.java`, the judge (ADR-0007), without DSS's own
// `ATTESTATION_CONSTRAINTS_FAILURE`.
const DSS_SUB_INDICATIONS: [&str; 25] = [
    "FORMAT_FAILURE",
    "HASH_FAILURE",
    "SIG_CRYPTO_FAILURE",
    "REVOKED",
    "EXPIRED",
    "NOT_YET_VALID",
    "SIG_CONSTRAINTS_FAILURE",
    "CHAIN_CONSTRAINTS_FAILURE",
    "CERTIFICATE_CHAIN_GENERAL_FAILURE",
    "CRYPTO_CONSTRAINTS_FAILURE",
    "POLICY_PROCESSING_ERROR",
    "SIGNATURE_POLICY_NOT_AVAILABLE",
    "TIMESTAMP_ORDER_FAILURE",
    "NO_SIGNING_CERTIFICATE_FOUND",
    "NO_CERTIFICATE_CHAIN_FOUND",
    "NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
    "REVOKED_NO_POE",
    "REVOKED_CA_NO_POE",
    "OUT_OF_BOUNDS_NOT_REVOKED",
    "OUT_OF_BOUNDS_NO_POE",
    "REVOCATION_OUT_OF_BOUNDS_NO_POE",
    "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
    "NO_POE",
    "TRY_LATER",
    "SIGNED_DATA_NOT_FOUND",
];

#[test]
fn names_match_dss_6_5_1() {
    let names: Vec<&str> = SubIndication::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(names, DSS_SUB_INDICATIONS);
    for sub in SubIndication::ALL {
        assert_eq!(
            sub.urn(),
            format!("urn:etsi:019102:subindication:{}", sub.as_str())
        );
    }

    let indications = [
        (
            Indication::TotalPassed,
            "TOTAL_PASSED",
            "urn:etsi:019102:mainindication:total-passed",
        ),
        (
            Indication::TotalFailed,
            "TOTAL_FAILED",
            "urn:etsi:019102:mainindication:total-failed",
        ),
        (
            Indication::Indeterminate,
            "INDETERMINATE",
            "urn:etsi:019102:mainindication:indeterminate",
        ),
    ];
    for (indication, name, urn) in indications {
        assert_eq!(indication.as_str(), name);
        assert_eq!(indication.urn(), urn);
    }
}

#[test]
fn passed_carries_no_sub_indication() {
    let level = Some(SignatureLevel {
        form: SignatureForm::PAdES,
        profile: SignatureProfile::BaselineB,
    });

    let passed = ValidationReport::passed(level);
    assert_eq!(passed.indication(), Indication::TotalPassed);
    assert_eq!(passed.sub_indication(), None);
    assert_eq!(passed.level(), level);

    let failed = ValidationReport::failed(SubIndication::HashFailure, None);
    assert_eq!(failed.indication(), Indication::TotalFailed);
    assert_eq!(failed.sub_indication(), Some(SubIndication::HashFailure));

    let indeterminate = ValidationReport::indeterminate(SubIndication::TryLater, level);
    assert_eq!(indeterminate.indication(), Indication::Indeterminate);
    assert_eq!(
        indeterminate.sub_indication(),
        Some(SubIndication::TryLater)
    );
    assert_eq!(indeterminate.level(), level);
}
