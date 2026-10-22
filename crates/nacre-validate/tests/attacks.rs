#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! One test per file of `corpus/attacks/` (`docs/security/attacks/pades.md`). Each file
//! has one defect, so each must fail on its own rule.

use nacre_core::{ErrorKind, Indication, SubIndication};
use nacre_validate::{Defect, Error, validate};

/// The single signature of `file`, checked to be refused as a format failure.
fn rejected(file: &[u8]) -> Defect {
    let mut results = validate(file).unwrap();
    assert_eq!(results.len(), 1);
    let result = results.remove(0);
    assert_eq!(result.report.indication(), Indication::TotalFailed);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::FormatFailure)
    );
    assert!(!result.digest_verified && !result.signature_verified);
    result.defect.unwrap()
}

#[test]
fn usf_contents_missing_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/usf-contents-missing.pdf"));
    assert!(matches!(defect, Defect::ContentsMissing), "{defect:?}");
}

#[test]
fn usf_contents_null_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/usf-contents-null.pdf"));
    assert!(matches!(defect, Defect::ContentsMissing), "{defect:?}");
}

#[test]
fn usf_contents_empty_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/usf-contents-empty.pdf"));
    assert!(matches!(defect, Defect::ContentsMissing), "{defect:?}");
}

#[test]
fn usf_contents_zeros_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/usf-contents-zeros.pdf"));
    assert!(matches!(defect, Defect::ContentsNotDer), "{defect:?}");
}

#[test]
fn usf_byterange_missing_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/usf-byterange-missing.pdf"));
    assert!(matches!(defect, Defect::ByteRangeMalformed), "{defect:?}");
}

#[test]
fn usf_byterange_null_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/usf-byterange-null.pdf"));
    assert!(matches!(defect, Defect::ByteRangeMalformed), "{defect:?}");
}

#[test]
fn usf_byterange_short_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/usf-byterange-short.pdf"));
    assert!(matches!(defect, Defect::ByteRangeMalformed), "{defect:?}");
}

#[test]
fn byterange_not_from_start_is_rejected() {
    let defect = rejected(include_bytes!(
        "corpus/attacks/byterange-not-from-start.pdf"
    ));
    assert!(
        matches!(defect, Defect::ByteRangeNotFromStart),
        "{defect:?}"
    );
}

#[test]
fn byterange_overlap_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/byterange-overlap.pdf"));
    assert!(matches!(defect, Defect::ByteRangeOverlap), "{defect:?}");
}

#[test]
fn byterange_outside_file_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/byterange-outside-file.pdf"));
    assert!(matches!(defect, Defect::ByteRangeOutsideFile), "{defect:?}");
}

#[test]
fn byterange_not_whole_file_is_rejected() {
    let defect = rejected(include_bytes!(
        "corpus/attacks/byterange-not-whole-file.pdf"
    ));
    assert!(
        matches!(defect, Defect::ByteRangeNotWholeFile),
        "{defect:?}"
    );
}

#[test]
fn swa_wrapped_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/swa-wrapped.pdf"));
    assert!(matches!(defect, Defect::GapNotContents), "{defect:?}");
}

#[test]
fn isa_appended_revision_is_rejected() {
    let defect = rejected(include_bytes!("corpus/attacks/isa-appended-revision.pdf"));
    assert!(matches!(defect, Defect::LaterRevision), "{defect:?}");
}

#[test]
fn isa_no_xref_is_rejected() {
    let error = validate(include_bytes!("corpus/attacks/isa-no-xref.pdf")).unwrap_err();
    assert!(
        matches!(error, Error::Pdf(nacre_pdf::Error::TrailingData { .. })),
        "{error:?}"
    );
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
