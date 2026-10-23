#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! One test per file of `corpus/attacks/` (`docs/security/attacks/pades.md`). Each file
//! has one defect, so each must fail on its own rule.

use nacre_core::{ErrorKind, Indication, SubIndication};
use nacre_validate::{Defect, Error, ObjectId, RevisionVerdict, SignatureValidation, validate};

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

/// The first signature of `file`, sound in itself, refused for a later revision: the
/// objects that revision's verdict refuses.
fn revision_refused(file: &[u8]) -> Vec<ObjectId> {
    let results = validate(file).unwrap();
    let result: &SignatureValidation = &results[0];
    assert_eq!(result.report.indication(), Indication::TotalFailed);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::FormatFailure)
    );
    assert!(result.digest_verified && result.signature_verified);
    let Some(Defect::RevisionNotAllowed { end }) = result.defect else {
        panic!("{:?}", result.defect);
    };
    let revision = result
        .later_revisions
        .iter()
        .find(|r| r.end == end)
        .unwrap();
    let RevisionVerdict::NotAllowed { refused } = &revision.verdict else {
        panic!("{revision:?}");
    };
    assert!(!refused.is_empty());
    assert!(refused.iter().all(|id| revision.changed.contains(id)));
    refused.clone()
}

fn ids(numbers: &[u32]) -> Vec<ObjectId> {
    numbers.iter().map(|n| ObjectId::new(*n, 0)).collect()
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
    revision_refused(include_bytes!("corpus/attacks/isa-appended-revision.pdf"));
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

#[test]
fn shadow_hide_is_rejected() {
    let refused = revision_refused(include_bytes!("corpus/attacks/shadow-hide.pdf"));
    assert_eq!(refused, ids(&[6]));
}

#[test]
fn shadow_replace_is_rejected() {
    let refused = revision_refused(include_bytes!("corpus/attacks/shadow-replace.pdf"));
    assert_eq!(refused, ids(&[5]));
}

#[test]
fn shadow_hide_and_replace_is_rejected() {
    let refused = revision_refused(include_bytes!("corpus/attacks/shadow-hide-and-replace.pdf"));
    assert_eq!(refused, ids(&[7]));
}

#[test]
fn shadow_late_definition_is_rejected() {
    let refused = revision_refused(include_bytes!("corpus/attacks/shadow-late-definition.pdf"));
    assert_eq!(refused, ids(&[50]));
}

#[test]
fn shadow_dss_page_is_rejected() {
    let refused = revision_refused(include_bytes!("corpus/attacks/shadow-dss-page.pdf"));
    assert_eq!(refused, ids(&[7]));
}

#[test]
fn shadow_fill_late_definition_is_rejected() {
    let refused = revision_refused(include_bytes!(
        "corpus/attacks/shadow-fill-late-definition.pdf"
    ));
    assert_eq!(refused, ids(&[50]));
}

#[test]
fn shadow_form_field_is_rejected() {
    let refused = revision_refused(include_bytes!("corpus/attacks/shadow-form-field.pdf"));
    assert!(refused.contains(&ObjectId::new(7, 0)), "{refused:?}");
}

#[test]
fn eaa_freetext_is_rejected() {
    revision_refused(include_bytes!("corpus/attacks/eaa-freetext.pdf"));
}

/// The certification refused for a later revision, and the signature `Sneaky`, sound in
/// itself, refused by the revision that adds it.
fn sneaky_refused(file: &[u8]) {
    revision_refused(file);

    let results = validate(file).unwrap();
    let sneaky = results.iter().find(|r| r.field == "Sneaky").unwrap();
    assert_eq!(sneaky.report.indication(), Indication::TotalFailed);
    assert_eq!(
        sneaky.report.sub_indication(),
        Some(SubIndication::FormatFailure)
    );
    assert!(sneaky.digest_verified && sneaky.signature_verified);
    assert!(
        matches!(sneaky.defect, Some(Defect::AddedByRevisionNotAllowed { end }) if end == file.len()),
        "{:?}",
        sneaky.defect
    );
}

#[test]
fn ssa_visible_signature_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-visible-signature.pdf"));
}

#[test]
fn ssa_split_widget_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-split-widget.pdf"));
}

#[test]
fn ssa_empty_field_signed_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-empty-field-signed.pdf"));
}
