#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! One test per file of `corpus/attacks/` (`docs/security/attacks/pades.md`). Each file
//! has one defect, so each must fail on its own rule.

use nacre_core::{ErrorKind, Indication, SubIndication};
use std::time::SystemTime;

use nacre_validate::{
    ChainDefect, Defect, Error, ObjectId, RevisionVerdict, RevocationDefect, SignatureValidation,
    TrustAnchors, validate, validate_with_anchors,
};

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
    refused_by_revision(&validate(file).unwrap()[0])
}

/// The objects refused by the later revision that fails `result`, sound in itself.
fn refused_by_revision(result: &SignatureValidation) -> Vec<ObjectId> {
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
    let results = validate(file).unwrap();
    let certification = results.iter().find(|r| r.field == "Certification").unwrap();
    refused_by_revision(certification);

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

#[test]
fn ssa_zero_rect_shown_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-zero-rect-shown.pdf"));
}

#[test]
fn ssa_hidden_widget_shown_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-hidden-widget-shown.pdf"));
}

#[test]
fn ssa_indirect_rect_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-indirect-rect.pdf"));
}

#[test]
fn ssa_kid_widget_shown_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-kid-widget-shown.pdf"));
}

#[test]
fn ssa_orphan_widget_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-orphan-widget.pdf"));
}

#[test]
fn ssa_unlisted_widget_shown_is_rejected() {
    sneaky_refused(include_bytes!(
        "corpus/attacks/ssa-unlisted-widget-shown.pdf"
    ));
}

#[test]
fn ssa_layer_widget_shown_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-layer-widget-shown.pdf"));
}

#[test]
fn ssa_moved_rect_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-moved-rect.pdf"));
}

#[test]
fn ssa_unreadable_rect_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-unreadable-rect.pdf"));
}

#[test]
fn ssa_toggle_noview_shown_is_rejected() {
    sneaky_refused(include_bytes!("corpus/attacks/ssa-toggle-noview-shown.pdf"));
}

/// The signature outside `/Fields` is not listed, so only the certification shows it:
/// the page, the field, its signature dictionary and its appearance are refused.
#[test]
fn ssa_outside_fields_is_rejected() {
    let file = include_bytes!("corpus/attacks/ssa-outside-fields.pdf");
    assert_eq!(validate(file).unwrap().len(), 1);
    assert_eq!(revision_refused(file), ids(&[3, 11, 12, 13]));
}

/// The single signature of `file`, validated with the chain corpus root as anchor on
/// 2026-10-22.
fn with_chain_root(file: &[u8]) -> SignatureValidation {
    let anchors =
        TrustAnchors::from_certificates([&include_bytes!("corpus/chain/root.der")[..]]).unwrap();
    let at: SystemTime =
        x509_cert::time::Time::from(der::DateTime::new(2026, 10, 22, 0, 0, 0).unwrap())
            .to_system_time();
    let mut results = validate_with_anchors(file, &anchors, at).unwrap();
    assert_eq!(results.len(), 1);
    results.remove(0)
}

/// The chain defect of the single signature of `file`, sound in itself, with `sub`.
fn chain_rejected(file: &[u8], sub: SubIndication) -> ChainDefect {
    let result = with_chain_root(file);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(result.report.sub_indication(), Some(sub));
    assert!(result.digest_verified && result.signature_verified);
    assert!(result.chain.is_none());
    let Some(Defect::Chain(defect)) = result.defect else {
        panic!("{:?}", result.defect);
    };
    defect
}

#[test]
fn chain_impostor_root_is_rejected() {
    let result = with_chain_root(include_bytes!("corpus/attacks/chain-impostor-root.pdf"));

    assert!(result.defect.is_none(), "{:?}", result.defect);
    assert!(result.chain.is_none());
    assert!(result.digest_verified && result.signature_verified);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::NoCertificateChainFound)
    );
}

#[test]
fn chain_leaf_as_ca_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-leaf-as-ca.pdf"),
        SubIndication::ChainConstraintsFailure,
    );
    assert_eq!(defect, ChainDefect::NotACa { depth: 1 });
}

#[test]
fn chain_path_length_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-path-length.pdf"),
        SubIndication::ChainConstraintsFailure,
    );
    assert_eq!(defect, ChainDefect::PathLength { depth: 2 });
}

#[test]
fn chain_expired_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-expired.pdf"),
        SubIndication::OutOfBoundsNoPoe,
    );
    assert_eq!(defect, ChainDefect::Expired { depth: 0 });
}

#[test]
fn chain_key_usage_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-key-usage.pdf"),
        SubIndication::ChainConstraintsFailure,
    );
    assert_eq!(defect, ChainDefect::KeyUsage);
}

#[test]
fn chain_critical_extension_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-critical-extension.pdf"),
        SubIndication::CertificateChainGeneralFailure,
    );
    assert!(
        matches!(
            defect,
            ChainDefect::UnsupportedCriticalExtension { depth: 1, .. }
        ),
        "{defect:?}"
    );
}

#[test]
fn chain_not_yet_valid_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-not-yet-valid.pdf"),
        SubIndication::OutOfBoundsNoPoe,
    );
    assert_eq!(defect, ChainDefect::NotYetValid { depth: 0 });
}

#[test]
fn chain_ca_key_usage_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-ca-key-usage.pdf"),
        SubIndication::ChainConstraintsFailure,
    );
    assert_eq!(defect, ChainDefect::CaKeyUsage { depth: 1 });
}

#[test]
fn chain_extended_key_usage_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-extended-key-usage.pdf"),
        SubIndication::ChainConstraintsFailure,
    );
    assert_eq!(defect, ChainDefect::ExtendedKeyUsage { depth: 0 });
}

#[test]
fn chain_malformed_extension_is_rejected() {
    let defect = chain_rejected(
        include_bytes!("corpus/attacks/chain-malformed-extension.pdf"),
        SubIndication::CertificateChainGeneralFailure,
    );
    assert_eq!(defect, ChainDefect::MalformedExtension { depth: 0 });
}

/// `chain-cms.pdf` given an appended `/DSS` of 300 unreadable streams: the unsigned pool is
/// a hint, so the chain the CMS proves still stands, its revocation left without data.
#[test]
fn chain_dss_junk_does_not_hide_the_chain() {
    let result = with_chain_root(include_bytes!("corpus/attacks/chain-dss-junk.pdf"));

    assert!(
        matches!(
            result.defect,
            Some(Defect::Revocation(RevocationDefect::Missing { depth: 0 }))
        ),
        "{:?}",
        result.defect
    );
    let chain = result.chain.expect("the CMS chain");
    let expected: [&[u8]; 3] = [
        include_bytes!("corpus/chain/leaf.der"),
        include_bytes!("corpus/chain/intermediate.der"),
        include_bytes!("corpus/chain/root.der"),
    ];
    assert_eq!(chain.certificates, expected);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::CertificateChainGeneralFailure)
    );
}
