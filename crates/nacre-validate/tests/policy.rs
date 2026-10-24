#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Each switch of `ValidationPolicy` (ADR-0026), on committed attack files: the verdict of
//! `strict()`, then that of `strict()` with that one switch off.

use std::time::SystemTime;

use nacre_core::{Indication, SubIndication};
use nacre_validate::{
    ChainDefect, Defect, Error, RevocationDefect, SignatureValidation, TrustAnchors,
    ValidationPolicy, validate_with_policy,
};

fn judge(file: &[u8], policy: &ValidationPolicy) -> Result<Vec<SignatureValidation>, Error> {
    validate_with_policy(
        file,
        &TrustAnchors::default(),
        SystemTime::UNIX_EPOCH,
        None,
        policy,
    )
}

fn strict_without(off: impl FnOnce(&mut ValidationPolicy)) -> ValidationPolicy {
    let mut policy = ValidationPolicy::strict();
    off(&mut policy);
    policy
}

/// A signature with no defect and no anchor: `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`.
fn sound(result: &SignatureValidation) {
    assert!(
        result.defect.is_none(),
        "{}: {:?}",
        result.field,
        result.defect
    );
    assert!(result.digest_verified && result.signature_verified);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::NoCertificateChainFound)
    );
}

fn single(mut results: Vec<SignatureValidation>) -> SignatureValidation {
    assert_eq!(results.len(), 1);
    results.remove(0)
}

/// (a) Later revisions: an appended revision and signed bytes ending at no revision.
#[test]
fn later_revisions_switch() {
    let off = strict_without(|p| p.refuse_later_revisions = false);

    let appended = include_bytes!("corpus/attacks/isa-appended-revision.pdf");
    let strict = single(judge(appended, &ValidationPolicy::strict()).unwrap());
    assert!(
        matches!(strict.defect, Some(Defect::RevisionNotAllowed { .. })),
        "{:?}",
        strict.defect
    );
    let lax = single(judge(appended, &off).unwrap());
    sound(&lax);
    assert!(!lax.later_revisions.is_empty());

    let short = include_bytes!("corpus/attacks/byterange-not-whole-file.pdf");
    let strict = single(judge(short, &ValidationPolicy::strict()).unwrap());
    assert!(
        matches!(strict.defect, Some(Defect::ByteRangeNotWholeFile)),
        "{:?}",
        strict.defect
    );
    sound(&single(judge(short, &off).unwrap()));
}

/// (b) Sneaky signatures: with the switch off, both the certification and the sneaky
/// signature are sound.
#[test]
fn sneaky_signatures_switch() {
    let file = include_bytes!("corpus/attacks/ssa-visible-signature.pdf");
    let strict = judge(file, &ValidationPolicy::strict()).unwrap();
    let sneaky = strict.iter().find(|r| r.field == "Sneaky").unwrap();
    assert!(
        matches!(
            sneaky.defect,
            Some(Defect::AddedByRevisionNotAllowed { .. })
        ),
        "{:?}",
        sneaky.defect
    );

    let lax = judge(
        file,
        &strict_without(|p| p.refuse_sneaky_signatures = false),
    )
    .unwrap();
    assert_eq!(lax.len(), 2);
    lax.iter().for_each(sound);
}

/// (c) Trailing data: the file is judged as it stands before the data.
#[test]
fn trailing_data_switch() {
    let file = include_bytes!("corpus/attacks/isa-no-xref.pdf");
    let error = judge(file, &ValidationPolicy::strict()).unwrap_err();
    assert!(
        matches!(error, Error::Pdf(nacre_pdf::Error::TrailingData { .. })),
        "{error:?}"
    );

    let lax = judge(file, &strict_without(|p| p.refuse_trailing_data = false)).unwrap();
    sound(&single(lax));
}

/// (d) Unusable signatures: left out with the switch off, and only those.
#[test]
fn unusable_signatures_switch() {
    let off = strict_without(|p| p.list_unusable_signatures = false);
    for file in [
        &include_bytes!("corpus/attacks/usf-contents-missing.pdf")[..],
        include_bytes!("corpus/attacks/usf-contents-zeros.pdf"),
    ] {
        assert_eq!(judge(file, &ValidationPolicy::strict()).unwrap().len(), 1);
        assert!(judge(file, &off).unwrap().is_empty());
    }

    let overlap =
        single(judge(include_bytes!("corpus/attacks/byterange-overlap.pdf"), &off).unwrap());
    assert!(
        matches!(overlap.defect, Some(Defect::ByteRangeOverlap)),
        "{:?}",
        overlap.defect
    );
    assert_eq!(overlap.report.indication(), Indication::TotalFailed);
}

/// The single signature of `file`, judged under `policy` with the chain corpus root as
/// anchor on 2026-10-22.
fn with_chain_root(file: &[u8], policy: &ValidationPolicy) -> Result<SignatureValidation, Error> {
    let anchors =
        TrustAnchors::from_certificates([&include_bytes!("corpus/chain/root.der")[..]]).unwrap();
    let at: SystemTime =
        x509_cert::time::Time::from(der::DateTime::new(2026, 10, 22, 0, 0, 0).unwrap())
            .to_system_time();
    validate_with_policy(file, &anchors, at, None, policy).map(single)
}

fn sub(result: &SignatureValidation) -> Option<SubIndication> {
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    result.report.sub_indication()
}

/// The path is kept and only its missing revocation data refuses it.
fn revocation_missing(result: &SignatureValidation) {
    assert_eq!(
        sub(result),
        Some(SubIndication::CertificateChainGeneralFailure)
    );
    assert!(result.chain.is_some());
    assert!(
        matches!(
            result.defect,
            Some(Defect::Revocation(RevocationDefect::Missing { depth: 0 }))
        ),
        "{:?}",
        result.defect
    );
}

/// (e) Signer key usage: `keyUsage` and `extendedKeyUsage` of the leaf.
#[test]
fn signer_key_usage_switch() {
    let off = strict_without(|p| p.judge_signer_key_usage = false);
    for file in [
        &include_bytes!("corpus/attacks/chain-key-usage.pdf")[..],
        include_bytes!("corpus/attacks/chain-extended-key-usage.pdf"),
    ] {
        let strict = with_chain_root(file, &ValidationPolicy::strict()).unwrap();
        assert_eq!(sub(&strict), Some(SubIndication::ChainConstraintsFailure));
        revocation_missing(&with_chain_root(file, &off).unwrap());
    }
}

/// (f) Malformed extensions: a verdict under `strict()`, an error with the switch off.
#[test]
fn malformed_extensions_switch() {
    let file = include_bytes!("corpus/attacks/chain-malformed-extension.pdf");
    let strict = with_chain_root(file, &ValidationPolicy::strict()).unwrap();
    assert!(
        matches!(
            strict.defect,
            Some(Defect::Chain(ChainDefect::MalformedExtension { .. }))
        ),
        "{:?}",
        strict.defect
    );

    let error = with_chain_root(
        file,
        &strict_without(|p| p.judge_malformed_extensions = false),
    )
    .unwrap_err();
    assert!(matches!(error, Error::MalformedCertificate), "{error:?}");
}

/// (g) Validity before revocation, with no data: the missing data decides first.
#[test]
fn validity_before_revocation_switch() {
    let file = include_bytes!("corpus/attacks/chain-expired.pdf");
    let strict = with_chain_root(file, &ValidationPolicy::strict()).unwrap();
    assert_eq!(sub(&strict), Some(SubIndication::OutOfBoundsNoPoe));

    let lax = with_chain_root(
        file,
        &strict_without(|p| p.judge_validity_before_revocation = false),
    )
    .unwrap();
    revocation_missing(&lax);
}
