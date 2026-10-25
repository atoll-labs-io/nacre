#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::SystemTime;

use der::{Decode, Header, Reader, SliceReader};
use nacre_cms::Error as CmsError;
use nacre_core::{
    Indication, SignatureForm, SignatureLevel, SignatureProfile, SubIndication, TestSigner,
};
use nacre_pades::{DateTime, sign};
use nacre_pdf::{Document, Object};
use nacre_validate::{
    AllowedChange, Defect, LaterRevision, RevisionVerdict, RevocationDefect, SignatureValidation,
    TrustAnchors, validate, validate_with_anchors,
};

const UNSIGNED: &[u8] = include_bytes!("corpus/unsigned.pdf");
const CERTIFIED_PYHANKO: &[u8] = include_bytes!("corpus/certified-pyhanko.pdf");

fn signer() -> TestSigner {
    TestSigner::from_secret(&[0x11; 32]).unwrap()
}

fn time() -> DateTime {
    DateTime::new(2026, 10, 22, 8, 0, 0).unwrap()
}

/// The result of the signature in `field`.
fn of<'r>(results: &'r [SignatureValidation], field: &str) -> &'r SignatureValidation {
    results
        .iter()
        .find(|r| r.field == field)
        .unwrap_or_else(|| panic!("no signature {field} in {results:?}"))
}

fn verdicts(result: &SignatureValidation) -> Vec<&RevisionVerdict> {
    result.later_revisions.iter().map(|r| &r.verdict).collect()
}

/// A signature whose later revisions are all allowed, with exactly `kinds`.
fn allowed(result: &SignatureValidation, kinds: &[&[AllowedChange]]) {
    assert!(result.defect.is_none(), "{:?}", result.later_revisions);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    let expected: Vec<RevisionVerdict> = kinds
        .iter()
        .map(|k| RevisionVerdict::Allowed(k.to_vec()))
        .collect();
    assert_eq!(verdicts(result), expected.iter().collect::<Vec<_>>());
}

/// A sound signature failed by its later revision ending at `end`.
fn refused_revision(result: &SignatureValidation) -> &LaterRevision {
    let Some(Defect::RevisionNotAllowed { end }) = result.defect else {
        panic!("{:?}: {:?}", result.defect, result.later_revisions);
    };
    assert_eq!(result.report.indication(), Indication::TotalFailed);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::FormatFailure)
    );
    assert!(result.digest_verified && result.signature_verified);
    let revision = result
        .later_revisions
        .iter()
        .find(|r| r.end == end)
        .unwrap();
    assert!(
        matches!(&revision.verdict, RevisionVerdict::NotAllowed { refused } if !refused.is_empty()),
        "{revision:?}"
    );
    revision
}

fn signed() -> Vec<u8> {
    let signer = TestSigner::from_secret(&[0x11; 32]).unwrap();
    sign(
        UNSIGNED,
        &signer,
        DateTime::new(2026, 10, 22, 8, 0, 0).unwrap(),
    )
    .unwrap()
}

/// The offset of the first hex digit of `/Contents`, and the DER length it holds.
fn contents_slot(pdf: &[u8]) -> (usize, usize) {
    let doc = Document::parse(pdf).unwrap();
    let field = &doc.signature_fields()[0];
    let Object::Dictionary(sig) = doc.object(field.value.unwrap()).unwrap() else {
        panic!("/V is not a dictionary");
    };
    let Some(Object::Array(range)) = sig.get(b"ByteRange") else {
        panic!("no /ByteRange");
    };
    let Object::Integer(gap_start) = range[1] else {
        panic!("non-integer in /ByteRange");
    };
    let Some(Object::String(contents)) = sig.get(b"Contents") else {
        panic!("no /Contents");
    };
    let mut reader = SliceReader::new(contents).unwrap();
    let header = Header::decode(&mut reader).unwrap();
    let der_len = usize::try_from((reader.position() + header.length()).unwrap()).unwrap();
    (usize::try_from(gap_start).unwrap() + 1, der_len)
}

#[test]
fn s06_signature_is_verified_but_indeterminate() {
    let results = validate(&signed()).unwrap();

    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.field, "Signature1");
    assert!(result.digest_verified);
    assert!(result.signature_verified);
    assert!(result.defect.is_none(), "{:?}", result.defect);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::NoCertificateChainFound)
    );
    assert_eq!(
        result.report.level(),
        Some(SignatureLevel {
            form: SignatureForm::PAdES,
            profile: SignatureProfile::BaselineB
        })
    );
}

#[test]
fn third_party_signature_is_verified() {
    let results = validate(CERTIFIED_PYHANKO).unwrap();

    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.field, "Certification");
    assert!(result.defect.is_none(), "{:?}", result.defect);
    assert!(result.digest_verified);
    assert!(result.signature_verified);
}

#[test]
fn changed_signed_byte_is_hash_failure() {
    let mut pdf = signed();
    let at = pdf
        .windows(b"(Nacre".len())
        .position(|w| w == b"(Nacre")
        .unwrap();
    pdf[at + 1] = b'M';

    let result = &validate(&pdf).unwrap()[0];

    assert_eq!(result.report.indication(), Indication::TotalFailed);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::HashFailure)
    );
    assert!(!result.digest_verified);
    assert!(
        matches!(
            result.defect,
            Some(Defect::Cms(CmsError::MessageDigestMismatch))
        ),
        "{:?}",
        result.defect
    );
}

#[test]
fn altered_signature_value_is_sig_crypto_failure() {
    let mut pdf = signed();
    let (start, der_len) = contents_slot(&pdf);
    let last_digit = start + 2 * der_len - 1;
    pdf[last_digit] = if pdf[last_digit] == b'0' { b'1' } else { b'0' };

    let result = &validate(&pdf).unwrap()[0];

    assert_eq!(result.report.indication(), Indication::TotalFailed);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::SigCryptoFailure)
    );
    assert!(result.digest_verified);
    assert!(!result.signature_verified);
}

#[test]
fn twice_signed_first_signature_has_an_allowed_signature_revision() {
    let twice = sign(&signed(), &signer(), time()).unwrap();

    let results = validate(&twice).unwrap();

    allowed(of(&results, "Signature1"), &[&[AllowedChange::Signature]]);
    allowed(of(&results, "Signature2"), &[]);
}

#[test]
fn pyhanko_twice_signed_is_allowed() {
    let results = validate(include_bytes!("corpus/signed-twice-pyhanko.pdf")).unwrap();

    assert_eq!(results.len(), 2);
    allowed(of(&results, "Sig1"), &[]);
    allowed(of(&results, "Sig2"), &[&[AllowedChange::Signature]]);
}

#[test]
fn lta_dss_and_timestamp_are_allowed() {
    let pdf = include_bytes!("corpus/signed-lta-pyhanko.pdf");
    let results = validate(pdf).unwrap();

    assert_eq!(results.len(), 1);
    let sig = of(&results, "Sig1");
    allowed(
        sig,
        &[
            &[AllowedChange::Dss, AllowedChange::DocumentTimestamp],
            &[AllowedChange::Dss],
        ],
    );
    let catalog = Document::parse(pdf).unwrap().catalog_id();
    assert!(sig.later_revisions[0].changed.contains(&catalog));
}

#[test]
fn signing_a_certified_p3_document_is_allowed() {
    let pdf = sign(CERTIFIED_PYHANKO, &signer(), time()).unwrap();

    let results = validate(&pdf).unwrap();

    allowed(
        of(&results, "Certification"),
        &[&[AllowedChange::Signature]],
    );
}

#[test]
fn certified_visible_field_signed_is_allowed() {
    let results = validate(include_bytes!("corpus/certified-visible-field-signed.pdf")).unwrap();

    allowed(
        of(&results, "Certification"),
        &[&[AllowedChange::Signature]],
    );
    allowed(of(&results, "Approver"), &[]);
}

#[test]
fn certified_form_fill_is_allowed() {
    let results = validate(include_bytes!("corpus/certified-form-fill.pdf")).unwrap();

    allowed(of(&results, "Certification"), &[&[AllowedChange::FormFill]]);
}

#[test]
fn form_fill_under_p1_is_not_allowed() {
    let results = validate(include_bytes!("corpus/certified-p1-form-fill.pdf")).unwrap();

    let revision = refused_revision(of(&results, "Certification"));
    assert!(revision.changed.contains(&nacre_pdf::ObjectId::new(7, 0)));
}

#[test]
fn locked_field_fill_is_not_allowed() {
    let results = validate(include_bytes!("corpus/fieldmdp-locked-fill.pdf")).unwrap();

    let certification = of(&results, "Certification");
    assert_eq!(
        verdicts(certification)[0],
        &RevisionVerdict::Allowed(vec![AllowedChange::Signature])
    );
    refused_revision(certification);
    refused_revision(of(&results, "Approval"));
}

#[test]
fn second_signer_beside_a_refused_fill_is_judged_alone() {
    let results = validate(include_bytes!("corpus/fill-and-second-signature.pdf")).unwrap();

    let revision = refused_revision(of(&results, "Signature1"));
    assert!(revision.changed.contains(&nacre_pdf::ObjectId::new(7, 0)));
    let bob = of(&results, "Bob");
    assert!(bob.later_revisions.is_empty());
    allowed(bob, &[]);
}

#[test]
fn revision_over_the_docmdp_cap_lists_its_objects() {
    let pdf = include_bytes!("corpus/docmdp-reference-cap.pdf");
    let doc = Document::parse(pdf).unwrap();
    let catalog = doc.catalog_id();
    let Some(Object::Dictionary(perms)) = doc.catalog().get(b"Perms") else {
        panic!("no direct /Perms");
    };
    let Some(Object::Reference(hostile)) = perms.get(b"DocMDP") else {
        panic!("no /DocMDP reference");
    };

    let results = validate(pdf).unwrap();

    let certification = of(&results, "Certification");
    let revisions = &certification.later_revisions;
    assert_eq!(revisions.len(), 3);
    assert_eq!(
        verdicts(certification)[..2],
        [
            &RevisionVerdict::Allowed(vec![AllowedChange::FormFill]),
            &RevisionVerdict::Unreadable,
        ]
    );
    // The permission no longer reads, so the next revisions are judged under /P 1.
    assert!(
        matches!(&revisions[2].verdict, RevisionVerdict::NotAllowed { refused } if !refused.is_empty()),
        "{:?}",
        revisions[2]
    );
    assert_eq!(revisions[1].changed, {
        let mut ids = vec![catalog, *hostile];
        ids.sort_unstable();
        ids
    });
    assert!(
        matches!(certification.defect, Some(Defect::RevisionNotAllowed { end }) if end == revisions[1].end),
        "{:?}",
        certification.defect
    );
    let late = of(&results, "Late");
    assert!(late.digest_verified && late.signature_verified);
    assert!(
        matches!(late.defect, Some(Defect::AddedByRevisionNotAllowed { end }) if end == pdf.len()),
        "{:?}",
        late.defect
    );
}

#[test]
fn signature_added_under_p1_is_refused_with_its_revision() {
    let pdf = include_bytes!("corpus/certified-p1-second-signature.pdf");
    let results = validate(pdf).unwrap();

    refused_revision(of(&results, "Certification"));
    let late = of(&results, "Late");
    assert_eq!(late.report.indication(), Indication::TotalFailed);
    assert!(late.digest_verified && late.signature_verified);
    assert!(
        matches!(late.defect, Some(Defect::AddedByRevisionNotAllowed { end }) if end == pdf.len()),
        "{:?}",
        late.defect
    );
}

const CHAIN_ROOT: &[u8] = include_bytes!("corpus/chain/root.der");
const CHAIN_INTERMEDIATE: &[u8] = include_bytes!("corpus/chain/intermediate.der");
const CHAIN_LEAF: &[u8] = include_bytes!("corpus/chain/leaf.der");

/// The single signature of `pdf`, validated with the chain corpus root as anchor on
/// 2026-10-22.
fn with_root(pdf: &[u8]) -> SignatureValidation {
    let anchors = TrustAnchors::from_certificates([CHAIN_ROOT]).unwrap();
    let at: SystemTime =
        x509_cert::time::Time::from(der::DateTime::new(2026, 10, 22, 0, 0, 0).unwrap())
            .to_system_time();
    let mut results = validate_with_anchors(pdf, &anchors, at).unwrap();
    assert_eq!(results.len(), 1);
    results.remove(0)
}

/// A signature whose chain is valid, with no revocation data to judge it by.
fn chain_valid(result: &SignatureValidation) {
    assert!(
        matches!(
            result.defect,
            Some(Defect::Revocation(RevocationDefect::Missing { depth: 0 }))
        ),
        "{:?}",
        result.defect
    );
    assert!(result.digest_verified && result.signature_verified);
    let chain = result.chain.as_ref().unwrap();
    assert_eq!(
        chain.certificates,
        vec![CHAIN_LEAF, CHAIN_INTERMEDIATE, CHAIN_ROOT]
    );
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::CertificateChainGeneralFailure)
    );
    assert_eq!(
        result.report.level(),
        Some(SignatureLevel {
            form: SignatureForm::PAdES,
            profile: SignatureProfile::BaselineB
        })
    );
}

#[test]
fn chain_from_cms_is_valid_but_revocation_missing() {
    let pdf = include_bytes!("corpus/chain/chain-cms.pdf");

    chain_valid(&with_root(pdf));

    let untrusted = &validate(pdf).unwrap()[0];
    assert!(untrusted.defect.is_none(), "{:?}", untrusted.defect);
    assert!(untrusted.chain.is_none());
    assert_eq!(untrusted.report.indication(), Indication::Indeterminate);
    assert_eq!(
        untrusted.report.sub_indication(),
        Some(SubIndication::NoCertificateChainFound)
    );
}

#[test]
fn chain_from_dss_is_valid() {
    let result = with_root(include_bytes!("corpus/chain/chain-dss.pdf"));

    chain_valid(&result);
    assert_eq!(
        verdicts(&result),
        [&RevisionVerdict::Allowed(vec![AllowedChange::Dss])]
    );
}

#[test]
fn revision_defect_outranks_chain() {
    let result = with_root(include_bytes!(
        "corpus/chain/chain-cms-refused-revision.pdf"
    ));

    refused_revision(&result);
    assert!(result.chain.is_none());
}
