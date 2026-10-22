#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::{Decode, Header, Reader, SliceReader};
use nacre_cms::Error as CmsError;
use nacre_core::{Indication, SubIndication, TestSigner};
use nacre_pades::{DateTime, sign};
use nacre_pdf::{Document, Object};
use nacre_validate::{Defect, validate};

const UNSIGNED: &[u8] = include_bytes!("corpus/unsigned.pdf");
const CERTIFIED_DSS: &[u8] = include_bytes!("corpus/certified-dss.pdf");

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
    assert_eq!(result.report.level(), None);
}

#[test]
fn third_party_signature_is_verified() {
    let results = validate(CERTIFIED_DSS).unwrap();

    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.field, "signature-test");
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
