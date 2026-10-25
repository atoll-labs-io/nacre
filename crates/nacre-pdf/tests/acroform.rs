#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use nacre_pdf::Document;

/// `pdf` with its single `from` replaced by `to`, padded with spaces so no offset moves.
fn patch(pdf: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = pdf.windows(from.len()).position(|w| w == from).unwrap();
    assert!(!pdf[at + 1..].windows(from.len()).any(|w| w == from));
    let mut out = pdf.to_vec();
    let mut replacement = to.to_vec();
    replacement.resize(from.len(), b' ');
    out[at..at + from.len()].copy_from_slice(&replacement);
    out
}

/// A signed field whose `/V` is a direct object is listed, its value marked unreadable,
/// instead of failing the whole file (ADR-0028).
#[test]
fn signature_value_that_is_no_reference_is_reported() {
    let signed = support::corpus("real/certified-pyhanko.pdf");
    let doc = Document::parse(&signed).unwrap();
    let field = &doc.signature_fields()[0];
    assert_eq!(field.name, "Certification");
    assert!(field.value.is_some());
    assert!(!field.value_unreadable);

    for direct in [&b"/V 7"[..], b"/V <<>>"] {
        let pdf = patch(&signed, b"/V 11 0 R", direct);
        let doc = Document::parse(&pdf).unwrap();
        let fields = doc.signature_fields();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "Certification");
        assert_eq!(fields[0].value, None);
        assert!(fields[0].value_unreadable);
        assert!(!fields[1].value_unreadable);
    }
}
