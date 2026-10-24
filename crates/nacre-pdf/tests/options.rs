#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use nacre_pdf::{Document, Error, ObjectId, ReadOptions};
use support::refusals;

fn misplaced_xref() -> ReadOptions {
    let mut options = ReadOptions::default();
    options.misplaced_xref = true;
    options
}

#[test]
fn misplaced_xref_reads_a_startxref_on_whitespace() {
    let bytes = refusals::startxref_off_by_one();
    let doc = Document::parse_with_options(&bytes, &misplaced_xref()).unwrap();
    let revisions = doc.revisions();
    assert_eq!(revisions.len(), 1);
    assert_eq!(revisions[0].startxref, 565);
    assert_eq!(revisions[0].end, bytes.len());
    assert!(doc.signature_fields().is_empty());
}

#[test]
fn misplaced_xref_skips_whitespace_only() {
    let err = Document::parse_with_options(
        &refusals::xref_entry_pointing_elsewhere(),
        &misplaced_xref(),
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::ObjectMismatch { object, .. } if object == ObjectId::new(1, 0)),
        "{err:?}"
    );

    let mut bytes = refusals::startxref_off_by_one();
    let at = bytes.len() - b"564\n%%EOF\n".len();
    assert_eq!(&bytes[at..at + 3], b"564");
    bytes[at..at + 3].copy_from_slice(b"562");
    let err = Document::parse_with_options(&bytes, &misplaced_xref()).unwrap_err();
    assert!(
        matches!(err, Error::NotAnXrefSection { offset: 562 }),
        "{err:?}"
    );
}
