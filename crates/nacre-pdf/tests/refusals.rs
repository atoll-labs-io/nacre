#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use nacre_pdf::{Document, Error, ObjectId};
use support::refusals;

fn refuse(bytes: &[u8]) -> Error {
    Document::parse(bytes).unwrap_err()
}

#[test]
fn startxref_off_by_one_is_refused() {
    let err = refuse(&refusals::startxref_off_by_one());
    assert!(
        matches!(err, Error::NotAnXrefSection { offset: 564 }),
        "{err:?}"
    );
}

#[test]
fn malformed_prev_is_refused() {
    let err = refuse(&refusals::malformed_prev());
    assert!(
        matches!(
            err,
            Error::XrefTable {
                offset: 66,
                reason: "/Prev is not an offset"
            }
        ),
        "{err:?}"
    );
}

#[test]
fn xref_entry_pointing_elsewhere_is_refused() {
    let err = refuse(&refusals::xref_entry_pointing_elsewhere());
    assert!(
        matches!(err, Error::ObjectMismatch { object, .. } if object == ObjectId::new(1, 0)),
        "{err:?}"
    );
}

#[test]
fn missing_catalog_is_refused() {
    let err = refuse(&refusals::missing_catalog());
    assert!(
        matches!(err, Error::ObjectNotFound { object } if object == ObjectId::new(9, 0)),
        "{err:?}"
    );
}

#[test]
fn object_stream_index_past_n_is_refused() {
    let err = refuse(&refusals::object_stream_index_past_n());
    assert!(
        matches!(err, Error::ObjectStream { object, reason: "index past /N" } if object == ObjectId::new(4, 0)),
        "{err:?}"
    );
}

#[test]
fn encrypted_pdf_is_refused() {
    let err = refuse(&refusals::encrypted());
    assert!(matches!(err, Error::Encrypted), "{err:?}");
}

#[test]
fn other_filter_on_xref_stream_is_refused() {
    let err = refuse(&refusals::other_filter_on_xref_stream());
    assert!(
        matches!(&err, Error::UnsupportedFilter { filter, .. } if filter == "/LZWDecode"),
        "{err:?}"
    );
}

#[test]
fn bytes_after_last_eof_are_refused() {
    let err = refuse(&refusals::bytes_after_last_eof());
    assert!(matches!(err, Error::TrailingData { .. }), "{err:?}");
}
