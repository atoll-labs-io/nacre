#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use std::time::{Duration, Instant};

use nacre_pdf::{Document, Error, MAX_INPUT_LEN, ObjectId};
use support::{Xref, hostile, minimal};

fn refuse(bytes: &[u8]) -> Error {
    Document::parse(bytes).unwrap_err()
}

#[test]
fn xref_prev_loop_is_refused() {
    let err = refuse(&hostile::xref_prev_loop());
    assert!(matches!(err, Error::XrefLoop { offset: 9 }), "{err:?}");
}

#[test]
fn reference_loop_is_refused() {
    let err = refuse(&hostile::reference_loop());
    assert!(
        matches!(err, Error::ReferenceLoop { object } if object == ObjectId::new(5, 0)),
        "{err:?}"
    );
}

#[test]
fn field_kids_loop_is_refused() {
    let err = refuse(&hostile::field_kids_loop());
    assert!(
        matches!(err, Error::FieldLoop { object } if object == ObjectId::new(3, 0)),
        "{err:?}"
    );
}

#[test]
fn wrong_stream_length_is_refused() {
    for bytes in [
        hostile::stream_length_too_short(),
        hostile::stream_length_past_end(),
    ] {
        let err = refuse(&bytes);
        assert!(
            matches!(err, Error::StreamLength { object } if object == ObjectId::new(3, 0)),
            "{err:?}"
        );
    }
}

#[test]
fn deep_nesting_is_refused() {
    let err = refuse(&hostile::deep_nesting());
    assert!(matches!(err, Error::TooDeep { .. }), "{err:?}");
}

#[test]
fn size_limit_is_50_000_000_bytes() {
    let pdf = minimal(Xref::Table);
    let at_limit = pdf.build_padded_to(MAX_INPUT_LEN);
    assert_eq!(at_limit.len(), 50_000_000);
    Document::parse(&at_limit).unwrap();
    let over = pdf.build_padded_to(MAX_INPUT_LEN + 1);
    let err = refuse(&over);
    assert!(
        matches!(
            err,
            Error::TooLarge {
                len: 50_000_001,
                max: 50_000_000
            }
        ),
        "{err:?}"
    );
}

#[test]
fn huge_declared_counts_are_refused() {
    let err = refuse(&hostile::huge_declared_counts());
    assert!(
        matches!(
            err,
            Error::XrefTable {
                reason: "subsection longer than the file",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn xref_stream_with_wrong_decoded_length_is_refused() {
    let err = refuse(&hostile::xref_stream_wrong_decoded_length());
    assert!(matches!(err, Error::XrefStream { .. }), "{err:?}");
}

#[test]
fn hostile_inputs_fail_within_two_seconds() {
    let inputs: Vec<_> = hostile::all()
        .into_iter()
        .chain(support::refusals::all())
        .collect();
    let started = Instant::now();
    for (name, bytes) in &inputs {
        assert!(Document::parse(bytes).is_err(), "{name} was accepted");
    }
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}
