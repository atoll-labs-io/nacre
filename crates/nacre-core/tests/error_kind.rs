#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_core::{Error, ErrorKind};

fn boxed() -> Box<dyn std::error::Error + Send + Sync> {
    "inner".into()
}

#[test]
fn core_kinds() {
    let rows = [
        (
            Error::DigestLength {
                expected: 32,
                actual: 20,
            },
            ErrorKind::InvalidInput,
        ),
        (Error::Signer(boxed()), ErrorKind::Signer),
        (Error::Timestamp(boxed()), ErrorKind::Unavailable),
        (Error::Revocation(boxed()), ErrorKind::Unavailable),
    ];
    for (error, kind) in rows {
        assert_eq!(error.kind(), kind, "{error}");
    }
}

#[test]
fn kind_display_is_fixed() {
    let texts = [
        (ErrorKind::InvalidInput, "invalid input"),
        (ErrorKind::InvalidSignature, "invalid signature"),
        (ErrorKind::Indeterminate, "indeterminate"),
        (ErrorKind::Signer, "signer failure"),
        (ErrorKind::Unavailable, "service unavailable"),
    ];
    for (kind, text) in texts {
        assert_eq!(kind.to_string(), text);
    }
    let a = Error::DigestLength {
        expected: 32,
        actual: 1,
    };
    let b = Error::DigestLength {
        expected: 48,
        actual: 99,
    };
    assert_eq!(a.kind().to_string(), b.kind().to_string());
}
