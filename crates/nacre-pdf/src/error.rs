use crate::ObjectId;

/// Why a PDF was refused. Offsets are byte offsets into the input, except inside an
/// object stream, where they count from the start of its decoded data.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is longer than [`MAX_INPUT_LEN`](crate::MAX_INPUT_LEN).
    #[error("the input is {len} bytes, more than the {max} accepted")]
    TooLarge { len: usize, max: usize },
    /// The input does not start with `%PDF-`.
    #[error("the input does not start with %PDF-")]
    MissingHeader,
    /// No `startxref N %%EOF` in the last 1,024 bytes.
    #[error("no startxref statement in the last 1024 bytes")]
    MissingStartxref,
    /// Something other than whitespace follows the last `%%EOF`.
    #[error("data after the last %%EOF at offset {offset}")]
    TrailingData { offset: usize },
    /// An offset meant to hold a cross-reference section holds something else.
    #[error("no cross-reference section at offset {offset}")]
    NotAnXrefSection { offset: usize },
    /// A cross-reference table is malformed.
    #[error("malformed cross-reference table at offset {offset}: {reason}")]
    XrefTable { offset: usize, reason: &'static str },
    /// A cross-reference stream is malformed.
    #[error("malformed cross-reference stream {object}: {reason}")]
    XrefStream {
        object: ObjectId,
        reason: &'static str,
    },
    /// The `/Prev` chain comes back to a section already read.
    #[error("the /Prev chain loops back to offset {offset}")]
    XrefLoop { offset: usize },
    /// The bytes at an offset are not the syntax expected there.
    #[error("syntax error at offset {offset}: expected {expected}")]
    Syntax {
        offset: usize,
        expected: &'static str,
    },
    /// Arrays and dictionaries nest deeper than allowed.
    #[error("arrays and dictionaries nest too deep at offset {offset}")]
    TooDeep { offset: usize },
    /// A dictionary holds the same key twice.
    #[error("duplicate dictionary key at offset {offset}")]
    DuplicateKey { offset: usize },
    /// A stream's `/Length` is missing, invalid, or not followed by `endstream`.
    #[error("stream {object} does not end where its /Length says")]
    StreamLength { object: ObjectId },
    /// A stream uses a filter, or a chain of filters, this reader does not decode.
    #[error("stream {object} uses the unsupported filter {filter}")]
    UnsupportedFilter { object: ObjectId, filter: String },
    /// A stream uses a predictor this reader does not reverse.
    #[error("stream {object} uses the unsupported predictor {predictor}")]
    UnsupportedPredictor { object: ObjectId, predictor: i64 },
    /// A stream's data does not decode.
    #[error("stream {object} does not decode")]
    Decode { object: ObjectId },
    /// Decoding a stream would exceed the per-stream or per-parse budget.
    #[error("stream {object} decodes to more than {max} bytes")]
    DecodedTooLarge { object: ObjectId, max: usize },
    /// A followed reference names an object that is absent, free or of another generation.
    #[error("object {object} not found")]
    ObjectNotFound { object: ObjectId },
    /// A cross-reference entry points at bytes that are not that object.
    #[error(
        "the cross-reference entry of {object} points at offset {offset}, which does not hold it"
    )]
    ObjectMismatch { object: ObjectId, offset: usize },
    /// An object stream, or the entry pointing into it, is malformed.
    #[error("object {object} cannot be read from its object stream: {reason}")]
    ObjectStream {
        object: ObjectId,
        reason: &'static str,
    },
    /// Following references comes back to an object already on the path, or goes too far.
    #[error("reference loop through object {object}")]
    ReferenceLoop { object: ObjectId },
    /// An object on a followed path is not of the type that path requires.
    #[error("object {object} is not a {expected}")]
    WrongType {
        object: ObjectId,
        expected: &'static str,
    },
    /// The newest trailer holds `/Encrypt`; encrypted documents are not read.
    #[error("the document is encrypted")]
    Encrypted,
    /// The AcroForm field tree comes back to a field already visited.
    #[error("the form field tree loops through object {object}")]
    FieldLoop { object: ObjectId },
    /// A count read from the input exceeds its bound. The offset is 0 when the bound is
    /// not tied to a position.
    #[error("{what} exceeds its limit at offset {offset}")]
    Limit { what: &'static str, offset: usize },
    /// An object the writer cannot write where it was given.
    #[error("cannot write {what}")]
    Unwritable { what: &'static str },
    /// The caller's signature dictionary entries hold a key the writer sets itself.
    #[error("the signature dictionary entry /{key} is set by the writer")]
    ReservedEntry { key: String },
    /// The signature slot was asked with no room for a signature.
    #[error("the signature slot must hold at least one byte")]
    EmptySignatureSlot,
    /// A signature field with this full name already exists.
    #[error("a signature field named {name} already exists")]
    DuplicateField { name: String },
    /// The document is certified with DocMDP `/P 1`: no approval signature may be added.
    #[error("the document is certified with no changes allowed (DocMDP /P 1)")]
    CertifiedNoChanges,
    /// The DER signature is longer than the slot reserved for it.
    #[error("the signature is {len} bytes, more than the {capacity} reserved")]
    SignatureTooLarge { len: usize, capacity: usize },
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        use nacre_core::ErrorKind;
        match self {
            Self::UnsupportedFilter { .. }
            | Self::UnsupportedPredictor { .. }
            | Self::Encrypted => ErrorKind::Indeterminate,
            Self::TooLarge { .. }
            | Self::MissingHeader
            | Self::MissingStartxref
            | Self::TrailingData { .. }
            | Self::NotAnXrefSection { .. }
            | Self::XrefTable { .. }
            | Self::XrefStream { .. }
            | Self::XrefLoop { .. }
            | Self::Syntax { .. }
            | Self::TooDeep { .. }
            | Self::DuplicateKey { .. }
            | Self::StreamLength { .. }
            | Self::Decode { .. }
            | Self::DecodedTooLarge { .. }
            | Self::ObjectNotFound { .. }
            | Self::ObjectMismatch { .. }
            | Self::ObjectStream { .. }
            | Self::ReferenceLoop { .. }
            | Self::WrongType { .. }
            | Self::FieldLoop { .. }
            | Self::Limit { .. }
            | Self::Unwritable { .. }
            | Self::ReservedEntry { .. }
            | Self::EmptySignatureSlot
            | Self::DuplicateField { .. }
            | Self::CertifiedNoChanges
            | Self::SignatureTooLarge { .. } => ErrorKind::InvalidInput,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nacre_core::ErrorKind::{self, *};

    #[test]
    fn every_variant_has_its_kind() {
        let o = ObjectId::new(1, 0);
        let rows: Vec<(Error, ErrorKind)> = vec![
            (Error::TooLarge { len: 2, max: 1 }, InvalidInput),
            (Error::MissingHeader, InvalidInput),
            (Error::MissingStartxref, InvalidInput),
            (Error::TrailingData { offset: 1 }, InvalidInput),
            (Error::NotAnXrefSection { offset: 1 }, InvalidInput),
            (
                Error::XrefTable {
                    offset: 1,
                    reason: "r",
                },
                InvalidInput,
            ),
            (
                Error::XrefStream {
                    object: o,
                    reason: "r",
                },
                InvalidInput,
            ),
            (Error::XrefLoop { offset: 1 }, InvalidInput),
            (
                Error::Syntax {
                    offset: 1,
                    expected: "e",
                },
                InvalidInput,
            ),
            (Error::TooDeep { offset: 1 }, InvalidInput),
            (Error::DuplicateKey { offset: 1 }, InvalidInput),
            (Error::StreamLength { object: o }, InvalidInput),
            (
                Error::UnsupportedFilter {
                    object: o,
                    filter: "f".into(),
                },
                Indeterminate,
            ),
            (
                Error::UnsupportedPredictor {
                    object: o,
                    predictor: 3,
                },
                Indeterminate,
            ),
            (Error::Decode { object: o }, InvalidInput),
            (Error::DecodedTooLarge { object: o, max: 1 }, InvalidInput),
            (Error::ObjectNotFound { object: o }, InvalidInput),
            (
                Error::ObjectMismatch {
                    object: o,
                    offset: 1,
                },
                InvalidInput,
            ),
            (
                Error::ObjectStream {
                    object: o,
                    reason: "r",
                },
                InvalidInput,
            ),
            (Error::ReferenceLoop { object: o }, InvalidInput),
            (
                Error::WrongType {
                    object: o,
                    expected: "e",
                },
                InvalidInput,
            ),
            (Error::Encrypted, Indeterminate),
            (Error::FieldLoop { object: o }, InvalidInput),
            (
                Error::Limit {
                    what: "w",
                    offset: 0,
                },
                InvalidInput,
            ),
            (Error::Unwritable { what: "w" }, InvalidInput),
            (Error::ReservedEntry { key: "k".into() }, InvalidInput),
            (Error::EmptySignatureSlot, InvalidInput),
            (Error::DuplicateField { name: "n".into() }, InvalidInput),
            (Error::CertifiedNoChanges, InvalidInput),
            (
                Error::SignatureTooLarge {
                    len: 2,
                    capacity: 1,
                },
                InvalidInput,
            ),
        ];
        assert_eq!(rows.len(), 30);
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }
}
