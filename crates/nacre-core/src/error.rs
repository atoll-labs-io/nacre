/// An implementation's own error, carried as the source of an [`Error`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The error every trait of the contract returns.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The digest handed to a signer does not have the length its algorithm produces.
    #[error("digest length is {actual} bytes, the signature algorithm expects {expected}")]
    DigestLength { expected: usize, actual: usize },
    /// The signer failed; the source is the implementation's error.
    #[error("the signer failed")]
    Signer(#[source] BoxError),
    /// The timestamp authority failed; the source is the implementation's error.
    #[error("the timestamp authority failed")]
    Timestamp(#[source] BoxError),
    /// The revocation source failed; the source is the implementation's error.
    #[error("the revocation source failed")]
    Revocation(#[source] BoxError),
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::DigestLength { .. } => ErrorKind::InvalidInput,
            Self::Signer(_) => ErrorKind::Signer,
            Self::Timestamp(_) | Self::Revocation(_) => ErrorKind::Unavailable,
        }
    }
}

/// The coarse category of an error: what an application may show to a third party, while
/// the detailed error stays for the developer.
///
/// EN 319 102-1 sub-indications are results of a validation, never kinds. A new variant is
/// a contract change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The bytes or arguments given are malformed, beyond a limit, or refuse the operation
    /// asked.
    InvalidInput,
    /// The input was read and the signature is proven wrong.
    InvalidSignature,
    /// Nacre cannot conclude: an unsupported feature or missing material.
    Indeterminate,
    /// The signer failed.
    Signer,
    /// An outside service (timestamp authority, revocation source) failed.
    Unavailable,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid input",
            Self::InvalidSignature => "invalid signature",
            Self::Indeterminate => "indeterminate",
            Self::Signer => "signer failure",
            Self::Unavailable => "service unavailable",
        })
    }
}
