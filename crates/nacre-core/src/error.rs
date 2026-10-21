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
