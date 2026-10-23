/// The error every function of this crate returns.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The PDF could not be read or the revision could not be written.
    #[error("PDF: {0}")]
    Pdf(#[from] nacre_pdf::Error),
    /// The CMS signature could not be made.
    #[error("CMS: {0}")]
    Cms(#[from] nacre_cms::Error),
    /// The timestamp authority failed to answer.
    #[error("the timestamp authority failed")]
    Timestamp(#[source] nacre_core::Error),
    /// The timestamp authority returned a token that is not a single DER value.
    #[error("the timestamp authority returned a token that is not DER")]
    TimestampToken(#[source] der::Error),
    /// The timestamp token does not fit the room reserved for it.
    #[error("the timestamp token is {len} bytes, more than the {max} reserved")]
    TimestampTooLarge {
        /// The size of the token, in DER bytes.
        len: usize,
        /// The most the `/Contents` slot reserves room for.
        max: usize,
    },
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        match self {
            Self::Pdf(inner) => inner.kind(),
            Self::Cms(inner) => inner.kind(),
            Self::Timestamp(inner) => inner.kind(),
            Self::TimestampToken(_) | Self::TimestampTooLarge { .. } => {
                nacre_core::ErrorKind::InvalidInput
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nacre_core::ErrorKind::{self, *};

    #[test]
    fn every_variant_has_its_kind() {
        let rows: Vec<(Error, ErrorKind)> = vec![
            (
                Error::Pdf(nacre_pdf::Error::DuplicateField { name: "S".into() }),
                InvalidInput,
            ),
            (Error::Pdf(nacre_pdf::Error::Encrypted), Indeterminate),
            (
                Error::Cms(nacre_cms::Error::SignatureInvalid),
                InvalidSignature,
            ),
            (
                Error::Cms(nacre_cms::Error::Signer(nacre_core::Error::Signer(
                    "x".into(),
                ))),
                ErrorKind::Signer,
            ),
            (
                Error::Timestamp(nacre_core::Error::Timestamp("x".into())),
                Unavailable,
            ),
            (
                Error::TimestampToken(der::Error::from(der::ErrorKind::Failed)),
                InvalidInput,
            ),
            (Error::TimestampTooLarge { len: 2, max: 1 }, InvalidInput),
        ];
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }
}
