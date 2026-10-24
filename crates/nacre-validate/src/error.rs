/// Why a PDF could not be validated at all. A signature found defective is not an error:
/// it is a [`SignatureValidation`](crate::SignatureValidation) with a failed report.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The PDF itself cannot be read.
    #[error("the PDF cannot be read: {0}")]
    Pdf(#[from] nacre_pdf::Error),
    /// The PDF holds more signatures than are validated in one call.
    #[error("{count} signatures, at most {max} are validated")]
    TooManySignatures { count: usize, max: usize },
    /// More revisions follow the oldest signed one than are qualified in one call.
    #[error("{count} revisions after the oldest signed one, at most {max} are qualified")]
    TooManyRevisions { count: usize, max: usize },
    /// A certificate given as a trust anchor cannot be read.
    #[error("a trust anchor cannot be read: {0}")]
    TrustAnchor(der::Error),
    /// A certificate given as a trust anchor is PEM text, where DER is expected.
    #[error("a trust anchor looks like PEM; give it as DER")]
    TrustAnchorPem,
    /// A certificate of a verified signature's CMS repeats an extension, under a
    /// [`ValidationPolicy`](crate::ValidationPolicy) that does not judge malformed
    /// extensions.
    #[error("a certificate of a signature repeats an extension")]
    MalformedCertificate,
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        match self {
            Self::Pdf(inner) => inner.kind(),
            Self::TooManySignatures { .. }
            | Self::TooManyRevisions { .. }
            | Self::TrustAnchor(_)
            | Self::TrustAnchorPem
            | Self::MalformedCertificate => nacre_core::ErrorKind::InvalidInput,
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
                Error::Pdf(nacre_pdf::Error::TrailingData { offset: 1 }),
                InvalidInput,
            ),
            (Error::Pdf(nacre_pdf::Error::Encrypted), Indeterminate),
            (Error::TooManySignatures { count: 2, max: 1 }, InvalidInput),
            (Error::TooManyRevisions { count: 65, max: 64 }, InvalidInput),
            (
                Error::TrustAnchor(der::Error::from(der::ErrorKind::Failed)),
                InvalidInput,
            ),
            (Error::TrustAnchorPem, InvalidInput),
            (Error::MalformedCertificate, InvalidInput),
        ];
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }
}
