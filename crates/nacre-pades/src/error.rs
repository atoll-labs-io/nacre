use std::fmt;

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
    /// The revocation source gave nothing for `certificate`, named by its subject.
    #[error("no revocation data could be obtained for {certificate}")]
    Revocation {
        /// The subject of the certificate, as RFC 4514 text.
        certificate: String,
        /// What the revocation source answered.
        #[source]
        source: nacre_core::Error,
    },
    /// No certificate of the chains, nor of the issuers the caller gave, issued `certificate`.
    #[error("the issuer of {certificate} is in neither the chains nor the issuers given")]
    IssuerMissing {
        /// The subject of the certificate, as RFC 4514 text.
        certificate: String,
    },
    /// The revocation source answered with a kind of data this crate cannot store.
    #[error("the revocation data for {certificate} is of a kind that cannot be stored")]
    RevocationUnsupported {
        /// The subject of the certificate, as RFC 4514 text.
        certificate: String,
    },
    /// A certificate of the signer's chain, of the token or of the issuers is not X.509 DER.
    #[error("a certificate is not X.509 DER")]
    Certificate(#[source] der::Error),
    /// The B-T signature was made but could not be raised to B-LT. `signed` is that B-T
    /// file: the signer has already signed and may not be able to sign again.
    #[error("the B-T signature could not be raised to B-LT: {source}")]
    LongTerm {
        /// The PDF signed at B-T, without `/DSS`.
        signed: SignedPdf,
        /// Why the long-term step failed.
        #[source]
        source: Box<Error>,
    },
}

/// A signed PDF handed back inside an error. Its `Debug` prints only the length, so a
/// logged error never carries the document.
pub struct SignedPdf(pub Vec<u8>);

impl fmt::Debug for SignedPdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPdf")
            .field("len", &self.0.len())
            .finish()
    }
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        match self {
            Self::Pdf(inner) => inner.kind(),
            Self::Cms(inner) => inner.kind(),
            Self::Timestamp(inner) => inner.kind(),
            Self::Revocation { source, .. } => source.kind(),
            Self::LongTerm { source, .. } => source.kind(),
            Self::TimestampToken(_) | Self::TimestampTooLarge { .. } | Self::Certificate(_) => {
                nacre_core::ErrorKind::InvalidInput
            }
            Self::IssuerMissing { .. } | Self::RevocationUnsupported { .. } => {
                nacre_core::ErrorKind::Indeterminate
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
            (
                Error::Revocation {
                    certificate: "CN=x".into(),
                    source: nacre_core::Error::Revocation("x".into()),
                },
                Unavailable,
            ),
            (
                Error::IssuerMissing {
                    certificate: "CN=x".into(),
                },
                Indeterminate,
            ),
            (
                Error::RevocationUnsupported {
                    certificate: "CN=x".into(),
                },
                Indeterminate,
            ),
            (
                Error::Certificate(der::Error::from(der::ErrorKind::Failed)),
                InvalidInput,
            ),
            (
                Error::LongTerm {
                    signed: SignedPdf(Vec::new()),
                    source: Box::new(Error::IssuerMissing {
                        certificate: "CN=x".into(),
                    }),
                },
                Indeterminate,
            ),
        ];
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }

    #[test]
    fn signed_pdf_debug_hides_the_bytes() {
        let printed = format!("{:?}", SignedPdf(b"%PDF-secret".to_vec()));

        assert!(!printed.contains("secret"), "{printed}");
        assert!(printed.contains("11"), "{printed}");
    }
}
