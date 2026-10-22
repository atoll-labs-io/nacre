use der::oid::ObjectIdentifier;

/// The error every function of this crate returns.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not valid DER for the structure being read, or encoding failed.
    #[error("invalid DER: {0}")]
    Der(#[from] der::Error),
    /// The `ContentInfo` does not hold a `SignedData`.
    #[error("the content is not a SignedData")]
    NotSignedData,
    /// The `SignedData` does not hold exactly one `SignerInfo`.
    #[error("{0} signer infos, exactly one is supported")]
    SignerCount(usize),
    /// A digest, signature or key algorithm this crate does not support.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(ObjectIdentifier),
    /// The signature algorithm does not match the key of the signer certificate.
    #[error("the signature algorithm does not match the signer key")]
    AlgorithmMismatch,
    /// The `SignerInfo` has no signed attributes.
    #[error("the signer info has no signed attributes")]
    MissingSignedAttributes,
    /// A required signed attribute is absent.
    #[error("signed attribute {0} is missing")]
    MissingAttribute(ObjectIdentifier),
    /// A signed attribute type appears more than once.
    #[error("signed attribute {0} appears more than once")]
    DuplicateAttribute(ObjectIdentifier),
    /// A signed attribute that must hold exactly one value holds another count.
    #[error("signed attribute {0} must hold exactly one value")]
    AttributeValueCount(ObjectIdentifier),
    /// The profile forbids an attribute that was asked for.
    #[error("the profile forbids attribute {0}")]
    ForbiddenAttribute(ObjectIdentifier),
    /// The `contentType` signed attribute differs from `eContentType`.
    #[error("the contentType attribute differs from eContentType")]
    ContentTypeMismatch,
    /// Neither a detached content nor an encapsulated one was given.
    #[error("no content to verify")]
    ContentMissing,
    /// A detached content was given while the `SignedData` encapsulates one.
    #[error("both a detached and an encapsulated content")]
    ContentAmbiguous,
    /// A digest does not have the length of its algorithm.
    #[error("digest length is {actual} bytes, the algorithm produces {expected}")]
    DigestLength { expected: usize, actual: usize },
    /// The digest of the content differs from the `messageDigest` attribute.
    #[error("the content digest differs from the messageDigest attribute")]
    MessageDigestMismatch,
    /// No certificate of the `SignedData` matches the signer identifier.
    #[error("no certificate matches the signer identifier")]
    SignerCertificateNotFound,
    /// The `signingCertificateV2` attribute names another certificate.
    #[error("the signingCertificateV2 attribute names another certificate")]
    SigningCertificateMismatch,
    /// The signature does not verify with the signer certificate's key.
    #[error("the signature is invalid")]
    SignatureInvalid,
    /// A certificate of the `SignedData` could not be read.
    #[error("invalid certificate: {0}")]
    Certificate(#[source] der::Error),
    /// The signer failed.
    #[error("the signer failed")]
    Signer(#[from] nacre_core::Error),
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        use nacre_core::ErrorKind;
        match self {
            Self::Der(_)
            | Self::NotSignedData
            | Self::ForbiddenAttribute(_)
            | Self::ContentMissing
            | Self::ContentAmbiguous
            | Self::DigestLength { .. }
            | Self::Certificate(_) => ErrorKind::InvalidInput,
            Self::AlgorithmMismatch
            | Self::MissingSignedAttributes
            | Self::MissingAttribute(_)
            | Self::DuplicateAttribute(_)
            | Self::AttributeValueCount(_)
            | Self::ContentTypeMismatch
            | Self::MessageDigestMismatch
            | Self::SigningCertificateMismatch
            | Self::SignatureInvalid => ErrorKind::InvalidSignature,
            Self::SignerCount(_)
            | Self::UnsupportedAlgorithm(_)
            | Self::SignerCertificateNotFound => ErrorKind::Indeterminate,
            Self::Signer(inner) => inner.kind(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nacre_core::ErrorKind::{self, *};

    #[test]
    fn every_variant_has_its_kind() {
        let oid = ObjectIdentifier::new_unwrap("1.2.3");
        let der = || der::Error::from(der::ErrorKind::Failed);
        let rows: Vec<(Error, ErrorKind)> = vec![
            (Error::Der(der()), InvalidInput),
            (Error::NotSignedData, InvalidInput),
            (Error::ForbiddenAttribute(oid), InvalidInput),
            (Error::ContentMissing, InvalidInput),
            (Error::ContentAmbiguous, InvalidInput),
            (
                Error::DigestLength {
                    expected: 32,
                    actual: 20,
                },
                InvalidInput,
            ),
            (Error::Certificate(der()), InvalidInput),
            (Error::AlgorithmMismatch, InvalidSignature),
            (Error::MissingSignedAttributes, InvalidSignature),
            (Error::MissingAttribute(oid), InvalidSignature),
            (Error::DuplicateAttribute(oid), InvalidSignature),
            (Error::AttributeValueCount(oid), InvalidSignature),
            (Error::ContentTypeMismatch, InvalidSignature),
            (Error::MessageDigestMismatch, InvalidSignature),
            (Error::SigningCertificateMismatch, InvalidSignature),
            (Error::SignatureInvalid, InvalidSignature),
            (Error::SignerCount(2), Indeterminate),
            (Error::UnsupportedAlgorithm(oid), Indeterminate),
            (Error::SignerCertificateNotFound, Indeterminate),
            (
                Error::Signer(nacre_core::Error::Signer("x".into())),
                ErrorKind::Signer,
            ),
            (
                Error::Signer(nacre_core::Error::Timestamp("x".into())),
                Unavailable,
            ),
        ];
        assert_eq!(rows.len(), 21);
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }
}
