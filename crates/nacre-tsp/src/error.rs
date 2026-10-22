use nacre_core::DigestAlgorithm;

/// The error every function of this crate returns.
///
/// No message carries a token, an imprint or a nonce.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The input is not valid DER for the structure being read, or encoding failed.
    #[error("invalid DER: {0}")]
    Der(#[from] der::Error),
    /// A digest does not have the length of its algorithm.
    #[error("digest length is {actual} bytes, the algorithm produces {expected}")]
    DigestLength { expected: usize, actual: usize },
    /// The response grants the request but carries no token.
    #[error("the response is granted but carries no token")]
    TokenMissing,
    /// The token does not encapsulate a `TSTInfo`.
    #[error("the token does not encapsulate a TSTInfo")]
    NotTstInfo,
    /// The `TSTInfo` has a version other than 1.
    #[error("TSTInfo version {0}, only 1 is defined")]
    TstInfoVersion(u8),
    /// The `genTime` of the `TSTInfo` is not a valid RFC 3161 `GeneralizedTime`.
    #[error("invalid genTime")]
    GenTime,
    /// The TSA certificate could not be read.
    #[error("invalid TSA certificate: {0}")]
    Certificate(#[source] der::Error),
    /// The token time-stamps another imprint, or with another hash algorithm.
    #[error("the token time-stamps another imprint")]
    ImprintMismatch,
    /// The token carries no nonce while the request sent one.
    #[error("the token carries no nonce")]
    NonceMissing,
    /// The token carries another nonce than the request.
    #[error("the token carries another nonce")]
    NonceMismatch,
    /// The TSA certificate's extended key usage is not `id-kp-timeStamping` alone, critical.
    #[error("the TSA certificate is not restricted to time-stamping")]
    NotTimestampingCertificate,
    /// A digest algorithm this crate cannot name.
    #[error("unsupported digest algorithm {0:?}")]
    UnsupportedAlgorithm(DigestAlgorithm),
    /// The token has no `signingCertificateV2` binding it to the TSA certificate.
    #[error("the token has no signingCertificateV2 attribute")]
    SigningCertificateMissing,
    /// The TSA did not grant the request.
    #[error("the TSA refused the request: status {status}, failure info {fail_info:?}")]
    Refused { status: u32, fail_info: Option<u32> },
    /// No randomness for the nonce.
    #[error("no randomness for the nonce: {0}")]
    Random(getrandom::Error),
    /// The HTTP exchange with the TSA failed.
    #[cfg(feature = "http")]
    #[error("TSA request failed: {0}")]
    Http(#[from] ureq::Error),
    /// The token's `SignedData` is malformed or its signature does not verify.
    #[error("token signature: {0}")]
    Cms(#[from] nacre_cms::Error),
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        use nacre_core::ErrorKind;
        match self {
            Self::Der(_)
            | Self::DigestLength { .. }
            | Self::TokenMissing
            | Self::NotTstInfo
            | Self::TstInfoVersion(_)
            | Self::GenTime
            | Self::Certificate(_) => ErrorKind::InvalidInput,
            Self::ImprintMismatch
            | Self::NonceMissing
            | Self::NonceMismatch
            | Self::NotTimestampingCertificate => ErrorKind::InvalidSignature,
            Self::UnsupportedAlgorithm(_) | Self::SigningCertificateMissing => {
                ErrorKind::Indeterminate
            }
            Self::Refused { .. } | Self::Random(_) => ErrorKind::Unavailable,
            #[cfg(feature = "http")]
            Self::Http(_) => ErrorKind::Unavailable,
            Self::Cms(inner) => inner.kind(),
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
        let der = || der::Error::from(der::ErrorKind::Failed);
        let mut rows: Vec<(Error, ErrorKind)> = vec![
            (Error::Der(der()), InvalidInput),
            (
                Error::DigestLength {
                    expected: 32,
                    actual: 20,
                },
                InvalidInput,
            ),
            (Error::TokenMissing, InvalidInput),
            (Error::NotTstInfo, InvalidInput),
            (Error::TstInfoVersion(2), InvalidInput),
            (Error::GenTime, InvalidInput),
            (Error::Certificate(der()), InvalidInput),
            (Error::ImprintMismatch, InvalidSignature),
            (Error::NonceMissing, InvalidSignature),
            (Error::NonceMismatch, InvalidSignature),
            (Error::NotTimestampingCertificate, InvalidSignature),
            (
                Error::UnsupportedAlgorithm(DigestAlgorithm::Sha384),
                Indeterminate,
            ),
            (Error::SigningCertificateMissing, Indeterminate),
            (
                Error::Refused {
                    status: 2,
                    fail_info: Some(1),
                },
                Unavailable,
            ),
            (Error::Random(getrandom::Error::UNSUPPORTED), Unavailable),
            (
                Error::Cms(nacre_cms::Error::SignatureInvalid),
                InvalidSignature,
            ),
            (
                Error::Cms(nacre_cms::Error::SignerCertificateNotFound),
                Indeterminate,
            ),
        ];
        #[cfg(feature = "http")]
        rows.push((Error::Http(ureq::Error::ConnectionFailed), Unavailable));
        let expected = if cfg!(feature = "http") { 18 } else { 17 };
        assert_eq!(rows.len(), expected);
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }
}
