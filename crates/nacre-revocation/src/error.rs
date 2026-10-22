use std::time::SystemTime;

use der::oid::ObjectIdentifier;

/// The error every function of this crate returns.
///
/// Every refusal to use a CRL is its own variant: none of them can be read as "not revoked".
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The CRL, or an extension inside it, is not valid DER for the structure being read.
    #[error("invalid DER")]
    Der(#[from] der::Error),
    /// The certificate whose status is asked, or whose distribution point is read, could
    /// not be read.
    #[error("invalid certificate")]
    Certificate(#[source] der::Error),
    /// The issuer certificate given to verify the CRL could not be read.
    #[error("invalid issuer certificate")]
    IssuerCertificate(#[source] der::Error),
    /// The outer `signatureAlgorithm` differs from `tbsCertList.signature`, or the signature
    /// algorithm does not match the issuer's key.
    #[error("the signature algorithm does not match")]
    AlgorithmMismatch,
    /// The signature does not verify with the issuer certificate's key.
    #[error("the CRL signature is invalid")]
    SignatureInvalid,
    /// The CRL was issued by another authority than the certificate's issuer.
    #[error("the CRL was issued by another authority")]
    WrongIssuer,
    /// The CRL, or one of its entries, carries a critical extension this crate does not
    /// process (issuing distribution point, delta CRL, certificate issuer...).
    #[error("unsupported critical extension {0}")]
    UnsupportedCriticalExtension(ObjectIdentifier),
    /// A signature or key algorithm this crate does not support.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(ObjectIdentifier),
    /// The issuer certificate has a `keyUsage` without `cRLSign`.
    #[error("the issuer certificate may not sign CRLs")]
    IssuerNotCrlSigner,
    /// The CRL has no `nextUpdate`, so its freshness cannot be shown.
    #[error("the CRL has no nextUpdate")]
    MissingNextUpdate,
    /// The CRL's `nextUpdate` is before the control date.
    #[error("the CRL expired at its nextUpdate")]
    Expired {
        /// The CRL's `nextUpdate`.
        next_update: SystemTime,
    },
    /// The certificate names no `http://` distribution point this crate can use.
    #[error("no usable CRL distribution point")]
    NoDistributionPoint,
    /// The certificate's distribution point resolves to a loopback, private, link-local or
    /// other non-public address, which [`crate::HttpCrlSource`] does not reach. The message
    /// never names the URL, which is the certificate's.
    #[cfg(feature = "http")]
    #[error("the CRL distribution point is not a public address")]
    NonPublicAddress,
    /// The CRL download failed, or answered with a redirect, which is not followed. The
    /// message stays generic: the URL is the certificate's.
    #[cfg(feature = "http")]
    #[error("the CRL download failed")]
    Http(#[source] ureq::Error),
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        use nacre_core::ErrorKind;
        match self {
            Self::Der(_) | Self::Certificate(_) | Self::IssuerCertificate(_) => {
                ErrorKind::InvalidInput
            }
            Self::AlgorithmMismatch | Self::SignatureInvalid => ErrorKind::InvalidSignature,
            Self::WrongIssuer
            | Self::UnsupportedCriticalExtension(_)
            | Self::UnsupportedAlgorithm(_)
            | Self::IssuerNotCrlSigner
            | Self::MissingNextUpdate
            | Self::Expired { .. }
            | Self::NoDistributionPoint => ErrorKind::Indeterminate,
            #[cfg(feature = "http")]
            Self::NonPublicAddress => ErrorKind::InvalidInput,
            #[cfg(feature = "http")]
            Self::Http(_) => ErrorKind::Unavailable,
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
        #[allow(unused_mut)]
        let mut rows: Vec<(Error, ErrorKind)> = vec![
            (Error::Der(der()), InvalidInput),
            (Error::Certificate(der()), InvalidInput),
            (Error::IssuerCertificate(der()), InvalidInput),
            (Error::AlgorithmMismatch, InvalidSignature),
            (Error::SignatureInvalid, InvalidSignature),
            (Error::WrongIssuer, Indeterminate),
            (Error::UnsupportedCriticalExtension(oid), Indeterminate),
            (Error::UnsupportedAlgorithm(oid), Indeterminate),
            (Error::IssuerNotCrlSigner, Indeterminate),
            (Error::MissingNextUpdate, Indeterminate),
            (
                Error::Expired {
                    next_update: SystemTime::UNIX_EPOCH,
                },
                Indeterminate,
            ),
            (Error::NoDistributionPoint, Indeterminate),
        ];
        assert_eq!(rows.len(), 12);
        #[cfg(feature = "http")]
        {
            rows.push((Error::NonPublicAddress, InvalidInput));
            rows.push((Error::Http(ureq::Error::ConnectionFailed), Unavailable));
            assert_eq!(rows.len(), 14);
        }
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }
}
