use std::time::SystemTime;

use der::oid::ObjectIdentifier;

/// The error every function of this crate returns.
///
/// Every refusal to use a CRL or an OCSP response is its own variant: none of them can be
/// read as "not revoked" or "good".
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The CRL or OCSP response, or an extension inside it, is not valid DER for the
    /// structure being read.
    #[error("invalid DER")]
    Der(#[from] der::Error),
    /// The certificate whose status is asked, or whose distribution point is read, could
    /// not be read.
    #[error("invalid certificate")]
    Certificate(#[source] der::Error),
    /// The issuer certificate given to verify the CRL or OCSP response could not be read.
    #[error("invalid issuer certificate")]
    IssuerCertificate(#[source] der::Error),
    /// The outer `signatureAlgorithm` of a CRL differs from `tbsCertList.signature`, or the
    /// signature algorithm of a CRL or OCSP response does not match the signer's key.
    #[error("the signature algorithm does not match")]
    AlgorithmMismatch,
    /// The signature of the CRL or OCSP response does not verify with the key of its
    /// signer: the issuer, or the responder it delegated.
    #[error("the revocation data signature is invalid")]
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
    /// The `nextUpdate` of the CRL or OCSP response is before the control date.
    #[error("the revocation data expired at its nextUpdate")]
    Expired {
        /// The `nextUpdate` of the CRL or OCSP response.
        next_update: SystemTime,
    },
    /// The certificate names no `http://` distribution point this crate can use.
    #[error("no usable CRL distribution point")]
    NoDistributionPoint,
    /// The OCSP responder answered with a `responseStatus` other than `successful` (0).
    #[error("the OCSP responder answered with status {0}")]
    ResponseStatus(u8),
    /// The OCSP response is of another type than `id-pkix-ocsp-basic`.
    #[error("unsupported OCSP response type {0}")]
    UnsupportedResponseType(ObjectIdentifier),
    /// The OCSP response has no single response about the certificate asked.
    #[error("the OCSP response does not cover the certificate")]
    CertificateNotInResponse,
    /// The OCSP responder does not know the certificate (`certStatus` `unknown`).
    #[error("the OCSP responder does not know the certificate")]
    UnknownCertificate,
    /// The OCSP response is signed neither by the issuer nor by a responder the issuer
    /// delegated with `id-kp-OCSPSigning`.
    #[error("the OCSP responder is not authorized by the issuer")]
    UnauthorizedResponder,
    /// The OCSP response carries a nonce other than the request's: it answers another
    /// request, or is replayed.
    #[error("the OCSP response nonce does not match the request")]
    NonceMismatch,
    /// The OCSP response's `thisUpdate` is outside the tolerance around the date given.
    #[error("the OCSP response thisUpdate is outside the tolerance")]
    ThisUpdateOutOfTolerance {
        /// The response's `thisUpdate`.
        this_update: SystemTime,
    },
    /// The nonce given for an OCSP request holds this many octets, outside the 1 to 32
    /// octets of RFC 8954 §2.1.
    #[error("the OCSP nonce holds {0} octets, not 1 to 32")]
    NonceLength(usize),
    /// The certificate names no `http://` OCSP responder this crate can use.
    #[error("no usable OCSP responder")]
    NoOcspResponder,
    /// The system's random generator failed while making a nonce.
    #[error("the random generator failed")]
    Random(#[source] getrandom::Error),
    /// The revocation source address named by the certificate (CRL distribution point or
    /// OCSP responder) resolves to a loopback, private, link-local or
    /// other non-public address, which the HTTP sources do not reach. The message
    /// never names the URL, which is the certificate's.
    #[cfg(feature = "http")]
    #[error("the revocation source address is not public")]
    NonPublicAddress,
    /// The CRL download or the OCSP exchange failed, or answered with a redirect, which is not followed. The
    /// message stays generic: the URL is the certificate's.
    #[cfg(feature = "http")]
    #[error("the revocation download failed")]
    Http(#[source] ureq::Error),
}

impl Error {
    /// The coarse category of this error, safe to show to an untrusted party.
    pub fn kind(&self) -> nacre_core::ErrorKind {
        use nacre_core::ErrorKind;
        match self {
            Self::Der(_)
            | Self::Certificate(_)
            | Self::IssuerCertificate(_)
            | Self::NonceLength(_) => ErrorKind::InvalidInput,
            // A foreign responder or another nonce means a forged or replayed answer.
            Self::AlgorithmMismatch
            | Self::SignatureInvalid
            | Self::UnauthorizedResponder
            | Self::NonceMismatch => ErrorKind::InvalidSignature,
            Self::WrongIssuer
            | Self::UnsupportedCriticalExtension(_)
            | Self::UnsupportedAlgorithm(_)
            | Self::IssuerNotCrlSigner
            | Self::MissingNextUpdate
            | Self::Expired { .. }
            | Self::NoDistributionPoint
            | Self::ResponseStatus(_)
            | Self::UnsupportedResponseType(_)
            | Self::CertificateNotInResponse
            | Self::UnknownCertificate
            | Self::ThisUpdateOutOfTolerance { .. }
            | Self::NoOcspResponder => ErrorKind::Indeterminate,
            Self::Random(_) => ErrorKind::Unavailable,
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
            (Error::ResponseStatus(3), Indeterminate),
            (Error::UnsupportedResponseType(oid), Indeterminate),
            (Error::CertificateNotInResponse, Indeterminate),
            (Error::UnknownCertificate, Indeterminate),
            (Error::UnauthorizedResponder, InvalidSignature),
            (Error::NonceMismatch, InvalidSignature),
            (
                Error::ThisUpdateOutOfTolerance {
                    this_update: SystemTime::UNIX_EPOCH,
                },
                Indeterminate,
            ),
            (Error::NonceLength(0), InvalidInput),
            (Error::NoOcspResponder, Indeterminate),
            (Error::Random(getrandom::Error::UNSUPPORTED), Unavailable),
        ];
        assert_eq!(rows.len(), 22);
        #[cfg(feature = "http")]
        {
            rows.push((Error::NonPublicAddress, InvalidInput));
            rows.push((Error::Http(ureq::Error::ConnectionFailed), Unavailable));
            assert_eq!(rows.len(), 24);
        }
        for (error, kind) in rows {
            assert_eq!(error.kind(), kind, "{error}");
        }
    }
}
