#![forbid(unsafe_code)]
//! Certificate revocation for Nacre: X.509 CRLs (RFC 5280 §5) and OCSP (RFC 6960).
//! **Experimental**: not yet fuzzed at length nor cross-checked against a reference crate.
//!
//! [`Crl::from_der`] reads a DER CRL: issuer, `thisUpdate`, `nextUpdate` and the revoked
//! serials with their date and reason. [`Crl::verify_signature`] checks it with its
//! issuer's certificate, for ECDSA P-256 and RSA PKCS#1 v1.5 with SHA-256, over the
//! `tbsCertList` bytes received, never a re-encoding. [`Crl::status`] says whether a
//! certificate is listed at a control date given by the caller, after refusing, each with
//! its own [`Error`], a CRL from another issuer, a bad signature, an unsupported critical
//! extension, a missing or passed `nextUpdate`.
//!
//! [`OcspRequest`] builds a DER `OCSPRequest` for a certificate and its issuer, with a
//! nonce. [`OcspResponse::from_der`] reads a successful basic response, and
//! [`OcspResponse::status`] judges it at a control date: the single response about the
//! certificate, no unsupported critical extension, a responder that is the issuer or a
//! responder it delegated with `id-kp-OCSPSigning`, a signature over the `tbsResponseData`
//! bytes received, a `nextUpdate` not passed, then `good`, `revoked` or an error for
//! `unknown`. Two checks stay apart, since `status` cannot know what they need: the nonce,
//! [`OcspResponse::check_nonce`], against the request that was sent; the freshness of
//! `thisUpdate`, [`OcspResponse::check_this_update`], against a date and a tolerance the
//! caller gives. A caller judging a response fetched now checks both (`HttpOcspSource`
//! already checks the nonce); one judging a past signing time with a later response may
//! skip the freshness check, as a CRL issued later is accepted. Two accessors give a
//! caller what it judges beyond one date: [`OcspResponse::delegated_responder`], the
//! certificate of the delegate `status` accepts, checked at `producedAt` only, and
//! [`OcspResponse::archive_cutoff`], the single response's `archiveCutoff` (RFC 6960
//! §4.4.4).
//!
//! Judged here: one CRL or one OCSP response against one certificate at one date. Left to
//! the caller (s17): the certificate chain, and comparing a revocation date with a signing
//! time. A v1 CRL, which has no version field, is refused as invalid DER.
//!
//! [`Fallback`] asks a second source when the first fails, OCSP then CRL for instance.
//! Under the `http` feature, `HttpCrlSource` downloads the CRL named by a certificate's
//! `http://` distribution point, and `HttpOcspSource` asks the `http://` OCSP responder of
//! its `authorityInfoAccess`, with a random nonce it checks. Both implement
//! [`nacre_core::RevocationSource`]. Those URLs are untrusted: the sources reach only public
//! addresses and follow no redirect. No other code path opens a connection, and nothing
//! reads the system clock.

mod crl;
mod error;
mod fallback;
#[cfg(feature = "http")]
mod http;
mod ocsp;
mod verify;

pub use crl::{Crl, CrlStatus, RevokedEntry};
pub use error::Error;
pub use fallback::Fallback;
#[cfg(feature = "http")]
pub use http::{HttpCrlSource, HttpOcspSource};
pub use ocsp::{OcspRequest, OcspResponse, OcspStatus};
pub use x509_cert::ext::pkix::CrlReason;
