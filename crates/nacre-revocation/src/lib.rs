#![forbid(unsafe_code)]
//! Certificate revocation for Nacre, starting with X.509 CRLs (RFC 5280 §5).
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
//! Judged here: one CRL against one certificate at one date. Left to the caller (s17): the
//! certificate chain, and comparing a revocation date with a signing time. A v1 CRL, which
//! has no version field, is refused as invalid DER.
//!
//! Under the `http` feature, `HttpCrlSource` implements [`nacre_core::RevocationSource`] by
//! downloading the CRL named by a certificate's `http://` distribution point. That URL is
//! untrusted: the source reaches only public addresses and follows no redirect. No other
//! code path opens a connection, and nothing reads the system clock.

mod crl;
mod error;
#[cfg(feature = "http")]
mod http;
mod verify;

pub use crl::{Crl, CrlStatus, RevokedEntry};
pub use error::Error;
#[cfg(feature = "http")]
pub use http::HttpCrlSource;
pub use x509_cert::ext::pkix::CrlReason;
