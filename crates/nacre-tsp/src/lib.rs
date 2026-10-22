#![forbid(unsafe_code)]
//! RFC 3161 time-stamping, written for Nacre. **Experimental**: not yet fuzzed at length
//! nor cross-checked against a reference crate.
//!
//! [`Request`] builds a DER `TimeStampReq` from a digest, with a nonce and `certReq`.
//! [`verify_response`] reads the TSA's `TimeStampResp` and checks its status, then the
//! token: [`verify_token`] verifies its `SignedData` with [`nacre_cms`], requires a
//! `signingCertificateV2` binding it to the TSA certificate, requires that certificate's
//! extended key usage to be `id-kp-timeStamping` alone and critical (RFC 3161 §2.3), and
//! compares the time-stamped imprint with the expected one; the response check then
//! compares the nonce.
//!
//! Only the imprint leaves the caller: the request carries the digest, never the data.
//! Nothing here reads the clock: `genTime` is returned, never judged, and neither the
//! chain nor the validity of the TSA certificate is judged.
//!
//! The `http` feature, off by default, adds `HttpTsa`, a
//! [`nacre_core::TimestampAuthority`] that posts the request to a TSA over HTTP; without
//! it the crate has no network dependency.

mod asn1;
mod error;
#[cfg(feature = "http")]
mod http;
pub mod oid;
mod request;
mod response;
mod token;

pub use error::Error;
#[cfg(feature = "http")]
pub use http::HttpTsa;
pub use request::Request;
pub use response::verify_response;
pub use token::{VerifiedToken, verify_token};
