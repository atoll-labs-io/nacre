#![forbid(unsafe_code)]
//! PAdES (ETSI EN 319 142-1) for Nacre. **Experimental**: not yet fuzzed at length nor
//! cross-checked against a reference implementation.
//!
//! [`sign`] signs a PDF at PAdES-BASELINE-B, and only that level: it appends one
//! incremental revision holding an invisible signature field whose `/Sig` dictionary has
//! `/SubFilter /ETSI.CAdES.detached` and the signing time in `/M`, and whose `/Contents`
//! holds a detached CMS carrying `signingCertificateV2` and never `signingTime`.
//!
//! Revocation data never goes into the CMS. The signing time is the caller's: this crate
//! reads no clock.

mod error;
mod reserve;
mod sign;

pub use der::DateTime;
pub use error::Error;
pub use sign::sign;
