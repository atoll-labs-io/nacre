#![forbid(unsafe_code)]
//! Validation of PAdES signatures for Nacre. **Experimental**: not yet fuzzed at length nor
//! cross-checked against a reference validator.
//!
//! [`validate`] judges the integrity of each signature of a PDF: its `/ByteRange` covers
//! the whole file except the `/Contents` hex string, that string holds one DER `SignedData`,
//! and the digest and signature of that `SignedData` verify over the signed bytes. It
//! returns one [`SignatureValidation`] per signature, in field order.
//!
//! The certificate chain, revocation and the level are not judged yet, so a sound
//! signature ends `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, never `TOTAL_PASSED`.
//! A signature followed by a later revision is refused for now
//! ([`Defect::LaterRevision`]): qualifying later revisions comes next. Document timestamps
//! (`/SubFilter /ETSI.RFC3161`) are left out of the result.

mod error;
mod report;
mod validate;

pub use error::Error;
pub use report::{Defect, SignatureValidation};
pub use validate::validate;
