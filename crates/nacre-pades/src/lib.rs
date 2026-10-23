#![forbid(unsafe_code)]
//! PAdES (ETSI EN 319 142-1) for Nacre. **Experimental**: not yet fuzzed at length nor
//! cross-checked against a reference implementation.
//!
//! [`sign`] signs a PDF at PAdES-BASELINE-B and [`sign_at_level`] at B-B, B-T, B-LT or B-LTA:
//! it appends one incremental revision holding an invisible signature field whose `/Sig`
//! dictionary has `/SubFilter /ETSI.CAdES.detached` and the signing time in `/M`, and whose
//! `/Contents` holds a detached CMS carrying `signingCertificateV2` and never `signingTime`.
//!
//! At B-T the token of a timestamp authority sits in the unsigned attribute
//! `id-aa-signatureTimeStampToken` of the `SignerInfo` and time-stamps the signature value.
//! The authority is reached only through `TimestampAuthority`.
//!
//! At B-LT a further revision adds a `/DSS` dictionary holding the certificates of the
//! signer's chain and of the timestamp token, their CRLs and OCSP responses, and a `/VRI`
//! entry for the signature. Revocation data is obtained only through `RevocationSource`.
//!
//! At B-LTA a last revision holds a document timestamp (`/Type /DocTimeStamp`,
//! `/SubFilter /ETSI.RFC3161`) over every byte before it, from an authority that may differ
//! from the signature's. [`extend`] later renews it: one revision adds the validation data of
//! the newest document timestamp's authority to `/DSS`, then another holds a new document
//! timestamp. When to extend is the caller's decision.
//!
//! Revocation data never goes into the CMS. The signing time is the caller's: this crate
//! reads no clock.

mod archive;
mod dss;
mod error;
mod ltv;
mod reserve;
mod sign;
mod timestamp;

pub use archive::extend;
pub use der::DateTime;
pub use error::{Error, SignedPdf};
pub use sign::{Level, sign, sign_at_level};
pub use timestamp::TIMESTAMP_TOKEN_MAX;
