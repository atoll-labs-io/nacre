#![forbid(unsafe_code)]
//! CMS `SignedData` (RFC 5652), written for Nacre. **Experimental**: not yet fuzzed at
//! length nor cross-checked against a reference crate.
//!
//! [`sign_detached`] signs a digest with a [`nacre_core::Signer`] into a detached DER
//! `SignedData` whose signed attributes are `contentType`, `messageDigest` and
//! `signingCertificateV2`, plus `signingTime` when the [`Profile`] allows it.
//! [`SignedData::from_der`] reads one, detached or encapsulated, and
//! [`SignedData::verify`] checks it for ECDSA P-256 and RSA PKCS#1 v1.5 with SHA-256.
//!
//! Received bytes are kept: the signed attributes are verified over the octets that
//! arrived, never over a re-encoding, and [`SignedData::to_der`] writes a decoded value
//! back unchanged, so an unsigned attribute can be added without re-signing.

mod error;
mod model;
pub mod oid;
mod sign;
mod verify;

pub use error::Error;
pub use model::{
    Attribute, ContentInfo, EncapsulatedContentInfo, SignedAttributes, SignedData,
    SignerIdentifier, SignerInfo,
};
pub use sign::{Profile, sign_detached};
pub use verify::VerifiedSigner;
