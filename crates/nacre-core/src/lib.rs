#![forbid(unsafe_code)]
//! The contract every Nacre signature family and every caller codes against.
//!
//! `nacre-core` defines the [`Signer`], [`TimestampAuthority`] and [`RevocationSource`]
//! traits, through which a family obtains a signature, a timestamp token or revocation
//! data without performing any I/O itself, and the [`ValidationReport`] a validator
//! returns, named after ETSI EN 319 102-1.
//!
//! Certificates, tokens, CRLs and OCSP responses cross the traits as DER bytes, and every
//! trait method returns the single [`Error`] of this crate; an implementation's own error
//! travels as its boxed [`std::error::Error::source`].
//! [`Error::kind`] gives the coarse [`ErrorKind`] an application may show to a third party.
//!
//! The `test-signer` feature, never enabled by default, adds [`TestSigner`], a software
//! P-256 signer for tests only.

mod algorithm;
mod error;
mod report;
mod revocation;
mod signer;
#[cfg(feature = "test-signer")]
mod test_signer;
mod timestamp;

pub use algorithm::{DigestAlgorithm, SignatureAlgorithm};
pub use error::{BoxError, Error, ErrorKind};
pub use report::{
    Indication, SignatureForm, SignatureLevel, SignatureProfile, SubIndication, ValidationReport,
};
pub use revocation::{RevocationData, RevocationSource};
pub use signer::Signer;
#[cfg(feature = "test-signer")]
pub use test_signer::TestSigner;
pub use timestamp::TimestampAuthority;
