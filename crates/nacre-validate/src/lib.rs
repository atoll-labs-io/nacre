#![forbid(unsafe_code)]
//! Validation of PAdES signatures for Nacre. **Experimental**: not yet fuzzed at length nor
//! cross-checked against a reference validator.
//!
//! [`validate`] judges the integrity of each signature of a PDF: its `/ByteRange` covers
//! the whole file except the `/Contents` hex string, that string holds one DER `SignedData`,
//! and the digest and signature of that `SignedData` verify over the signed bytes. It
//! returns one [`SignatureValidation`] per signature, in field order.
//!
//! Each revision appended after a signature is listed in its result
//! ([`SignatureValidation::later_revisions`]) with the objects it changes, and qualified by
//! comparing the objects reachable before and after it: a `/DSS`, a document timestamp, a
//! new signature, or a form fill the DocMDP and FieldMDP permissions allow. Any other
//! change fails the signature with [`Defect::RevisionNotAllowed`]. A signature its own
//! revision refuses as a signature (on a certified document, one whose field shows a widget
//! the certified state did not place at the same rectangle, or one under DocMDP 1) fails
//! with [`Defect::AddedByRevisionNotAllowed`].
//!
//! [`validate_with_anchors`] also builds the signer's certification path from the
//! certificates of the CMS and of the `/DSS` up to the [`TrustAnchors`] the caller supplies,
//! and judges it at a control date the caller gives (RFC 5280 path validation: validity,
//! basic constraints, path length, key usage, extended key usage, critical extensions).
//! [`build_chain`] does the same with no PDF, for any format. [`validate`] trusts no
//! anchor, so a sound signature ends `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`. A
//! valid path is returned in [`SignatureValidation::chain`], and the signature still ends
//! `INDETERMINATE` / `TRY_LATER`: revocation and the level are not judged yet, so no
//! signature ends `TOTAL_PASSED`.
//! Document timestamps (`/SubFilter /ETSI.RFC3161`) are left out of the result.

mod chain;
mod error;
mod report;
mod revisions;
mod validate;

pub use chain::{CertificatePath, ChainDefect, TrustAnchors, build_chain};
pub use error::Error;
pub use nacre_pdf::ObjectId;
pub use report::{AllowedChange, Defect, LaterRevision, RevisionVerdict, SignatureValidation};
pub use validate::{validate, validate_with_anchors};
