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
//! [`validate_with_revocation`] also builds the signer's certification path from the
//! certificates of the CMS and of the `/DSS` up to the [`TrustAnchors`] the caller supplies
//! (RFC 5280 path validation: validity, basic constraints, path length, key usage, extended
//! key usage, critical extensions), then judges the revocation of each certificate of it
//! from the CRLs and OCSP responses the document carries and an optional
//! [`nacre_core::RevocationSource`], issued within that certificate's validity: data issued
//! after its `notAfter` does not count, as DSS 6.5.1 drops it. Both are judged at the
//! best-signature-time: the `genTime` of the earliest timestamp whose token verifies and
//! whose authority's path and revocation pass at the control date the caller gives, a
//! signature timestamp or a document timestamp after the signature, else that control date
//! ([`SignatureValidation::best_signature_time`]). A revocation dated after it does not
//! count. Revocation data is judged at its own date, its
//! freshness ignored, as DSS does, except for a signature no timestamp gives a proof of
//! existence: there a "not revoked" counts only when issued within 24 hours before the
//! control date, a deliberate departure from DSS 6.5.1 that keeps an old CRL appended to
//! the `/DSS` from passing a key revoked since, while an old proof of revocation still
//! counts unless it is a `certificateHold`. A revoked certificate gives `INDETERMINATE` /
//! `REVOKED_NO_POE` (or `REVOKED_CA_NO_POE`), one put on hold `TRY_LATER`, one with no
//! usable revocation data `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE` ([`Defect::Revocation`],
//! [`RevocationDefect`]), the verdicts DSS 6.5.1 gives. A path that passes gives
//! `TOTAL_PASSED` unless the signing time the signature claims (`/M`) is missing or unreadable, before the signer's `notBefore` or after its `notAfter`:
//! `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE` ([`Defect::ClaimedTimeMissing`],
//! [`Defect::ClaimedTimeBeforeCertificate`], [`Defect::ClaimedTimeAfterCertificate`]), as
//! DSS does. Before that claimed time, a CA below the anchor without
//! `subjectKeyIdentifier` gives `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`
//! ([`Defect::CaKeyIdentifierMissing`]), and revocation data whose issuing CA, below the
//! anchor, or whose delegated OCSP responder is out of its validity at the control date
//! gives `INDETERMINATE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE`
//! ([`RevocationDefect::IssuerOutOfBounds`]), as DSS does. A timestamp token whose
//! authority's path holds a CA below the anchor without `subjectKeyIdentifier` proves no
//! time. These rules, DSS's own, apply under every policy, except that DSS exempts the
//! anchor's delegated OCSP responder, which only a switch judges. [`validate_with_anchors`]
//! does the same with no source. [`build_chain`] builds and judges a path with no PDF, for
//! any format. [`validate`] trusts no anchor, so a sound signature ends `INDETERMINATE` /
//! `NO_CERTIFICATE_CHAIN_FOUND`. Document timestamps (`/SubFilter /ETSI.RFC3161`) are left
//! out of the result.
//!
//! Every listed signature's report carries the level its structure reaches, whatever its
//! verdict, as DSS 6.5.1 reads it (ADR-0025): the form from `/SubFilter` (PAdES or PKCS7),
//! `PAdES-BES` for a `signingTime` attribute or no readable `/M`, then B, T with a
//! signature or document timestamp valid or not, LT when the `/DSS` of the file, gathered
//! over its revisions, holds data its issuer signed for each certificate of the chains that
//! count, LTA when a document
//! timestamp covers a `/DSS` that already gives LT. A PAdES signature without ESS
//! `signingCertificate` nor `signingCertificateV2`, or under any other `/SubFilter`, has no
//! level. The proof of time stays in [`SignatureValidation::best_signature_time`].
//!
//! Every rule above that DSS 6.5.1 does not apply is a switch of a [`ValidationPolicy`]
//! (ADR-0026, ADR-0029, ADR-0030, ADR-0031): later revisions, sneaky signatures, trailing
//! data after the last `%%EOF`, unusable signatures listed, the signer's key usage, validity judged
//! before revocation, malformed extensions judged, fresh revocation, unsupported
//! `/SubFilter`s refused, a misplaced cross-reference offset refused, a CRL's
//! `expiredCertsOnCRL` and an OCSP response's `archiveCutoff` ignored, the issuer of
//! data saying "revoked" judged, the anchor's delegated OCSP responder judged, and OCSP
//! responses with a critical extension refused. [`validate`],
//! [`validate_with_anchors`] and [`validate_with_revocation`] apply
//! [`ValidationPolicy::strict`], every switch on. [`validate_with_policy`] takes the
//! policy; [`ValidationPolicy::dss`] turns every switch off to give DSS's verdict, and
//! reopens the attacks its documentation names.

mod chain;
mod date;
mod error;
mod level;
mod policy;
mod report;
mod revisions;
mod revocation;
mod validate;

pub use chain::{CertificatePath, ChainDefect, TrustAnchors, build_chain};
pub use error::Error;
pub use nacre_pdf::ObjectId;
pub use policy::ValidationPolicy;
pub use report::{AllowedChange, Defect, LaterRevision, RevisionVerdict, SignatureValidation};
pub use revocation::RevocationDefect;
pub use validate::{
    validate, validate_with_anchors, validate_with_policy, validate_with_revocation,
};
