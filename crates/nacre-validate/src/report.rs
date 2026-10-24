use std::time::SystemTime;

use nacre_core::{SubIndication, ValidationReport};
use nacre_pdf::ObjectId;

use crate::{CertificatePath, ChainDefect, RevocationDefect};

/// The integrity verdict on one signature field.
#[non_exhaustive]
#[derive(Debug)]
pub struct SignatureValidation {
    /// The field's dotted full name.
    pub field: String,
    pub report: ValidationReport,
    /// The digest of the signed bytes matches the CMS `messageDigest`.
    pub digest_verified: bool,
    /// The CMS signature verifies with the signer certificate's key.
    pub signature_verified: bool,
    /// The first rule the signature broke, `None` when every check passed.
    pub defect: Option<Defect>,
    /// Each revision appended after the one the signed bytes end at, oldest first; empty
    /// when the signed bytes end at no revision.
    pub later_revisions: Vec<LaterRevision>,
    /// The certification path from the signer to a trust anchor that RFC 5280 judges
    /// valid at the best-signature-time, `None` when no path was found or the signature
    /// failed before its chain was built. `Some` with a [`Defect::Revocation`],
    /// [`Defect::OutOfRangeNotRevoked`] or [`Defect::ClaimedTimeBeforeCertificate`] means
    /// the path is valid but a check judged after it failed.
    pub chain: Option<CertificatePath>,
    /// The `genTime` of the earliest signature timestamp whose token verifies and whose
    /// authority's path and revocation pass at the control date; `None` when no timestamp
    /// gives that proof, the control date then standing for it.
    pub best_signature_time: Option<SystemTime>,
}

/// One revision appended after a signature, and what it changes.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaterRevision {
    /// The offset just past this revision's `%%EOF`.
    pub end: usize,
    /// Every object reachable from the catalog that the revision changes or adds, sorted,
    /// whatever the verdict.
    pub changed: Vec<ObjectId>,
    pub verdict: RevisionVerdict,
}

/// Whether a later revision is one a signed document may receive.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionVerdict {
    /// Every change matches an allowed kind; an empty list means nothing visible changed.
    Allowed(Vec<AllowedChange>),
    /// `refused` lists, sorted, the changed objects no rule accepts.
    NotAllowed { refused: Vec<ObjectId> },
    /// The document as of this revision, or of the one before, cannot be read.
    Unreadable,
}

/// A kind of change a later revision may make.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedChange {
    /// The document security store (`/DSS`) is added or extended.
    Dss,
    /// A document timestamp is added.
    DocumentTimestamp,
    /// A signature is added.
    Signature,
    /// Form fields are filled, as the DocMDP and FieldMDP permissions in force allow.
    FormFill,
}

/// The first rule a signature broke. Every structural defect gives `TOTAL_FAILED` /
/// `FORMAT_FAILURE`; a [`Defect::Cms`] gives the outcome of its CMS error, a
/// [`Defect::Chain`] that of its chain defect, a [`Defect::Revocation`] that of its
/// revocation defect; the two defects judged after revocation are `INDETERMINATE`. A
/// defect a [`ValidationPolicy`](crate::ValidationPolicy) switch guards is not given with
/// that switch off: the revision defects, [`Defect::ByteRangeNotWholeFile`], the
/// sneaky-signature case of [`Defect::AddedByRevisionNotAllowed`], the signer's key usage
/// and validity among the [`Defect::Chain`] ones.
#[non_exhaustive]
#[derive(Debug)]
pub enum Defect {
    /// `/V` does not name a dictionary.
    NotASignatureDictionary,
    /// `/SubFilter` is neither `/ETSI.CAdES.detached` nor `/adbe.pkcs7.detached`.
    UnsupportedSubFilter,
    /// `/Contents` is absent, `null`, empty or not a string.
    ContentsMissing,
    /// `/ByteRange` is not an array of four non-negative integers.
    ByteRangeMalformed,
    /// The first signed range does not start at byte 0.
    ByteRangeNotFromStart,
    /// The second signed range starts before the first one ends.
    ByteRangeOverlap,
    /// The second signed range ends past the end of the file.
    ByteRangeOutsideFile,
    /// The bytes between the two ranges are not exactly the `/Contents` hex string.
    GapNotContents,
    /// The signed bytes do not end where a revision ends.
    ByteRangeNotWholeFile,
    /// A later revision, the one ending at `end`, is not allowed or cannot be read.
    RevisionNotAllowed { end: usize },
    /// The revision that added this signature, the one ending at `end`, refuses it as a
    /// signature: on a certified document, one whose field shows a widget the certified
    /// state did not place at the same rectangle, or any signature under DocMDP 1.
    AddedByRevisionNotAllowed { end: usize },
    /// `/Contents` is not one DER `SEQUENCE` followed only by zero bytes.
    ContentsNotDer,
    /// The CMS `SignedData` is unreadable or does not verify.
    Cms(nacre_cms::Error),
    /// A path reaches a trust anchor but breaks a rule of RFC 5280; judged last, once the
    /// integrity and the later revisions passed. Its report is [`ChainDefect::report`].
    Chain(ChainDefect),
    /// The path is valid but a certificate of it is revoked at or before the
    /// best-signature-time, or has no usable revocation data; judged after the chain. Its
    /// report is [`RevocationDefect::report`].
    Revocation(RevocationDefect),
    /// Under a [`ValidationPolicy`](crate::ValidationPolicy) that judges revocation before
    /// validity, a certificate of the path, the one the [`ChainDefect::Expired`] or
    /// [`ChainDefect::NotYetValid`] it holds names, is out of its validity at the
    /// best-signature-time while its revocation data says it is not revoked:
    /// `INDETERMINATE` / `OUT_OF_BOUNDS_NOT_REVOKED`, the path kept.
    OutOfRangeNotRevoked(ChainDefect),
    /// The signing time the signature dictionary claims (`/M`) is before the signer
    /// certificate's `notBefore`: `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE`, the path
    /// kept. Judged under every policy, once the chain and its revocation passed.
    ClaimedTimeBeforeCertificate,
}

impl SignatureValidation {
    /// A signature every check passed: `chain` is its valid path, whose revocation passed
    /// too, and the signature `TOTAL_PASSED` with no level; `None` when no path reaches an
    /// anchor.
    pub(crate) fn sound(
        field: String,
        later_revisions: Vec<LaterRevision>,
        chain: Option<CertificatePath>,
        best_signature_time: Option<SystemTime>,
    ) -> Self {
        let report = match chain {
            Some(_) => ValidationReport::passed(None),
            None => ValidationReport::indeterminate(SubIndication::NoCertificateChainFound, None),
        };
        Self {
            field,
            report,
            digest_verified: true,
            signature_verified: true,
            defect: None,
            later_revisions,
            chain,
            best_signature_time,
        }
    }

    /// A signature whose valid `chain` failed a check judged after it: revocation, validity
    /// after revocation, or the claimed signing time.
    pub(crate) fn after_chain(
        field: String,
        defect: Defect,
        later_revisions: Vec<LaterRevision>,
        chain: CertificatePath,
        best_signature_time: Option<SystemTime>,
    ) -> Self {
        Self {
            chain: Some(chain),
            best_signature_time,
            ..Self::defective(field, defect, later_revisions)
        }
    }

    pub(crate) fn defective(
        field: String,
        defect: Defect,
        later_revisions: Vec<LaterRevision>,
    ) -> Self {
        let failed = || ValidationReport::failed(SubIndication::FormatFailure, None);
        // The revision rule is judged last, once the digest and the signature verified.
        let (report, digest_verified, signature_verified) = match &defect {
            Defect::Cms(error) => {
                let (report, digest_verified) = cms_outcome(error);
                (report, digest_verified, false)
            }
            Defect::RevisionNotAllowed { .. } | Defect::AddedByRevisionNotAllowed { .. } => {
                (failed(), true, true)
            }
            Defect::Chain(chain) => (chain.report(), true, true),
            Defect::Revocation(revocation) => (revocation.report(), true, true),
            Defect::OutOfRangeNotRevoked(_) => (
                ValidationReport::indeterminate(SubIndication::OutOfBoundsNotRevoked, None),
                true,
                true,
            ),
            Defect::ClaimedTimeBeforeCertificate => (
                ValidationReport::indeterminate(SubIndication::SigConstraintsFailure, None),
                true,
                true,
            ),
            _ => (failed(), false, false),
        };
        Self {
            field,
            report,
            digest_verified,
            signature_verified,
            defect: Some(defect),
            later_revisions,
            chain: None,
            best_signature_time: None,
        }
    }
}

/// The report a CMS verification error gives, and whether the digest was verified before
/// it: `nacre-cms` checks the message digest just before the signature, so only
/// `SignatureInvalid` comes after a verified digest.
fn cms_outcome(error: &nacre_cms::Error) -> (ValidationReport, bool) {
    use nacre_cms::Error as E;
    match error {
        E::MessageDigestMismatch | E::DigestLength { .. } => (
            ValidationReport::failed(SubIndication::HashFailure, None),
            false,
        ),
        E::SignatureInvalid => (
            ValidationReport::failed(SubIndication::SigCryptoFailure, None),
            true,
        ),
        E::AlgorithmMismatch => (
            ValidationReport::failed(SubIndication::SigCryptoFailure, None),
            false,
        ),
        E::SignerCertificateNotFound | E::SigningCertificateMismatch => (
            ValidationReport::indeterminate(SubIndication::NoSigningCertificateFound, None),
            false,
        ),
        E::UnsupportedAlgorithm(_) => (
            ValidationReport::indeterminate(SubIndication::CryptoConstraintsFailureNoPoe, None),
            false,
        ),
        _ => (
            ValidationReport::failed(SubIndication::FormatFailure, None),
            false,
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use der::oid::ObjectIdentifier;
    use nacre_cms::Error as E;
    use nacre_core::Indication::{self, *};
    use nacre_core::SubIndication::*;

    #[test]
    fn every_cms_error_has_its_outcome() {
        let oid = ObjectIdentifier::new_unwrap("1.2.3");
        let der = || der::Error::from(der::ErrorKind::Failed);
        let rows: Vec<(E, Indication, SubIndication, bool)> = vec![
            (E::MessageDigestMismatch, TotalFailed, HashFailure, false),
            (
                E::DigestLength {
                    expected: 32,
                    actual: 20,
                },
                TotalFailed,
                HashFailure,
                false,
            ),
            (E::SignatureInvalid, TotalFailed, SigCryptoFailure, true),
            (E::AlgorithmMismatch, TotalFailed, SigCryptoFailure, false),
            (
                E::SignerCertificateNotFound,
                Indeterminate,
                NoSigningCertificateFound,
                false,
            ),
            (
                E::SigningCertificateMismatch,
                Indeterminate,
                NoSigningCertificateFound,
                false,
            ),
            (
                E::UnsupportedAlgorithm(oid),
                Indeterminate,
                CryptoConstraintsFailureNoPoe,
                false,
            ),
            (E::Der(der()), TotalFailed, FormatFailure, false),
            (E::NotSignedData, TotalFailed, FormatFailure, false),
            (E::SignerCount(2), TotalFailed, FormatFailure, false),
            (
                E::MissingSignedAttributes,
                TotalFailed,
                FormatFailure,
                false,
            ),
            (E::MissingAttribute(oid), TotalFailed, FormatFailure, false),
            (
                E::DuplicateAttribute(oid),
                TotalFailed,
                FormatFailure,
                false,
            ),
            (
                E::AttributeValueCount(oid),
                TotalFailed,
                FormatFailure,
                false,
            ),
            (
                E::ForbiddenAttribute(oid),
                TotalFailed,
                FormatFailure,
                false,
            ),
            (E::ContentTypeMismatch, TotalFailed, FormatFailure, false),
            (E::ContentMissing, TotalFailed, FormatFailure, false),
            (E::ContentAmbiguous, TotalFailed, FormatFailure, false),
            (E::Certificate(der()), TotalFailed, FormatFailure, false),
            (
                E::Signer(nacre_core::Error::Signer("x".into())),
                TotalFailed,
                FormatFailure,
                false,
            ),
        ];
        assert_eq!(rows.len(), 20);
        for (error, indication, sub, digest_verified) in rows {
            let name = format!("{error:?}");
            let v = SignatureValidation::defective("f".into(), Defect::Cms(error), Vec::new());
            assert_eq!(v.report.indication(), indication, "{name}");
            assert_eq!(v.report.sub_indication(), Some(sub), "{name}");
            assert_eq!(v.digest_verified, digest_verified, "{name}");
            assert!(!v.signature_verified, "{name}");
        }
    }
}
