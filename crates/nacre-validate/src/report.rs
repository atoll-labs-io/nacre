use nacre_core::{SubIndication, ValidationReport};

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
    /// The first rule the signature broke, `None` when both checks passed.
    pub defect: Option<Defect>,
}

/// The first rule a signature broke. Every structural defect gives `TOTAL_FAILED` /
/// `FORMAT_FAILURE`; a [`Defect::Cms`] gives the outcome of its CMS error.
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
    /// A later revision follows the signed one.
    LaterRevision,
    /// `/Contents` is not one DER `SEQUENCE` followed only by zero bytes.
    ContentsNotDer,
    /// The CMS `SignedData` is unreadable or does not verify.
    Cms(nacre_cms::Error),
}

impl SignatureValidation {
    pub(crate) fn sound(field: String) -> Self {
        Self {
            field,
            report: ValidationReport::indeterminate(SubIndication::NoCertificateChainFound, None),
            digest_verified: true,
            signature_verified: true,
            defect: None,
        }
    }

    pub(crate) fn defective(field: String, defect: Defect) -> Self {
        let (report, digest_verified) = match &defect {
            Defect::Cms(error) => cms_outcome(error),
            _ => (
                ValidationReport::failed(SubIndication::FormatFailure, None),
                false,
            ),
        };
        Self {
            field,
            report,
            digest_verified,
            signature_verified: false,
            defect: Some(defect),
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
            let v = SignatureValidation::defective("f".into(), Defect::Cms(error));
            assert_eq!(v.report.indication(), indication, "{name}");
            assert_eq!(v.report.sub_indication(), Some(sub), "{name}");
            assert_eq!(v.digest_verified, digest_verified, "{name}");
            assert!(!v.signature_verified, "{name}");
        }
    }
}
