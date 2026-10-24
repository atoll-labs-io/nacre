/// The rules only Nacre applies, one switch each (ADR-0026, ADR-0029, ADR-0030). Each switch on
/// keeps a protection DSS 6.5.1 lacks; each switch off gives DSS's verdict on that case.
///
/// [`ValidationPolicy::strict`], the [`Default`], turns them all on and is what
/// [`validate`](crate::validate), [`validate_with_anchors`](crate::validate_with_anchors)
/// and [`validate_with_revocation`](crate::validate_with_revocation) apply.
/// [`ValidationPolicy::dss`] turns them all off. A rule DSS applies and Nacre would
/// otherwise lack, such as a signing time (`/M`) missing or out of the signer's validity,
/// revocation data issued after a certificate's `notAfter` with no `expiredCertsOnCRL`
/// not counting, revocation data from a CA out of its validity at the control date, or a
/// CA without `subjectKeyIdentifier`, is no switch:
/// both presets apply it, so no preset is laxer than DSS. Turning one switch off from
/// `strict()` reopens that switch's attack only.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationPolicy {
    /// Refuse a later revision no rule allows ([`Defect::RevisionNotAllowed`]), a signature
    /// added under DocMDP 1 ([`Defect::AddedByRevisionNotAllowed`]) and signed bytes that
    /// end at no revision ([`Defect::ByteRangeNotWholeFile`]). Off, the signature is judged
    /// as if nothing were appended: shadow attacks and incremental saving attacks pass.
    /// [`SignatureValidation::later_revisions`] lists the revisions either way.
    ///
    /// [`Defect::RevisionNotAllowed`]: crate::Defect::RevisionNotAllowed
    /// [`Defect::AddedByRevisionNotAllowed`]: crate::Defect::AddedByRevisionNotAllowed
    /// [`Defect::ByteRangeNotWholeFile`]: crate::Defect::ByteRangeNotWholeFile
    /// [`SignatureValidation::later_revisions`]: crate::SignatureValidation::later_revisions
    pub refuse_later_revisions: bool,
    /// Refuse a signature added on a certified document whose field shows a widget the
    /// certified state did not place at the same rectangle (the sneaky signature attack).
    pub refuse_sneaky_signatures: bool,
    /// Refuse a file with data after its last `startxref … %%EOF`. Off, the file is judged
    /// as it stands before that data, which is ignored.
    pub refuse_trailing_data: bool,
    /// List a field whose `/V` is neither a reference nor names a dictionary, whose
    /// `/Contents` is missing or not DER, or whose `/ByteRange` is malformed, as
    /// `TOTAL_FAILED`. Off, such a field is left out of the result, as DSS does.
    pub list_unusable_signatures: bool,
    /// Judge the signer's `keyUsage` and `extendedKeyUsage` ([`ChainDefect::KeyUsage`],
    /// [`ChainDefect::ExtendedKeyUsage`]). A timestamp authority's are judged either way.
    ///
    /// [`ChainDefect::KeyUsage`]: crate::ChainDefect::KeyUsage
    /// [`ChainDefect::ExtendedKeyUsage`]: crate::ChainDefect::ExtendedKeyUsage
    pub judge_signer_key_usage: bool,
    /// Refuse a signer's path holding a certificate out of its validity at the
    /// best-signature-time before its revocation is judged (`OUT_OF_BOUNDS_NO_POE`). Off,
    /// revocation is judged first: no data gives `CERTIFICATE_CHAIN_GENERAL_FAILURE`, a
    /// revocation `REVOKED_NO_POE`, and "not revoked" [`Defect::OutOfRangeNotRevoked`].
    ///
    /// [`Defect::OutOfRangeNotRevoked`]: crate::Defect::OutOfRangeNotRevoked
    pub judge_validity_before_revocation: bool,
    /// Give a verdict ([`ChainDefect::MalformedExtension`]) on a certificate that repeats
    /// an extension; a timestamp authority's then gives no proof of time. Off, a
    /// certificate of a verified signature's CMS, or of one of its signature timestamp
    /// tokens, that repeats one makes the validation fail with
    /// [`Error::MalformedCertificate`], as DSS does; a `/DSS` certificate is not scanned.
    ///
    /// [`ChainDefect::MalformedExtension`]: crate::ChainDefect::MalformedExtension
    /// [`Error::MalformedCertificate`]: crate::Error::MalformedCertificate
    pub judge_malformed_extensions: bool,
    /// With no proof of existence, count only revocation data issued within 24 hours before
    /// the control date that says "not revoked"; an older revocation dated at or before the
    /// judged time still counts, unless it is a `certificateHold`. Off, freshness is
    /// ignored: an old "not revoked" in the `/DSS` passes a key revoked since.
    pub require_fresh_revocation: bool,
    /// Refuse a signature whose `/SubFilter` is neither `/ETSI.CAdES.detached` nor
    /// `/adbe.pkcs7.detached` ([`Defect::UnsupportedSubFilter`]). Off, any other
    /// `/SubFilter`, a missing one or one that is not a name included, is verified as a
    /// detached CMS and gets no ETSI level, as DSS does (ADR-0027, ADR-0029).
    ///
    /// [`Defect::UnsupportedSubFilter`]: crate::Defect::UnsupportedSubFilter
    pub refuse_unsupported_sub_filters: bool,
    /// Refuse a file whose `startxref` or `/Prev` offset lands on whitespace before its
    /// cross-reference section ([`Error::Pdf`] `NotAnXrefSection`). Off, that whitespace
    /// is skipped through `nacre_pdf::ReadOptions::misplaced_xref`, as DSS reads such a
    /// file; an offset landing anywhere else is refused either way.
    ///
    /// [`Error::Pdf`]: crate::Error::Pdf
    pub refuse_misplaced_xref: bool,
    /// Drop a CRL, or an OCSP response, issued after the `notAfter` of the certificate it
    /// covers, even when the CRL's `expiredCertsOnCRL` extension (RFC 5280, 5.2.7), or the
    /// response's `archiveCutoff` (RFC 6960, 4.4.4), is at or before that `notAfter`. Off,
    /// such data counts for that certificate, as DSS does (ADR-0030); data whose date is
    /// later, or absent, is dropped either way.
    pub ignore_expired_certs_on_crl: bool,
    /// Require the CA, or the delegated OCSP responder, that issued the deciding revocation
    /// data of a certificate to be within its validity at the control date even when that
    /// data says "revoked" (after the best-signature-time, since an earlier revocation
    /// refuses the path first). Off, such a certificate is skipped by that rule, as DSS does
    /// (ADR-0030); data saying "not revoked" is judged either way.
    pub judge_issuer_of_revoked_data: bool,
}

impl ValidationPolicy {
    /// Every switch on: every protection Nacre has. The default.
    pub const fn strict() -> Self {
        Self {
            refuse_later_revisions: true,
            refuse_sneaky_signatures: true,
            refuse_trailing_data: true,
            list_unusable_signatures: true,
            judge_signer_key_usage: true,
            judge_validity_before_revocation: true,
            judge_malformed_extensions: true,
            require_fresh_revocation: true,
            refuse_unsupported_sub_filters: true,
            refuse_misplaced_xref: true,
            ignore_expired_certs_on_crl: true,
            judge_issuer_of_revoked_data: true,
        }
    }

    /// **Unsafe for deciding whether to trust a document**: this preset accepts attacks
    /// that [`strict`](Self::strict) refuses — shadow attacks and incremental saving
    /// attacks (any later revision), sneaky signatures, data appended after the last
    /// `%%EOF`, a signer certificate whose key usage forbids signing, a signature under a
    /// `/SubFilter` Nacre does not support, a cross-reference section found only by
    /// skipping whitespace, a CRL issued after a certificate expired, trusted on its
    /// `expiredCertsOnCRL`, or an OCSP response trusted on its `archiveCutoff`, revocation data saying revoked, trusted from a CA or responder
    /// out of its validity, and, for a signature with no timestamp, a stale "not revoked"
    /// CRL or OCSP response appended to the `/DSS`.
    ///
    /// Every switch off: the verdict DSS 6.5.1 gives, for comparing Nacre with it. Only the
    /// rules DSS also applies remain.
    pub const fn dss() -> Self {
        Self {
            refuse_later_revisions: false,
            refuse_sneaky_signatures: false,
            refuse_trailing_data: false,
            list_unusable_signatures: false,
            judge_signer_key_usage: false,
            judge_validity_before_revocation: false,
            judge_malformed_extensions: false,
            require_fresh_revocation: false,
            refuse_unsupported_sub_filters: false,
            refuse_misplaced_xref: false,
            ignore_expired_certs_on_crl: false,
            judge_issuer_of_revoked_data: false,
        }
    }
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self::strict()
    }
}
