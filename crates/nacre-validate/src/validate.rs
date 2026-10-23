use std::time::SystemTime;

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode, Header, Reader, SliceReader, Tag};
use nacre_cms::SignedData;
use nacre_core::{DigestAlgorithm, RevocationData, RevocationSource};
use nacre_pdf::{Dictionary, Document, Object};
use sha2::{Digest, Sha256};

use crate::chain::{Purpose, build_path};
use crate::revisions::{Qualified, qualify};
use crate::revocation::{FRESHNESS_TOLERANCE, RevocationPool, judge_path};
use crate::{
    ChainDefect, Defect, Error, LaterRevision, RevisionVerdict, SignatureValidation, TrustAnchors,
};

/// Bounds the hashing one call may do to 64 times the largest accepted input (50 MB).
const MAX_SIGNATURES: usize = 64;

const SUB_FILTERS: [&[u8]; 2] = [b"ETSI.CAdES.detached", b"adbe.pkcs7.detached"];

/// `id-aa-signatureTimeStampToken` (RFC 3161 Appendix A).
const SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// Signature timestamps of one signature that are judged; later ones are ignored.
const MAX_TIMESTAMPS: usize = 16;

/// Validates the integrity of every signature of `pdf`, in field order, and qualifies each
/// revision appended after it, trusting no certificate.
///
/// An empty signature field and a document timestamp (`/SubFilter /ETSI.RFC3161`) are left
/// out. A signature whose bytes and CMS verify, and whose later revisions are all allowed,
/// ends `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, since no path can reach an anchor;
/// any defect ends `TOTAL_FAILED` or `INDETERMINATE` with its sub-indication, named in
/// [`SignatureValidation::defect`]. [`validate_with_anchors`] judges the chain.
///
/// An unreadable PDF, one holding more than 64 signatures, or more than 64 revisions after
/// its oldest signed one, is an [`Error`].
pub fn validate(pdf: &[u8]) -> Result<Vec<SignatureValidation>, Error> {
    // With no anchor no path exists, so the control date is never read.
    validate_with_anchors(pdf, &TrustAnchors::default(), SystemTime::UNIX_EPOCH)
}

/// [`validate_with_revocation`] with no [`RevocationSource`]: only the revocation data the
/// document carries is read.
pub fn validate_with_anchors(
    pdf: &[u8],
    anchors: &TrustAnchors,
    at: SystemTime,
) -> Result<Vec<SignatureValidation>, Error> {
    validate_with_revocation(pdf, anchors, at, None)
}

/// Validates as [`validate`] does, then, for each signature that passed every other check,
/// judges its certificate chain and its revocation up to `anchors`, the control date being
/// `at`.
///
/// The best-signature-time is the `genTime` of the earliest signature timestamp whose token
/// verifies over the signature value, whose authority's path (leaf `id-kp-timeStamping`)
/// reaches `anchors` valid at `at`, and whose revocation passes at `at`; with no such
/// timestamp, or one dated after `at`, it is `at`. It is returned in
/// [`SignatureValidation::best_signature_time`]. At most 16 timestamps are judged, each
/// against a SHA-256 imprint of the signature value only: a token whose imprint uses
/// another algorithm gives no proof of time.
///
/// The signer's path is built and judged (RFC 5280) at the best-signature-time from the
/// certificates of the CMS and of the document's `/DSS` (`/Certs`, unfiltered streams
/// only). Then each certificate of it below the anchor is judged against the CRLs of the
/// CMS and of the timestamp tokens, the `/DSS` `/CRLs` and `/OCSPs`, and the one answer of
/// `source` when given: of the data that verifies and was issued after the certificate's
/// `notBefore`, the latest decides. With a best-signature-time from a timestamp,
/// freshness is not judged, as DSS 6.5.1 does. Without one, only data issued within 24
/// hours before `at` (the CRL's `thisUpdate`, the response's `producedAt`) counts, so an
/// old "not revoked" in the `/DSS` cannot pass a key revoked since: a deliberate departure
/// from DSS, which ignores freshness there too. A revocation at or before the
/// best-signature-time gives [`Defect::Revocation`], `INDETERMINATE` / `REVOKED_NO_POE`
/// (`REVOKED_CA_NO_POE` for a CA), and a certificate with no usable data gives
/// `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`; both keep the path in
/// [`SignatureValidation::chain`]. A path whose revocation passes gives `TOTAL_PASSED`,
/// with no level.
///
/// No path gives `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND` with no defect; a path with
/// a defect gives [`Defect::Chain`] and its report.
///
/// `source` is reached only for certificates of a path an anchor certifies, and its
/// failures count as no answer. Nothing else here opens a connection or reads the clock.
pub fn validate_with_revocation(
    pdf: &[u8],
    anchors: &TrustAnchors,
    at: SystemTime,
    source: Option<&dyn RevocationSource>,
) -> Result<Vec<SignatureValidation>, Error> {
    validate_with(pdf, anchors, at, source, MAX_SIGNATURES)
}

fn validate_with(
    pdf: &[u8],
    anchors: &TrustAnchors,
    at: SystemTime,
    source: Option<&dyn RevocationSource>,
    max_signatures: usize,
) -> Result<Vec<SignatureValidation>, Error> {
    let doc = Document::parse(pdf)?;
    let mut signatures = Vec::new();
    for field in doc.signature_fields() {
        let Some(value) = field.value else {
            continue;
        };
        let dict = match doc.object(value) {
            Ok(Object::Dictionary(dict)) => Some(dict),
            _ => None,
        };
        if dict.as_ref().is_some_and(is_document_timestamp) {
            continue;
        }
        signatures.push((field.name.clone(), value, dict));
    }
    if signatures.len() > max_signatures {
        return Err(Error::TooManySignatures {
            count: signatures.len(),
            max: max_signatures,
        });
    }

    let revision_of = |end: usize| doc.revisions().iter().position(|r| r.end == end);
    let checked: Vec<_> = signatures
        .into_iter()
        .map(|(field, value, dict)| {
            let (end, result) = check(&doc, pdf, dict);
            (field, value, end.and_then(revision_of), result)
        })
        .collect();
    let first = checked.iter().filter_map(|(_, _, at, _)| *at).min();
    let later = match first {
        Some(first) => qualify(pdf, &doc, first)?,
        None => Vec::new(),
    };
    let dss = if anchors.is_empty() {
        Dss::default()
    } else {
        Dss::read(&doc, pdf)
    };

    Ok(checked
        .into_iter()
        .map(|(field, value, revision, result)| {
            let (own, mine): (Option<&Qualified>, Vec<LaterRevision>) = match (revision, first) {
                (Some(at), Some(first)) => (
                    (at - first).checked_sub(1).and_then(|i| later.get(i)),
                    later
                        .iter()
                        .skip(at - first)
                        .map(|q| q.revision.clone())
                        .collect(),
                ),
                _ => (None, Vec::new()),
            };
            // A signature its own revision refuses as a signature (SSA, DocMDP 1) would
            // otherwise read as sound, nothing being appended after it. One added beside a
            // change refused for another reason is judged on its own signed bytes.
            let added_by = own
                .filter(|q| q.refused_signatures.contains(&value))
                .map(|q| q.revision.end);
            let refused = mine
                .iter()
                .find(|r| !matches!(r.verdict, RevisionVerdict::Allowed(_)))
                .map(|r| r.end);
            match (result, added_by, refused) {
                (Err(defect), _, _) => SignatureValidation::defective(field, defect, mine),
                (Ok(_), Some(end), _) => SignatureValidation::defective(
                    field,
                    Defect::AddedByRevisionNotAllowed { end },
                    mine,
                ),
                (Ok(_), None, Some(end)) => {
                    SignatureValidation::defective(field, Defect::RevisionNotAllowed { end }, mine)
                }
                (Ok(signed), None, None) => {
                    let context = Context {
                        anchors,
                        at,
                        source,
                        dss: &dss,
                    };
                    context.judge(field, mine, &signed)
                }
            }
        })
        .collect())
}

/// A signature timestamp token, with the certificates and CRLs its `SignedData` carries.
struct Token<'a> {
    der: &'a [u8],
    certificates: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
}

/// What a sound signature's chain, timestamps and revocation are judged with.
struct Context<'a> {
    anchors: &'a TrustAnchors,
    at: SystemTime,
    source: Option<&'a dyn RevocationSource>,
    dss: &'a Dss,
}

impl Context<'_> {
    fn judge(
        &self,
        field: String,
        mine: Vec<LaterRevision>,
        signed: &Signed,
    ) -> SignatureValidation {
        if self.anchors.is_empty() {
            return SignatureValidation::sound(field, mine, None, None);
        }
        let tokens: Vec<Token<'_>> = signed
            .timestamps
            .iter()
            .map(|der| {
                let (certificates, crls) = SignedData::from_der(der)
                    .map(|data| (data.certificates, data.crls))
                    .unwrap_or_default();
                Token {
                    der,
                    certificates,
                    crls,
                }
            })
            .collect();
        // The signature's own data first, so whatever `/DSS` appends cannot push it out of
        // the capped pool.
        let revocation: Vec<RevocationData> = signed
            .crls
            .iter()
            .chain(tokens.iter().flat_map(|token| &token.crls))
            .chain(&self.dss.crls)
            .cloned()
            .map(RevocationData::Crl)
            .chain(self.dss.ocsps.iter().cloned().map(RevocationData::Ocsp))
            .collect();
        let pool = RevocationPool::from_der(&revocation);

        let best_signature_time = tokens
            .iter()
            .filter_map(|token| self.proven_time(token, signed, &pool))
            .min();
        let time = best_signature_time.unwrap_or(self.at);
        // With no proof of existence, data issued long before the control date could
        // predate a revocation the signer's key already suffered.
        let issued_from = best_signature_time
            .is_none()
            .then(|| self.at.checked_sub(FRESHNESS_TOLERANCE).unwrap_or(self.at));

        let certificates: Vec<&[u8]> = signed
            .certificates
            .iter()
            .chain(&self.dss.certificates)
            .map(Vec::as_slice)
            .collect();
        match build_path(
            &signed.signer,
            &certificates,
            self.anchors,
            time,
            Purpose::Signing,
        ) {
            Ok(path) => match judge_path(&path, &pool, self.source, time, issued_from) {
                Ok(()) => SignatureValidation::sound(field, mine, Some(path), best_signature_time),
                Err(defect) => {
                    SignatureValidation::revoked(field, defect, mine, path, best_signature_time)
                }
            },
            Err(ChainDefect::NoPath) => {
                SignatureValidation::sound(field, mine, None, best_signature_time)
            }
            Err(defect) => SignatureValidation {
                best_signature_time,
                ..SignatureValidation::defective(field, Defect::Chain(defect), mine)
            },
        }
    }

    /// The `genTime` `token` proves for `signed`, when it verifies over the signature value,
    /// its authority's path reaches an anchor at the control date and passes revocation
    /// there, and it is not after the control date.
    fn proven_time(
        &self,
        token: &Token<'_>,
        signed: &Signed,
        pool: &RevocationPool,
    ) -> Option<SystemTime> {
        let verified =
            nacre_tsp::verify_token(token.der, DigestAlgorithm::Sha256, &signed.imprint).ok()?;
        let certificates: Vec<&[u8]> = token
            .certificates
            .iter()
            .chain(&signed.certificates)
            .chain(&self.dss.certificates)
            .map(Vec::as_slice)
            .collect();
        let path = build_path(
            verified.tsa_certificate(),
            &certificates,
            self.anchors,
            self.at,
            Purpose::Timestamping,
        )
        .ok()?;
        judge_path(&path, pool, self.source, self.at, None).ok()?;
        let time = x509_cert::time::Time::from(verified.gen_time()).to_system_time();
        (time <= self.at).then_some(time)
    }
}

fn is_document_timestamp(dict: &Dictionary) -> bool {
    matches!(dict.get(b"SubFilter"), Some(Object::Name(n)) if n == b"ETSI.RFC3161")
}

/// Runs the checks on one signature: where its signed bytes end, once known, and the first
/// defect. The revisions after it are judged by the caller, last.
fn check(
    doc: &Document<'_>,
    pdf: &[u8],
    dict: Option<Dictionary>,
) -> (Option<usize>, Result<Signed, Defect>) {
    match signed_bytes(doc, pdf, dict) {
        Ok((end, contents, [b, c])) => (Some(end), verify(pdf, &contents, [b, c, end])),
        Err(defect) => (None, Err(defect)),
    }
}

// The order of the checks is part of the contract: each case of the attack corpus must
// reach the rule that names it.
fn signed_bytes(
    doc: &Document<'_>,
    pdf: &[u8],
    dict: Option<Dictionary>,
) -> Result<(usize, Vec<u8>, [usize; 2]), Defect> {
    let dict = dict.ok_or(Defect::NotASignatureDictionary)?;

    match dict.get(b"SubFilter") {
        Some(Object::Name(n)) if SUB_FILTERS.contains(&n.as_slice()) => {}
        _ => return Err(Defect::UnsupportedSubFilter),
    }

    let contents = match follow_once(doc, dict.get(b"Contents")) {
        Some(Object::String(bytes)) if !bytes.is_empty() => bytes,
        _ => return Err(Defect::ContentsMissing),
    };

    let [a, b, c, d] = byte_range(doc, &dict).ok_or(Defect::ByteRangeMalformed)?;
    if a != 0 {
        return Err(Defect::ByteRangeNotFromStart);
    }
    if b > c {
        return Err(Defect::ByteRangeOverlap);
    }
    let end = c
        .checked_add(d)
        .filter(|end| *end <= pdf.len())
        .ok_or(Defect::ByteRangeOutsideFile)?;
    if !gap_is_contents(pdf.get(b..c).unwrap_or_default(), &contents) {
        return Err(Defect::GapNotContents);
    }
    if !doc.revisions().iter().any(|r| r.end == end) {
        return Err(Defect::ByteRangeNotWholeFile);
    }
    Ok((end, contents, [b, c]))
}

/// What a verified CMS gives the chain and revocation, as DER: the signer's certificate,
/// every certificate and CRL it carries, the SHA-256 of the signature value and the first
/// signature timestamp tokens.
struct Signed {
    signer: Vec<u8>,
    certificates: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    imprint: Vec<u8>,
    timestamps: Vec<Vec<u8>>,
}

fn verify(pdf: &[u8], contents: &[u8], [b, c, end]: [usize; 3]) -> Result<Signed, Defect> {
    let der = der_prefix(contents).ok_or(Defect::ContentsNotDer)?;

    let mut hasher = Sha256::new();
    hasher.update(pdf.get(..b).unwrap_or_default());
    hasher.update(pdf.get(c..end).unwrap_or_default());
    let digest = hasher.finalize();
    let signed = SignedData::from_der(der).map_err(Defect::Cms)?;
    let verified = signed
        .verify_detached_digest(&digest)
        .map_err(Defect::Cms)?;
    let info = verified.signer_info();
    let timestamps = info
        .unsigned_attrs
        .iter()
        .filter(|attribute| attribute.oid == SIGNATURE_TIME_STAMP_TOKEN)
        .flat_map(|attribute| &attribute.values)
        .take(MAX_TIMESTAMPS)
        .filter_map(|value| value.to_der().ok())
        .collect();
    let imprint = Sha256::digest(&info.signature).to_vec();
    let signer = verified.certificate().to_vec();
    Ok(Signed {
        signer,
        certificates: signed.certificates.clone(),
        crls: signed.crls.clone(),
        imprint,
        timestamps,
    })
}

/// The raw data of the unfiltered streams the document's `/DSS` lists.
#[derive(Debug, Default)]
struct Dss {
    certificates: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    ocsps: Vec<Vec<u8>>,
}

impl Dss {
    fn read(doc: &Document<'_>, pdf: &[u8]) -> Self {
        let Some(Object::Dictionary(dss)) = follow_once(doc, doc.catalog().get(b"DSS")) else {
            return Self::default();
        };
        Self {
            certificates: dss_streams(doc, pdf, &dss, b"Certs"),
            crls: dss_streams(doc, pdf, &dss, b"CRLs"),
            ocsps: dss_streams(doc, pdf, &dss, b"OCSPs"),
        }
    }
}

/// The raw data of each unfiltered stream the `/DSS` array `key` lists. Anything
/// unreadable is left out: the judgement then misses it rather than guesses.
fn dss_streams(doc: &Document<'_>, pdf: &[u8], dss: &Dictionary, key: &[u8]) -> Vec<Vec<u8>> {
    let Some(Object::Array(items)) = follow_once(doc, dss.get(key)) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match follow_once(doc, Some(item)) {
            Some(Object::Stream(stream)) if stream.dict.get(b"Filter").is_none() => {
                pdf.get(stream.data).map(<[u8]>::to_vec)
            }
            _ => None,
        })
        .collect()
}

/// The value of an entry, one reference followed.
fn follow_once(doc: &Document<'_>, value: Option<&Object>) -> Option<Object> {
    match value? {
        Object::Reference(id) => doc.object(*id).ok(),
        direct => Some(direct.clone()),
    }
}

pub(crate) fn byte_range(doc: &Document<'_>, dict: &Dictionary) -> Option<[usize; 4]> {
    let Object::Array(items) = follow_once(doc, dict.get(b"ByteRange"))? else {
        return None;
    };
    let [a, b, c, d] = items.as_slice() else {
        return None;
    };
    let number = |item: &Object| match item {
        Object::Integer(n) => usize::try_from(*n).ok(),
        _ => None,
    };
    Some([number(a)?, number(b)?, number(c)?, number(d)?])
}

/// Whether `gap` is exactly `<`, an even run of hex digits and `>`, decoding to `contents`.
fn gap_is_contents(gap: &[u8], contents: &[u8]) -> bool {
    let Some(hex) = gap
        .strip_prefix(b"<")
        .and_then(|rest| rest.strip_suffix(b">"))
    else {
        return false;
    };
    let mut pairs = hex.chunks_exact(2);
    if !pairs.remainder().is_empty() || hex.len() / 2 != contents.len() {
        return false;
    }
    pairs.by_ref().zip(contents).all(|(pair, byte)| match pair {
        [high, low] => {
            let digit = |c: u8| char::from(c).to_digit(16);
            matches!((digit(*high), digit(*low)), (Some(h), Some(l)) if h * 16 + l == u32::from(*byte))
        }
        _ => false,
    })
}

/// The leading DER `SEQUENCE` of `contents`, when every byte after it is zero.
fn der_prefix(contents: &[u8]) -> Option<&[u8]> {
    let mut reader = SliceReader::new(contents).ok()?;
    let header = Header::decode(&mut reader).ok()?;
    if header.tag() != Tag::Sequence {
        return None;
    }
    let len = usize::try_from((reader.position() + header.length()).ok()?).ok()?;
    let (der, padding) = contents.split_at_checked(len)?;
    padding.iter().all(|b| *b == 0).then_some(der)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nacre_core::TestSigner;
    use nacre_pades::{DateTime, sign};

    #[test]
    fn signatures_over_the_cap_are_refused() {
        let signer = TestSigner::from_secret(&[0x11; 32]).unwrap();
        let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();
        let once = sign(
            include_bytes!("../tests/corpus/unsigned.pdf"),
            &signer,
            time,
        )
        .unwrap();
        let twice = sign(&once, &signer, time).unwrap();

        let error = validate_with(
            &twice,
            &TrustAnchors::default(),
            SystemTime::UNIX_EPOCH,
            None,
            1,
        )
        .unwrap_err();

        assert!(
            matches!(error, Error::TooManySignatures { count: 2, max: 1 }),
            "{error}"
        );
    }

    #[test]
    fn too_many_revisions_are_refused() {
        let signer = TestSigner::from_secret(&[0x11; 32]).unwrap();
        let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();
        let mut pdf = sign(
            include_bytes!("../tests/corpus/unsigned.pdf"),
            &signer,
            time,
        )
        .unwrap();
        for _ in 0..64 {
            pdf = Document::parse(&pdf).unwrap().update().finish().unwrap();
        }
        assert!(validate(&pdf).is_ok());

        pdf = Document::parse(&pdf).unwrap().update().finish().unwrap();
        let error = validate(&pdf).unwrap_err();

        assert!(
            matches!(error, Error::TooManyRevisions { count: 65, max: 64 }),
            "{error}"
        );
    }
}
