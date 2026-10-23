use std::time::SystemTime;

use der::{Decode, Header, Reader, SliceReader, Tag};
use nacre_cms::SignedData;
use nacre_pdf::{Dictionary, Document, Object};
use sha2::{Digest, Sha256};

use crate::revisions::{Qualified, qualify};
use crate::{
    ChainDefect, Defect, Error, LaterRevision, RevisionVerdict, SignatureValidation, TrustAnchors,
    build_chain,
};

/// Bounds the hashing one call may do to 64 times the largest accepted input (50 MB).
const MAX_SIGNATURES: usize = 64;

const SUB_FILTERS: [&[u8]; 2] = [b"ETSI.CAdES.detached", b"adbe.pkcs7.detached"];

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

/// Validates as [`validate`] does, then builds and judges, at the control date `at`, the
/// chain of each signature that passed every other check, from the certificates of its CMS
/// and of the document's `/DSS` (`/Certs`, unfiltered streams only) up to `anchors`.
///
/// No path gives `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND` with no defect; a path with
/// a defect gives [`Defect::Chain`] and its report; a valid path is kept in
/// [`SignatureValidation::chain`] and gives `INDETERMINATE` / `TRY_LATER`, its revocation
/// not being judged yet.
pub fn validate_with_anchors(
    pdf: &[u8],
    anchors: &TrustAnchors,
    at: SystemTime,
) -> Result<Vec<SignatureValidation>, Error> {
    validate_with(pdf, anchors, at, MAX_SIGNATURES)
}

fn validate_with(
    pdf: &[u8],
    anchors: &TrustAnchors,
    at: SystemTime,
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
        Vec::new()
    } else {
        dss_certificates(&doc, pdf)
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
                    let pool: Vec<&[u8]> = signed
                        .certificates
                        .iter()
                        .chain(&dss)
                        .map(Vec::as_slice)
                        .collect();
                    match build_chain(&signed.signer, &pool, anchors, at) {
                        Ok(path) => SignatureValidation::sound(field, mine, Some(path)),
                        Err(ChainDefect::NoPath) => SignatureValidation::sound(field, mine, None),
                        Err(defect) => {
                            SignatureValidation::defective(field, Defect::Chain(defect), mine)
                        }
                    }
                }
            }
        })
        .collect())
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

/// What a verified CMS gives the chain: the signer's certificate and every certificate it
/// carries, as DER.
struct Signed {
    signer: Vec<u8>,
    certificates: Vec<Vec<u8>>,
}

fn verify(pdf: &[u8], contents: &[u8], [b, c, end]: [usize; 3]) -> Result<Signed, Defect> {
    let der = der_prefix(contents).ok_or(Defect::ContentsNotDer)?;

    let mut hasher = Sha256::new();
    hasher.update(pdf.get(..b).unwrap_or_default());
    hasher.update(pdf.get(c..end).unwrap_or_default());
    let digest = hasher.finalize();
    let signed = SignedData::from_der(der).map_err(Defect::Cms)?;
    let signer = signed
        .verify_detached_digest(&digest)
        .map_err(Defect::Cms)?
        .certificate()
        .to_vec();
    Ok(Signed {
        signer,
        certificates: signed.certificates,
    })
}

/// The raw data of each unfiltered stream the `/DSS /Certs` of `doc` lists. Anything
/// unreadable is left out: the chain then misses it rather than guesses.
fn dss_certificates(doc: &Document<'_>, pdf: &[u8]) -> Vec<Vec<u8>> {
    let Some(Object::Dictionary(dss)) = follow_once(doc, doc.catalog().get(b"DSS")) else {
        return Vec::new();
    };
    let Some(Object::Array(certs)) = follow_once(doc, dss.get(b"Certs")) else {
        return Vec::new();
    };
    certs
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

        let error =
            validate_with(&twice, &TrustAnchors::default(), SystemTime::UNIX_EPOCH, 1).unwrap_err();

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
