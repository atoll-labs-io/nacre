use der::{Decode, Header, Reader, SliceReader, Tag};
use nacre_cms::SignedData;
use nacre_pdf::{Dictionary, Document, Object};
use sha2::{Digest, Sha256};

use crate::{Defect, Error, SignatureValidation};

/// Bounds the hashing one call may do to 64 times the largest accepted input (50 MB).
const MAX_SIGNATURES: usize = 64;

const SUB_FILTERS: [&[u8]; 2] = [b"ETSI.CAdES.detached", b"adbe.pkcs7.detached"];

/// Validates the integrity of every signature of `pdf`, in field order.
///
/// An empty signature field and a document timestamp (`/SubFilter /ETSI.RFC3161`) are left
/// out. A signature whose bytes and CMS verify ends `INDETERMINATE` /
/// `NO_CERTIFICATE_CHAIN_FOUND`, since its chain is not judged yet; any defect ends
/// `TOTAL_FAILED` or `INDETERMINATE` with its sub-indication, named in
/// [`SignatureValidation::defect`].
///
/// An unreadable PDF, or one holding more than 64 signatures, is an [`Error`].
pub fn validate(pdf: &[u8]) -> Result<Vec<SignatureValidation>, Error> {
    validate_with(pdf, MAX_SIGNATURES)
}

fn validate_with(pdf: &[u8], max_signatures: usize) -> Result<Vec<SignatureValidation>, Error> {
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
        signatures.push((field.name.clone(), dict));
    }
    if signatures.len() > max_signatures {
        return Err(Error::TooManySignatures {
            count: signatures.len(),
            max: max_signatures,
        });
    }
    Ok(signatures
        .into_iter()
        .map(|(field, dict)| match check(&doc, pdf, dict) {
            Ok(()) => SignatureValidation::sound(field),
            Err(defect) => SignatureValidation::defective(field, defect),
        })
        .collect())
}

fn is_document_timestamp(dict: &Dictionary) -> bool {
    matches!(dict.get(b"SubFilter"), Some(Object::Name(n)) if n == b"ETSI.RFC3161")
}

// The order of the checks is part of the contract: each case of the attack corpus must
// reach the rule that names it.
fn check(doc: &Document<'_>, pdf: &[u8], dict: Option<Dictionary>) -> Result<(), Defect> {
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
    if !covers_last_revision(doc, end) {
        return Err(Defect::LaterRevision);
    }

    let der = der_prefix(&contents).ok_or(Defect::ContentsNotDer)?;

    let mut hasher = Sha256::new();
    hasher.update(pdf.get(..b).unwrap_or_default());
    hasher.update(pdf.get(c..end).unwrap_or_default());
    let digest = hasher.finalize();
    SignedData::from_der(der)
        .and_then(|signed| signed.verify_detached_digest(&digest).map(|_| ()))
        .map_err(Defect::Cms)
}

/// Whether the signed bytes end with the file. This is the one place where a later
/// revision is judged; qualifying what such a revision changes will replace it.
fn covers_last_revision(doc: &Document<'_>, end: usize) -> bool {
    doc.revisions().last().is_some_and(|r| r.end == end)
}

/// The value of an entry, one reference followed.
fn follow_once(doc: &Document<'_>, value: Option<&Object>) -> Option<Object> {
    match value? {
        Object::Reference(id) => doc.object(*id).ok(),
        direct => Some(direct.clone()),
    }
}

fn byte_range(doc: &Document<'_>, dict: &Dictionary) -> Option<[usize; 4]> {
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

        let error = validate_with(&twice, 1).unwrap_err();

        assert!(
            matches!(error, Error::TooManySignatures { count: 2, max: 1 }),
            "{error}"
        );
    }
}
