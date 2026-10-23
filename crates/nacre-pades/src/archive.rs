use der::{Decode, Encode, Header, Reader, SliceReader};
use nacre_cms::{SignedData, SignerIdentifier};
use nacre_core::{DigestAlgorithm, RevocationSource, TimestampAuthority};
use nacre_pdf::{Dictionary, Document, Object, SignatureSpec};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use crate::sign::field_name;
use crate::timestamp::{TIMESTAMP_TOKEN_MAX, check_token};
use crate::{Error, SignedPdf, dss, ltv};

/// Appends to `pdf` one revision holding a document timestamp: a `/Type /DocTimeStamp`
/// dictionary with `/SubFilter /ETSI.RFC3161` whose `/Contents` holds the token `tsa`
/// returns for the SHA-256 of its `/ByteRange`. `tsa` is asked once.
pub(crate) fn document_timestamp(
    pdf: &[u8],
    tsa: &dyn TimestampAuthority,
) -> Result<Vec<u8>, Error> {
    let doc = Document::parse(pdf)?;
    let mut entries = Dictionary::new();
    entries.insert(b"Type", Object::Name(b"DocTimeStamp".to_vec()));
    let prepared = doc.update().sign(SignatureSpec {
        field: field_name(&doc),
        sub_filter: b"ETSI.RFC3161".to_vec(),
        contents_len: TIMESTAMP_TOKEN_MAX,
        entries,
    })?;

    let mut hasher = Sha256::new();
    for part in prepared.signed_parts() {
        hasher.update(part);
    }
    let token = tsa
        .timestamp(DigestAlgorithm::Sha256, &hasher.finalize())
        .map_err(Error::Timestamp)?;
    check_token(&token)?;
    Ok(prepared.embed(&token)?)
}

/// Renews the archive time-stamp of `pdf`, a PAdES-BASELINE-LTA file.
///
/// The newest document timestamp is the one whose `/ByteRange` ends latest. One revision
/// adds to `/DSS` the certificates its token carries, those they lead to by issuer name
/// (with `issuers` as the only other source) and the revocation data `revocation` gives for
/// each that is not self-signed, under a `/VRI` key for that timestamp. A second revision
/// then holds a new document timestamp from `tsa`, asked once, after `/DSS` is written.
/// Every earlier revision stays a byte prefix of the result.
///
/// A token that does not carry its signer's certificate is renewed only when `issuers` or
/// the existing `/DSS` holds it; the walk by issuer name then draws on both. Otherwise
/// [`Error::TimestampSignerMissing`] is returned before `tsa` or `revocation` is asked
/// anything, since the renewal would leave that authority's validation data out.
///
/// The caller decides when to call it: nothing here reads a clock or judges whether a
/// renewal is due. A PDF with no document timestamp returns [`Error::NotArchived`] before
/// `tsa` or `revocation` is asked anything. When `tsa` fails after `/DSS` is written,
/// [`Error::Archive`] carries the file with that revision, so the fetched data is kept.
pub fn extend(
    pdf: &[u8],
    tsa: &dyn TimestampAuthority,
    revocation: &dyn RevocationSource,
    issuers: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let doc = Document::parse(pdf)?;
    let contents = newest_document_timestamp(&doc)?.ok_or(Error::NotArchived)?;
    let token = SignedData::from_der(der_prefix(&contents)?)?;
    let mut certificates = token.certificates;
    let sid = &token
        .signer_infos
        .first()
        .ok_or(Error::TimestampSignerMissing)?
        .sid;
    let material = if find_signer(&certificates, sid)?.is_some() {
        ltv::material(&certificates, &[], issuers, revocation)?
    } else {
        let mut pool = issuers.to_vec();
        pool.extend(dss_certificates(&doc, pdf)?);
        let signer = find_signer(&pool, sid)?.ok_or(Error::TimestampSignerMissing)?;
        certificates.push(signer.to_vec());
        ltv::material(&certificates, &[], &pool, revocation)?
    };
    let with_dss = dss::append(pdf, &dss::vri_key(&contents, contents.len()), &material)?;
    document_timestamp(&with_dss, tsa).map_err(|error| Error::Archive {
        signed: SignedPdf(with_dss),
        source: Box::new(error),
    })
}

/// The decoded `/Contents` of the document timestamp whose `/ByteRange` ends latest. Only
/// that one's `/Contents` is judged; every `/ByteRange` must be readable to tell which it is.
fn newest_document_timestamp(doc: &Document<'_>) -> Result<Option<Vec<u8>>, Error> {
    let mut newest: Option<(usize, Dictionary)> = None;
    for field in doc.signature_fields() {
        let Some(id) = field.value else {
            continue;
        };
        let Object::Dictionary(sig) = doc.object(id)? else {
            continue;
        };
        if sig.get(b"SubFilter") != Some(&Object::Name(b"ETSI.RFC3161".to_vec())) {
            continue;
        }
        let end = range_end(&sig).ok_or(Error::DocumentTimestamp(
            "one has an unreadable /ByteRange, so the newest cannot be told",
        ))?;
        if newest.as_ref().is_none_or(|(latest, _)| end > *latest) {
            newest = Some((end, sig));
        }
    }
    let Some((_, sig)) = newest else {
        return Ok(None);
    };
    match sig.get(b"Contents") {
        Some(Object::String(contents)) => Ok(Some(contents.clone())),
        _ => Err(Error::DocumentTimestamp(
            "the newest has no /Contents string",
        )),
    }
}

/// The first of `certificates` that `sid` names; those that are not X.509 are skipped.
fn find_signer<'c>(
    certificates: &'c [Vec<u8>],
    sid: &SignerIdentifier,
) -> Result<Option<&'c [u8]>, Error> {
    for der in certificates {
        let Ok(certificate) = Certificate::from_der(der) else {
            continue;
        };
        let tbs = certificate.tbs_certificate();
        let named = match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer,
                serial_number,
            } => {
                tbs.serial_number() == serial_number
                    && tbs.issuer().to_der().map_err(Error::Certificate)? == *issuer
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => tbs
                .get_extension::<SubjectKeyIdentifier>()
                .map_err(Error::Certificate)?
                .is_some_and(|(_, ext)| ext.0.as_bytes() == ski.as_slice()),
        };
        if named {
            return Ok(Some(der));
        }
    }
    Ok(None)
}

/// The raw data of each stream `/DSS /Certs` of `doc` lists that parses as a certificate.
/// A filtered stream is not decoded: it is left out, so a signer it holds stays missing
/// rather than guessed, and the walk by issuer name never meets bytes it cannot read.
fn dss_certificates(doc: &Document<'_>, pdf: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let resolve = |value: &Object| -> Result<Object, Error> {
        Ok(match value {
            Object::Reference(id) => doc.object(*id)?,
            other => other.clone(),
        })
    };
    let Some(dss) = doc.catalog().get(b"DSS") else {
        return Ok(Vec::new());
    };
    let Object::Dictionary(dss) = resolve(dss)? else {
        return Ok(Vec::new());
    };
    let Some(certs) = dss.get(b"Certs") else {
        return Ok(Vec::new());
    };
    let Object::Array(certs) = resolve(certs)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for item in &certs {
        if let Object::Stream(stream) = resolve(item)?
            && let Some(data) = pdf.get(stream.data)
            && Certificate::from_der(data).is_ok()
        {
            out.push(data.to_vec());
        }
    }
    Ok(out)
}

/// `c + d` of a `/ByteRange [a b c d]` of four non-negative integers.
fn range_end(sig: &Dictionary) -> Option<usize> {
    let Some(Object::Array(range)) = sig.get(b"ByteRange") else {
        return None;
    };
    let [_, _, Object::Integer(c), Object::Integer(d)] = range.as_slice() else {
        return None;
    };
    usize::try_from(*c)
        .ok()?
        .checked_add(usize::try_from(*d).ok()?)
}

/// The single DER SEQUENCE at the start of `contents`, refused unless every byte after it
/// is zero padding.
fn der_prefix(contents: &[u8]) -> Result<&[u8], Error> {
    const MALFORMED: Error = Error::DocumentTimestamp("/Contents is not one DER SEQUENCE");
    let mut reader = SliceReader::new(contents).map_err(|_| MALFORMED)?;
    let header = Header::decode(&mut reader).map_err(|_| MALFORMED)?;
    if header.tag() != der::Tag::Sequence {
        return Err(MALFORMED);
    }
    let len = (reader.position() + header.length()).map_err(|_| MALFORMED)?;
    let len = usize::try_from(len).map_err(|_| MALFORMED)?;
    let (token, padding) = contents.split_at_checked(len).ok_or(MALFORMED)?;
    if padding.iter().any(|&byte| byte != 0) {
        return Err(MALFORMED);
    }
    Ok(token)
}
