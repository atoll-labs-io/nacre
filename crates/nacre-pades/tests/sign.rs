#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::{Cell, RefCell};

use der::{Decode, Header, Reader, SliceReader};
use nacre_cms::{SignedData, oid};
use nacre_core::{
    DigestAlgorithm, ErrorKind, SignatureAlgorithm, Signer, TestSigner, TimestampAuthority,
};
use nacre_pades::{DateTime, Error, Level, TIMESTAMP_TOKEN_MAX, sign, sign_at_level};
use nacre_pdf::{Dictionary, Document, Object};
use sha2::{Digest, Sha256};

const UNSIGNED: &[u8] = include_bytes!("corpus/unsigned.pdf");

fn signer() -> TestSigner {
    TestSigner::from_secret(&[0x11; 32]).unwrap()
}

fn time() -> DateTime {
    DateTime::new(2026, 10, 22, 8, 0, 0).unwrap()
}

struct Counting {
    inner: TestSigner,
    calls: Cell<usize>,
}

impl Signer for Counting {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        self.inner.certificate_chain()
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, nacre_core::Error> {
        self.calls.set(self.calls.get() + 1);
        self.inner.sign_digest(digest)
    }
}

fn counting() -> Counting {
    Counting {
        inner: signer(),
        calls: Cell::new(0),
    }
}

struct Read {
    name: String,
    sig: Dictionary,
    byte_range: [usize; 4],
    contents: Vec<u8>,
    cms: Vec<u8>,
}

/// Every signature of `pdf`, in field order, read back through its field's `/V`.
fn signatures(pdf: &[u8]) -> Vec<Read> {
    let doc = Document::parse(pdf).unwrap();
    doc.signature_fields()
        .iter()
        .map(|field| {
            let Object::Dictionary(sig) = doc.object(field.value.unwrap()).unwrap() else {
                panic!("/V is not a dictionary");
            };
            let Some(Object::Array(range)) = sig.get(b"ByteRange") else {
                panic!("no /ByteRange");
            };
            let range: Vec<usize> = range
                .iter()
                .map(|o| match o {
                    Object::Integer(n) => usize::try_from(*n).unwrap(),
                    _ => panic!("non-integer in /ByteRange"),
                })
                .collect();
            let Some(Object::String(contents)) = sig.get(b"Contents") else {
                panic!("no /Contents");
            };
            let mut reader = SliceReader::new(contents).unwrap();
            let header = Header::decode(&mut reader).unwrap();
            let len = usize::try_from((reader.position() + header.length()).unwrap()).unwrap();
            Read {
                name: field.name.clone(),
                byte_range: range.try_into().unwrap(),
                cms: contents[..len].to_vec(),
                contents: contents.clone(),
                sig: sig.clone(),
            }
        })
        .collect()
}

fn range_digest(pdf: &[u8], [a, b, c, d]: [usize; 4]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&pdf[a..a + b]);
    hasher.update(&pdf[c..c + d]);
    hasher.finalize().to_vec()
}

fn has_signed_attribute(signed: &SignedData, wanted: der::oid::ObjectIdentifier) -> bool {
    signed.signer_infos[0]
        .signed_attrs
        .as_ref()
        .unwrap()
        .attributes()
        .unwrap()
        .iter()
        .any(|a| a.oid == wanted)
}

#[test]
fn signature_is_cades_detached_with_time_in_m() {
    let signed = sign(UNSIGNED, &signer(), time()).unwrap();

    let reads = signatures(&signed);
    assert_eq!(reads.len(), 1);
    let read = &reads[0];
    assert_eq!(
        read.sig.get(b"Filter"),
        Some(&Object::Name(b"Adobe.PPKLite".to_vec()))
    );
    assert_eq!(
        read.sig.get(b"SubFilter"),
        Some(&Object::Name(b"ETSI.CAdES.detached".to_vec()))
    );
    assert_eq!(
        read.sig.get(b"M"),
        Some(&Object::String(b"D:20261022080000Z".to_vec()))
    );
    let cms = SignedData::from_der(&read.cms).unwrap();
    assert!(has_signed_attribute(&cms, oid::SIGNING_CERTIFICATE_V2));
    assert!(!has_signed_attribute(&cms, oid::SIGNING_TIME));
    assert!(cms.crls.is_empty());
    cms.verify_detached_digest(&range_digest(&signed, read.byte_range))
        .unwrap();
}

#[test]
fn second_signature_takes_a_new_revision() {
    let once = sign(UNSIGNED, &signer(), time()).unwrap();
    let twice = sign(&once, &signer(), time()).unwrap();

    assert!(once.starts_with(UNSIGNED));
    assert!(twice.starts_with(&once));
    let original_revisions = Document::parse(UNSIGNED).unwrap().revisions().len();
    assert_eq!(
        Document::parse(&twice).unwrap().revisions().len(),
        original_revisions + 2
    );
    let reads = signatures(&twice);
    assert_eq!(reads.len(), 2);
    assert_ne!(reads[0].name, reads[1].name);
    let [_, _, c, d] = reads[0].byte_range;
    assert_eq!(c + d, once.len());
    for read in &reads {
        SignedData::from_der(&read.cms)
            .unwrap()
            .verify_detached_digest(&range_digest(&twice, read.byte_range))
            .unwrap();
    }
}

#[test]
fn reserve_leaves_only_the_signature_slack() {
    let signed = sign(UNSIGNED, &signer(), time()).unwrap();

    let read = &signatures(&signed)[0];
    let cms = SignedData::from_der(&read.cms).unwrap();
    assert_eq!(
        read.contents.len() - read.cms.len(),
        72 - cms.signer_infos[0].signature.len()
    );
}

#[test]
fn the_signer_signs_once() {
    let signer = counting();

    sign(UNSIGNED, &signer, time()).unwrap();

    assert_eq!(signer.calls.get(), 1);
}

#[test]
fn refusal_returns_the_pdf_error() {
    let signer = counting();

    let error = sign(b"not a pdf", &signer, time()).unwrap_err();

    assert!(matches!(error, Error::Pdf(_)), "{error}");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(signer.calls.get(), 0);
}

struct FakeTsa {
    answer: Result<Vec<u8>, &'static str>,
    seen: RefCell<Option<(DigestAlgorithm, Vec<u8>)>>,
}

impl FakeTsa {
    fn answering(token: Vec<u8>) -> Self {
        Self {
            answer: Ok(token),
            seen: RefCell::new(None),
        }
    }
}

impl TimestampAuthority for FakeTsa {
    fn timestamp(
        &self,
        algorithm: DigestAlgorithm,
        imprint: &[u8],
    ) -> Result<Vec<u8>, nacre_core::Error> {
        *self.seen.borrow_mut() = Some((algorithm, imprint.to_vec()));
        self.answer
            .clone()
            .map_err(|message| nacre_core::Error::Timestamp(message.into()))
    }
}

/// An OCTET STRING whose whole DER encoding is `n` bytes.
fn der_of_len(n: usize) -> Vec<u8> {
    let header = if n - 2 < 128 {
        2
    } else if n - 3 < 256 {
        3
    } else {
        4
    };
    let content = n - header;
    let mut out = vec![0x04];
    if header == 2 {
        out.push(content as u8);
    } else if header == 3 {
        out.extend([0x81, content as u8]);
    } else {
        out.extend([0x82, (content >> 8) as u8, content as u8]);
    }
    out.extend(vec![0; content]);
    assert_eq!(out.len(), n);
    out
}

const SIGNATURE_TIME_STAMP_TOKEN: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

#[test]
fn level_t_stores_the_token_over_the_signature_value() {
    let signer = counting();
    let token = der_of_len(100);
    let tsa = FakeTsa::answering(token.clone());

    let signed = sign_at_level(UNSIGNED, &signer, time(), Level::T { tsa: &tsa }).unwrap();

    let read = &signatures(&signed)[0];
    let cms = SignedData::from_der(&read.cms).unwrap();
    let info = &cms.signer_infos[0];
    assert_eq!(info.unsigned_attrs.len(), 1);
    let attribute = &info.unsigned_attrs[0];
    assert_eq!(attribute.oid, SIGNATURE_TIME_STAMP_TOKEN);
    assert_eq!(attribute.values.len(), 1);
    assert_eq!(der::Encode::to_der(&attribute.values[0]).unwrap(), token);
    assert_eq!(
        *tsa.seen.borrow(),
        Some((
            DigestAlgorithm::Sha256,
            Sha256::digest(&info.signature).to_vec()
        ))
    );
    cms.verify_detached_digest(&range_digest(&signed, read.byte_range))
        .unwrap();
    assert_eq!(
        read.sig.get(b"SubFilter"),
        Some(&Object::Name(b"ETSI.CAdES.detached".to_vec()))
    );
    assert_eq!(signer.calls.get(), 1);
}

#[test]
fn tsa_failure_designates_the_tsa() {
    let tsa = FakeTsa {
        answer: Err("down"),
        seen: RefCell::new(None),
    };

    let error = sign_at_level(UNSIGNED, &signer(), time(), Level::T { tsa: &tsa }).unwrap_err();

    assert!(matches!(error, Error::Timestamp(_)), "{error}");
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert!(error.to_string().contains("timestamp authority"));
}

#[test]
fn largest_token_fits_with_only_the_signature_slack() {
    let tsa = FakeTsa::answering(der_of_len(TIMESTAMP_TOKEN_MAX));

    let signed = sign_at_level(UNSIGNED, &signer(), time(), Level::T { tsa: &tsa }).unwrap();

    let read = &signatures(&signed)[0];
    let cms = SignedData::from_der(&read.cms).unwrap();
    assert_eq!(
        read.contents.len() - read.cms.len(),
        72 - cms.signer_infos[0].signature.len()
    );
}

#[test]
fn oversized_token_is_refused() {
    let tsa = FakeTsa::answering(der_of_len(TIMESTAMP_TOKEN_MAX + 1));

    let error = sign_at_level(UNSIGNED, &signer(), time(), Level::T { tsa: &tsa }).unwrap_err();

    assert!(
        matches!(
            error,
            Error::TimestampTooLarge { len, max }
                if len == TIMESTAMP_TOKEN_MAX + 1 && max == TIMESTAMP_TOKEN_MAX
        ),
        "{error}"
    );
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn malformed_token_is_refused() {
    let mut token = der_of_len(100);
    token.push(0);
    let tsa = FakeTsa::answering(token);

    let error = sign_at_level(UNSIGNED, &signer(), time(), Level::T { tsa: &tsa }).unwrap_err();

    assert!(matches!(error, Error::TimestampToken(_)), "{error}");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
