#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::{Cell, RefCell};

use der::{Decode, Header, Reader, SliceReader};
use nacre_cms::{Profile, SignedData, oid};
use nacre_core::{
    DigestAlgorithm, ErrorKind, RevocationData, RevocationSource, SignatureAlgorithm, Signer,
    TestSigner, TimestampAuthority,
};
use nacre_pades::{DateTime, Error, Level, TIMESTAMP_TOKEN_MAX, extend, sign, sign_at_level};
use nacre_pdf::{Dictionary, Document, Object, ObjectId};
use sha1::Sha1;
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

const EC_CA: &[u8] = include_bytes!("corpus/pki/ec-ca.der");
const LEAF: &[u8] = include_bytes!("corpus/pki/leaf.der");
const REVOKED: &[u8] = include_bytes!("corpus/pki/revoked.der");
const EC_CA_CRL: &[u8] = include_bytes!("corpus/pki/ec-ca.crl");
const GOOD_OCSP: &[u8] = include_bytes!("corpus/pki/good.der");

/// Signs with the test key and presents `chain`; nothing here checks one against the other.
struct Chained {
    inner: TestSigner,
    chain: Vec<Vec<u8>>,
}

impl Signer for Chained {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, nacre_core::Error> {
        self.inner.sign_digest(digest)
    }
}

fn chained(chain: &[&[u8]]) -> Chained {
    Chained {
        inner: signer(),
        chain: chain.iter().map(|c| c.to_vec()).collect(),
    }
}

/// A real `SignedData` carrying `chain`, standing in for a token pades never verifies.
fn cms_token(chain: &[&[u8]]) -> FakeTsa {
    FakeTsa::answering(
        nacre_cms::sign_detached(&[0; 32], &chained(chain), &Profile::CMS, None).unwrap(),
    )
}

struct Recording {
    asked: RefCell<Vec<Vec<u8>>>,
    failing: Option<&'static [u8]>,
}

fn recording(failing: Option<&'static [u8]>) -> Recording {
    Recording {
        asked: RefCell::new(Vec::new()),
        failing,
    }
}

impl RevocationSource for Recording {
    fn revocation(
        &self,
        certificate: &[u8],
        _issuer: &[u8],
    ) -> Result<RevocationData, nacre_core::Error> {
        self.asked.borrow_mut().push(certificate.to_vec());
        if self.failing == Some(certificate) {
            return Err(nacre_core::Error::Revocation("down".into()));
        }
        Ok(if certificate == LEAF {
            RevocationData::Ocsp(GOOD_OCSP.to_vec())
        } else {
            RevocationData::Crl(EC_CA_CRL.to_vec())
        })
    }
}

struct Dss {
    certs: Vec<(ObjectId, Vec<u8>)>,
    crls: Vec<(ObjectId, Vec<u8>)>,
    ocsps: Vec<(ObjectId, Vec<u8>)>,
    /// Each `/VRI` key and its entry's reference, then its `/Cert`, `/CRL` and `/OCSP`.
    vri: Vec<(Vec<u8>, ObjectId, [Vec<ObjectId>; 3])>,
}

fn references(value: Option<&Object>) -> Vec<ObjectId> {
    match value {
        None => Vec::new(),
        Some(Object::Array(items)) => items
            .iter()
            .map(|item| match item {
                Object::Reference(id) => *id,
                _ => panic!("not a reference"),
            })
            .collect(),
        Some(_) => panic!("not an array"),
    }
}

fn dictionary_at(doc: &Document<'_>, id: ObjectId) -> Dictionary {
    let Object::Dictionary(dict) = doc.object(id).unwrap() else {
        panic!("{id} is not a dictionary");
    };
    dict
}

/// `/DSS` read back, each stream's raw bytes sliced from its data range.
fn dss(pdf: &[u8]) -> Option<Dss> {
    let doc = Document::parse(pdf).unwrap();
    let Object::Reference(id) = doc.catalog().get(b"DSS")? else {
        panic!("/DSS is not a reference");
    };
    let dss = dictionary_at(&doc, *id);
    let streams = |key: &[u8]| -> Vec<(ObjectId, Vec<u8>)> {
        references(dss.get(key))
            .into_iter()
            .map(|id| {
                let Object::Stream(stream) = doc.object(id).unwrap() else {
                    panic!("{id} is not a stream");
                };
                (id, pdf[stream.data].to_vec())
            })
            .collect()
    };
    let Some(Object::Dictionary(vri)) = dss.get(b"VRI") else {
        panic!("no direct /VRI");
    };
    let vri = vri
        .iter()
        .map(|(key, value)| {
            let Object::Reference(id) = value else {
                panic!("VRI entry is not a reference");
            };
            let entry = dictionary_at(&doc, *id);
            assert_eq!(entry.get(b"Type"), Some(&Object::Name(b"VRI".to_vec())));
            (
                key.to_vec(),
                *id,
                [
                    references(entry.get(b"Cert")),
                    references(entry.get(b"CRL")),
                    references(entry.get(b"OCSP")),
                ],
            )
        })
        .collect();
    Some(Dss {
        certs: streams(b"Certs"),
        crls: streams(b"CRLs"),
        ocsps: streams(b"OCSPs"),
        vri,
    })
}

fn ids(streams: &[(ObjectId, Vec<u8>)]) -> Vec<ObjectId> {
    streams.iter().map(|(id, _)| *id).collect()
}

fn bytes(streams: &[(ObjectId, Vec<u8>)]) -> Vec<Vec<u8>> {
    streams.iter().map(|(_, b)| b.clone()).collect()
}

fn sign_lt(
    pdf: &[u8],
    signer: &Chained,
    tsa: &FakeTsa,
    source: &Recording,
    issuers: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    sign_at_level(
        pdf,
        signer,
        time(),
        Level::LT {
            tsa,
            revocation: source,
            issuers,
        },
    )
}

#[test]
fn level_lt_writes_dss_after_the_signature() {
    let source = recording(None);

    let signed = sign_lt(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &cms_token(&[REVOKED, EC_CA]),
        &source,
        &[],
    )
    .unwrap();

    let dss = dss(&signed).unwrap();
    let mut certs = bytes(&dss.certs);
    certs.sort();
    let mut expected = vec![LEAF.to_vec(), REVOKED.to_vec(), EC_CA.to_vec()];
    expected.sort();
    assert_eq!(certs, expected);
    assert_eq!(bytes(&dss.crls), vec![EC_CA_CRL.to_vec()]);
    assert_eq!(bytes(&dss.ocsps), vec![GOOD_OCSP.to_vec()]);
    let asked = source.asked.borrow();
    assert_eq!(asked.iter().filter(|c| c.as_slice() == LEAF).count(), 1);
    assert_eq!(asked.iter().filter(|c| c.as_slice() == REVOKED).count(), 1);
    assert!(!asked.iter().any(|c| c.as_slice() == EC_CA));

    let read = &signatures(&signed)[0];
    let key: String = Sha1::digest(&read.contents)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    assert_eq!(dss.vri.len(), 1);
    let (vri_key, _, [cert, crl, ocsp]) = &dss.vri[0];
    assert_eq!(vri_key, key.as_bytes());
    assert_eq!(cert, &ids(&dss.certs));
    assert_eq!(crl, &ids(&dss.crls));
    assert_eq!(ocsp, &ids(&dss.ocsps));

    let revisions = Document::parse(&signed).unwrap().revisions().to_vec();
    assert_eq!(
        revisions.len(),
        Document::parse(UNSIGNED).unwrap().revisions().len() + 2
    );
    let [_, _, c, d] = read.byte_range;
    assert_eq!(revisions[revisions.len() - 2].end, c + d);
    assert!(dss_free(&signed[..c + d]));
}

fn dss_free(pdf: &[u8]) -> bool {
    Document::parse(pdf)
        .unwrap()
        .catalog()
        .get(b"DSS")
        .is_none()
}

#[test]
fn level_lt_adds_nothing_to_the_cms() {
    let signed = sign_lt(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &cms_token(&[REVOKED, EC_CA]),
        &recording(None),
        &[],
    )
    .unwrap();

    let cms = SignedData::from_der(&signatures(&signed)[0].cms).unwrap();
    assert!(cms.crls.is_empty());
    let mut certificates = cms.certificates.clone();
    certificates.sort();
    let mut chain = vec![LEAF.to_vec(), EC_CA.to_vec()];
    chain.sort();
    assert_eq!(certificates, chain);
    let unsigned = &cms.signer_infos[0].unsigned_attrs;
    assert_eq!(unsigned.len(), 1);
    assert_eq!(unsigned[0].oid, SIGNATURE_TIME_STAMP_TOKEN);
}

/// The B-T file inside a `LongTerm` error: one signature carrying the token, no `/DSS`.
fn assert_bt(signed: &[u8]) {
    let reads = signatures(signed);
    assert_eq!(reads.len(), 1);
    let cms = SignedData::from_der(&reads[0].cms).unwrap();
    assert_eq!(cms.signer_infos[0].unsigned_attrs.len(), 1);
    assert!(dss_free(signed));
}

#[test]
fn unavailable_revocation_names_the_certificate_and_returns_bt() {
    let error = sign_lt(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &cms_token(&[REVOKED, EC_CA]),
        &recording(Some(REVOKED)),
        &[],
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("Nacre OpenSSL CRL fixture revoked"),
        "{error}"
    );
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    let Error::LongTerm { signed, source } = error else {
        panic!("not LongTerm");
    };
    let Error::Revocation { certificate, .. } = *source else {
        panic!("not Revocation: {source}");
    };
    assert!(
        certificate.contains("Nacre OpenSSL CRL fixture revoked"),
        "{certificate}"
    );
    assert_bt(&signed.0);
}

#[test]
fn missing_issuer_names_the_certificate() {
    let error = sign_lt(
        UNSIGNED,
        &chained(&[LEAF]),
        &cms_token(&[REVOKED]),
        &recording(None),
        &[],
    )
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Indeterminate);
    let Error::LongTerm { signed, source } = error else {
        panic!("not LongTerm");
    };
    let Error::IssuerMissing { certificate } = *source else {
        panic!("not IssuerMissing: {source}");
    };
    assert!(
        certificate.contains("Nacre OpenSSL CRL fixture leaf"),
        "{certificate}"
    );
    assert_bt(&signed.0);

    let signed = sign_lt(
        UNSIGNED,
        &chained(&[LEAF]),
        &cms_token(&[REVOKED]),
        &recording(None),
        &[EC_CA.to_vec()],
    )
    .unwrap();

    assert!(bytes(&dss(&signed).unwrap().certs).contains(&EC_CA.to_vec()));
}

#[test]
fn second_lt_signature_keeps_the_earlier_dss() {
    let signer = chained(&[LEAF, EC_CA]);
    let tsa = cms_token(&[REVOKED, EC_CA]);
    let once = sign_lt(UNSIGNED, &signer, &tsa, &recording(None), &[]).unwrap();
    let twice = sign_lt(&once, &signer, &tsa, &recording(None), &[]).unwrap();

    let first = dss(&once).unwrap();
    let second = dss(&twice).unwrap();
    assert_eq!(second.vri.len(), 2);
    let (first_key, first_entry, _) = &first.vri[0];
    assert!(
        second
            .vri
            .iter()
            .any(|(key, entry, _)| key == first_key && entry == first_entry)
    );
    for (before, after) in [
        (&first.certs, &second.certs),
        (&first.crls, &second.crls),
        (&first.ocsps, &second.ocsps),
    ] {
        assert!(ids(after).starts_with(&ids(before)));
        assert!(after.len() > before.len());
    }
}

/// Counts the questions put to `inner`, which records the last one.
struct Counted {
    inner: FakeTsa,
    calls: Cell<usize>,
}

fn counted(inner: FakeTsa) -> Counted {
    Counted {
        inner,
        calls: Cell::new(0),
    }
}

impl Counted {
    fn token(&self) -> Vec<u8> {
        self.inner.answer.clone().unwrap()
    }

    fn seen(&self) -> Option<(DigestAlgorithm, Vec<u8>)> {
        self.inner.seen.borrow().clone()
    }
}

impl TimestampAuthority for Counted {
    fn timestamp(
        &self,
        algorithm: DigestAlgorithm,
        imprint: &[u8],
    ) -> Result<Vec<u8>, nacre_core::Error> {
        self.calls.set(self.calls.get() + 1);
        self.inner.timestamp(algorithm, imprint)
    }
}

fn sign_lta(
    pdf: &[u8],
    signer: &Chained,
    tsa: &Counted,
    document_tsa: &Counted,
    source: &Recording,
) -> Result<Vec<u8>, Error> {
    sign_at_level(
        pdf,
        signer,
        time(),
        Level::LTA {
            tsa,
            revocation: source,
            issuers: &[],
            document_tsa,
        },
    )
}

fn is_document_timestamp(read: &Read) -> bool {
    read.sig.get(b"SubFilter") == Some(&Object::Name(b"ETSI.RFC3161".to_vec()))
}

/// The document timestamps of `pdf`, the one whose `/ByteRange` ends latest last.
fn document_timestamps(pdf: &[u8]) -> Vec<Read> {
    let mut stamps: Vec<Read> = signatures(pdf)
        .into_iter()
        .filter(is_document_timestamp)
        .collect();
    stamps.sort_by_key(|read| read.byte_range[2] + read.byte_range[3]);
    stamps
}

fn upper_hex_sha1(bytes: &[u8]) -> Vec<u8> {
    Sha1::digest(bytes)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>()
        .into_bytes()
}

fn revision_count(pdf: &[u8]) -> usize {
    Document::parse(pdf).unwrap().revisions().len()
}

fn lta() -> Vec<u8> {
    sign_lta(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &counted(cms_token(&[REVOKED, EC_CA])),
        &counted(cms_token(&[LEAF, EC_CA])),
        &recording(None),
    )
    .unwrap()
}

#[test]
fn level_lta_adds_a_document_timestamp_after_dss() {
    let tsa = counted(cms_token(&[REVOKED, EC_CA]));
    let document_tsa = counted(cms_token(&[LEAF, EC_CA]));

    let out = sign_lta(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &tsa,
        &document_tsa,
        &recording(None),
    )
    .unwrap();

    assert!(out.starts_with(UNSIGNED));
    let reads = signatures(&out);
    assert_eq!(reads.len(), 2);
    let stamp = reads.last().unwrap();
    assert_eq!(
        stamp.sig.get(b"Type"),
        Some(&Object::Name(b"DocTimeStamp".to_vec()))
    );
    assert!(is_document_timestamp(stamp));
    assert_eq!(stamp.sig.get(b"M"), None);
    assert_eq!(stamp.cms, document_tsa.token());
    let [_, _, c, d] = stamp.byte_range;
    assert_eq!(c + d, out.len());
    assert_eq!(
        document_tsa.seen(),
        Some((
            DigestAlgorithm::Sha256,
            range_digest(&out, stamp.byte_range)
        ))
    );
    assert_eq!(tsa.calls.get(), 1);
    assert_eq!(document_tsa.calls.get(), 1);

    let revisions = Document::parse(&out).unwrap().revisions().to_vec();
    assert_eq!(revisions.len(), revision_count(UNSIGNED) + 3);
    let before_stamp = &out[..revisions[revisions.len() - 2].end];
    assert!(dss(before_stamp).is_some());
    assert_eq!(signatures(before_stamp).len(), 1);
}

#[test]
fn document_timestamp_failure_returns_the_lt_file() {
    let document_tsa = counted(FakeTsa {
        answer: Err("down"),
        seen: RefCell::new(None),
    });

    let error = sign_lta(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &counted(cms_token(&[REVOKED, EC_CA])),
        &document_tsa,
        &recording(None),
    )
    .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Unavailable);
    let Error::Archive { signed, source } = error else {
        panic!("not Archive: {error}");
    };
    assert!(matches!(*source, Error::Timestamp(_)), "{source}");
    assert!(dss(&signed.0).is_some());
    let reads = signatures(&signed.0);
    assert_eq!(reads.len(), 1);
    assert!(!is_document_timestamp(&reads[0]));
}

/// Checks one `extend` from `before` to `after`: the newest document timestamp of `before`
/// got a `/VRI` entry listing `token_certificates` and the revocation data asked for
/// `asked`, then a new document timestamp from `tsa` covers the whole file.
fn assert_renewed(
    before: &[u8],
    after: &[u8],
    tsa: &Counted,
    source: &Recording,
    token_certificates: &[&[u8]],
    asked: &[u8],
) {
    assert!(after.starts_with(before));
    let newest = document_timestamps(before).pop().unwrap();
    let key = upper_hex_sha1(&newest.contents);
    let earlier = dss(before).unwrap();
    let later = dss(after).unwrap();
    assert_eq!(later.vri.len(), earlier.vri.len() + 1);
    assert!(earlier.vri.iter().all(|(k, _, _)| k != &key));
    for (k, entry, _) in &earlier.vri {
        assert!(later.vri.iter().any(|(l, e, _)| l == k && e == entry));
    }

    let (_, _, [cert, crl, ocsp]) = later.vri.iter().find(|(k, _, _)| k == &key).unwrap();
    let pick = |streams: &[(ObjectId, Vec<u8>)], wanted: &[ObjectId]| -> Vec<Vec<u8>> {
        wanted
            .iter()
            .map(|id| streams.iter().find(|(s, _)| s == id).unwrap().1.clone())
            .collect()
    };
    let mut certs = pick(&later.certs, cert);
    certs.sort();
    let mut expected: Vec<Vec<u8>> = token_certificates.iter().map(|c| c.to_vec()).collect();
    expected.sort();
    assert_eq!(certs, expected);
    let mut revocation = pick(&later.crls, crl);
    revocation.extend(pick(&later.ocsps, ocsp));
    let answer = if asked == LEAF { GOOD_OCSP } else { EC_CA_CRL };
    assert_eq!(revocation, vec![answer.to_vec()]);
    assert_eq!(*source.asked.borrow(), vec![asked.to_vec()]);

    let stamps = document_timestamps(after);
    assert_eq!(stamps.len(), document_timestamps(before).len() + 1);
    let renewed = stamps.last().unwrap();
    let [_, _, c, d] = renewed.byte_range;
    assert_eq!(c + d, after.len());
    assert_eq!(renewed.cms, tsa.token());
    assert_eq!(
        tsa.seen(),
        Some((
            DigestAlgorithm::Sha256,
            range_digest(after, renewed.byte_range)
        ))
    );
    assert_eq!(tsa.calls.get(), 1);
    assert_eq!(revision_count(after), revision_count(before) + 2);
}

#[test]
fn extend_renews_the_newest_document_timestamp() {
    let lta = lta();

    // Each authority's token carries a different chain, so a renewal that picked an older
    // timestamp would store the wrong certificates under the wrong key.
    let first_tsa = counted(cms_token(&[REVOKED, EC_CA]));
    let first_source = recording(None);
    let once = extend(&lta, &first_tsa, &first_source, &[]).unwrap();
    assert_renewed(&lta, &once, &first_tsa, &first_source, &[LEAF, EC_CA], LEAF);

    let second_tsa = counted(cms_token(&[LEAF, EC_CA]));
    let second_source = recording(None);
    let twice = extend(&once, &second_tsa, &second_source, &[]).unwrap();
    assert_renewed(
        &once,
        &twice,
        &second_tsa,
        &second_source,
        &[REVOKED, EC_CA],
        REVOKED,
    );
}

#[test]
fn extend_refuses_a_pdf_without_document_timestamp() {
    let lt = sign_lt(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &cms_token(&[REVOKED, EC_CA]),
        &recording(None),
        &[],
    )
    .unwrap();
    let tsa = counted(cms_token(&[REVOKED, EC_CA]));
    let source = recording(None);

    let error = extend(&lt, &tsa, &source, &[]).unwrap_err();

    assert!(matches!(error, Error::NotArchived), "{error}");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(tsa.calls.get(), 0);
    assert!(source.asked.borrow().is_empty());
}

#[test]
fn extend_refuses_a_malformed_document_timestamp() {
    let mut lta = lta();
    let stamp = document_timestamps(&lta).pop().unwrap();
    // `b` of `/ByteRange [a b c d]` is the offset of the `<` that opens the `/Contents` hex
    // string: its first byte becomes 0x00 in place.
    let open = stamp.byte_range[1];
    lta[open + 1..open + 3].copy_from_slice(b"00");
    let tsa = counted(cms_token(&[REVOKED, EC_CA]));
    let source = recording(None);

    let error = extend(&lta, &tsa, &source, &[]).unwrap_err();

    assert!(matches!(error, Error::DocumentTimestamp(_)), "{error}");
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert_eq!(tsa.calls.get(), 0);
    assert!(source.asked.borrow().is_empty());
}

#[test]
fn extend_refuses_a_document_timestamp_padded_with_non_zero_bytes() {
    let mut lta = lta();
    let stamp = document_timestamps(&lta).pop().unwrap();
    // `c` is just after the `>` that closes `/Contents`: its last byte, padding, becomes 0x01.
    let close = stamp.byte_range[2] - 1;
    lta[close - 2..close].copy_from_slice(b"01");
    let tsa = counted(cms_token(&[REVOKED, EC_CA]));
    let source = recording(None);

    let error = extend(&lta, &tsa, &source, &[]).unwrap_err();

    assert!(matches!(error, Error::DocumentTimestamp(_)), "{error}");
    assert_eq!(tsa.calls.get(), 0);
    assert!(source.asked.borrow().is_empty());
}

#[test]
fn renewing_tsa_failure_returns_the_file_with_its_dss() {
    let lta = lta();
    let tsa = counted(FakeTsa {
        answer: Err("down"),
        seen: RefCell::new(None),
    });

    let error = extend(&lta, &tsa, &recording(None), &[]).unwrap_err();

    assert_eq!(error.kind(), ErrorKind::Unavailable);
    let Error::Archive { signed, source } = error else {
        panic!("not Archive: {error}");
    };
    assert!(matches!(*source, Error::Timestamp(_)), "{source}");
    assert!(signed.0.starts_with(&lta));
    assert_eq!(revision_count(&signed.0), revision_count(&lta) + 1);
    let key = upper_hex_sha1(&document_timestamps(&lta).pop().unwrap().contents);
    assert!(
        dss(&signed.0)
            .unwrap()
            .vri
            .iter()
            .any(|(k, _, _)| k == &key)
    );
    assert_eq!(document_timestamps(&signed.0).len(), 1);
}

/// A TSA whose token, signed for `chain[0]`, carries no certificate at all.
fn certificate_less_token(chain: &[&[u8]]) -> Counted {
    let mut token = SignedData::from_der(&cms_token(chain).answer.unwrap()).unwrap();
    token.certificates.clear();
    counted(FakeTsa::answering(token.to_der().unwrap()))
}

/// An LTA file whose `/DSS` holds `[LEAF, EC_CA]` and whose document timestamp token,
/// signed for `document_signer`, carries no certificate.
fn lta_with_certificate_less_stamp(document_signer: &[u8]) -> Vec<u8> {
    sign_lta(
        UNSIGNED,
        &chained(&[LEAF, EC_CA]),
        &counted(cms_token(&[LEAF, EC_CA])),
        &certificate_less_token(&[document_signer, EC_CA]),
        &recording(None),
    )
    .unwrap()
}

#[test]
fn extend_needs_the_certificate_of_a_certificate_less_token_signer() {
    let lta = lta_with_certificate_less_stamp(REVOKED);
    let tsa = counted(cms_token(&[LEAF, EC_CA]));
    let source = recording(None);

    let error = extend(&lta, &tsa, &source, &[]).unwrap_err();

    assert!(matches!(error, Error::TimestampSignerMissing), "{error}");
    assert_eq!(error.kind(), ErrorKind::Indeterminate);
    assert_eq!(tsa.calls.get(), 0);
    assert!(source.asked.borrow().is_empty());

    // Given by the caller, the signer is renewed; its issuer comes from `/DSS`.
    let out = extend(&lta, &tsa, &source, &[REVOKED.to_vec()]).unwrap();
    assert_renewed(&lta, &out, &tsa, &source, &[REVOKED, EC_CA], REVOKED);
}

#[test]
fn extend_finds_a_certificate_less_token_signer_in_dss() {
    let lta = lta_with_certificate_less_stamp(LEAF);
    let tsa = counted(cms_token(&[REVOKED, EC_CA]));
    let source = recording(None);

    let out = extend(&lta, &tsa, &source, &[]).unwrap();

    assert_renewed(&lta, &out, &tsa, &source, &[LEAF, EC_CA], LEAF);
}

/// `pdf` with one more revision whose `/DSS /Certs` starts with a FlateDecode stream, which
/// nacre does not decode, before the certificates already there.
fn with_filtered_dss_certificate(pdf: &[u8]) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let Some(Object::Reference(id)) = doc.catalog().get(b"DSS") else {
        panic!("no /DSS reference");
    };
    let mut dss = dictionary_at(&doc, *id);
    let mut update = doc.update();
    let mut filtered = Dictionary::new();
    filtered.insert(b"Filter", Object::Name(b"FlateDecode".to_vec()));
    let stream = update
        .add_stream(filtered, b"x\x9c\x03\x00\x00\x00\x00\x01".to_vec())
        .unwrap();
    let mut certs = vec![Object::Reference(stream)];
    certs.extend(
        references(dss.get(b"Certs"))
            .into_iter()
            .map(Object::Reference),
    );
    dss.insert(b"Certs", Object::Array(certs));
    let dss = update.add(Object::Dictionary(dss)).unwrap();
    update.set_catalog(b"DSS", Object::Reference(dss));
    update.finish().unwrap()
}

#[test]
fn extend_leaves_out_a_dss_stream_that_is_not_a_certificate() {
    let lta = with_filtered_dss_certificate(&lta_with_certificate_less_stamp(LEAF));
    let tsa = counted(cms_token(&[REVOKED, EC_CA]));
    let source = recording(None);

    let out = extend(&lta, &tsa, &source, &[]).unwrap();

    assert_renewed(&lta, &out, &tsa, &source, &[LEAF, EC_CA], LEAF);
}
