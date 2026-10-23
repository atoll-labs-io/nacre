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
use nacre_pades::{DateTime, Error, Level, TIMESTAMP_TOKEN_MAX, sign, sign_at_level};
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
