//! Writes the attack corpus of `tests/corpus/attacks/`: each file is a `TimeStampResp`
//! answering `tests/corpus/recorded/request.tsq`, correct apart from one defect.
//!
//! `cargo run -p nacre-tsp --example forge_attacks -- crates/nacre-tsp/tests/corpus/attacks`
//!
//! The output is deterministic: a fixed test key, RFC 6979 ECDSA, fixed dates.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use der::asn1::{OctetString, UintRef};
use der::oid::ObjectIdentifier;
use der::{Any, DateTime, Decode, Encode, Header, Length, Tag};
use nacre_cms::{
    Attribute, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier, SignerInfo,
};
use nacre_core::{Signer, TestSigner};
use nacre_tsp::oid;
use p256::ecdsa::{DerSignature, SigningKey};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const SECRET: [u8; 32] = [0x11; 32];
const DATA: &[u8] = include_bytes!("../tests/corpus/recorded/data.bin");
// The nonce of `recorded/request.tsq`.
const NONCE: [u8; 8] = [0xd4, 0x1c, 0xbf, 0xf4, 0xfd, 0xed, 0x9d, 0x81];
const GEN_TIME: &[u8] = b"20261022092550.25Z";
// `2.999.1.1`, the bench TSA's policy, which const-oid cannot hold: written raw.
const POLICY: &[u8] = &[0x06, 0x04, 0x88, 0x37, 0x01, 0x01];
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SIGNING_CERTIFICATE_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const CODE_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.3");
// SHA3-256: a 32-byte digest like SHA-256, so only the identifier differs.
const SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");

enum Ess {
    V2,
    V1,
}

fn main() {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("usage: forge_attacks <dir>"),
    );
    std::fs::create_dir_all(&dir).unwrap();

    let signer = TestSigner::from_secret(&SECRET).unwrap();
    let tsa = tsa_certificate(true, vec![oid::TIME_STAMPING]);
    let imprint = Sha256::digest(DATA);

    let valid = token(&signer, &tsa, &tst_info(&imprint, Some(&NONCE)), Ess::V2);
    write(&dir, "valid", &valid);

    write(
        &dir,
        "nonce-absent",
        &token(&signer, &tsa, &tst_info(&imprint, None), Ess::V2),
    );

    let other = Sha256::digest(b"another content");
    write(
        &dir,
        "imprint-other",
        &token(&signer, &tsa, &tst_info(&other, Some(&NONCE)), Ess::V2),
    );

    let ca_without_eku = &signer.certificate_chain()[0];
    write(
        &dir,
        "no-timestamping-eku",
        &token(
            &signer,
            ca_without_eku,
            &tst_info(&imprint, Some(&NONCE)),
            Ess::V2,
        ),
    );

    let mut altered = SignedData::from_der(&valid).unwrap();
    let signature = &mut altered.signer_infos[0].signature;
    *signature.last_mut().unwrap() ^= 0x01;
    write(&dir, "signature-invalid", &altered.to_der().unwrap());

    write(
        &dir,
        "ess-v1-only",
        &token(&signer, &tsa, &tst_info(&imprint, Some(&NONCE)), Ess::V1),
    );

    // Consistent with its `contentType` attribute, so only the TSTInfo rule can refuse it.
    write(
        &dir,
        "content-type-other",
        &token_of(
            &signer,
            &tsa,
            &tst_info(&imprint, Some(&NONCE)),
            Ess::V2,
            nacre_cms::oid::DATA,
        ),
    );

    let eku_not_critical = tsa_certificate(false, vec![oid::TIME_STAMPING]);
    write(
        &dir,
        "eku-not-critical",
        &token(
            &signer,
            &eku_not_critical,
            &tst_info(&imprint, Some(&NONCE)),
            Ess::V2,
        ),
    );

    let eku_extra = tsa_certificate(true, vec![oid::TIME_STAMPING, CODE_SIGNING]);
    write(
        &dir,
        "eku-extra-purpose",
        &token(
            &signer,
            &eku_extra,
            &tst_info(&imprint, Some(&NONCE)),
            Ess::V2,
        ),
    );

    let sha3 = AlgorithmIdentifierOwned {
        oid: SHA3_256,
        parameters: Some(Any::null()),
    };
    write(
        &dir,
        "imprint-algorithm-other",
        &token(
            &signer,
            &tsa,
            &tst_info_with(sha3, &imprint, Some(&NONCE)),
            Ess::V2,
        ),
    );

    let integer_parameters = AlgorithmIdentifierOwned {
        oid: oid::SHA256,
        parameters: Some(Any::from_der(&[0x02, 0x01, 0x00]).unwrap()),
    };
    write(
        &dir,
        "imprint-parameters-other",
        &token(
            &signer,
            &tsa,
            &tst_info_with(integer_parameters, &imprint, Some(&NONCE)),
            Ess::V2,
        ),
    );
}

/// A `TimeStampToken` over `tst_info`, signed with the test key and carrying `certificate`.
fn token(signer: &TestSigner, certificate: &[u8], tst_info: &[u8], ess: Ess) -> Vec<u8> {
    token_of(signer, certificate, tst_info, ess, oid::TST_INFO)
}

/// As [`token`], with `content_type` as both the `eContentType` and the `contentType`
/// attribute.
fn token_of(
    signer: &TestSigner,
    certificate: &[u8],
    tst_info: &[u8],
    ess: Ess,
    content_type: ObjectIdentifier,
) -> Vec<u8> {
    let parsed = Certificate::from_der(certificate).unwrap();
    let tbs = parsed.tbs_certificate();
    let ess = match ess {
        Ess::V2 => Attribute::new(
            oid::SIGNING_CERTIFICATE_V2,
            &ess_certificate(&Sha256::digest(certificate)),
        ),
        Ess::V1 => Attribute::new(
            SIGNING_CERTIFICATE_V1,
            &ess_certificate(&Sha1::digest(certificate)),
        ),
    }
    .unwrap();
    let attributes = vec![
        Attribute::new(nacre_cms::oid::CONTENT_TYPE, &content_type).unwrap(),
        Attribute::new(
            nacre_cms::oid::MESSAGE_DIGEST,
            &OctetString::new(Sha256::digest(tst_info).as_slice()).unwrap(),
        )
        .unwrap(),
        ess,
    ];
    let signed_attrs = SignedAttributes::from_attributes(attributes).unwrap();
    let signature = signer
        .sign_digest(&Sha256::digest(signed_attrs.to_be_signed().unwrap()))
        .unwrap();
    SignedData {
        version: 3,
        digest_algorithms: vec![sha256()],
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: content_type,
            econtent: Some(tst_info.to_vec()),
        },
        certificates: vec![certificate.to_vec()],
        crls: Vec::new(),
        signer_infos: vec![SignerInfo {
            version: 1,
            sid: SignerIdentifier::IssuerAndSerialNumber {
                issuer: tbs.issuer().to_der().unwrap(),
                serial_number: tbs.serial_number().clone(),
            },
            digest_algorithm: sha256(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
            signature,
            unsigned_attrs: Vec::new(),
        }],
    }
    .to_der()
    .unwrap()
}

/// `TSTInfo { v1, policy, messageImprint, serialNumber 1, genTime, nonce }`.
fn tst_info(imprint: &[u8], nonce: Option<&[u8]>) -> Vec<u8> {
    let mut algorithm = sha256();
    algorithm.parameters = Some(Any::null());
    tst_info_with(algorithm, imprint, nonce)
}

fn tst_info_with(
    algorithm: AlgorithmIdentifierOwned,
    imprint: &[u8],
    nonce: Option<&[u8]>,
) -> Vec<u8> {
    let mut message_imprint = algorithm.to_der().unwrap();
    message_imprint.extend(OctetString::new(imprint).unwrap().to_der().unwrap());

    let mut body = 1u8.to_der().unwrap();
    body.extend(POLICY);
    body.extend(tlv(Tag::Sequence, &message_imprint));
    body.extend(1u8.to_der().unwrap());
    body.extend(tlv(Tag::GeneralizedTime, GEN_TIME));
    if let Some(nonce) = nonce {
        body.extend(UintRef::new(nonce).unwrap().to_der().unwrap());
    }
    tlv(Tag::Sequence, &body)
}

/// `SigningCertificate(V2) { certs: [ESSCertID(v2) { certHash }] }`, the v2 hash being the
/// DEFAULT SHA-256, so DER omits its algorithm.
fn ess_certificate(hash: &[u8]) -> Any {
    let cert_id = tlv(
        Tag::Sequence,
        &OctetString::new(hash).unwrap().to_der().unwrap(),
    );
    let certs = tlv(Tag::Sequence, &cert_id);
    Any::from_der(&tlv(Tag::Sequence, &certs)).unwrap()
}

struct TsaProfile(Name);

impl BuilderProfile for TsaProfile {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.0.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}

/// A self-signed TSA certificate on the test key whose only extension is an
/// `extendedKeyUsage` of `purposes`, critical when asked (the builder's default is not).
fn tsa_certificate(critical: bool, purposes: Vec<ObjectIdentifier>) -> Vec<u8> {
    let key = SigningKey::from_slice(&SECRET).unwrap();
    let subject = Name::from_str("CN=Nacre forged TSA,O=Nacre tests,C=FR").unwrap();
    let validity = Validity::new(time(2026), time(2036));
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
    let mut builder = CertificateBuilder::new(
        TsaProfile(subject),
        SerialNumber::from(1u32),
        validity,
        spki,
    )
    .unwrap();
    builder
        .add_extension((critical, &ExtendedKeyUsage(purposes)))
        .unwrap();
    builder
        .build::<_, DerSignature>(&key)
        .unwrap()
        .to_der()
        .unwrap()
}

fn sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oid::SHA256,
        parameters: None,
    }
}

fn time(year: u16) -> Time {
    Time::from(DateTime::new(year, 1, 1, 0, 0, 0).unwrap())
}

fn tlv(tag: Tag, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    Header::new(tag, Length::try_from(content.len()).unwrap())
        .encode_to_vec(&mut out)
        .unwrap();
    out.extend_from_slice(content);
    out
}

/// Wraps `token` in a granted `TimeStampResp`.
fn write(dir: &Path, name: &str, token: &[u8]) {
    let mut body = vec![0x30, 0x03, 0x02, 0x01, 0x00];
    body.extend_from_slice(token);
    std::fs::write(dir.join(format!("{name}.tsr")), tlv(Tag::Sequence, &body)).unwrap();
}
