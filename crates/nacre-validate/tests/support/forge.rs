//! A fictitious PKI built at test time: certificates, CRLs, timestamp tokens and PDFs
//! signed with them, for the revocation cases. Fixed keys and RFC 6979 ECDSA, so every run
//! builds the same bytes.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use der::asn1::{BitString, GeneralizedTime, Null, OctetString};
use der::flagset::FlagSet;
use der::oid::ObjectIdentifier;
use der::{Any, DateTime, Decode, Encode, Header, Length, Tag};
use nacre_cms::{
    Attribute, EncapsulatedContentInfo, SignedAttributes, SignedData, SignerIdentifier, SignerInfo,
    sign_detached,
};
use nacre_core::{DigestAlgorithm, SignatureAlgorithm, Signer, TimestampAuthority};
use nacre_pades::{Level, sign_at_level};
use nacre_pdf::{Dictionary, Document, Object, SignatureSpec};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder, CrlBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::ext::pkix::{
    BasicConstraints, CrlNumber, CrlReason, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

// The OCSP declarations of nacre-revocation, which its public API does not expose (ADR-0018).
#[allow(dead_code, unreachable_pub)]
#[path = "../../../nacre-revocation/src/ocsp/asn1.rs"]
mod asn1;

pub const UNSIGNED: &[u8] = include_bytes!("../corpus/unsigned.pdf");

const TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const EXPIRED_CERTS_ON_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.60");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
const OCSP_NOCHECK: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");
const ARCHIVE_CUTOFF: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.6");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// Under the arc RFC 5612 reserves for documentation (enterprise number 32473).
const POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.17");

/// A UTC instant as an X.509 time.
pub fn time(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Time {
    Time::from(DateTime::new(year, month, day, hour, minute, second).unwrap())
}

pub fn instant(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> SystemTime {
    time(year, month, day, hour, minute, second).to_system_time()
}

pub fn key(secret: &[u8; 32]) -> SigningKey {
    SigningKey::from_slice(secret).unwrap()
}

/// What a forged certificate is: a CA, a document signer, a timestamp authority whose
/// critical `extendedKeyUsage` is `id-kp-timeStamping` alone, or an OCSP responder its
/// issuer delegated (`id-kp-OCSPSigning`, `id-pkix-ocsp-nocheck`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Ca,
    Signer,
    Tsa,
    OcspResponder,
}

/// The extensions of a forged certificate: its role's usual ones, or a leaf's set apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extensions {
    Usual,
    /// The role's extensions, its `keyUsage` replaced by this one.
    KeyUsage(FlagSet<KeyUsages>),
    /// The role's extensions, its `keyUsage` given twice.
    RepeatedKeyUsage,
    /// The role's extensions, the `subjectKeyIdentifier` of a CA or a responder left out.
    WithoutKeyIdentifier,
}

struct Profile {
    subject: Name,
    issuer: Name,
    role: Role,
    extensions: Extensions,
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let ca = self.role == Role::Ca;
        let basic_constraints = BasicConstraints {
            ca,
            path_len_constraint: None,
        }
        .to_extension(tbs.subject(), &[])?;
        let usage: FlagSet<KeyUsages> = match (self.extensions, self.role) {
            (Extensions::KeyUsage(usage), _) => usage,
            (_, Role::Ca) => KeyUsages::KeyCertSign | KeyUsages::CRLSign,
            (_, Role::Signer) => KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
            (_, Role::Tsa | Role::OcspResponder) => KeyUsages::DigitalSignature.into(),
        };
        let key_usage = KeyUsage(usage)
            .to_extension(tbs.subject(), std::slice::from_ref(&basic_constraints))?;
        let mut extensions = vec![basic_constraints, key_usage.clone()];
        if self.extensions == Extensions::RepeatedKeyUsage {
            extensions.push(key_usage);
        }
        if (ca || self.role == Role::OcspResponder)
            && self.extensions != Extensions::WithoutKeyIdentifier
        {
            let digest = Sha256::digest(spk.subject_public_key.raw_bytes());
            extensions.push(
                SubjectKeyIdentifier(OctetString::new(&digest[..20])?)
                    .to_extension(tbs.subject(), &extensions)?,
            );
        }
        if self.role == Role::Tsa {
            extensions.push(Extension {
                extn_id: EXTENDED_KEY_USAGE,
                critical: true,
                extn_value: OctetString::new(ExtendedKeyUsage(vec![TIME_STAMPING]).to_der()?)?,
            });
        }
        if self.role == Role::OcspResponder {
            extensions.push(Extension {
                extn_id: EXTENDED_KEY_USAGE,
                critical: false,
                extn_value: OctetString::new(ExtendedKeyUsage(vec![OCSP_SIGNING]).to_der()?)?,
            });
            extensions.push(Extension {
                extn_id: OCSP_NOCHECK,
                critical: false,
                extn_value: OctetString::new(Null.to_der()?)?,
            });
        }
        Ok(extensions)
    }
}

/// A certificate for `key`, of `role`, named `subject`, issued by `issuer` (itself when
/// `None`) with `issuer_key`, valid 2026-01-01 to 2036-01-01.
pub fn issue(
    role: Role,
    subject: &str,
    serial: u64,
    key: &SigningKey,
    issuer: Option<&Certificate>,
    issuer_key: &SigningKey,
) -> Certificate {
    issue_valid(
        role,
        subject,
        serial,
        key,
        issuer,
        issuer_key,
        time(2026, 1, 1, 0, 0, 0),
        time(2036, 1, 1, 0, 0, 0),
    )
}

/// [`issue`], valid from `not_before` to `not_after`.
#[allow(clippy::too_many_arguments)]
pub fn issue_valid(
    role: Role,
    subject: &str,
    serial: u64,
    key: &SigningKey,
    issuer: Option<&Certificate>,
    issuer_key: &SigningKey,
    not_before: Time,
    not_after: Time,
) -> Certificate {
    issue_with(
        role,
        subject,
        serial,
        key,
        issuer,
        issuer_key,
        (not_before, not_after),
        Extensions::Usual,
    )
}

/// [`issue_valid`] with `extensions`, valid from the first time to the second.
#[allow(clippy::too_many_arguments)]
pub fn issue_with(
    role: Role,
    subject: &str,
    serial: u64,
    key: &SigningKey,
    issuer: Option<&Certificate>,
    issuer_key: &SigningKey,
    (not_before, not_after): (Time, Time),
    extensions: Extensions,
) -> Certificate {
    let subject = Name::from_str(subject).unwrap();
    let profile = Profile {
        issuer: issuer.map_or(subject.clone(), |issuer| {
            issuer.tbs_certificate().subject().clone()
        }),
        subject,
        role,
        extensions,
    };
    let validity = Validity::new(not_before, not_after);
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
    CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki)
        .unwrap()
        .build::<_, DerSignature>(issuer_key)
        .unwrap()
}

/// A CRL of `issuer`, signed with `key`, listing each certificate of `revoked` with its
/// revocation date.
pub fn crl(
    issuer: &Certificate,
    key: &SigningKey,
    this_update: Time,
    next_update: Time,
    revoked: &[(&Certificate, Time)],
) -> Vec<u8> {
    let entries: Vec<_> = revoked
        .iter()
        .map(|(certificate, date)| (*certificate, *date, None))
        .collect();
    crl_with_reasons(issuer, key, this_update, next_update, &entries)
}

/// [`crl`], each entry carrying its `reasonCode` when given.
pub fn crl_with_reasons(
    issuer: &Certificate,
    key: &SigningKey,
    this_update: Time,
    next_update: Time,
    revoked: &[(&Certificate, Time, Option<CrlReason>)],
) -> Vec<u8> {
    let entries: Vec<RevokedCert> = revoked
        .iter()
        .map(|(certificate, date, reason)| RevokedCert {
            serial_number: certificate.tbs_certificate().serial_number().clone(),
            revocation_date: *date,
            crl_entry_extensions: reason.map(|reason| {
                vec![
                    reason
                        .to_extension(issuer.tbs_certificate().subject(), &[])
                        .unwrap(),
                ]
            }),
        })
        .collect();
    CrlBuilder::new_with_this_update(issuer, CrlNumber::try_from(1u32).unwrap(), this_update)
        .unwrap()
        .with_next_update(Some(next_update))
        .with_certificates(entries.into_iter())
        .build::<_, DerSignature>(key)
        .unwrap()
        .to_der()
        .unwrap()
}

/// A CRL of `issuer` revoking nothing, signed with `key`, whose `expiredCertsOnCRL`
/// extension (RFC 5280, 5.2.7, not critical) says it keeps entries for certificates expired
/// since `from`.
pub fn crl_with_expired_certs_on_crl(
    issuer: &Certificate,
    key: &SigningKey,
    this_update: Time,
    next_update: Time,
    from: Time,
) -> Vec<u8> {
    let der = crl(issuer, key, this_update, next_update, &[]);
    let mut list: CertificateList = CertificateList::from_der(&der).unwrap();
    let from = GeneralizedTime::from_system_time(from.to_system_time()).unwrap();
    list.tbs_cert_list
        .crl_extensions
        .get_or_insert_with(Vec::new)
        .push(Extension {
            extn_id: EXPIRED_CERTS_ON_CRL,
            critical: false,
            extn_value: OctetString::new(from.to_der().unwrap()).unwrap(),
        });
    let tbs = list.tbs_cert_list.to_der().unwrap();
    let signature: DerSignature = key.sign_prehash(&Sha256::digest(&tbs)).unwrap();
    list.signature = BitString::from_bytes(signature.as_bytes()).unwrap();
    list.to_der().unwrap()
}

/// Where an extension of a forged OCSP response sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspPlace {
    /// The `singleExtensions` of its single response.
    Single,
    /// The `responseExtensions` of its `ResponseData`.
    Response,
}

/// An extension of a forged OCSP response: its OID, the DER of its value, whether it is
/// critical and where it sits.
#[derive(Debug, Clone)]
pub struct OcspExtension {
    pub oid: ObjectIdentifier,
    pub value: Vec<u8>,
    pub critical: bool,
    pub place: OcspPlace,
}

impl OcspExtension {
    /// An `archiveCutoff` (RFC 6960, 4.4.4) of `from`.
    pub fn archive_cutoff(from: Time, critical: bool, place: OcspPlace) -> Self {
        Self {
            oid: ARCHIVE_CUTOFF,
            value: GeneralizedTime::from_system_time(from.to_system_time())
                .unwrap()
                .to_der()
                .unwrap(),
            critical,
            place,
        }
    }
}

/// A basic OCSP response on `certificate` (issued by `issuer`), signed with `key` and naming
/// `responder` by name, `embed` in its `certs` when given. `thisUpdate` is `produced`,
/// `nextUpdate` 7 days later; the status is "revoked" at the date of `revoked`, with its
/// reason when given, else "good". Each of `extensions` goes where it says.
#[allow(clippy::too_many_arguments)]
pub fn ocsp(
    certificate: &Certificate,
    issuer: &Certificate,
    key: &SigningKey,
    responder: &Certificate,
    embed: Option<&Certificate>,
    produced: Time,
    revoked: Option<(Time, Option<CrlReason>)>,
    extensions: &[OcspExtension],
) -> Vec<u8> {
    use asn1::{
        BasicOcspResponse, CertStatus, ID_PKIX_OCSP_BASIC, OcspRequest, OcspResponse,
        OcspResponseStatus, ResponderId, ResponseBytes, ResponseData, RevokedInfo, SingleResponse,
    };
    let generalized = |time: SystemTime| GeneralizedTime::from_system_time(time).unwrap();
    let request = nacre_revocation::OcspRequest::new(
        &certificate.to_der().unwrap(),
        &issuer.to_der().unwrap(),
        &[1],
    )
    .unwrap();
    let request = OcspRequest::from_der(&request.to_der().unwrap()).unwrap();
    let cert_id = request.tbs_request.request_list[0].req_cert.clone();
    let cert_status = match revoked {
        None => CertStatus::Good(Null),
        Some((date, reason)) => CertStatus::Revoked(RevokedInfo {
            revocation_time: generalized(date.to_system_time()),
            revocation_reason: reason,
        }),
    };
    let placed = |place: OcspPlace| {
        let list: Vec<Extension> = extensions
            .iter()
            .filter(|extension| extension.place == place)
            .map(|extension| Extension {
                extn_id: extension.oid,
                critical: extension.critical,
                extn_value: OctetString::new(extension.value.clone()).unwrap(),
            })
            .collect();
        (!list.is_empty()).then_some(list)
    };
    let produced = produced.to_system_time();
    let data = ResponseData {
        version: x509_cert::certificate::Version::V1,
        responder_id: ResponderId::ByName(responder.tbs_certificate().subject().clone()),
        produced_at: generalized(produced),
        responses: vec![SingleResponse {
            cert_id,
            cert_status,
            this_update: generalized(produced),
            next_update: Some(generalized(produced + Duration::from_secs(7 * 86_400))),
            single_extensions: placed(OcspPlace::Single),
        }],
        response_extensions: placed(OcspPlace::Response),
    };
    let signature: DerSignature = key
        .sign_prehash(&Sha256::digest(data.to_der().unwrap()))
        .unwrap();
    let basic = BasicOcspResponse {
        tbs_response_data: data,
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        },
        signature: BitString::from_bytes(signature.as_bytes()).unwrap(),
        certs: embed.map(|certificate| vec![Any::encode_from(certificate).unwrap()]),
    };
    OcspResponse {
        response_status: OcspResponseStatus::Successful,
        response_bytes: Some(ResponseBytes {
            response_type: ID_PKIX_OCSP_BASIC,
            response: OctetString::new(basic.to_der().unwrap()).unwrap(),
        }),
    }
    .to_der()
    .unwrap()
}

/// A P-256 signer holding `chain`, signer first.
pub struct ChainSigner {
    pub key: SigningKey,
    pub chain: Vec<Vec<u8>>,
}

impl Signer for ChainSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256Sha256
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, nacre_core::Error> {
        let signature: DerSignature = self
            .key
            .sign_prehash(digest)
            .map_err(|error| nacre_core::Error::Signer(Box::new(error)))?;
        Ok(signature.as_bytes().to_vec())
    }
}

/// A timestamp authority answering with a token signed by `key`, carrying `certificates`
/// (its own first), dated `gen_time`. With `imprint` set, the token time-stamps that digest
/// instead of the one asked.
pub struct ForgedTsa {
    pub key: SigningKey,
    pub certificates: Vec<Vec<u8>>,
    pub gen_time: DateTime,
    pub imprint: Option<Vec<u8>>,
}

impl TimestampAuthority for ForgedTsa {
    fn timestamp(
        &self,
        _algorithm: DigestAlgorithm,
        imprint: &[u8],
    ) -> Result<Vec<u8>, nacre_core::Error> {
        let imprint = self.imprint.as_deref().unwrap_or(imprint);
        Ok(token(&self.key, &self.certificates, self.gen_time, imprint))
    }
}

/// A `TimeStampToken` over `imprint` (SHA-256), signed with `key`, its signer the first of
/// `certificates`, with `signingCertificateV2`.
pub fn token(
    key: &SigningKey,
    certificates: &[Vec<u8>],
    gen_time: DateTime,
    imprint: &[u8],
) -> Vec<u8> {
    let tsa = &certificates[0];
    let tst_info = tst_info(gen_time, imprint);
    let parsed = Certificate::from_der(tsa).unwrap();
    let tbs = parsed.tbs_certificate();
    let cert_id = tlv(
        Tag::Sequence,
        &OctetString::new(Sha256::digest(tsa).as_slice())
            .unwrap()
            .to_der()
            .unwrap(),
    );
    let ess = Any::from_der(&tlv(Tag::Sequence, &tlv(Tag::Sequence, &cert_id))).unwrap();
    let attributes = vec![
        Attribute::new(nacre_cms::oid::CONTENT_TYPE, &TST_INFO).unwrap(),
        Attribute::new(
            nacre_cms::oid::MESSAGE_DIGEST,
            &OctetString::new(Sha256::digest(&tst_info).as_slice()).unwrap(),
        )
        .unwrap(),
        Attribute::new(SIGNING_CERTIFICATE_V2, &ess).unwrap(),
    ];
    let signed_attrs = SignedAttributes::from_attributes(attributes).unwrap();
    let signature: DerSignature = key
        .sign_prehash(&Sha256::digest(signed_attrs.to_be_signed().unwrap()))
        .unwrap();
    SignedData {
        version: 3,
        digest_algorithms: vec![sha256()],
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: TST_INFO,
            econtent: Some(tst_info),
        },
        certificates: certificates.to_vec(),
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
            signature: signature.as_bytes().to_vec(),
            unsigned_attrs: Vec::new(),
        }],
    }
    .to_der()
    .unwrap()
}

/// `TSTInfo { v1, policy, messageImprint, serialNumber 1, genTime }`.
fn tst_info(gen_time: DateTime, imprint: &[u8]) -> Vec<u8> {
    let mut algorithm = sha256();
    algorithm.parameters = Some(Any::null());
    let mut message_imprint = algorithm.to_der().unwrap();
    message_imprint.extend(OctetString::new(imprint).unwrap().to_der().unwrap());

    let mut body = 1u8.to_der().unwrap();
    body.extend(POLICY.to_der().unwrap());
    body.extend(tlv(Tag::Sequence, &message_imprint));
    body.extend(1u8.to_der().unwrap());
    body.extend(GeneralizedTime::from_date_time(gen_time).to_der().unwrap());
    tlv(Tag::Sequence, &body)
}

fn sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: SHA256,
        parameters: None,
    }
}

fn tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
    let mut out = Header::new(tag, Length::try_from(value.len()).unwrap())
        .to_der()
        .unwrap();
    out.extend_from_slice(value);
    out
}

/// `unsigned.pdf` signed by `signer` at `level`, its `/M` 2026-10-22T08:00Z.
pub fn signed(signer: &dyn Signer, level: Level<'_>) -> Vec<u8> {
    let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();
    sign_at_level(UNSIGNED, signer, time, level).unwrap()
}

/// `unsigned.pdf` signed once by `signer` in the field `Signature1`, under `/SubFilter
/// /<sub_filter>`, its `/M` written only when `claimed` is given, its CMS a PAdES one with no
/// signature timestamp.
pub fn custom_signed(signer: &dyn Signer, sub_filter: &[u8], claimed: Option<&[u8]>) -> Vec<u8> {
    let mut entries = Dictionary::new();
    if let Some(claimed) = claimed {
        entries.insert(b"M", Object::String(claimed.to_vec()));
    }
    let prepared = Document::parse(UNSIGNED)
        .unwrap()
        .update()
        .sign(SignatureSpec {
            field: "Signature1".into(),
            sub_filter: sub_filter.to_vec(),
            contents_len: 40000,
            entries,
        })
        .unwrap();
    let mut hasher = Sha256::new();
    for part in prepared.signed_parts() {
        hasher.update(part);
    }
    let cms = sign_detached(&hasher.finalize(), signer, &nacre_cms::Profile::PADES, None).unwrap();
    prepared.embed(&cms).unwrap()
}

/// `pdf` with its last occurrence of `from` replaced by `to`, padded with spaces to the same
/// length so that no offset moves.
pub fn patch(pdf: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    assert!(to.len() <= from.len());
    let mut out = pdf.to_vec();
    let at = out
        .windows(from.len())
        .rposition(|window| window == from)
        .unwrap();
    let mut replacement = to.to_vec();
    replacement.resize(from.len(), b' ');
    out[at..at + from.len()].copy_from_slice(&replacement);
    out
}

/// `pdf`, whose last `/ByteRange` covers bytes patched since it was signed, signed again by
/// `signer` over those bytes, its new CMS written in the same `/Contents` slot.
pub fn resign(pdf: &[u8], signer: &dyn Signer) -> Vec<u8> {
    let at = pdf
        .windows(b"/ByteRange".len())
        .rposition(|window| window == b"/ByteRange")
        .unwrap();
    let open = at + pdf[at..].iter().position(|b| *b == b'[').unwrap();
    let close = open + pdf[open..].iter().position(|b| *b == b']').unwrap();
    let range: Vec<usize> = std::str::from_utf8(&pdf[open + 1..close])
        .unwrap()
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    let [_, b, c, d] = range[..] else {
        panic!("not a four-number /ByteRange");
    };
    let mut hasher = Sha256::new();
    hasher.update(&pdf[..b]);
    hasher.update(&pdf[c..c + d]);
    let cms = sign_detached(&hasher.finalize(), signer, &nacre_cms::Profile::PADES, None).unwrap();
    let hexed: String = cms.iter().map(|byte| format!("{byte:02X}")).collect();
    let mut out = pdf.to_vec();
    let slot = &mut out[b + 1..c - 1];
    assert!(hexed.len() <= slot.len());
    slot.fill(b'0');
    slot[..hexed.len()].copy_from_slice(hexed.as_bytes());
    out
}

/// `pdf` given one revision whose catalog points at a `/DSS` listing `certificates` under
/// `/Certs` and `crls` under `/CRLs`, each as an unfiltered stream.
pub fn with_dss(pdf: &[u8], certificates: &[Vec<u8>], crls: &[Vec<u8>]) -> Vec<u8> {
    with_dss_ocsps(pdf, certificates, crls, &[])
}

/// [`with_dss`], with `ocsps` under `/OCSPs`.
pub fn with_dss_ocsps(
    pdf: &[u8],
    certificates: &[Vec<u8>],
    crls: &[Vec<u8>],
    ocsps: &[Vec<u8>],
) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let mut update = doc.update();
    let mut dss = Dictionary::new();
    for (key, items) in [
        (&b"Certs"[..], certificates),
        (&b"CRLs"[..], crls),
        (&b"OCSPs"[..], ocsps),
    ] {
        if items.is_empty() {
            continue;
        }
        let streams = items
            .iter()
            .map(|data| {
                Object::Reference(update.add_stream(Dictionary::new(), data.clone()).unwrap())
            })
            .collect();
        dss.insert(key, Object::Array(streams));
    }
    let dss = update.add(Object::Dictionary(dss)).unwrap();
    update.set_catalog(b"DSS", Object::Reference(dss));
    update.finish().unwrap()
}

/// `id-aa-signingCertificate` (RFC 2634, ESS v1).
const SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// The ESS attribute naming the signer certificate in a forged CMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ess {
    /// `signingCertificateV2`, SHA-256.
    V2,
    /// `signingCertificate`, SHA-1.
    V1,
    None,
}

/// How [`signed_with`] signs: the `/SubFilter`, the `/M` (absent when `None`), a
/// `signingTime` attribute, the ESS attribute, other signed attributes, the CRLs of the CMS
/// and a signature timestamp from `tsa`.
pub struct Signature<'a> {
    pub sub_filter: &'a [u8],
    pub claimed: Option<&'a [u8]>,
    pub signing_time: Option<Time>,
    pub ess: Ess,
    pub attributes: Vec<Attribute>,
    pub crls: Vec<Vec<u8>>,
    pub tsa: Option<&'a dyn TimestampAuthority>,
}

impl Default for Signature<'_> {
    /// A PAdES signature with ESS v2, its `/M` 2026-10-22T08:00Z, nothing else.
    fn default() -> Self {
        Self {
            sub_filter: b"ETSI.CAdES.detached",
            claimed: Some(b"D:20261022080000Z"),
            signing_time: None,
            ess: Ess::V2,
            attributes: Vec::new(),
            crls: Vec::new(),
            tsa: None,
        }
    }
}

/// `pdf` signed once more by `signer` (P-256) in a new field, as `options` says, the
/// `SignerInfo` built from its own signed attributes.
pub fn signed_with(pdf: &[u8], signer: &dyn Signer, options: &Signature<'_>) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let mut entries = Dictionary::new();
    if let Some(claimed) = options.claimed {
        entries.insert(b"M", Object::String(claimed.to_vec()));
    }
    let prepared = doc
        .update()
        .sign(SignatureSpec {
            field: free_field(&doc, "Signature"),
            sub_filter: options.sub_filter.to_vec(),
            contents_len: 40000,
            entries,
        })
        .unwrap();
    let mut hasher = Sha256::new();
    for part in prepared.signed_parts() {
        hasher.update(part);
    }
    let chain = signer.certificate_chain();
    let leaf = &chain[0];
    let mut attributes = vec![
        Attribute::new(nacre_cms::oid::CONTENT_TYPE, &nacre_cms::oid::DATA).unwrap(),
        Attribute::new(
            nacre_cms::oid::MESSAGE_DIGEST,
            &OctetString::new(hasher.finalize().as_slice()).unwrap(),
        )
        .unwrap(),
    ];
    let hash = match options.ess {
        Ess::V2 => Some((SIGNING_CERTIFICATE_V2, Sha256::digest(leaf).to_vec())),
        Ess::V1 => Some((SIGNING_CERTIFICATE, sha1(leaf).to_vec())),
        Ess::None => None,
    };
    if let Some((oid, hash)) = hash {
        let cert_id = tlv(
            Tag::Sequence,
            &OctetString::new(hash).unwrap().to_der().unwrap(),
        );
        let ess = Any::from_der(&tlv(Tag::Sequence, &tlv(Tag::Sequence, &cert_id))).unwrap();
        attributes.push(Attribute::new(oid, &ess).unwrap());
    }
    if let Some(time) = options.signing_time {
        attributes.push(Attribute::new(nacre_cms::oid::SIGNING_TIME, &time).unwrap());
    }
    attributes.extend(options.attributes.iter().cloned());
    let signed_attrs = SignedAttributes::from_attributes(attributes).unwrap();
    let signature = signer
        .sign_digest(&Sha256::digest(signed_attrs.to_be_signed().unwrap()))
        .unwrap();
    let parsed = Certificate::from_der(leaf).unwrap();
    let tbs = parsed.tbs_certificate();
    let mut info = SignerInfo {
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
    };
    if let Some(tsa) = options.tsa {
        let token = tsa
            .timestamp(DigestAlgorithm::Sha256, &Sha256::digest(&info.signature))
            .unwrap();
        info.push_unsigned_attribute(Attribute {
            oid: SIGNATURE_TIME_STAMP_TOKEN,
            values: vec![Any::from_der(&token).unwrap()],
        });
    }
    let cms = SignedData {
        version: 1,
        digest_algorithms: vec![sha256()],
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: nacre_cms::oid::DATA,
            econtent: None,
        },
        certificates: chain.to_vec(),
        crls: options.crls.clone(),
        signer_infos: vec![info],
    };
    prepared.embed(&cms.to_der().unwrap()).unwrap()
}

/// `pdf` given one revision holding a document timestamp: a `/Type /DocTimeStamp`
/// dictionary under `/SubFilter /ETSI.RFC3161` whose `/Contents` is the token `tsa`
/// returns for the SHA-256 of its `/ByteRange`, as `nacre-pades` writes it.
pub fn document_timestamp(pdf: &[u8], tsa: &dyn TimestampAuthority) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let mut entries = Dictionary::new();
    entries.insert(b"Type", Object::Name(b"DocTimeStamp".to_vec()));
    let prepared = doc
        .update()
        .sign(SignatureSpec {
            field: free_field(&doc, "DocumentTimestamp"),
            sub_filter: b"ETSI.RFC3161".to_vec(),
            contents_len: 20000,
            entries,
        })
        .unwrap();
    let mut hasher = Sha256::new();
    for part in prepared.signed_parts() {
        hasher.update(part);
    }
    let token = tsa
        .timestamp(DigestAlgorithm::Sha256, &hasher.finalize())
        .unwrap();
    prepared.embed(&token).unwrap()
}

/// `<prefix><n>` for the smallest `n` from 1 no signature field of `doc` is named.
fn free_field(doc: &Document<'_>, prefix: &str) -> String {
    let taken: Vec<String> = doc
        .signature_fields()
        .iter()
        .map(|field| field.name.clone())
        .collect();
    (1..)
        .map(|n| format!("{prefix}{n}"))
        .find(|name| !taken.contains(name))
        .unwrap()
}

/// SHA-1 (FIPS 180-4), for the ESS v1 attribute alone: no dependency of this crate has it.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(data.len() as u64 * 8).to_be_bytes());
    for block in message.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..20 => ((b & c) | (!b & d), 0x5a82_7999),
                20..40 => (b ^ c ^ d, 0x6ed9_eba1),
                40..60 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        for (state, value) in h.iter_mut().zip([a, b, c, d, e]) {
            *state = state.wrapping_add(value);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}
