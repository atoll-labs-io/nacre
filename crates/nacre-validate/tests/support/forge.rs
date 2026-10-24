//! A fictitious PKI built at test time: certificates, CRLs, timestamp tokens and PDFs
//! signed with them, for the revocation cases. Fixed keys and RFC 6979 ECDSA, so every run
//! builds the same bytes.

use std::str::FromStr;
use std::time::SystemTime;

use der::asn1::{GeneralizedTime, OctetString};
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
use x509_cert::crl::RevokedCert;
use x509_cert::ext::pkix::{
    BasicConstraints, CrlNumber, CrlReason, ExtendedKeyUsage, KeyUsage, KeyUsages,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

pub const UNSIGNED: &[u8] = include_bytes!("../corpus/unsigned.pdf");

const TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
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

/// What a forged certificate is: a CA, a document signer, or a timestamp authority whose
/// critical `extendedKeyUsage` is `id-kp-timeStamping` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Ca,
    Signer,
    Tsa,
}

/// The extensions of a forged certificate: its role's usual ones, or a leaf's set apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extensions {
    Usual,
    /// The role's extensions, its `keyUsage` replaced by this one.
    KeyUsage(FlagSet<KeyUsages>),
    /// The role's extensions, its `keyUsage` given twice.
    RepeatedKeyUsage,
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
        _spk: SubjectPublicKeyInfoRef<'_>,
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
            (_, Role::Tsa) => KeyUsages::DigitalSignature.into(),
        };
        let key_usage = KeyUsage(usage)
            .to_extension(tbs.subject(), std::slice::from_ref(&basic_constraints))?;
        let mut extensions = vec![basic_constraints, key_usage.clone()];
        if self.extensions == Extensions::RepeatedKeyUsage {
            extensions.push(key_usage);
        }
        if self.role == Role::Tsa {
            extensions.push(Extension {
                extn_id: EXTENDED_KEY_USAGE,
                critical: true,
                extn_value: OctetString::new(ExtendedKeyUsage(vec![TIME_STAMPING]).to_der()?)?,
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

/// `pdf` given one revision whose catalog points at a `/DSS` listing `certificates` under
/// `/Certs` and `crls` under `/CRLs`, each as an unfiltered stream.
pub fn with_dss(pdf: &[u8], certificates: &[Vec<u8>], crls: &[Vec<u8>]) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let mut update = doc.update();
    let mut dss = Dictionary::new();
    for (key, items) in [(&b"Certs"[..], certificates), (&b"CRLs"[..], crls)] {
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
