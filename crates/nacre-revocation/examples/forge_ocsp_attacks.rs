//! Writes the attack corpus of `tests/corpus/ocsp-attacks/`: each OCSP response says the leaf
//! `leaf.der` is revoked and is correctly signed apart from one defect, next to the
//! certificates the cases need.
//!
//! `cargo run -p nacre-revocation --example forge_ocsp_attacks -- crates/nacre-revocation/tests/corpus/ocsp-attacks`
//!
//! The output is deterministic: fixed test keys, RFC 6979 ECDSA, fixed dates and nonce.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// The crate's own declarations, which its public API does not expose (ADR-0018).
#[allow(dead_code)]
#[path = "../src/ocsp/asn1.rs"]
mod asn1;

use std::path::{Path, PathBuf};
use std::str::FromStr;

use asn1::{
    BasicOcspResponse, CertId, CertStatus, ID_PKIX_OCSP_BASIC, ID_PKIX_OCSP_NONCE, ID_SHA1,
    OcspResponse, OcspResponseStatus, ResponderId, ResponseBytes, ResponseData, RevokedInfo,
    SingleResponse,
};
use der::asn1::{BitString, GeneralizedTime, Null, OctetString};
use der::oid::ObjectIdentifier;
use der::{Any, DateTime, Encode};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use sha1::{Digest, Sha1};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;
use x509_cert::builder::profile::{BuilderProfile, cabf};
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::{TbsCertificate, Version};
use x509_cert::ext::pkix::{BasicConstraints, CrlReason, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const CA_SECRET: [u8; 32] = [0x41; 32];
const IMPOSTOR_SECRET: [u8; 32] = [0x42; 32];
const LEAF_SECRET: [u8; 32] = [0x43; 32];
const DELEGATE_SECRET: [u8; 32] = [0x44; 32];
const CA: &str = "CN=Nacre OCSP attack CA,O=Nacre tests,C=FR";
const LEAF: &str = "CN=Nacre OCSP attack leaf,O=Nacre tests,C=FR";
const FOREIGN_DELEGATE: &str = "CN=Nacre OCSP foreign delegate,O=Nacre tests,C=FR";
const PLAIN_DELEGATE: &str = "CN=Nacre OCSP delegate without OCSPSigning,O=Nacre tests,C=FR";
const EXPIRED_DELEGATE: &str = "CN=Nacre OCSP expired delegate,O=Nacre tests,C=FR";
/// The nonce `N` every response carries.
const NONCE: [u8; 32] = [0x4e; 32];
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
const ID_KP_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const ID_PKIX_OCSP_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.3");

fn main() {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("usage: forge_ocsp_attacks <dir>"),
    );
    std::fs::create_dir_all(&dir).unwrap();

    let ca_key = SigningKey::from_slice(&CA_SECRET).unwrap();
    let impostor_key = SigningKey::from_slice(&IMPOSTOR_SECRET).unwrap();
    let leaf_key = SigningKey::from_slice(&LEAF_SECRET).unwrap();
    let delegate_key = SigningKey::from_slice(&DELEGATE_SECRET).unwrap();

    let profile = cabf::Root::new(false, name(CA)).unwrap();
    let ca = CertificateBuilder::new(profile, SerialNumber::from(1u32), validity(), spki(&ca_key))
        .unwrap()
        .build::<_, DerSignature>(&ca_key)
        .unwrap();
    let leaf = certificate(Small::leaf(LEAF), 0x1001, &leaf_key, &ca_key);
    // Issued under the CA's name, but signed by another key: only the signature tells.
    let foreign_delegate = certificate(
        Small::delegate(FOREIGN_DELEGATE, ID_KP_OCSP_SIGNING),
        0x2001,
        &delegate_key,
        &impostor_key,
    );
    let plain_delegate = certificate(
        Small::delegate(PLAIN_DELEGATE, ID_KP_CLIENT_AUTH),
        0x2002,
        &delegate_key,
        &ca_key,
    );
    // Issued and signed by the CA with OCSPSigning, but expired before `producedAt`.
    let expired_delegate = certificate_valid(
        Small::delegate(EXPIRED_DELEGATE, ID_KP_OCSP_SIGNING),
        0x2003,
        &delegate_key,
        &ca_key,
        years(2025, 2026),
    );
    write(&dir, "ca", &ca);
    write(&dir, "leaf", &leaf);
    write(&dir, "foreign-delegate", &foreign_delegate);
    write(&dir, "plain-delegate", &plain_delegate);
    write(&dir, "expired-delegate", &expired_delegate);

    let leaf_id = cert_id(&ca, leaf.tbs_certificate().serial_number().clone());
    let revoked = || {
        CertStatus::Revoked(RevokedInfo {
            revocation_time: generalized(2026, 4, 1),
            revocation_reason: Some(CrlReason::KeyCompromise),
        })
    };
    let single = |cert_id: CertId, status: CertStatus, next: GeneralizedTime| SingleResponse {
        cert_id,
        cert_status: status,
        this_update: generalized(2026, 10, 1),
        next_update: Some(next),
        single_extensions: None,
    };
    let fresh = generalized(2036, 10, 1);
    let by_ca = |single: SingleResponse| response(by_name(CA), single, &ca_key, None);

    let base = by_ca(single(leaf_id.clone(), revoked(), fresh));
    std::fs::write(dir.join("base.der"), &base).unwrap();

    // The revocation time, moved by one minute after signing: still a valid time.
    let at = base
        .windows(15)
        .position(|window| window == b"20260401000000Z")
        .unwrap();
    let mut changed = base;
    changed[at + 11] = b'1';
    std::fs::write(dir.join("bad-signature.der"), changed).unwrap();

    let delegated = |delegate: &Certificate, subject: &str| {
        response(
            by_name(subject),
            single(leaf_id.clone(), revoked(), fresh),
            &delegate_key,
            Some(delegate),
        )
    };
    std::fs::write(
        dir.join("foreign-delegate-response.der"),
        delegated(&foreign_delegate, FOREIGN_DELEGATE),
    )
    .unwrap();
    std::fs::write(
        dir.join("plain-delegate-response.der"),
        delegated(&plain_delegate, PLAIN_DELEGATE),
    )
    .unwrap();
    std::fs::write(
        dir.join("expired-delegate-response.der"),
        delegated(&expired_delegate, EXPIRED_DELEGATE),
    )
    .unwrap();

    std::fs::write(
        dir.join("stale.der"),
        by_ca(single(leaf_id.clone(), revoked(), generalized(2026, 6, 1))),
    )
    .unwrap();

    let mut critical = single(leaf_id.clone(), revoked(), fresh);
    critical.single_extensions = Some(vec![Extension {
        extn_id: ID_PKIX_OCSP_CRL,
        critical: true,
        extn_value: OctetString::new(vec![0x30, 0x00]).unwrap(),
    }]);
    std::fs::write(dir.join("critical-single-extension.der"), by_ca(critical)).unwrap();

    std::fs::write(
        dir.join("other-serial.der"),
        by_ca(single(
            cert_id(&ca, SerialNumber::from(0x9999u32)),
            revoked(),
            fresh,
        )),
    )
    .unwrap();

    std::fs::write(
        dir.join("unknown.der"),
        by_ca(single(leaf_id, CertStatus::Unknown(Null), fresh)),
    )
    .unwrap();

    let try_later = OcspResponse {
        response_status: OcspResponseStatus::TryLater,
        response_bytes: None,
    };
    write(&dir, "try-later", &try_later);
}

/// A signed `OCSPResponse` holding one single response and the nonce `N`.
fn response(
    responder_id: ResponderId,
    single: SingleResponse,
    key: &SigningKey,
    certificate: Option<&Certificate>,
) -> Vec<u8> {
    let nonce = Extension {
        extn_id: ID_PKIX_OCSP_NONCE,
        critical: false,
        extn_value: OctetString::new(
            OctetString::new(NONCE.as_slice())
                .unwrap()
                .to_der()
                .unwrap(),
        )
        .unwrap(),
    };
    let data = ResponseData {
        version: Version::V1,
        responder_id,
        produced_at: generalized(2026, 10, 1),
        responses: vec![single],
        response_extensions: Some(vec![nonce]),
    };
    let signature: DerSignature = key.sign(&data.to_der().unwrap());
    let basic = BasicOcspResponse {
        tbs_response_data: data,
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        },
        signature: BitString::from_bytes(signature.as_bytes()).unwrap(),
        certs: certificate.map(|certificate| vec![Any::encode_from(certificate).unwrap()]),
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

fn cert_id(issuer: &Certificate, serial_number: SerialNumber) -> CertId {
    let tbs = issuer.tbs_certificate();
    let name = tbs.subject().to_der().unwrap();
    let key = tbs.subject_public_key_info().subject_public_key.raw_bytes();
    CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA1,
            parameters: Some(Any::null()),
        },
        issuer_name_hash: OctetString::new(Sha1::digest(&name).to_vec()).unwrap(),
        issuer_key_hash: OctetString::new(Sha1::digest(key).to_vec()).unwrap(),
        serial_number,
    }
}

fn by_name(subject: &str) -> ResponderId {
    ResponderId::ByName(name(subject))
}

/// A certificate profile reduced to what the corpus needs: issued under the CA's name,
/// `basicConstraints` CA false, a critical `keyUsage` and an optional `extendedKeyUsage`.
struct Small {
    subject: Name,
    extended_key_usage: Option<ObjectIdentifier>,
}

impl Small {
    fn leaf(subject: &str) -> Self {
        Self {
            subject: name(subject),
            extended_key_usage: None,
        }
    }

    fn delegate(subject: &str, purpose: ObjectIdentifier) -> Self {
        Self {
            subject: name(subject),
            extended_key_usage: Some(purpose),
        }
    }
}

impl BuilderProfile for Small {
    fn get_issuer(&self, _subject: &Name) -> Name {
        name(CA)
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
        let basic_constraints = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_extension(tbs.subject(), &[])?;
        let key_usage = KeyUsage(KeyUsages::DigitalSignature.into())
            .to_extension(tbs.subject(), std::slice::from_ref(&basic_constraints))?;
        let mut extensions = vec![basic_constraints, key_usage];
        if let Some(purpose) = self.extended_key_usage {
            let usage = ExtendedKeyUsage(vec![purpose]).to_extension(tbs.subject(), &extensions)?;
            extensions.push(usage);
        }
        Ok(extensions)
    }
}

fn certificate(profile: Small, serial: u32, key: &SigningKey, signer: &SigningKey) -> Certificate {
    certificate_valid(profile, serial, key, signer, validity())
}

fn certificate_valid(
    profile: Small,
    serial: u32,
    key: &SigningKey,
    signer: &SigningKey,
    validity: Validity,
) -> Certificate {
    CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki(key))
        .unwrap()
        .build::<_, DerSignature>(signer)
        .unwrap()
}

fn spki(key: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap()
}

fn name(dn: &str) -> Name {
    Name::from_str(dn).unwrap()
}

fn validity() -> Validity {
    years(2026, 2036)
}

/// From January 1st of `from` to January 1st of `to`.
fn years(from: u16, to: u16) -> Validity {
    let time = |year| Time::from(DateTime::new(year, 1, 1, 0, 0, 0).unwrap());
    Validity::new(time(from), time(to))
}

fn generalized(year: u16, month: u8, day: u8) -> GeneralizedTime {
    GeneralizedTime::from_date_time(DateTime::new(year, month, day, 0, 0, 0).unwrap())
}

fn write(dir: &Path, stem: &str, value: &impl Encode) {
    std::fs::write(dir.join(format!("{stem}.der")), value.to_der().unwrap()).unwrap();
}
