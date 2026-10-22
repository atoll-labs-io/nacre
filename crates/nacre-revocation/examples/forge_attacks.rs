//! Writes the attack corpus of `tests/corpus/attacks/`: each CRL lists the leaf `leaf.der`
//! and is correctly signed apart from one defect, next to the certificates the cases need.
//!
//! `cargo run -p nacre-revocation --example forge_crl_attacks -- crates/nacre-revocation/tests/corpus/attacks`
//!
//! The output is deterministic: fixed test keys, RFC 6979 ECDSA, fixed dates.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use der::asn1::{BitString, OctetString};
use der::oid::ObjectIdentifier;
use der::{Any, DateTime, Encode};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, SigningKey};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;
use x509_cert::builder::profile::{BuilderProfile, cabf};
use x509_cert::builder::{Builder, CertificateBuilder, CrlBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::ext::pkix::crl::dp::IssuingDistributionPoint;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, CrlNumber, CrlReason, KeyUsage, KeyUsages};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const CA_SECRET: [u8; 32] = [0x21; 32];
const OTHER_CA_SECRET: [u8; 32] = [0x22; 32];
const LEAF_SECRET: [u8; 32] = [0x23; 32];
const CA: &str = "CN=Nacre attack CA,O=Nacre tests,C=FR";
const OTHER_CA: &str = "CN=Nacre other attack CA,O=Nacre tests,C=FR";
const RENAMED_CA: &str = "CN=Nacre renamed attack CA,O=Nacre tests,C=FR";
const LEAF: &str = "CN=Nacre attack leaf,O=Nacre tests,C=FR";
const ID_CE_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.28");
const ID_CE_CERTIFICATE_ISSUER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.29");
const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

fn main() {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("usage: forge_crl_attacks <dir>"),
    );
    std::fs::create_dir_all(&dir).unwrap();

    let ca_key = SigningKey::from_slice(&CA_SECRET).unwrap();
    let other_key = SigningKey::from_slice(&OTHER_CA_SECRET).unwrap();
    let leaf_key = SigningKey::from_slice(&LEAF_SECRET).unwrap();

    let ca = root(CA, &ca_key);
    let other_ca = root(OTHER_CA, &other_key);
    let leaf = certificate(
        Small {
            subject: name(LEAF),
            issuer: Some(name(CA)),
            ca: false,
            key_usage: KeyUsages::DigitalSignature.into(),
        },
        0x1001,
        &leaf_key,
        &ca_key,
    );
    // The CA's name and key, with a keyUsage that does not allow CRL signing.
    let non_crl_signer = certificate(
        Small {
            subject: name(CA),
            issuer: None,
            ca: true,
            key_usage: KeyUsages::DigitalSignature.into(),
        },
        2,
        &ca_key,
        &ca_key,
    );
    // The CA's key under another subject: a CRL of the CA verifies with it.
    let renamed_ca = certificate(
        Small {
            subject: name(RENAMED_CA),
            issuer: None,
            ca: true,
            key_usage: KeyUsages::KeyCertSign | KeyUsages::CRLSign,
        },
        3,
        &ca_key,
        &ca_key,
    );
    write(&dir, "ca", &ca);
    write(&dir, "other-ca", &other_ca);
    write(&dir, "leaf", &leaf);
    write(&dir, "non-crl-signer-ca", &non_crl_signer);
    write(&dir, "renamed-ca", &renamed_ca);

    let serial = leaf.tbs_certificate().serial_number().clone();
    let entry = |extensions: Vec<Extension>| RevokedCert {
        serial_number: serial.clone(),
        revocation_date: time(2026, 4, 1),
        crl_entry_extensions: Some(extensions),
    };
    let reason = || {
        CrlReason::KeyCompromise
            .to_extension(&name(CA), &[])
            .unwrap()
    };
    let crl = |issuer: &Certificate, key: &SigningKey, next: Option<Time>, entry: RevokedCert| {
        CrlBuilder::new_with_this_update(
            issuer,
            CrlNumber::try_from(1u32).unwrap(),
            time(2026, 5, 1),
        )
        .unwrap()
        .with_next_update(next)
        .with_certificates([entry].into_iter())
        .build::<_, DerSignature>(key)
        .unwrap()
    };
    let fresh = Some(time(2036, 5, 1));

    write(
        &dir,
        "wrong-issuer",
        &crl(&other_ca, &other_key, fresh, entry(vec![reason()])),
    );

    write(
        &dir,
        "issuer-renamed",
        &crl(&ca, &ca_key, fresh, entry(vec![reason()])),
    );

    let valid = crl(&ca, &ca_key, fresh, entry(vec![reason()]))
        .to_der()
        .unwrap();
    // The revocation date, moved by one minute after signing: still a valid time.
    let at = valid
        .windows(13)
        .position(|window| window == b"260401000000Z")
        .unwrap();
    let mut changed = valid;
    changed[at + 9] = b'1';
    std::fs::write(dir.join("bad-signature.der"), changed).unwrap();

    write(
        &dir,
        "stale",
        &crl(&ca, &ca_key, Some(time(2026, 6, 1)), entry(vec![reason()])),
    );
    write(
        &dir,
        "no-next-update",
        &crl(&ca, &ca_key, None, entry(vec![reason()])),
    );

    let mut list = crl(&ca, &ca_key, fresh, entry(vec![reason()]));
    let idp = IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: true,
        only_contains_ca_certs: false,
        only_some_reasons: None,
        indirect_crl: false,
        only_contains_attribute_certs: false,
    };
    list.tbs_cert_list
        .crl_extensions
        .get_or_insert_with(Vec::new)
        .push(Extension {
            extn_id: ID_CE_ISSUING_DISTRIBUTION_POINT,
            critical: true,
            extn_value: OctetString::new(idp.to_der().unwrap()).unwrap(),
        });
    resign(&mut list, &ca_key);
    write(&dir, "critical-extension", &list);

    let mut list = crl(&ca, &ca_key, fresh, entry(vec![reason()]));
    list.signature_algorithm = AlgorithmIdentifierOwned {
        oid: SHA256_WITH_RSA_ENCRYPTION,
        parameters: Some(Any::null()),
    };
    write(&dir, "algorithm-substitution", &list);

    write(
        &dir,
        "issuer-not-crl-signer",
        &crl(&non_crl_signer, &ca_key, fresh, entry(vec![reason()])),
    );

    let certificate_issuer = vec![GeneralName::DirectoryName(name(CA))];
    let critical_issuer = Extension {
        extn_id: ID_CE_CERTIFICATE_ISSUER,
        critical: true,
        extn_value: OctetString::new(certificate_issuer.to_der().unwrap()).unwrap(),
    };
    write(
        &dir,
        "critical-entry-extension",
        &crl(&ca, &ca_key, fresh, entry(vec![reason(), critical_issuer])),
    );
}

/// A certificate profile reduced to what the corpus needs: a subject, an issuer (the
/// subject when `None`), `basicConstraints` and a critical `keyUsage`.
struct Small {
    subject: Name,
    issuer: Option<Name>,
    ca: bool,
    key_usage: der::flagset::FlagSet<KeyUsages>,
}

impl BuilderProfile for Small {
    fn get_issuer(&self, subject: &Name) -> Name {
        self.issuer.clone().unwrap_or_else(|| subject.clone())
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
            ca: self.ca,
            path_len_constraint: None,
        }
        .to_extension(tbs.subject(), &[])?;
        let key_usage = KeyUsage(self.key_usage)
            .to_extension(tbs.subject(), std::slice::from_ref(&basic_constraints))?;
        Ok(vec![basic_constraints, key_usage])
    }
}

fn root(subject: &str, key: &SigningKey) -> Certificate {
    let profile = cabf::Root::new(false, name(subject)).unwrap();
    CertificateBuilder::new(profile, SerialNumber::from(1u32), validity(), spki(key))
        .unwrap()
        .build::<_, DerSignature>(key)
        .unwrap()
}

fn certificate(profile: Small, serial: u32, key: &SigningKey, signer: &SigningKey) -> Certificate {
    CertificateBuilder::new(profile, SerialNumber::from(serial), validity(), spki(key))
        .unwrap()
        .build::<_, DerSignature>(signer)
        .unwrap()
}

fn resign(list: &mut CertificateList, key: &SigningKey) {
    let signature: DerSignature = key.sign(&list.tbs_cert_list.to_der().unwrap());
    list.signature = BitString::from_bytes(signature.as_bytes()).unwrap();
}

fn spki(key: &SigningKey) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap()
}

fn name(dn: &str) -> Name {
    Name::from_str(dn).unwrap()
}

fn validity() -> Validity {
    Validity::new(time(2026, 1, 1), time(2036, 1, 1))
}

fn time(year: u16, month: u8, day: u8) -> Time {
    Time::from(DateTime::new(year, month, day, 0, 0, 0).unwrap())
}

fn write(dir: &Path, stem: &str, value: &impl Encode) {
    std::fs::write(dir.join(format!("{stem}.der")), value.to_der().unwrap()).unwrap();
}
