//! Writes the attack corpus of `tests/corpus/attacks/`: each file is a correctly signed
//! detached `SignedData` over `tests/corpus/openssl/content.bin`, apart from one defect.
//!
//! `cargo run -p nacre-cms --example forge_attacks -- crates/nacre-cms/tests/corpus/attacks`
//!
//! The output is deterministic: a fixed test key, RFC 6979 ECDSA, fixed validity dates.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Any, DateTime, Encode};
use nacre_cms::{
    Attribute, Profile, SignedAttributes, SignedData, SignerIdentifier, SignerInfo, oid,
    sign_detached,
};
use nacre_core::{Signer, TestSigner};
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::builder::profile::cabf;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const SECRET: [u8; 32] = [0x11; 32];
const CONTENT: &[u8] = include_bytes!("../tests/corpus/openssl/content.bin");
const TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

fn main() {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("usage: forge_attacks <dir>"),
    );
    std::fs::create_dir_all(&dir).unwrap();

    let signer = TestSigner::from_secret(&SECRET).unwrap();
    let digest = Sha256::digest(CONTENT);
    let base =
        SignedData::from_der(&sign_detached(&digest, &signer, &Profile::PADES, None).unwrap())
            .unwrap();
    let attributes = base.signer_infos[0]
        .signed_attrs
        .as_ref()
        .unwrap()
        .attributes()
        .unwrap();

    let mut signed = base.clone();
    signed.signer_infos[0].signature_algorithm = AlgorithmIdentifierOwned {
        oid: oid::SHA256_WITH_RSA_ENCRYPTION,
        parameters: Some(Any::null()),
    };
    write(&dir, "alg-confusion", &signed);

    let mut signed = base.clone();
    let info = &mut signed.signer_infos[0];
    info.signed_attrs = None;
    info.signature = signer.sign_digest(&digest).unwrap();
    write(&dir, "signed-attrs-absent", &signed);

    let mut signed = base.clone();
    let without_digest = attributes
        .iter()
        .filter(|a| a.oid != oid::MESSAGE_DIGEST)
        .cloned()
        .collect();
    resign(&mut signed.signer_infos[0], without_digest, &signer);
    write(&dir, "message-digest-absent", &signed);

    let mut signed = base.clone();
    let mut duplicated = attributes.clone();
    duplicated.extend(
        attributes
            .iter()
            .filter(|a| a.oid == oid::MESSAGE_DIGEST)
            .cloned(),
    );
    resign(&mut signed.signer_infos[0], duplicated, &signer);
    write(&dir, "signed-attrs-duplicate", &signed);

    let mut signed = base.clone();
    let other_digest = Sha256::digest(b"another content");
    let wrong_digest = attributes
        .iter()
        .map(|a| {
            if a.oid == oid::MESSAGE_DIGEST {
                Attribute::new(
                    oid::MESSAGE_DIGEST,
                    &OctetString::new(other_digest.as_slice()).unwrap(),
                )
                .unwrap()
            } else {
                a.clone()
            }
        })
        .collect();
    resign(&mut signed.signer_infos[0], wrong_digest, &signer);
    write(&dir, "message-digest-mismatch", &signed);

    let mut signed = base.clone();
    if let SignerIdentifier::IssuerAndSerialNumber { serial_number, .. } =
        &mut signed.signer_infos[0].sid
    {
        *serial_number = SerialNumber::from(2u32);
    }
    write(&dir, "sid-unknown", &signed);

    // The substitute shares the key, issuer and serial of the signer certificate, so the
    // sid designates it first and the signature verifies with its key; only the
    // signingCertificateV2 hash, naming the original, tells them apart.
    let mut signed = base.clone();
    signed.certificates = vec![
        substitute_certificate(),
        signer.certificate_chain()[0].clone(),
    ];
    write(&dir, "cert-substitution", &signed);

    let mut signed = base;
    signed.encap_content_info.econtent_type = TST_INFO;
    write(&dir, "content-type-mismatch", &signed);
}

fn resign(info: &mut SignerInfo, attributes: Vec<Attribute>, signer: &TestSigner) {
    let signed_attrs = SignedAttributes::from_attributes(attributes).unwrap();
    info.signature = signer
        .sign_digest(&Sha256::digest(signed_attrs.to_be_signed().unwrap()))
        .unwrap();
    info.signed_attrs = Some(signed_attrs);
}

fn substitute_certificate() -> Vec<u8> {
    let key = SigningKey::from_slice(&SECRET).unwrap();
    let subject = Name::from_str("CN=Nacre test signer,O=Nacre tests,C=FR").unwrap();
    let profile = cabf::Root::new(false, subject).unwrap();
    let validity = Validity::new(time(2027), time(2037));
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
    CertificateBuilder::new(profile, SerialNumber::from(1u32), validity, spki)
        .unwrap()
        .build::<_, DerSignature>(&key)
        .unwrap()
        .to_der()
        .unwrap()
}

fn time(year: u16) -> Time {
    Time::from(DateTime::new(year, 1, 1, 0, 0, 0).unwrap())
}

fn write(dir: &Path, name: &str, signed: &SignedData) {
    std::fs::write(dir.join(format!("{name}.der")), signed.to_der().unwrap()).unwrap();
}
