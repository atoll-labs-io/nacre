#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;

use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::pem::LineEnding;
use der::{DateTime, Encode};
use nacre_cms::{Attribute, Error, Profile, SignedData, oid, sign_detached};
use nacre_core::{Signer, TestSigner};
use sha2::{Digest, Sha256};
use x509_cert::time::Time;

const CONTENT: &[u8] = include_bytes!("corpus/openssl/content.bin");

fn signer() -> TestSigner {
    TestSigner::from_secret(&[0x11; 32]).unwrap()
}

fn signing_time() -> Time {
    Time::from(DateTime::new(2026, 10, 22, 8, 0, 0).unwrap())
}

fn attribute(signed: &SignedData, wanted: ObjectIdentifier) -> Option<Attribute> {
    signed.signer_infos[0]
        .signed_attrs
        .as_ref()
        .unwrap()
        .attributes()
        .unwrap()
        .into_iter()
        .find(|a| a.oid == wanted)
}

#[test]
fn detached_signature_carries_required_attributes() {
    let signer = signer();
    let digest = Sha256::digest(CONTENT);
    let der = sign_detached(&digest, &signer, &Profile::PADES, None).unwrap();
    let signed = SignedData::from_der(&der).unwrap();

    assert_eq!(signed.econtent(), None);
    let content_type = attribute(&signed, oid::CONTENT_TYPE).unwrap();
    assert_eq!(
        content_type.values[0]
            .decode_as::<ObjectIdentifier>()
            .unwrap(),
        oid::DATA
    );
    let message_digest = attribute(&signed, oid::MESSAGE_DIGEST).unwrap();
    assert_eq!(
        message_digest.values[0]
            .decode_as::<OctetString>()
            .unwrap()
            .as_bytes(),
        digest.as_slice()
    );
    // SigningCertificateV2 ::= SEQUENCE { SEQUENCE OF ESSCertIDv2 { certHash } }: the hash
    // is the last 32 bytes of the value.
    let ess = attribute(&signed, oid::SIGNING_CERTIFICATE_V2).unwrap();
    let ess_der = ess.values[0].to_der().unwrap();
    let cert_hash = Sha256::digest(&signer.certificate_chain()[0]);
    assert!(
        ess_der.ends_with(
            &OctetString::new(cert_hash.as_slice())
                .unwrap()
                .to_der()
                .unwrap()
        )
    );
}

#[test]
fn openssl_accepts_nacre_signature() {
    let signer = signer();
    let der = sign_detached(
        &Sha256::digest(CONTENT),
        &signer,
        &Profile::CMS,
        Some(signing_time()),
    )
    .unwrap();

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("openssl_accepts_nacre_signature");
    std::fs::create_dir_all(&dir).unwrap();
    let pem = der::pem::encode_string(
        "CERTIFICATE",
        LineEnding::LF,
        &signer.certificate_chain()[0],
    )
    .unwrap();
    std::fs::write(dir.join("cert.pem"), pem).unwrap();
    std::fs::write(dir.join("content.bin"), CONTENT).unwrap();
    std::fs::write(dir.join("signature.der"), &der).unwrap();

    let output = Command::new("openssl")
        .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
        .arg(dir.join("signature.der"))
        .arg("-content")
        .arg(dir.join("content.bin"))
        .arg("-CAfile")
        .arg(dir.join("cert.pem"))
        .args(["-purpose", "any", "-cades", "-out"])
        .arg(dir.join("verified.bin"))
        .output()
        .expect("openssl must be on PATH: it is the CMS judge (ADR-0007)");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn pades_profile_refuses_signing_time() {
    let err = sign_detached(
        &Sha256::digest(CONTENT),
        &signer(),
        &Profile::PADES,
        Some(signing_time()),
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::ForbiddenAttribute(o) if o == oid::SIGNING_TIME),
        "{err:?}"
    );
}

#[test]
fn cms_profile_writes_signing_time() {
    let der = sign_detached(
        &Sha256::digest(CONTENT),
        &signer(),
        &Profile::CMS,
        Some(signing_time()),
    )
    .unwrap();
    let signed = SignedData::from_der(&der).unwrap();
    let time = attribute(&signed, oid::SIGNING_TIME).unwrap();
    assert_eq!(time.values[0].decode_as::<Time>().unwrap(), signing_time());
}

#[test]
fn wrong_digest_length_is_refused() {
    let err = sign_detached(&[0u8; 20], &signer(), &Profile::CMS, None).unwrap_err();
    assert!(
        matches!(
            err,
            Error::DigestLength {
                expected: 32,
                actual: 20
            }
        ),
        "{err:?}"
    );
}
