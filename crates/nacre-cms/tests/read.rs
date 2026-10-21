#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::Encode;
use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use nacre_cms::{Attribute, Error, Profile, SignedData, oid, sign_detached};
use nacre_core::TestSigner;
use sha2::{Digest, Sha256};

const CONTENT: &[u8] = include_bytes!("corpus/openssl/content.bin");
const EC_DETACHED: &[u8] = include_bytes!("corpus/openssl/ec-detached.der");
const RSA_DETACHED: &[u8] = include_bytes!("corpus/openssl/rsa-detached.der");
const EC_ATTACHED: &[u8] = include_bytes!("corpus/openssl/ec-attached.der");

#[test]
fn round_trip_is_byte_identical() {
    for fixture in [EC_DETACHED, RSA_DETACHED, EC_ATTACHED] {
        let signed = SignedData::from_der(fixture).unwrap();
        assert_eq!(signed.to_der().unwrap(), fixture);
    }
}

#[test]
fn openssl_ecdsa_detached_verifies() {
    let signed = SignedData::from_der(EC_DETACHED).unwrap();
    let signer = signed.verify(Some(CONTENT)).unwrap();
    assert_eq!(signer.certificate(), signed.certificates[0].as_slice());
}

#[test]
fn openssl_rsa_detached_verifies() {
    let signed = SignedData::from_der(RSA_DETACHED).unwrap();
    assert_eq!(
        signed.signer_infos[0].signature_algorithm.oid,
        oid::RSA_ENCRYPTION
    );
    let signer = signed.verify(Some(CONTENT)).unwrap();
    assert_eq!(signer.certificate(), signed.certificates[0].as_slice());
}

#[test]
fn openssl_attached_verifies_and_exposes_content() {
    let signed = SignedData::from_der(EC_ATTACHED).unwrap();
    assert_eq!(signed.econtent(), Some(CONTENT));
    signed.verify(None).unwrap();
}

#[test]
fn changed_content_byte_fails() {
    let signed = SignedData::from_der(EC_DETACHED).unwrap();
    let mut content = CONTENT.to_vec();
    content[0] ^= 0x01;
    let err = signed.verify(Some(&content)).unwrap_err();
    assert!(matches!(err, Error::MessageDigestMismatch), "{err:?}");
}

#[test]
fn changed_signed_attribute_byte_fails() {
    // signingTime: the attribute's OID, then SET { UTCTime "YYMMDDhhmmssZ" }.
    let time_oid = oid::SIGNING_TIME.to_der().unwrap();
    let at = EC_DETACHED
        .windows(time_oid.len())
        .position(|w| w == time_oid)
        .unwrap();
    let year_digit = at + time_oid.len() + 2 + 2 + 1;
    let mut tampered = EC_DETACHED.to_vec();
    assert!(tampered[year_digit].is_ascii_digit());
    tampered[year_digit] = if tampered[year_digit] == b'9' {
        b'8'
    } else {
        tampered[year_digit] + 1
    };

    let signed = SignedData::from_der(&tampered).unwrap();
    let err = signed.verify(Some(CONTENT)).unwrap_err();
    assert!(matches!(err, Error::SignatureInvalid), "{err:?}");
}

#[test]
fn unsigned_attribute_added_without_resigning() {
    let signer = TestSigner::from_secret(&[0x11; 32]).unwrap();
    let der = sign_detached(&Sha256::digest(CONTENT), &signer, &Profile::PADES, None).unwrap();
    let mut signed = SignedData::from_der(&der).unwrap();
    let before = signed.signer_infos[0].clone();

    let timestamp_token = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
    let token = OctetString::new(&b"a timestamp token"[..]).unwrap();
    signed.signer_infos[0]
        .push_unsigned_attribute(Attribute::new(timestamp_token, &token).unwrap());
    let reread = SignedData::from_der(&signed.to_der().unwrap()).unwrap();

    let after = &reread.signer_infos[0];
    assert_eq!(after.unsigned_attrs.len(), 1);
    assert_eq!(after.unsigned_attrs[0].oid, timestamp_token);
    assert_eq!(
        after.unsigned_attrs[0].values[0]
            .decode_as::<OctetString>()
            .unwrap(),
        token
    );
    assert_eq!(
        after.signed_attrs.as_ref().unwrap().to_be_signed().unwrap(),
        before
            .signed_attrs
            .as_ref()
            .unwrap()
            .to_be_signed()
            .unwrap()
    );
    assert_eq!(after.signature, before.signature);
    reread.verify(Some(CONTENT)).unwrap();
}
