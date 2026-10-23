#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! One test per OCSP attack of `docs/security/attacks/revocation.md`. Every response says
//! the leaf is revoked and is correctly signed apart from its one defect: a skipped rule
//! answers "revoked".

use std::time::Duration;

use der::DateTime;
use der::oid::ObjectIdentifier;
use nacre_revocation::{Error, OcspRequest, OcspResponse, OcspStatus};

const CA: &[u8] = include_bytes!("corpus/ocsp-attacks/ca.der");
const LEAF: &[u8] = include_bytes!("corpus/ocsp-attacks/leaf.der");
const BASE: &[u8] = include_bytes!("corpus/ocsp-attacks/base.der");
/// The nonce every response of the corpus carries.
const NONCE: [u8; 32] = [0x4e; 32];

fn status(response: &[u8]) -> Result<OcspStatus, Error> {
    let at = DateTime::new(2027, 1, 1, 0, 0, 0).unwrap().to_system_time();
    OcspResponse::from_der(response)
        .unwrap()
        .status(LEAF, CA, at)
}

#[test]
fn delegate_issued_by_another_key_is_unauthorized() {
    let response = include_bytes!("corpus/ocsp-attacks/foreign-delegate-response.der");
    assert!(matches!(
        status(response),
        Err(Error::UnauthorizedResponder)
    ));
}

#[test]
fn delegate_without_ocsp_signing_is_unauthorized() {
    let response = include_bytes!("corpus/ocsp-attacks/plain-delegate-response.der");
    assert!(matches!(
        status(response),
        Err(Error::UnauthorizedResponder)
    ));
}

#[test]
fn delegate_expired_at_produced_at_is_unauthorized() {
    let response = include_bytes!("corpus/ocsp-attacks/expired-delegate-response.der");
    assert!(matches!(
        status(response),
        Err(Error::UnauthorizedResponder)
    ));
}

#[test]
fn response_to_another_nonce_is_rejected() {
    let response = OcspResponse::from_der(BASE).unwrap();
    assert_eq!(response.nonce(), Some(NONCE.as_slice()));
    let request = OcspRequest::new(LEAF, CA, &[0x6e; 32]).unwrap();
    assert!(matches!(
        response.check_nonce(&request),
        Err(Error::NonceMismatch)
    ));
}

#[test]
fn this_update_out_of_tolerance_is_rejected() {
    let response = OcspResponse::from_der(BASE).unwrap();
    let this_update = response.this_update().unwrap();
    let at = this_update + Duration::from_secs(24 * 3600);
    assert!(matches!(
        response.check_this_update(LEAF, CA, at, Duration::from_secs(300)),
        Err(Error::ThisUpdateOutOfTolerance { this_update: date }) if date == this_update
    ));
}

#[test]
fn changed_byte_after_signing_is_rejected() {
    let response = include_bytes!("corpus/ocsp-attacks/bad-signature.der");
    assert!(matches!(status(response), Err(Error::SignatureInvalid)));
}

#[test]
fn stale_response_is_rejected() {
    let response = include_bytes!("corpus/ocsp-attacks/stale.der");
    let next_update = DateTime::new(2026, 6, 1, 0, 0, 0).unwrap().to_system_time();
    assert!(matches!(
        status(response),
        Err(Error::Expired { next_update: date }) if date == next_update
    ));
}

#[test]
fn critical_single_extension_is_rejected() {
    let response = include_bytes!("corpus/ocsp-attacks/critical-single-extension.der");
    assert!(matches!(
        status(response),
        Err(Error::UnsupportedCriticalExtension(oid))
            if oid == ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.3")
    ));
}

#[test]
fn response_about_another_serial_is_rejected() {
    let response = include_bytes!("corpus/ocsp-attacks/other-serial.der");
    assert!(matches!(
        status(response),
        Err(Error::CertificateNotInResponse)
    ));
}

#[test]
fn unknown_status_is_rejected() {
    let response = include_bytes!("corpus/ocsp-attacks/unknown.der");
    assert!(matches!(status(response), Err(Error::UnknownCertificate)));
}

#[test]
fn unsuccessful_response_status_is_rejected() {
    let response = include_bytes!("corpus/ocsp-attacks/try-later.der");
    assert!(matches!(
        OcspResponse::from_der(response),
        Err(Error::ResponseStatus(3))
    ));
}
