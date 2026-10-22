#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::SystemTime;

use der::{DateTime, Decode};
use nacre_revocation::{Crl, CrlReason, Error, RevokedEntry};
use x509_cert::Certificate;

const EC_CA: &[u8] = include_bytes!("corpus/openssl/ec-ca.der");
const EC_CRL: &[u8] = include_bytes!("corpus/openssl/ec-ca.crl");
const REVOKED: &[u8] = include_bytes!("corpus/openssl/revoked.der");
const RSA_CA: &[u8] = include_bytes!("corpus/openssl/rsa-ca.der");
const RSA_CRL: &[u8] = include_bytes!("corpus/openssl/rsa-ca.crl");

fn date(year: u16, month: u8, day: u8) -> SystemTime {
    DateTime::new(year, month, day, 0, 0, 0)
        .unwrap()
        .to_system_time()
}

#[test]
fn openssl_crl_fields_are_read() {
    let crl = Crl::from_der(EC_CRL).unwrap();
    let ca = Certificate::from_der(EC_CA).unwrap();
    let revoked = Certificate::from_der(REVOKED).unwrap();

    assert_eq!(crl.issuer(), ca.tbs_certificate().subject());
    assert_eq!(crl.this_update(), date(2026, 10, 1));
    assert_eq!(crl.next_update(), Some(date(2036, 10, 1)));
    assert_eq!(
        crl.revoked().unwrap(),
        vec![RevokedEntry {
            serial: revoked
                .tbs_certificate()
                .serial_number()
                .as_bytes()
                .to_vec(),
            date: date(2026, 6, 1),
            reason: Some(CrlReason::KeyCompromise),
        }]
    );
}

#[test]
fn openssl_crls_verify_and_one_changed_byte_fails() {
    Crl::from_der(EC_CRL)
        .unwrap()
        .verify_signature(EC_CA)
        .unwrap();
    Crl::from_der(RSA_CRL)
        .unwrap()
        .verify_signature(RSA_CA)
        .unwrap();

    // thisUpdate, 2026-10-01 00:00:00, moved by one minute: still a valid time.
    let this_update = b"261001000000Z";
    let at = EC_CRL
        .windows(this_update.len())
        .position(|window| window == this_update)
        .unwrap();
    let mut changed = EC_CRL.to_vec();
    changed[at + 9] = b'1';
    let crl = Crl::from_der(&changed).unwrap();
    assert_ne!(crl.this_update(), date(2026, 10, 1));
    assert!(matches!(
        crl.verify_signature(EC_CA),
        Err(Error::SignatureInvalid)
    ));
}
