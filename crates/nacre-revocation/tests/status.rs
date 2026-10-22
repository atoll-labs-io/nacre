#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::time::SystemTime;

use der::DateTime;
use nacre_revocation::{Crl, CrlReason, CrlStatus};

const CA: &[u8] = include_bytes!("corpus/openssl/ec-ca.der");
const CRL: &[u8] = include_bytes!("corpus/openssl/ec-ca.crl");
const LEAF: &[u8] = include_bytes!("corpus/openssl/leaf.der");
const REVOKED: &[u8] = include_bytes!("corpus/openssl/revoked.der");

fn date(year: u16, month: u8, day: u8) -> SystemTime {
    DateTime::new(year, month, day, 0, 0, 0)
        .unwrap()
        .to_system_time()
}

#[test]
fn listed_leaf_is_revoked_with_date_and_reason() {
    let crl = Crl::from_der(CRL).unwrap();
    assert_eq!(
        crl.status(REVOKED, CA, date(2027, 1, 1)).unwrap(),
        CrlStatus::Revoked {
            date: date(2026, 6, 1),
            reason: Some(CrlReason::KeyCompromise),
        }
    );
}

#[test]
fn unlisted_leaf_is_not_revoked() {
    let crl = Crl::from_der(CRL).unwrap();
    assert_eq!(
        crl.status(LEAF, CA, date(2027, 1, 1)).unwrap(),
        CrlStatus::NotRevoked
    );
}

#[test]
fn crl_issued_after_the_control_date_is_accepted() {
    let crl = Crl::from_der(CRL).unwrap();
    let at = date(2026, 9, 1);
    assert!(at < crl.this_update());
    assert_eq!(crl.status(LEAF, CA, at).unwrap(), CrlStatus::NotRevoked);
}
