#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! OCSP responses written by `openssl ocsp`, signed by the CA (by name and by key hash) and
//! by a delegated responder. OpenSSL stamps `thisUpdate` with the generation time, so the
//! judgement date is read from each response.

use der::DateTime;
use nacre_revocation::{CrlReason, OcspResponse, OcspStatus};

const CA: &[u8] = include_bytes!("corpus/ocsp-openssl/ca.der");
const LEAF: &[u8] = include_bytes!("corpus/ocsp-openssl/leaf.der");
const REVOKED_LEAF: &[u8] = include_bytes!("corpus/ocsp-openssl/revoked-leaf.der");

fn status(response: &[u8], certificate: &[u8]) -> OcspStatus {
    let response = OcspResponse::from_der(response).unwrap();
    let at = response.this_update().unwrap();
    response.status(certificate, CA, at).unwrap()
}

#[test]
fn ca_signed_revoked_has_its_date_and_reason() {
    let status = status(
        include_bytes!("corpus/ocsp-openssl/revoked.der"),
        REVOKED_LEAF,
    );
    assert_eq!(
        status,
        OcspStatus::Revoked {
            date: DateTime::new(2026, 6, 1, 0, 0, 0).unwrap().to_system_time(),
            reason: Some(CrlReason::KeyCompromise),
        }
    );
}

#[test]
fn ca_signed_good_is_good() {
    // Its ResponderID is the SHA-1 hash of the CA's key, not its name.
    let status = status(include_bytes!("corpus/ocsp-openssl/good.der"), LEAF);
    assert_eq!(status, OcspStatus::Good);
}

#[test]
fn delegated_responder_is_accepted() {
    let status = status(
        include_bytes!("corpus/ocsp-openssl/delegated-good.der"),
        LEAF,
    );
    assert_eq!(status, OcspStatus::Good);
}

#[test]
fn delegate_and_archive_cutoff_are_exposed() {
    let delegated =
        OcspResponse::from_der(include_bytes!("corpus/ocsp-openssl/delegated-good.der")).unwrap();
    assert_eq!(
        delegated.delegated_responder(CA).unwrap().as_deref(),
        Some(&include_bytes!("corpus/ocsp-openssl/responder.der")[..])
    );
    let good = OcspResponse::from_der(include_bytes!("corpus/ocsp-openssl/good.der")).unwrap();
    assert_eq!(good.delegated_responder(CA).unwrap(), None);
    assert_eq!(good.archive_cutoff(LEAF, CA).unwrap(), None);
}
