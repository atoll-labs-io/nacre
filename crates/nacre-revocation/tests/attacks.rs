#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! One test per attack of `docs/security/attacks/revocation.md`. Every CRL lists the leaf
//! and is correctly signed apart from its one defect: a skipped rule answers "revoked".

use der::DateTime;
use der::oid::ObjectIdentifier;
use nacre_revocation::{Crl, CrlStatus, Error};

const CA: &[u8] = include_bytes!("corpus/attacks/ca.der");
const OTHER_CA: &[u8] = include_bytes!("corpus/attacks/other-ca.der");
const NON_CRL_SIGNER_CA: &[u8] = include_bytes!("corpus/attacks/non-crl-signer-ca.der");
const RENAMED_CA: &[u8] = include_bytes!("corpus/attacks/renamed-ca.der");
const LEAF: &[u8] = include_bytes!("corpus/attacks/leaf.der");

fn status(crl: &[u8], issuer: &[u8]) -> Result<CrlStatus, Error> {
    let at = DateTime::new(2027, 1, 1, 0, 0, 0).unwrap().to_system_time();
    Crl::from_der(crl).unwrap().status(LEAF, issuer, at)
}

#[test]
fn crl_from_another_issuer_is_rejected() {
    let crl = include_bytes!("corpus/attacks/wrong-issuer.der");
    // The other CA signed the CRL: its signature verifies with the issuer given.
    Crl::from_der(crl)
        .unwrap()
        .verify_signature(OTHER_CA)
        .unwrap();
    assert!(matches!(status(crl, OTHER_CA), Err(Error::WrongIssuer)));
}

#[test]
fn issuer_certificate_under_another_name_is_rejected() {
    let crl = include_bytes!("corpus/attacks/issuer-renamed.der");
    // Same key as the CA: only the name tells this certificate is not the CRL's issuer.
    Crl::from_der(crl)
        .unwrap()
        .verify_signature(RENAMED_CA)
        .unwrap();
    assert!(matches!(status(crl, RENAMED_CA), Err(Error::WrongIssuer)));
}

#[test]
fn changed_byte_after_signing_is_rejected() {
    let crl = include_bytes!("corpus/attacks/bad-signature.der");
    assert!(matches!(status(crl, CA), Err(Error::SignatureInvalid)));
}

#[test]
fn stale_crl_is_rejected() {
    let crl = include_bytes!("corpus/attacks/stale.der");
    let next_update = DateTime::new(2026, 6, 1, 0, 0, 0).unwrap().to_system_time();
    assert!(matches!(
        status(crl, CA),
        Err(Error::Expired { next_update: at }) if at == next_update
    ));
}

#[test]
fn crl_without_next_update_is_rejected() {
    let crl = include_bytes!("corpus/attacks/no-next-update.der");
    assert!(matches!(status(crl, CA), Err(Error::MissingNextUpdate)));
}

#[test]
fn critical_crl_extension_is_rejected() {
    let crl = include_bytes!("corpus/attacks/critical-extension.der");
    let idp = ObjectIdentifier::new_unwrap("2.5.29.28");
    assert!(matches!(
        status(crl, CA),
        Err(Error::UnsupportedCriticalExtension(oid)) if oid == idp
    ));
}

#[test]
fn algorithm_substitution_is_rejected() {
    let crl = include_bytes!("corpus/attacks/algorithm-substitution.der");
    assert!(matches!(status(crl, CA), Err(Error::AlgorithmMismatch)));
}

#[test]
fn issuer_without_crl_sign_is_rejected() {
    let crl = include_bytes!("corpus/attacks/issuer-not-crl-signer.der");
    assert!(matches!(
        status(crl, NON_CRL_SIGNER_CA),
        Err(Error::IssuerNotCrlSigner)
    ));
}

#[test]
fn critical_entry_extension_is_rejected() {
    let crl = include_bytes!("corpus/attacks/critical-entry-extension.der");
    let certificate_issuer = ObjectIdentifier::new_unwrap("2.5.29.29");
    assert!(matches!(
        status(crl, CA),
        Err(Error::UnsupportedCriticalExtension(oid)) if oid == certificate_issuer
    ));
}
