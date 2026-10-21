#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! One test per file of `corpus/attacks/` (`docs/security/attacks/cms.md`). Each file is
//! correctly signed apart from its one defect, so each must fail on its own rule.

use nacre_cms::{Error, SignedData, oid};

const CONTENT: &[u8] = include_bytes!("corpus/openssl/content.bin");

fn verify(file: &[u8]) -> Error {
    SignedData::from_der(file)
        .unwrap()
        .verify(Some(CONTENT))
        .unwrap_err()
}

#[test]
fn algorithm_confusion_is_rejected() {
    let err = verify(include_bytes!("corpus/attacks/alg-confusion.der"));
    assert!(matches!(err, Error::AlgorithmMismatch), "{err:?}");
}

#[test]
fn absent_signed_attributes_are_rejected() {
    let err = verify(include_bytes!("corpus/attacks/signed-attrs-absent.der"));
    assert!(matches!(err, Error::MissingSignedAttributes), "{err:?}");
}

#[test]
fn absent_message_digest_is_rejected() {
    let err = verify(include_bytes!("corpus/attacks/message-digest-absent.der"));
    assert!(
        matches!(err, Error::MissingAttribute(o) if o == oid::MESSAGE_DIGEST),
        "{err:?}"
    );
}

#[test]
fn duplicated_signed_attribute_is_rejected() {
    let err = verify(include_bytes!("corpus/attacks/signed-attrs-duplicate.der"));
    assert!(
        matches!(err, Error::DuplicateAttribute(o) if o == oid::MESSAGE_DIGEST),
        "{err:?}"
    );
}

#[test]
fn inconsistent_message_digest_is_rejected() {
    let err = verify(include_bytes!("corpus/attacks/message-digest-mismatch.der"));
    assert!(matches!(err, Error::MessageDigestMismatch), "{err:?}");
}

#[test]
fn signer_identifier_designating_no_certificate_is_rejected() {
    let err = verify(include_bytes!("corpus/attacks/sid-unknown.der"));
    assert!(matches!(err, Error::SignerCertificateNotFound), "{err:?}");
}

#[test]
fn substituted_certificate_is_rejected() {
    let err = verify(include_bytes!("corpus/attacks/cert-substitution.der"));
    assert!(matches!(err, Error::SigningCertificateMismatch), "{err:?}");
}

#[test]
fn content_type_mismatch_is_rejected() {
    let err = verify(include_bytes!("corpus/attacks/content-type-mismatch.der"));
    assert!(matches!(err, Error::ContentTypeMismatch), "{err:?}");
}
