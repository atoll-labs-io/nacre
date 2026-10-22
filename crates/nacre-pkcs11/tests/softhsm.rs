#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The signer against SoftHSM, each test on its own fresh token (`support::in_token`).

mod support;

use std::error::Error as _;

use nacre_core::{SignatureAlgorithm, Signer, TestSigner};
use nacre_pkcs11::{Error, KeySelector, Pin, PinState, Pkcs11Signer};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256};
use support::{PIN, Token, in_token, verifying_key};

const SECRET: [u8; 32] = [0x11; 32];
const FAKE_ISSUER: &[u8] = b"\x30\x03\x02\x01\x07";

fn test_certificate() -> Vec<u8> {
    TestSigner::from_secret(&SECRET)
        .unwrap()
        .certificate_chain()[0]
        .clone()
}

fn open_error(token: &Token, key: KeySelector, pin: Pin) -> Error {
    match Pkcs11Signer::open(&token.config(key, Vec::new()), pin) {
        Ok(_) => panic!("the signer opened"),
        Err(error) => error,
    }
}

fn assert_ecdsa_signs(signer: &Pkcs11Signer, certificate: &[u8], messages: &[&[u8]]) {
    let key = verifying_key(certificate);
    for message in messages {
        let digest = Sha256::digest(message);
        let der = signer.sign_digest(&digest).unwrap();
        let signature = p256::ecdsa::Signature::from_der(&der).unwrap();
        key.verify_prehash(&digest, &signature).unwrap();
    }
}

#[test]
#[ignore = "conformance"]
fn ecdsa_key_found_by_label_signs_verifiable_der() {
    in_token("ecdsa_key_found_by_label_signs_verifiable_der", |token| {
        let certificate = test_certificate();
        token.put_ec_key(&SECRET, "nacre-ec", &[0x01], false);
        token.put_certificate(&certificate, "nacre-ec-cert", &[0x01]);

        let config = token.config(
            KeySelector::Label("nacre-ec".into()),
            vec![FAKE_ISSUER.to_vec()],
        );
        let signer = Pkcs11Signer::open(&config, Token::pin()).unwrap();

        assert_eq!(signer.algorithm(), SignatureAlgorithm::EcdsaP256Sha256);
        assert_eq!(
            signer.certificate_chain(),
            [certificate.clone(), FAKE_ISSUER.to_vec()]
        );
        assert_ecdsa_signs(&signer, &certificate, &[b"one", b"two", b"three"]);
        assert!(matches!(
            signer.sign_digest(&[0u8; 20]),
            Err(nacre_core::Error::DigestLength {
                expected: 32,
                actual: 20
            })
        ));
    });
}

#[test]
#[ignore = "conformance"]
fn rsa_key_found_by_id_signs_pkcs1_v15() {
    in_token("rsa_key_found_by_id_signs_pkcs1_v15", |token| {
        token.generate_rsa("nacre-rsa", &[0x03]);
        token.put_certificate(&test_certificate(), "nacre-rsa-cert", &[0x03]);

        let config = token.config(KeySelector::Id(vec![0x03]), Vec::new());
        let signer = Pkcs11Signer::open(&config, Token::pin()).unwrap();
        assert_eq!(signer.algorithm(), SignatureAlgorithm::RsaPkcs1v15Sha256);

        let message = b"a PDF byte range";
        let signature = signer.sign_digest(&Sha256::digest(message)).unwrap();
        assert_eq!(signature.len(), 256);
        // The token builds the DigestInfo itself: an independent judge of ours.
        token.verify_rsa_sha256(&[0x03], message, &signature);
    });
}

#[test]
#[ignore = "conformance"]
fn wrong_pin_reports_the_token_state_without_the_pin() {
    in_token(
        "wrong_pin_reports_the_token_state_without_the_pin",
        |token| {
            token.put_ec_key(&SECRET, "nacre-ec", &[0x01], false);
            token.put_certificate(&test_certificate(), "nacre-ec-cert", &[0x01]);
            let wrong = "905518";

            let error = open_error(
                token,
                KeySelector::Label("nacre-ec".into()),
                Pin::new(wrong.to_owned()),
            );

            assert!(
                matches!(error, Error::WrongPin(PinState::CountLow)),
                "{error:?}"
            );
            let mut texts = vec![format!("{error:?}"), error.to_string()];
            let mut source = error.source();
            while let Some(inner) = source {
                texts.push(format!("{inner:?}"));
                texts.push(inner.to_string());
                source = inner.source();
            }
            for text in texts {
                assert!(!text.contains(wrong) && !text.contains(PIN), "{text}");
            }
        },
    );
}

#[test]
#[ignore = "conformance"]
fn always_authenticate_key_signs_twice() {
    in_token("always_authenticate_key_signs_twice", |token| {
        let certificate = test_certificate();
        token.put_ec_key(&SECRET, "nacre-ec", &[0x02], true);
        token.put_certificate(&certificate, "nacre-ec-cert", &[0x02]);

        let config = token.config(KeySelector::Id(vec![0x02]), Vec::new());
        let signer = Pkcs11Signer::open(&config, Token::pin()).unwrap();

        assert_ecdsa_signs(&signer, &certificate, &[b"first", b"second"]);
    });
}

fn signer_error(error: nacre_core::Error) -> Error {
    match error {
        nacre_core::Error::Signer(inner) => *inner.downcast::<Error>().unwrap(),
        other => panic!("not a signer error: {other:?}"),
    }
}

#[test]
#[ignore = "conformance"]
fn refused_context_pin_is_never_sent_again() {
    in_token("refused_context_pin_is_never_sent_again", |token| {
        token.put_ec_key(&SECRET, "nacre-ec", &[0x02], true);
        token.put_certificate(&test_certificate(), "nacre-ec-cert", &[0x02]);
        let config = token.config(KeySelector::Id(vec![0x02]), Vec::new());
        let signer = Pkcs11Signer::open(&config, Token::pin()).unwrap();
        token.change_pin(PIN, "618204");
        let digest = Sha256::digest(b"refused");

        let first = signer_error(signer.sign_digest(&digest).unwrap_err());
        assert!(
            matches!(first, Error::WrongPin(PinState::CountLow)),
            "{first:?}"
        );
        // Without the guard, SoftHSM answers `OperationActive` here; a module that ends the
        // operation on a refused login would get the refused PIN again.
        for _ in 0..2 {
            let again = signer_error(signer.sign_digest(&digest).unwrap_err());
            assert!(matches!(again, Error::PinRefused), "{again:?}");
        }
    });
}

#[test]
#[ignore = "conformance"]
fn second_signer_of_a_logged_in_token_is_refused() {
    in_token("second_signer_of_a_logged_in_token_is_refused", |token| {
        let certificate = test_certificate();
        token.put_ec_key(&SECRET, "nacre-ec", &[0x01], false);
        token.put_certificate(&certificate, "nacre-ec-cert", &[0x01]);
        let first = Pkcs11Signer::open(
            &token.config(KeySelector::Id(vec![0x01]), Vec::new()),
            Token::pin(),
        )
        .unwrap();

        let error = open_error(
            token,
            KeySelector::Id(vec![0x01]),
            Pin::new("905518".to_owned()),
        );

        assert!(matches!(error, Error::AlreadyLoggedIn), "{error:?}");
        assert_ecdsa_signs(&first, &certificate, &[b"still signs"]);
    });
}

#[test]
#[ignore = "conformance"]
fn missing_key_is_named() {
    in_token("missing_key_is_named", |token| {
        token.put_ec_key(&SECRET, "nacre-ec", &[0x01], false);

        let error = open_error(token, KeySelector::Label("absent".into()), Token::pin());

        assert!(matches!(error, Error::KeyNotFound), "{error:?}");
    });
}
