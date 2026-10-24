#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The level each signature's structure reaches (ADR-0025), on committed files and on PDFs
//! signed at test time; it is read whatever the verdict.

mod support;

use std::time::SystemTime;

use der::{DateTime, Encode};
use nacre_core::{Indication, SignatureForm, SignatureLevel, SignatureProfile};
use nacre_validate::{TrustAnchors, ValidationPolicy, validate_with_policy};
use support::forge::{self, ChainSigner, Ess, ForgedTsa, Role, Signature};

/// Each listed signature of `pdf`, judged under `dss()` with no anchor: its field, its
/// indication and its level.
fn levels(pdf: &[u8]) -> Vec<(String, Indication, Option<SignatureLevel>)> {
    validate_with_policy(
        pdf,
        &TrustAnchors::default(),
        SystemTime::UNIX_EPOCH,
        None,
        &ValidationPolicy::dss(),
    )
    .unwrap()
    .into_iter()
    .map(|result| {
        (
            result.field,
            result.report.indication(),
            result.report.level(),
        )
    })
    .collect()
}

/// A signature's indication and level.
type Verdict = (Indication, Option<SignatureLevel>);

fn level(pdf: &[u8]) -> Option<SignatureLevel> {
    let levels = levels(pdf);
    assert_eq!(levels.len(), 1, "{levels:?}");
    levels[0].2
}

fn pades(profile: SignatureProfile) -> Option<SignatureLevel> {
    Some(SignatureLevel {
        form: SignatureForm::PAdES,
        profile,
    })
}

fn pkcs7(profile: SignatureProfile) -> Option<SignatureLevel> {
    Some(SignatureLevel {
        form: SignatureForm::Pkcs7,
        profile,
    })
}

/// A self-signed signer, enough for a level, which judges no chain.
fn signer() -> ChainSigner {
    let key = forge::key(&[0x51; 32]);
    let certificate = forge::issue(
        Role::Signer,
        "CN=Nacre s18 level signer,O=Nacre tests,C=FR",
        0x51,
        &key,
        None,
        &key,
    );
    ChainSigner {
        key,
        chain: vec![certificate.to_der().unwrap()],
    }
}

/// (a) The committed files, under `dss()`.
#[test]
fn committed_files_have_their_level() {
    use SignatureProfile::*;
    let rows: [(&[u8], &[Verdict]); 5] = [
        (
            include_bytes!("corpus/chain/chain-cms.pdf"),
            &[(Indication::Indeterminate, pades(BaselineB))],
        ),
        (
            include_bytes!("corpus/attacks/byterange-overlap.pdf"),
            &[(Indication::TotalFailed, pades(BaselineB))],
        ),
        (
            include_bytes!("corpus/signed-twice-pyhanko.pdf"),
            &[
                (Indication::Indeterminate, pkcs7(BaselineT)),
                (Indication::Indeterminate, pkcs7(BaselineT)),
            ],
        ),
        (
            include_bytes!("corpus/signed-lta-pyhanko.pdf"),
            &[(Indication::Indeterminate, pades(BaselineLta))],
        ),
        (
            include_bytes!("corpus/attacks/subfilter-unsupported.pdf"),
            &[(Indication::Indeterminate, None)],
        ),
    ];
    for (pdf, expected) in rows {
        let found: Vec<_> = levels(pdf)
            .into_iter()
            .map(|(_, indication, level)| (indication, level))
            .collect();
        assert_eq!(found, expected);
    }
}

/// (b) A `signingTime` attribute makes a PAdES signature BES, never a PKCS7 one.
#[test]
fn signing_time_gives_bes_to_pades_only() {
    let signer = signer();
    let signing_time = Some(forge::time(2026, 10, 22, 8, 0, 0));
    let pades_with_time = forge::signed_with(
        forge::UNSIGNED,
        &signer,
        &Signature {
            signing_time,
            ..Signature::default()
        },
    );
    assert_eq!(
        level(&pades_with_time),
        pades(SignatureProfile::ExtendedBes)
    );

    let pkcs7_with_time = forge::signed_with(
        forge::UNSIGNED,
        &signer,
        &Signature {
            sub_filter: b"adbe.pkcs7.detached",
            signing_time,
            ..Signature::default()
        },
    );
    assert_eq!(level(&pkcs7_with_time), pkcs7(SignatureProfile::BaselineB));
}

/// (c) A PAdES signature needs an ESS attribute, v1 or v2.
#[test]
fn pades_needs_an_ess_attribute() {
    let signer = signer();
    let with = |ess| {
        forge::signed_with(
            forge::UNSIGNED,
            &signer,
            &Signature {
                ess,
                ..Signature::default()
            },
        )
    };
    assert_eq!(level(&with(Ess::None)), None);
    assert_eq!(level(&with(Ess::V1)), pades(SignatureProfile::BaselineB));
}

/// (d) A document timestamp after a B signature makes it T, valid or not.
#[test]
fn document_timestamp_after_the_signature_gives_t() {
    let basic = forge::signed_with(forge::UNSIGNED, &signer(), &Signature::default());
    let key = forge::key(&[0x52; 32]);
    let tsa = forge::issue(
        Role::Tsa,
        "CN=Nacre s18 level TSA,O=Nacre tests,C=FR",
        0x52,
        &key,
        None,
        &key,
    );
    let stamped = forge::document_timestamp(
        &basic,
        &ForgedTsa {
            key,
            certificates: vec![tsa.to_der().unwrap()],
            gen_time: DateTime::new(2026, 10, 22, 9, 0, 0).unwrap(),
            imprint: Some(vec![0; 32]),
        },
    );

    assert_eq!(level(&basic), pades(SignatureProfile::BaselineB));
    assert_eq!(level(&stamped), pades(SignatureProfile::BaselineT));
}
