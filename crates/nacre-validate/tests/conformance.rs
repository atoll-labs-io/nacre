#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! PDFs signed with the bench's PKI (`conformance/README.md`), judged by Nacre and by the
//! running DSS, which must agree on the indication and the sub-indication. Certificates the
//! bench cannot revoke after signing are forged at test time under the bench intermediate,
//! with no CRL distribution point and no OCSP responder, so DSS reads only the `/DSS`.

mod support;

use std::time::{Duration, SystemTime};

use der::{DateTime, Decode, Encode};
use nacre_conformance::Dss;
use nacre_core::{
    Indication, RevocationData, RevocationSource, SignatureForm, SignatureLevel, SignatureProfile,
    SubIndication,
};
use nacre_pades::Level;
use nacre_revocation::{Fallback, HttpCrlSource, HttpOcspSource};
use nacre_tsp::HttpTsa;
use nacre_validate::{SignatureValidation, TrustAnchors, validate_with_revocation};
use p256::ecdsa::SigningKey;
use support::forge::{self, ChainSigner, ForgedTsa, Role};
use support::{BenchSigner, bench_certificate, bench_key};
use x509_cert::Certificate;
use x509_cert::time::Time;

const TSA_URL: &str = "http://127.0.0.1:18081/cgi-bin/tsa";
const DOCUMENT_TSA_URL: &str = "http://127.0.0.1:18081/cgi-bin/tsa2";

fn bench_revocation() -> Fallback<HttpOcspSource, HttpCrlSource> {
    Fallback::new(
        HttpOcspSource::allowing_loopback(),
        HttpCrlSource::allowing_loopback(),
    )
}

fn x509(at: SystemTime) -> Time {
    Time::from(DateTime::from_system_time(at).unwrap())
}

/// The single signature of `pdf`, judged by Nacre now with the bench root as anchor.
fn nacre(pdf: &[u8], source: Option<&dyn RevocationSource>) -> SignatureValidation {
    let root = bench_certificate("root.cert.pem");
    let anchors = TrustAnchors::from_certificates([root.as_slice()]).unwrap();
    let mut results = validate_with_revocation(pdf, &anchors, SystemTime::now(), source).unwrap();
    assert_eq!(results.len(), 1);
    results.remove(0)
}

/// Asserts that Nacre and DSS both give `indication` / `sub` on `pdf`, Nacre judging with
/// `source`, and that DSS reports the PAdES level `profile`; Nacre gives no level before s18.
fn confront(
    name: &str,
    pdf: &[u8],
    source: Option<&dyn RevocationSource>,
    (indication, sub): (Indication, Option<SubIndication>),
    profile: SignatureProfile,
) -> SignatureValidation {
    let ours = nacre(pdf, source);
    let reports = Dss::from_env().unwrap().validate(name, pdf).unwrap();
    assert_eq!(reports.signatures.len(), 1);
    let theirs = &reports.signatures[0].report;

    assert_eq!(
        (theirs.indication(), theirs.sub_indication(), theirs.level()),
        (
            indication,
            sub,
            Some(SignatureLevel {
                form: SignatureForm::PAdES,
                profile
            })
        ),
        "DSS on {name}"
    );
    assert_eq!(
        (ours.report.indication(), ours.report.sub_indication()),
        (indication, sub),
        "Nacre on {name}: {:?}",
        ours.defect
    );
    ours
}

/// A serial no bench certificate uses: the bench numbers from 0x1000 and 0x2000.
fn fresh_serial(offset: u64) -> u64 {
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    (seconds << 8) + offset
}

/// A certificate of `role` issued by the bench intermediate, with no CDP and no AIA.
fn forged(role: Role, subject: &str, key: &SigningKey, offset: u64) -> Certificate {
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    forge::issue(
        role,
        subject,
        fresh_serial(offset),
        key,
        Some(&intermediate),
        &bench_key("intermediate"),
    )
}

/// Revokes `revoked` one second before it answers, two seconds after it is asked, with a
/// CRL of the bench intermediate; the bench answers every other certificate.
struct RevokingSource {
    revoked: Vec<Certificate>,
}

impl RevocationSource for RevokingSource {
    fn revocation(
        &self,
        certificate: &[u8],
        issuer: &[u8],
    ) -> Result<RevocationData, nacre_core::Error> {
        if !self
            .revoked
            .iter()
            .any(|forged| forged.to_der().unwrap() == certificate)
        {
            return bench_revocation().revocation(certificate, issuer);
        }
        std::thread::sleep(Duration::from_secs(2));
        let intermediate =
            Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
        let now = SystemTime::now();
        let date = x509(now - Duration::from_secs(1));
        let revoked: Vec<(&Certificate, Time)> =
            self.revoked.iter().map(|cert| (cert, date)).collect();
        Ok(RevocationData::Crl(forge::crl(
            &intermediate,
            &bench_key("intermediate"),
            x509(now),
            x509(now + Duration::from_secs(30 * 24 * 3600)),
            &revoked,
        )))
    }
}

/// C0, c01: the bench `signer` at B-B, revocation fetched from the bench.
#[test]
#[ignore = "conformance"]
fn bench_chain_is_valid() {
    let pdf = forge::signed(&BenchSigner::load(), Level::B);

    let result = confront(
        "s17-c0-signer-b",
        &pdf,
        Some(&bench_revocation()),
        (Indication::TotalPassed, None),
        SignatureProfile::BaselineB,
    );

    assert_eq!(
        result.chain.as_ref().unwrap().certificates,
        vec![
            bench_certificate("signer.cert.pem"),
            bench_certificate("intermediate.cert.pem"),
            bench_certificate("root.cert.pem"),
        ]
    );
}

/// C1, c05 and c07: a forged signer revoked after its bench B-T stamp, its CRL in `/DSS`.
#[test]
#[ignore = "conformance"]
fn revoked_after_the_bench_stamp_passes() {
    let key = forge::key(&[0x51; 32]);
    let signer = forged(
        Role::Signer,
        "CN=Nacre s17 forged signer,O=Nacre tests,C=FR",
        &key,
        1,
    );
    let chain = ChainSigner {
        key,
        chain: vec![
            signer.to_der().unwrap(),
            bench_certificate("intermediate.cert.pem"),
        ],
    };
    let issuers = [bench_certificate("root.cert.pem")];
    let pdf = forge::signed(
        &chain,
        Level::LT {
            tsa: &HttpTsa::new(TSA_URL),
            revocation: &RevokingSource {
                revoked: vec![signer],
            },
            issuers: &issuers,
        },
    );

    let result = confront(
        "s17-c1-revoked-after-stamp",
        &pdf,
        None,
        (Indication::TotalPassed, None),
        SignatureProfile::BaselineLt,
    );

    assert!(result.best_signature_time.is_some());
}

/// C2, c04: the bench `revoked`, stamped after its revocation.
#[test]
#[ignore = "conformance"]
fn bench_revoked_stamped_is_revoked_no_poe() {
    let pdf = forge::signed(
        &BenchSigner::load_as("revoked"),
        Level::T {
            tsa: &HttpTsa::new(TSA_URL),
        },
    );

    confront(
        "s17-c2-revoked-t",
        &pdf,
        Some(&bench_revocation()),
        (Indication::Indeterminate, Some(SubIndication::RevokedNoPoe)),
        SignatureProfile::BaselineT,
    );
}

/// C3, c02: the bench `revoked` at B-B.
#[test]
#[ignore = "conformance"]
fn bench_revoked_basic_is_revoked_no_poe() {
    let pdf = forge::signed(&BenchSigner::load_as("revoked"), Level::B);

    confront(
        "s17-c3-revoked-b",
        &pdf,
        Some(&bench_revocation()),
        (Indication::Indeterminate, Some(SubIndication::RevokedNoPoe)),
        SignatureProfile::BaselineB,
    );
}

/// C4, AC3: the `/DSS` of a bench B-LT and B-LTA file is enough, with no source.
#[test]
#[ignore = "conformance"]
fn bench_long_term_files_pass_offline() {
    let issuers = [bench_certificate("root.cert.pem")];
    let tsa = HttpTsa::new(TSA_URL);
    let revocation = bench_revocation();
    let lt = forge::signed(
        &BenchSigner::load(),
        Level::LT {
            tsa: &tsa,
            revocation: &revocation,
            issuers: &issuers,
        },
    );
    let lta = forge::signed(
        &BenchSigner::load(),
        Level::LTA {
            tsa: &tsa,
            revocation: &revocation,
            issuers: &issuers,
            document_tsa: &HttpTsa::new(DOCUMENT_TSA_URL),
        },
    );

    for (name, pdf, profile) in [
        ("s17-c4-signer-lt", lt, SignatureProfile::BaselineLt),
        ("s17-c4-signer-lta", lta, SignatureProfile::BaselineLta),
    ] {
        let result = confront(name, &pdf, None, (Indication::TotalPassed, None), profile);
        assert!(result.best_signature_time.is_some(), "{name}");
    }
}

/// C5, c08: a forged signer with no CDP, no AIA and no data in the file.
#[test]
#[ignore = "conformance"]
fn forged_signer_without_data_is_a_general_failure() {
    let key = forge::key(&[0x52; 32]);
    let signer = forged(
        Role::Signer,
        "CN=Nacre s17 unreachable signer,O=Nacre tests,C=FR",
        &key,
        2,
    );
    let chain = ChainSigner {
        key,
        chain: vec![
            signer.to_der().unwrap(),
            bench_certificate("intermediate.cert.pem"),
        ],
    };
    let pdf = forge::signed(&chain, Level::B);

    confront(
        "s17-c5-no-data-b",
        &pdf,
        None,
        (
            Indication::Indeterminate,
            Some(SubIndication::CertificateChainGeneralFailure),
        ),
        SignatureProfile::BaselineB,
    );
}

/// C6, c14 and AC4: a forged signer and a forged TSA, both revoked after the stamp: the
/// TSA gives no proof of time, so the signer's revocation counts.
#[test]
#[ignore = "conformance"]
fn revoked_tsa_after_the_stamp_gives_no_poe() {
    let signer_key = forge::key(&[0x53; 32]);
    let tsa_key = forge::key(&[0x54; 32]);
    let signer = forged(
        Role::Signer,
        "CN=Nacre s17 forged signer,O=Nacre tests,C=FR",
        &signer_key,
        3,
    );
    let tsa = forged(
        Role::Tsa,
        "CN=Nacre s17 forged TSA,O=Nacre tests,C=FR",
        &tsa_key,
        4,
    );
    let chain = ChainSigner {
        key: signer_key,
        chain: vec![
            signer.to_der().unwrap(),
            bench_certificate("intermediate.cert.pem"),
        ],
    };
    let authority = ForgedTsa {
        key: tsa_key,
        certificates: vec![tsa.to_der().unwrap()],
        gen_time: DateTime::from_system_time(SystemTime::now()).unwrap(),
        imprint: None,
    };
    let issuers = [bench_certificate("root.cert.pem")];
    let pdf = forge::signed(
        &chain,
        Level::LT {
            tsa: &authority,
            revocation: &RevokingSource {
                revoked: vec![signer, tsa],
            },
            issuers: &issuers,
        },
    );

    let result = confront(
        "s17-c6-revoked-tsa",
        &pdf,
        None,
        (Indication::Indeterminate, Some(SubIndication::RevokedNoPoe)),
        SignatureProfile::BaselineLt,
    );

    assert_eq!(result.best_signature_time, None);
}
