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
use nacre_pdf::{Dictionary, Document, Object};
use nacre_revocation::{Fallback, HttpCrlSource, HttpOcspSource};
use nacre_tsp::HttpTsa;
use nacre_validate::{
    ChainDefect, Defect, Error, SignatureValidation, TrustAnchors, ValidationPolicy,
    validate_with_policy,
};
use p256::ecdsa::SigningKey;
use support::forge::{self, ChainSigner, Extensions, ForgedTsa, Role};
use support::{BenchSigner, bench_certificate, bench_key};
use x509_cert::Certificate;
use x509_cert::ext::pkix::KeyUsages;
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

/// Every signature of `pdf`, judged by Nacre now under `policy` with the bench root as
/// anchor.
fn judged(
    pdf: &[u8],
    source: Option<&dyn RevocationSource>,
    policy: &ValidationPolicy,
) -> Result<Vec<SignatureValidation>, Error> {
    let root = bench_certificate("root.cert.pem");
    let anchors = TrustAnchors::from_certificates([root.as_slice()]).unwrap();
    validate_with_policy(pdf, &anchors, SystemTime::now(), source, policy)
}

/// The single signature of `pdf`, judged by Nacre now under `policy`.
fn nacre(
    pdf: &[u8],
    source: Option<&dyn RevocationSource>,
    policy: &ValidationPolicy,
) -> SignatureValidation {
    let mut results = judged(pdf, source, policy).unwrap();
    assert_eq!(results.len(), 1);
    results.remove(0)
}

type Verdict = (Indication, Option<SubIndication>);

fn verdict(result: &SignatureValidation) -> Verdict {
    (result.report.indication(), result.report.sub_indication())
}

/// Asserts that Nacre and DSS both give `indication` / `sub` on `pdf`, Nacre judging with
/// `source` under `policy`, and that both report the PAdES level `profile`.
fn confront(
    name: &str,
    pdf: &[u8],
    source: Option<&dyn RevocationSource>,
    (indication, sub): (Indication, Option<SubIndication>),
    profile: SignatureProfile,
    policy: &ValidationPolicy,
) -> SignatureValidation {
    let ours = nacre(pdf, source, policy);
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
        (
            ours.report.indication(),
            ours.report.sub_indication(),
            ours.report.level()
        ),
        (indication, sub, theirs.level()),
        "Nacre on {name}: {:?}",
        ours.defect
    );
    ours
}

/// Asserts that DSS lists as many signatures as `expected` with those verdicts, in any
/// order, and that Nacre under `policy` lists the same; no level is compared. Returns
/// Nacre's results.
fn confront_signatures(
    name: &str,
    pdf: &[u8],
    source: Option<&dyn RevocationSource>,
    expected: &[Verdict],
    policy: &ValidationPolicy,
) -> Vec<SignatureValidation> {
    let sorted = |mut verdicts: Vec<Verdict>| {
        verdicts.sort_by_key(|v| format!("{v:?}"));
        verdicts
    };
    let expected = sorted(expected.to_vec());
    let reports = Dss::from_env().unwrap().validate(name, pdf).unwrap();
    let theirs = sorted(
        reports
            .signatures
            .iter()
            .map(|s| (s.report.indication(), s.report.sub_indication()))
            .collect(),
    );
    assert_eq!(theirs, expected, "DSS on {name}");
    let ours = judged(pdf, source, policy).unwrap();
    assert_eq!(
        sorted(ours.iter().map(verdict).collect()),
        expected,
        "Nacre on {name}: {:?}",
        ours.iter().map(|r| &r.defect).collect::<Vec<_>>()
    );
    ours
}

/// Asserts that DSS answers `pdf` with an error and that Nacre under `policy` returns one.
fn confront_error(name: &str, pdf: &[u8], policy: &ValidationPolicy) -> Error {
    let theirs = Dss::from_env().unwrap().validate(name, pdf);
    assert!(theirs.is_err(), "DSS on {name}: {theirs:?}");
    judged(pdf, Some(&bench_revocation()), policy).unwrap_err()
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
        &ValidationPolicy::strict(),
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
        &ValidationPolicy::strict(),
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
        &ValidationPolicy::strict(),
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
        &ValidationPolicy::strict(),
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
        let result = confront(
            name,
            &pdf,
            None,
            (Indication::TotalPassed, None),
            profile,
            &ValidationPolicy::strict(),
        );
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
        &ValidationPolicy::strict(),
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
        &ValidationPolicy::strict(),
    );

    assert_eq!(result.best_signature_time, None);
}

/// A signer of serial `offset` issued by the bench intermediate, valid over `validity`, with
/// `extensions`, no CDP and no AIA.
fn forged_signer(
    subject: &str,
    secret: u8,
    offset: u64,
    validity: (SystemTime, SystemTime),
    extensions: Extensions,
) -> ChainSigner {
    let key = forge::key(&[secret; 32]);
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    let signer = forge::issue_with(
        Role::Signer,
        subject,
        fresh_serial(offset),
        &key,
        Some(&intermediate),
        &bench_key("intermediate"),
        (x509(validity.0), x509(validity.1)),
        extensions,
    );
    ChainSigner {
        key,
        chain: vec![
            signer.to_der().unwrap(),
            bench_certificate("intermediate.cert.pem"),
        ],
    }
}

/// The bench intermediate's CRL issued at `this_update`, revoking nothing.
fn intermediate_crl(this_update: SystemTime) -> Vec<u8> {
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    forge::crl(
        &intermediate,
        &bench_key("intermediate"),
        x509(this_update),
        x509(this_update + Duration::from_secs(30 * 24 * 3600)),
        &[],
    )
}

fn usual_validity() -> (SystemTime, SystemTime) {
    (
        forge::instant(2026, 1, 1, 0, 0, 0),
        forge::instant(2036, 1, 1, 0, 0, 0),
    )
}

fn hours(n: u64) -> Duration {
    Duration::from_secs(n * 3600)
}

const PASSED: Verdict = (Indication::TotalPassed, None);
const NO_CHAIN: Verdict = (
    Indication::Indeterminate,
    Some(SubIndication::NoCertificateChainFound),
);

/// Switch "later revisions", l37: a bench B given a revision that sets a JavaScript
/// `/OpenAction`.
#[test]
#[ignore = "conformance"]
fn later_revisions_policy() {
    let signed = forge::signed(&BenchSigner::load(), Level::B);
    let doc = Document::parse(&signed).unwrap();
    let mut update = doc.update();
    let mut action = Dictionary::new();
    action.insert(b"S", Object::Name(b"JavaScript".to_vec()));
    action.insert(b"JS", Object::String(b"app.alert('appended');".to_vec()));
    let action = update.add(Object::Dictionary(action)).unwrap();
    update.set_catalog(b"OpenAction", Object::Reference(action));
    let pdf = update.finish().unwrap();
    let source = bench_revocation();

    confront_signatures(
        "s41-later-revisions",
        &pdf,
        Some(&source),
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&pdf, Some(&source), &ValidationPolicy::strict());
    assert_eq!(verdict(&strict).0, Indication::TotalFailed);
}

/// Switch "sneaky signatures": both signatures of `ssa-visible-signature.pdf`.
#[test]
#[ignore = "conformance"]
fn sneaky_signatures_policy() {
    let pdf = include_bytes!("corpus/attacks/ssa-visible-signature.pdf");

    confront_signatures(
        "s41-ssa-visible-signature",
        pdf,
        None,
        &[NO_CHAIN, NO_CHAIN],
        &ValidationPolicy::dss(),
    );
    let strict = judged(pdf, None, &ValidationPolicy::strict()).unwrap();
    assert_eq!(strict.len(), 2);
    assert!(
        strict
            .iter()
            .all(|r| r.report.indication() == Indication::TotalFailed)
    );
}

/// Switch "trailing data": `isa-no-xref.pdf`.
#[test]
#[ignore = "conformance"]
fn trailing_data_policy() {
    let pdf = include_bytes!("corpus/attacks/isa-no-xref.pdf");

    confront_signatures(
        "s41-isa-no-xref",
        pdf,
        None,
        &[NO_CHAIN],
        &ValidationPolicy::dss(),
    );
    let error = judged(pdf, None, &ValidationPolicy::strict()).unwrap_err();
    assert!(matches!(error, Error::Pdf(_)), "{error:?}");
}

/// Switch "unusable signatures listed": `usf-contents-missing.pdf`.
#[test]
#[ignore = "conformance"]
fn unusable_signatures_policy() {
    let pdf = include_bytes!("corpus/attacks/usf-contents-missing.pdf");

    confront_signatures(
        "s41-usf-contents-missing",
        pdf,
        None,
        &[],
        &ValidationPolicy::dss(),
    );
    assert_eq!(
        judged(pdf, None, &ValidationPolicy::strict())
            .unwrap()
            .len(),
        1
    );
}

/// Switch "signer key usage", c42: a `keyCertSign`-only signer, its CRL in `/DSS`.
#[test]
#[ignore = "conformance"]
fn signer_key_usage_policy() {
    let signer = forged_signer(
        "CN=Nacre s41 key usage signer,O=Nacre tests,C=FR",
        0x61,
        41,
        usual_validity(),
        Extensions::KeyUsage(KeyUsages::KeyCertSign.into()),
    );
    let pdf = forge::with_dss(
        &forge::signed(&signer, Level::B),
        &[],
        &[intermediate_crl(SystemTime::now() - hours(1))],
    );
    let source = bench_revocation();

    confront_signatures(
        "s41-signer-key-usage",
        &pdf,
        Some(&source),
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&pdf, Some(&source), &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        (
            Indication::Indeterminate,
            Some(SubIndication::ChainConstraintsFailure)
        )
    );
}

/// Switch "validity before revocation", c40: a signer expired yesterday, no data.
#[test]
#[ignore = "conformance"]
fn validity_before_revocation_policy() {
    let now = SystemTime::now();
    let signer = forged_signer(
        "CN=Nacre s41 expired signer,O=Nacre tests,C=FR",
        0x62,
        42,
        (forge::instant(2026, 1, 1, 0, 0, 0), now - hours(24)),
        Extensions::Usual,
    );
    let pdf = forge::signed(&signer, Level::B);

    confront_signatures(
        "s41-validity-before-revocation",
        &pdf,
        None,
        &[(
            Indication::Indeterminate,
            Some(SubIndication::CertificateChainGeneralFailure),
        )],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&pdf, None, &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        (
            Indication::Indeterminate,
            Some(SubIndication::OutOfBoundsNoPoe)
        )
    );
}

/// Switch "malformed extensions judged": a signer repeating `keyUsage`.
#[test]
#[ignore = "conformance"]
fn malformed_extensions_policy() {
    let signer = forged_signer(
        "CN=Nacre s41 malformed signer,O=Nacre tests,C=FR",
        0x63,
        43,
        usual_validity(),
        Extensions::RepeatedKeyUsage,
    );
    let pdf = forge::with_dss(
        &forge::signed(&signer, Level::B),
        &[],
        &[intermediate_crl(SystemTime::now() - hours(1))],
    );

    let error = confront_error("s41-malformed-extension", &pdf, &ValidationPolicy::dss());
    assert!(matches!(error, Error::MalformedCertificate), "{error:?}");
    let strict = nacre(&pdf, Some(&bench_revocation()), &ValidationPolicy::strict());
    assert!(
        matches!(
            strict.defect,
            Some(Defect::Chain(ChainDefect::MalformedExtension { depth: 0 }))
        ),
        "{:?}",
        strict.defect
    );
}

/// Switch "fresh revocation": a B-B whose signer's only CRL, in `/DSS`, is 25 hours old.
#[test]
#[ignore = "conformance"]
fn fresh_revocation_policy() {
    let signer = forged_signer(
        "CN=Nacre s41 stale CRL signer,O=Nacre tests,C=FR",
        0x64,
        44,
        usual_validity(),
        Extensions::Usual,
    );
    let pdf = forge::with_dss(
        &forge::signed(&signer, Level::B),
        &[],
        &[intermediate_crl(SystemTime::now() - hours(25))],
    );
    let source = bench_revocation();

    confront_signatures(
        "s41-fresh-revocation",
        &pdf,
        Some(&source),
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&pdf, Some(&source), &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        (
            Indication::Indeterminate,
            Some(SubIndication::CertificateChainGeneralFailure)
        )
    );
}

/// The `/M` rule, under both presets: a signer whose `notBefore` follows the `/M` of
/// 2026-10-22T08:00Z.
#[test]
#[ignore = "conformance"]
fn claimed_time_before_not_before() {
    let now = SystemTime::now();
    let not_before = now - hours(1);
    assert!(not_before > forge::instant(2026, 10, 22, 8, 0, 0));
    let signer = forged_signer(
        "CN=Nacre s41 late signer,O=Nacre tests,C=FR",
        0x65,
        45,
        (not_before, forge::instant(2036, 1, 1, 0, 0, 0)),
        Extensions::Usual,
    );
    let pdf = forge::with_dss(
        &forge::signed(&signer, Level::B),
        &[],
        &[intermediate_crl(now - Duration::from_secs(60))],
    );
    let source = bench_revocation();
    let expected = (
        Indication::Indeterminate,
        Some(SubIndication::SigConstraintsFailure),
    );

    confront_signatures(
        "s41-claimed-time",
        &pdf,
        Some(&source),
        &[expected],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&pdf, Some(&source), &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), expected);
}

/// The bench root's CRL, written at the bench's start.
fn root_crl() -> Vec<u8> {
    std::fs::read(nacre_conformance::pki_dir().join("root.crl")).unwrap()
}

/// A "not revoked" CRL of the intermediate issued at `issued`, then the bench root's CRL.
fn chain_crls(issued: SystemTime) -> [Vec<u8>; 2] {
    [intermediate_crl(issued), root_crl()]
}

const CONSTRAINTS: Verdict = (
    Indication::Indeterminate,
    Some(SubIndication::SigConstraintsFailure),
);
const GENERAL_FAILURE: Verdict = (
    Indication::Indeterminate,
    Some(SubIndication::CertificateChainGeneralFailure),
);
const FORMAT: Verdict = (Indication::TotalFailed, Some(SubIndication::FormatFailure));

/// n11 and m1: a bench B with no `/M`, then with `/M (garbage)`, its CRLs in `/DSS`.
#[test]
#[ignore = "conformance"]
fn claimed_time_missing() {
    let signer = BenchSigner::load();
    let crls = chain_crls(SystemTime::now() - hours(1));
    for (name, claimed) in [
        ("s43-claimed-time-missing", None),
        ("s43-claimed-time-garbage", Some(&b"garbage"[..])),
    ] {
        let pdf = forge::with_dss(
            &forge::custom_signed(&signer, b"ETSI.CAdES.detached", claimed),
            &[],
            &crls,
        );

        confront_signatures(name, &pdf, None, &[CONSTRAINTS], &ValidationPolicy::dss());
        let strict = nacre(&pdf, None, &ValidationPolicy::strict());
        assert_eq!(verdict(&strict), CONSTRAINTS, "{name}");
    }
}

/// n02: a `/M` of 2027-06-01 on a signer valid now and until 30 days from now.
#[test]
#[ignore = "conformance"]
fn claimed_time_after_not_after() {
    let now = SystemTime::now();
    let signer = forged_signer(
        "CN=Nacre s43 short-lived signer,O=Nacre tests,C=FR",
        0x71,
        51,
        (forge::instant(2026, 1, 1, 0, 0, 0), now + hours(30 * 24)),
        Extensions::Usual,
    );
    let pdf = forge::with_dss(
        &forge::custom_signed(&signer, b"ETSI.CAdES.detached", Some(b"D:20270601000000Z")),
        &[],
        &chain_crls(now - hours(1)),
    );

    confront_signatures(
        "s43-claimed-time-after-not-after",
        &pdf,
        None,
        &[CONSTRAINTS],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&pdf, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), CONSTRAINTS);
}

/// n01c, n01d and e1: a signer expired yesterday, its CRL in `/DSS` issued after or before
/// its `notAfter`; e1 is a B-T stamped three days ago, while the signer was valid.
#[test]
#[ignore = "conformance"]
fn data_issued_after_not_after() {
    let now = SystemTime::now();
    let expired = |subject: &str, secret: u8, offset: u64| {
        forged_signer(
            subject,
            secret,
            offset,
            (forge::instant(2026, 1, 1, 0, 0, 0), now - hours(24)),
            Extensions::Usual,
        )
    };
    let out_of_bounds = (
        Indication::Indeterminate,
        Some(SubIndication::OutOfBoundsNoPoe),
    );

    let signer = expired("CN=Nacre s43 n01c signer,O=Nacre tests,C=FR", 0x72, 52);
    let late = forge::with_dss(
        &forge::signed(&signer, Level::B),
        &[],
        &chain_crls(now - hours(1)),
    );
    confront_signatures(
        "s43-n01c-crl-after-not-after",
        &late,
        None,
        &[GENERAL_FAILURE],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&late, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), out_of_bounds);

    let signer = expired("CN=Nacre s43 n01d signer,O=Nacre tests,C=FR", 0x73, 53);
    let early = forge::with_dss(
        &forge::signed(&signer, Level::B),
        &[],
        &chain_crls(now - hours(48)),
    );
    confront_signatures(
        "s43-n01d-crl-before-not-after",
        &early,
        None,
        &[(
            Indication::Indeterminate,
            Some(SubIndication::OutOfBoundsNotRevoked),
        )],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&early, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), out_of_bounds);

    let signer = expired("CN=Nacre s43 e1 signer,O=Nacre tests,C=FR", 0x74, 54);
    let tsa = ForgedTsa {
        key: bench_key("tsa"),
        certificates: vec![
            bench_certificate("tsa.cert.pem"),
            bench_certificate("intermediate.cert.pem"),
        ],
        gen_time: DateTime::from_system_time(now - hours(72)).unwrap(),
        imprint: None,
    };
    let stamped = forge::with_dss(
        &forge::signed(&signer, Level::T { tsa: &tsa }),
        &[],
        &chain_crls(now - hours(1)),
    );
    confront_signatures(
        "s43-e1-stamped-crl-after-not-after",
        &stamped,
        None,
        &[GENERAL_FAILURE],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&stamped, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), GENERAL_FAILURE, "{:?}", strict.defect);
    assert!(strict.best_signature_time.is_some());
}

/// n04: a B-T whose timestamp authority repeats `keyUsage`, the signer's CRLs in `/DSS`.
#[test]
#[ignore = "conformance"]
fn malformed_timestamp_certificate_policy() {
    let now = SystemTime::now();
    let signer = forged_signer(
        "CN=Nacre s43 stamped signer,O=Nacre tests,C=FR",
        0x75,
        55,
        usual_validity(),
        Extensions::Usual,
    );
    let tsa_key = forge::key(&[0x76; 32]);
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    let tsa = forge::issue_with(
        Role::Tsa,
        "CN=Nacre s43 malformed TSA,O=Nacre tests,C=FR",
        fresh_serial(56),
        &tsa_key,
        Some(&intermediate),
        &bench_key("intermediate"),
        (x509(usual_validity().0), x509(usual_validity().1)),
        Extensions::RepeatedKeyUsage,
    );
    let authority = ForgedTsa {
        key: tsa_key,
        certificates: vec![
            tsa.to_der().unwrap(),
            bench_certificate("intermediate.cert.pem"),
        ],
        gen_time: DateTime::from_system_time(now).unwrap(),
        imprint: None,
    };
    let pdf = forge::with_dss(
        &forge::signed(&signer, Level::T { tsa: &authority }),
        &[],
        &chain_crls(now - hours(1)),
    );

    let error = confront_error(
        "s43-malformed-timestamp-certificate",
        &pdf,
        &ValidationPolicy::dss(),
    );
    assert!(matches!(error, Error::MalformedCertificate), "{error:?}");
    let strict = nacre(&pdf, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), PASSED, "{:?}", strict.defect);
    assert_eq!(strict.best_signature_time, None);
}

/// n06 and n07: a sound bench CMS under `/SubFilter /adbe.x509.rsa_sha1`, then under a
/// name no one defines.
#[test]
#[ignore = "conformance"]
fn unsupported_sub_filters_policy() {
    let signer = BenchSigner::load();
    let crls = chain_crls(SystemTime::now() - hours(1));
    for (name, sub_filter) in [
        ("s43-subfilter-x509-rsa-sha1", &b"adbe.x509.rsa_sha1"[..]),
        ("s43-subfilter-unknown", b"Nacre.unknown"),
    ] {
        let pdf = forge::with_dss(
            &forge::custom_signed(&signer, sub_filter, Some(b"D:20261022080000Z")),
            &[],
            &crls,
        );

        confront_signatures(name, &pdf, None, &[PASSED], &ValidationPolicy::dss());
        let strict = nacre(&pdf, None, &ValidationPolicy::strict());
        assert_eq!(verdict(&strict), FORMAT, "{name}");
    }
}

/// n08 and n08b: a bench B whose field's `/V` is patched to `7`, then to the page's content
/// stream `4 0 R`.
#[test]
#[ignore = "conformance"]
fn unreadable_signature_value_policy() {
    let signed = forge::signed(&BenchSigner::load(), Level::B);
    let value = Document::parse(&signed).unwrap().signature_fields()[0]
        .value
        .unwrap();
    let reference = format!("/V {} {} R", value.number, value.generation);
    for (name, to) in [
        ("s43-v-direct", &b"/V 7"[..]),
        ("s43-v-stream", b"/V 4 0 R"),
    ] {
        let pdf = forge::patch(&signed, reference.as_bytes(), to);

        confront_signatures(name, &pdf, None, &[], &ValidationPolicy::dss());
        let strict = judged(&pdf, None, &ValidationPolicy::strict()).unwrap();
        assert_eq!(strict.len(), 1, "{name}");
        assert_eq!(verdict(&strict[0]), FORMAT, "{name}");
    }
}

/// Switch "misplaced xref": pyHanko's `startxref` one byte before `xref`, then
/// `xref-misplaced-startxref.pdf`, whose last `startxref` names the end of line before it.
#[test]
#[ignore = "conformance"]
fn misplaced_xref_policy() {
    let refused = |pdf: &[u8]| {
        let error = judged(pdf, None, &ValidationPolicy::strict()).unwrap_err();
        assert!(
            matches!(error, Error::Pdf(nacre_pdf::Error::NotAnXrefSection { .. })),
            "{error:?}"
        );
    };
    let hostile = include_bytes!("../../nacre-pdf/tests/corpus/hostile/startxref-off-by-one.pdf");
    confront_signatures(
        "s45-startxref-off-by-one",
        hostile,
        None,
        &[],
        &ValidationPolicy::dss(),
    );
    refused(hostile);

    let signed = include_bytes!("corpus/attacks/xref-misplaced-startxref.pdf");
    confront_signatures(
        "s45-xref-misplaced-startxref",
        signed,
        None,
        &[NO_CHAIN],
        &ValidationPolicy::dss(),
    );
    refused(signed);
}

/// p03, p04 and p04b: a bench B under `/SubFilter` removed, then `7`, then a string,
/// signed again over the patched bytes, its CRLs in `/DSS`.
#[test]
#[ignore = "conformance"]
fn missing_sub_filter_policy() {
    let signer = BenchSigner::load();
    let crls = chain_crls(SystemTime::now() - hours(1));
    let signed = forge::custom_signed(&signer, b"ETSI.CAdES.detached", Some(b"D:20261022080000Z"));
    for (name, to) in [
        ("s45-p03-subfilter-missing", &b""[..]),
        ("s45-p04-subfilter-integer", b"/SubFilter 7"),
        ("s45-p04b-subfilter-string", b"/SubFilter (adbe)"),
    ] {
        let pdf = forge::with_dss(
            &forge::resign(
                &forge::patch(&signed, b"/SubFilter /ETSI.CAdES.detached", to),
                &signer,
            ),
            &[],
            &crls,
        );

        confront_signatures(name, &pdf, None, &[PASSED], &ValidationPolicy::dss());
        let strict = nacre(&pdf, None, &ValidationPolicy::strict());
        assert_eq!(verdict(&strict), FORMAT, "{name}");
    }
}

/// The bench intermediate's CRL issued at `this_update`, revoking nothing, whose
/// `expiredCertsOnCRL` is `from`.
fn intermediate_crl_with_expired_certs(this_update: SystemTime, from: SystemTime) -> Vec<u8> {
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    forge::crl_with_expired_certs_on_crl(
        &intermediate,
        &bench_key("intermediate"),
        x509(this_update),
        x509(this_update + hours(30 * 24)),
        x509(from),
    )
}

/// p09 and s1: a signer expired yesterday, the intermediate's CRL issued an hour ago with
/// an `expiredCertsOnCRL` 60 days back; s1 is a B-T stamped five days ago.
#[test]
#[ignore = "conformance"]
fn expired_certs_on_crl_policy() {
    let now = SystemTime::now();
    let crls = [
        intermediate_crl_with_expired_certs(now - hours(1), now - hours(60 * 24)),
        root_crl(),
    ];
    let expired = |subject: &str, secret: u8, offset: u64| {
        forged_signer(
            subject,
            secret,
            offset,
            (forge::instant(2026, 1, 1, 0, 0, 0), now - hours(24)),
            Extensions::Usual,
        )
    };

    let signer = expired("CN=Nacre s45 p09 signer,O=Nacre tests,C=FR", 0x81, 61);
    let basic = forge::with_dss(&forge::signed(&signer, Level::B), &[], &crls);
    confront_signatures(
        "s45-p09-expired-certs-on-crl",
        &basic,
        None,
        &[(
            Indication::Indeterminate,
            Some(SubIndication::OutOfBoundsNotRevoked),
        )],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&basic, None, &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        (
            Indication::Indeterminate,
            Some(SubIndication::OutOfBoundsNoPoe)
        )
    );

    let signer = expired("CN=Nacre s45 s1 signer,O=Nacre tests,C=FR", 0x82, 62);
    let tsa = ForgedTsa {
        key: bench_key("tsa"),
        certificates: vec![
            bench_certificate("tsa.cert.pem"),
            bench_certificate("intermediate.cert.pem"),
        ],
        gen_time: DateTime::from_system_time(now - hours(5 * 24)).unwrap(),
        imprint: None,
    };
    let stamped = forge::with_dss(&forge::signed(&signer, Level::T { tsa: &tsa }), &[], &crls);
    let ours = confront_signatures(
        "s45-s1-stamped-expired-certs-on-crl",
        &stamped,
        None,
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    assert!(ours[0].best_signature_time.is_some());
    let strict = nacre(&stamped, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), GENERAL_FAILURE, "{:?}", strict.defect);
}

/// A CA of serial `offset` under the bench root, with `extensions`, valid until
/// `not_after`, and a signer under it.
fn forged_ca(
    subject: &str,
    secret: u8,
    offset: u64,
    not_after: SystemTime,
    extensions: Extensions,
) -> (Certificate, SigningKey, ChainSigner) {
    let ca_key = forge::key(&[secret; 32]);
    let root = Certificate::from_der(&bench_certificate("root.cert.pem")).unwrap();
    let ca = forge::issue_with(
        Role::Ca,
        subject,
        fresh_serial(offset),
        &ca_key,
        Some(&root),
        &bench_key("root"),
        (x509(usual_validity().0), x509(not_after)),
        extensions,
    );
    let key = forge::key(&[secret + 1; 32]);
    let signer = forge::issue(
        Role::Signer,
        "CN=Nacre s45 signer under a forged CA,O=Nacre tests,C=FR",
        fresh_serial(offset + 1),
        &key,
        Some(&ca),
        &ca_key,
    );
    let chain = ChainSigner {
        key,
        chain: vec![signer.to_der().unwrap(), ca.to_der().unwrap()],
    };
    (ca, ca_key, chain)
}

/// A CRL of `issuer` issued at `this_update`, revoking nothing.
fn crl_at(issuer: &Certificate, key: &SigningKey, this_update: SystemTime) -> Vec<u8> {
    forge::crl(
        issuer,
        key,
        x509(this_update),
        x509(this_update + hours(30 * 24)),
        &[],
    )
}

/// p06b and p06d: a CA under the bench root expired yesterday, its signer's CRL and the
/// root's both issued two days ago; p06b is a B-T stamped three days ago, p06d a B.
#[test]
#[ignore = "conformance"]
fn issuer_out_of_validity_policy() {
    let now = SystemTime::now();
    let (ca, ca_key, signer) = forged_ca(
        "CN=Nacre s45 expired CA,O=Nacre tests,C=FR",
        0x83,
        63,
        now - hours(24),
        Extensions::Usual,
    );
    let root = Certificate::from_der(&bench_certificate("root.cert.pem")).unwrap();
    let crls = [
        crl_at(&ca, &ca_key, now - hours(48)),
        crl_at(&root, &bench_key("root"), now - hours(48)),
        intermediate_crl(now - hours(1)),
    ];
    let out_of_bounds = (
        Indication::Indeterminate,
        Some(SubIndication::RevocationOutOfBoundsNoPoe),
    );
    let tsa = ForgedTsa {
        key: bench_key("tsa"),
        certificates: vec![
            bench_certificate("tsa.cert.pem"),
            bench_certificate("intermediate.cert.pem"),
        ],
        gen_time: DateTime::from_system_time(now - hours(72)).unwrap(),
        imprint: None,
    };

    let stamped = forge::with_dss(&forge::signed(&signer, Level::T { tsa: &tsa }), &[], &crls);
    confront_signatures(
        "s45-p06b-issuer-expired-t",
        &stamped,
        None,
        &[out_of_bounds],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&stamped, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), out_of_bounds, "{:?}", strict.defect);
    assert!(strict.best_signature_time.is_some());

    let basic = forge::with_dss(&forge::signed(&signer, Level::B), &[], &crls);
    confront_signatures(
        "s45-p06d-issuer-expired-b",
        &basic,
        None,
        &[out_of_bounds],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&basic, None, &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        (
            Indication::Indeterminate,
            Some(SubIndication::OutOfBoundsNoPoe)
        )
    );
}

/// s4 with data: a B under a CA of the bench root without `subjectKeyIdentifier`, fresh
/// CRLs of that CA and of the root in `/DSS`.
#[test]
#[ignore = "conformance"]
fn ca_without_key_identifier_policy() {
    let now = SystemTime::now();
    let (ca, ca_key, signer) = forged_ca(
        "CN=Nacre s45 CA without key identifier,O=Nacre tests,C=FR",
        0x85,
        65,
        usual_validity().1,
        Extensions::WithoutKeyIdentifier,
    );
    let root = Certificate::from_der(&bench_certificate("root.cert.pem")).unwrap();
    let pdf = forge::with_dss(
        &forge::signed(&signer, Level::B),
        &[],
        &[
            crl_at(&ca, &ca_key, now - hours(1)),
            crl_at(&root, &bench_key("root"), now - hours(1)),
        ],
    );

    let ours = confront_signatures(
        "s45-s4-ca-without-key-identifier",
        &pdf,
        None,
        &[GENERAL_FAILURE],
        &ValidationPolicy::dss(),
    );
    assert!(
        matches!(
            ours[0].defect,
            Some(Defect::CaKeyIdentifierMissing { depth: 1 })
        ),
        "{:?}",
        ours[0].defect
    );
    let strict = nacre(&pdf, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), GENERAL_FAILURE, "{:?}", strict.defect);
    assert!(
        matches!(
            strict.defect,
            Some(Defect::CaKeyIdentifierMissing { depth: 1 })
        ),
        "{:?}",
        strict.defect
    );
}

const REVOKED: Verdict = (Indication::Indeterminate, Some(SubIndication::RevokedNoPoe));
const REVOCATION_OUT_OF_BOUNDS: Verdict = (
    Indication::Indeterminate,
    Some(SubIndication::RevocationOutOfBoundsNoPoe),
);

/// The bench TSA's token dated `gen_time`, carrying the TSA and the intermediate.
fn bench_tsa_at(gen_time: SystemTime) -> ForgedTsa {
    ForgedTsa {
        key: bench_key("tsa"),
        certificates: vec![
            bench_certificate("tsa.cert.pem"),
            bench_certificate("intermediate.cert.pem"),
        ],
        gen_time: DateTime::from_system_time(gen_time).unwrap(),
        imprint: None,
    }
}

/// k1: a B-T stamped five days ago by a TSA under a CA of the bench root without
/// `subjectKeyIdentifier`, the signer revoked an hour ago. The token proves no time.
#[test]
#[ignore = "conformance"]
fn tsa_ca_without_key_identifier_policy() {
    let now = SystemTime::now();
    let root = Certificate::from_der(&bench_certificate("root.cert.pem")).unwrap();
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    let ca_key = forge::key(&[0x91; 32]);
    let ca = forge::issue_with(
        Role::Ca,
        "CN=Nacre s46 TSA CA without key identifier,O=Nacre tests,C=FR",
        fresh_serial(70),
        &ca_key,
        Some(&root),
        &bench_key("root"),
        (x509(now - hours(60 * 24)), x509(now + hours(60 * 24))),
        Extensions::WithoutKeyIdentifier,
    );
    let tsa_key = forge::key(&[0x92; 32]);
    let tsa = forge::issue_with(
        Role::Tsa,
        "CN=Nacre s46 TSA under a CA without key identifier,O=Nacre tests,C=FR",
        fresh_serial(71),
        &tsa_key,
        Some(&ca),
        &ca_key,
        (x509(now - hours(50 * 24)), x509(now + hours(50 * 24))),
        Extensions::Usual,
    );
    let authority = ForgedTsa {
        key: tsa_key,
        certificates: vec![tsa.to_der().unwrap(), ca.to_der().unwrap()],
        ..bench_tsa_at(now - hours(5 * 24))
    };
    let signer = forged_signer(
        "CN=Nacre s46 k1 signer,O=Nacre tests,C=FR",
        0x93,
        72,
        usual_validity(),
        Extensions::Usual,
    );
    let leaf = Certificate::from_der(&signer.chain[0]).unwrap();
    let pdf = forge::with_dss(
        &forge::signed(&signer, Level::T { tsa: &authority }),
        &[],
        &[
            forge::crl(
                &intermediate,
                &bench_key("intermediate"),
                x509(now),
                x509(now + hours(30 * 24)),
                &[(&leaf, x509(now - hours(1)))],
            ),
            crl_at(&root, &bench_key("root"), now - hours(1)),
            crl_at(&ca, &ca_key, now - hours(1)),
        ],
    );

    let ours = confront_signatures(
        "s46-k1-tsa-ca-without-key-identifier",
        &pdf,
        None,
        &[REVOKED],
        &ValidationPolicy::dss(),
    );
    assert_eq!(ours[0].best_signature_time, None);
    let strict = nacre(&pdf, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), REVOKED, "{:?}", strict.defect);
    assert_eq!(strict.best_signature_time, None);
}

/// v3 and v5: a B-T stamped five days ago under a CA of the bench root expired
/// yesterday. In v3 the CA's CRL of three days ago revokes the signer four days ago; in v5
/// the root's revokes the CA four days ago and the CA's says "good".
#[test]
#[ignore = "conformance"]
fn issuer_of_revoked_data_policy() {
    let now = SystemTime::now();
    let root = Certificate::from_der(&bench_certificate("root.cert.pem")).unwrap();
    let tsa = bench_tsa_at(now - hours(5 * 24));
    let ca_crl = |ca: &Certificate, key: &SigningKey, revoked: &[(&Certificate, Time)]| {
        forge::crl(
            ca,
            key,
            x509(now - hours(3 * 24)),
            x509(now + hours(30 * 24)),
            revoked,
        )
    };
    let four_days_ago = x509(now - hours(4 * 24));

    let (ca, ca_key, signer) = forged_ca(
        "CN=Nacre s46 v3 expired CA,O=Nacre tests,C=FR",
        0x94,
        73,
        now - hours(24),
        Extensions::Usual,
    );
    let leaf = Certificate::from_der(&signer.chain[0]).unwrap();
    let v3 = forge::with_dss(
        &forge::signed(&signer, Level::T { tsa: &tsa }),
        &[],
        &[
            ca_crl(&ca, &ca_key, &[(&leaf, four_days_ago)]),
            ca_crl(&root, &bench_key("root"), &[]),
            intermediate_crl(now - hours(1)),
            root_crl(),
        ],
    );
    let ours = confront_signatures(
        "s46-v3-revoked-by-expired-ca",
        &v3,
        None,
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    assert!(ours[0].best_signature_time.is_some());
    let strict = nacre(&v3, None, &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        REVOCATION_OUT_OF_BOUNDS,
        "{:?}",
        strict.defect
    );

    let (ca, ca_key, signer) = forged_ca(
        "CN=Nacre s46 v5 expired CA,O=Nacre tests,C=FR",
        0x96,
        75,
        now - hours(24),
        Extensions::Usual,
    );
    let v5 = forge::with_dss(
        &forge::signed(&signer, Level::T { tsa: &tsa }),
        &[],
        &[
            ca_crl(&ca, &ca_key, &[]),
            ca_crl(&root, &bench_key("root"), &[(&ca, four_days_ago)]),
            intermediate_crl(now - hours(1)),
            root_crl(),
        ],
    );
    confront_signatures(
        "s46-v5-expired-ca-revoked",
        &v5,
        None,
        &[REVOCATION_OUT_OF_BOUNDS],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&v5, None, &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        REVOCATION_OUT_OF_BOUNDS,
        "{:?}",
        strict.defect
    );
}

/// e2 and e3: a bench B whose `/DSS` holds the root's CRL and a "good" OCSP response on
/// the signer produced three days ago by a delegate of the intermediate, embedded, valid
/// then and expired yesterday (e2) or still valid (e3).
#[test]
#[ignore = "conformance"]
fn delegated_responder_policy() {
    let now = SystemTime::now();
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    let signer = forged_signer(
        "CN=Nacre s46 e2 signer,O=Nacre tests,C=FR",
        0x98,
        77,
        usual_validity(),
        Extensions::Usual,
    );
    let leaf = Certificate::from_der(&signer.chain[0]).unwrap();
    let basic = forge::signed(&signer, Level::B);
    let with_delegate = |secret: u8, offset: u64, not_after: SystemTime| {
        let key = forge::key(&[secret; 32]);
        let delegate = forge::issue_with(
            Role::OcspResponder,
            &format!("CN=Nacre s46 OCSP delegate {offset},O=Nacre tests,C=FR"),
            fresh_serial(offset),
            &key,
            Some(&intermediate),
            &bench_key("intermediate"),
            (x509(now - hours(30 * 24)), x509(not_after)),
            Extensions::Usual,
        );
        let response = forge::ocsp(
            &leaf,
            &intermediate,
            &key,
            &delegate,
            Some(&delegate),
            x509(now - hours(3 * 24)),
            None,
            &[],
        );
        forge::with_dss_ocsps(&basic, &[], &[root_crl()], &[response])
    };

    let e2 = with_delegate(0x99, 78, now - hours(24));
    confront_signatures(
        "s46-e2-ocsp-delegate-expired-since",
        &e2,
        None,
        &[REVOCATION_OUT_OF_BOUNDS],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&e2, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), GENERAL_FAILURE, "{:?}", strict.defect);

    let e3 = with_delegate(0x9a, 79, now + hours(30 * 24));
    confront_signatures(
        "s46-e3-ocsp-delegate-valid",
        &e3,
        None,
        &[PASSED],
        &ValidationPolicy::dss(),
    );
}

/// e4 and e5: a signer expired yesterday, an intermediate-signed "good" OCSP response of
/// an hour ago whose `archiveCutoff` is 60 days back; e4 is a B, e5 a B-T stamped five days
/// ago.
#[test]
#[ignore = "conformance"]
fn archive_cutoff_policy() {
    let now = SystemTime::now();
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    let expired = |subject: &str, secret: u8, offset: u64| {
        forged_signer(
            subject,
            secret,
            offset,
            (forge::instant(2026, 1, 1, 0, 0, 0), now - hours(24)),
            Extensions::Usual,
        )
    };
    let response = |signer: &ChainSigner| {
        forge::ocsp(
            &Certificate::from_der(&signer.chain[0]).unwrap(),
            &intermediate,
            &bench_key("intermediate"),
            &intermediate,
            None,
            x509(now - hours(1)),
            None,
            &[forge::OcspExtension::archive_cutoff(
                x509(now - hours(60 * 24)),
                false,
                forge::OcspPlace::Single,
            )],
        )
    };

    let signer = expired("CN=Nacre s46 e4 signer,O=Nacre tests,C=FR", 0x9b, 80);
    let e4 = forge::with_dss_ocsps(
        &forge::signed(&signer, Level::B),
        &[],
        &[root_crl()],
        &[response(&signer)],
    );
    confront_signatures(
        "s46-e4-expired-ocsp-archive-cutoff",
        &e4,
        None,
        &[(
            Indication::Indeterminate,
            Some(SubIndication::OutOfBoundsNotRevoked),
        )],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&e4, None, &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        (
            Indication::Indeterminate,
            Some(SubIndication::OutOfBoundsNoPoe)
        )
    );

    let signer = expired("CN=Nacre s46 e5 signer,O=Nacre tests,C=FR", 0x9c, 81);
    let tsa = bench_tsa_at(now - hours(5 * 24));
    let e5 = forge::with_dss_ocsps(
        &forge::signed(&signer, Level::T { tsa: &tsa }),
        &[],
        &[root_crl(), intermediate_crl(now - hours(1))],
        &[response(&signer)],
    );
    let ours = confront_signatures(
        "s46-e5-stamped-expired-ocsp-archive-cutoff",
        &e5,
        None,
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    assert!(ours[0].best_signature_time.is_some());
    let strict = nacre(&e5, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), GENERAL_FAILURE, "{:?}", strict.defect);
}

/// a7: a B-T stamped five days ago under a CA of the bench root, whose only data is a
/// "good" response by a delegate of the root, embedded, produced after the bench root's CRL
/// and expired since. DSS exempts the anchor's delegate; `strict()` does not.
#[test]
#[ignore = "conformance"]
fn anchor_delegated_responder_policy() {
    let root = Certificate::from_der(&bench_certificate("root.cert.pem")).unwrap();
    let root_crl_date = nacre_revocation::Crl::from_der(&root_crl())
        .unwrap()
        .this_update();
    let produced = SystemTime::now().max(root_crl_date) + Duration::from_secs(1);
    let delegate_key = forge::key(&[0x9e; 32]);
    let delegate = forge::issue_with(
        Role::OcspResponder,
        "CN=Nacre s18 a7 root OCSP delegate,O=Nacre tests,C=FR",
        fresh_serial(84),
        &delegate_key,
        Some(&root),
        &bench_key("root"),
        (
            x509(produced - hours(30 * 24)),
            x509(produced + Duration::from_secs(5)),
        ),
        Extensions::Usual,
    );
    let (ca, ca_key, signer) = forged_ca(
        "CN=Nacre s18 a7 CA,O=Nacre tests,C=FR",
        0x9f,
        85,
        forge::instant(2036, 1, 1, 0, 0, 0),
        Extensions::Usual,
    );
    let response = forge::ocsp(
        &ca,
        &root,
        &delegate_key,
        &delegate,
        Some(&delegate),
        x509(produced),
        None,
        &[],
    );
    let now = SystemTime::now();
    let tsa = bench_tsa_at(now - hours(5 * 24));
    let a7 = forge::with_dss_ocsps(
        &forge::signed(&signer, Level::T { tsa: &tsa }),
        &[],
        &[crl_at(&ca, &ca_key, now - hours(1))],
        &[response],
    );
    while SystemTime::now() <= produced + Duration::from_secs(6) {
        std::thread::sleep(Duration::from_secs(1));
    }

    let source = bench_revocation();
    confront_signatures(
        "s18-a7-root-delegate-expired",
        &a7,
        Some(&source),
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&a7, Some(&source), &ValidationPolicy::strict());
    assert_eq!(
        verdict(&strict),
        REVOCATION_OUT_OF_BOUNDS,
        "{:?}",
        strict.defect
    );
}

/// u1: a B by a signer of the bench intermediate whose only data is a "good" response of
/// the intermediate, an hour old, holding a critical extension of an unknown OID in its
/// single response. DSS reads it; `strict()` refuses it.
#[test]
#[ignore = "conformance"]
fn critical_ocsp_extensions_policy() {
    let now = SystemTime::now();
    let intermediate = Certificate::from_der(&bench_certificate("intermediate.cert.pem")).unwrap();
    let signer = forged_signer(
        "CN=Nacre s18 u1 signer,O=Nacre tests,C=FR",
        0xa1,
        86,
        usual_validity(),
        Extensions::Usual,
    );
    let unknown = forge::OcspExtension {
        oid: der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.18"),
        value: der::asn1::Null.to_der().unwrap(),
        critical: true,
        place: forge::OcspPlace::Single,
    };
    let response = forge::ocsp(
        &Certificate::from_der(&signer.chain[0]).unwrap(),
        &intermediate,
        &bench_key("intermediate"),
        &intermediate,
        None,
        x509(now - hours(1)),
        None,
        &[unknown],
    );
    let u1 = forge::with_dss_ocsps(
        &forge::signed(&signer, Level::B),
        &[],
        &[root_crl()],
        &[response],
    );

    confront_signatures(
        "s18-u1-critical-unknown-single",
        &u1,
        None,
        &[PASSED],
        &ValidationPolicy::dss(),
    );
    let strict = nacre(&u1, None, &ValidationPolicy::strict());
    assert_eq!(verdict(&strict), GENERAL_FAILURE, "{:?}", strict.defect);
}
