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
/// `source` under `policy`, and that DSS reports the PAdES level `profile`; Nacre gives no
/// level before s18.
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
        (ours.report.indication(), ours.report.sub_indication()),
        (indication, sub),
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
