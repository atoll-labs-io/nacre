#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The campaign (AC4, AC5): every committed corpus and the bench cases forged at run time,
//! each judged once by the running DSS, then by Nacre under `dss()` and under `strict()`,
//! with the bench root as anchor, the current time and the bench revocation source.
//!
//! Each signature, matched to DSS's by field name, gives its indication, sub-indication and
//! level, and each file its signature count. DSS answering an HTTP error status and Nacre
//! returning `Err` agree, the status and body DSS sent kept as `<case>.error.txt`; a request
//! that gets no answer, or an answer that is not a DSS report, fails the campaign. So does a
//! DSS that does not answer at start, before any case is judged. Under `dss()` any
//! difference fails. Under `strict()` a difference is
//! explained by the smallest set of switches that, turned off from `strict()`, gives DSS's
//! verdict on the file, single switches first, then pairs, then triples; one no such set
//! explains fails.
//! Both tables go to `<reports_dir>/campaign-dss.md` and `campaign-strict.md`, beside DSS's
//! `campaign-*.xml` reports; `conformance/campaign/run.sh` keeps them.

mod support;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64ct::{Base64, Encoding};
use der::asn1::{BitString, GeneralizedTime, Null, ObjectIdentifier, OctetString};
use der::{Any, DateTime, Decode, Encode};
use nacre_cms::Attribute;
use nacre_conformance::Dss;
use nacre_core::{Indication, RevocationSource, SignatureLevel, SubIndication, TimestampAuthority};
use nacre_pades::Level;
use nacre_pdf::{Dictionary, Document, Object};
use nacre_revocation::{Crl, CrlReason, Fallback, HttpCrlSource, HttpOcspSource};
use nacre_tsp::HttpTsa;
use nacre_validate::{TrustAnchors, ValidationPolicy, validate_with_policy};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use support::forge::{
    self, ChainSigner, Ess, Extensions, ForgedTsa, OcspExtension, OcspPlace, Role, Signature,
};
use support::{BenchSigner, SWITCHES, bench_certificate, bench_key};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::KeyUsages;
use x509_cert::time::Time;

const DSS_URL: &str = "http://127.0.0.1:18080";
const TSA_URL: &str = "http://127.0.0.1:18081/cgi-bin/tsa";
const DOCUMENT_TSA_URL: &str = "http://127.0.0.1:18081/cgi-bin/tsa2";

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);

/// One signature's verdict: indication, sub-indication and level.
type Row = (Indication, Option<SubIndication>, Option<SignatureLevel>);

/// What a validator says of one file: an error, or each signature's row with its field
/// name, sorted by field name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Error,
    Signatures(Vec<(String, Row)>),
}

impl Outcome {
    fn sorted(mut rows: Vec<(String, Row)>) -> Self {
        rows.sort_by_key(|(field, row)| (field.clone(), format!("{row:?}")));
        Self::Signatures(rows)
    }
}

fn bench_revocation() -> Fallback<HttpOcspSource, HttpCrlSource> {
    Fallback::new(
        HttpOcspSource::allowing_loopback(),
        HttpCrlSource::allowing_loopback(),
    )
}

/// The DSS the campaign calls, by `NACRE_DSS_URL` as [`Dss::from_env`] reads it; [`Dss::new`]
/// refuses any URL off this machine.
fn dss_url() -> String {
    let url = std::env::var("NACRE_DSS_URL").unwrap_or_else(|_| DSS_URL.to_owned());
    Dss::new(&url).unwrap();
    url.trim_end_matches('/').to_owned()
}

/// An agent that hands back an HTTP error status as a response, so its body can be kept.
fn plain_agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(120)))
            .build(),
    )
}

/// Fails at once, naming the URL, when DSS does not answer.
fn dss_answers() {
    let url = dss_url();
    if let Err(error) = plain_agent().get(&url).call() {
        panic!("DSS does not answer at {url} ({error}): start the bench, conformance/README.md");
    }
}

/// DSS's answer to an error status, asked again with the same request so its body is kept as
/// `<reports_dir>/<name>.error.txt`.
fn keep_error(name: &str, pdf: &[u8], status: u16) {
    let request = serde_json::json!({
        "signedDocument": { "bytes": Base64::encode_string(pdf), "name": name },
        "originalDocuments": [],
        "policy": null,
        "signatureId": null,
    });
    let response = plain_agent()
        .post(format!(
            "{}/services/rest/validation/validateSignature",
            dss_url()
        ))
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&request).unwrap())
        .unwrap_or_else(|error| panic!("{name}: DSS stopped answering ({error})"));
    let again = response.status().as_u16();
    assert_eq!(again, status, "{name}: DSS answered {status}, then {again}");
    let body = response.into_body().read_to_string().unwrap();
    let dir = nacre_conformance::reports_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join(format!("{name}.error.txt")),
        format!("HTTP {status}\n\n{body}\n"),
    )
    .unwrap();
}

/// DSS's verdict on `pdf`, kept as `<reports_dir>/<name>.json` and `.xml`; each signature's
/// field is read from the kept JSON. Only an HTTP error status DSS itself sent is an
/// [`Outcome::Error`]; any other failure stops the campaign.
fn dss(name: &str, pdf: &[u8]) -> Outcome {
    let reports = match Dss::from_env().unwrap().validate(name, pdf) {
        Ok(reports) => reports,
        Err(nacre_conformance::Error::Http(ureq::Error::StatusCode(status))) => {
            keep_error(name, pdf, status);
            return Outcome::Error;
        }
        Err(error) => panic!("{name}: no DSS verdict: {error}"),
    };
    let json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(nacre_conformance::reports_dir().join(format!("{name}.json"))).unwrap(),
    )
    .unwrap();
    let fields = json
        .pointer("/DiagnosticData/Signature")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let field = |id: &str| {
        fields
            .iter()
            .find(|signature| signature.get("Id").and_then(serde_json::Value::as_str) == Some(id))
            .and_then(|signature| signature.pointer("/PDFRevision/SignatureField/0/name"))
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| format!("?{id}"), str::to_owned)
    };
    Outcome::sorted(
        reports
            .signatures
            .iter()
            .map(|verdict| {
                let report = &verdict.report;
                (
                    field(&verdict.id),
                    (report.indication(), report.sub_indication(), report.level()),
                )
            })
            .collect(),
    )
}

/// Nacre's verdict on `pdf` under `policy`, now, with the bench root and the bench source.
fn nacre(pdf: &[u8], policy: &ValidationPolicy, anchors: &TrustAnchors) -> Outcome {
    let source = bench_revocation();
    let source: &dyn RevocationSource = &source;
    match validate_with_policy(pdf, anchors, SystemTime::now(), Some(source), policy) {
        Err(_) => Outcome::Error,
        Ok(results) => Outcome::sorted(
            results
                .into_iter()
                .map(|result| {
                    let report = result.report;
                    (
                        result.field,
                        (report.indication(), report.sub_indication(), report.level()),
                    )
                })
                .collect(),
        ),
    }
}

/// The smallest set of switches that, turned off from `strict()`, gives `expected` on `pdf`:
/// single switches first, then pairs, then triples.
fn explanation(
    pdf: &[u8],
    expected: &Outcome,
    anchors: &TrustAnchors,
) -> Option<Vec<&'static str>> {
    let count = SWITCHES.len();
    let mut sets: Vec<Vec<usize>> = (0..count).map(|a| vec![a]).collect();
    for a in 0..count {
        for b in a + 1..count {
            sets.push(vec![a, b]);
        }
    }
    for a in 0..count {
        for b in a + 1..count {
            for c in b + 1..count {
                sets.push(vec![a, b, c]);
            }
        }
    }
    sets.into_iter().find_map(|set| {
        let mut policy = ValidationPolicy::strict();
        for &index in &set {
            (SWITCHES[index].1)(&mut policy);
        }
        (nacre(pdf, &policy, anchors) == *expected)
            .then(|| set.iter().map(|&index| SWITCHES[index].0).collect())
    })
}

fn row_text(row: Option<&Row>) -> String {
    match row {
        None => "—".to_owned(),
        Some((indication, sub, level)) => {
            let level = level.map_or_else(
                || "no level".to_owned(),
                |level| format!("{:?} {:?}", level.form, level.profile),
            );
            match sub {
                Some(sub) => format!("{} / {} / {level}", indication.as_str(), sub.as_str()),
                None => format!("{} / {level}", indication.as_str()),
            }
        }
    }
}

/// The table lines of one file: one per field either side lists, then the count; `last`,
/// the explanation, goes on every row that differs.
fn lines(case: &str, theirs: &Outcome, ours: &Outcome, last: &str) -> Vec<String> {
    let (Outcome::Signatures(theirs), Outcome::Signatures(ours)) = (theirs, ours) else {
        let text = |outcome: &Outcome| match outcome {
            Outcome::Error => "error".to_owned(),
            Outcome::Signatures(rows) => format!("{} signature(s)", rows.len()),
        };
        let same = if theirs == ours { "=" } else { "≠" };
        return vec![format!(
            "| `{case}` | (file) | {} | {} | {same} | {last} |",
            text(theirs),
            text(ours)
        )];
    };
    let mut fields: Vec<&String> = theirs.iter().chain(ours.iter()).map(|(f, _)| f).collect();
    fields.sort();
    fields.dedup();
    let mut out: Vec<String> = fields
        .into_iter()
        .map(|field| {
            let pick = |rows: &[(String, Row)]| -> Vec<Row> {
                rows.iter()
                    .filter(|(name, _)| name == field)
                    .map(|(_, row)| *row)
                    .collect()
            };
            let (a, b) = (pick(theirs), pick(ours));
            let (same, why) = if a == b { ("=", "") } else { ("≠", last) };
            format!(
                "| `{case}` | `{field}` | {} | {} | {same} | {why} |",
                row_text(a.first()),
                row_text(b.first())
            )
        })
        .collect();
    let (same, why) = if theirs.len() == ours.len() {
        ("=", "")
    } else {
        ("≠", last)
    };
    out.push(format!(
        "| `{case}` | (count) | {} | {} | {same} | {why} |",
        theirs.len(),
        ours.len()
    ));
    out
}

/// Every `*.pdf` under `dir`, recursively, named after its path from the workspace.
fn committed(workspace: &Path, dir: &Path, cases: &mut Vec<(String, Vec<u8>)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.map(|entry| entry.unwrap().path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            committed(workspace, &path, cases);
        } else if path.extension().is_some_and(|e| e == "pdf") {
            let relative = path.strip_prefix(workspace).unwrap().with_extension("");
            let name = relative.to_str().unwrap().replace('/', "-");
            cases.push((name, std::fs::read(&path).unwrap()));
        }
    }
}

#[test]
#[ignore = "conformance"]
fn campaign() {
    dss_answers();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace = workspace.canonicalize().unwrap();
    let mut cases = Vec::new();
    for dir in [
        "crates/nacre-validate/tests/corpus",
        "crates/nacre-pdf/tests/corpus/hostile",
        "crates/nacre-pdf/tests/corpus/real",
        "conformance/corpus",
    ] {
        committed(&workspace, &workspace.join(dir), &mut cases);
    }
    let bench = Bench::new();
    cases.extend(bench.cases());
    bench.wait();

    let mut names: Vec<&String> = cases.iter().map(|(name, _)| name).collect();
    names.sort();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "two cases share a name");

    let root = bench_certificate("root.cert.pem");
    let anchors = TrustAnchors::from_certificates([root.as_slice()]).unwrap();
    let header = "| Case | Field | DSS | Nacre | | |\n| --- | --- | --- | --- | --- | --- |\n";
    let mut dss_table = String::from(header);
    let mut strict_table = String::from(header);
    let mut differ = Vec::new();
    let mut unexplained = Vec::new();
    let mut explained = 0;
    for (case, pdf) in &cases {
        let theirs = dss(&format!("campaign-{case}"), pdf);
        let lax = nacre(pdf, &ValidationPolicy::dss(), &anchors);
        if lax != theirs {
            differ.push(case.clone());
        }
        for line in lines(case, &theirs, &lax, "") {
            dss_table.push_str(&line);
            dss_table.push('\n');
        }
        let strict = nacre(pdf, &ValidationPolicy::strict(), &anchors);
        let reason = if strict == theirs {
            String::new()
        } else {
            match explanation(pdf, &theirs, &anchors) {
                Some(switches) => {
                    explained += 1;
                    switches
                        .iter()
                        .map(|switch| format!("`{switch}`"))
                        .collect::<Vec<_>>()
                        .join(" + ")
                }
                None => {
                    unexplained.push(case.clone());
                    "**unexplained**".to_owned()
                }
            }
        };
        for line in lines(case, &theirs, &strict, &reason) {
            strict_table.push_str(&line);
            strict_table.push('\n');
        }
    }

    let summary = |what: &str, count: usize| format!("\n{} cases, {count} {what}.\n", cases.len());
    dss_table.push_str(&summary("differ from DSS under `dss()`", differ.len()));
    strict_table.push_str(&summary(
        &format!(
            "explained by switches under `strict()`, {} unexplained",
            unexplained.len()
        ),
        explained,
    ));
    let reports = nacre_conformance::reports_dir();
    std::fs::create_dir_all(&reports).unwrap();
    std::fs::write(reports.join("campaign-dss.md"), &dss_table).unwrap();
    std::fs::write(reports.join("campaign-strict.md"), &strict_table).unwrap();

    assert!(differ.is_empty(), "differ from DSS under dss(): {differ:?}");
    assert!(
        unexplained.is_empty(),
        "unexplained under strict(): {unexplained:?}"
    );
}

fn ts(at: SystemTime) -> Time {
    Time::from(DateTime::from_system_time(at).unwrap())
}

/// `at` as a PDF date in UTC, for a `/M`.
fn claimed(at: SystemTime) -> Vec<u8> {
    let t = DateTime::from_system_time(at).unwrap();
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minutes(),
        t.seconds()
    )
    .into_bytes()
}

/// The `/M` of the spike's first cases.
const FIXED_CLAIMED: &[u8] = b"D:20261023080000Z";

/// `certificate` signed by `key` and `rest` after it, as a signer.
fn chain(key: &SigningKey, certificate: &Certificate, rest: &[&Certificate]) -> ChainSigner {
    ChainSigner {
        key: key.clone(),
        chain: std::iter::once(certificate)
            .chain(rest.iter().copied())
            .map(|c| c.to_der().unwrap())
            .collect(),
    }
}

/// A CRL of `issuer` issued at `at`, valid 30 days, revoking `revoked` with their reasons.
fn crl(
    issuer: &Certificate,
    key: &SigningKey,
    at: SystemTime,
    revoked: &[(&Certificate, SystemTime, Option<CrlReason>)],
) -> Vec<u8> {
    let entries: Vec<_> = revoked
        .iter()
        .map(|(certificate, date, reason)| (*certificate, ts(*date), *reason))
        .collect();
    forge::crl_with_reasons(issuer, key, ts(at), ts(at + 30 * DAY), &entries)
}

/// [`crl`] revoking nothing, given one more extension of `oid` (value `NULL`), critical or
/// not, then signed again.
fn crl_with_extension(
    issuer: &Certificate,
    key: &SigningKey,
    at: SystemTime,
    oid: &str,
    critical: bool,
) -> Vec<u8> {
    let der = crl(issuer, key, at, &[]);
    let mut list: CertificateList = CertificateList::from_der(&der).unwrap();
    list.tbs_cert_list
        .crl_extensions
        .get_or_insert_with(Vec::new)
        .push(Extension {
            extn_id: ObjectIdentifier::new_unwrap(oid),
            critical,
            extn_value: OctetString::new(Null.to_der().unwrap()).unwrap(),
        });
    let tbs = list.tbs_cert_list.to_der().unwrap();
    let signature: DerSignature = key.sign_prehash(&Sha256::digest(&tbs)).unwrap();
    list.signature = BitString::from_bytes(signature.as_bytes()).unwrap();
    list.to_der().unwrap()
}

/// An extension of `oid` whose value is the time `at`, as an `archiveCutoff` is.
fn time_extension(oid: &str, at: SystemTime, critical: bool, place: OcspPlace) -> OcspExtension {
    OcspExtension {
        oid: ObjectIdentifier::new_unwrap(oid),
        value: GeneralizedTime::from_system_time(at)
            .unwrap()
            .to_der()
            .unwrap(),
        critical,
        place,
    }
}

const ARCHIVE_CUTOFF: &str = "1.3.6.1.5.5.7.48.1.6";
const CRL_REFERENCES: &str = "1.3.6.1.5.5.7.48.1.3";
/// Under the arc RFC 5612 reserves for documentation.
const UNKNOWN: &str = "1.3.6.1.4.1.32473.99";

/// `pdf` with `/V n g R` of its first field patched to `to`, padded.
fn patch_value(pdf: &[u8], to: &[u8]) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let value = doc.signature_fields()[0].value.unwrap();
    let from = format!("/V {} {} R", value.number, value.generation).into_bytes();
    forge::patch(pdf, &from, to)
}

/// What every bench case is forged from: the bench PKI read at its start, and one time.
struct Bench {
    now: SystemTime,
    root: Certificate,
    root_key: SigningKey,
    intermediate: Certificate,
    intermediate_key: SigningKey,
    root_crl: Vec<u8>,
    intermediate_crl: Vec<u8>,
    /// Root-issued data forged for a CA of no CDP is dated here, after the bench's
    /// `root.crl`, which DSS also applies to that CA (research, traps).
    root_time: SystemTime,
    signer: BenchSigner,
    tsa: HttpTsa,
    document_tsa: HttpTsa,
}

impl Bench {
    fn new() -> Self {
        let read = |name: &str| std::fs::read(nacre_conformance::pki_dir().join(name)).unwrap();
        let root_crl = read("root.crl");
        let now = SystemTime::now();
        let root_time = (now - MINUTE)
            .max(Crl::from_der(&root_crl).unwrap().this_update() + Duration::from_secs(1));
        Self {
            now,
            root: Certificate::from_der(&bench_certificate("root.cert.pem")).unwrap(),
            root_key: bench_key("root"),
            intermediate: Certificate::from_der(&bench_certificate("intermediate.cert.pem"))
                .unwrap(),
            intermediate_key: bench_key("intermediate"),
            intermediate_crl: read("intermediate.crl"),
            root_crl,
            root_time,
            signer: BenchSigner::load(),
            tsa: HttpTsa::new(TSA_URL),
            document_tsa: HttpTsa::new(DOCUMENT_TSA_URL),
        }
    }

    /// Waits until every certificate meant to expire just after `root_time` has.
    fn wait(&self) {
        while SystemTime::now() <= self.root_time + 6 * Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// A serial no bench certificate uses, `code` keeping each forged one apart.
    fn serial(&self, code: u64) -> u64 {
        let seconds = self
            .now
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (seconds << 8) + code
    }

    /// A certificate of `role` for the key of secret `code`, issued by `issuer`.
    #[allow(clippy::too_many_arguments)]
    fn issued_with(
        &self,
        role: Role,
        code: u64,
        issuer: &Certificate,
        issuer_key: &SigningKey,
        not_before: SystemTime,
        not_after: SystemTime,
        extensions: Extensions,
    ) -> (SigningKey, Certificate) {
        let key = forge::key(&[u8::try_from(code).unwrap(); 32]);
        let certificate = forge::issue_with(
            role,
            &format!("CN=Nacre s18 campaign {code:02x},O=Nacre tests,C=FR"),
            self.serial(code),
            &key,
            Some(issuer),
            issuer_key,
            (ts(not_before), ts(not_after)),
            extensions,
        );
        (key, certificate)
    }

    fn issued(
        &self,
        role: Role,
        code: u64,
        issuer: &Certificate,
        issuer_key: &SigningKey,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> (SigningKey, Certificate) {
        self.issued_with(
            role,
            code,
            issuer,
            issuer_key,
            not_before,
            not_after,
            Extensions::Usual,
        )
    }

    /// A signer of the intermediate, valid over the given span.
    fn intermediate_signer(
        &self,
        code: u64,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> (ChainSigner, Certificate) {
        let (key, certificate) = self.issued(
            Role::Signer,
            code,
            &self.intermediate,
            &self.intermediate_key,
            not_before,
            not_after,
        );
        (
            chain(&key, &certificate, &[&self.intermediate]),
            certificate,
        )
    }

    /// A CA of the root, with `subjectKeyIdentifier`, valid over the given span.
    fn root_ca(
        &self,
        code: u64,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> (SigningKey, Certificate) {
        self.issued(
            Role::Ca,
            code,
            &self.root,
            &self.root_key,
            not_before,
            not_after,
        )
    }

    /// The intermediate's CRL issued at `at`, revoking `revoked`.
    fn intermediate_crl_at(
        &self,
        at: SystemTime,
        revoked: &[(&Certificate, SystemTime)],
    ) -> Vec<u8> {
        let entries: Vec<_> = revoked.iter().map(|(c, d)| (*c, *d, None)).collect();
        crl(&self.intermediate, &self.intermediate_key, at, &entries)
    }

    /// A token of the bench TSA (`tsa`) or document TSA (`tsa2`) dated `at`, over `imprint`
    /// when given.
    fn bench_tsa(&self, name: &str, at: SystemTime, imprint: Option<Vec<u8>>) -> ForgedTsa {
        ForgedTsa {
            key: bench_key(name),
            certificates: vec![
                bench_certificate(&format!("{name}.cert.pem")),
                self.intermediate.to_der().unwrap(),
            ],
            gen_time: DateTime::from_system_time(at).unwrap(),
            imprint,
        }
    }

    /// `unsigned.pdf` signed by `signer` under `sub_filter`, its `/M` `claimed`, with a
    /// `signingTime` attribute of `signing_time` and a signature timestamp from `tsa`.
    fn custom(
        &self,
        signer: &dyn nacre_core::Signer,
        sub_filter: &[u8],
        claimed: Option<&[u8]>,
        signing_time: Option<SystemTime>,
        tsa: Option<&dyn TimestampAuthority>,
    ) -> Vec<u8> {
        forge::signed_with(
            forge::UNSIGNED,
            signer,
            &Signature {
                sub_filter,
                claimed,
                signing_time: signing_time.map(ts),
                tsa,
                ..Signature::default()
            },
        )
    }

    /// An OCSP responder delegated by `issuer`, valid over the given span.
    fn delegate(
        &self,
        code: u64,
        issuer: &Certificate,
        issuer_key: &SigningKey,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> (SigningKey, Certificate) {
        self.issued(
            Role::OcspResponder,
            code,
            issuer,
            issuer_key,
            not_before,
            not_after,
        )
    }

    fn cases(&self) -> Vec<(String, Vec<u8>)> {
        let mut cases = Vec::new();
        self.levels(&mut cases);
        self.chains(&mut cases);
        self.n(&mut cases);
        self.p(&mut cases);
        self.q_r_s_t(&mut cases);
        self.k_o_v(&mut cases);
        self.e_v(&mut cases);
        self.h_w_a_c_p(&mut cases);
        self.later(&mut cases);
        self.holds(&mut cases);
        self.anchor_delegates(&mut cases);
        self.critical(&mut cases);
        self.modified(&mut cases);
        cases
            .into_iter()
            .map(|(name, pdf)| (format!("bench-{name}"), pdf))
            .collect()
    }
}

fn put(cases: &mut Vec<(String, Vec<u8>)>, name: &str, pdf: Vec<u8>) {
    cases.push((name.to_owned(), pdf));
}

/// The bench cases, one per row of the s18 research's spike tables, `x` cases aside (s47).
impl Bench {
    /// s48, `m`: modifications after signing that DSS's format checks refuse, from the bench
    /// signer's B signature. `m2` stands in for DSS's `pades-spoofing-replaced-reason.pdf`,
    /// which carries a real person's name and is never committed.
    fn modified(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let b = forge::signed(&self.signer, Level::B);
        let doc = Document::parse(&b).unwrap();

        let Some(Object::Reference(old_pages)) = doc.catalog().get(b"Pages").cloned() else {
            panic!("no /Pages reference");
        };
        let Object::Dictionary(old) = doc.object(old_pages).unwrap() else {
            panic!("/Pages is no dictionary");
        };
        let Some(Object::Array(kids)) = old.get(b"Kids").cloned() else {
            panic!("no /Kids");
        };
        // Ids are allocated in sequence: the page takes the first free one, its tree the next.
        let page_id = doc.update().add(Object::Null).unwrap();
        let pages_id = nacre_pdf::ObjectId::new(page_id.number + 1, 0);
        let mut update = doc.update();
        let mut page = Dictionary::new();
        page.insert(b"Type", Object::Name(b"Page".to_vec()));
        page.insert(b"Parent", Object::Reference(pages_id));
        page.insert(
            b"MediaBox",
            Object::Array([0, 0, 595, 842].map(Object::Integer).to_vec()),
        );
        assert_eq!(update.add(Object::Dictionary(page)).unwrap(), page_id);
        let mut pages = Dictionary::new();
        pages.insert(b"Type", Object::Name(b"Pages".to_vec()));
        pages.insert(
            b"Kids",
            Object::Array(
                kids.into_iter()
                    .chain([Object::Reference(page_id)])
                    .collect(),
            ),
        );
        pages.insert(b"Count", Object::Integer(2));
        assert_eq!(update.add(Object::Dictionary(pages)).unwrap(), pages_id);
        update.set_catalog(b"Pages", Object::Reference(pages_id));
        put(cases, "m1-b-page-added", update.finish().unwrap());

        let value = doc.signature_fields()[0].value.unwrap();
        let Object::Dictionary(mut signature) = doc.object(value).unwrap() else {
            panic!("no signature dictionary");
        };
        signature.insert(b"Reason", Object::String(b"Rejected".to_vec()));
        put(
            cases,
            "m2-b-reason-replaced",
            forge::redefine(&b, &[(value, Object::Dictionary(signature))]),
        );
    }

    /// Spike 3, `l`: the bench signer at each level, then each element of a level alone.
    fn levels(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let s = &self.signer;
        let revocation = bench_revocation();
        let issuers = [bench_certificate("root.cert.pem")];
        let (tsa, tsa2) = (&self.tsa, &self.document_tsa);
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let pkcs7: &[u8] = b"adbe.pkcs7.detached";
        let fixed = Some(FIXED_CLAIMED);
        let lt = || Level::LT {
            tsa,
            revocation: &revocation,
            issuers: &issuers,
        };
        let b = forge::signed(s, Level::B);
        let t = forge::signed(s, Level::T { tsa });
        let lt_file = forge::signed(s, lt());
        let lta = forge::signed(
            s,
            Level::LTA {
                tsa,
                revocation: &revocation,
                issuers: &issuers,
                document_tsa: tsa2,
            },
        );
        put(cases, "l01-b", b.clone());
        put(cases, "l02-t", t.clone());
        put(cases, "l03-lt", lt_file.clone());
        put(cases, "l04-lta", lta.clone());
        put(
            cases,
            "l05-b-signing-time",
            self.custom(s, cades, fixed, Some(self.now), None),
        );
        put(
            cases,
            "l06-b-cms-crl",
            forge::signed_with(
                forge::UNSIGNED,
                s,
                &Signature {
                    claimed: fixed,
                    crls: vec![self.intermediate_crl.clone()],
                    ..Signature::default()
                },
            ),
        );
        put(
            cases,
            "l07-t-signing-time",
            self.custom(s, cades, fixed, Some(self.now), Some(tsa)),
        );
        let zeroed = self.bench_tsa("tsa", self.now, Some(vec![0; 32]));
        put(
            cases,
            "l08-t-bad-imprint",
            self.custom(s, cades, fixed, None, Some(&zeroed)),
        );
        let rogue_key = forge::key(&[0x61; 32]);
        let rogue = forge::issue(
            Role::Tsa,
            "CN=Rogue TSA,O=Nacre tests,C=FR",
            7,
            &rogue_key,
            None,
            &rogue_key,
        );
        let untrusted = ForgedTsa {
            key: rogue_key,
            certificates: vec![rogue.to_der().unwrap()],
            gen_time: DateTime::from_system_time(self.now).unwrap(),
            imprint: None,
        };
        put(
            cases,
            "l09-t-untrusted-tsa",
            self.custom(s, cades, fixed, None, Some(&untrusted)),
        );
        let zeroed_document = self.bench_tsa("tsa2", self.now, Some(vec![0; 32]));
        put(
            cases,
            "l10-lta-bad-doc-imprint",
            forge::signed(
                s,
                Level::LTA {
                    tsa,
                    revocation: &revocation,
                    issuers: &issuers,
                    document_tsa: &zeroed_document,
                },
            ),
        );
        let inter_crl = self.intermediate_crl.clone();
        let root_crl = self.root_crl.clone();
        let chain = vec![
            bench_certificate("signer.cert.pem"),
            bench_certificate("intermediate.cert.pem"),
            bench_certificate("root.cert.pem"),
        ];
        let mut chain_t = chain.clone();
        chain_t.push(bench_certificate("tsa.cert.pem"));
        put(
            cases,
            "l11-b-plus-dss",
            forge::with_dss(&b, &chain, std::slice::from_ref(&inter_crl)),
        );
        put(
            cases,
            "l12-t-plus-dss-certs-only",
            forge::with_dss(&t, &chain_t, &[]),
        );
        put(
            cases,
            "l13-t-plus-dss-full",
            forge::with_dss(&t, &chain_t, std::slice::from_ref(&inter_crl)),
        );
        put(
            cases,
            "l14-pkcs7-b",
            self.custom(s, pkcs7, fixed, None, None),
        );
        put(
            cases,
            "l15-pkcs7-b-signing-time",
            self.custom(s, pkcs7, None, Some(self.now), None),
        );
        put(cases, "l16-b-no-m", self.custom(s, cades, None, None, None));
        let forged_tsa = self.bench_tsa("tsa", self.now, None);
        put(
            cases,
            "l17-t-revoked-tsa-signer-ok-untrusted-imprint-ok",
            self.custom(s, cades, fixed, None, Some(&forged_tsa)),
        );
        let revoked = BenchSigner::load_as("revoked");
        put(cases, "l18-lt-revoked", forge::signed(&revoked, lt()));
        put(
            cases,
            "l19-lta-revoked",
            forge::signed(
                &revoked,
                Level::LTA {
                    tsa,
                    revocation: &revocation,
                    issuers: &issuers,
                    document_tsa: tsa2,
                },
            ),
        );
        let both = [inter_crl.clone(), root_crl.clone()];
        put(
            cases,
            "l20-t-dss-chain-both-crls",
            forge::with_dss(&t, &chain, &both),
        );
        put(
            cases,
            "l21-t-dss-chain-tsa-both-crls",
            forge::with_dss(&t, &chain_t, &both),
        );
        put(
            cases,
            "l22-t-dss-crls-only",
            forge::with_dss(&t, &[], &both),
        );
        put(
            cases,
            "l23-b-dss-full",
            forge::with_dss(&b, &chain_t, &both),
        );
        put(cases, "l24-b-docts", forge::document_timestamp(&b, tsa2));
        put(
            cases,
            "l25-b-dss-docts",
            forge::document_timestamp(&forge::with_dss(&b, &chain, &both), tsa2),
        );
        let t_docts = forge::document_timestamp(&t, tsa2);
        put(cases, "l26-t-docts", t_docts.clone());
        let mut chain_all = chain_t.clone();
        chain_all.push(bench_certificate("tsa2.cert.pem"));
        put(
            cases,
            "l27-t-docts-dss",
            forge::with_dss(&t_docts, &chain_all, &both),
        );
        let t21 = forge::with_dss(&t, &chain_t, &both);
        put(
            cases,
            "l28-t-dss-docts-nolta-data",
            forge::document_timestamp(&t21, tsa2),
        );
        put(
            cases,
            "l29-t-dss-docts-bad",
            forge::document_timestamp(&t21, &zeroed_document),
        );
        put(
            cases,
            "l30-lta-plus-dss",
            forge::with_dss(
                &lta,
                &[bench_certificate("tsa2.cert.pem")],
                std::slice::from_ref(&inter_crl),
            ),
        );
        put(cases, "l31-lt-ocsp-only", lt_file);
        let rogue_ca_key = forge::key(&[0x62; 32]);
        let rogue_ca = forge::issue(
            Role::Ca,
            "CN=Rogue CA,O=Nacre tests,C=FR",
            8,
            &rogue_ca_key,
            None,
            &rogue_ca_key,
        );
        let rogue_tsa_key = forge::key(&[0x63; 32]);
        let rogue_tsa = forge::issue(
            Role::Tsa,
            "CN=Rogue TSA2,O=Nacre tests,C=FR",
            9,
            &rogue_tsa_key,
            Some(&rogue_ca),
            &rogue_ca_key,
        );
        let rogue_stamp = ForgedTsa {
            key: rogue_tsa_key,
            certificates: vec![rogue_tsa.to_der().unwrap(), rogue_ca.to_der().unwrap()],
            gen_time: DateTime::from_system_time(self.now).unwrap(),
            imprint: None,
        };
        let rogue_t = self.custom(s, cades, fixed, None, Some(&rogue_stamp));
        put(
            cases,
            "l32-t-rogue-ca-tsa-dss-signer-only",
            forge::with_dss(&rogue_t, &chain, &both),
        );
        let rogue_crl = crl_of_nothing(&rogue_ca, &forge::key(&[0x62; 32]), self.now);
        put(
            cases,
            "l33-t-rogue-ca-tsa-dss-all",
            forge::with_dss(
                &rogue_t,
                &chain,
                &[inter_crl.clone(), root_crl.clone(), rogue_crl],
            ),
        );
        let fake_root_crl = crl_of_nothing(&self.root, &forge::key(&[0x64; 32]), self.now);
        put(
            cases,
            "l34-t-dss-forged-root-crl",
            forge::with_dss(&t, &chain, &[inter_crl.clone(), fake_root_crl]),
        );
        put(
            cases,
            "l35-t-cms-crls",
            forge::signed_with(
                forge::UNSIGNED,
                s,
                &Signature {
                    claimed: fixed,
                    crls: both.to_vec(),
                    tsa: Some(tsa),
                    ..Signature::default()
                },
            ),
        );
        put(
            cases,
            "l36-b-no-ess",
            forge::signed_with(
                forge::UNSIGNED,
                s,
                &Signature {
                    claimed: fixed,
                    ess: Ess::None,
                    ..Signature::default()
                },
            ),
        );
        let doc = Document::parse(&b).unwrap();
        let mut update = doc.update();
        let mut action = Dictionary::new();
        action.insert(b"S", Object::Name(b"JavaScript".to_vec()));
        action.insert(
            b"JS",
            Object::String(b"app.alert('added after signing')".to_vec()),
        );
        update.set_catalog(b"OpenAction", Object::Dictionary(action));
        put(cases, "l37-b-openaction", update.finish().unwrap());
        put(
            cases,
            "l38-t-dss-docts-rogue",
            forge::document_timestamp(&t21, &rogue_stamp),
        );
        let expired = forge::crl(
            &self.intermediate,
            &self.intermediate_key,
            ts(self.now - 3 * DAY),
            ts(self.now - 2 * DAY),
            &[],
        );
        put(
            cases,
            "l39-t-dss-expired-crl",
            forge::with_dss(&t, &chain_t, &[expired.clone(), root_crl.clone()]),
        );
        put(
            cases,
            "l40-b-dss-stale-crl",
            forge::with_dss(&b, &chain, &[expired, root_crl]),
        );
    }

    /// Spike 3, `c40`–`c45`: a B by a signer of the intermediate out of its validity, or
    /// whose key usage or extended key usage forbids signing, a fresh CRL in `/DSS`.
    fn chains(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let usual = KeyUsages::DigitalSignature | KeyUsages::NonRepudiation;
        let eku = |oid: &str| Some(ObjectIdentifier::new_unwrap(oid));
        let rows = [
            (
                "c40-expired-b",
                0x40,
                now - 30 * DAY,
                now - DAY,
                usual,
                None,
            ),
            (
                "c41-not-yet-valid-b",
                0x41,
                now + DAY,
                now + 30 * DAY,
                usual,
                None,
            ),
            (
                "c42-ku-certsign-b",
                0x42,
                now - 30 * DAY,
                now + 30 * DAY,
                KeyUsages::KeyCertSign.into(),
                None,
            ),
            (
                "c43-eku-serverauth-b",
                0x43,
                now - 30 * DAY,
                now + 30 * DAY,
                usual,
                eku("1.3.6.1.5.5.7.3.1"),
            ),
            (
                "c44-eku-clientauth-b",
                0x44,
                now - 30 * DAY,
                now + 30 * DAY,
                usual,
                eku("1.3.6.1.5.5.7.3.2"),
            ),
            (
                "c45-eku-emailprot-b",
                0x45,
                now - 30 * DAY,
                now + 30 * DAY,
                usual,
                eku("1.3.6.1.5.5.7.3.4"),
            ),
        ];
        for (name, code, not_before, not_after, usage, purpose) in rows {
            let key = forge::key(&[code; 32]);
            let leaf = self.leaf(
                u64::from(code),
                &key,
                (not_before, not_after),
                usage,
                purpose,
            );
            let signer = chain(&key, &leaf, &[&self.intermediate]);
            let fresh = self.intermediate_crl_at(now, &[]);
            put(
                cases,
                name,
                forge::with_dss(
                    &forge::signed(&signer, Level::B),
                    &[],
                    &[fresh, self.root_crl.clone()],
                ),
            );
        }
    }

    /// A signer of the intermediate with `usage` and, when given, an `extendedKeyUsage`
    /// naming `purpose` alone.
    fn leaf(
        &self,
        code: u64,
        key: &SigningKey,
        (not_before, not_after): (SystemTime, SystemTime),
        usage: der::flagset::FlagSet<KeyUsages>,
        purpose: Option<ObjectIdentifier>,
    ) -> Certificate {
        use x509_cert::builder::{Builder, CertificateBuilder};
        let profile = LeafProfile {
            subject: format!("CN=Nacre s18 campaign leaf {code:02x},O=Nacre tests,C=FR")
                .parse()
                .unwrap(),
            issuer: self.intermediate.tbs_certificate().subject().clone(),
            usage,
            purpose,
        };
        let spki =
            x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
        CertificateBuilder::new(
            profile,
            x509_cert::serial_number::SerialNumber::from(self.serial(code)),
            x509_cert::time::Validity::new(ts(not_before), ts(not_after)),
            spki,
        )
        .unwrap()
        .build::<_, DerSignature>(&self.intermediate_key)
        .unwrap()
    }
}

/// The extensions of [`Bench::leaf`]: not a CA, `usage`, and `purpose` as its only
/// `extendedKeyUsage` when given.
struct LeafProfile {
    subject: x509_cert::name::Name,
    issuer: x509_cert::name::Name,
    usage: der::flagset::FlagSet<KeyUsages>,
    purpose: Option<ObjectIdentifier>,
}

impl x509_cert::builder::profile::BuilderProfile for LeafProfile {
    fn get_issuer(&self, _subject: &x509_cert::name::Name) -> x509_cert::name::Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> x509_cert::name::Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        _spk: spki::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: spki::SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::certificate::TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        use x509_cert::ext::ToExtension;
        use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
        let constraints = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        }
        .to_extension(tbs.subject(), &[])?;
        let usage =
            KeyUsage(self.usage).to_extension(tbs.subject(), std::slice::from_ref(&constraints))?;
        let mut extensions = vec![constraints, usage];
        if let Some(purpose) = self.purpose {
            extensions.push(Extension {
                extn_id: ObjectIdentifier::new_unwrap("2.5.29.37"),
                critical: false,
                extn_value: OctetString::new(ExtendedKeyUsage(vec![purpose]).to_der()?)?,
            });
        }
        Ok(extensions)
    }
}

/// A CRL of `issuer`'s name signed with `key`, issued at `at`, revoking nothing.
fn crl_of_nothing(issuer: &Certificate, key: &SigningKey, at: SystemTime) -> Vec<u8> {
    crl(issuer, key, at, &[])
}

impl Bench {
    /// Spike 3, `n`: expiry and revocation, claimed times, malformed certificates,
    /// `/SubFilter`s, `/V`, ESS v1, EPES, PKCS7 and document timestamps as proof.
    fn n(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let s = &self.signer;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let pkcs7: &[u8] = b"adbe.pkcs7.detached";
        let fixed = Some(FIXED_CLAIMED);
        let root_crl = || self.root_crl.clone();
        let expired = |code| self.intermediate_signer(code, now - 30 * DAY, now - DAY);

        let (signer, certificate) = expired(0x51);
        let crls = [
            self.intermediate_crl_at(now - HOUR, &[(&certificate, now - 10 * DAY)]),
            root_crl(),
        ];
        put(
            cases,
            "n01-expired-revoked",
            forge::with_dss(&forge::signed(&signer, Level::B), &[], &crls),
        );
        let (signer, certificate) = expired(0x59);
        let crls = [
            self.intermediate_crl_at(now - 2 * DAY, &[(&certificate, now - 10 * DAY)]),
            root_crl(),
        ];
        put(
            cases,
            "n01b-expired-revoked-crl-before-expiry",
            forge::with_dss(&forge::signed(&signer, Level::B), &[], &crls),
        );
        let (signer, _) = expired(0x5a);
        let crls = [self.intermediate_crl_at(now - HOUR, &[]), root_crl()];
        put(
            cases,
            "n01c-expired-crl-after-expiry",
            forge::with_dss(&forge::signed(&signer, Level::B), &[], &crls),
        );
        let (signer, _) = expired(0x5b);
        let crls = [self.intermediate_crl_at(now - 2 * DAY, &[]), root_crl()];
        put(
            cases,
            "n01d-expired-crl-before-expiry",
            forge::with_dss(&forge::signed(&signer, Level::B), &[], &crls),
        );

        let fresh = [self.intermediate_crl_at(now - HOUR, &[]), root_crl()];
        let (signer, _) = self.intermediate_signer(0x52, now - 30 * DAY, now + 30 * DAY);
        let pdf = self.custom(&signer, cades, Some(b"D:20270601000000Z"), None, None);
        put(
            cases,
            "n02-m-after-not-after",
            forge::with_dss(&pdf, &[], &fresh),
        );
        let not_before = now - HOUR;
        let (signer, _) = self.intermediate_signer(0x53, not_before, now + 30 * DAY);
        let without_offset = |at: SystemTime| {
            let mut date = claimed(at);
            date.pop();
            date
        };
        let before = without_offset(not_before - 30 * MINUTE);
        let pdf = self.custom(&signer, cades, Some(&before), None, None);
        put(
            cases,
            "n03-m-no-offset-before-nb",
            forge::with_dss(&pdf, &[], &fresh),
        );
        let after = without_offset(not_before + 30 * MINUTE);
        let pdf = self.custom(&signer, cades, Some(&after), None, None);
        put(
            cases,
            "n03b-m-no-offset-after-nb",
            forge::with_dss(&pdf, &[], &fresh),
        );

        let (tsa_key, tsa) = self.issued_with(
            Role::Tsa,
            0x54,
            &self.intermediate,
            &self.intermediate_key,
            now - 30 * DAY,
            now + 30 * DAY,
            Extensions::RepeatedKeyUsage,
        );
        let repeated = ForgedTsa {
            key: tsa_key,
            certificates: vec![tsa.to_der().unwrap(), self.intermediate.to_der().unwrap()],
            gen_time: DateTime::from_system_time(now).unwrap(),
            imprint: None,
        };
        put(
            cases,
            "n04-tsa-repeated-ext",
            self.custom(s, cades, fixed, None, Some(&repeated)),
        );
        let (_, junk) = self.issued_with(
            Role::Signer,
            0x55,
            &self.intermediate,
            &self.intermediate_key,
            now - 30 * DAY,
            now + 30 * DAY,
            Extensions::RepeatedKeyUsage,
        );
        put(
            cases,
            "n05-dss-repeated-ext",
            forge::with_dss(&forge::signed(s, Level::B), &[junk.to_der().unwrap()], &[]),
        );
        put(
            cases,
            "n06-subfilter-x509",
            self.custom(s, b"adbe.x509.rsa_sha1", fixed, None, None),
        );
        put(
            cases,
            "n07-subfilter-unknown",
            self.custom(s, b"Nacre.Unknown", fixed, None, None),
        );
        let plain = forge::signed_with(
            forge::UNSIGNED,
            s,
            &Signature {
                claimed: None,
                ..Signature::default()
            },
        );
        put(cases, "n08-v-not-dict", patch_value(&plain, b"/V 7"));
        put(cases, "n08b-v-stream", patch_value(&plain, b"/V 4 0 R"));
        put(
            cases,
            "n09-ess-v1",
            forge::signed_with(
                forge::UNSIGNED,
                s,
                &Signature {
                    claimed: fixed,
                    ess: Ess::V1,
                    ..Signature::default()
                },
            ),
        );
        put(
            cases,
            "n10-epes",
            forge::signed_with(
                forge::UNSIGNED,
                s,
                &Signature {
                    claimed: fixed,
                    attributes: vec![Attribute {
                        oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15"),
                        values: vec![Any::null()],
                    }],
                    ..Signature::default()
                },
            ),
        );
        put(cases, "n11-no-m", self.custom(s, cades, None, None, None));
        put(
            cases,
            "n12-pkcs7-st-no-m",
            self.custom(s, pkcs7, None, Some(now), None),
        );
        put(
            cases,
            "n12b-pkcs7-st-m",
            self.custom(s, pkcs7, fixed, Some(now), None),
        );

        let tsa2 = &self.document_tsa;
        let (signer, certificate) = self.intermediate_signer(0x56, now - 30 * DAY, now + 30 * DAY);
        let basic = forge::signed(&signer, Level::B);
        let archived = forge::document_timestamp(&basic, tsa2);
        let zeroed = self.bench_tsa("tsa2", now, Some(vec![0; 32]));
        let archived_badly = forge::document_timestamp(&basic, &zeroed);
        std::thread::sleep(Duration::from_secs(3));
        let later = SystemTime::now();
        let revoked =
            self.intermediate_crl_at(later, &[(&certificate, later - Duration::from_secs(1))]);
        let tsa2_certificate = [bench_certificate("tsa2.cert.pem")];
        put(
            cases,
            "n13-docts-poe-revoked-after",
            forge::with_dss(&archived, &tsa2_certificate, &[revoked.clone(), root_crl()]),
        );
        put(
            cases,
            "n14-docts-bad-revoked-after",
            forge::with_dss(&archived_badly, &tsa2_certificate, &[revoked, root_crl()]),
        );
        let (signer, certificate) = self.intermediate_signer(0x57, now - 30 * DAY, now + 30 * DAY);
        let basic = forge::signed(&signer, Level::B);
        let revoked_at = SystemTime::now() - Duration::from_secs(5);
        let archived = forge::document_timestamp(&basic, tsa2);
        let crls = [
            self.intermediate_crl_at(SystemTime::now(), &[(&certificate, revoked_at)]),
            root_crl(),
        ];
        put(
            cases,
            "n15-revoked-before-docts",
            forge::with_dss(&archived, &[], &crls),
        );
        let (signer, _) = self.intermediate_signer(0x58, now - 30 * DAY, now + 30 * DAY);
        let stale = [self.intermediate_crl_at(now - 25 * HOUR, &[]), root_crl()];
        let basic = forge::with_dss(&forge::signed(&signer, Level::B), &[], &stale);
        put(
            cases,
            "n16-stale-crl-then-docts",
            forge::document_timestamp(&basic, tsa2),
        );
    }
}

impl Bench {
    /// Spike 3, `p`: no `/M`, `/SubFilter` missing or not a name, `signingTime`, an
    /// expired CA, an expired TSA, data issued after the signer's `notAfter`.
    fn p(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let s = &self.signer;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let m_now = claimed(now - HOUR);
        let root_crl = || self.root_crl.clone();
        let (inter, inter_key) = (&self.intermediate, &self.intermediate_key);

        let (signer, _) = self.intermediate_signer(0x61, now - 30 * DAY, now + 30 * DAY);
        put(
            cases,
            "p01-no-m-no-data",
            self.custom(&signer, cades, None, None, None),
        );
        let (signer, certificate) = self.intermediate_signer(0x62, now - 30 * DAY, now + 30 * DAY);
        let pdf = self.custom(&signer, cades, None, None, None);
        let crls = [
            self.intermediate_crl_at(now, &[(&certificate, now - HOUR)]),
            root_crl(),
        ];
        put(cases, "p02-no-m-revoked", forge::with_dss(&pdf, &[], &crls));
        let base = self.custom(s, cades, Some(&m_now), None, None);
        let sub_filter: &[u8] = b"/SubFilter /ETSI.CAdES.detached";
        put(
            cases,
            "p03-subfilter-missing",
            forge::resign(&forge::patch(&base, sub_filter, b""), s),
        );
        put(
            cases,
            "p04-subfilter-integer",
            forge::resign(&forge::patch(&base, sub_filter, b"/SubFilter 7"), s),
        );
        put(
            cases,
            "p04b-subfilter-string",
            forge::resign(
                &forge::patch(&base, sub_filter, b"/SubFilter (ETSI.CAdES.det)"),
                s,
            ),
        );
        put(cases, "p04c-resign-control", forge::resign(&base, s));
        put(
            cases,
            "p05-pades-signing-time-no-m",
            self.custom(s, cades, None, Some(now - HOUR), None),
        );
        put(
            cases,
            "p05b-pkcs7-signing-time-no-m",
            self.custom(s, b"adbe.pkcs7.detached", None, Some(now - HOUR), None),
        );

        let (ca_key, ca) = self.root_ca(0x66, now - 60 * DAY, now - DAY);
        let (key, certificate) = self.issued(
            Role::Signer,
            0x67,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let signer = chain(&key, &certificate, &[&ca]);
        let tsa_past = self.bench_tsa("tsa", now - 5 * DAY, None);
        let m_past = claimed(now - 5 * DAY - HOUR);
        let stamped = self.custom(&signer, cades, Some(&m_past), None, Some(&tsa_past));
        let ca_crl = crl(&ca, &ca_key, now - 3 * DAY, &[]);
        let root_now = crl(&self.root, &self.root_key, now, &[]);
        let root_old = crl(&self.root, &self.root_key, now - 3 * DAY, &[]);
        let tsa_crl = self.intermediate_crl_at(now, &[]);
        put(
            cases,
            "p06-ca-expired-root-crl-late",
            forge::with_dss(
                &stamped,
                &[],
                &[ca_crl.clone(), root_now, tsa_crl.clone(), root_crl()],
            ),
        );
        let p06b = forge::with_dss(
            &stamped,
            &[],
            &[ca_crl.clone(), root_old.clone(), tsa_crl, root_crl()],
        );
        put(cases, "p06b-ca-expired-root-crl-before", p06b.clone());
        put(
            cases,
            "p06c-ca-expired-then-docts",
            forge::document_timestamp(&p06b, &self.document_tsa),
        );
        let basic = self.custom(&signer, cades, Some(&m_past), None, None);
        let tsa2_past = self.bench_tsa("tsa2", now - 2 * DAY, None);
        let ca_data = [ca_crl.clone(), root_old.clone(), root_crl()];
        put(
            cases,
            "p06e-ca-expired-docts-before-expiry",
            forge::document_timestamp(&forge::with_dss(&basic, &[], &ca_data), &tsa2_past),
        );
        put(
            cases,
            "p06d-ca-expired-b-no-ts",
            forge::with_dss(&basic, &[], &ca_data),
        );

        let (tsa_key, tsa) =
            self.issued(Role::Tsa, 0x68, inter, inter_key, now - 60 * DAY, now - DAY);
        let expired_tsa = ForgedTsa {
            key: tsa_key,
            certificates: vec![tsa.to_der().unwrap(), inter.to_der().unwrap()],
            gen_time: DateTime::from_system_time(now - 5 * DAY).unwrap(),
            imprint: None,
        };
        let (signer, certificate) = self.intermediate_signer(0x69, now - 50 * DAY, now + 30 * DAY);
        let pdf = self.custom(&signer, cades, Some(&m_past), None, Some(&expired_tsa));
        let revoked = self.intermediate_crl_at(now, &[(&certificate, now - HOUR)]);
        put(
            cases,
            "p07-tsa-expired-data-late",
            forge::with_dss(&pdf, &[], &[revoked.clone(), root_crl()]),
        );
        let early = self.intermediate_crl_at(now - 3 * DAY, &[]);
        put(
            cases,
            "p07b-tsa-expired-data-before",
            forge::with_dss(&pdf, &[], &[early.clone(), revoked, root_crl()]),
        );
        let (signer, _) = self.intermediate_signer(0x6a, now - 50 * DAY, now + 30 * DAY);
        let pdf = self.custom(&signer, cades, Some(&m_past), None, Some(&expired_tsa));
        put(
            cases,
            "p07c-tsa-expired-signer-ok",
            forge::with_dss(&pdf, &[], &[early, root_crl()]),
        );

        let m_five = claimed(now - 5 * DAY);
        let (signer, certificate) = self.intermediate_signer(0x6b, now - 30 * DAY, now - DAY);
        let pdf = self.custom(&signer, cades, Some(&m_five), None, None);
        let response = forge::ocsp(
            &certificate,
            inter,
            inter_key,
            inter,
            None,
            ts(now),
            None,
            &[],
        );
        put(
            cases,
            "p08-expired-ocsp-late",
            forge::with_dss_ocsps(&pdf, &[], &[root_crl()], &[response]),
        );
        let (signer, _) = self.intermediate_signer(0x6c, now - 30 * DAY, now - DAY);
        let pdf = self.custom(&signer, cades, Some(&m_five), None, None);
        let kept = forge::crl_with_expired_certs_on_crl(
            inter,
            inter_key,
            ts(now),
            ts(now + 30 * DAY),
            ts(now - 60 * DAY),
        );
        put(
            cases,
            "p09-expired-crl-expired-certs-on-crl",
            forge::with_dss(&pdf, &[], &[kept, root_crl()]),
        );
        let late = self.intermediate_crl_at(now, &[]);
        put(
            cases,
            "p09b-expired-crl-late-plain",
            forge::with_dss(&pdf, &[], &[late, root_crl()]),
        );
        let (signer, _) = self.intermediate_signer(0x6d, now - 30 * DAY, now + 30 * DAY);
        let pdf = self.custom(&signer, cades, Some(&m_now), None, None);
        let fresh = self.intermediate_crl_at(now, &[]);
        put(
            cases,
            "p10-control",
            forge::with_dss(&pdf, &[], &[fresh, root_crl()]),
        );
    }

    /// Spike 3, `q`, `r`, `s` and `t`: the `/DSS` around timestamps, CAs without
    /// `subjectKeyIdentifier`, PKCS7 at T and above.
    fn q_r_s_t(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let m_now = claimed(now - HOUR);
        let (tsa, tsa2) = (&self.tsa, &self.document_tsa);
        let (root, root_key) = (&self.root, &self.root_key);
        let root_crl = || self.root_crl.clone();

        let (signer, _) = self.intermediate_signer(0x71, now - 30 * DAY, now + 30 * DAY);
        let t = self.custom(&signer, cades, Some(&m_now), None, Some(tsa));
        let b = self.custom(&signer, cades, Some(&m_now), None, None);
        let old = [
            self.intermediate_crl_at(now - 3 * DAY, &[]),
            crl(root, root_key, now - 3 * DAY, &[]),
        ];
        std::thread::sleep(Duration::from_secs(2));
        let later = SystemTime::now();
        let new = [
            self.intermediate_crl_at(later, &[]),
            crl(root, root_key, later, &[]),
        ];
        put(
            cases,
            "q1-t-dss-crls-before-ts",
            forge::with_dss(&t, &[], &old),
        );
        put(
            cases,
            "q2-t-dss-crls-after-ts",
            forge::with_dss(&t, &[], &new),
        );
        put(
            cases,
            "q3-b-dss-old-docts-now",
            forge::document_timestamp(&forge::with_dss(&b, &[], &old), tsa2),
        );
        let tsa2_past = self.bench_tsa("tsa2", now - 2 * DAY, None);
        put(
            cases,
            "q4-b-dss-old-docts-past",
            forge::document_timestamp(&forge::with_dss(&b, &[], &old), &tsa2_past),
        );
        let tsa_past = self.bench_tsa("tsa", now - 2 * DAY, None);
        let m_past = claimed(now - 2 * DAY - HOUR);
        let t_past = self.custom(&signer, cades, Some(&m_past), None, Some(&tsa_past));
        put(
            cases,
            "q5-t-past-dss-old",
            forge::with_dss(&t_past, &[], &old),
        );
        put(
            cases,
            "q6-t-past-dss-new",
            forge::with_dss(&t_past, &[], &new),
        );

        let (ca_key, ca) = self.root_ca(0x72, now - 60 * DAY, now + 60 * DAY);
        let (key, certificate) = self.issued(
            Role::Signer,
            0x73,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let signer = chain(&key, &certificate, &[&ca]);
        let vb = self.custom(&signer, cades, Some(&m_now), None, None);
        let vt = self.custom(&signer, cades, Some(&m_now), None, Some(tsa));
        let signer_data = [
            crl(&ca, &ca_key, now - DAY, &[]),
            crl(root, root_key, now - DAY, &[]),
        ];
        let all = [
            signer_data[0].clone(),
            signer_data[1].clone(),
            self.intermediate_crl_at(now - DAY, &[]),
        ];
        let docts = forge::document_timestamp;
        put(
            cases,
            "r1-b-dss-signer-only-docts",
            docts(&forge::with_dss(&vb, &[], &signer_data), tsa2),
        );
        put(
            cases,
            "r2-b-dss-signer-and-tsa-docts",
            docts(&forge::with_dss(&vb, &[], &all), tsa2),
        );
        put(
            cases,
            "r3-t-dss-signer-only",
            forge::with_dss(&vt, &[], &signer_data),
        );
        put(
            cases,
            "r4-b-docts-then-dss-signer-and-tsa",
            forge::with_dss(&docts(&vb, tsa2), &[], &all),
        );
        put(
            cases,
            "r5-b-docts-dss-docts",
            docts(&forge::with_dss(&docts(&vb, tsa2), &[], &all), tsa2),
        );
        let rogue_key = forge::key(&[0x74; 32]);
        let rogue_ca = forge::issue_with(
            Role::Ca,
            "CN=Rogue CA,O=Nacre tests,C=FR",
            self.serial(0x74),
            &rogue_key,
            None,
            &rogue_key,
            (ts(now - 60 * DAY), ts(now + 60 * DAY)),
            Extensions::Usual,
        );
        let (rogue_tsa_key, rogue_tsa) = self.issued(
            Role::Tsa,
            0x75,
            &rogue_ca,
            &rogue_key,
            now - 50 * DAY,
            now + 50 * DAY,
        );
        let rogue = ForgedTsa {
            key: rogue_tsa_key,
            certificates: vec![rogue_tsa.to_der().unwrap(), rogue_ca.to_der().unwrap()],
            gen_time: DateTime::from_system_time(now).unwrap(),
            imprint: None,
        };
        put(
            cases,
            "r7-t-rogue-docts-dss-docts",
            docts(&forge::with_dss(&docts(&vt, &rogue), &[], &all), tsa2),
        );
        put(
            cases,
            "r8-t-dss-docts-rogue",
            docts(&forge::with_dss(&vt, &[], &all), &rogue),
        );
        put(
            cases,
            "r6-b-docts-dss-signer-only-docts",
            docts(&forge::with_dss(&docts(&vb, tsa2), &[], &signer_data), tsa2),
        );

        let (inter, inter_key) = (&self.intermediate, &self.intermediate_key);
        let (signer, _) = self.intermediate_signer(0x76, now - 30 * DAY, now - DAY);
        let tsa_five = self.bench_tsa("tsa", now - 5 * DAY, None);
        let m_five = claimed(now - 5 * DAY - HOUR);
        let pdf = self.custom(&signer, cades, Some(&m_five), None, Some(&tsa_five));
        let kept = forge::crl_with_expired_certs_on_crl(
            inter,
            inter_key,
            ts(now),
            ts(now + 30 * DAY),
            ts(now - 60 * DAY),
        );
        put(
            cases,
            "s1-t-expired-ecoc",
            forge::with_dss(&pdf, &[], &[kept, root_crl()]),
        );
        let late = self.intermediate_crl_at(now, &[]);
        put(
            cases,
            "s1b-t-expired-late-plain",
            forge::with_dss(&pdf, &[], &[late, root_crl()]),
        );
        let (ca_key, ca) = self.issued_with(
            Role::Ca,
            0x77,
            root,
            root_key,
            now - 60 * DAY,
            now + 60 * DAY,
            Extensions::WithoutKeyIdentifier,
        );
        let (key, certificate) = self.issued(
            Role::Signer,
            0x78,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let signer = chain(&key, &certificate, &[&ca]);
        let root_day = crl(root, root_key, now - DAY, &[]);
        let ca_crl = |revoked: &[(&Certificate, SystemTime, Option<CrlReason>)]| {
            crl(&ca, &ca_key, now - HOUR, revoked)
        };
        put(
            cases,
            "s2-noski-no-m",
            forge::with_dss(
                &self.custom(&signer, cades, None, None, None),
                &[],
                &[ca_crl(&[]), root_day.clone()],
            ),
        );
        put(
            cases,
            "s3-noski-revoked",
            forge::with_dss(
                &self.custom(&signer, cades, Some(&m_now), None, None),
                &[],
                &[ca_crl(&[(&certificate, now - DAY, None)]), root_day.clone()],
            ),
        );
        put(
            cases,
            "s4-noski-no-data",
            self.custom(&signer, cades, Some(&m_now), None, None),
        );
        let (key, expired) =
            self.issued(Role::Signer, 0x79, &ca, &ca_key, now - 50 * DAY, now - DAY);
        let pdf = self.custom(
            &chain(&key, &expired, &[&ca]),
            cades,
            Some(&claimed(now - 5 * DAY)),
            None,
            None,
        );
        put(
            cases,
            "s5-noski-signer-expired",
            forge::with_dss(
                &pdf,
                &[],
                &[crl(&ca, &ca_key, now - 3 * DAY, &[]), root_day],
            ),
        );

        let pkcs7 = self.custom(
            &self.signer,
            b"adbe.pkcs7.detached",
            Some(&m_now),
            None,
            Some(tsa),
        );
        let with_data = forge::with_dss(
            &pkcs7,
            &[],
            &[self.intermediate_crl_at(now - HOUR, &[]), root_crl()],
        );
        put(cases, "t1-pkcs7-t-dss", with_data.clone());
        put(cases, "t2-pkcs7-t-dss-docts", docts(&with_data, tsa2));
    }
}

impl Bench {
    /// Spike 4, `k`, `o` and `v`: a TSA under a CA without `subjectKeyIdentifier`, delegated
    /// OCSP responders, revoked signers under an expired CA.
    fn k_o_v(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let m_now = claimed(now - HOUR);
        let (root, root_key) = (&self.root, &self.root_key);
        let (inter, inter_key) = (&self.intermediate, &self.intermediate_key);
        let root_crl = || self.root_crl.clone();

        for (name, code, not_before, not_after) in [
            ("o1-ocsp-delegate-ok", 0x81, now - 30 * DAY, now + 30 * DAY),
            ("o2-ocsp-delegate-expired", 0x82, now - 30 * DAY, now - DAY),
            ("o3-ocsp-delegate-not-yet", 0x83, now + DAY, now + 30 * DAY),
        ] {
            let (signer, certificate) =
                self.intermediate_signer(code + 0x10, now - 30 * DAY, now + 30 * DAY);
            let pdf = self.custom(&signer, cades, Some(&m_now), None, None);
            let (delegate_key, delegate) =
                self.delegate(code, inter, inter_key, not_before, not_after);
            let response = forge::ocsp(
                &certificate,
                inter,
                &delegate_key,
                &delegate,
                Some(&delegate),
                ts(now),
                None,
                &[],
            );
            put(
                cases,
                name,
                forge::with_dss_ocsps(&pdf, &[], &[root_crl()], &[response]),
            );
        }

        let (ca_key, ca) = self.issued_with(
            Role::Ca,
            0x84,
            root,
            root_key,
            now - 60 * DAY,
            now + 60 * DAY,
            Extensions::WithoutKeyIdentifier,
        );
        let (tsa_key, tsa) = self.issued(
            Role::Tsa,
            0x85,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 50 * DAY,
        );
        let stamp = ForgedTsa {
            key: tsa_key,
            certificates: vec![tsa.to_der().unwrap(), ca.to_der().unwrap()],
            gen_time: DateTime::from_system_time(now - 5 * DAY).unwrap(),
            imprint: None,
        };
        let ca_crl = crl(&ca, &ca_key, now - HOUR, &[]);
        let root_hour = crl(root, root_key, now - HOUR, &[]);
        let (signer, certificate) = self.intermediate_signer(0x86, now - 30 * DAY, now + 30 * DAY);
        let m_five = claimed(now - 5 * DAY - HOUR);
        let pdf = self.custom(&signer, cades, Some(&m_five), None, Some(&stamp));
        let revoked = self.intermediate_crl_at(now, &[(&certificate, now - HOUR)]);
        put(
            cases,
            "k1-t-tsa-ca-noski-signer-revoked",
            forge::with_dss(
                &pdf,
                &[],
                &[revoked.clone(), root_hour.clone(), ca_crl.clone()],
            ),
        );
        put(
            cases,
            "k2-t-tsa-ca-noski-signer-ok",
            forge::with_dss(
                &pdf,
                &[],
                &[
                    self.intermediate_crl_at(now - HOUR, &[]),
                    root_hour.clone(),
                    ca_crl.clone(),
                ],
            ),
        );
        let basic = self.custom(&signer, cades, Some(&m_five), None, None);
        put(
            cases,
            "k3-b-docts-noski-signer-revoked",
            forge::with_dss(
                &forge::document_timestamp(&basic, &stamp),
                &[],
                &[revoked.clone(), root_hour, ca_crl],
            ),
        );
        let tsa2_past = self.bench_tsa("tsa2", now - 5 * DAY, None);
        put(
            cases,
            "k4-b-docts-ski-signer-revoked",
            forge::with_dss(
                &forge::document_timestamp(&basic, &tsa2_past),
                &[],
                &[revoked, root_crl()],
            ),
        );

        let (ca_key, ca) = self.root_ca(0x87, now - 60 * DAY, now - DAY);
        let root_old = crl(root, root_key, now - 3 * DAY, &[]);
        let tsa_past = self.bench_tsa("tsa", now - 5 * DAY, None);
        for (name, code, revoked_days, stamped) in [
            ("v1-b-revoked-6d-ca-expired", 0x88, 6, false),
            ("v2-t5d-revoked-6d-ca-expired", 0x89, 6, true),
            ("v3-t5d-revoked-4d-ca-expired", 0x8a, 4, true),
        ] {
            let (key, certificate) = self.issued(
                Role::Signer,
                code,
                &ca,
                &ca_key,
                now - 50 * DAY,
                now + 30 * DAY,
            );
            let signer = chain(&key, &certificate, &[&ca]);
            let tsa: Option<&dyn TimestampAuthority> =
                stamped.then_some(&tsa_past as &dyn TimestampAuthority);
            let pdf = self.custom(&signer, cades, Some(&claimed(now - 7 * DAY)), None, tsa);
            let ca_crl = crl(
                &ca,
                &ca_key,
                now - 3 * DAY,
                &[(&certificate, now - revoked_days * DAY, None)],
            );
            put(
                cases,
                name,
                forge::with_dss(
                    &pdf,
                    &[],
                    &[
                        ca_crl,
                        root_old.clone(),
                        self.intermediate_crl_at(now - HOUR, &[]),
                        root_crl(),
                    ],
                ),
            );
        }
    }

    /// Spike 4, `e` and `v`: OCSP responses built in Rust, delegated or with an
    /// `archiveCutoff`, and a CA revoked while out of its validity.
    fn e_v(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let m_now = claimed(now - HOUR);
        let (root, root_key) = (&self.root, &self.root_key);
        let (inter, inter_key) = (&self.intermediate, &self.intermediate_key);
        let root_crl = || self.root_crl.clone();
        let cutoff = |from: SystemTime| {
            [time_extension(
                ARCHIVE_CUTOFF,
                from,
                false,
                OcspPlace::Single,
            )]
        };

        let (signer, certificate) = self.intermediate_signer(0x91, now - 30 * DAY, now + 30 * DAY);
        let pdf = self.custom(&signer, cades, Some(&m_now), None, None);
        let control = forge::ocsp(
            &certificate,
            inter,
            inter_key,
            inter,
            None,
            ts(now - 2 * HOUR),
            None,
            &[],
        );
        put(
            cases,
            "e1-ocsp-rust-control",
            forge::with_dss_ocsps(&pdf, &[], &[root_crl()], &[control]),
        );
        for (name, code, not_after) in [
            ("e2-ocsp-delegate-expired-since", 0x92, now - DAY),
            ("e3-ocsp-delegate-valid-3d", 0x93, now + 30 * DAY),
        ] {
            let (key, delegate) = self.delegate(code, inter, inter_key, now - 30 * DAY, not_after);
            let response = forge::ocsp(
                &certificate,
                inter,
                &key,
                &delegate,
                Some(&delegate),
                ts(now - 3 * DAY),
                None,
                &[],
            );
            put(
                cases,
                name,
                forge::with_dss_ocsps(&pdf, &[], &[root_crl()], &[response]),
            );
        }
        let (signer, certificate) = self.intermediate_signer(0x94, now - 30 * DAY, now - DAY);
        let pdf = self.custom(&signer, cades, Some(&claimed(now - 5 * DAY)), None, None);
        let with_cutoff = forge::ocsp(
            &certificate,
            inter,
            inter_key,
            inter,
            None,
            ts(now - HOUR),
            None,
            &cutoff(now - 60 * DAY),
        );
        put(
            cases,
            "e4-expired-ocsp-archive-cutoff",
            forge::with_dss_ocsps(&pdf, &[], &[root_crl()], &[with_cutoff]),
        );
        let plain = forge::ocsp(
            &certificate,
            inter,
            inter_key,
            inter,
            None,
            ts(now - HOUR),
            None,
            &[],
        );
        put(
            cases,
            "e4b-expired-ocsp-no-cutoff",
            forge::with_dss_ocsps(&pdf, &[], &[root_crl()], &[plain]),
        );
        let tsa_past = self.bench_tsa("tsa", now - 5 * DAY, None);
        let (signer, certificate) = self.intermediate_signer(0x95, now - 30 * DAY, now - DAY);
        let pdf = self.custom(
            &signer,
            cades,
            Some(&claimed(now - 5 * DAY - HOUR)),
            None,
            Some(&tsa_past),
        );
        let with_cutoff = forge::ocsp(
            &certificate,
            inter,
            inter_key,
            inter,
            None,
            ts(now - HOUR),
            None,
            &cutoff(now - 60 * DAY),
        );
        put(
            cases,
            "e5-t-expired-ocsp-archive-cutoff",
            forge::with_dss_ocsps(
                &pdf,
                &[],
                &[root_crl(), self.intermediate_crl_at(now - HOUR, &[])],
                &[with_cutoff],
            ),
        );

        let (ca_key, ca) = self.root_ca(0x96, now - 60 * DAY, now - DAY);
        let (key, certificate) = self.issued(
            Role::Signer,
            0x97,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let pdf = self.custom(
            &chain(&key, &certificate, &[&ca]),
            cades,
            Some(&claimed(now - 7 * DAY)),
            None,
            Some(&tsa_past),
        );
        let ca_crl = crl(&ca, &ca_key, now - 3 * DAY, &[]);
        let root_revokes = crl(root, root_key, now - 3 * DAY, &[(&ca, now - 4 * DAY, None)]);
        put(
            cases,
            "v5-t5d-ca-revoked-4d-ca-expired",
            forge::with_dss(
                &pdf,
                &[],
                &[
                    ca_crl,
                    root_revokes,
                    self.intermediate_crl_at(now - HOUR, &[]),
                    root_crl(),
                ],
            ),
        );
        let (signer, certificate) = self.intermediate_signer(0x98, now - 50 * DAY, now + 30 * DAY);
        let pdf = self.custom(
            &signer,
            cades,
            Some(&claimed(now - 7 * DAY)),
            None,
            Some(&tsa_past),
        );
        let revoked = self.intermediate_crl_at(now - 3 * DAY, &[(&certificate, now - 4 * DAY)]);
        put(
            cases,
            "v6-t5d-revoked-4d-control",
            forge::with_dss(&pdf, &[], &[revoked, root_crl()]),
        );
    }
}

const HOLD: Option<CrlReason> = Some(CrlReason::CertificateHold);

impl Bench {
    /// Spike 5, `h`, `w`, `a`, `c` and `p`: holds, a revoked signer under a revoked and
    /// expired CA, the root's delegated responder on the intermediate, `archiveCutoff`
    /// placement and criticality, an intermediate's delegate with a proof of existence.
    fn h_w_a_c_p(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let (root, root_key) = (&self.root, &self.root_key);
        let (inter, inter_key) = (&self.intermediate, &self.intermediate_key);
        let root_crl = || self.root_crl.clone();
        let tsa_past = self.bench_tsa("tsa", now - 5 * DAY, None);
        let m_seven = claimed(now - 7 * DAY);
        let m_two_hours = claimed(now - 2 * HOUR);

        let (signer, certificate) = self.intermediate_signer(0xa1, now - 50 * DAY, now + 30 * DAY);
        let pdf = self.custom(&signer, cades, Some(&m_seven), None, Some(&tsa_past));
        let held = |days: u32| {
            crl(
                inter,
                inter_key,
                now - 3 * DAY,
                &[(&certificate, now - days * DAY, HOLD)],
            )
        };
        put(
            cases,
            "h1-t5d-hold-4d-after-stamp",
            forge::with_dss(&pdf, &[], &[held(4), root_crl()]),
        );
        put(
            cases,
            "h2-t5d-hold-6d-before-stamp",
            forge::with_dss(&pdf, &[], &[held(6), root_crl()]),
        );
        let (signer_b, certificate_b) =
            self.intermediate_signer(0xa2, now - 50 * DAY, now + 30 * DAY);
        let pdf_b = self.custom(&signer_b, cades, Some(&m_two_hours), None, None);
        let held_hour = crl(
            inter,
            inter_key,
            now - 30 * MINUTE,
            &[(&certificate_b, now - HOUR, HOLD)],
        );
        put(
            cases,
            "h3-b-hold-1h",
            forge::with_dss(&pdf_b, &[], &[held_hour, root_crl()]),
        );
        let held_ocsp = forge::ocsp(
            &certificate,
            inter,
            inter_key,
            inter,
            None,
            ts(now - 3 * DAY),
            Some((ts(now - 4 * DAY), HOLD)),
            &[],
        );
        put(
            cases,
            "h4-t5d-ocsp-hold-4d",
            forge::with_dss_ocsps(&pdf, &[], &[root_crl()], &[held_ocsp]),
        );

        let (ca_key, ca) = self.root_ca(0xa3, now - 60 * DAY, now - DAY);
        let (key, leaf) = self.issued(
            Role::Signer,
            0xa4,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let pdf_w = self.custom(
            &chain(&key, &leaf, &[&ca]),
            cades,
            Some(&m_seven),
            None,
            Some(&tsa_past),
        );
        let ca_revokes = crl(&ca, &ca_key, now - 3 * DAY, &[(&leaf, now - 4 * DAY, None)]);
        let root_revokes = crl(root, root_key, now - 3 * DAY, &[(&ca, now - 4 * DAY, None)]);
        let tsa_data = self.intermediate_crl_at(now - HOUR, &[]);
        put(
            cases,
            "w1-t5d-signer-and-ca-revoked-4d-ca-expired",
            forge::with_dss(
                &pdf_w,
                &[],
                &[
                    ca_revokes.clone(),
                    root_revokes.clone(),
                    tsa_data.clone(),
                    root_crl(),
                ],
            ),
        );
        let root_good = crl(root, root_key, now - 3 * DAY, &[]);
        put(
            cases,
            "w2-t5d-signer-revoked-ca-expired-root-good",
            forge::with_dss(
                &pdf_w,
                &[],
                &[ca_revokes, root_good, tsa_data.clone(), root_crl()],
            ),
        );
        let ca_good = crl(&ca, &ca_key, now - 3 * DAY, &[]);
        put(
            cases,
            "w3-t5d-signer-good-ca-revoked-ca-expired",
            forge::with_dss(
                &pdf_w,
                &[],
                &[ca_good, root_revokes, tsa_data.clone(), root_crl()],
            ),
        );

        let (signer_a, _) = self.intermediate_signer(0xa5, now - 50 * DAY, now + 30 * DAY);
        let pdf_a = self.custom(&signer_a, cades, Some(&m_seven), None, Some(&tsa_past));
        let (expired_key, expired) = self.delegate(0xa6, root, root_key, now - 30 * DAY, now - DAY);
        let (valid_key, valid) =
            self.delegate(0xa7, root, root_key, now - 30 * DAY, now + 30 * DAY);
        let on_intermediate = |key: &SigningKey, delegate: &Certificate| {
            forge::ocsp(
                inter,
                root,
                key,
                delegate,
                Some(delegate),
                ts(now - 3 * DAY),
                None,
                &[],
            )
        };
        put(
            cases,
            "a1-t5d-root-delegate-expired-since",
            forge::with_dss_ocsps(
                &pdf_a,
                &[],
                std::slice::from_ref(&tsa_data),
                &[on_intermediate(&expired_key, &expired)],
            ),
        );
        put(
            cases,
            "a2-t5d-root-delegate-valid",
            forge::with_dss_ocsps(
                &pdf_a,
                &[],
                std::slice::from_ref(&tsa_data),
                &[on_intermediate(&valid_key, &valid)],
            ),
        );
        let (signer_a3, _) = self.intermediate_signer(0xa8, now - 50 * DAY, now + 30 * DAY);
        let pdf_a3 = self.custom(&signer_a3, cades, Some(&m_two_hours), None, None);
        put(
            cases,
            "a3-b-root-delegate-expired-since",
            forge::with_dss_ocsps(
                &pdf_a3,
                &[],
                std::slice::from_ref(&tsa_data),
                &[on_intermediate(&expired_key, &expired)],
            ),
        );

        let sixty = now - 60 * DAY;
        let (signer_c, certificate_c) = self.intermediate_signer(0xa9, now - 30 * DAY, now - DAY);
        let pdf_c = self.custom(&signer_c, cades, Some(&claimed(now - 5 * DAY)), None, None);
        let response = |certificate: &Certificate, critical: bool, place: OcspPlace| {
            forge::ocsp(
                certificate,
                inter,
                inter_key,
                inter,
                None,
                ts(now - HOUR),
                None,
                &[time_extension(ARCHIVE_CUTOFF, sixty, critical, place)],
            )
        };
        put(
            cases,
            "c1-b-cutoff-in-response-extensions",
            forge::with_dss_ocsps(
                &pdf_c,
                &[],
                &[root_crl()],
                &[response(&certificate_c, false, OcspPlace::Response)],
            ),
        );
        put(
            cases,
            "c2-b-cutoff-single-critical",
            forge::with_dss_ocsps(
                &pdf_c,
                &[],
                &[root_crl()],
                &[response(&certificate_c, true, OcspPlace::Single)],
            ),
        );
        put(
            cases,
            "c0-b-cutoff-single-control",
            forge::with_dss_ocsps(
                &pdf_c,
                &[],
                &[root_crl()],
                &[response(&certificate_c, false, OcspPlace::Single)],
            ),
        );
        let (signer_c5, certificate_c5) = self.intermediate_signer(0xaa, now - 30 * DAY, now - DAY);
        let pdf_c5 = self.custom(
            &signer_c5,
            cades,
            Some(&claimed(now - 5 * DAY - HOUR)),
            None,
            Some(&tsa_past),
        );
        put(
            cases,
            "c3-t5d-cutoff-in-response-extensions",
            forge::with_dss_ocsps(
                &pdf_c5,
                &[],
                &[root_crl(), tsa_data.clone()],
                &[response(&certificate_c5, false, OcspPlace::Response)],
            ),
        );
        put(
            cases,
            "c4-t5d-cutoff-single-critical",
            forge::with_dss_ocsps(
                &pdf_c5,
                &[],
                &[root_crl(), tsa_data.clone()],
                &[response(&certificate_c5, true, OcspPlace::Single)],
            ),
        );

        let (signer_p, certificate_p) =
            self.intermediate_signer(0xab, now - 50 * DAY, now + 30 * DAY);
        let pdf_p = self.custom(&signer_p, cades, Some(&m_seven), None, Some(&tsa_past));
        let (expired_key, expired) =
            self.delegate(0xac, inter, inter_key, now - 30 * DAY, now - DAY);
        let (valid_key, valid) =
            self.delegate(0xad, inter, inter_key, now - 30 * DAY, now + 30 * DAY);
        let delegated = |key: &SigningKey,
                         delegate: &Certificate,
                         revoked: Option<(Time, Option<CrlReason>)>| {
            forge::ocsp(
                &certificate_p,
                inter,
                key,
                delegate,
                Some(delegate),
                ts(now - 3 * DAY),
                revoked,
                &[],
            )
        };
        put(
            cases,
            "p1-t5d-delegate-expired-since",
            forge::with_dss_ocsps(
                &pdf_p,
                &[],
                &[root_crl(), tsa_data.clone()],
                &[delegated(&expired_key, &expired, None)],
            ),
        );
        put(
            cases,
            "p2-t5d-delegate-valid",
            forge::with_dss_ocsps(
                &pdf_p,
                &[],
                &[root_crl(), tsa_data],
                &[delegated(&valid_key, &valid, None)],
            ),
        );
        put(
            cases,
            "p3-t5d-delegate-expired-says-revoked-4d",
            forge::with_dss_ocsps(
                &pdf_p,
                &[],
                &[root_crl()],
                &[delegated(
                    &expired_key,
                    &expired,
                    Some((ts(now - 4 * DAY), None)),
                )],
            ),
        );
    }

    /// Spike 5, forged later: the root's delegate on a CA of no CDP, an intermediate's
    /// delegate with a proof of existence, holds on a CA and through OCSP, lifted holds,
    /// `archiveCutoff` critical on a valid signer, CRLs with an unknown extension.
    fn later(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let (root, root_key) = (&self.root, &self.root_key);
        let (inter, inter_key) = (&self.intermediate, &self.intermediate_key);
        let root_crl = || self.root_crl.clone();
        let tsa_past = self.bench_tsa("tsa", now - 5 * DAY, None);
        let m_seven = claimed(now - 7 * DAY);
        let m_two_hours = claimed(now - 2 * HOUR);

        let (ca_key, ca) = self.root_ca(0xb1, now - 60 * DAY, now + 60 * DAY);
        let (key, leaf) = self.issued(
            Role::Signer,
            0xb2,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let signer = chain(&key, &leaf, &[&ca]);
        let pdf = self.custom(&signer, cades, Some(&m_seven), None, Some(&tsa_past));
        let ca_crl = crl(&ca, &ca_key, now - HOUR, &[]);
        // a4 had DSS apply the bench's newer `root.crl` to this CA: its delegate's response
        // now postdates that CRL, and the delegate expires just after (research, traps).
        let (short_key, short) = self.delegate(
            0xb3,
            root,
            root_key,
            now - 30 * DAY,
            self.root_time + Duration::from_secs(5),
        );
        let (valid_key, valid) =
            self.delegate(0xb4, root, root_key, now - 30 * DAY, now + 30 * DAY);
        let (expired_key, expired) = self.delegate(0xbc, root, root_key, now - 30 * DAY, now - DAY);
        let on_ca = |key: &SigningKey, delegate: &Certificate, produced: SystemTime| {
            forge::ocsp(
                &ca,
                root,
                key,
                delegate,
                Some(delegate),
                ts(produced),
                None,
                &[],
            )
        };
        put(
            cases,
            "a4-t5d-root-delegate-expired-since",
            forge::with_dss_ocsps(
                &pdf,
                &[],
                std::slice::from_ref(&ca_crl),
                &[on_ca(&short_key, &short, self.root_time)],
            ),
        );
        put(
            cases,
            "a5-t5d-root-delegate-valid",
            forge::with_dss_ocsps(
                &pdf,
                &[],
                std::slice::from_ref(&ca_crl),
                &[on_ca(&valid_key, &valid, now - 3 * DAY)],
            ),
        );
        let pdf_b = self.custom(&signer, cades, Some(&m_two_hours), None, None);
        put(
            cases,
            "a6-b-root-delegate-expired-since",
            forge::with_dss_ocsps(
                &pdf_b,
                &[],
                std::slice::from_ref(&ca_crl),
                &[on_ca(&expired_key, &expired, now - 3 * DAY)],
            ),
        );

        let (signer_p, certificate_p) =
            self.intermediate_signer(0xb5, now - 50 * DAY, now + 30 * DAY);
        let pdf_p = self.custom(&signer_p, cades, Some(&m_seven), None, Some(&tsa_past));
        for (name, code, not_after) in [
            ("p4-t5d-delegate-expired-since", 0xb6, now - DAY),
            ("p5-t5d-delegate-valid", 0xb7, now + 30 * DAY),
        ] {
            let (key, delegate) = self.delegate(code, inter, inter_key, now - 30 * DAY, not_after);
            let response = forge::ocsp(
                &certificate_p,
                inter,
                &key,
                &delegate,
                Some(&delegate),
                ts(now - 3 * DAY),
                None,
                &[],
            );
            put(
                cases,
                name,
                forge::with_dss_ocsps(&pdf_p, &[], &[root_crl()], &[response]),
            );
        }

        let (ca_key, ca) = self.root_ca(0xb8, now - 60 * DAY, now + 60 * DAY);
        let (key, leaf) = self.issued(
            Role::Signer,
            0xb9,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let pdf_h = self.custom(
            &chain(&key, &leaf, &[&ca]),
            cades,
            Some(&m_seven),
            None,
            Some(&tsa_past),
        );
        let ca_crl = crl(&ca, &ca_key, now - HOUR, &[]);
        // h5 had the same stale-CRL artefact: the root's hold is issued after `root.crl`.
        let root_holds = crl(
            root,
            root_key,
            self.root_time,
            &[(&ca, now - 6 * DAY, HOLD)],
        );
        put(
            cases,
            "h5-t5d-ca-hold-6d",
            forge::with_dss(&pdf_h, &[], &[ca_crl, root_holds]),
        );
        let held = forge::ocsp(
            &certificate_p,
            inter,
            inter_key,
            inter,
            None,
            ts(now - 3 * DAY),
            Some((ts(now - 6 * DAY), HOLD)),
            &[],
        );
        put(
            cases,
            "h6-t5d-ocsp-hold-6d",
            forge::with_dss_ocsps(&pdf_p, &[], &[root_crl()], &[held]),
        );
        let (signer_l, certificate_l) =
            self.intermediate_signer(0xba, now - 50 * DAY, now + 30 * DAY);
        let pdf_l = self.custom(&signer_l, cades, Some(&m_two_hours), None, None);
        let hold_crl = crl(
            inter,
            inter_key,
            now - 50 * MINUTE,
            &[(&certificate_l, now - HOUR, HOLD)],
        );
        put(
            cases,
            "h7-b-hold-then-lifted",
            forge::with_dss(
                &pdf_l,
                &[],
                &[
                    hold_crl,
                    self.intermediate_crl_at(now - 10 * MINUTE, &[]),
                    root_crl(),
                ],
            ),
        );
        let revoked = self.intermediate_crl_at(now - 30 * MINUTE, &[(&certificate_l, now - HOUR)]);
        put(
            cases,
            "h8-b-revoked-1h-control",
            forge::with_dss(&pdf_l, &[], &[revoked, root_crl()]),
        );

        let (signer_v, certificate_v) =
            self.intermediate_signer(0xbb, now - 30 * DAY, now + 30 * DAY);
        let pdf_v = self.custom(&signer_v, cades, Some(&m_two_hours), None, None);
        let critical = |place| {
            forge::ocsp(
                &certificate_v,
                inter,
                inter_key,
                inter,
                None,
                ts(now - HOUR),
                None,
                &[time_extension(ARCHIVE_CUTOFF, now - 60 * DAY, true, place)],
            )
        };
        put(
            cases,
            "c5-b-valid-cutoff-single-critical",
            forge::with_dss_ocsps(&pdf_v, &[], &[root_crl()], &[critical(OcspPlace::Single)]),
        );
        put(
            cases,
            "c6-b-valid-cutoff-response-critical",
            forge::with_dss_ocsps(&pdf_v, &[], &[root_crl()], &[critical(OcspPlace::Response)]),
        );
        for (name, flag) in [
            ("c7-b-crl-unknown-critical", true),
            ("c8-b-crl-unknown-noncritical", false),
        ] {
            let extended = crl_with_extension(inter, inter_key, now - HOUR, UNKNOWN, flag);
            put(
                cases,
                name,
                forge::with_dss(&pdf_v, &[], &[extended, root_crl()]),
            );
        }
    }

    /// Spike 5, holds and revocations of a CA of no CDP by the root, its data issued after
    /// the bench's `root.crl` (h9 to h11 had the stale-CRL artefact before, research, traps).
    fn holds(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let (root, root_key) = (&self.root, &self.root_key);
        let tsa_past = self.bench_tsa("tsa", now - 5 * DAY, None);
        let key_compromise = Some(CrlReason::KeyCompromise);
        for (prefix, ca_code, leaf_code) in [("", 0xc1, 0xc2), ("again-", 0xd1, 0xd2)] {
            let (ca_key, ca) = self.root_ca(ca_code, now - 60 * DAY, now + 60 * DAY);
            let (key, leaf) = self.issued(
                Role::Signer,
                leaf_code,
                &ca,
                &ca_key,
                now - 50 * DAY,
                now + 30 * DAY,
            );
            let signer = chain(&key, &leaf, &[&ca]);
            let stamped = self.custom(
                &signer,
                cades,
                Some(&claimed(now - 7 * DAY)),
                None,
                Some(&tsa_past),
            );
            let ca_crl = crl(&ca, &ca_key, now - HOUR, &[]);
            let root_says = |reason, when: SystemTime| {
                crl(root, root_key, self.root_time, &[(&ca, when, reason)])
            };
            let mut rows = vec![];
            if prefix.is_empty() {
                rows.extend([
                    ("h9-t5d-ca-revoked-6d", None, now - 6 * DAY),
                    ("h10-t5d-ca-keycompromise-6d", key_compromise, now - 6 * DAY),
                    ("h11-t5d-ca-hold-6d-again", HOLD, now - 6 * DAY),
                ]);
            } else {
                rows.extend([
                    ("h9b-t5d-ca-revoked-6d-root-crl-now", None, now - 6 * DAY),
                    ("h11b-t5d-ca-hold-6d-root-crl-now", HOLD, now - 6 * DAY),
                    ("h14-t5d-ca-revoked-4d-root-crl-now", None, now - 4 * DAY),
                ]);
            }
            for (name, reason, when) in rows {
                put(
                    cases,
                    name,
                    forge::with_dss(&stamped, &[], &[ca_crl.clone(), root_says(reason, when)]),
                );
            }
            if prefix.is_empty() {
                let basic = self.custom(&signer, cades, Some(&claimed(now - 2 * HOUR)), None, None);
                for (name, reason) in [("h12-b-ca-revoked-1h", None), ("h13-b-ca-hold-1h", HOLD)] {
                    let root_now =
                        crl(root, root_key, self.root_time, &[(&ca, now - HOUR, reason)]);
                    put(
                        cases,
                        name,
                        forge::with_dss(&basic, &[], &[ca_crl.clone(), root_now]),
                    );
                }
            }
        }
    }

    /// Spike 5, a7 and a8: a CA of no CDP whose only data is a response by a delegate of the
    /// root, produced after the bench's `root.crl` and expired since; T and B.
    fn anchor_delegates(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let cades: &[u8] = b"ETSI.CAdES.detached";
        let (root, root_key) = (&self.root, &self.root_key);
        let (ca_key, ca) = self.root_ca(0xd4, now - 60 * DAY, now + 60 * DAY);
        let (key, leaf) = self.issued(
            Role::Signer,
            0xd5,
            &ca,
            &ca_key,
            now - 50 * DAY,
            now + 30 * DAY,
        );
        let signer = chain(&key, &leaf, &[&ca]);
        let ca_crl = crl(&ca, &ca_key, now - HOUR, &[]);
        let (delegate_key, delegate) = self.delegate(
            0xd3,
            root,
            root_key,
            now - 30 * DAY,
            self.root_time + Duration::from_secs(5),
        );
        let response = forge::ocsp(
            &ca,
            root,
            &delegate_key,
            &delegate,
            Some(&delegate),
            ts(self.root_time),
            None,
            &[],
        );
        let tsa_past = self.bench_tsa("tsa", now - 5 * DAY, None);
        let stamped = self.custom(
            &signer,
            cades,
            Some(&claimed(now - 7 * DAY)),
            None,
            Some(&tsa_past),
        );
        put(
            cases,
            "a7-t5d-root-delegate-expired-1min",
            forge::with_dss_ocsps(
                &stamped,
                &[],
                std::slice::from_ref(&ca_crl),
                std::slice::from_ref(&response),
            ),
        );
        let basic = self.custom(&signer, cades, Some(&claimed(now - 2 * HOUR)), None, None);
        put(
            cases,
            "a8-b-root-delegate-expired-1min",
            forge::with_dss_ocsps(&basic, &[], &[ca_crl], &[response]),
        );
    }

    /// Spike 5, `u`: a valid signer whose only data is a response of the intermediate
    /// holding an extension of an unknown OID, `crlReferences` or `archiveCutoff`, in its
    /// single response or its response extensions, critical or not.
    fn critical(&self, cases: &mut Vec<(String, Vec<u8>)>) {
        let now = self.now;
        let (inter, inter_key) = (&self.intermediate, &self.intermediate_key);
        let (signer, certificate) = self.intermediate_signer(0xe1, now - 30 * DAY, now + 30 * DAY);
        let pdf = self.custom(
            &signer,
            b"ETSI.CAdES.detached",
            Some(&claimed(now - 2 * HOUR)),
            None,
            None,
        );
        for (tag, oid) in [
            ("u1-unknown", UNKNOWN),
            ("u2-crlref", CRL_REFERENCES),
            ("u3-cutoff", ARCHIVE_CUTOFF),
        ] {
            for (shape, critical, place) in [
                ("single-critical", true, OcspPlace::Single),
                ("response-critical", true, OcspPlace::Response),
                ("single-noncritical", false, OcspPlace::Single),
            ] {
                let response = forge::ocsp(
                    &certificate,
                    inter,
                    inter_key,
                    inter,
                    None,
                    ts(now - HOUR),
                    None,
                    &[time_extension(oid, now - 60 * DAY, critical, place)],
                );
                put(
                    cases,
                    &format!("{tag}-{shape}"),
                    forge::with_dss_ocsps(
                        &pdf,
                        &[],
                        std::slice::from_ref(&self.root_crl),
                        &[response],
                    ),
                );
            }
        }
    }
}
