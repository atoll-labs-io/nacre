#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Each switch of `ValidationPolicy` (ADR-0026), on committed attack files: the verdict of
//! `strict()`, then that of `strict()` with that one switch off.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use der::{Decode, Encode};
use nacre_core::{Indication, SubIndication};
use nacre_validate::{
    ChainDefect, Defect, Error, RevocationDefect, SignatureValidation, TrustAnchors,
    ValidationPolicy, validate_with_policy,
};
use support::Stub;
use support::forge;
use x509_cert::Certificate;

fn judge(file: &[u8], policy: &ValidationPolicy) -> Result<Vec<SignatureValidation>, Error> {
    validate_with_policy(
        file,
        &TrustAnchors::default(),
        SystemTime::UNIX_EPOCH,
        None,
        policy,
    )
}

fn strict_without(off: impl FnOnce(&mut ValidationPolicy)) -> ValidationPolicy {
    let mut policy = ValidationPolicy::strict();
    off(&mut policy);
    policy
}

/// A signature with no defect and no anchor: `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`.
fn sound(result: &SignatureValidation) {
    assert!(
        result.defect.is_none(),
        "{}: {:?}",
        result.field,
        result.defect
    );
    assert!(result.digest_verified && result.signature_verified);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::NoCertificateChainFound)
    );
}

fn single(mut results: Vec<SignatureValidation>) -> SignatureValidation {
    assert_eq!(results.len(), 1);
    results.remove(0)
}

/// (a) Later revisions: an appended revision and signed bytes ending at no revision.
#[test]
fn later_revisions_switch() {
    let off = strict_without(|p| p.refuse_later_revisions = false);

    let appended = include_bytes!("corpus/attacks/isa-appended-revision.pdf");
    let strict = single(judge(appended, &ValidationPolicy::strict()).unwrap());
    assert!(
        matches!(strict.defect, Some(Defect::RevisionNotAllowed { .. })),
        "{:?}",
        strict.defect
    );
    let lax = single(judge(appended, &off).unwrap());
    sound(&lax);
    assert!(!lax.later_revisions.is_empty());

    let short = include_bytes!("corpus/attacks/byterange-not-whole-file.pdf");
    let strict = single(judge(short, &ValidationPolicy::strict()).unwrap());
    assert!(
        matches!(strict.defect, Some(Defect::ByteRangeNotWholeFile)),
        "{:?}",
        strict.defect
    );
    sound(&single(judge(short, &off).unwrap()));
}

/// (b) Sneaky signatures: with the switch off, both the certification and the sneaky
/// signature are sound.
#[test]
fn sneaky_signatures_switch() {
    let file = include_bytes!("corpus/attacks/ssa-visible-signature.pdf");
    let strict = judge(file, &ValidationPolicy::strict()).unwrap();
    let sneaky = strict.iter().find(|r| r.field == "Sneaky").unwrap();
    assert!(
        matches!(
            sneaky.defect,
            Some(Defect::AddedByRevisionNotAllowed { .. })
        ),
        "{:?}",
        sneaky.defect
    );

    let lax = judge(
        file,
        &strict_without(|p| p.refuse_sneaky_signatures = false),
    )
    .unwrap();
    assert_eq!(lax.len(), 2);
    lax.iter().for_each(sound);
}

/// (c) Trailing data: the file is judged as it stands before the data.
#[test]
fn trailing_data_switch() {
    let file = include_bytes!("corpus/attacks/isa-no-xref.pdf");
    let error = judge(file, &ValidationPolicy::strict()).unwrap_err();
    assert!(
        matches!(error, Error::Pdf(nacre_pdf::Error::TrailingData { .. })),
        "{error:?}"
    );

    let lax = judge(file, &strict_without(|p| p.refuse_trailing_data = false)).unwrap();
    sound(&single(lax));
}

/// (d) Unusable signatures: left out with the switch off, and only those.
#[test]
fn unusable_signatures_switch() {
    let off = strict_without(|p| p.list_unusable_signatures = false);
    for file in [
        &include_bytes!("corpus/attacks/usf-contents-missing.pdf")[..],
        include_bytes!("corpus/attacks/usf-contents-zeros.pdf"),
        include_bytes!("corpus/attacks/usf-v-direct.pdf"),
        include_bytes!("corpus/attacks/usf-v-stream.pdf"),
    ] {
        assert_eq!(judge(file, &ValidationPolicy::strict()).unwrap().len(), 1);
        assert!(judge(file, &off).unwrap().is_empty());
    }

    let overlap =
        single(judge(include_bytes!("corpus/attacks/byterange-overlap.pdf"), &off).unwrap());
    assert!(
        matches!(overlap.defect, Some(Defect::ByteRangeOverlap)),
        "{:?}",
        overlap.defect
    );
    assert_eq!(overlap.report.indication(), Indication::TotalFailed);
}

/// (i) Unsupported sub-filters: a sound CMS under `/adbe.x509.rsa_sha1` is verified with the
/// switch off.
#[test]
fn unsupported_sub_filters_switch() {
    let file = include_bytes!("corpus/attacks/subfilter-unsupported.pdf");
    let strict = single(judge(file, &ValidationPolicy::strict()).unwrap());
    assert!(
        matches!(strict.defect, Some(Defect::UnsupportedSubFilter)),
        "{:?}",
        strict.defect
    );

    let off = strict_without(|p| p.refuse_unsupported_sub_filters = false);
    sound(&single(judge(file, &off).unwrap()));
}

/// (j) Misplaced xref: pyHanko's `startxref` one byte before `xref`, read with the switch
/// off, where it holds no signature; then `xref-misplaced-startxref.pdf`, whose signature
/// is then verified.
#[test]
fn misplaced_xref_switch() {
    let file = include_bytes!("../../nacre-pdf/tests/corpus/hostile/startxref-off-by-one.pdf");
    let error = judge(file, &ValidationPolicy::strict()).unwrap_err();
    assert!(
        matches!(
            error,
            Error::Pdf(nacre_pdf::Error::NotAnXrefSection { offset: 564 })
        ),
        "{error:?}"
    );

    let off = strict_without(|p| p.refuse_misplaced_xref = false);
    assert!(judge(file, &off).unwrap().is_empty());

    let signed = include_bytes!("corpus/attacks/xref-misplaced-startxref.pdf");
    let error = judge(signed, &ValidationPolicy::strict()).unwrap_err();
    assert!(
        matches!(error, Error::Pdf(nacre_pdf::Error::NotAnXrefSection { .. })),
        "{error:?}"
    );
    sound(&single(judge(signed, &off).unwrap()));
}

/// (i) Unsupported sub-filters, continued: a `/SubFilter` missing, then not a name, over a
/// sound CMS, is verified with the switch off.
#[test]
fn missing_sub_filter_switch() {
    let key = forge::key(&[0x41; 32]);
    let certificate = forge::issue(
        forge::Role::Signer,
        "CN=Nacre s45 sub-filter signer,O=Nacre tests,C=FR",
        0x45,
        &key,
        None,
        &key,
    );
    let signer = forge::ChainSigner {
        key,
        chain: vec![certificate.to_der().unwrap()],
    };
    let signed = forge::custom_signed(&signer, b"ETSI.CAdES.detached", Some(b"D:20261022080000Z"));
    let off = strict_without(|p| p.refuse_unsupported_sub_filters = false);
    for to in [&b""[..], b"/SubFilter 7"] {
        let file = forge::resign(
            &forge::patch(&signed, b"/SubFilter /ETSI.CAdES.detached", to),
            &signer,
        );
        let strict = single(judge(&file, &ValidationPolicy::strict()).unwrap());
        assert!(
            matches!(strict.defect, Some(Defect::UnsupportedSubFilter)),
            "{:?}",
            strict.defect
        );
        sound(&single(judge(&file, &off).unwrap()));
    }
}

/// The single signature of `file`, judged under `policy` with the chain corpus root as
/// anchor on 2026-10-22.
fn with_chain_root(file: &[u8], policy: &ValidationPolicy) -> Result<SignatureValidation, Error> {
    let anchors =
        TrustAnchors::from_certificates([&include_bytes!("corpus/chain/root.der")[..]]).unwrap();
    let at: SystemTime =
        x509_cert::time::Time::from(der::DateTime::new(2026, 10, 22, 0, 0, 0).unwrap())
            .to_system_time();
    validate_with_policy(file, &anchors, at, None, policy).map(single)
}

fn sub(result: &SignatureValidation) -> Option<SubIndication> {
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    result.report.sub_indication()
}

/// The path is kept and only its missing revocation data refuses it.
fn revocation_missing(result: &SignatureValidation) {
    assert_eq!(
        sub(result),
        Some(SubIndication::CertificateChainGeneralFailure)
    );
    assert!(result.chain.is_some());
    assert!(
        matches!(
            result.defect,
            Some(Defect::Revocation(RevocationDefect::Missing { depth: 0 }))
        ),
        "{:?}",
        result.defect
    );
}

/// (e) Signer key usage: `keyUsage` and `extendedKeyUsage` of the leaf.
#[test]
fn signer_key_usage_switch() {
    let off = strict_without(|p| p.judge_signer_key_usage = false);
    for file in [
        &include_bytes!("corpus/attacks/chain-key-usage.pdf")[..],
        include_bytes!("corpus/attacks/chain-extended-key-usage.pdf"),
    ] {
        let strict = with_chain_root(file, &ValidationPolicy::strict()).unwrap();
        assert_eq!(sub(&strict), Some(SubIndication::ChainConstraintsFailure));
        revocation_missing(&with_chain_root(file, &off).unwrap());
    }
}

/// (f) Malformed extensions: a verdict under `strict()`, an error with the switch off.
#[test]
fn malformed_extensions_switch() {
    let file = include_bytes!("corpus/attacks/chain-malformed-extension.pdf");
    let strict = with_chain_root(file, &ValidationPolicy::strict()).unwrap();
    assert!(
        matches!(
            strict.defect,
            Some(Defect::Chain(ChainDefect::MalformedExtension { .. }))
        ),
        "{:?}",
        strict.defect
    );

    let error = with_chain_root(
        file,
        &strict_without(|p| p.judge_malformed_extensions = false),
    )
    .unwrap_err();
    assert!(matches!(error, Error::MalformedCertificate), "{error:?}");
}

/// (g) Validity before revocation, with no data: the missing data decides first.
#[test]
fn validity_before_revocation_switch() {
    let file = include_bytes!("corpus/attacks/chain-expired.pdf");
    let strict = with_chain_root(file, &ValidationPolicy::strict()).unwrap();
    assert_eq!(sub(&strict), Some(SubIndication::OutOfBoundsNoPoe));

    let lax = with_chain_root(
        file,
        &strict_without(|p| p.judge_validity_before_revocation = false),
    )
    .unwrap();
    revocation_missing(&lax);
}

/// A switch of `ValidationPolicy`: its name and what turns it off.
type Switch = (&'static str, fn(&mut ValidationPolicy));

const SWITCHES: [Switch; 12] = [
    ("refuse_later_revisions", |p| {
        p.refuse_later_revisions = false
    }),
    ("refuse_sneaky_signatures", |p| {
        p.refuse_sneaky_signatures = false
    }),
    ("refuse_trailing_data", |p| p.refuse_trailing_data = false),
    ("list_unusable_signatures", |p| {
        p.list_unusable_signatures = false
    }),
    ("judge_signer_key_usage", |p| {
        p.judge_signer_key_usage = false
    }),
    ("judge_validity_before_revocation", |p| {
        p.judge_validity_before_revocation = false
    }),
    ("judge_malformed_extensions", |p| {
        p.judge_malformed_extensions = false
    }),
    ("require_fresh_revocation", |p| {
        p.require_fresh_revocation = false
    }),
    ("refuse_unsupported_sub_filters", |p| {
        p.refuse_unsupported_sub_filters = false
    }),
    ("refuse_misplaced_xref", |p| p.refuse_misplaced_xref = false),
    ("ignore_expired_certs_on_crl", |p| {
        p.ignore_expired_certs_on_crl = false
    }),
    ("judge_issuer_of_revoked_data", |p| {
        p.judge_issuer_of_revoked_data = false
    }),
];

const DSS: &str = "dss()";

fn manifest() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// Every `*.pdf` of `tests/corpus/attacks/`, by file name, read at run time.
fn attack_files() -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(manifest().join("tests/corpus/attacks"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "pdf"))
        .map(|path| {
            let name = path.file_name().unwrap().to_str().unwrap().to_owned();
            (name, std::fs::read(&path).unwrap())
        })
        .collect()
}

/// The « Ouverte sous » cell of each catalog row whose case is a file of `files`, read
/// from `docs/security/attacks/*.md`; each file must appear in exactly one row.
fn catalog(files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    let dir: PathBuf = manifest().join("../../docs/security/attacks");
    let mut cells = BTreeMap::new();
    let mut pages: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "md"))
        .collect();
    pages.sort();
    for page in pages {
        for line in std::fs::read_to_string(&page).unwrap().lines() {
            let Some(row) = line.trim().strip_prefix('|') else {
                continue;
            };
            let row: Vec<&str> = row.split('|').map(str::trim).collect();
            let Some((_, row)) = row.split_last() else {
                continue;
            };
            let Some(case) = row.iter().find_map(|cell| {
                cell.strip_prefix('`')
                    .and_then(|c| c.strip_suffix('`'))
                    .filter(|name| files.contains_key(*name))
            }) else {
                continue;
            };
            let last = row.last().unwrap().to_string();
            let previous = cells.insert(case.to_owned(), last);
            assert!(previous.is_none(), "{case} has two rows in the catalog");
        }
    }
    let missing: Vec<_> = files.keys().filter(|f| !cells.contains_key(*f)).collect();
    assert!(missing.is_empty(), "no catalog row for {missing:?}");
    for (file, cell) in &cells {
        assert!(
            cell.starts_with("`dss()`") || cell.starts_with("aucune"),
            "{file}: {cell}"
        );
        assert!(!cell.contains("idem"), "{file}: {cell}");
        for name in backticked(cell) {
            assert!(
                name == DSS || SWITCHES.iter().any(|(switch, _)| *switch == name),
                "{file}: `{name}` is no switch"
            );
        }
    }
    cells
}

/// The backticked names of `cell`.
fn backticked(cell: &str) -> Vec<&str> {
    cell.split('`').skip(1).step_by(2).collect()
}

/// A "not revoked" CRL of `issuer`, signed with `secret`, issued 2026-10-21T12:00Z.
fn chain_crl(issuer: &[u8], secret: u8) -> Vec<u8> {
    forge::crl(
        &Certificate::from_der(issuer).unwrap(),
        &forge::key(&[secret; 32]),
        forge::time(2026, 10, 21, 12, 0, 0),
        forge::time(2026, 11, 21, 12, 0, 0),
        &[],
    )
}

type Verdict = Result<Vec<(String, Indication, Option<SubIndication>)>, String>;

/// What `file` gives under `policy`, with the chain root as anchor on 2026-10-22 and a
/// source answering "not revoked" for the chain intermediate and root: its `Error`
/// variant, or each signature's field, indication and sub-indication; and whether a
/// signature is listed with no defect.
fn verdict(file: &[u8], policy: &ValidationPolicy) -> (Verdict, bool) {
    let root = include_bytes!("corpus/chain/root.der");
    let intermediate = include_bytes!("corpus/chain/intermediate.der");
    let stub = Stub {
        intermediate: intermediate.to_vec(),
        intermediate_crl: chain_crl(intermediate, 0x32),
        root_crl: chain_crl(root, 0x31),
        failing: false,
    };
    let anchors = TrustAnchors::from_certificates([&root[..]]).unwrap();
    let at = forge::instant(2026, 10, 22, 0, 0, 0);
    match validate_with_policy(file, &anchors, at, Some(&stub), policy) {
        Err(error) => {
            let debug = format!("{error:?}");
            let variant = debug
                .split(|c: char| !c.is_alphanumeric())
                .next()
                .unwrap()
                .to_owned();
            (Err(variant), false)
        }
        Ok(results) => {
            let sound = results.iter().any(|r| r.defect.is_none());
            let listed = results
                .iter()
                .map(|r| {
                    (
                        r.field.clone(),
                        r.report.indication(),
                        r.report.sub_indication(),
                    )
                })
                .collect();
            (Ok(listed), sound)
        }
    }
}

/// AC6: over the attack corpus, `strict()` minus one switch changes exactly the files whose
/// catalog row names that switch.
#[test]
fn each_switch_changes_only_what_the_catalog_names() {
    let files = attack_files();
    let cells = catalog(&files);
    let strict: BTreeMap<&String, Verdict> = files
        .iter()
        .map(|(name, file)| (name, verdict(file, &ValidationPolicy::strict()).0))
        .collect();
    for (switch, off) in SWITCHES {
        let policy = strict_without(off);
        let changed: BTreeSet<&str> = files
            .iter()
            .filter(|(name, file)| verdict(file, &policy).0 != strict[name])
            .map(|(name, _)| name.as_str())
            .collect();
        let named: BTreeSet<&str> = cells
            .iter()
            .filter(|(_, cell)| backticked(cell).contains(&switch))
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(changed, named, "{switch}");
    }
}

/// AC7: under `dss()`, a file opens (its verdict differs from `strict()` and a signature is
/// listed with no defect) exactly when its catalog row starts with `dss()`.
#[test]
fn dss_opens_only_what_the_catalog_marks() {
    let files = attack_files();
    let cells = catalog(&files);
    let opened: BTreeSet<&str> = files
        .iter()
        .filter(|(_, file)| {
            let (dss, sound) = verdict(file, &ValidationPolicy::dss());
            sound && dss != verdict(file, &ValidationPolicy::strict()).0
        })
        .map(|(name, _)| name.as_str())
        .collect();
    let marked: BTreeSet<&str> = cells
        .iter()
        .filter(|(_, cell)| cell.starts_with("`dss()`"))
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(opened, marked);
}
