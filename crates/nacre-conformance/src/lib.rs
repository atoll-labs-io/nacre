//! The client of Nacre's conformance bench (ADR-0007): it submits a signed file to the local,
//! pinned DSS 6.5.1 of `conformance/compose.yaml` and reads its verdict.
//!
//! DSS judges with the bench's anchors, configured on the server (`conformance/pki/out/anchors.p12`):
//! its REST validation takes no anchor per request. The verdict is read from the JSON simple
//! report; the ETSI `ValidationReport` XML that DSS returns alongside is kept as evidence.
//!
//! Reading a recorded answer ([`parse_response`], [`level`]) needs no network. Talking to DSS
//! ([`Dss`]) sits behind the `http` feature and only ever reaches `127.0.0.1` or `localhost`:
//! never the Commission's online demo.
#![forbid(unsafe_code)]

#[cfg(feature = "http")]
mod client;
mod report;

use std::path::PathBuf;

#[cfg(feature = "http")]
pub use client::Dss;
pub use report::{Reports, SignatureVerdict, level, parse_response};

/// Everything that can go wrong while asking DSS for a verdict or reading one.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A DSS URL outside the local machine, or a report name that would leave the report folder.
    #[error("refused: {0}")]
    Url(String),
    /// The request to DSS failed, or DSS answered with an error status.
    #[cfg(feature = "http")]
    #[error("DSS request failed: {0}")]
    Http(#[from] ureq::Error),
    /// DSS's answer is not JSON.
    #[error("DSS answer is not JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// DSS's answer is JSON but not shaped like a DSS 6.5.1 validation report.
    #[error("unexpected DSS report: {0}")]
    Report(&'static str),
    /// A report could not be written under `target/conformance/`.
    #[error("cannot keep the report: {0}")]
    Io(#[from] std::io::Error),
}

fn workspace_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// The bench's test PKI as generated at bench start, `conformance/pki/out/`: never committed,
/// and every key and serial changes with each start.
pub fn pki_dir() -> PathBuf {
    workspace_dir().join("conformance").join("pki").join("out")
}

/// The bench's reference documents as signed at bench start, `conformance/reference/out/`
/// (`conformance/reference/generate.sh`).
pub fn reference_dir() -> PathBuf {
    workspace_dir()
        .join("conformance")
        .join("reference")
        .join("out")
}

/// Where `Dss::validate` keeps DSS's answers: `<CARGO_TARGET_DIR or the workspace's
/// target>/conformance/`.
pub fn reports_dir() -> PathBuf {
    let target = match std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from) {
        Some(dir) if dir.is_absolute() => dir,
        Some(dir) => workspace_dir().join(dir),
        None => workspace_dir().join("target"),
    };
    target.join("conformance")
}
