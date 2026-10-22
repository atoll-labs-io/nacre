use std::time::Duration;

use base64ct::{Base64, Encoding};
use serde_json::json;

use crate::{Error, Reports, parse_response, reports_dir};

const DEFAULT_URL: &str = "http://127.0.0.1:18080";
// DSS answers with its detailed report and diagnostic data, which grow with the document;
// ureq's default cap of 10 MB is too low for a large PDF.
const BODY_LIMIT: u64 = 64 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

/// A local DSS 6.5.1, as `conformance/compose.yaml` runs it.
#[derive(Debug)]
pub struct Dss {
    base_url: String,
    agent: ureq::Agent,
}

impl Dss {
    /// A client of the DSS at `base_url`, which must be `http://127.0.0.1:<port>` or
    /// `http://localhost:<port>`: documents never leave the machine.
    pub fn new(base_url: &str) -> Result<Self, Error> {
        let local = base_url.trim_end_matches('/');
        let authority = local
            .strip_prefix("http://")
            .ok_or_else(|| refused_url(base_url))?;
        let (host, port) = authority
            .split_once(':')
            .ok_or_else(|| refused_url(base_url))?;
        let port_is_valid = !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port != 0);
        if !matches!(host, "127.0.0.1" | "localhost") || !port_is_valid {
            return Err(refused_url(base_url));
        }
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .build();
        Ok(Self {
            base_url: local.to_owned(),
            agent: ureq::Agent::new_with_config(config),
        })
    }

    /// The DSS named by `NACRE_DSS_URL`, by default the bench's `http://127.0.0.1:18080`.
    pub fn from_env() -> Result<Self, Error> {
        match std::env::var("NACRE_DSS_URL") {
            Ok(url) => Self::new(&url),
            Err(_) => Self::new(DEFAULT_URL),
        }
    }

    /// Submits `document` to DSS's REST validation and reads its verdict.
    ///
    /// The raw JSON answer and the ETSI XML report are kept as
    /// `<target>/conformance/<name>.json` and `<name>.xml`; `name` may hold neither a path
    /// separator nor `..`.
    pub fn validate(&self, name: &str, document: &[u8]) -> Result<Reports, Error> {
        if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
            return Err(Error::Url(format!("report name {name:?}")));
        }
        let url = format!(
            "{}/services/rest/validation/validateSignature",
            self.base_url
        );
        let request = json!({
            "signedDocument": { "bytes": Base64::encode_string(document), "name": name },
            "originalDocuments": [],
            "policy": null,
            "signatureId": null,
        });
        let body = self
            .agent
            .post(&url)
            .send_json(&request)?
            .into_body()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_vec()?;

        let dir = reports_dir();
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{name}.json")), &body)?;
        let reports = parse_response(&body)?;
        std::fs::write(dir.join(format!("{name}.xml")), &reports.etsi_xml)?;
        Ok(reports)
    }
}

fn refused_url(url: &str) -> Error {
    Error::Url(format!(
        "DSS URL {url:?}: only http://127.0.0.1:<port> or http://localhost:<port>"
    ))
}
