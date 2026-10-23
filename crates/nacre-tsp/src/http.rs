use std::time::Duration;

use nacre_core::{DigestAlgorithm, TimestampAuthority};

use crate::{Error, Request, verify_response};

const TIMEOUT: Duration = Duration::from_secs(30);
// A TimeStampResp is a few kilobytes; a TSA that sends more is not answering.
const BODY_LIMIT: u64 = 1024 * 1024;

/// A [`TimestampAuthority`] that posts an RFC 3161 request to a TSA over HTTP
/// (`application/timestamp-query`) and returns the token once [`verify_response`] has
/// verified it.
#[derive(Debug)]
pub struct HttpTsa {
    url: String,
    agent: ureq::Agent,
}

impl HttpTsa {
    /// A client of the TSA at `url`, `http://` or `https://`.
    pub fn new(url: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .build();
        Self {
            url: url.to_owned(),
            agent: ureq::Agent::new_with_config(config),
        }
    }

    fn request(&self, algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<Vec<u8>, Error> {
        let request = Request::with_random_nonce(algorithm, imprint)?;
        let response = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/timestamp-query")
            .send(&request.to_der()?[..])?
            .into_body()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_vec()?;
        Ok(verify_response(&response, &request)?.token().to_vec())
    }
}

impl TimestampAuthority for HttpTsa {
    fn timestamp(
        &self,
        algorithm: DigestAlgorithm,
        imprint: &[u8],
    ) -> Result<Vec<u8>, nacre_core::Error> {
        // A wrong-length imprint is refused before any request: the caller's mistake, not
        // an unavailable TSA.
        self.request(algorithm, imprint)
            .map_err(|error| match error {
                Error::DigestLength { expected, actual } => {
                    nacre_core::Error::DigestLength { expected, actual }
                }
                error => nacre_core::Error::timestamp_with_kind(error.kind(), error),
            })
    }
}
