//! OCSP (RFC 6960): a request with a nonce, and the reading and judging of a basic response.

pub(crate) mod asn1;
mod request;
mod response;

pub use request::OcspRequest;
pub use response::{OcspResponse, OcspStatus};
