//! The subset of RFC 6960 §4.1-4.2 this crate reads and writes (ADR-0018). Self-contained
//! on `der`, `spki` and `x509-cert`, so the attack-corpus example can include it as is.

use der::asn1::{Any, BitString, GeneralizedTime, Null, ObjectIdentifier, OctetString};
use der::{Choice, Enumerated, Sequence};
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::Version;
use x509_cert::ext::Extensions;
use x509_cert::ext::pkix::CrlReason;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;

pub const ID_PKIX_OCSP_BASIC: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
pub const ID_PKIX_OCSP_NONCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.2");
pub const ID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// `OCSPRequest ::= SEQUENCE { tbsRequest, optionalSignature [0] EXPLICIT OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspRequest {
    pub tbs_request: TbsRequest,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub optional_signature: Option<Any>,
}

/// `TBSRequest`; `requestorName` is kept undecoded, this crate never sends one.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsRequest {
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub requestor_name: Option<Any>,
    pub request_list: Vec<Request>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub request_extensions: Option<Extensions>,
}

/// `Request ::= SEQUENCE { reqCert CertID, singleRequestExtensions [0] EXPLICIT OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Request {
    pub req_cert: CertId,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub single_request_extensions: Option<Extensions>,
}

/// `CertID`: hashes of the issuer's name and key, and the certificate's serial.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CertId {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub issuer_name_hash: OctetString,
    pub issuer_key_hash: OctetString,
    pub serial_number: SerialNumber,
}

/// `OCSPResponseStatus`; 4 is not used by RFC 6960 and reads as invalid DER.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Enumerated)]
#[repr(u8)]
pub enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

/// `OCSPResponse ::= SEQUENCE { responseStatus, responseBytes [0] EXPLICIT OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct OcspResponse {
    pub response_status: OcspResponseStatus,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub response_bytes: Option<ResponseBytes>,
}

/// `ResponseBytes ::= SEQUENCE { responseType OBJECT IDENTIFIER, response OCTET STRING }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseBytes {
    pub response_type: ObjectIdentifier,
    pub response: OctetString,
}

/// `BasicOCSPResponse`; the certificates stay undecoded so that each one's `tbsCertificate`
/// can be verified on the bytes received.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub certs: Option<Vec<Any>>,
}

/// `ResponseData`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ResponseData {
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,
    pub responder_id: ResponderId,
    pub produced_at: GeneralizedTime,
    pub responses: Vec<SingleResponse>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub response_extensions: Option<Extensions>,
}

/// `ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }`, explicitly tagged.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Name),
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(OctetString),
}

/// `SingleResponse`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    pub this_update: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub next_update: Option<GeneralizedTime>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub single_extensions: Option<Extensions>,
}

/// `CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] IMPLICIT RevokedInfo,
/// unknown [2] IMPLICIT UnknownInfo }`, `UnknownInfo` being `NULL`.
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
pub enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(Null),
}

/// `RevokedInfo ::= SEQUENCE { revocationTime, revocationReason [0] EXPLICIT OPTIONAL }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct RevokedInfo {
    pub revocation_time: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub revocation_reason: Option<CrlReason>,
}
