use der::asn1::{Any, OctetString};
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use x509_cert::certificate::Version;
use x509_cert::ext::Extension;

use super::asn1::{self, CertId, ID_PKIX_OCSP_NONCE, ID_SHA1, ID_SHA256, Request, TbsRequest};
use crate::Error;

/// RFC 8954 §2.1: a nonce of 32 octets, the most a responder must accept.
const NONCE_LEN: usize = 32;

/// An OCSP request for one certificate, with a nonce and no signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspRequest {
    cert_id: CertId,
    nonce: Vec<u8>,
}

impl OcspRequest {
    /// A request about `certificate`, issued by `issuer`, both given as DER, carrying
    /// `nonce`, of 1 to 32 octets (RFC 8954 §2.1), else [`Error::NonceLength`]. The `CertID` uses SHA-1, which RFC 5019 §2.1.1 asks of clients: it only
    /// identifies the certificate, the response's signature does not depend on it.
    pub fn new(certificate: &[u8], issuer: &[u8], nonce: &[u8]) -> Result<Self, Error> {
        if !(1..=NONCE_LEN).contains(&nonce.len()) {
            return Err(Error::NonceLength(nonce.len()));
        }
        let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
        let issuer = Certificate::from_der(issuer).map_err(Error::IssuerCertificate)?;
        Ok(Self {
            cert_id: cert_id(ID_SHA1, &certificate, &issuer)?,
            nonce: nonce.to_vec(),
        })
    }

    /// A request with a fresh random nonce of 32 octets.
    pub fn with_random_nonce(certificate: &[u8], issuer: &[u8]) -> Result<Self, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(Error::Random)?;
        Self::new(certificate, issuer, &nonce)
    }

    /// The nonce this request carries.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// The DER `OCSPRequest`: version 1, one request, the nonce extension, non-critical,
    /// whose value is the DER `OCTET STRING` of the nonce (RFC 8954 §2.1).
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let nonce = Extension {
            extn_id: ID_PKIX_OCSP_NONCE,
            critical: false,
            extn_value: OctetString::new(OctetString::new(self.nonce.as_slice())?.to_der()?)?,
        };
        let request = asn1::OcspRequest {
            tbs_request: TbsRequest {
                version: Version::V1,
                requestor_name: None,
                request_list: vec![Request {
                    req_cert: self.cert_id.clone(),
                    single_request_extensions: None,
                }],
                request_extensions: Some(vec![nonce]),
            },
            optional_signature: None,
        };
        Ok(request.to_der()?)
    }
}

/// The `CertID` of `certificate` under `issuer`, hashed with `algorithm` (SHA-1 or
/// SHA-256): the hash of the issuer's encoded subject, the hash of its `subjectPublicKey`
/// bit string value, and the certificate's serial.
pub(crate) fn cert_id(
    algorithm: ObjectIdentifier,
    certificate: &Certificate,
    issuer: &Certificate,
) -> Result<CertId, Error> {
    let issuer_tbs = issuer.tbs_certificate();
    let name = issuer_tbs
        .subject()
        .to_der()
        .map_err(Error::IssuerCertificate)?;
    let key = issuer_tbs
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let (name_hash, key_hash) = match algorithm {
        ID_SHA1 => (Sha1::digest(&name).to_vec(), Sha1::digest(key).to_vec()),
        ID_SHA256 => (Sha256::digest(&name).to_vec(), Sha256::digest(key).to_vec()),
        other => return Err(Error::UnsupportedAlgorithm(other)),
    };
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: algorithm,
            parameters: Some(Any::null()),
        },
        issuer_name_hash: OctetString::new(name_hash)?,
        issuer_key_hash: OctetString::new(key_hash)?,
        serial_number: certificate.tbs_certificate().serial_number().clone(),
    })
}

/// `KeyHash` of RFC 6960 §4.2.1: SHA-1 of the `subjectPublicKey` bit string value.
pub(crate) fn key_hash(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    Sha1::digest(spki.subject_public_key.raw_bytes()).to_vec()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn request_cert_id_matches_openssl() {
        let ca = include_bytes!("../../tests/corpus/ocsp-openssl/ca.der");
        let leaf = include_bytes!("../../tests/corpus/ocsp-openssl/leaf.der");
        let fixture = include_bytes!("../../tests/corpus/ocsp-openssl/request-leaf.der");
        let openssl = asn1::OcspRequest::from_der(fixture).unwrap();
        let ours = asn1::OcspRequest::from_der(
            &OcspRequest::new(leaf, ca, &[7; 32])
                .unwrap()
                .to_der()
                .unwrap(),
        )
        .unwrap();
        let openssl_id = &openssl.tbs_request.request_list[0].req_cert;
        let our_id = &ours.tbs_request.request_list[0].req_cert;
        assert_eq!(openssl_id.hash_algorithm.oid, ID_SHA1);
        assert_eq!(our_id, openssl_id);
    }

    #[test]
    fn nonce_outside_one_to_32_octets_is_refused() {
        let ca = include_bytes!("../../tests/corpus/ocsp-openssl/ca.der");
        let leaf = include_bytes!("../../tests/corpus/ocsp-openssl/leaf.der");
        for length in [0, 33] {
            assert!(matches!(
                OcspRequest::new(leaf, ca, &vec![7; length]),
                Err(Error::NonceLength(got)) if got == length
            ));
        }
        assert!(OcspRequest::new(leaf, ca, &[7]).is_ok());
    }
}
