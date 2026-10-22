use der::asn1::{OctetString, UintRef};
use der::oid::ObjectIdentifier;
use der::{Any, Encode, Tag};
use nacre_core::DigestAlgorithm;
use spki::AlgorithmIdentifierOwned;

use crate::asn1::tlv;
use crate::{Error, oid};

const NONCE_LEN: usize = 8;

/// An RFC 3161 `TimeStampReq` over an imprint, with a nonce and `certReq` set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    algorithm: DigestAlgorithm,
    imprint: Vec<u8>,
    nonce: Vec<u8>,
}

impl Request {
    /// A request over `imprint`, a digest computed with `algorithm`, with `nonce` read as
    /// an unsigned big-endian integer.
    pub fn new(algorithm: DigestAlgorithm, imprint: &[u8], nonce: &[u8]) -> Result<Self, Error> {
        digest_oid(algorithm)?;
        check_digest_length(algorithm, imprint)?;
        Ok(Self {
            algorithm,
            imprint: imprint.to_vec(),
            nonce: unsigned(nonce)?,
        })
    }

    /// A request over `imprint` with a fresh 64-bit random nonce.
    pub fn with_random_nonce(algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<Self, Error> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(Error::Random)?;
        Self::new(algorithm, imprint, &nonce)
    }

    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    pub fn imprint(&self) -> &[u8] {
        &self.imprint
    }

    /// The nonce as an unsigned big-endian integer, leading zero octets stripped.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// The DER `TimeStampReq`: version 1, the imprint, the nonce, `certReq` TRUE, no
    /// policy and no extensions.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let mut body = 1u8.to_der()?;
        body.extend(message_imprint(self.algorithm, &self.imprint)?);
        body.extend(UintRef::new(&self.nonce)?.to_der()?);
        body.extend(true.to_der()?);
        tlv(Tag::Sequence, &body)
    }
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }`, parameters NULL as
/// OpenSSL writes them.
fn message_imprint(algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<Vec<u8>, Error> {
    let mut body = AlgorithmIdentifierOwned {
        oid: digest_oid(algorithm)?,
        parameters: Some(Any::null()),
    }
    .to_der()?;
    body.extend(OctetString::new(imprint)?.to_der()?);
    tlv(Tag::Sequence, &body)
}

pub(crate) fn digest_oid(algorithm: DigestAlgorithm) -> Result<ObjectIdentifier, Error> {
    match algorithm {
        DigestAlgorithm::Sha256 => Ok(oid::SHA256),
        DigestAlgorithm::Sha384 => Ok(oid::SHA384),
        DigestAlgorithm::Sha512 => Ok(oid::SHA512),
        other => Err(Error::UnsupportedAlgorithm(other)),
    }
}

pub(crate) fn check_digest_length(algorithm: DigestAlgorithm, digest: &[u8]) -> Result<(), Error> {
    let expected = algorithm.output_len();
    if digest.len() != expected {
        return Err(Error::DigestLength {
            expected,
            actual: digest.len(),
        });
    }
    Ok(())
}

/// `bytes` as an unsigned integer with its leading zero octets stripped; zero is `[0]`.
pub(crate) fn unsigned(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let stripped = UintRef::new(bytes)?.as_bytes();
    Ok(if stripped.is_empty() {
        vec![0]
    } else {
        stripped.to_vec()
    })
}
