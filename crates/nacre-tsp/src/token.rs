use der::asn1::{OctetString, UintRef};
use der::{DateTime, Decode, Tag, TagNumber};
use nacre_cms::SignedData;
use nacre_core::DigestAlgorithm;
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::ext::pkix::ExtendedKeyUsage;

use crate::asn1::{expect, nested, peek_tag};
use crate::request::{check_digest_length, digest_oid, unsigned};
use crate::{Error, oid};

const CONTEXT_0: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber(0),
};
const CONTEXT_1: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber(1),
};

/// A time-stamp token whose signature, TSA certificate binding and imprint verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    token: Vec<u8>,
    tsa_certificate: Vec<u8>,
    gen_time: DateTime,
    policy: Vec<u8>,
    serial_number: Vec<u8>,
    nonce: Option<Vec<u8>>,
}

impl VerifiedToken {
    /// The DER `TimeStampToken` (a `ContentInfo`) as received, never re-encoded.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// The DER of the certificate that signed the token, as carried in it.
    pub fn tsa_certificate(&self) -> &[u8] {
        &self.tsa_certificate
    }

    /// The `genTime` of the token, to the second; a fraction is read and dropped.
    pub fn gen_time(&self) -> DateTime {
        self.gen_time
    }

    /// The content octets of the policy `OBJECT IDENTIFIER`, as received: `const-oid`
    /// refuses some valid identifiers, such as the bench TSA's `2.999.1.1`.
    pub fn policy(&self) -> &[u8] {
        &self.policy
    }

    /// The serial number, unsigned big-endian.
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }

    /// The nonce, unsigned big-endian with leading zero octets stripped, when the token
    /// carries one.
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }
}

/// Verifies `token`, a DER `TimeStampToken`, as time-stamping `imprint`, a digest
/// computed with `algorithm`.
///
/// It does not judge the TSA certificate's chain or validity, nor `genTime`.
pub fn verify_token(
    token: &[u8],
    algorithm: DigestAlgorithm,
    imprint: &[u8],
) -> Result<VerifiedToken, Error> {
    let expected_oid = digest_oid(algorithm)?;
    check_digest_length(algorithm, imprint)?;

    // The order of the checks is part of the contract: each attack of the corpus must
    // reach the rule that names it.
    let signed = SignedData::from_der(token)?;
    if signed.encap_content_info.econtent_type != oid::TST_INFO {
        return Err(Error::NotTstInfo);
    }
    let econtent = signed.econtent().ok_or(Error::NotTstInfo)?;
    let signer = signed.verify(None)?;

    // nacre-cms checks signingCertificateV2 only when present; without it nothing binds
    // the signature to the certificate that carries the timeStamping purpose.
    let has_ess_v2 = signer
        .signer_info()
        .signed_attrs
        .as_ref()
        .map(|attrs| attrs.attributes())
        .transpose()?
        .is_some_and(|attrs| attrs.iter().any(|a| a.oid == oid::SIGNING_CERTIFICATE_V2));
    if !has_ess_v2 {
        return Err(Error::SigningCertificateMissing);
    }
    check_timestamping_purpose(signer.certificate())?;

    let info = TstInfo::from_der(econtent)?;
    let parameters_null = match &info.hash_algorithm.parameters {
        None => true,
        Some(any) => any.header().tag() == Tag::Null && any.value().is_empty(),
    };
    if info.hash_algorithm.oid != expected_oid || !parameters_null || info.hashed != imprint {
        return Err(Error::ImprintMismatch);
    }

    Ok(VerifiedToken {
        token: token.to_vec(),
        tsa_certificate: signer.certificate().to_vec(),
        gen_time: info.gen_time,
        policy: info.policy,
        serial_number: info.serial_number,
        nonce: info.nonce,
    })
}

/// RFC 3161 §2.3: the extended key usage is present, critical, and `id-kp-timeStamping`
/// is its only purpose.
fn check_timestamping_purpose(certificate: &[u8]) -> Result<(), Error> {
    let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
    match certificate
        .tbs_certificate()
        .get_extension::<ExtendedKeyUsage>()
        .map_err(Error::Certificate)?
    {
        Some((true, usage)) if usage.0 == [oid::TIME_STAMPING] => Ok(()),
        _ => Err(Error::NotTimestampingCertificate),
    }
}

/// The fields of a `TSTInfo` (RFC 3161 §2.4.2) this crate reads; `accuracy`, `ordering`,
/// `tsa` and `extensions` are skipped.
struct TstInfo {
    policy: Vec<u8>,
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed: Vec<u8>,
    serial_number: Vec<u8>,
    gen_time: DateTime,
    nonce: Option<Vec<u8>>,
}

impl TstInfo {
    fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        nested(bytes, |r| {
            nested(expect(r, Tag::Sequence)?, |r| {
                let version = u8::decode(r)?;
                if version != 1 {
                    return Err(Error::TstInfoVersion(version));
                }
                let policy = expect(r, Tag::ObjectIdentifier)?.to_vec();
                let (hash_algorithm, hashed) = nested(expect(r, Tag::Sequence)?, |r| {
                    let algorithm = AlgorithmIdentifierOwned::decode(r)?;
                    let hashed = OctetString::decode(r)?.into_bytes().into_vec();
                    Ok((algorithm, hashed))
                })?;
                let serial_number = UintRef::decode(r)?.as_bytes().to_vec();
                let gen_time = parse_gen_time(expect(r, Tag::GeneralizedTime)?)?;
                if peek_tag(r)? == Some(Tag::Sequence) {
                    expect(r, Tag::Sequence)?;
                }
                if peek_tag(r)? == Some(Tag::Boolean) {
                    bool::decode(r)?;
                }
                let nonce = match peek_tag(r)? {
                    Some(Tag::Integer) => Some(unsigned(UintRef::decode(r)?.as_bytes())?),
                    _ => None,
                };
                if peek_tag(r)? == Some(CONTEXT_0) {
                    expect(r, CONTEXT_0)?;
                }
                if peek_tag(r)? == Some(CONTEXT_1) {
                    expect(r, CONTEXT_1)?;
                }
                Ok(Self {
                    policy,
                    hash_algorithm,
                    hashed,
                    serial_number,
                    gen_time,
                    nonce,
                })
            })
        })
    }
}

/// `YYYYMMDDHHMMSS[.f]Z` with one to nine fraction digits: RFC 3161 §2.4.2 allows the
/// fraction that `der::asn1::GeneralizedTime` refuses.
fn parse_gen_time(bytes: &[u8]) -> Result<DateTime, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::GenTime)?;
    let body = text.strip_suffix('Z').ok_or(Error::GenTime)?;
    let (whole, fraction) = match body.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (body, None),
    };
    let all_digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.len() != 14 || !all_digits(whole) {
        return Err(Error::GenTime);
    }
    if let Some(fraction) = fraction
        && (fraction.is_empty() || fraction.len() > 9 || !all_digits(fraction))
    {
        return Err(Error::GenTime);
    }
    let field = |from: usize, to: usize| -> Result<u16, Error> {
        whole
            .get(from..to)
            .and_then(|digits| digits.parse().ok())
            .ok_or(Error::GenTime)
    };
    let narrow = |value: u16| u8::try_from(value).map_err(|_| Error::GenTime);
    DateTime::new(
        field(0, 4)?,
        narrow(field(4, 6)?)?,
        narrow(field(6, 8)?)?,
        narrow(field(8, 10)?)?,
        narrow(field(10, 12)?)?,
        narrow(field(12, 14)?)?,
    )
    .map_err(|_| Error::GenTime)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn gen_time_parsing() {
        let second = DateTime::new(2026, 10, 22, 9, 25, 50).unwrap();
        assert_eq!(parse_gen_time(b"20261022092550Z").unwrap(), second);
        assert_eq!(parse_gen_time(b"20261022092550.125Z").unwrap(), second);
        for refused in [
            &b"20261022092550.Z"[..],
            b"20261022092550.1234567891Z",
            b"20261022092550",
            b"20261322092550Z",
        ] {
            assert!(
                matches!(parse_gen_time(refused), Err(Error::GenTime)),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }
}
