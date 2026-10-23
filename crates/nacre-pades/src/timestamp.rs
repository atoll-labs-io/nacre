use der::asn1::ObjectIdentifier;
use der::{Any, Decode};
use nacre_cms::{Attribute, SignedData};
use nacre_core::{DigestAlgorithm, TimestampAuthority};
use sha2::{Digest, Sha256};

use crate::Error;

/// `id-aa-signatureTimeStampToken` (RFC 3161 Appendix A, RFC 5126).
const SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");

/// The largest DER `TimeStampToken` the `/Contents` slot reserves room for. Recorded tokens
/// are about 1.8 KB (bench) and 6 KB (DigiCert, RSA-4096 with its chain).
pub const TIMESTAMP_TOKEN_MAX: usize = 16_384;

/// Puts `token` into the first `SignerInfo` of `cms` as its signature timestamp. The only
/// place the attribute is built, for the dry run and the real one alike.
pub(crate) fn with_token(cms: &[u8], token: Any) -> Result<Vec<u8>, Error> {
    let mut signed = SignedData::from_der(cms)?;
    let info = signed
        .signer_infos
        .first_mut()
        .ok_or(Error::Cms(nacre_cms::Error::SignerCount(0)))?;
    info.push_unsigned_attribute(Attribute {
        oid: SIGNATURE_TIME_STAMP_TOKEN,
        values: vec![token],
    });
    Ok(signed.to_der()?)
}

/// SHA-256 of the signature value's content octets.
fn signature_imprint(cms: &[u8]) -> Result<Vec<u8>, Error> {
    let signed = SignedData::from_der(cms)?;
    let info = signed
        .signer_infos
        .first()
        .ok_or(Error::Cms(nacre_cms::Error::SignerCount(0)))?;
    Ok(Sha256::digest(&info.signature).to_vec())
}

/// Asks `tsa` to time-stamp the signature value of `cms` and returns `cms` carrying the token.
pub(crate) fn timestamp_signature(
    cms: &[u8],
    tsa: &dyn TimestampAuthority,
) -> Result<Vec<u8>, Error> {
    let imprint = signature_imprint(cms)?;
    let token = tsa
        .timestamp(DigestAlgorithm::Sha256, &imprint)
        .map_err(Error::Timestamp)?;
    if token.len() > TIMESTAMP_TOKEN_MAX {
        return Err(Error::TimestampTooLarge {
            len: token.len(),
            max: TIMESTAMP_TOKEN_MAX,
        });
    }
    let token = Any::from_der(&token).map_err(Error::TimestampToken)?;
    with_token(cms, token)
}
