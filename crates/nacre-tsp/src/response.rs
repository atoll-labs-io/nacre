use der::asn1::BitStringRef;
use der::{Decode, Reader, Tag};

use crate::asn1::{expect, nested, peek_tag};
use crate::{Error, Request, VerifiedToken, verify_token};

const GRANTED: u32 = 0;
const GRANTED_WITH_MODS: u32 = 1;

/// Reads `response`, a DER `TimeStampResp` answering `request`, and verifies its token:
/// the status grants the request, then [`verify_token`] with the request's imprint, then
/// the token's nonce equals the request's.
pub fn verify_response(response: &[u8], request: &Request) -> Result<VerifiedToken, Error> {
    let (status, fail_info, token) = nested(response, |r| {
        nested(expect(r, Tag::Sequence)?, |r| {
            let (status, fail_info) = nested(expect(r, Tag::Sequence)?, |r| {
                let status = u32::decode(r)?;
                if peek_tag(r)? == Some(Tag::Sequence) {
                    expect(r, Tag::Sequence)?;
                }
                let fail_info = match peek_tag(r)? {
                    Some(Tag::BitString) => Some(fail_bits(BitStringRef::decode(r)?)),
                    _ => None,
                };
                Ok((status, fail_info))
            })?;
            let token = match peek_tag(r)? {
                Some(_) => Some(r.tlv_bytes()?),
                None => None,
            };
            Ok((status, fail_info, token))
        })
    })?;

    if status != GRANTED && status != GRANTED_WITH_MODS {
        return Err(Error::Refused { status, fail_info });
    }
    let token = token.ok_or(Error::TokenMissing)?;
    let verified = verify_token(token, request.algorithm(), request.imprint())?;
    match verified.nonce() {
        None => Err(Error::NonceMissing),
        Some(nonce) if nonce != request.nonce() => Err(Error::NonceMismatch),
        Some(_) => Ok(verified),
    }
}

/// `PKIFailureInfo` named bits as a mask: bit `n` of the BIT STRING is `1 << n`. Bits past
/// 31 name no failure RFC 3161 defines and are dropped.
fn fail_bits(bits: BitStringRef<'_>) -> u32 {
    bits.bits()
        .take(32)
        .enumerate()
        .filter(|(_, set)| *set)
        .fold(0, |mask, (n, _)| mask | (1 << n))
}
