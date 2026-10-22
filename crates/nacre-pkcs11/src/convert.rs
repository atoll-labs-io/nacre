use crate::Error;

/// The DER `DigestInfo` prefix for SHA-256 (RFC 8017, section 9.2, note 1), followed by the
/// 32-byte digest in what `CKM_RSA_PKCS` signs.
pub(crate) const DIGEST_INFO_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Turns the token's raw P-256 `r||s` into a DER `ECDSA-Sig-Value`.
pub(crate) fn ecdsa_der(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let length = || Error::SignatureLength { actual: raw.len() };
    if raw.len() != 64 {
        return Err(length());
    }
    let signature = p256::ecdsa::Signature::from_slice(raw).map_err(|_| length())?;
    Ok(signature.to_der().as_bytes().to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn raw_ecdsa_becomes_minimal_der() {
        let mut raw = [0u8; 64];
        raw[31] = 0x01;
        raw[32] = 0x80;
        let mut expected = vec![0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00, 0x80];
        expected.extend([0u8; 31]);
        assert_eq!(ecdsa_der(&raw).unwrap(), expected);

        assert!(matches!(
            ecdsa_der(&raw[..63]),
            Err(Error::SignatureLength { actual: 63 })
        ));
    }
}
