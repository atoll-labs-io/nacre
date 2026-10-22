use der::Decode;
use nacre_cms::Profile;
use nacre_core::{SignatureAlgorithm, Signer};
use x509_cert::Certificate;

use crate::Error;

/// DER `ECDSA-Sig-Value` for P-256 at its longest: two 33-byte integers and their headers.
const ECDSA_P256_MAX: usize = 72;

/// The longest signature value `algorithm` can produce with the key of `certificate`.
fn max_signature_len(
    algorithm: SignatureAlgorithm,
    certificate: &[u8],
) -> Result<usize, nacre_core::Error> {
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => Ok(ECDSA_P256_MAX),
        // The key's bit string holds the modulus and the exponent in a DER sequence, so it
        // is always longer than a signature, which is as long as the modulus.
        SignatureAlgorithm::RsaPkcs1v15Sha256 => {
            let certificate = Certificate::from_der(certificate)
                .map_err(|error| nacre_core::Error::Signer(Box::new(error)))?;
            Ok(certificate
                .tbs_certificate()
                .subject_public_key_info()
                .subject_public_key
                .raw_bytes()
                .len())
        }
        _ => Err(nacre_core::Error::Signer(
            "unsupported signature algorithm".into(),
        )),
    }
}

/// Stands in for the real signer during the dry run: it returns a placeholder of the
/// longest length and never reaches the key, which may count its uses.
struct Sizing<'s> {
    inner: &'s dyn Signer,
}

impl Signer for Sizing<'_> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        self.inner.certificate_chain()
    }

    fn sign_digest(&self, _digest: &[u8]) -> Result<Vec<u8>, nacre_core::Error> {
        let certificate = self
            .inner
            .certificate_chain()
            .first()
            .map(Vec::as_slice)
            .unwrap_or_default();
        Ok(vec![0; max_signature_len(self.algorithm(), certificate)?])
    }
}

/// The bytes to reserve for `/Contents`: the length of the CMS `signer` would write with its
/// longest signature value. The CMS length depends on nothing else, so the real one fits.
///
/// This is the single place a later level adds the timestamp token's reserve to;
/// PAdES-BASELINE-B reserves nothing for a token.
pub(crate) fn contents_capacity(signer: &dyn Signer) -> Result<usize, Error> {
    let digest = [0; 32];
    let dry = nacre_cms::sign_detached(&digest, &Sizing { inner: signer }, &Profile::PADES, None)?;
    Ok(dry.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn rsa_bound_covers_the_signature() {
        let der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/corpus/rsa-detached.der"
        ))
        .unwrap();
        let signed = nacre_cms::SignedData::from_der(&der).unwrap();
        let signature = &signed.signer_infos[0].signature;

        let bound = max_signature_len(
            SignatureAlgorithm::RsaPkcs1v15Sha256,
            &signed.certificates[0],
        )
        .unwrap();

        assert!(bound >= signature.len(), "{bound} < {}", signature.len());
        assert!(bound < signature.len() + 64, "{bound}");
    }
}
