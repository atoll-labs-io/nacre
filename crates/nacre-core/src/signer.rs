use crate::{Error, SignatureAlgorithm};

/// Something that signs a digest with a private key it never exposes.
pub trait Signer {
    /// The algorithm of the signatures this signer produces.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The certificate chain as DER: the signer's own certificate first, then its issuers
    /// towards the trust anchor. Never empty.
    fn certificate_chain(&self) -> &[Vec<u8>];

    /// Signs `digest`, computed with `self.algorithm().digest()`.
    ///
    /// An ECDSA signature is returned as a DER `ECDSA-Sig-Value`, an RSA signature as the
    /// raw signature bytes.
    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, Error>;
}
