/// The signature algorithm a [`Signer`](crate::Signer) produces.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// ECDSA on P-256 over a SHA-256 digest.
    EcdsaP256Sha256,
    /// RSASSA-PKCS1-v1_5 over a SHA-256 digest.
    RsaPkcs1v15Sha256,
}

impl SignatureAlgorithm {
    /// The digest algorithm the signed digest must be computed with.
    pub fn digest(self) -> DigestAlgorithm {
        match self {
            Self::EcdsaP256Sha256 | Self::RsaPkcs1v15Sha256 => DigestAlgorithm::Sha256,
        }
    }
}

/// A digest algorithm of the contract.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl DigestAlgorithm {
    /// The length of the digest in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}
