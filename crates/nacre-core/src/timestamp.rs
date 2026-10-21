use crate::{DigestAlgorithm, Error};

/// An RFC 3161 timestamp authority.
pub trait TimestampAuthority {
    /// Obtains a timestamp over `imprint`, a digest computed with `algorithm`, and returns
    /// the DER `TimeStampToken`. Only the imprint leaves the caller.
    fn timestamp(&self, algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<Vec<u8>, Error>;
}
