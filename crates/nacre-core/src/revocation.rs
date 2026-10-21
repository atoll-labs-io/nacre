use crate::Error;

/// Revocation data for one certificate, as DER.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationData {
    /// A DER `CertificateList`.
    Crl(Vec<u8>),
    /// A DER `OCSPResponse`.
    Ocsp(Vec<u8>),
}

/// Something that obtains revocation data for a certificate.
pub trait RevocationSource {
    /// Returns a CRL or an OCSP response covering `certificate`, both given as DER;
    /// `issuer` is the certificate that issued it, which an OCSP request needs.
    fn revocation(&self, certificate: &[u8], issuer: &[u8]) -> Result<RevocationData, Error>;
}
