use std::time::SystemTime;

use der::asn1::AnyRef;
use der::{Decode, Reader, SliceReader};
use x509_cert::Certificate;
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::ext::Extensions;
use x509_cert::ext::pkix::CrlReason;
use x509_cert::name::Name;

use crate::Error;

/// A decoded CRL, with the `tbsCertList` bytes it arrived with.
#[derive(Debug, Clone)]
pub struct Crl {
    list: CertificateList,
    tbs: Vec<u8>,
}

/// One entry of a CRL's `revokedCertificates`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedEntry {
    /// The content octets of the serial number, as encoded in the CRL.
    pub serial: Vec<u8>,
    /// The `revocationDate`.
    pub date: SystemTime,
    /// The `reasonCode` entry extension, when present.
    pub reason: Option<CrlReason>,
}

/// What a usable CRL says of a certificate. A CRL that cannot be used is an [`Error`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlStatus {
    /// The certificate's serial is not listed.
    NotRevoked,
    /// The certificate's serial is listed. The date may be after the control date: whether a
    /// revocation applies to a signature made before it is the caller's judgement.
    Revoked {
        /// The `revocationDate` of the entry.
        date: SystemTime,
        /// Its `reasonCode`, when present.
        reason: Option<CrlReason>,
    },
}

impl Crl {
    /// Reads a DER `CertificateList`. Bytes after it are an error.
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        let list = CertificateList::from_der(bytes)?;
        let mut outer = SliceReader::new(bytes)?;
        let sequence = AnyRef::decode(&mut outer)?;
        outer.finish()?;
        let mut inner = SliceReader::new(sequence.value())?;
        let tbs = inner.tlv_bytes()?.to_vec();
        Ok(Self { list, tbs })
    }

    pub(crate) fn certificate_list(&self) -> &CertificateList {
        &self.list
    }

    /// The `tbsCertList` bytes as received, over which the signature is checked.
    pub(crate) fn tbs_bytes(&self) -> &[u8] {
        &self.tbs
    }

    /// The CRL issuer's name.
    pub fn issuer(&self) -> &Name {
        &self.list.tbs_cert_list.issuer
    }

    /// `thisUpdate`.
    pub fn this_update(&self) -> SystemTime {
        self.list.tbs_cert_list.this_update.to_system_time()
    }

    /// `nextUpdate`, absent from a CRL that [`Crl::status`] refuses.
    pub fn next_update(&self) -> Option<SystemTime> {
        self.list
            .tbs_cert_list
            .next_update
            .map(|time| time.to_system_time())
    }

    /// Every revoked entry, in the CRL's order. A malformed `reasonCode` is an error.
    pub fn revoked(&self) -> Result<Vec<RevokedEntry>, Error> {
        self.entries().iter().map(entry).collect()
    }

    /// Verifies the CRL's signature with `issuer_certificate`, given as DER.
    pub fn verify_signature(&self, issuer_certificate: &[u8]) -> Result<(), Error> {
        let issuer = Certificate::from_der(issuer_certificate).map_err(Error::IssuerCertificate)?;
        crate::verify::verify(self, &issuer)
    }

    /// Says whether `certificate` is listed, judging the CRL against `issuer`, the
    /// certificate that issued it, at the control date `at`. Both are given as DER.
    ///
    /// A `thisUpdate` after `at` is accepted: a CRL issued later still tells about the
    /// past. The CRL's authority key identifier is not judged; its signature proves the key.
    pub fn status(
        &self,
        certificate: &[u8],
        issuer: &[u8],
        at: SystemTime,
    ) -> Result<CrlStatus, Error> {
        // The order is part of the contract: each attack of the corpus must reach the rule
        // that names it (docs/security/attacks/revocation.md).
        let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
        let issuer = Certificate::from_der(issuer).map_err(Error::IssuerCertificate)?;

        let crl_issuer = self.issuer();
        if crl_issuer != certificate.tbs_certificate().issuer()
            || crl_issuer != issuer.tbs_certificate().subject()
        {
            return Err(Error::WrongIssuer);
        }

        critical(self.list.tbs_cert_list.crl_extensions.as_ref())?;
        for revoked in self.entries() {
            critical(revoked.crl_entry_extensions.as_ref())?;
        }

        crate::verify::verify(self, &issuer)?;

        let next_update = self.next_update().ok_or(Error::MissingNextUpdate)?;
        if next_update < at {
            return Err(Error::Expired { next_update });
        }

        let serial = certificate.tbs_certificate().serial_number().as_bytes();
        match self
            .entries()
            .iter()
            .find(|revoked| revoked.serial_number.as_bytes() == serial)
        {
            Some(revoked) => {
                let entry = entry(revoked)?;
                Ok(CrlStatus::Revoked {
                    date: entry.date,
                    reason: entry.reason,
                })
            }
            None => Ok(CrlStatus::NotRevoked),
        }
    }

    fn entries(&self) -> &[RevokedCert] {
        self.list
            .tbs_cert_list
            .revoked_certificates
            .as_deref()
            .unwrap_or_default()
    }
}

fn critical(extensions: Option<&Extensions>) -> Result<(), Error> {
    match extensions
        .into_iter()
        .flatten()
        .find(|extension| extension.critical)
    {
        Some(extension) => Err(Error::UnsupportedCriticalExtension(extension.extn_id)),
        None => Ok(()),
    }
}

fn entry(revoked: &RevokedCert) -> Result<RevokedEntry, Error> {
    let reason = revoked
        .crl_entry_extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == <CrlReason as der::oid::AssociatedOid>::OID)
        .map(|extension| CrlReason::from_der(extension.extn_value.as_bytes()))
        .transpose()?;
    Ok(RevokedEntry {
        serial: revoked.serial_number.as_bytes().to_vec(),
        date: revoked.revocation_date.to_system_time(),
        reason,
    })
}
