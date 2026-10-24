use std::time::{Duration, SystemTime};

use der::asn1::{Any, GeneralizedTime, OctetString};
use der::oid::ObjectIdentifier;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;
use x509_cert::ext::pkix::{CrlReason, ExtendedKeyUsage};

use super::asn1::{
    BasicOcspResponse, CertId, CertStatus, ID_PKIX_OCSP_BASIC, ID_PKIX_OCSP_NONCE,
    OcspResponseStatus, ResponderId, SingleResponse,
};
use super::request::{OcspRequest, cert_id, key_hash};
use crate::Error;
use crate::crl::{critical, signed_tbs};
use crate::verify::verify_signed;

const ID_KP_OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");
const ID_PKIX_OCSP_ARCHIVE_CUTOFF: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.6");

/// A decoded `successful` OCSP response of type `id-pkix-ocsp-basic`, with the
/// `tbsResponseData` bytes it arrived with.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    basic: BasicOcspResponse,
    tbs: Vec<u8>,
    nonce: Option<Vec<u8>>,
}

/// What a usable OCSP response says of a certificate. A response that cannot be used, or
/// that says `unknown`, is an [`Error`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspStatus {
    /// The responder says the certificate is not revoked.
    Good,
    /// The certificate is revoked. The date may be after the control date: whether a
    /// revocation applies to a signature made before it is the caller's judgement.
    Revoked {
        /// The `revocationTime`.
        date: SystemTime,
        /// The `revocationReason`, when present.
        reason: Option<CrlReason>,
    },
}

impl OcspResponse {
    /// Reads a DER `OCSPResponse`. Bytes after it, a `responseStatus` other than
    /// `successful`, a response type other than `id-pkix-ocsp-basic`, an entry of `certs`
    /// that is not a certificate and a malformed nonce extension are errors.
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        let response = super::asn1::OcspResponse::from_der(bytes)?;
        if response.response_status != OcspResponseStatus::Successful {
            return Err(Error::ResponseStatus(response.response_status as u8));
        }
        let response_bytes = response
            .response_bytes
            .ok_or(der::Error::from(der::ErrorKind::Failed))?;
        if response_bytes.response_type != ID_PKIX_OCSP_BASIC {
            return Err(Error::UnsupportedResponseType(response_bytes.response_type));
        }
        let octets = response_bytes.response.as_bytes();
        let basic = BasicOcspResponse::from_der(octets)?;
        for certificate in basic.certs.iter().flatten() {
            Certificate::from_der(&certificate.to_der()?)?;
        }
        let tbs = signed_tbs(octets)?;
        let nonce = basic
            .tbs_response_data
            .response_extensions
            .iter()
            .flatten()
            .find(|extension| extension.extn_id == ID_PKIX_OCSP_NONCE)
            .map(|extension| OctetString::from_der(extension.extn_value.as_bytes()))
            .transpose()?
            .map(|nonce| nonce.as_bytes().to_vec());
        Ok(Self { basic, tbs, nonce })
    }

    /// `producedAt`.
    pub fn produced_at(&self) -> SystemTime {
        self.basic.tbs_response_data.produced_at.to_system_time()
    }

    /// The `thisUpdate` of the first single response; `None` when the response holds none.
    pub fn this_update(&self) -> Option<SystemTime> {
        self.responses()
            .first()
            .map(|single| single.this_update.to_system_time())
    }

    /// The nonce of the response, when it carries one.
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }

    /// Refuses a response whose nonce differs from `request`'s with
    /// [`Error::NonceMismatch`]. A response without a nonce is accepted, as pre-signed
    /// responses carry none (RFC 8954 §2.1): its freshness then rests on
    /// [`OcspResponse::check_this_update`].
    pub fn check_nonce(&self, request: &OcspRequest) -> Result<(), Error> {
        match self.nonce() {
            Some(nonce) if nonce != request.nonce() => Err(Error::NonceMismatch),
            _ => Ok(()),
        }
    }

    /// Refuses, with [`Error::ThisUpdateOutOfTolerance`], a response whose single response
    /// about `certificate` (issued by `issuer`, both DER) has a `thisUpdate` more than
    /// `tolerance` away from `at`, before or after. [`OcspResponse::status`] does not
    /// check it: call this one when the response must be fresh at `at`.
    pub fn check_this_update(
        &self,
        certificate: &[u8],
        issuer: &[u8],
        at: SystemTime,
        tolerance: Duration,
    ) -> Result<(), Error> {
        let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
        let issuer = Certificate::from_der(issuer).map_err(Error::IssuerCertificate)?;
        let this_update = self
            .single(&certificate, &issuer)?
            .this_update
            .to_system_time();
        let distance = this_update
            .duration_since(at)
            .or_else(|_| at.duration_since(this_update))
            .unwrap_or(Duration::MAX);
        if distance > tolerance {
            return Err(Error::ThisUpdateOutOfTolerance { this_update });
        }
        Ok(())
    }

    /// Says what the response tells of `certificate`, judging it against `issuer`, the
    /// certificate that issued it, at the control date `at`. Both are given as DER.
    ///
    /// A `thisUpdate` after `at` is accepted, as for a CRL: a response issued later still
    /// tells about the past. Neither the nonce nor the freshness of `thisUpdate` is judged
    /// here: see [`OcspResponse::check_nonce`] and [`OcspResponse::check_this_update`].
    pub fn status(
        &self,
        certificate: &[u8],
        issuer: &[u8],
        at: SystemTime,
    ) -> Result<OcspStatus, Error> {
        // The order is part of the contract: each attack of the corpus must reach the rule
        // that names it (docs/security/attacks/revocation.md).
        let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
        let issuer = Certificate::from_der(issuer).map_err(Error::IssuerCertificate)?;

        let single = self.single(&certificate, &issuer)?;

        critical(self.basic.tbs_response_data.response_extensions.as_ref())?;
        critical(single.single_extensions.as_ref())?;

        let key = self.responder_key(&issuer)?;

        let signature = self
            .basic
            .signature
            .as_bytes()
            .ok_or(Error::SignatureInvalid)?;
        verify_signed(
            self.basic.signature_algorithm.oid,
            &key,
            &self.tbs,
            signature,
        )?;

        if let Some(next_update) = single.next_update {
            let next_update = next_update.to_system_time();
            if next_update < at {
                return Err(Error::Expired { next_update });
            }
        }

        match &single.cert_status {
            CertStatus::Good(_) => Ok(OcspStatus::Good),
            CertStatus::Revoked(info) => Ok(OcspStatus::Revoked {
                date: info.revocation_time.to_system_time(),
                reason: info.revocation_reason,
            }),
            CertStatus::Unknown(_) => Err(Error::UnknownCertificate),
        }
    }

    /// The DER of the delegated responder [`OcspResponse::status`] would accept for a
    /// response about a certificate of `issuer` (DER): `None` when the `ResponderID` names
    /// the issuer itself, [`Error::UnauthorizedResponder`] when no certificate of `certs`
    /// qualifies. Its validity is checked at `producedAt` only; judging it at another date
    /// is the caller's.
    pub fn delegated_responder(&self, issuer: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let issuer = Certificate::from_der(issuer).map_err(Error::IssuerCertificate)?;
        match self.responder(&issuer)? {
            Responder::Issuer => Ok(None),
            Responder::Delegate(der, _) => Ok(Some(der)),
        }
    }

    /// The `archiveCutoff` (RFC 6960 §4.4.4) of the single response about `certificate`,
    /// issued by `issuer` (both DER): the date from which the responder keeps the status of
    /// certificates expired since. A missing or undecodable value is `None`.
    pub fn archive_cutoff(
        &self,
        certificate: &[u8],
        issuer: &[u8],
    ) -> Result<Option<SystemTime>, Error> {
        let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
        let issuer = Certificate::from_der(issuer).map_err(Error::IssuerCertificate)?;
        let single = self.single(&certificate, &issuer)?;
        Ok(single
            .single_extensions
            .iter()
            .flatten()
            .find(|extension| extension.extn_id == ID_PKIX_OCSP_ARCHIVE_CUTOFF)
            .and_then(|extension| GeneralizedTime::from_der(extension.extn_value.as_bytes()).ok())
            .map(|time| time.to_system_time()))
    }

    fn responses(&self) -> &[SingleResponse] {
        &self.basic.tbs_response_data.responses
    }

    /// The single response whose `CertID`, recomputed with its own hash algorithm, is the
    /// certificate's.
    fn single(
        &self,
        certificate: &Certificate,
        issuer: &Certificate,
    ) -> Result<&SingleResponse, Error> {
        for single in self.responses() {
            let expected = cert_id(single.cert_id.hash_algorithm.oid, certificate, issuer)?;
            if same_cert_id(&single.cert_id, &expected) {
                return Ok(single);
            }
        }
        Err(Error::CertificateNotInResponse)
    }

    /// The key that must have signed the response: the issuer's when the `ResponderID`
    /// names it, else that of a certificate of `certs` the issuer delegated with
    /// `id-kp-OCSPSigning` (RFC 6960 §4.2.2.2).
    fn responder_key(&self, issuer: &Certificate) -> Result<SubjectPublicKeyInfoOwned, Error> {
        Ok(match self.responder(issuer)? {
            Responder::Issuer => issuer.tbs_certificate().subject_public_key_info().clone(),
            Responder::Delegate(_, key) => key,
        })
    }

    fn responder(&self, issuer: &Certificate) -> Result<Responder, Error> {
        let responder = &self.basic.tbs_response_data.responder_id;
        if names(responder, issuer) {
            return Ok(Responder::Issuer);
        }
        let produced_at = self.produced_at();
        self.basic
            .certs
            .iter()
            .flatten()
            .find_map(|candidate| delegate(candidate, responder, issuer, produced_at))
            .ok_or(Error::UnauthorizedResponder)
    }
}

/// Who signed a response: the issuer, or a delegate given by its DER and its key.
enum Responder {
    Issuer,
    Delegate(Vec<u8>, SubjectPublicKeyInfoOwned),
}

fn same_cert_id(received: &CertId, expected: &CertId) -> bool {
    received.hash_algorithm.oid == expected.hash_algorithm.oid
        && received.issuer_name_hash == expected.issuer_name_hash
        && received.issuer_key_hash == expected.issuer_key_hash
        && received.serial_number.as_bytes() == expected.serial_number.as_bytes()
}

fn names(responder: &ResponderId, certificate: &Certificate) -> bool {
    let tbs = certificate.tbs_certificate();
    match responder {
        ResponderId::ByName(name) => name == tbs.subject(),
        ResponderId::ByKey(hash) => hash.as_bytes() == key_hash(tbs.subject_public_key_info()),
    }
}

/// `candidate`, with its key, when it is a responder the issuer delegated: named by the
/// `ResponderID`, issued under the issuer's name, signed by the issuer's key, with
/// `id-kp-OCSPSigning`, valid at `producedAt`. Any failure leaves it unauthorized.
fn delegate(
    candidate: &Any,
    responder: &ResponderId,
    issuer: &Certificate,
    produced_at: SystemTime,
) -> Option<Responder> {
    let bytes = candidate.to_der().ok()?;
    let certificate = Certificate::from_der(&bytes).ok()?;
    let tbs = certificate.tbs_certificate();
    let issuer_tbs = issuer.tbs_certificate();
    if !names(responder, &certificate) || tbs.issuer() != issuer_tbs.subject() {
        return None;
    }
    // RFC 5280 §4.1.1.2: the unsigned outer algorithm must repeat the signed one.
    if certificate.signature_algorithm() != tbs.signature() {
        return None;
    }
    let signed = signed_tbs(&bytes).ok()?;
    verify_signed(
        certificate.signature_algorithm().oid,
        issuer_tbs.subject_public_key_info(),
        &signed,
        certificate.signature().as_bytes()?,
    )
    .ok()?;
    let (_, usage) = tbs.get_extension::<ExtendedKeyUsage>().ok()??;
    if !usage.0.contains(&ID_KP_OCSP_SIGNING) {
        return None;
    }
    let validity = tbs.validity();
    if produced_at < validity.not_before.to_system_time()
        || produced_at > validity.not_after.to_system_time()
    {
        return None;
    }
    let key = tbs.subject_public_key_info().clone();
    Some(Responder::Delegate(bytes, key))
}
