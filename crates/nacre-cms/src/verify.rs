use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Any, Decode, Encode, Reader, Tag};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use crate::model::{expect, nested, peek_tag};
use crate::{Attribute, Error, SignedData, SignerIdentifier, SignerInfo, oid};

const SHA256_LEN: usize = 32;

/// The signer of a `SignedData` whose signature verified.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedSigner<'a> {
    certificate: &'a [u8],
    signer_info: &'a SignerInfo,
}

impl<'a> VerifiedSigner<'a> {
    /// The DER of the signer certificate, as carried in the `SignedData`.
    pub fn certificate(&self) -> &'a [u8] {
        self.certificate
    }

    pub fn signer_info(&self) -> &'a SignerInfo {
        self.signer_info
    }
}

enum KeyKind {
    EcP256,
    Rsa,
}

impl SignedData {
    /// Verifies the signature over `detached`, or over the encapsulated content when
    /// `detached` is `None`.
    ///
    /// This proves the signature and its binding to a certificate carried in the
    /// `SignedData`; it does not judge that certificate, its chain or its validity.
    pub fn verify(&self, detached: Option<&[u8]>) -> Result<VerifiedSigner<'_>, Error> {
        self.verify_with(|econtent| match (detached, econtent) {
            (Some(_), Some(_)) => Err(Error::ContentAmbiguous),
            (None, None) => Err(Error::ContentMissing),
            (Some(content), None) | (None, Some(content)) => Ok(Sha256::digest(content).to_vec()),
        })
    }

    /// Verifies a detached signature against `digest`, the SHA-256 of the content
    /// computed by the caller (a PDF byte range, for instance).
    pub fn verify_detached_digest(&self, digest: &[u8]) -> Result<VerifiedSigner<'_>, Error> {
        self.verify_with(|econtent| {
            if econtent.is_some() {
                return Err(Error::ContentAmbiguous);
            }
            if digest.len() != SHA256_LEN {
                return Err(Error::DigestLength {
                    expected: SHA256_LEN,
                    actual: digest.len(),
                });
            }
            Ok(digest.to_vec())
        })
    }

    // The order of the checks is part of the contract: each attack of the corpus must
    // reach the rule that names it.
    fn verify_with(
        &self,
        content_digest: impl FnOnce(Option<&[u8]>) -> Result<Vec<u8>, Error>,
    ) -> Result<VerifiedSigner<'_>, Error> {
        let signer_info = match self.signer_infos.as_slice() {
            [one] => one,
            other => return Err(Error::SignerCount(other.len())),
        };
        let signed_attrs = signer_info
            .signed_attrs
            .as_ref()
            .ok_or(Error::MissingSignedAttributes)?;
        let attributes = signed_attrs.attributes()?;
        check_unique(&attributes)?;

        let content_type = single_value(&attributes, oid::CONTENT_TYPE)?;
        let message_digest = single_value(&attributes, oid::MESSAGE_DIGEST)?;
        if content_type.decode_as::<ObjectIdentifier>()? != self.encap_content_info.econtent_type {
            return Err(Error::ContentTypeMismatch);
        }

        let (certificate_der, certificate) = self.signer_certificate(&signer_info.sid)?;
        let spki = certificate.tbs_certificate().subject_public_key_info();
        let key = check_algorithms(signer_info, &spki.algorithm)?;

        if let Some(ess) = attributes
            .iter()
            .find(|a| a.oid == oid::SIGNING_CERTIFICATE_V2)
        {
            check_signing_certificate(ess, certificate_der)?;
        }

        let digest = content_digest(self.econtent())?;
        if message_digest.decode_as::<OctetString>()?.as_bytes() != digest.as_slice() {
            return Err(Error::MessageDigestMismatch);
        }

        let hash = Sha256::digest(signed_attrs.to_be_signed()?);
        let public_key = spki.subject_public_key.raw_bytes();
        let valid = match key {
            KeyKind::EcP256 => verify_ecdsa(public_key, &hash, &signer_info.signature),
            KeyKind::Rsa => verify_rsa(&spki.to_der()?, &hash, &signer_info.signature),
        };
        if !valid {
            return Err(Error::SignatureInvalid);
        }

        Ok(VerifiedSigner {
            certificate: certificate_der,
            signer_info,
        })
    }

    fn signer_certificate(&self, sid: &SignerIdentifier) -> Result<(&[u8], Certificate), Error> {
        for der in &self.certificates {
            // Other CertificateChoices (attribute certificates, `other`) are tagged [0]–[3].
            if der.first() != Some(&0x30) {
                continue;
            }
            let certificate = Certificate::from_der(der).map_err(Error::Certificate)?;
            let tbs = certificate.tbs_certificate();
            let matches = match sid {
                SignerIdentifier::IssuerAndSerialNumber {
                    issuer,
                    serial_number,
                } => tbs.serial_number() == serial_number && tbs.issuer().to_der()? == *issuer,
                SignerIdentifier::SubjectKeyIdentifier(ski) => tbs
                    .get_extension::<SubjectKeyIdentifier>()
                    .map_err(Error::Certificate)?
                    .is_some_and(|(_, ext)| ext.0.as_bytes() == ski.as_slice()),
            };
            if matches {
                return Ok((der, certificate));
            }
        }
        Err(Error::SignerCertificateNotFound)
    }
}

fn check_unique(attributes: &[Attribute]) -> Result<(), Error> {
    let mut oids: Vec<&ObjectIdentifier> = attributes.iter().map(|a| &a.oid).collect();
    oids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    if let Some(pair) = oids.windows(2).find(|pair| pair.first() == pair.last())
        && let Some(oid) = pair.first()
    {
        return Err(Error::DuplicateAttribute(**oid));
    }
    for single in [oid::CONTENT_TYPE, oid::MESSAGE_DIGEST, oid::SIGNING_TIME] {
        if let Some(attribute) = attributes.iter().find(|a| a.oid == single)
            && attribute.values.len() != 1
        {
            return Err(Error::AttributeValueCount(single));
        }
    }
    Ok(())
}

fn single_value(attributes: &[Attribute], wanted: ObjectIdentifier) -> Result<&Any, Error> {
    attributes
        .iter()
        .find(|a| a.oid == wanted)
        .and_then(|a| a.values.first())
        .ok_or(Error::MissingAttribute(wanted))
}

fn check_algorithms(
    signer_info: &SignerInfo,
    key_algorithm: &AlgorithmIdentifierOwned,
) -> Result<KeyKind, Error> {
    if signer_info.digest_algorithm.oid != oid::SHA256 {
        return Err(Error::UnsupportedAlgorithm(
            signer_info.digest_algorithm.oid,
        ));
    }
    let wants_rsa = match signer_info.signature_algorithm.oid {
        oid::ECDSA_WITH_SHA256 => false,
        oid::SHA256_WITH_RSA_ENCRYPTION | oid::RSA_ENCRYPTION => true,
        other => return Err(Error::UnsupportedAlgorithm(other)),
    };
    let key = match key_algorithm.oid {
        oid::EC_PUBLIC_KEY => {
            let curve = key_algorithm
                .parameters
                .as_ref()
                .ok_or(Error::UnsupportedAlgorithm(oid::EC_PUBLIC_KEY))?
                .decode_as::<ObjectIdentifier>()?;
            if curve != oid::PRIME256V1 {
                return Err(Error::UnsupportedAlgorithm(curve));
            }
            KeyKind::EcP256
        }
        oid::RSA_ENCRYPTION => KeyKind::Rsa,
        other => return Err(Error::UnsupportedAlgorithm(other)),
    };
    match (key, wants_rsa) {
        (KeyKind::EcP256, false) => Ok(KeyKind::EcP256),
        (KeyKind::Rsa, true) => Ok(KeyKind::Rsa),
        _ => Err(Error::AlgorithmMismatch),
    }
}

/// `SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies OPTIONAL }`
/// (RFC 5035). Its first `ESSCertIDv2` names the signer certificate.
fn check_signing_certificate(ess: &Attribute, certificate: &[u8]) -> Result<(), Error> {
    let value = ess
        .values
        .first()
        .ok_or(Error::SigningCertificateMismatch)?;
    value.header().tag().assert_eq(Tag::Sequence)?;
    let cert_hash = nested(value.value(), |r| {
        let certs = expect(r, Tag::Sequence)?;
        skip_rest(r)?;
        nested(certs, |r| {
            let first = expect(r, Tag::Sequence)?;
            skip_rest(r)?;
            nested(first, |r| {
                if peek_tag(r)? == Some(Tag::Sequence) {
                    let algorithm = AlgorithmIdentifierOwned::decode(r)?;
                    if algorithm.oid != oid::SHA256 {
                        return Err(Error::UnsupportedAlgorithm(algorithm.oid));
                    }
                }
                let hash = OctetString::decode(r)?;
                skip_rest(r)?;
                Ok(hash)
            })
        })
    })?;
    if cert_hash.as_bytes() != Sha256::digest(certificate).as_slice() {
        return Err(Error::SigningCertificateMismatch);
    }
    Ok(())
}

fn skip_rest(r: &mut der::SliceReader<'_>) -> Result<(), Error> {
    while !r.is_finished() {
        r.tlv_bytes()?;
    }
    Ok(())
}

fn verify_ecdsa(public_key: &[u8], hash: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_der(signature) else {
        return false;
    };
    // p256 does not normalise S on verification, so a high-S signature is accepted,
    // as OpenSSL accepts it.
    key.verify_prehash(hash, &signature).is_ok()
}

fn verify_rsa(spki: &[u8], hash: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = rsa::pkcs1v15::VerifyingKey::<Sha256>::from_public_key_der(spki) else {
        return false;
    };
    let Ok(signature) = rsa::pkcs1v15::Signature::try_from(signature) else {
        return false;
    };
    key.verify_prehash(hash, &signature).is_ok()
}
