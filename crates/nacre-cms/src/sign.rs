use der::asn1::OctetString;
use der::oid::ObjectIdentifier;
use der::{Any, Decode, Encode, Tag};
use nacre_core::{SignatureAlgorithm, Signer};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::time::Time;

use crate::model::tlv;
use crate::{
    Attribute, EncapsulatedContentInfo, Error, SignedAttributes, SignedData, SignerIdentifier,
    SignerInfo, oid,
};

/// The signed attributes a signature format allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    forbidden: &'static [ObjectIdentifier],
}

impl Profile {
    /// Plain CMS: every attribute is allowed.
    pub const CMS: Profile = Profile::forbidding(&[]);
    /// PAdES (ETSI EN 319 142-1 §5.1): `signingTime` is forbidden, the time lives in the
    /// PDF dictionary.
    pub const PADES: Profile = Profile::forbidding(&[oid::SIGNING_TIME]);

    /// A profile forbidding the signed attributes `forbidden`.
    pub const fn forbidding(forbidden: &'static [ObjectIdentifier]) -> Self {
        Self { forbidden }
    }

    pub fn forbids(&self, attribute: &ObjectIdentifier) -> bool {
        self.forbidden.contains(attribute)
    }
}

/// Signs `digest`, the SHA-256 of the content, into a detached DER `SignedData`.
///
/// The signed attributes are `contentType` (`id-data`), `messageDigest`,
/// `signingCertificateV2` naming the signer certificate, and `signingTime` when
/// `signing_time` is given. An attribute `profile` forbids is refused, and nothing is
/// written.
pub fn sign_detached(
    digest: &[u8],
    signer: &dyn Signer,
    profile: &Profile,
    signing_time: Option<Time>,
) -> Result<Vec<u8>, Error> {
    let algorithm = signer.algorithm();
    let expected = algorithm.digest().output_len();
    if digest.len() != expected {
        return Err(Error::DigestLength {
            expected,
            actual: digest.len(),
        });
    }
    let signature_algorithm = match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => AlgorithmIdentifierOwned {
            oid: oid::ECDSA_WITH_SHA256,
            parameters: None,
        },
        SignatureAlgorithm::RsaPkcs1v15Sha256 => AlgorithmIdentifierOwned {
            oid: oid::SHA256_WITH_RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        // A variant added to nacre-core later has no identifier known here.
        _ => {
            return Err(Error::Signer(nacre_core::Error::Signer(
                "unsupported signature algorithm".into(),
            )));
        }
    };

    let chain = signer.certificate_chain();
    let signer_certificate = chain.first().ok_or(Error::SignerCertificateNotFound)?;
    let certificate = Certificate::from_der(signer_certificate).map_err(Error::Certificate)?;
    let tbs = certificate.tbs_certificate();
    let sid = SignerIdentifier::IssuerAndSerialNumber {
        issuer: tbs.issuer().to_der()?,
        serial_number: tbs.serial_number().clone(),
    };

    let mut attributes = vec![
        Attribute::new(oid::CONTENT_TYPE, &oid::DATA)?,
        Attribute::new(oid::MESSAGE_DIGEST, &OctetString::new(digest)?)?,
        Attribute::new(
            oid::SIGNING_CERTIFICATE_V2,
            &signing_certificate_v2(signer_certificate)?,
        )?,
    ];
    if let Some(time) = signing_time {
        attributes.push(Attribute::new(oid::SIGNING_TIME, &time)?);
    }
    if let Some(forbidden) = attributes.iter().find(|a| profile.forbids(&a.oid)) {
        return Err(Error::ForbiddenAttribute(forbidden.oid));
    }

    let signed_attrs = SignedAttributes::from_attributes(attributes)?;
    let signature = signer.sign_digest(&Sha256::digest(signed_attrs.to_be_signed()?))?;

    let mut certificates = chain.to_vec();
    certificates.sort();

    SignedData {
        version: 1,
        digest_algorithms: vec![sha256()],
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: oid::DATA,
            econtent: None,
        },
        certificates,
        crls: Vec::new(),
        signer_infos: vec![SignerInfo {
            version: 1,
            sid,
            digest_algorithm: sha256(),
            signed_attrs: Some(signed_attrs),
            signature_algorithm,
            signature,
            unsigned_attrs: Vec::new(),
        }],
    }
    .to_der()
}

fn sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oid::SHA256,
        parameters: None,
    }
}

/// `SigningCertificateV2 { certs: [ESSCertIDv2 { certHash }] }` (RFC 5035): the hash
/// algorithm is the DEFAULT SHA-256, so DER omits it, and `issuerSerial` is left out.
fn signing_certificate_v2(certificate: &[u8]) -> Result<Any, Error> {
    let cert_hash = OctetString::new(Sha256::digest(certificate).as_slice())?.to_der()?;
    let ess_cert_id = tlv(Tag::Sequence, &cert_hash)?;
    let certs = tlv(Tag::Sequence, &ess_cert_id)?;
    Ok(Any::from_der(&tlv(Tag::Sequence, &certs)?)?)
}
