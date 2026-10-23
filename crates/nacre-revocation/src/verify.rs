use der::Encode;
use der::oid::ObjectIdentifier;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;
use x509_cert::ext::pkix::KeyUsage;

use crate::{Crl, Error};

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

enum KeyKind {
    EcP256,
    Rsa,
}

pub(crate) fn verify(crl: &Crl, issuer: &Certificate) -> Result<(), Error> {
    let list = crl.certificate_list();
    // RFC 5280 §5.1.1.2: the unsigned outer algorithm must repeat the signed one.
    if list.signature_algorithm != list.tbs_cert_list.signature {
        return Err(Error::AlgorithmMismatch);
    }
    let tbs_certificate = issuer.tbs_certificate();
    if let Some((_, key_usage)) = tbs_certificate
        .get_extension::<KeyUsage>()
        .map_err(Error::IssuerCertificate)?
        && !key_usage.crl_sign()
    {
        return Err(Error::IssuerNotCrlSigner);
    }

    let signature = list.signature.as_bytes().ok_or(Error::SignatureInvalid)?;
    verify_signed(
        list.tbs_cert_list.signature.oid,
        tbs_certificate.subject_public_key_info(),
        crl.tbs_bytes(),
        signature,
    )
}

/// Verifies `signature` over the bytes `tbs` as received, with `spki`, for the algorithms
/// this crate supports.
pub(crate) fn verify_signed(
    algorithm: ObjectIdentifier,
    spki: &SubjectPublicKeyInfoOwned,
    tbs: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let key = check_algorithms(algorithm, spki)?;
    let hash = Sha256::digest(tbs);
    let valid = match key {
        KeyKind::EcP256 => verify_ecdsa(spki.subject_public_key.raw_bytes(), &hash, signature),
        KeyKind::Rsa => verify_rsa(
            &spki.to_der().map_err(Error::IssuerCertificate)?,
            &hash,
            signature,
        ),
    };
    if valid {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

fn check_algorithms(
    signature_algorithm: ObjectIdentifier,
    spki: &SubjectPublicKeyInfoOwned,
) -> Result<KeyKind, Error> {
    let wants_rsa = match signature_algorithm {
        ECDSA_WITH_SHA256 => false,
        SHA256_WITH_RSA_ENCRYPTION => true,
        other => return Err(Error::UnsupportedAlgorithm(other)),
    };
    let key_algorithm = &spki.algorithm;
    let key = match key_algorithm.oid {
        EC_PUBLIC_KEY => {
            let curve = key_algorithm
                .parameters
                .as_ref()
                .ok_or(Error::UnsupportedAlgorithm(EC_PUBLIC_KEY))?
                .decode_as::<ObjectIdentifier>()
                .map_err(Error::IssuerCertificate)?;
            if curve != PRIME256V1 {
                return Err(Error::UnsupportedAlgorithm(curve));
            }
            KeyKind::EcP256
        }
        RSA_ENCRYPTION => KeyKind::Rsa,
        other => return Err(Error::UnsupportedAlgorithm(other)),
    };
    match (key, wants_rsa) {
        (KeyKind::EcP256, false) => Ok(KeyKind::EcP256),
        (KeyKind::Rsa, true) => Ok(KeyKind::Rsa),
        _ => Err(Error::AlgorithmMismatch),
    }
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
