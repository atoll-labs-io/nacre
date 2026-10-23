//! Certificate path building and judging (RFC 5280 §6.1), with no PDF involved: CAdES,
//! XAdES and JAdES validators call [`build_chain`] with their own certificate pool.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use der::asn1::AnyRef;
use der::{Decode, Encode, Reader, SliceReader};
use nacre_core::{SubIndication, ValidationReport};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use spki::{ObjectIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};

use crate::Error;

/// Certificates below the anchor one path may hold.
const MAX_PATH_LEN: usize = 8;
/// Distinct readable certificates of a pool one [`build_chain`] call reads; later ones
/// are ignored.
const MAX_POOL_LEN: usize = 256;

const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The extensions a certificate of a path may mark critical. Any other critical extension,
/// a `nameConstraints` or a `policyConstraints` among them, refuses the path rather than
/// being ignored.
const UNDERSTOOD_EXTENSIONS: [ObjectIdentifier; 9] = [
    ObjectIdentifier::new_unwrap("2.5.29.19"),
    ObjectIdentifier::new_unwrap("2.5.29.15"),
    ObjectIdentifier::new_unwrap("2.5.29.37"),
    ObjectIdentifier::new_unwrap("2.5.29.14"),
    ObjectIdentifier::new_unwrap("2.5.29.35"),
    ObjectIdentifier::new_unwrap("2.5.29.17"),
    ObjectIdentifier::new_unwrap("2.5.29.32"),
    ObjectIdentifier::new_unwrap("2.5.29.31"),
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1"),
];

/// The purposes a signer's `extendedKeyUsage` must name one of for it to sign documents:
/// `anyExtendedKeyUsage`, `id-kp-clientAuth` (carried by PIV and many qualified signing
/// certificates), `id-kp-emailProtection`, `id-kp-documentSigning` (RFC 9336), Adobe
/// Authentic Documents Trust and Microsoft Document Signing.
const SIGNING_PURPOSES: [ObjectIdentifier; 6] = [
    ObjectIdentifier::new_unwrap("2.5.29.37.0"),
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2"),
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.4"),
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.36"),
    ObjectIdentifier::new_unwrap("1.2.840.113583.1.1.5"),
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.10.3.12"),
];

const TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// What the leaf of a path is judged fit for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// Signing documents: an `extendedKeyUsage`, when present, names one of
    /// `SIGNING_PURPOSES`.
    Signing,
    /// Time-stamping: the `extendedKeyUsage` is present and names `id-kp-timeStamping`.
    Timestamping,
}

/// The certificates a caller trusts. A path ends at one of them; neither its validity nor
/// its extensions are judged (RFC 5280 §6.1). [`TrustAnchors::default`] trusts none.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    anchors: Vec<Node>,
}

impl TrustAnchors {
    /// Reads each DER certificate of `certificates`; an unreadable one, or one given as PEM,
    /// is an error.
    pub fn from_certificates<'a>(
        certificates: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Error> {
        let anchors = certificates
            .into_iter()
            .map(|der| {
                if der.trim_ascii_start().starts_with(b"-----BEGIN") {
                    return Err(Error::TrustAnchorPem);
                }
                Node::read(der).map_err(Error::TrustAnchor)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { anchors })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// A valid certification path, as DER, leaf first, the trust anchor last. Its revocation
/// is not judged.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePath {
    pub certificates: Vec<Vec<u8>>,
}

/// Why no valid path was found. `depth` counts from the signer's certificate, 0.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDefect {
    /// No path leads from the signer to a trust anchor.
    NoPath,
    /// The signer's certificate cannot be read.
    SignerUnreadable,
    /// The certificate at `depth` expired before the control date.
    Expired { depth: usize },
    /// The certificate at `depth` is not valid yet at the control date.
    NotYetValid { depth: usize },
    /// The signer's `keyUsage` allows neither `digitalSignature` nor `nonRepudiation`.
    KeyUsage,
    /// The signer's certificate (`depth` 0) has an `extendedKeyUsage` naming no document
    /// signing purpose; for a timestamp authority's path, one lacking `id-kp-timeStamping`.
    ExtendedKeyUsage { depth: usize },
    /// The issuing certificate at `depth` is not a CA (`basicConstraints` absent or `cA`
    /// false).
    NotACa { depth: usize },
    /// The issuing certificate at `depth` has a `keyUsage` without `keyCertSign`.
    CaKeyUsage { depth: usize },
    /// The issuing certificate at `depth` has more CA certificates below it than its
    /// `pathLenConstraint` allows.
    PathLength { depth: usize },
    /// The certificate at `depth` marks critical an extension not understood here.
    UnsupportedCriticalExtension { depth: usize, oid: ObjectIdentifier },
    /// An extension of the certificate at `depth` is duplicated or cannot be decoded.
    MalformedExtension { depth: usize },
}

impl ChainDefect {
    /// The EN 319 102-1 outcome of this defect, always `INDETERMINATE` and with no level.
    pub fn report(&self) -> ValidationReport {
        let sub = match self {
            Self::NoPath => SubIndication::NoCertificateChainFound,
            Self::SignerUnreadable => SubIndication::NoSigningCertificateFound,
            Self::Expired { .. } | Self::NotYetValid { .. } => SubIndication::OutOfBoundsNoPoe,
            Self::KeyUsage
            | Self::ExtendedKeyUsage { .. }
            | Self::NotACa { .. }
            | Self::CaKeyUsage { .. }
            | Self::PathLength { .. } => SubIndication::ChainConstraintsFailure,
            Self::UnsupportedCriticalExtension { .. } | Self::MalformedExtension { .. } => {
                SubIndication::CertificateChainGeneralFailure
            }
        };
        ValidationReport::indeterminate(sub, None)
    }
}

/// Builds the path of `signer`, a DER certificate, through the DER certificates of `pool`
/// to one of `anchors`, and judges it at the control date `at`.
///
/// With no anchor the answer is [`ChainDefect::NoPath`] at once. The pool is a hint, never
/// evidence: a pool entry that is not a readable certificate is skipped, an entry repeated
/// byte for byte counts once, and past 256 distinct certificates the rest are ignored, so
/// a caller lists the certificates it trusts most to carry the path first (in PDF, the
/// CMS ones before the `/DSS` ones). Copies of one `tbsCertificate` stay apart until one
/// of them is verified, so a copy with a broken signature never hides a sound one.
///
/// Only an anchor or a pool certificate an anchor certifies, directly or through other
/// certified ones, is ever tried as an issuer, so a certificate no anchor certifies costs
/// at most one signature check per certified issuer of its issuer's name and can hide no
/// path. Each (certificate, issuer) pair is verified at most once. Candidates are tried
/// anchors first, then in pool order, so the result is deterministic: the first path that
/// judges clean, else the defect of the first path that reaches an anchor, else
/// [`ChainDefect::NoPath`]. A path holds at most 8 certificates below its anchor.
pub fn build_chain(
    signer: &[u8],
    pool: &[&[u8]],
    anchors: &TrustAnchors,
    at: SystemTime,
) -> Result<CertificatePath, ChainDefect> {
    build_path(signer, pool, anchors, at, Purpose::Signing)
}

/// [`build_chain`] with the leaf judged for `purpose`.
pub(crate) fn build_path(
    signer: &[u8],
    pool: &[&[u8]],
    anchors: &TrustAnchors,
    at: SystemTime,
    purpose: Purpose,
) -> Result<CertificatePath, ChainDefect> {
    let leaf = Node::read(signer).map_err(|_| ChainDefect::SignerUnreadable)?;
    if anchors.anchors.iter().any(|anchor| anchor.der == leaf.der) {
        return Ok(CertificatePath {
            certificates: vec![leaf.der],
        });
    }
    if anchors.is_empty() {
        return Err(ChainDefect::NoPath);
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut seen: HashSet<&[u8]> = HashSet::new();
    for &der in pool {
        if nodes.len() >= MAX_POOL_LEN {
            break;
        }
        if der.first() != Some(&0x30) || !seen.insert(der) {
            continue;
        }
        let Ok(node) = Node::read(der) else {
            continue;
        };
        // The leaf and the anchors are already known with their own key; a copy of their
        // `tbsCertificate` adds nothing.
        let known = |other: &Node| other.tbs == node.tbs;
        if node.tbs.is_none() || known(&leaf) || anchors.anchors.iter().any(known) {
            continue;
        }
        nodes.push(node);
    }
    let mut search = Search {
        leaf: &leaf,
        nodes: &nodes,
        anchors: &anchors.anchors,
        at,
        purpose,
        issued: HashMap::new(),
        certified: vec![false; nodes.len()],
        steps: 0,
        max_steps: (nodes.len() + 1) * MAX_PATH_LEN,
        first_defect: None,
    };
    search.certify();
    let mut path = vec![Id::Leaf];
    if let Some(anchor) = search.walk(&mut path) {
        let mut certificates: Vec<Vec<u8>> =
            path.iter().map(|id| search.node(*id).der.clone()).collect();
        certificates.push(anchor.der.clone());
        return Ok(CertificatePath { certificates });
    }
    Err(search.first_defect.unwrap_or(ChainDefect::NoPath))
}

/// A certificate read once, with what the search compares.
#[derive(Debug, Clone)]
struct Node {
    der: Vec<u8>,
    certificate: Certificate,
    tbs: Option<Vec<u8>>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
}

impl Node {
    fn read(der: &[u8]) -> Result<Self, der::Error> {
        let certificate = Certificate::from_der(der)?;
        let tbs = certificate.tbs_certificate();
        // Key identifiers only narrow the search: the signature check is the proof, so an
        // unreadable one is treated as absent.
        let subject_key_id = tbs
            .get_extension::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .map(|(_, ski)| ski.0.as_bytes().to_vec());
        let authority_key_id = tbs
            .get_extension::<AuthorityKeyIdentifier>()
            .ok()
            .flatten()
            .and_then(|(_, aki)| aki.key_identifier)
            .map(|id| id.as_bytes().to_vec());
        Ok(Self {
            subject: tbs.subject().to_der()?,
            issuer: tbs.issuer().to_der()?,
            tbs: signed_tbs(der).ok(),
            der: der.to_vec(),
            subject_key_id,
            authority_key_id,
            certificate,
        })
    }

    /// Whether `self` may have issued `child`, before any signature is checked.
    fn names(&self, child: &Node) -> bool {
        self.subject == child.issuer
            && match (&self.subject_key_id, &child.authority_key_id) {
                (Some(ski), Some(aki)) => ski == aki,
                _ => true,
            }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Id {
    Leaf,
    Anchor(usize),
    Pool(usize),
}

struct Search<'n> {
    leaf: &'n Node,
    nodes: &'n [Node],
    anchors: &'n [Node],
    at: SystemTime,
    purpose: Purpose,
    /// Whether the issuer (second) signed the child (first), once verified.
    issued: HashMap<(Id, Id), bool>,
    /// Pool certificates an anchor certifies, directly or through certified ones.
    certified: Vec<bool>,
    /// Bounds the paths tried among certified certificates, which only the anchors' keys
    /// can multiply.
    steps: usize,
    max_steps: usize,
    first_defect: Option<ChainDefect>,
}

impl<'n> Search<'n> {
    fn node(&self, id: Id) -> &'n Node {
        let (nodes, leaf) = (self.nodes, self.leaf);
        match id {
            Id::Leaf => leaf,
            Id::Anchor(i) => self.anchors.get(i).unwrap_or(leaf),
            Id::Pool(i) => nodes.get(i).unwrap_or(leaf),
        }
    }

    /// Marks, level by level from the anchors, the pool certificates an issuer already
    /// reached has signed. Of several copies of one `tbsCertificate`, only the first one
    /// verified is marked: the others can add no path, only work.
    fn certify(&mut self) {
        let nodes = self.nodes;
        let mut certified_tbs: HashSet<&'n [u8]> = HashSet::new();
        let mut frontier: Vec<Id> = (0..self.anchors.len()).map(Id::Anchor).collect();
        for _ in 1..MAX_PATH_LEN {
            let mut next = Vec::new();
            for (i, node) in nodes.iter().enumerate() {
                let Some(tbs) = node.tbs.as_deref() else {
                    continue;
                };
                if self.certified.get(i) == Some(&true) || certified_tbs.contains(tbs) {
                    continue;
                }
                if frontier
                    .iter()
                    .any(|issuer| self.issued_by(Id::Pool(i), *issuer))
                {
                    if let Some(flag) = self.certified.get_mut(i) {
                        *flag = true;
                    }
                    certified_tbs.insert(tbs);
                    next.push(Id::Pool(i));
                }
            }
            if next.is_empty() {
                return;
            }
            frontier = next;
        }
    }

    /// Extends `path` depth first until a path judged clean reaches an anchor, which is
    /// returned; `path` then holds the certificates below it.
    fn walk(&mut self, path: &mut Vec<Id>) -> Option<&'n Node> {
        let child = *path.last()?;
        self.steps += 1;
        if self.steps > self.max_steps {
            return None;
        }
        for a in 0..self.anchors.len() {
            if !self.issued_by(child, Id::Anchor(a)) {
                continue;
            }
            let nodes: Vec<&Node> = path.iter().map(|id| self.node(*id)).collect();
            match judge(&nodes, self.at, self.purpose) {
                Ok(()) => return self.anchors.get(a),
                Err(defect) => {
                    self.first_defect.get_or_insert(defect);
                }
            }
        }
        if path.len() >= MAX_PATH_LEN {
            return None;
        }
        for i in 0..self.nodes.len() {
            let candidate = Id::Pool(i);
            if self.certified.get(i) != Some(&true)
                || path.contains(&candidate)
                || !self.issued_by(child, candidate)
            {
                continue;
            }
            path.push(candidate);
            if let Some(anchor) = self.walk(path) {
                return Some(anchor);
            }
            path.pop();
        }
        None
    }

    fn issued_by(&mut self, child: Id, issuer: Id) -> bool {
        if let Some(known) = self.issued.get(&(child, issuer)) {
            return *known;
        }
        let (child_node, issuer_node) = (self.node(child), self.node(issuer));
        let verdict = issuer_node.names(child_node) && signed_by(child_node, issuer_node);
        self.issued.insert((child, issuer), verdict);
        verdict
    }
}

/// Judges `path`, leaf first, its anchor left out, at `at` (RFC 5280 §6.1.3, §6.1.4), its
/// leaf for `purpose`.
fn judge(path: &[&Node], at: SystemTime, purpose: Purpose) -> Result<(), ChainDefect> {
    for (depth, node) in path.iter().enumerate() {
        let tbs = node.certificate.tbs_certificate();
        let validity = tbs.validity();
        if at < validity.not_before.to_system_time() {
            return Err(ChainDefect::NotYetValid { depth });
        }
        if at > validity.not_after.to_system_time() {
            return Err(ChainDefect::Expired { depth });
        }
        if let Some(extension) = tbs
            .extensions()
            .into_iter()
            .flatten()
            .find(|e| e.critical && !UNDERSTOOD_EXTENSIONS.contains(&e.extn_id))
        {
            return Err(ChainDefect::UnsupportedCriticalExtension {
                depth,
                oid: extension.extn_id,
            });
        }
        let malformed = |_| ChainDefect::MalformedExtension { depth };
        let key_usage = tbs.get_extension::<KeyUsage>().map_err(malformed)?;
        let extended_key_usage = tbs.get_extension::<ExtendedKeyUsage>().map_err(malformed)?;
        if depth == 0 {
            // RFC 5280 §4.2.1.12: when present, critical or not, the signer may only be used
            // for the purposes it lists. An issuer's EKU is decoded but not judged: RFC 5280
            // does not chain it.
            let fit = match (purpose, extended_key_usage) {
                (Purpose::Signing, None) => true,
                (Purpose::Signing, Some((_, purposes))) => {
                    purposes.0.iter().any(|p| SIGNING_PURPOSES.contains(p))
                }
                (Purpose::Timestamping, None) => false,
                (Purpose::Timestamping, Some((_, purposes))) => purposes.0.contains(&TIME_STAMPING),
            };
            if !fit {
                return Err(ChainDefect::ExtendedKeyUsage { depth });
            }
            // RFC 5280 §4.2.1.3: an absent keyUsage restricts nothing.
            if let Some((_, usage)) = key_usage
                && !usage.digital_signature()
                && !usage.non_repudiation()
            {
                return Err(ChainDefect::KeyUsage);
            }
            continue;
        }
        let constraints = tbs.get_extension::<BasicConstraints>().map_err(malformed)?;
        let Some((_, constraints)) = constraints.filter(|(_, c)| c.ca) else {
            return Err(ChainDefect::NotACa { depth });
        };
        if let Some((_, usage)) = key_usage
            && !usage.key_cert_sign()
        {
            return Err(ChainDefect::CaKeyUsage { depth });
        }
        let cas_below = depth - 1;
        if constraints
            .path_len_constraint
            .is_some_and(|max| usize::from(max) < cas_below)
        {
            return Err(ChainDefect::PathLength { depth });
        }
    }
    Ok(())
}

/// Whether `issuer`'s key verifies `child`'s signature over its TBS bytes as received.
fn signed_by(child: &Node, issuer: &Node) -> bool {
    let certificate = &child.certificate;
    // RFC 5280 §4.1.1.2: the unsigned outer algorithm must repeat the signed one.
    if certificate.signature_algorithm() != certificate.tbs_certificate().signature() {
        return false;
    }
    let (Some(tbs), Some(signature)) = (&child.tbs, certificate.signature().as_bytes()) else {
        return false;
    };
    verify_signed(
        certificate.signature_algorithm().oid,
        issuer
            .certificate
            .tbs_certificate()
            .subject_public_key_info(),
        tbs,
        signature,
    )
}

enum KeyKind {
    EcP256,
    Rsa,
}

fn verify_signed(
    algorithm: ObjectIdentifier,
    spki: &SubjectPublicKeyInfoOwned,
    tbs: &[u8],
    signature: &[u8],
) -> bool {
    let hash = Sha256::digest(tbs);
    match key_kind(algorithm, spki) {
        Some(KeyKind::EcP256) => {
            verify_ecdsa(spki.subject_public_key.raw_bytes(), &hash, signature)
        }
        Some(KeyKind::Rsa) => spki
            .to_der()
            .is_ok_and(|der| verify_rsa(&der, &hash, signature)),
        None => false,
    }
}

/// The key kind, when the signature algorithm and the key are a supported matching pair.
fn key_kind(algorithm: ObjectIdentifier, spki: &SubjectPublicKeyInfoOwned) -> Option<KeyKind> {
    let key = &spki.algorithm;
    match (algorithm, key.oid) {
        (ECDSA_WITH_SHA256, EC_PUBLIC_KEY) => {
            let curve = key
                .parameters
                .as_ref()?
                .decode_as::<ObjectIdentifier>()
                .ok()?;
            (curve == PRIME256V1).then_some(KeyKind::EcP256)
        }
        (SHA256_WITH_RSA_ENCRYPTION, RSA_ENCRYPTION) => Some(KeyKind::Rsa),
        _ => None,
    }
}

fn verify_ecdsa(public_key: &[u8], hash: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_der(signature) else {
        return false;
    };
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

/// The `tbsCertificate` of a DER certificate, as received.
fn signed_tbs(bytes: &[u8]) -> der::Result<Vec<u8>> {
    let mut outer = SliceReader::new(bytes)?;
    let sequence = AnyRef::decode(&mut outer)?;
    outer.finish()?;
    let mut inner = SliceReader::new(sequence.value())?;
    Ok(inner.tlv_bytes()?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nacre_core::SubIndication::*;

    #[test]
    fn every_chain_defect_has_its_report() {
        let oid = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1");
        let rows = [
            (ChainDefect::NoPath, NoCertificateChainFound),
            (ChainDefect::SignerUnreadable, NoSigningCertificateFound),
            (ChainDefect::Expired { depth: 0 }, OutOfBoundsNoPoe),
            (ChainDefect::NotYetValid { depth: 1 }, OutOfBoundsNoPoe),
            (ChainDefect::KeyUsage, ChainConstraintsFailure),
            (
                ChainDefect::ExtendedKeyUsage { depth: 0 },
                ChainConstraintsFailure,
            ),
            (ChainDefect::NotACa { depth: 1 }, ChainConstraintsFailure),
            (
                ChainDefect::CaKeyUsage { depth: 1 },
                ChainConstraintsFailure,
            ),
            (
                ChainDefect::PathLength { depth: 2 },
                ChainConstraintsFailure,
            ),
            (
                ChainDefect::UnsupportedCriticalExtension { depth: 1, oid },
                CertificateChainGeneralFailure,
            ),
            (
                ChainDefect::MalformedExtension { depth: 0 },
                CertificateChainGeneralFailure,
            ),
        ];
        for (defect, sub) in rows {
            let report = defect.report();
            assert_eq!(
                report.indication(),
                nacre_core::Indication::Indeterminate,
                "{defect:?}"
            );
            assert_eq!(report.sub_indication(), Some(sub), "{defect:?}");
            assert_eq!(report.level(), None, "{defect:?}");
        }
    }
}
