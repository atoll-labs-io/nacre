//! The level a signature's structure reaches, as DSS 6.5.1 reads it (ADR-0025): nothing here
//! verifies a timestamp or judges revocation data, it only looks at what the file holds.

use std::collections::HashMap;

use der::Encode;
use der::asn1::ObjectIdentifier;
use nacre_cms::{SignedData, SignerIdentifier};
use nacre_core::{SignatureForm, SignatureLevel, SignatureProfile};
use nacre_pdf::{Dictionary, Document, Object, ReadOptions};
use nacre_revocation::{Crl, OcspResponse};
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use crate::TrustAnchors;
use crate::chain::{MAX_PATH_LEN, MAX_POOL_LEN, Node, signed_by};
use crate::date::pdf_date;
use crate::revisions::MAX_REVISIONS;
use crate::validate::{
    Dss, MAX_TIMESTAMPS, SIGNATURE_TIME_STAMP_TOKEN, byte_range, der_prefix, follow_once,
    is_document_timestamp,
};

/// `id-aa-signingCertificate` (RFC 2634, ESS v1).
const SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");

/// Document timestamps of one file that are read; later ones are ignored.
const MAX_DOCUMENT_TIMESTAMPS: usize = 16;

/// A document timestamp (`/SubFilter /ETSI.RFC3161`) of the file, with a readable
/// `/ByteRange`.
pub(crate) struct DocumentTimestamp {
    /// Where its signed bytes end.
    pub(crate) end: usize,
    pub(crate) dict: Dictionary,
    /// The DER of its `/Contents`, unverified; `None` when it holds no DER `SEQUENCE`.
    token: Option<Vec<u8>>,
}

/// The `/DSS` as of the end of one revision.
struct State {
    end: usize,
    /// Every certificate, CRL and OCSP response a `/DSS` held in this revision or an
    /// earlier one, as DSS 6.5.1 gathers them: a revision that replaces the `/DSS` does not
    /// take back what an earlier one held.
    dss: Dss,
    /// The end of the latest revision, up to this one, that changed the `/DSS`; 0 when none
    /// did.
    changed_at: usize,
}

/// The CRLs and OCSP responses of one `/DSS` that are readable, at most 256.
struct Revocation {
    crls: Vec<Crl>,
    ocsps: Vec<OcspResponse>,
}

impl Revocation {
    fn read(dss: &Dss) -> Self {
        let crls: Vec<Crl> = dss
            .crls
            .iter()
            .filter_map(|der| Crl::from_der(der).ok())
            .take(MAX_POOL_LEN)
            .collect();
        let ocsps = dss
            .ocsps
            .iter()
            .filter_map(|der| OcspResponse::from_der(der).ok())
            .take(MAX_POOL_LEN - crls.len())
            .collect();
        Self { crls, ocsps }
    }

    /// Whether a CRL or an OCSP response `issuer` signed covers `certificate`, whatever its
    /// dates, its extensions and what it says (ADR-0025): a CRL of `issuer`'s name whose
    /// signature its key verifies, or a response holding a single response about
    /// `certificate` signed by `issuer` or a responder it delegated.
    ///
    /// Under every policy, `refuse_critical_ocsp_extensions` included: a critical extension
    /// decides the pair's verdict, not whether the file carries data for it, so the level
    /// stays structural.
    fn covers(&self, certificate: &Node, issuer: &Node) -> bool {
        let issuer_name = issuer.certificate.tbs_certificate().subject();
        self.crls.iter().any(|crl| {
            crl.issuer() == issuer_name
                && crl.issuer() == certificate.certificate.tbs_certificate().issuer()
                && crl.verify_signature(&issuer.der).is_ok()
        }) || self.ocsps.iter().any(|response| {
            response
                .status_ignoring_critical_extensions(
                    &certificate.der,
                    &issuer.der,
                    response.produced_at(),
                )
                .is_ok()
        })
    }
}

/// What the level of every signature of one file is read from: its document timestamps,
/// the `/DSS` of its latest revisions, and the revocation data of the states that count.
pub(crate) struct Structure<'a> {
    pub(crate) timestamps: Vec<DocumentTimestamp>,
    states: Vec<State>,
    /// The revocation data of the `/DSS` of a state, by its index in `states`: the final
    /// one and each one a document timestamp covers.
    revocation: HashMap<usize, Revocation>,
    anchors: &'a TrustAnchors,
}

impl<'a> Structure<'a> {
    /// Reads the structure of `doc`, the document of `pdf`, its earlier states read with
    /// `options`: its first 16 document timestamps, the `/DSS` of each of its last 65
    /// revisions, and the revocation data of the states that count.
    pub(crate) fn read(
        doc: &Document<'_>,
        pdf: &[u8],
        options: &ReadOptions,
        anchors: &'a TrustAnchors,
    ) -> Self {
        let mut timestamps: Vec<DocumentTimestamp> = doc
            .signature_fields()
            .iter()
            .filter(|field| !field.value_unreadable)
            .filter_map(|field| match doc.object(field.value?) {
                Ok(Object::Dictionary(dict)) if is_document_timestamp(&dict) => Some(dict),
                _ => None,
            })
            .filter_map(|dict| {
                let [_, _, c, d] = byte_range(doc, &dict)?;
                let token = match follow_once(doc, dict.get(b"Contents")) {
                    Some(Object::String(bytes)) => der_prefix(&bytes).map(<[u8]>::to_vec),
                    _ => None,
                };
                Some(DocumentTimestamp {
                    end: c.checked_add(d)?,
                    dict,
                    token,
                })
            })
            .collect();
        timestamps.sort_by_key(|timestamp| timestamp.end);
        timestamps.truncate(MAX_DOCUMENT_TIMESTAMPS);

        let ends: Vec<usize> = doc.revisions().iter().map(|r| r.end).collect();
        let window = ends.len().saturating_sub(MAX_REVISIONS + 1);
        let last = ends.len().saturating_sub(1);
        let mut states: Vec<State> = Vec::new();
        let mut previous = Dss::default();
        for (index, &end) in ends.iter().enumerate().skip(window) {
            let own = if index == last {
                Dss::read(doc, pdf)
            } else {
                pdf.get(..end)
                    .and_then(|prefix| {
                        let earlier = Document::parse_with_options(prefix, options).ok()?;
                        Some(Dss::read(&earlier, prefix))
                    })
                    .unwrap_or_default()
            };
            let changed_at = match states.last() {
                Some(state) if own == previous => state.changed_at,
                None if own == Dss::default() => 0,
                _ => end,
            };
            let mut dss = states
                .last()
                .map(|state| state.dss.clone())
                .unwrap_or_default();
            dss.extend(&own);
            previous = own;
            states.push(State {
                end,
                dss,
                changed_at,
            });
        }

        let mut needed: Vec<usize> = timestamps
            .iter()
            .filter_map(|timestamp| state_signed_by(&states, timestamp.end))
            .collect();
        needed.extend(states.len().checked_sub(1));
        let revocation = needed
            .into_iter()
            .filter_map(|index| Some((index, Revocation::read(&states.get(index)?.dss))))
            .collect();
        Self {
            timestamps,
            states,
            revocation,
            anchors,
        }
    }

    /// The level of the signature whose dictionary is `dict`, from its `/SubFilter`, its
    /// `/M`, its CMS read unverified and the revisions after it; `None` when it has no
    /// `/SubFilter` Nacre names a form for, no readable CMS, or, for PAdES, no ESS
    /// `signingCertificate` nor `signingCertificateV2`.
    ///
    /// PAdES with a `signingTime` attribute or no readable `/M` is `PAdES-BES`, which climbs
    /// no further. Otherwise B climbs to T with a signature-timestamp attribute or a
    /// document timestamp after the signature, valid or not; to LT when the `/DSS` of the
    /// file, gathered over its revisions, covers every chain that counts
    /// ([`Structure::long_term`]); to LTA when a document timestamp after the signature
    /// covers a `/DSS` that already gives LT, written in an earlier revision or in its own.
    pub(crate) fn level(
        &self,
        doc: &Document<'_>,
        dict: Option<&Dictionary>,
    ) -> Option<SignatureLevel> {
        let dict = dict?;
        let form = match dict.get(b"SubFilter") {
            Some(Object::Name(name)) if name == b"ETSI.CAdES.detached" => SignatureForm::PAdES,
            Some(Object::Name(name)) if name == b"adbe.pkcs7.detached" => SignatureForm::Pkcs7,
            _ => return None,
        };
        let contents = match follow_once(doc, dict.get(b"Contents")) {
            Some(Object::String(bytes)) => bytes,
            _ => return None,
        };
        let cms = SignedData::from_der(der_prefix(&contents)?).ok()?;
        let info = cms.signer_infos.first()?;
        let attributes = match &info.signed_attrs {
            Some(attributes) => attributes.attributes().ok()?,
            None => Vec::new(),
        };
        let at = |profile| Some(SignatureLevel { form, profile });
        if form == SignatureForm::PAdES {
            let has = |oid: ObjectIdentifier| attributes.iter().any(|a| a.oid == oid);
            if !has(SIGNING_CERTIFICATE) && !has(nacre_cms::oid::SIGNING_CERTIFICATE_V2) {
                return None;
            }
            let claimed = match follow_once(doc, dict.get(b"M")) {
                Some(Object::String(bytes)) => pdf_date(&bytes),
                _ => None,
            };
            if has(nacre_cms::oid::SIGNING_TIME) || claimed.is_none() {
                return at(SignatureProfile::ExtendedBes);
            }
        }

        let signature_end = byte_range(doc, dict).and_then(|[_, _, c, d]| c.checked_add(d));
        let later: Vec<&DocumentTimestamp> = self
            .timestamps
            .iter()
            .filter(|timestamp| signature_end.is_some_and(|end| timestamp.end > end))
            .collect();
        let tokens: Vec<Vec<u8>> = info
            .unsigned_attrs
            .iter()
            .filter(|attribute| attribute.oid == SIGNATURE_TIME_STAMP_TOKEN)
            .flat_map(|attribute| &attribute.values)
            .take(MAX_TIMESTAMPS)
            .filter_map(|value| value.to_der().ok())
            .collect();
        if tokens.is_empty() && later.is_empty() {
            return at(SignatureProfile::BaselineB);
        }
        let signature = Signature {
            cms: &cms,
            sid: &info.sid,
            tokens: &tokens,
            later: &later,
        };
        let Some(last) = self.states.len().checked_sub(1) else {
            return at(SignatureProfile::BaselineT);
        };
        if !self.long_term(&signature, last) {
            return at(SignatureProfile::BaselineT);
        }
        let archived = later.iter().any(|timestamp| {
            state_signed_by(&self.states, timestamp.end)
                .is_some_and(|i| self.long_term(&signature, i))
        });
        at(if archived {
            SignatureProfile::BaselineLta
        } else {
            SignatureProfile::BaselineLt
        })
    }

    /// Whether the `/DSS` data gathered up to state `index` covers, for each certificate
    /// except self-signed ones, the chains that count there: the signer's, each signature
    /// timestamp's, each document timestamp's after the signature in a revision before the
    /// last `/DSS`, and, with no signature timestamp, the first document timestamp's after
    /// the signature.
    /// Each chain is walked by name and verified signature through the certificates of the
    /// CMS, of the tokens, of that `/DSS` and of the trust anchors. Chains made only of
    /// self-signed certificates cover nothing, so they never give LT on their own.
    fn long_term(&self, signature: &Signature<'_>, index: usize) -> bool {
        let (Some(state), Some(revocation)) = (self.states.get(index), self.revocation.get(&index))
        else {
            return false;
        };
        let first_counts = signature.tokens.is_empty();
        let mut tokens: Vec<&[u8]> = signature.tokens.iter().map(Vec::as_slice).collect();
        for (position, stamp) in signature.later.iter().enumerate() {
            if stamp.end < state.changed_at || (position == 0 && first_counts) {
                let Some(token) = &stamp.token else {
                    return false;
                };
                tokens.push(token);
            }
        }
        let Ok(tokens) = tokens
            .into_iter()
            .map(SignedData::from_der)
            .collect::<Result<Vec<_>, _>>()
        else {
            return false;
        };
        let candidates: Vec<Node> = signature
            .cms
            .certificates
            .iter()
            .chain(tokens.iter().flat_map(|token| &token.certificates))
            .chain(&state.dss.certificates)
            .filter_map(|der| Node::read(der).ok())
            .chain(self.anchors.nodes().iter().cloned())
            .take(MAX_POOL_LEN)
            .collect();
        let leaves = std::iter::once(Some(signature.sid)).chain(
            tokens
                .iter()
                .map(|token| token.signer_infos.first().map(|info| &info.sid)),
        );
        let mut pairs = 0;
        for sid in leaves {
            let Some(leaf) = sid.and_then(|sid| find(&candidates, sid)) else {
                return false;
            };
            match covered(leaf, &candidates, revocation) {
                Some(covered) => pairs += covered,
                None => return false,
            }
        }
        pairs > 0
    }
}

/// What the level of one signature is read from.
struct Signature<'s> {
    cms: &'s SignedData,
    sid: &'s SignerIdentifier,
    /// Its signature timestamp tokens, as DER.
    tokens: &'s [Vec<u8>],
    /// The document timestamps after it, oldest first.
    later: &'s [&'s DocumentTimestamp],
}

/// The index of the state a document timestamp whose signed bytes end at `end` covers: the
/// latest one ending there or before, so a `/DSS` written in the timestamp's own revision
/// counts, as pyHanko writes them.
fn state_signed_by(states: &[State], end: usize) -> Option<usize> {
    states.iter().rposition(|state| state.end <= end)
}

/// The first of `candidates` that `sid` names.
fn find<'n>(candidates: &'n [Node], sid: &SignerIdentifier) -> Option<&'n Node> {
    candidates.iter().find(|node| {
        let tbs = node.certificate.tbs_certificate();
        match sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer,
                serial_number,
            } => {
                tbs.serial_number() == serial_number
                    && tbs.issuer().to_der().is_ok_and(|name| name == *issuer)
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                matches!(
                    tbs.get_extension::<SubjectKeyIdentifier>(),
                    Ok(Some((_, found))) if found.0.as_bytes() == ski.as_slice()
                )
            }
        }
    })
}

/// How many pairs of the chain from `leaf` `revocation` covers, the chain walked through
/// `candidates` up to a self-signed certificate with at most 8 pairs; `None` when a pair is
/// not covered, or a certificate's issuer is not among `candidates`.
fn covered(leaf: &Node, candidates: &[Node], revocation: &Revocation) -> Option<usize> {
    let mut child = leaf;
    for pairs in 0..=MAX_PATH_LEN {
        if child.is_self_signed() {
            return Some(pairs);
        }
        let issuer = candidates.iter().find(|issuer| {
            issuer.der != child.der && issuer.names(child) && signed_by(child, issuer)
        })?;
        if !revocation.covers(child, issuer) {
            return None;
        }
        child = issuer;
    }
    None
}
