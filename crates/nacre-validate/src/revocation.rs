//! Revocation of a certification path at the best-signature-time, from stored CRLs and OCSP
//! responses and an optional [`RevocationSource`].

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

use der::Decode;
use nacre_core::{RevocationData, RevocationSource, SubIndication, ValidationReport};
use nacre_revocation::{Crl, CrlReason, CrlStatus, OcspResponse, OcspStatus};
use x509_cert::Certificate;

use crate::CertificatePath;

/// Distinct readable CRLs and OCSP responses one pool holds; later ones are ignored.
const MAX_POOL_LEN: usize = 256;

/// How long before the control date a CRL (`thisUpdate`) or an OCSP response (`producedAt`)
/// may have been issued and still count for a signature no timestamp gives a proof of
/// existence: 24 hours.
///
/// Without that proof, data issued before a revocation would otherwise pass a key revoked
/// later, and whoever holds the key chooses the `/DSS` it appends. A day matches CAs that
/// publish their CRLs and OCSP responses at least daily, and bounds to one day the window
/// in which a revoked key still passes offline. This departs from DSS 6.5.1, which ignores
/// freshness in every case; a signature with a proof of existence keeps DSS's rule.
pub(crate) const FRESHNESS_TOLERANCE: Duration = Duration::from_secs(24 * 3600);

/// Why a valid path does not pass its revocation check. `depth` counts from the leaf, 0.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationDefect {
    /// The latest usable revocation data on the certificate at `depth` says it was revoked
    /// on `date`, at or before the best-signature-time.
    Revoked { depth: usize, date: SystemTime },
    /// No usable CRL or OCSP response covers the certificate at `depth`.
    Missing { depth: usize },
}

impl RevocationDefect {
    /// The EN 319 102-1 outcome of this defect, as DSS 6.5.1 gives it: always
    /// `INDETERMINATE` and with no level.
    pub fn report(&self) -> ValidationReport {
        let sub = match self {
            Self::Revoked { depth: 0, .. } => SubIndication::RevokedNoPoe,
            Self::Revoked { .. } => SubIndication::RevokedCaNoPoe,
            Self::Missing { .. } => SubIndication::CertificateChainGeneralFailure,
        };
        ValidationReport::indeterminate(sub, None)
    }
}

enum Item {
    Crl(Crl),
    Ocsp(OcspResponse),
}

impl Item {
    fn read(data: &RevocationData) -> Option<Self> {
        match data {
            RevocationData::Crl(der) => Crl::from_der(der).ok().map(Self::Crl),
            RevocationData::Ocsp(der) => OcspResponse::from_der(der).ok().map(Self::Ocsp),
            _ => None,
        }
    }

    /// What the item says of `certificate`, judged at its own date: the CRL's `thisUpdate`
    /// or the response's `producedAt`. Judging there rather than at the control date makes
    /// an expired item usable, as DSS does; every other refusal of `status` drops it.
    fn verdict(&self, certificate: &[u8], issuer: &[u8]) -> Option<Verdict> {
        let (date, revoked, reason) = match self {
            Self::Crl(crl) => {
                let date = crl.this_update();
                match crl.status(certificate, issuer, date).ok()? {
                    CrlStatus::NotRevoked => (date, None, None),
                    CrlStatus::Revoked {
                        date: revoked,
                        reason,
                    } => (date, Some(revoked), reason),
                    _ => return None,
                }
            }
            Self::Ocsp(response) => {
                let date = response.produced_at();
                match response.status(certificate, issuer, date).ok()? {
                    OcspStatus::Good => (date, None, None),
                    OcspStatus::Revoked {
                        date: revoked,
                        reason,
                    } => (date, Some(revoked), reason),
                    _ => return None,
                }
            }
        };
        Some(Verdict {
            date,
            revoked,
            hold: reason == Some(CrlReason::CertificateHold),
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Verdict {
    date: SystemTime,
    revoked: Option<SystemTime>,
    /// The revocation is a `certificateHold`, which a later CRL may lift.
    hold: bool,
}

impl Verdict {
    /// Whether `self` is preferred to `other`: issued later, a revocation first on a tie.
    fn outranks(&self, other: &Verdict) -> bool {
        (self.date, self.revoked.is_some()) > (other.date, other.revoked.is_some())
    }
}

type Pair = (Vec<u8>, Vec<u8>);

/// The revocation data of one signature, read once, with what was already judged.
pub(crate) struct RevocationPool {
    items: Vec<Item>,
    /// The verdict of item `i` on a (certificate, issuer) pair.
    verdicts: RefCell<HashMap<(usize, Pair), Option<Verdict>>>,
    /// The source's answer on a (certificate, issuer) pair.
    answers: RefCell<HashMap<Pair, Option<Verdict>>>,
}

impl RevocationPool {
    /// Reads `items`, most trusted first. Items that are not a readable CRL or OCSP
    /// response and exact repeats are dropped before the 256-item cap applies, so a caller
    /// listing the signature's own data first keeps it whatever follows.
    pub(crate) fn from_der(items: &[RevocationData]) -> Self {
        let mut seen: HashSet<&[u8]> = HashSet::new();
        let mut read = Vec::new();
        for data in items {
            if read.len() >= MAX_POOL_LEN {
                break;
            }
            let bytes = match data {
                RevocationData::Crl(der) | RevocationData::Ocsp(der) => der.as_slice(),
                _ => continue,
            };
            if !seen.insert(bytes) {
                continue;
            }
            if let Some(item) = Item::read(data) {
                read.push(item);
            }
        }
        Self {
            items: read,
            verdicts: RefCell::new(HashMap::new()),
            answers: RefCell::new(HashMap::new()),
        }
    }

    fn verdict(
        &self,
        index: usize,
        item: &Item,
        certificate: &[u8],
        issuer: &[u8],
    ) -> Option<Verdict> {
        let key = (index, (certificate.to_vec(), issuer.to_vec()));
        if let Some(known) = self.verdicts.borrow().get(&key) {
            return *known;
        }
        let verdict = item.verdict(certificate, issuer);
        self.verdicts.borrow_mut().insert(key, verdict);
        verdict
    }

    fn answer(
        &self,
        source: &dyn RevocationSource,
        certificate: &[u8],
        issuer: &[u8],
    ) -> Option<Verdict> {
        let key = (certificate.to_vec(), issuer.to_vec());
        if let Some(known) = self.answers.borrow().get(&key) {
            return *known;
        }
        let verdict = source
            .revocation(certificate, issuer)
            .ok()
            .and_then(|data| Item::read(&data))
            .and_then(|item| item.verdict(certificate, issuer));
        self.answers.borrow_mut().insert(key, verdict);
        verdict
    }
}

/// Judges the revocation of every certificate of `path` below its anchor at `time`, the
/// best-signature-time. For each one, the usable items are the pool's and the one answer of
/// `source` (a failure adds none), each issued within the certificate's validity, from its
/// `notBefore` to its `notAfter`, and, when `issued_from` is given, at or after it, except
/// a revocation dated at or before `time` other than a `certificateHold`, which stays true
/// however old its proof; the latest one decides. A revocation dated at or before `time`
/// refuses the path, a later one does not, and a certificate no usable item covers is
/// [`RevocationDefect::Missing`].
///
/// An item issued after the certificate's `notAfter` is dropped under every policy, for the
/// signer, its CAs and a timestamp authority alike, as DSS 6.5.1 does: it is no switch
/// (ADR-0026, ADR-0027).
pub(crate) fn judge_path(
    path: &CertificatePath,
    pool: &RevocationPool,
    source: Option<&dyn RevocationSource>,
    time: SystemTime,
    issued_from: Option<SystemTime>,
) -> Result<(), RevocationDefect> {
    for (depth, pair) in path.certificates.windows(2).enumerate() {
        let [certificate, issuer] = pair else {
            continue;
        };
        let parsed =
            Certificate::from_der(certificate).map_err(|_| RevocationDefect::Missing { depth })?;
        let validity = parsed.tbs_certificate().validity();
        let not_before = validity.not_before.to_system_time();
        let not_after = validity.not_after.to_system_time();
        // Freshness guards against a "not revoked" issued before a revocation; an old proof
        // of revocation stays true, unless it is a hold that may have been lifted since. A
        // stale item revoking only after `time` says "not revoked at `time`", so it is dropped.
        let fresh = |verdict: &Verdict| {
            issued_from.is_none_or(|from| verdict.date >= from)
                || (verdict.revoked.is_some_and(|date| date <= time) && !verdict.hold)
        };
        let stored = pool
            .items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| pool.verdict(index, item, certificate, issuer));
        let fetched = source.and_then(|source| pool.answer(source, certificate, issuer));
        let latest = stored
            .chain(fetched)
            .filter(|verdict| (not_before..=not_after).contains(&verdict.date) && fresh(verdict))
            .reduce(|best, next| if next.outranks(&best) { next } else { best })
            .ok_or(RevocationDefect::Missing { depth })?;
        if let Some(date) = latest.revoked
            && date <= time
        {
            return Err(RevocationDefect::Revoked { depth, date });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nacre_core::Indication;
    use nacre_core::SubIndication::*;

    #[test]
    fn every_revocation_defect_has_its_report() {
        let date = SystemTime::UNIX_EPOCH;
        let rows = [
            (RevocationDefect::Revoked { depth: 0, date }, RevokedNoPoe),
            (RevocationDefect::Revoked { depth: 1, date }, RevokedCaNoPoe),
            (
                RevocationDefect::Missing { depth: 0 },
                CertificateChainGeneralFailure,
            ),
            (
                RevocationDefect::Missing { depth: 2 },
                CertificateChainGeneralFailure,
            ),
        ];
        for (defect, sub) in rows {
            let report = defect.report();
            assert_eq!(report.indication(), Indication::Indeterminate, "{defect:?}");
            assert_eq!(report.sub_indication(), Some(sub), "{defect:?}");
            assert_eq!(report.level(), None, "{defect:?}");
        }
    }
}
