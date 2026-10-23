use std::collections::{HashSet, VecDeque};

use der::Decode;
use nacre_core::{RevocationData, RevocationSource};
use x509_cert::Certificate;

use crate::Error;

/// What `/DSS` stores for one signature: certificates, CRLs and OCSP responses as DER,
/// each without duplicates, in first-seen order.
#[derive(Default)]
pub(crate) struct Material {
    pub(crate) certificates: Vec<Vec<u8>>,
    pub(crate) crls: Vec<Vec<u8>>,
    pub(crate) ocsps: Vec<Vec<u8>>,
}

fn push_unique(list: &mut Vec<Vec<u8>>, item: Vec<u8>) {
    if !list.contains(&item) {
        list.push(item);
    }
}

/// Walks issuers by name from `chain` and `token_certificates`, drawing on `issuers` for the
/// certificates neither carries, and asks `source` once for each certificate that is not
/// self-signed.
pub(crate) fn material(
    chain: &[Vec<u8>],
    token_certificates: &[Vec<u8>],
    issuers: &[Vec<u8>],
    source: &dyn RevocationSource,
) -> Result<Material, Error> {
    let pool = chain
        .iter()
        .chain(token_certificates)
        .chain(issuers)
        .map(|der| {
            Certificate::from_der(der)
                .map(|parsed| (der, parsed))
                .map_err(Error::Certificate)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut queue: VecDeque<usize> = (0..chain.len() + token_certificates.len()).collect();
    // Keyed on DER bytes, so a name loop (A issued by B, B by A) ends after the pool is spent.
    let mut visited: HashSet<&[u8]> = HashSet::new();
    let mut out = Material::default();

    while let Some(index) = queue.pop_front() {
        let Some((der, certificate)) = pool.get(index) else {
            continue;
        };
        if !visited.insert(der.as_slice()) {
            continue;
        }
        push_unique(&mut out.certificates, der.to_vec());
        let tbs = certificate.tbs_certificate();
        if tbs.subject() == tbs.issuer() {
            continue;
        }
        let name = || tbs.subject().to_string();
        let (issuer_index, (issuer_der, _)) = pool
            .iter()
            .enumerate()
            .find(|(_, (_, candidate))| candidate.tbs_certificate().subject() == tbs.issuer())
            .ok_or_else(|| Error::IssuerMissing {
                certificate: name(),
            })?;
        match source
            .revocation(der, issuer_der)
            .map_err(|source| Error::Revocation {
                certificate: name(),
                source,
            })? {
            RevocationData::Crl(crl) => push_unique(&mut out.crls, crl),
            RevocationData::Ocsp(ocsp) => push_unique(&mut out.ocsps, ocsp),
            _ => {
                return Err(Error::RevocationUnsupported {
                    certificate: name(),
                });
            }
        }
        queue.push_back(issuer_index);
    }
    Ok(out)
}
