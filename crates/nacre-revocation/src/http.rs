use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use der::Decode;
use nacre_core::{RevocationData, RevocationSource};
use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};
use x509_cert::Certificate;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{AuthorityInfoAccessSyntax, CrlDistributionPoints};

use crate::{Crl, Error, OcspRequest, OcspResponse};

const TIMEOUT: Duration = Duration::from_secs(30);
const BODY_LIMIT: u64 = 16 * 1024 * 1024;
const OCSP_BODY_LIMIT: u64 = 64 * 1024;
const ID_AD_OCSP: der::oid::ObjectIdentifier =
    der::oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");

/// A [`RevocationSource`] that downloads the CRL named by a certificate's first `http://`
/// distribution point.
///
/// The certificate may come from anyone, so the URL it names is untrusted: the source only
/// connects to public addresses, checked on the addresses the host resolves to, which are
/// the ones it then connects to. It follows no redirect, ignores proxy settings, stops
/// after 30 s and 16 MiB, and returns the bytes only once they read as a CRL; judging that
/// CRL is [`Crl::status`]'s job. `https` and LDAP points are skipped: a caller that needs
/// them injects its own source.
#[derive(Debug)]
pub struct HttpCrlSource {
    agent: ureq::Agent,
}

impl HttpCrlSource {
    /// A source that refuses loopback, private, link-local and other non-public addresses
    /// with [`Error::NonPublicAddress`].
    pub fn new() -> Self {
        Self {
            agent: with_policy(AddressPolicy { loopback: false }),
        }
    }

    /// A source that also reaches loopback addresses (`127.0.0.0/8`, `::1`), for a test
    /// bench on this machine. Private and link-local addresses stay refused.
    pub fn allowing_loopback() -> Self {
        Self {
            agent: with_policy(AddressPolicy { loopback: true }),
        }
    }

    /// The URL this source fetches for `certificate`, given as DER: the first `fullName`
    /// URI starting with `http://`, in a distribution point without `reasons` nor
    /// `cRLIssuer`, whose CRL would cover only part of the reasons or come from elsewhere.
    pub fn distribution_point(certificate: &[u8]) -> Result<String, Error> {
        let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
        let (_, points) = certificate
            .tbs_certificate()
            .get_extension::<CrlDistributionPoints>()
            .map_err(Error::Certificate)?
            .ok_or(Error::NoDistributionPoint)?;
        points
            .0
            .iter()
            .filter(|point| point.reasons.is_none() && point.crl_issuer.is_none())
            .filter_map(|point| match &point.distribution_point {
                Some(DistributionPointName::FullName(names)) => Some(names),
                _ => None,
            })
            .flatten()
            .find_map(|name| match name {
                GeneralName::UniformResourceIdentifier(uri)
                    if uri.as_str().starts_with("http://") =>
                {
                    Some(uri.as_str().to_owned())
                }
                _ => None,
            })
            .ok_or(Error::NoDistributionPoint)
    }

    fn fetch(&self, certificate: &[u8]) -> Result<Vec<u8>, Error> {
        let url = Self::distribution_point(certificate)?;
        let response = self.agent.get(&url).call().map_err(http_error)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(Error::Http(ureq::Error::StatusCode(status.as_u16())));
        }
        let body = response
            .into_body()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_vec()
            .map_err(http_error)?;
        Crl::from_der(&body)?;
        Ok(body)
    }
}

/// An agent that connects only where `policy` allows, follows no redirect, ignores proxy
/// settings and stops after 30 s.
fn with_policy(policy: AddressPolicy) -> ureq::Agent {
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(TIMEOUT))
        .max_redirects(0)
        // A proxy would resolve the host itself, out of reach of the address check.
        .proxy(None)
        .build();
    ureq::Agent::with_parts(config, DefaultConnector::default(), policy)
}

/// A [`RevocationSource`] that asks the OCSP responder named by a certificate's first
/// `http://` `id-ad-ocsp` access location.
///
/// The URL comes from the certificate, so the same address policy as [`HttpCrlSource`]
/// applies: public addresses only, no redirect, no proxy, 30 s. The request carries a
/// fresh 32-octet nonce; the response is returned once it reads as a successful basic
/// response whose nonce, when present, is the request's ([`OcspResponse::check_nonce`]).
/// Judging it is [`OcspResponse::status`]'s job. The body is limited to 64 KiB.
#[derive(Debug)]
pub struct HttpOcspSource {
    agent: ureq::Agent,
}

impl HttpOcspSource {
    /// A source that refuses loopback, private, link-local and other non-public addresses
    /// with [`Error::NonPublicAddress`].
    pub fn new() -> Self {
        Self {
            agent: with_policy(AddressPolicy { loopback: false }),
        }
    }

    /// A source that also reaches loopback addresses (`127.0.0.0/8`, `::1`), for a test
    /// bench on this machine. Private and link-local addresses stay refused.
    pub fn allowing_loopback() -> Self {
        Self {
            agent: with_policy(AddressPolicy { loopback: true }),
        }
    }

    /// The URL this source asks for `certificate`, given as DER: the first `id-ad-ocsp`
    /// access location of its `authorityInfoAccess` that is a URI starting with `http://`.
    pub fn responder_url(certificate: &[u8]) -> Result<String, Error> {
        let certificate = Certificate::from_der(certificate).map_err(Error::Certificate)?;
        let (_, access) = certificate
            .tbs_certificate()
            .get_extension::<AuthorityInfoAccessSyntax>()
            .map_err(Error::Certificate)?
            .ok_or(Error::NoOcspResponder)?;
        access
            .0
            .iter()
            .filter(|description| description.access_method == ID_AD_OCSP)
            .find_map(|description| match &description.access_location {
                GeneralName::UniformResourceIdentifier(uri)
                    if uri.as_str().starts_with("http://") =>
                {
                    Some(uri.as_str().to_owned())
                }
                _ => None,
            })
            .ok_or(Error::NoOcspResponder)
    }

    fn fetch(&self, certificate: &[u8], issuer: &[u8]) -> Result<Vec<u8>, Error> {
        let url = Self::responder_url(certificate)?;
        let request = OcspRequest::with_random_nonce(certificate, issuer)?;
        let response = self
            .agent
            .post(&url)
            .header("Content-Type", "application/ocsp-request")
            .send(&request.to_der()?[..])
            .map_err(http_error)?;
        let status = response.status();
        if status.is_redirection() {
            return Err(Error::Http(ureq::Error::StatusCode(status.as_u16())));
        }
        let body = response
            .into_body()
            .with_config()
            .limit(OCSP_BODY_LIMIT)
            .read_to_vec()
            .map_err(http_error)?;
        OcspResponse::from_der(&body)?.check_nonce(&request)?;
        Ok(body)
    }
}

impl Default for HttpOcspSource {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationSource for HttpOcspSource {
    /// Asks the responder of `certificate` about it; `issuer` identifies it in the request.
    fn revocation(
        &self,
        certificate: &[u8],
        issuer: &[u8],
    ) -> Result<RevocationData, nacre_core::Error> {
        self.fetch(certificate, issuer)
            .map(RevocationData::Ocsp)
            .map_err(|error| nacre_core::Error::Revocation(Box::new(error)))
    }
}

fn http_error(error: ureq::Error) -> Error {
    match error {
        ureq::Error::Other(inner) if inner.is::<Refused>() => Error::NonPublicAddress,
        error => Error::Http(error),
    }
}

/// Marks the resolver's refusal inside the `ureq::Error` it has to return.
#[derive(Debug, thiserror::Error)]
#[error("non-public address")]
struct Refused;

/// Resolves as ureq does, then refuses the whole host when any of its addresses is not
/// allowed: ureq connects only to the addresses returned here, so a second lookup cannot
/// swap in another one.
#[derive(Debug)]
struct AddressPolicy {
    loopback: bool,
}

impl Resolver for AddressPolicy {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addresses = DefaultResolver::default().resolve(uri, config, timeout)?;
        if addresses
            .iter()
            .all(|address| allowed(address.ip(), self.loopback))
        {
            Ok(addresses)
        } else {
            Err(ureq::Error::Other(Box::new(Refused)))
        }
    }
}

fn allowed(address: IpAddr, loopback: bool) -> bool {
    match address {
        IpAddr::V4(v4) => (loopback && v4.is_loopback()) || public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => allowed(IpAddr::V4(v4), loopback),
            None => (loopback && v6.is_loopback()) || public_v6(v6),
        },
    }
}

fn public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(a == 0
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_documentation()
        || address.is_multicast()
        // 240.0.0.0/4, reserved, and the broadcast address.
        || a >= 240
        // 100.64.0.0/10, shared address space (carrier-grade NAT).
        || (a == 100 && b & 0xc0 == 64)
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15, benchmarking.
        || (a == 198 && b & 0xfe == 18))
}

/// Only global unicast (`2000::/3`) is public; inside it, documentation and IETF protocol
/// ranges are not, and a 6to4 address is judged by the IPv4 address it carries.
fn public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let [first, second, ..] = segments;
    if first & 0xe000 != 0x2000 {
        return false;
    }
    if first == 0x2001 && (second == 0x0db8 || second < 0x0200) {
        return false;
    }
    if first == 0x2002 {
        let [_, _, a, b, c, d, ..] = address.octets();
        return public_v4(Ipv4Addr::new(a, b, c, d));
    }
    true
}

impl Default for HttpCrlSource {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationSource for HttpCrlSource {
    /// Downloads the CRL of `certificate`. `issuer` is not needed to fetch a CRL and is
    /// ignored; it serves when the CRL is judged.
    fn revocation(
        &self,
        certificate: &[u8],
        _issuer: &[u8],
    ) -> Result<RevocationData, nacre_core::Error> {
        self.fetch(certificate)
            .map(RevocationData::Crl)
            .map_err(|error| nacre_core::Error::Revocation(Box::new(error)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nacre_core::{Signer, TestSigner};

    #[test]
    fn distribution_point_of_the_fixture_leaf() {
        let leaf = include_bytes!("../tests/corpus/openssl/leaf.der");
        assert_eq!(
            HttpCrlSource::distribution_point(leaf).unwrap(),
            "http://crl.example.test/ca.crl"
        );
    }

    #[test]
    fn only_public_addresses_are_allowed() {
        let public = [
            "8.8.8.8",
            "193.0.0.1",
            "2a00:1450:4007::1",
            "2002:808:808::1",
        ];
        let refused = [
            "0.0.0.0",
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.0.0.8",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fd00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "2002:a00:1::1",
        ];
        for address in public {
            assert!(allowed(address.parse().unwrap(), false), "{address}");
        }
        for address in refused {
            assert!(!allowed(address.parse().unwrap(), false), "{address}");
        }
        for address in ["127.0.0.1", "127.8.0.1", "::1", "::ffff:127.0.0.1"] {
            assert!(!allowed(address.parse().unwrap(), false), "{address}");
            assert!(allowed(address.parse().unwrap(), true), "{address}");
        }
        for address in ["10.1.2.3", "fd00::1", "169.254.169.254"] {
            assert!(!allowed(address.parse().unwrap(), true), "{address}");
        }
    }

    #[test]
    fn certificate_without_point_is_refused() {
        let signer = TestSigner::from_secret(&[0x11; 32]).unwrap();
        let certificate = signer.certificate_chain().first().unwrap();
        assert!(matches!(
            HttpCrlSource::distribution_point(certificate),
            Err(Error::NoDistributionPoint)
        ));
    }
}
