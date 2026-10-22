#![cfg(feature = "http")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! The address and redirect refusals of `HttpCrlSource`, against a server on 127.0.0.1
//! that serves a valid CRL: every refusal here would otherwise be a successful fetch.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::str::FromStr;

use der::{DateTime, Encode};
use nacre_core::{ErrorKind, RevocationData, RevocationSource};
use nacre_revocation::{Error, HttpCrlSource};
use p256::ecdsa::{DerSignature, SigningKey};
use x509_cert::builder::profile::cabf;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::der::asn1::Ia5String;
use x509_cert::ext::pkix::CrlDistributionPoints;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const CRL: &[u8] = include_bytes!("corpus/openssl/ec-ca.crl");

/// Serves `CRL` at `/ca.crl` and a 302 to it at `/redirect`, one request per connection.
fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 2 {
                line.clear();
            }
            let response = if request_line.starts_with("GET /redirect ") {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/ca.crl\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .into_bytes()
            } else {
                let mut response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    CRL.len()
                )
                .into_bytes();
                response.extend_from_slice(CRL);
                response
            };
            stream.write_all(&response).unwrap();
        }
    });
    port
}

/// A certificate whose only use here is to name `url` as its CRL distribution point.
fn naming(url: &str) -> Vec<u8> {
    let key = SigningKey::from_slice(&[0x31; 32]).unwrap();
    let name = Name::from_str("CN=Nacre HTTP test,O=Nacre tests,C=FR").unwrap();
    let time = |year| Time::from(DateTime::new(year, 1, 1, 0, 0, 0).unwrap());
    let mut builder = CertificateBuilder::new(
        cabf::Root::new(false, name).unwrap(),
        SerialNumber::from(1u32),
        Validity::new(time(2026), time(2036)),
        SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap(),
    )
    .unwrap();
    builder
        .add_extension(&CrlDistributionPoints(vec![DistributionPoint {
            distribution_point: Some(DistributionPointName::FullName(vec![
                GeneralName::UniformResourceIdentifier(Ia5String::new(url).unwrap()),
            ])),
            reasons: None,
            crl_issuer: None,
        }]))
        .unwrap();
    builder
        .build::<_, DerSignature>(&key)
        .unwrap()
        .to_der()
        .unwrap()
}

fn fetch(source: &HttpCrlSource, url: &str) -> Result<Vec<u8>, Error> {
    match source.revocation(&naming(url), &[]) {
        Ok(RevocationData::Crl(bytes)) => Ok(bytes),
        Ok(_) => panic!("a CRL source answered with something else"),
        Err(nacre_core::Error::Revocation(error)) => Err(*error.downcast::<Error>().unwrap()),
        Err(error) => panic!("unexpected error {error}"),
    }
}

#[test]
fn redirect_is_not_followed() {
    let port = serve();
    let source = HttpCrlSource::allowing_loopback();
    assert_eq!(
        fetch(&source, &format!("http://127.0.0.1:{port}/ca.crl")).unwrap(),
        CRL
    );
    assert!(matches!(
        fetch(&source, &format!("http://127.0.0.1:{port}/redirect")),
        Err(Error::Http(ureq::Error::StatusCode(302)))
    ));
}

#[test]
fn loopback_point_is_refused_by_default() {
    let port = serve();
    let url = format!("http://127.0.0.1:{port}/ca.crl");
    let error = fetch(&HttpCrlSource::new(), &url).unwrap_err();
    assert!(matches!(error, Error::NonPublicAddress));
    assert_eq!(error.kind(), ErrorKind::InvalidInput);
    assert!(!error.to_string().contains("127.0.0.1"));
    assert!(!format!("{error:?}").contains("127.0.0.1"));
}

#[test]
fn private_addresses_are_refused_even_with_loopback_allowed() {
    for source in [HttpCrlSource::new(), HttpCrlSource::allowing_loopback()] {
        for url in ["http://10.1.2.3/ca.crl", "http://[fd00::1]/ca.crl"] {
            assert!(
                matches!(fetch(&source, url), Err(Error::NonPublicAddress)),
                "{url}"
            );
        }
    }
}
