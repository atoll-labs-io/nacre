#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io;

use nacre_core::{
    DigestAlgorithm, Error, RevocationData, RevocationSource, Signer, TestSigner,
    TimestampAuthority,
};

struct DownTsa;

impl TimestampAuthority for DownTsa {
    fn timestamp(&self, _algorithm: DigestAlgorithm, _imprint: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::timestamp(io::Error::other("tsa down")))
    }
}

struct FixedOcsp;

impl RevocationSource for FixedOcsp {
    fn revocation(&self, _certificate: &[u8], _issuer: &[u8]) -> Result<RevocationData, Error> {
        Ok(RevocationData::Ocsp(vec![0x30, 0x00]))
    }
}

#[test]
fn implementations_travel_as_trait_objects() {
    let test_signer = TestSigner::from_secret(&[0x22; 32]).unwrap();
    let signer: &dyn Signer = &test_signer;
    let tsa: &dyn TimestampAuthority = &DownTsa;
    let revocation: &dyn RevocationSource = &FixedOcsp;

    let chain = signer.certificate_chain();
    assert!(!chain.is_empty());
    assert!(!signer.sign_digest(&[0u8; 32]).unwrap().is_empty());

    assert_eq!(
        revocation.revocation(&chain[0], &chain[0]).unwrap(),
        RevocationData::Ocsp(vec![0x30, 0x00])
    );

    let err = tsa
        .timestamp(DigestAlgorithm::Sha256, &[0u8; 32])
        .unwrap_err();
    let source = std::error::Error::source(&err).expect("the implementation error is the source");
    let io_error = source
        .downcast_ref::<io::Error>()
        .expect("source is the io::Error");
    assert_eq!(io_error.to_string(), "tsa down");
}
