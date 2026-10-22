#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! A PDF signed by a SoftHSM key through `Pkcs11Signer`, judged by the running DSS
//! (`conformance/README.md`).

mod support;

use std::path::Path;

use nacre_conformance::{Dss, pki_dir, reports_dir};
use nacre_core::Indication;
use nacre_pades::{DateTime, sign};
use nacre_pkcs11::{KeySelector, Pkcs11Signer};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;
use support::{Token, in_token};

const UNSIGNED: &[u8] = include_bytes!("../../../conformance/reference/unsigned.pdf");

fn read(dir: &Path, name: &str) -> String {
    let path = dir.join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read {}: {error}; start the bench: conformance/README.md",
            path.display()
        )
    })
}

fn certificate(dir: &Path, name: &str) -> Vec<u8> {
    let pem = read(dir, name);
    let (label, der) = der::pem::decode_vec(pem.as_bytes()).unwrap();
    assert_eq!(label, "CERTIFICATE");
    der
}

#[test]
#[ignore = "conformance"]
fn softhsm_signature_is_pades_baseline_b() {
    in_token("softhsm_signature_is_pades_baseline_b", |token| {
        let report = reports_dir().join("s13-pkcs11-b.xml");
        // A report left by an earlier run must not stand in for this one.
        let _ = std::fs::remove_file(&report);
        let dir = pki_dir();
        let key = SigningKey::from_pkcs8_pem(&read(&dir, "signer.key.pem")).unwrap();
        let secret: [u8; 32] = key.to_bytes().into();
        token.put_ec_key(&secret, "bench-signer", &[0x0b], false);
        token.put_certificate(
            &certificate(&dir, "signer.cert.pem"),
            "bench-signer-cert",
            &[0x0b],
        );

        let config = token.config(
            KeySelector::Id(vec![0x0b]),
            vec![certificate(&dir, "intermediate.cert.pem")],
        );
        let signer = Pkcs11Signer::open(&config, Token::pin()).unwrap();
        // Inside the bench certificates' validity, 2026-01-01 to 2046-01-01.
        let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();
        let signed = sign(UNSIGNED, &signer, time).unwrap();

        let reports = Dss::from_env()
            .unwrap()
            .validate("s13-pkcs11-b", &signed)
            .unwrap();

        assert_eq!(reports.signatures.len(), 1);
        let verdict = &reports.signatures[0];
        assert_eq!(verdict.report.indication(), Indication::TotalPassed);
        assert_eq!(verdict.report.sub_indication(), None);
        assert_eq!(verdict.format, "PAdES-BASELINE-B");
        assert!(report.is_file());
    });
}
