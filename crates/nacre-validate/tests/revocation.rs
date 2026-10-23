#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

//! Revocation judged at the best-signature-time, on PDFs signed at test time under a
//! fictitious PKI: signature stamped 2026-10-22T08:00Z, control date 2026-10-23T00:00Z.

mod support;

use std::time::SystemTime;

use der::{DateTime, Encode};
use nacre_core::{Indication, RevocationData, RevocationSource, SubIndication};
use nacre_pades::Level;
use nacre_validate::{
    Defect, RevocationDefect, SignatureValidation, TrustAnchors, validate_with_revocation,
};
use p256::ecdsa::SigningKey;
use support::forge::{
    ChainSigner, ForgedTsa, Role, crl, instant, issue, key, signed, time, with_dss,
};
use x509_cert::Certificate;
use x509_cert::time::Time;

struct Pki {
    root: Certificate,
    root_key: SigningKey,
    intermediate: Certificate,
    intermediate_key: SigningKey,
    signer: Certificate,
    signer_key: SigningKey,
    tsa: Certificate,
    tsa_key: SigningKey,
}

impl Pki {
    fn new() -> Self {
        let root_key = key(&[0x41; 32]);
        let intermediate_key = key(&[0x42; 32]);
        let signer_key = key(&[0x43; 32]);
        let tsa_key = key(&[0x44; 32]);
        let root = issue(
            Role::Ca,
            "CN=Nacre revocation root,O=Nacre tests,C=FR",
            1,
            &root_key,
            None,
            &root_key,
        );
        let intermediate = issue(
            Role::Ca,
            "CN=Nacre revocation intermediate,O=Nacre tests,C=FR",
            2,
            &intermediate_key,
            Some(&root),
            &root_key,
        );
        let signer = issue(
            Role::Signer,
            "CN=Nacre revocation signer,O=Nacre tests,C=FR",
            3,
            &signer_key,
            Some(&intermediate),
            &intermediate_key,
        );
        let tsa = issue(
            Role::Tsa,
            "CN=Nacre revocation TSA,O=Nacre tests,C=FR",
            4,
            &tsa_key,
            Some(&intermediate),
            &intermediate_key,
        );
        Self {
            root,
            root_key,
            intermediate,
            intermediate_key,
            signer,
            signer_key,
            tsa,
            tsa_key,
        }
    }

    fn signer(&self) -> ChainSigner {
        ChainSigner {
            key: self.signer_key.clone(),
            chain: vec![der(&self.signer), der(&self.intermediate)],
        }
    }

    fn tsa(&self, imprint: Option<Vec<u8>>) -> ForgedTsa {
        ForgedTsa {
            key: self.tsa_key.clone(),
            certificates: vec![der(&self.tsa)],
            gen_time: DateTime::new(2026, 10, 22, 8, 0, 0).unwrap(),
            imprint,
        }
    }

    /// A B-B signature.
    fn basic(&self) -> Vec<u8> {
        signed(&self.signer(), Level::B)
    }

    /// A B-T signature stamped 08:00 by the TSA.
    fn stamped(&self) -> Vec<u8> {
        self.stamped_over(None)
    }

    fn stamped_over(&self, imprint: Option<Vec<u8>>) -> Vec<u8> {
        signed(
            &self.signer(),
            Level::T {
                tsa: &self.tsa(imprint),
            },
        )
    }

    /// The intermediate's CRL of 2026-10-22T10:00Z listing `revoked`.
    fn intermediate_crl(&self, revoked: &[(&Certificate, Time)]) -> Vec<u8> {
        crl(
            &self.intermediate,
            &self.intermediate_key,
            time(2026, 10, 22, 10, 0, 0),
            time(2026, 11, 22, 0, 0, 0),
            revoked,
        )
    }

    /// The root's CRL of 2026-10-22T10:00Z listing `revoked`.
    fn root_crl(&self, revoked: &[(&Certificate, Time)]) -> Vec<u8> {
        crl(
            &self.root,
            &self.root_key,
            time(2026, 10, 22, 10, 0, 0),
            time(2026, 11, 22, 0, 0, 0),
            revoked,
        )
    }

    /// The single signature of `pdf`, judged on 2026-10-23T00:00Z with the root as anchor.
    fn judge(&self, pdf: &[u8], source: Option<&dyn RevocationSource>) -> SignatureValidation {
        let root = der(&self.root);
        let anchors = TrustAnchors::from_certificates([root.as_slice()]).unwrap();
        let mut results =
            validate_with_revocation(pdf, &anchors, instant(2026, 10, 23, 0, 0, 0), source)
                .unwrap();
        assert_eq!(results.len(), 1);
        results.remove(0)
    }
}

fn der(certificate: &Certificate) -> Vec<u8> {
    certificate.to_der().unwrap()
}

fn stamp_time() -> SystemTime {
    instant(2026, 10, 22, 8, 0, 0)
}

fn passed(result: &SignatureValidation) {
    assert!(result.defect.is_none(), "{:?}", result.defect);
    assert_eq!(result.report.indication(), Indication::TotalPassed);
    assert_eq!(result.report.sub_indication(), None);
    assert_eq!(result.report.level(), None);
    assert_eq!(result.chain.as_ref().unwrap().certificates.len(), 3);
}

/// The revocation defect of `result`, checked to give `INDETERMINATE` / `sub` with the
/// path kept.
fn refused(result: &SignatureValidation, sub: SubIndication) -> RevocationDefect {
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(result.report.sub_indication(), Some(sub));
    assert!(result.digest_verified && result.signature_verified);
    assert_eq!(result.chain.as_ref().unwrap().certificates.len(), 3);
    let Some(Defect::Revocation(defect)) = &result.defect else {
        panic!("{:?}", result.defect);
    };
    defect.clone()
}

/// R1, AC1: revoked after the timestamp, the revocation does not count.
#[test]
fn revoked_after_the_timestamp_passes() {
    let pki = Pki::new();
    let pdf = with_dss(
        &pki.stamped(),
        &[],
        &[
            pki.intermediate_crl(&[(&pki.signer, time(2026, 10, 22, 9, 0, 0))]),
            pki.root_crl(&[]),
        ],
    );

    let result = pki.judge(&pdf, None);

    passed(&result);
    assert_eq!(result.best_signature_time, Some(stamp_time()));
}

/// R2, AC1: revoked before the timestamp.
#[test]
fn revoked_before_the_timestamp_is_revoked_no_poe() {
    let pki = Pki::new();
    let revoked = time(2026, 10, 22, 7, 0, 0);
    let pdf = with_dss(
        &pki.stamped(),
        &[],
        &[
            pki.intermediate_crl(&[(&pki.signer, revoked)]),
            pki.root_crl(&[]),
        ],
    );

    let result = pki.judge(&pdf, None);

    assert_eq!(
        refused(&result, SubIndication::RevokedNoPoe),
        RevocationDefect::Revoked {
            depth: 0,
            date: revoked.to_system_time()
        }
    );
    assert_eq!(result.best_signature_time, Some(stamp_time()));
}

/// R3, AC2: with no timestamp the control date decides.
#[test]
fn basic_signature_revoked_before_the_control_date() {
    let pki = Pki::new();
    let pdf = with_dss(
        &pki.basic(),
        &[],
        &[
            pki.intermediate_crl(&[(&pki.signer, time(2026, 10, 22, 9, 0, 0))]),
            pki.root_crl(&[]),
        ],
    );

    let result = pki.judge(&pdf, None);

    let defect = refused(&result, SubIndication::RevokedNoPoe);
    assert!(matches!(defect, RevocationDefect::Revoked { depth: 0, .. }));
    assert_eq!(result.best_signature_time, None);
}

/// R4: a revoked intermediate is a CA's revocation.
#[test]
fn revoked_intermediate_is_revoked_ca_no_poe() {
    let pki = Pki::new();
    let pdf = with_dss(
        &pki.basic(),
        &[],
        &[
            pki.intermediate_crl(&[]),
            pki.root_crl(&[(&pki.intermediate, time(2026, 10, 22, 9, 0, 0))]),
        ],
    );

    let defect = refused(&pki.judge(&pdf, None), SubIndication::RevokedCaNoPoe);

    assert!(matches!(defect, RevocationDefect::Revoked { depth: 1, .. }));
}

/// R5, AC3: no data and no source.
#[test]
fn no_revocation_data_is_a_general_failure() {
    let pki = Pki::new();

    let defect = refused(
        &pki.judge(&pki.basic(), None),
        SubIndication::CertificateChainGeneralFailure,
    );

    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

/// Answers each certificate with the CRL of its issuer, or fails.
struct Stub {
    intermediate: Vec<u8>,
    intermediate_crl: Vec<u8>,
    root_crl: Vec<u8>,
    failing: bool,
}

impl RevocationSource for Stub {
    fn revocation(
        &self,
        _certificate: &[u8],
        issuer: &[u8],
    ) -> Result<RevocationData, nacre_core::Error> {
        if self.failing {
            return Err(nacre_core::Error::revocation("unreachable"));
        }
        Ok(RevocationData::Crl(if issuer == self.intermediate {
            self.intermediate_crl.clone()
        } else {
            self.root_crl.clone()
        }))
    }
}

/// R6, AC3: the source fills in what the document lacks; its failure adds nothing.
#[test]
fn source_answers_what_the_document_lacks() {
    let pki = Pki::new();
    let pdf = pki.basic();
    let mut stub = Stub {
        intermediate: der(&pki.intermediate),
        intermediate_crl: pki.intermediate_crl(&[]),
        root_crl: pki.root_crl(&[]),
        failing: false,
    };

    passed(&pki.judge(&pdf, Some(&stub)));

    stub.failing = true;
    let defect = refused(
        &pki.judge(&pdf, Some(&stub)),
        SubIndication::CertificateChainGeneralFailure,
    );
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

/// R7, AC4: a TSA revoked before the control date gives no proof of time.
#[test]
fn revoked_tsa_gives_no_poe() {
    let pki = Pki::new();
    let pdf = with_dss(
        &pki.stamped(),
        &[],
        &[
            pki.intermediate_crl(&[
                (&pki.signer, time(2026, 10, 22, 9, 0, 0)),
                (&pki.tsa, time(2026, 10, 22, 9, 30, 0)),
            ]),
            pki.root_crl(&[]),
        ],
    );

    let result = pki.judge(&pdf, None);

    let defect = refused(&result, SubIndication::RevokedNoPoe);
    assert!(matches!(defect, RevocationDefect::Revoked { depth: 0, .. }));
    assert_eq!(result.best_signature_time, None);
}

/// R8: a CRL that does not verify is never read as "not revoked".
#[test]
fn crl_signed_by_another_key_is_ignored() {
    let pki = Pki::new();
    let forged = crl(
        &pki.intermediate,
        &key(&[0x45; 32]),
        time(2026, 10, 22, 10, 0, 0),
        time(2026, 11, 22, 0, 0, 0),
        &[],
    );
    let pdf = with_dss(&pki.basic(), &[], &[forged, pki.root_crl(&[])]);

    let defect = refused(
        &pki.judge(&pdf, None),
        SubIndication::CertificateChainGeneralFailure,
    );

    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

/// R9: a passed `nextUpdate` is not judged, as DSS ignores it. With no proof of existence
/// the CRL must still be issued within a day of the control date, as this one is (14 h).
#[test]
fn expired_crl_still_counts() {
    let pki = Pki::new();
    let stale = crl(
        &pki.intermediate,
        &pki.intermediate_key,
        time(2026, 10, 22, 10, 0, 0),
        time(2026, 10, 22, 12, 0, 0),
        &[],
    );
    let pdf = with_dss(&pki.basic(), &[], &[stale, pki.root_crl(&[])]);

    passed(&pki.judge(&pdf, None));
}

/// R10: the latest data wins, whatever the array order.
#[test]
fn latest_crl_wins() {
    let pki = Pki::new();
    let older = crl(
        &pki.intermediate,
        &pki.intermediate_key,
        time(2026, 10, 22, 8, 30, 0),
        time(2026, 11, 22, 0, 0, 0),
        &[],
    );
    let newer = pki.intermediate_crl(&[(&pki.signer, time(2026, 10, 22, 9, 0, 0))]);

    for crls in [
        [newer.clone(), older.clone(), pki.root_crl(&[])],
        [older, newer, pki.root_crl(&[])],
    ] {
        let pdf = with_dss(&pki.basic(), &[], &crls);

        let defect = refused(&pki.judge(&pdf, None), SubIndication::RevokedNoPoe);

        assert!(matches!(defect, RevocationDefect::Revoked { depth: 0, .. }));
    }
}

/// R11: data issued before the certificate existed says nothing of it.
#[test]
fn crl_before_not_before_is_ignored() {
    let pki = Pki::new();
    let early = crl(
        &pki.intermediate,
        &pki.intermediate_key,
        time(2025, 12, 1, 0, 0, 0),
        time(2036, 1, 1, 0, 0, 0),
        &[],
    );
    let pdf = with_dss(&pki.basic(), &[], &[early, pki.root_crl(&[])]);

    let defect = refused(
        &pki.judge(&pdf, None),
        SubIndication::CertificateChainGeneralFailure,
    );

    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

/// R12: a token over another imprint proves no time.
#[test]
fn token_over_another_imprint_gives_no_poe() {
    let pki = Pki::new();
    let pdf = with_dss(
        &pki.stamped_over(Some(vec![0x5a; 32])),
        &[],
        &[
            pki.intermediate_crl(&[(&pki.signer, time(2026, 10, 22, 9, 0, 0))]),
            pki.root_crl(&[]),
        ],
    );

    let result = pki.judge(&pdf, None);

    let defect = refused(&result, SubIndication::RevokedNoPoe);
    assert!(matches!(defect, RevocationDefect::Revoked { depth: 0, .. }));
    assert_eq!(result.best_signature_time, None);
}

/// R13: with no proof of existence, a CRL issued before the signer's revocation, and more
/// than a day before the control date, says nothing; a timestamp makes it count again.
#[test]
fn old_crl_does_not_pass_a_signature_without_poe() {
    let pki = Pki::new();
    let before_revocation = crl(
        &pki.intermediate,
        &pki.intermediate_key,
        time(2026, 10, 21, 23, 0, 0),
        time(2026, 11, 22, 0, 0, 0),
        &[],
    );
    let crls = [before_revocation, pki.root_crl(&[])];

    let defect = refused(
        &pki.judge(&with_dss(&pki.basic(), &[], &crls), None),
        SubIndication::CertificateChainGeneralFailure,
    );
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });

    let result = pki.judge(&with_dss(&pki.stamped(), &[], &crls), None);
    passed(&result);
    assert_eq!(result.best_signature_time, Some(stamp_time()));
}
