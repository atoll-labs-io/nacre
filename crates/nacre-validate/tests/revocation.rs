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
use nacre_core::{Indication, RevocationSource, SignatureForm, SignatureProfile, SubIndication};
use nacre_pades::Level;
use nacre_revocation::CrlReason;
use nacre_validate::{
    ChainDefect, Defect, Error, RevocationDefect, SignatureValidation, TrustAnchors,
    ValidationPolicy, validate_with_policy, validate_with_revocation,
};
use p256::ecdsa::SigningKey;
use support::Stub;
use support::forge::{
    ChainSigner, Extensions, ForgedTsa, OcspExtension, OcspPlace, Role, Signature, UNSIGNED, crl,
    crl_with_expired_certs_on_crl, crl_with_reasons, custom_signed, document_timestamp, instant,
    issue, issue_valid, issue_with, key, ocsp, signed, signed_with, time, with_dss, with_dss_ocsps,
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

    /// The single signature of `pdf`, judged on `at` under `policy`, with no source.
    fn judge_under(
        &self,
        pdf: &[u8],
        at: SystemTime,
        policy: &ValidationPolicy,
    ) -> SignatureValidation {
        let root = der(&self.root);
        let anchors = TrustAnchors::from_certificates([root.as_slice()]).unwrap();
        let mut results = validate_with_policy(pdf, &anchors, at, None, policy).unwrap();
        assert_eq!(results.len(), 1);
        results.remove(0)
    }

    /// A B-B signature by a signer of serial 5, valid from `not_before` to `not_after`.
    fn basic_valid(&self, not_before: Time, not_after: Time) -> (Certificate, Vec<u8>) {
        let signer = issue_valid(
            Role::Signer,
            "CN=Nacre policy signer,O=Nacre tests,C=FR",
            5,
            &self.signer_key,
            Some(&self.intermediate),
            &self.intermediate_key,
            not_before,
            not_after,
        );
        let chain = ChainSigner {
            key: self.signer_key.clone(),
            chain: vec![der(&signer), der(&self.intermediate)],
        };
        let pdf = signed(&chain, Level::B);
        (signer, pdf)
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

/// R13: a CRL issued before the signer's revocation, and more than a day before the
/// control date, says nothing; a timestamp does not make it count again, for it clears no
/// timestamp authority either under `strict()` (s42).
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
    let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
    assert_eq!(result.best_signature_time, None);
}

/// s42 AC1, AC2, AC3: a "not revoked" more than a day old, said of the intermediate, does
/// not clear the timestamp authority under `strict()`, for a signature timestamp and a
/// document timestamp alike; `dss()` and the switch off keep DSS's verdict.
#[test]
fn stale_crl_does_not_clear_a_timestamp_authority() {
    let pki = Pki::new();
    let stale = crl(
        &pki.intermediate,
        &pki.intermediate_key,
        time(2026, 10, 21, 23, 0, 0),
        time(2026, 11, 22, 0, 0, 0),
        &[],
    );
    let crls = [stale, pki.root_crl(&[])];
    let files = [
        with_dss(&pki.stamped(), &[], &crls),
        document_timestamp(&with_dss(&pki.basic(), &[], &crls), &pki.tsa(None)),
    ];

    for file in &files {
        let strict = pki.judge_under(file, control_date(), &ValidationPolicy::strict());
        let defect = refused(&strict, SubIndication::CertificateChainGeneralFailure);
        assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
        assert_eq!(strict.best_signature_time, None);

        for policy in [
            ValidationPolicy::dss(),
            strict_without(|p| p.require_fresh_revocation = false),
        ] {
            let result = pki.judge_under(file, control_date(), &policy);
            passed(&result);
            assert_eq!(result.best_signature_time, Some(stamp_time()));
        }
    }
}

fn control_date() -> SystemTime {
    instant(2026, 10, 23, 0, 0, 0)
}

fn strict_without(off: impl FnOnce(&mut ValidationPolicy)) -> ValidationPolicy {
    let mut policy = ValidationPolicy::strict();
    off(&mut policy);
    policy
}

/// The intermediate's CRL of 2026-10-22T08:00Z revoking nothing, issued before the
/// `notAfter` of the signer `expiring` gives.
fn crl_before_expiry(pki: &Pki) -> Vec<u8> {
    crl(
        &pki.intermediate,
        &pki.intermediate_key,
        time(2026, 10, 22, 8, 0, 0),
        time(2026, 11, 22, 0, 0, 0),
        &[],
    )
}

/// A signer valid until 2026-10-22T09:00Z, before the control date.
fn expiring() -> (Time, Time) {
    (time(2026, 1, 1, 0, 0, 0), time(2026, 10, 22, 9, 0, 0))
}

/// (g) Validity after revocation: a signer expired before the control date with a "not
/// revoked" CRL issued before its `notAfter` is out of bounds, not revoked, its path kept.
#[test]
fn expired_not_revoked_is_out_of_bounds_not_revoked() {
    let pki = Pki::new();
    let (not_before, not_after) = expiring();
    let (_, signature) = pki.basic_valid(not_before, not_after);
    let pdf = with_dss(
        &signature,
        &[],
        &[crl_before_expiry(&pki), pki.root_crl(&[])],
    );

    let strict = pki.judge_under(&pdf, control_date(), &ValidationPolicy::strict());
    assert_eq!(
        strict.report.sub_indication(),
        Some(SubIndication::OutOfBoundsNoPoe)
    );

    let policy = strict_without(|p| p.judge_validity_before_revocation = false);
    let result = pki.judge_under(&pdf, control_date(), &policy);
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::OutOfBoundsNotRevoked)
    );
    assert!(
        matches!(
            result.defect,
            Some(Defect::OutOfRangeNotRevoked(ChainDefect::Expired {
                depth: 0
            }))
        ),
        "{:?}",
        result.defect
    );
    assert_eq!(result.chain.as_ref().unwrap().certificates.len(), 3);
}

/// (h) Freshness off: the stale CRL of R13 passes a signature with no proof of existence.
#[test]
fn old_crl_passes_without_the_freshness_switch() {
    let pki = Pki::new();
    let before_revocation = crl(
        &pki.intermediate,
        &pki.intermediate_key,
        time(2026, 10, 21, 23, 0, 0),
        time(2026, 11, 22, 0, 0, 0),
        &[],
    );
    let pdf = with_dss(&pki.basic(), &[], &[before_revocation, pki.root_crl(&[])]);

    let policy = strict_without(|p| p.require_fresh_revocation = false);
    passed(&pki.judge_under(&pdf, control_date(), &policy));
}

/// (i) AC4: under `strict()`, an old proof of revocation still counts, unless it is a hold
/// or its revocation is dated after the judged time.
#[test]
fn old_revocation_counts_unless_on_hold() {
    let pki = Pki::new();
    let judged = |revoked, reason| {
        let old = crl_with_reasons(
            &pki.intermediate,
            &pki.intermediate_key,
            time(2026, 10, 21, 23, 0, 0),
            time(2026, 11, 22, 0, 0, 0),
            &[(&pki.signer, revoked, Some(reason))],
        );
        let pdf = with_dss(&pki.basic(), &[], &[old, pki.root_crl(&[])]);
        pki.judge_under(&pdf, control_date(), &ValidationPolicy::strict())
    };
    let before = time(2026, 10, 21, 22, 0, 0);

    let compromised = judged(before, CrlReason::KeyCompromise);
    let defect = refused(&compromised, SubIndication::RevokedNoPoe);
    assert!(matches!(defect, RevocationDefect::Revoked { depth: 0, .. }));

    let held = judged(before, CrlReason::CertificateHold);
    let defect = refused(&held, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });

    let later = judged(time(2026, 10, 23, 6, 0, 0), CrlReason::KeyCompromise);
    let defect = refused(&later, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

/// (j) AC3: a `/M` before the signer's `notBefore` fails under both presets.
#[test]
fn claimed_time_before_not_before_is_a_constraints_failure() {
    let pki = Pki::new();
    let (_, signature) = pki.basic_valid(time(2026, 10, 23, 0, 0, 0), time(2036, 1, 1, 0, 0, 0));
    let issued = time(2026, 10, 23, 12, 0, 0);
    let next = time(2026, 11, 23, 0, 0, 0);
    let pdf = with_dss(
        &signature,
        &[],
        &[
            crl(&pki.intermediate, &pki.intermediate_key, issued, next, &[]),
            crl(&pki.root, &pki.root_key, issued, next, &[]),
        ],
    );

    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        let result = pki.judge_under(&pdf, instant(2026, 10, 24, 0, 0, 0), &policy);
        assert_eq!(result.report.indication(), Indication::Indeterminate);
        assert_eq!(
            result.report.sub_indication(),
            Some(SubIndication::SigConstraintsFailure)
        );
        assert!(
            matches!(result.defect, Some(Defect::ClaimedTimeBeforeCertificate)),
            "{:?}",
            result.defect
        );
        assert_eq!(result.chain.as_ref().unwrap().certificates.len(), 3);
    }
}

/// AC3: a signature-timestamp authority repeating `keyUsage` proves no time under
/// `strict()`, the signature judged at the control date; with the switch off, the
/// validation fails as DSS does.
#[test]
fn malformed_timestamp_certificate() {
    let pki = Pki::new();
    let tsa = issue_with(
        Role::Tsa,
        "CN=Nacre malformed TSA,O=Nacre tests,C=FR",
        6,
        &pki.tsa_key,
        Some(&pki.intermediate),
        &pki.intermediate_key,
        (time(2026, 1, 1, 0, 0, 0), time(2036, 1, 1, 0, 0, 0)),
        Extensions::RepeatedKeyUsage,
    );
    let authority = ForgedTsa {
        certificates: vec![der(&tsa)],
        ..pki.tsa(None)
    };
    let pdf = with_dss(
        &signed(&pki.signer(), Level::T { tsa: &authority }),
        &[],
        &[pki.intermediate_crl(&[]), pki.root_crl(&[])],
    );

    let strict = pki.judge_under(&pdf, control_date(), &ValidationPolicy::strict());
    passed(&strict);
    assert_eq!(strict.best_signature_time, None);

    let root = der(&pki.root);
    let anchors = TrustAnchors::from_certificates([root.as_slice()]).unwrap();
    let policy = strict_without(|p| p.judge_malformed_extensions = false);
    let error = validate_with_policy(&pdf, &anchors, control_date(), None, &policy).unwrap_err();
    assert!(matches!(error, Error::MalformedCertificate), "{error:?}");
}

/// `result` is `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE` for a claimed-time defect, its
/// path kept.
fn constraints_failure(result: &SignatureValidation) -> &Defect {
    assert_eq!(result.report.indication(), Indication::Indeterminate);
    assert_eq!(
        result.report.sub_indication(),
        Some(SubIndication::SigConstraintsFailure)
    );
    assert_eq!(result.chain.as_ref().unwrap().certificates.len(), 3);
    result.defect.as_ref().unwrap()
}

/// AC1: no `/M`, or one no PDF date reads, fails under both presets, as DSS does.
#[test]
fn missing_claimed_time_is_a_constraints_failure() {
    let pki = Pki::new();
    for claimed in [None, Some(&b"garbage"[..])] {
        let pdf = with_dss(
            &custom_signed(&pki.signer(), b"ETSI.CAdES.detached", claimed),
            &[],
            &[pki.intermediate_crl(&[]), pki.root_crl(&[])],
        );
        for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
            let result = pki.judge_under(&pdf, control_date(), &policy);
            let defect = constraints_failure(&result);
            assert!(
                matches!(defect, Defect::ClaimedTimeMissing),
                "{claimed:?}: {defect:?}"
            );
        }
    }
}

/// AC1: a `/M` after the `notAfter` of a signer valid at the control date fails under both
/// presets, as DSS does.
#[test]
fn claimed_time_after_not_after_is_a_constraints_failure() {
    let pki = Pki::new();
    let signer = issue_valid(
        Role::Signer,
        "CN=Nacre short-lived signer,O=Nacre tests,C=FR",
        7,
        &pki.signer_key,
        Some(&pki.intermediate),
        &pki.intermediate_key,
        time(2026, 1, 1, 0, 0, 0),
        time(2027, 1, 1, 0, 0, 0),
    );
    let chain = ChainSigner {
        key: pki.signer_key.clone(),
        chain: vec![der(&signer), der(&pki.intermediate)],
    };
    let pdf = with_dss(
        &custom_signed(&chain, b"ETSI.CAdES.detached", Some(b"D:20270601000000Z")),
        &[],
        &[pki.intermediate_crl(&[]), pki.root_crl(&[])],
    );

    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        let result = pki.judge_under(&pdf, control_date(), &policy);
        let defect = constraints_failure(&result);
        assert!(
            matches!(defect, Defect::ClaimedTimeAfterCertificate),
            "{defect:?}"
        );
    }
}

/// AC2: a "not revoked" issued after the signer's `notAfter` does not count, under every
/// policy, as DSS does.
#[test]
fn data_issued_after_not_after_does_not_count() {
    let pki = Pki::new();
    let (not_before, not_after) = expiring();
    let late = [pki.intermediate_crl(&[]), pki.root_crl(&[])];

    // (a) A B, its signer expired, judged before its validity.
    let (_, basic) = pki.basic_valid(not_before, not_after);
    let policy = strict_without(|p| p.judge_validity_before_revocation = false);
    let result = pki.judge_under(&with_dss(&basic, &[], &late), control_date(), &policy);
    let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });

    // (b) A B-T whose signer was valid at the stamp, under `strict()`.
    let signer = issue_valid(
        Role::Signer,
        "CN=Nacre policy signer,O=Nacre tests,C=FR",
        5,
        &pki.signer_key,
        Some(&pki.intermediate),
        &pki.intermediate_key,
        not_before,
        not_after,
    );
    let chain = ChainSigner {
        key: pki.signer_key.clone(),
        chain: vec![der(&signer), der(&pki.intermediate)],
    };
    let stamped = signed(
        &chain,
        Level::T {
            tsa: &pki.tsa(None),
        },
    );
    let result = pki.judge_under(
        &with_dss(&stamped, &[], &late),
        control_date(),
        &ValidationPolicy::strict(),
    );
    assert_eq!(result.best_signature_time, Some(stamp_time()));
    let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

/// s1, AC3: a B-T whose signer expired at 09:00, an hour after its stamp, with the
/// intermediate's CRL of 10:00 in `/DSS`: its `expiredCertsOnCRL` decides with the switch
/// off, never under `strict()`.
#[test]
fn expired_certs_on_crl_switch() {
    let pki = Pki::new();
    let (not_before, not_after) = expiring();
    let signer = issue_valid(
        Role::Signer,
        "CN=Nacre policy signer,O=Nacre tests,C=FR",
        5,
        &pki.signer_key,
        Some(&pki.intermediate),
        &pki.intermediate_key,
        not_before,
        not_after,
    );
    let chain = ChainSigner {
        key: pki.signer_key.clone(),
        chain: vec![der(&signer), der(&pki.intermediate)],
    };
    let stamped = signed(
        &chain,
        Level::T {
            tsa: &pki.tsa(None),
        },
    );
    let with_ecoc = |from: Time| {
        with_dss(
            &stamped,
            &[],
            &[
                crl_with_expired_certs_on_crl(
                    &pki.intermediate,
                    &pki.intermediate_key,
                    time(2026, 10, 22, 10, 0, 0),
                    time(2026, 11, 22, 0, 0, 0),
                    from,
                ),
                pki.root_crl(&[]),
            ],
        )
    };
    let early = with_ecoc(time(2026, 1, 1, 0, 0, 0));
    let off = strict_without(|p| p.ignore_expired_certs_on_crl = false);

    let result = pki.judge_under(&early, control_date(), &ValidationPolicy::strict());
    let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });

    let result = pki.judge_under(&early, control_date(), &off);
    passed(&result);
    assert_eq!(result.best_signature_time, Some(stamp_time()));

    let late = with_ecoc(time(2026, 10, 22, 9, 30, 0));
    let result = pki.judge_under(&late, control_date(), &off);
    let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

/// p06, p06b and p06d, AC4: a CA under the root valid until 2026-10-22T12:00, judged on
/// 2026-10-23, its signer's CRL and the root's both of 10:00.
#[test]
fn issuer_out_of_validity_is_revocation_out_of_bounds() {
    let pki = Pki::new();
    let ca_key = key(&[0x45; 32]);
    let ca = issue_valid(
        Role::Ca,
        "CN=Nacre short-lived CA,O=Nacre tests,C=FR",
        6,
        &ca_key,
        Some(&pki.root),
        &pki.root_key,
        time(2026, 1, 1, 0, 0, 0),
        time(2026, 10, 22, 12, 0, 0),
    );
    let signer = issue(
        Role::Signer,
        "CN=Nacre short-lived CA signer,O=Nacre tests,C=FR",
        7,
        &pki.signer_key,
        Some(&ca),
        &ca_key,
    );
    let chain = ChainSigner {
        key: pki.signer_key.clone(),
        chain: vec![der(&signer), der(&ca)],
    };
    let tsa = ForgedTsa {
        certificates: vec![der(&pki.tsa), der(&pki.intermediate)],
        ..pki.tsa(None)
    };
    let ten = time(2026, 10, 22, 10, 0, 0);
    let month = time(2026, 11, 22, 0, 0, 0);
    let crls = |root_issued: Time| {
        vec![
            crl(&ca, &ca_key, ten, month, &[]),
            crl(&pki.root, &pki.root_key, root_issued, month, &[]),
            pki.intermediate_crl(&[]),
        ]
    };
    let stamped = signed(&chain, Level::T { tsa: &tsa });
    let basic = signed(&chain, Level::B);
    let out_of_bounds = RevocationDefect::IssuerOutOfBounds { depth: 0 };

    let pdf = with_dss(&stamped, &[], &crls(ten));
    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        let result = pki.judge_under(&pdf, control_date(), &policy);
        assert_eq!(result.best_signature_time, Some(stamp_time()));
        let defect = refused(&result, SubIndication::RevocationOutOfBoundsNoPoe);
        assert_eq!(defect, out_of_bounds);
    }

    let pdf = with_dss(&basic, &[], &crls(ten));
    let result = pki.judge_under(&pdf, control_date(), &ValidationPolicy::dss());
    let defect = refused(&result, SubIndication::RevocationOutOfBoundsNoPoe);
    assert_eq!(defect, out_of_bounds);

    let pdf = with_dss(&stamped, &[], &crls(time(2026, 10, 22, 13, 0, 0)));
    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        let result = pki.judge_under(&pdf, control_date(), &policy);
        let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
        assert_eq!(defect, RevocationDefect::Missing { depth: 1 });
    }
}

/// s2 to s4, AC5: the signer under an intermediate without `subjectKeyIdentifier`, same
/// name and key as the usual one, its CRLs in `/DSS`.
#[test]
fn ca_without_key_identifier_is_a_general_failure() {
    let pki = Pki::new();
    let intermediate = issue_with(
        Role::Ca,
        "CN=Nacre revocation intermediate,O=Nacre tests,C=FR",
        8,
        &pki.intermediate_key,
        Some(&pki.root),
        &pki.root_key,
        (time(2026, 1, 1, 0, 0, 0), time(2036, 1, 1, 0, 0, 0)),
        Extensions::WithoutKeyIdentifier,
    );
    let chain = ChainSigner {
        key: pki.signer_key.clone(),
        chain: vec![der(&pki.signer), der(&intermediate)],
    };
    let crls =
        |revoked: &[(&Certificate, Time)]| vec![pki.intermediate_crl(revoked), pki.root_crl(&[])];
    let missing = |result: &SignatureValidation| {
        assert_eq!(result.report.indication(), Indication::Indeterminate);
        assert_eq!(
            result.report.sub_indication(),
            Some(SubIndication::CertificateChainGeneralFailure)
        );
        assert_eq!(result.chain.as_ref().unwrap().certificates.len(), 3);
        assert!(
            matches!(
                result.defect,
                Some(Defect::CaKeyIdentifierMissing { depth: 1 })
            ),
            "{:?}",
            result.defect
        );
    };
    let stamped = signed(
        &chain,
        Level::T {
            tsa: &pki.tsa(None),
        },
    );
    let unclaimed = custom_signed(&chain, b"ETSI.CAdES.detached", None);
    let revoked = with_dss(
        &stamped,
        &[],
        &crls(&[(&pki.signer, time(2026, 10, 22, 7, 0, 0))]),
    );
    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        missing(&pki.judge_under(
            &with_dss(&stamped, &[], &crls(&[])),
            control_date(),
            &policy,
        ));
        missing(&pki.judge_under(
            &with_dss(&unclaimed, &[], &crls(&[])),
            control_date(),
            &policy,
        ));
        let result = pki.judge_under(&revoked, control_date(), &policy);
        refused(&result, SubIndication::RevokedNoPoe);
    }
}

/// k1, s46 AC1: a B-T whose TSA sits under a root-issued CA without
/// `subjectKeyIdentifier`, the signer revoked at 09:00, an hour after the stamp. The token
/// proves no time under either preset, so the revocation counts.
#[test]
fn tsa_ca_without_key_identifier_proves_no_time() {
    let pki = Pki::new();
    let ca_key = key(&[0x46; 32]);
    let tsa_key = key(&[0x47; 32]);
    let stamped = |extensions: Extensions| {
        let ca = issue_with(
            Role::Ca,
            "CN=Nacre TSA CA,O=Nacre tests,C=FR",
            9,
            &ca_key,
            Some(&pki.root),
            &pki.root_key,
            (time(2026, 1, 1, 0, 0, 0), time(2036, 1, 1, 0, 0, 0)),
            extensions,
        );
        let tsa = issue(
            Role::Tsa,
            "CN=Nacre TSA under its CA,O=Nacre tests,C=FR",
            10,
            &tsa_key,
            Some(&ca),
            &ca_key,
        );
        let authority = ForgedTsa {
            key: tsa_key.clone(),
            certificates: vec![der(&tsa), der(&ca)],
            ..pki.tsa(None)
        };
        let pdf = signed(&pki.signer(), Level::T { tsa: &authority });
        let ten = time(2026, 10, 22, 10, 0, 0);
        let month = time(2026, 11, 22, 0, 0, 0);
        with_dss(
            &pdf,
            &[],
            &[
                crl(&ca, &ca_key, ten, month, &[]),
                pki.root_crl(&[]),
                pki.intermediate_crl(&[(&pki.signer, time(2026, 10, 22, 9, 0, 0))]),
            ],
        )
    };

    let pdf = stamped(Extensions::WithoutKeyIdentifier);
    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        let result = pki.judge_under(&pdf, control_date(), &policy);
        assert_eq!(result.best_signature_time, None);
        refused(&result, SubIndication::RevokedNoPoe);
    }

    let result = pki.judge_under(
        &stamped(Extensions::Usual),
        control_date(),
        &ValidationPolicy::strict(),
    );
    passed(&result);
    assert_eq!(result.best_signature_time, Some(stamp_time()));
}

/// A CA under the root valid until 2026-10-22T12:00 with its key, and a B-T by a signer
/// it issued, stamped 08:00 by the TSA under the intermediate.
fn short_lived_ca(pki: &Pki) -> (Certificate, SigningKey, Certificate, Vec<u8>) {
    let ca_key = key(&[0x45; 32]);
    let ca = issue_valid(
        Role::Ca,
        "CN=Nacre short-lived CA,O=Nacre tests,C=FR",
        6,
        &ca_key,
        Some(&pki.root),
        &pki.root_key,
        time(2026, 1, 1, 0, 0, 0),
        time(2026, 10, 22, 12, 0, 0),
    );
    let signer = issue(
        Role::Signer,
        "CN=Nacre short-lived CA signer,O=Nacre tests,C=FR",
        7,
        &pki.signer_key,
        Some(&ca),
        &ca_key,
    );
    let chain = ChainSigner {
        key: pki.signer_key.clone(),
        chain: vec![der(&signer), der(&ca)],
    };
    let tsa = ForgedTsa {
        certificates: vec![der(&pki.tsa), der(&pki.intermediate)],
        ..pki.tsa(None)
    };
    let stamped = signed(&chain, Level::T { tsa: &tsa });
    (ca, ca_key, signer, stamped)
}

/// v3 and v5, s46 AC2: the short-lived CA's data on its signer says "revoked" at 09:00,
/// after the stamp (v3), or the root's data on the CA does while the CA's says "good"
/// (v5). Only v3 escapes the issuer rule, and only with the switch off.
#[test]
fn issuer_of_revoked_data_switch() {
    let pki = Pki::new();
    let (ca, ca_key, signer, stamped) = short_lived_ca(&pki);
    let ten = time(2026, 10, 22, 10, 0, 0);
    let month = time(2026, 11, 22, 0, 0, 0);
    let nine = time(2026, 10, 22, 9, 0, 0);
    let out_of_bounds = RevocationDefect::IssuerOutOfBounds { depth: 0 };
    let off = strict_without(|p| p.judge_issuer_of_revoked_data = false);

    let v3 = with_dss(
        &stamped,
        &[],
        &[
            crl(&ca, &ca_key, ten, month, &[(&signer, nine)]),
            pki.root_crl(&[]),
            pki.intermediate_crl(&[]),
        ],
    );
    let result = pki.judge_under(&v3, control_date(), &ValidationPolicy::strict());
    let defect = refused(&result, SubIndication::RevocationOutOfBoundsNoPoe);
    assert_eq!(defect, out_of_bounds);
    let result = pki.judge_under(&v3, control_date(), &off);
    passed(&result);
    assert_eq!(result.best_signature_time, Some(stamp_time()));

    let v5 = with_dss(
        &stamped,
        &[],
        &[
            crl(&ca, &ca_key, ten, month, &[]),
            pki.root_crl(&[(&ca, nine)]),
            pki.intermediate_crl(&[]),
        ],
    );
    let result = pki.judge_under(&v5, control_date(), &off);
    let defect = refused(&result, SubIndication::RevocationOutOfBoundsNoPoe);
    assert_eq!(defect, out_of_bounds);
}

/// e2 and e3, s46 AC3: a B-T whose `/DSS` holds the usual CRLs of 10:00 and a "good" OCSP
/// response on the signer produced at 11:00, which outranks them, signed by a delegate of
/// the intermediate valid at `producedAt`. Out of its validity at the control date, the
/// delegate refuses the path under both presets.
#[test]
fn delegated_responder_out_of_validity() {
    let pki = Pki::new();
    let delegate_key = key(&[0x48; 32]);
    let with_delegate = |not_after: Time| {
        let delegate = issue_with(
            Role::OcspResponder,
            "CN=Nacre OCSP delegate,O=Nacre tests,C=FR",
            11,
            &delegate_key,
            Some(&pki.intermediate),
            &pki.intermediate_key,
            (time(2026, 1, 1, 0, 0, 0), not_after),
            Extensions::Usual,
        );
        let response = ocsp(
            &pki.signer,
            &pki.intermediate,
            &delegate_key,
            &delegate,
            Some(&delegate),
            time(2026, 10, 22, 11, 0, 0),
            None,
            &[],
        );
        with_dss_ocsps(
            &pki.stamped(),
            &[],
            &[pki.intermediate_crl(&[]), pki.root_crl(&[])],
            &[response],
        )
    };

    let pdf = with_delegate(time(2026, 10, 22, 12, 0, 0));
    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        let result = pki.judge_under(&pdf, control_date(), &policy);
        assert_eq!(result.best_signature_time, Some(stamp_time()));
        let defect = refused(&result, SubIndication::RevocationOutOfBoundsNoPoe);
        assert_eq!(defect, RevocationDefect::IssuerOutOfBounds { depth: 0 });
    }

    let pdf = with_delegate(time(2036, 1, 1, 0, 0, 0));
    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        passed(&pki.judge_under(&pdf, control_date(), &policy));
    }
}

/// e4 and e5, s46 AC4: a B-T whose signer expired at 09:00, an hour after its stamp, with
/// an intermediate-signed "good" OCSP response of 10:00 in `/DSS`: its `archiveCutoff`
/// decides with the eleventh switch off, never under `strict()`.
#[test]
fn archive_cutoff_switch() {
    let pki = Pki::new();
    let (not_before, not_after) = expiring();
    let signer = issue_valid(
        Role::Signer,
        "CN=Nacre policy signer,O=Nacre tests,C=FR",
        5,
        &pki.signer_key,
        Some(&pki.intermediate),
        &pki.intermediate_key,
        not_before,
        not_after,
    );
    let chain = ChainSigner {
        key: pki.signer_key.clone(),
        chain: vec![der(&signer), der(&pki.intermediate)],
    };
    let stamped = signed(
        &chain,
        Level::T {
            tsa: &pki.tsa(None),
        },
    );
    let with_cutoff = |cutoff: Time| {
        let response = ocsp(
            &signer,
            &pki.intermediate,
            &pki.intermediate_key,
            &pki.intermediate,
            None,
            time(2026, 10, 22, 10, 0, 0),
            None,
            &[OcspExtension::archive_cutoff(
                cutoff,
                false,
                OcspPlace::Single,
            )],
        );
        with_dss_ocsps(
            &stamped,
            &[],
            &[pki.intermediate_crl(&[]), pki.root_crl(&[])],
            &[response],
        )
    };
    let early = with_cutoff(time(2026, 1, 1, 0, 0, 0));
    let off = strict_without(|p| p.ignore_expired_certs_on_crl = false);

    let result = pki.judge_under(&early, control_date(), &ValidationPolicy::strict());
    let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });

    let result = pki.judge_under(&early, control_date(), &off);
    passed(&result);
    assert_eq!(result.best_signature_time, Some(stamp_time()));

    let late = with_cutoff(time(2026, 10, 22, 9, 30, 0));
    let result = pki.judge_under(&late, control_date(), &off);
    let defect = refused(&result, SubIndication::CertificateChainGeneralFailure);
    assert_eq!(defect, RevocationDefect::Missing { depth: 0 });
}

fn level_of(result: &SignatureValidation) -> Option<SignatureProfile> {
    let level = result.report.level().unwrap();
    assert_eq!(level.form, SignatureForm::PAdES);
    Some(level.profile)
}

/// s18 (a): a B-T whose `/DSS` lacks the intermediate's CRL on the signer stays T; with it,
/// the signer's and the TSA's chains are covered: LT.
#[test]
fn dss_covering_every_chain_gives_lt() {
    let pki = Pki::new();
    let at = |crls: &[Vec<u8>]| {
        let result = pki.judge_under(
            &with_dss(&pki.stamped(), &[], crls),
            control_date(),
            &ValidationPolicy::strict(),
        );
        level_of(&result)
    };

    assert_eq!(at(&[pki.root_crl(&[])]), Some(SignatureProfile::BaselineT));
    assert_eq!(
        at(&[pki.intermediate_crl(&[]), pki.root_crl(&[])]),
        Some(SignatureProfile::BaselineLt)
    );
}

/// s18 (b): the same CRLs in the CMS, with no `/DSS`, leave the signature T.
#[test]
fn cms_revocation_data_does_not_give_lt() {
    let pki = Pki::new();
    let tsa = pki.tsa(None);
    let pdf = signed_with(
        UNSIGNED,
        &pki.signer(),
        &Signature {
            crls: vec![pki.intermediate_crl(&[]), pki.root_crl(&[])],
            tsa: Some(&tsa),
            ..Signature::default()
        },
    );

    let result = pki.judge_under(&pdf, control_date(), &ValidationPolicy::strict());

    passed(&result);
    assert_eq!(level_of(&result), Some(SignatureProfile::BaselineT));
}

/// s18 (c), r1 and r2: a B whose `/DSS` covers the signer's chain, then a document
/// timestamp by a TSA under another CA: T, since that TSA's chain is not covered; LTA once
/// the `/DSS` also holds that CA's CRL.
#[test]
fn document_timestamp_over_a_covering_dss_gives_lta() {
    let pki = Pki::new();
    let ca_key = key(&[0x4a; 32]);
    let ca = issue(
        Role::Ca,
        "CN=Nacre s18 document CA,O=Nacre tests,C=FR",
        20,
        &ca_key,
        Some(&pki.root),
        &pki.root_key,
    );
    let tsa = issue(
        Role::Tsa,
        "CN=Nacre s18 document TSA,O=Nacre tests,C=FR",
        21,
        &pki.tsa_key,
        Some(&ca),
        &ca_key,
    );
    let document_tsa = ForgedTsa {
        certificates: vec![der(&tsa), der(&ca)],
        gen_time: DateTime::new(2026, 10, 22, 12, 0, 0).unwrap(),
        ..pki.tsa(None)
    };
    let ca_crl = crl(
        &ca,
        &ca_key,
        time(2026, 10, 22, 10, 0, 0),
        time(2026, 11, 22, 0, 0, 0),
        &[],
    );
    let archived = |crls: &[Vec<u8>]| {
        let pdf = document_timestamp(&with_dss(&pki.basic(), &[], crls), &document_tsa);
        let result = pki.judge_under(&pdf, control_date(), &ValidationPolicy::dss());
        level_of(&result)
    };
    let signer_chain = [pki.intermediate_crl(&[]), pki.root_crl(&[])];

    assert_eq!(archived(&signer_chain), Some(SignatureProfile::BaselineT));
    assert_eq!(
        archived(&[signer_chain[0].clone(), signer_chain[1].clone(), ca_crl]),
        Some(SignatureProfile::BaselineLta)
    );
}

/// s18 AC3, n13 and k4: a B, then a document timestamp of 09:00 by the TSA, then a
/// `/DSS` whose CRL revokes the signer at 09:30. The timestamp proves the signature existed
/// before the revocation; over another imprint, it proves nothing.
#[test]
fn document_timestamp_is_a_proof_of_existence() {
    let pki = Pki::new();
    let nine = DateTime::new(2026, 10, 22, 9, 0, 0).unwrap();
    let archived = |imprint: Option<Vec<u8>>| {
        let tsa = ForgedTsa {
            gen_time: nine,
            ..pki.tsa(imprint)
        };
        let pdf = with_dss(
            &document_timestamp(&pki.basic(), &tsa),
            &[],
            &[
                pki.intermediate_crl(&[(&pki.signer, time(2026, 10, 22, 9, 30, 0))]),
                pki.root_crl(&[]),
            ],
        );
        pki.judge_under(&pdf, control_date(), &ValidationPolicy::strict())
    };

    let proven = archived(None);
    passed(&proven);
    assert_eq!(proven.best_signature_time, Some(nine.to_system_time()));

    let unproven = archived(Some(vec![0; 32]));
    let defect = refused(&unproven, SubIndication::RevokedNoPoe);
    assert!(matches!(defect, RevocationDefect::Revoked { depth: 0, .. }));
    assert_eq!(unproven.best_signature_time, None);
}

/// s18 H, h2 and h11b: a `certificateHold` at 07:00, before the stamp, on the signer, then
/// on the intermediate, gives `TRY_LATER` under both presets.
#[test]
fn hold_before_the_stamp_is_try_later() {
    let pki = Pki::new();
    let seven = time(2026, 10, 22, 7, 0, 0);
    let held = |certificate: &Certificate, issuer: &Certificate, issuer_key: &SigningKey| {
        crl_with_reasons(
            issuer,
            issuer_key,
            time(2026, 10, 22, 10, 0, 0),
            time(2026, 11, 22, 0, 0, 0),
            &[(certificate, seven, Some(CrlReason::CertificateHold))],
        )
    };
    let on_signer = with_dss(
        &pki.stamped(),
        &[],
        &[
            held(&pki.signer, &pki.intermediate, &pki.intermediate_key),
            pki.root_crl(&[]),
        ],
    );
    let on_intermediate = with_dss(
        &pki.stamped(),
        &[],
        &[
            pki.intermediate_crl(&[]),
            held(&pki.intermediate, &pki.root, &pki.root_key),
        ],
    );

    for policy in [ValidationPolicy::strict(), ValidationPolicy::dss()] {
        for (pdf, depth) in [(&on_signer, 0), (&on_intermediate, 1)] {
            let result = pki.judge_under(pdf, control_date(), &policy);
            assert_eq!(
                refused(&result, SubIndication::TryLater),
                RevocationDefect::OnHold {
                    depth,
                    date: seven.to_system_time()
                }
            );
        }
    }
}
