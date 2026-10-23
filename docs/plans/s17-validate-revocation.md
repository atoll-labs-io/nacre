---
validated: yes
---
# Plan — s17-validate-revocation

[Story](../stories.md) · [Research](../research/s17-validate-revocation.md)

Branch `story/s17-validate-revocation`. Read `docs/research/s17-validate-revocation.md` first; this plan builds on it without repeating it.

**Story corrected on `main` by 7eaee8f (PR #123).** AC1 and AC3 now name DSS 6.5.1's verdicts (`REVOKED_NO_POE`, `CERTIFICATE_CHAIN_GENERAL_FAILURE`), as the research's spike recorded and AC5 and brief success metric 2 require. This plan builds those verdicts.

## Story
Judge the revocation of every certificate of the signer's path, and of the signature timestamp's TSA path, from the `/DSS` data and an optional `RevocationSource`. A revocation applies when its date is at or before the best-signature-time: the `genTime` of the earliest signature timestamp whose token verifies and whose TSA path and revocation pass at the control date, otherwise the control date. ACs: see the story as corrected by 7eaee8f.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Reading and judging one CRL or OCSP response | already here: `Crl::status`, `OcspResponse::status` (`crates/nacre-revocation/src/crl.rs:98`, `src/ocsp/response.rs:141`) | — |
| Verifying a signature timestamp token | already here: `nacre_tsp::verify_token` (`crates/nacre-tsp/src/token.rs:71`) | — |
| TSA path building | already here: `build_chain`'s search (`crates/nacre-validate/src/chain.rs:168-223`), given a leaf purpose | — |
| Reading `/DSS /CRLs` and `/OCSPs` | already here: the walk of `dss_certificates` (`src/validate.rs:236-252`), generalised to a key | — |
| POE and revocation rule: pick the item, compare its date with the BST, map to a sub-indication | new code, in `src/revocation.rs` | nacre-revocation leaves this comparison to s17 (`crates/nacre-revocation/src/lib.rs:26-28`); no dependency judges EN 319 102-1 POE |
| Test PKI, CRLs, tokens and PDFs | dependency already installed: `x509-cert` builder, `CrlBuilder`, `nacre-cms`, `nacre-pades` (dev-deps), patterns copied from `crates/nacre-tsp/examples/forge_attacks.rs:179-275` and `crates/nacre-revocation/examples/forge_attacks.rs:96-120` | an example cannot be imported by a test; the cases are built at test time, so no corpus file is committed |

## Tasks
1. [x] **Dependencies.** `crates/nacre-validate/Cargo.toml`: add `nacre-tsp` and `nacre-revocation` as `{ path = "../…", version = "0.1.0" }` with no feature (as `nacre-cms`, `:15`). Dev-deps: `nacre-tsp` and `nacre-revocation` with `features = ["http"]`, `nacre-conformance` gains `features = ["http"]` (`:29`), `sha2` if the forge helper needs it. Update the package `description`. No `[workspace.dependencies]`. Test: `cargo build -p nacre-validate` (no test of its own).
2. [x] **Leaf purpose in the chain.** `src/chain.rs`: a private `Purpose { Signing, Timestamping }` threaded from a `pub(crate) fn build_path(signer, pool, anchors, at, purpose)` into `Search` and `judge` (`:394-454`). At depth 0, `Signing` keeps the `SIGNING_PURPOSES` rule (`:418-426`); `Timestamping` requires `id-kp-timeStamping` (`1.3.6.1.5.5.7.3.8`) in the EKU. `build_chain` keeps its public signature and calls `build_path(.., Purpose::Signing)`. Tests able to fail: R1 (a TSA path refused for its EKU loses the POE, R1 turns `REVOKED_NO_POE`); `tests/attacks.rs` `chain-extended-key-usage` keeps biting the signing rule.
3. [x] **The revocation judge, PDF-free.** New `src/revocation.rs`, crate-private:
   - `RevocationPool::from_der(items: &[RevocationData])`: each item read once (`Crl::from_der`, `OcspResponse::from_der`), an unreadable one skipped; at most 256 readable items, later ones ignored (as `MAX_POOL_LEN`, `chain.rs:22-25`).
   - `judge_path(path: &CertificatePath, pool, source: Option<&dyn RevocationSource>, time) -> Result<(), RevocationDefect>`: for each certificate below the anchor (depth `d`, issuer = the next certificate of the path), the candidates are the pool plus the source's one answer (an `Err` is ignored). A candidate counts when `status(cert, issuer, own_date)` is `Ok`, `own_date` being the CRL's `thisUpdate` or the response's `producedAt` (DSS ignores freshness: research, spike c19, c20), and `own_date >= cert.notBefore`. The latest `own_date` wins, a revoked one first on a tie. None → `Missing { depth }`; `Revoked { date, .. }` with `date <= time` → `Revoked { depth, date }`; else pass.
   - Public `RevocationDefect { Revoked { depth, date }, Missing { depth } }` (`#[non_exhaustive]`), exported from `lib.rs`, with `report()`: `Revoked` at depth 0 → `INDETERMINATE` / `REVOKED_NO_POE`, deeper → `REVOKED_CA_NO_POE`, `Missing` → `CERTIFICATE_CHAIN_GENERAL_FAILURE`. `Defect::Revocation(RevocationDefect)` in `src/report.rs`, its report taken from `report()`, `digest_verified` and `signature_verified` true, as `Defect::Chain` (`report.rs:144`). Never `TOTAL_FAILED` / `REVOKED`.
   - Test able to fail: U1 `every_revocation_defect_has_its_report` (unit, rows as `chain.rs:551-592`); R2, R4, R5, R8 to R11.
4. [x] **Signature timestamps and the best-signature-time.** `src/validate.rs`: `Signed` (`:210-232`) also keeps the SHA-256 of `SignerInfo.signature` and the DER of each value of the unsigned attribute `1.2.840.113549.1.9.16.2.14`, at most 16, later ones ignored. Per token: `verify_token(token, Sha256, imprint)`; TSA path through `build_path(tsa_certificate, token certificates + CMS + `/DSS` certificates, anchors, at, Timestamping)`; `judge_path(tsa path, pool, source, at)`. Any failure drops that token silently. BST = the earliest `genTime` left (convert with `x509_cert::time::Time::from(dt).to_system_time()`), else `at`. Tests able to fail: R1, R7, R12.
5. [x] **Wire the judgement.** `src/validate.rs`:
   - `dss_certificates` generalised to a key (`Certs`, `CRLs`, `OCSPs`); the `/DSS` is read whenever anchors exist (`:92-96`).
   - New `pub fn validate_with_revocation(pdf, anchors, at, source: Option<&dyn RevocationSource>)`; `validate_with_anchors` delegates with `None`; `validate` unchanged.
   - The signer's path is built at the BST (`:139`), then `judge_path(path, pool, source, bst)`. Pass → `ValidationReport::passed(None)`: `TOTAL_PASSED`, no level (s18). `RevocationDefect` → `Defect::Revocation`, the path kept in `SignatureValidation::chain` (its RFC 5280 judgement passed). No path → `NO_CERTIFICATE_CHAIN_FOUND` as today.
   - `SignatureValidation` gains `best_signature_time: Option<SystemTime>`, `Some` when a timestamp gave the POE. The `TRY_LATER` branch of `sound` (`report.rs:114-117`) goes.
   - Crate docs (`src/lib.rs:1-28`), the field docs (`report.rs:22-26`) and the function docs (`validate.rs:19-42`) say what is judged now.
   - Test able to fail: R1, R3, R6, and the three updated tests of task 6.
6. [x] **Existing tests that assumed `TRY_LATER`.** `tests/validate.rs:363-379` (`chain_valid`), `tests/attacks.rs:437-455` (`chain_dss_junk_does_not_hide_the_chain`), `tests/conformance.rs:20-53` (`bench_chain_is_valid`): a valid path with no revocation data now ends `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`, defect `Revocation(Missing { depth: 0 })`, path still in `chain`. `bench_chain_is_valid` gains the bench HTTP source and expects `TOTAL_PASSED`, as DSS on c01 (C0).
7. [x] **Offline cases.** `tests/support/forge.rs` (declared from `tests/support/mod.rs`, which takes `#![allow(dead_code)]` as `crates/nacre-pdf/tests/support/mod.rs:3`): a fictitious root, intermediate, signer and TSA (critical `timeStamping` EKU) with fixed keys, valid 2026-01-01 to 2036-01-01; a token builder with a fixed `genTime` and `signingCertificateV2`; a `TimestampAuthority` returning it; CRLs from `CrlBuilder`; a PDF signed through `nacre_pades::sign_at_level` (`Level::B`, `Level::T`) and given a `/DSS` revision with `Certs`, `CRLs` (`with_dss` of `examples/forge_chain_attacks.rs:332-345`, extended). New `tests/revocation.rs`, stamp at 2026-10-22T08:00Z, control date 2026-10-23T00:00Z, every certificate below the root covered by a CRL unless the case says otherwise (the intermediate by the root's): R1 to R12 below.
8. [x] **Confrontation with DSS.** `tests/conformance.rs`, each `#[ignore = "conformance"]`, each asserting that Nacre's indication and sub-indication equal DSS's for the same file, and the exact pair the spike recorded. A forged certificate is issued at test time under the bench intermediate (`conformance/pki/out/intermediate.key.pem`, PKCS#8, readable), with no CDP and no AIA, so DSS reads only the `/DSS` (its CRL cache, research, spike). Revocation after a stamp: the source given to `Level::LT` sleeps 2 s, then returns a CRL signed with the intermediate key whose revocation date is 1 s before now; other certificates go to the bench `Fallback`. Nacre judges at `SystemTime::now()` in the test. C0 to C6 below. Then `po-run` the full suite and the type check.

### Fix run 1 (review of b496946)
9. [x] R10 also checks the reverse array order ([older, newer]), so first-wins fails it (major 1).
10. [x] Freshness for a signature without proof of existence, `FRESHNESS_TOLERANCE` 24 h, documented in the crate, function and pivot; R13 `old_crl_does_not_pass_a_signature_without_poe`; R9 kept, its CRL being 14 h old (major 2).
11. [x] `confront` asserts the PAdES level DSS reports for C0 to C6 (minor).
12. [x] `validate_with_revocation` documents the SHA-256-only imprint (minor).

## Scene viewpoints
—

## Run interdicts
- Empty diff outside `crates/nacre-validate/`, `docs/research/s17-validate-revocation.md`, `docs/plans/s17-validate-revocation.md` and the pipeline's own `docs/verif/`, `docs/reviews/` files: in particular `crates/nacre-revocation/`, `crates/nacre-tsp/`, `crates/nacre-core/`, `crates/nacre-pades/`, `conformance/`, `docs/stories.md`, `docs/security/attacks/`.
- `build_chain`'s public signature (`chain.rs:168-173`) and `validate_with_anchors`'s are unchanged.
- No `SystemTime::now`, `Instant` or clock read under `crates/nacre-validate/src/`; no network there: the source is reached only through `RevocationSource`.
- Nothing in `src/` returns `TOTAL_FAILED` / `REVOKED`.
- No `[workspace.dependencies]`, no root `Cargo.toml` edit, no `Cargo.lock` committed.
- No corpus file of real or third-party documents; nothing commits a bench key.
- Document timestamps stay out of the result (`validate.rs:67`); no archival POE, no level: s18.

## The pivot
**Each revocation item is judged at its own date, and the revocation it states applies only at or before the best-signature-time.** Everything else (TSA, CA, missing data) is that rule applied to another path or another date. Ways it could be wrong:
- DSS may pick the latest item by another date (OCSP `thisUpdate` rather than `producedAt`). Compare with c07, and with C4 once the bench OCSP is past its five-minute `nextUpdate`.
- Judging at the item's own date neutralises nacre-revocation's expiry check on purpose (DSS: `BBB_RFC_IRIF` IGNORED). A reviewer should check that every other refusal of `status` (issuer, signature, critical extension, `unknown`) still drops the item, and that a dropped item is never read as "not revoked" (R8).
- The 256-item cap lets an appended `/DSS` of junk push genuine data out, turning a valid signature `INDETERMINATE`, never valid: fail-closed, the same trade as the chain's pool (decisions log, s16).
- **Deliberate divergence from DSS (decided by the person on 2026-10-23, review major 2), for s18 to list.** A signature with no proof of existence (B-B, or every token refused, so the best-signature-time is the control date) counts a revocation item only when its own date (`thisUpdate`, `producedAt`) is at or after the control date minus `FRESHNESS_TOLERANCE`, 24 h (`src/revocation.rs`): CAs publish at least daily, and it bounds to one day the window in which a key revoked since passes on an old CRL appended to `/DSS`. DSS ignores freshness there too; nothing fresh enough and no source gives `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE`. Signatures with a proof of existence, and the TSA path judged at the control date, keep DSS's rule. Cost: a CA publishing less often than daily makes an offline B-B signature `Missing`.
- Following DSS rather than the norm: settled by AC5, the brief's metric and the story as corrected by 7eaee8f; the norm text itself was not read (research, Open questions).

## Files touched
`crates/nacre-validate/Cargo.toml`, `src/lib.rs`, `src/chain.rs`, `src/revocation.rs` (new), `src/report.rs`, `src/validate.rs`, `tests/support/mod.rs`, `tests/support/forge.rs` (new), `tests/revocation.rs` (new), `tests/conformance.rs`, `tests/validate.rs`, `tests/attacks.rs`.

## Test strategy
The rule lives in `src/revocation.rs` and the BST in `src/validate.rs`; both are reached through `validate_with_revocation` on PDFs built at test time, the layer the caller uses. 20 new tests (R13 added by fix run 1), within the budget of 25; three existing ones change their expectation.

Offline, `tests/revocation.rs` (each one a distinct rule; deleting it turns the test red):
- R1 signer revoked 09:00, after the stamp, CRL in `/DSS` → `TOTAL_PASSED`, `best_signature_time` = 08:00 (AC1).
- R2 signer revoked 07:00, before the stamp → `INDETERMINATE` / `REVOKED_NO_POE` (AC1 corrected).
- R3 B-B, signer revoked 09:00, before the control date → `REVOKED_NO_POE`, `best_signature_time` `None` (AC2).
- R4 B-B, intermediate listed by the root's CRL → `REVOKED_CA_NO_POE`.
- R5 B-B, no revocation data, no source → `CERTIFICATE_CHAIN_GENERAL_FAILURE`, `Missing { depth: 0 }` (AC3 corrected).
- R6 R5's file with a stub source answering the CRLs → `TOTAL_PASSED`; with a failing source → `Missing` (AC3, the source).
- R7 R1 with the TSA revoked before the control date → `REVOKED_NO_POE`, `best_signature_time` `None` (AC4).
- R8 a CRL signed by another key, listing nothing → `Missing`: refused data is never "not revoked".
- R9 a CRL whose `nextUpdate` is before the control date, listing nothing → `TOTAL_PASSED` (spike c20).
- R10 B-B, an older CRL listing nothing and a newer one listing the signer, in both array orders → `REVOKED_NO_POE` (latest wins).
- R11 a CRL issued before the signer's `notBefore`, listing nothing → `Missing`.
- R12 R1 with a token over another imprint → `REVOKED_NO_POE`: an unverified token gives no POE.
- R13 B-B, `/DSS` intermediate CRL issued 25 h before the control date, listing nothing → `Missing`; the same `/DSS` on the B-T file → `TOTAL_PASSED` (fix run 1, divergence above).

Unit, `src/revocation.rs`: U1 every `RevocationDefect` has its report.

Conformance, `tests/conformance.rs`, bench and DSS, ignored (AC5), each asserting Nacre = DSS:
- C0 bench `signer`, B-B, bench HTTP source → `TOTAL_PASSED` (c01).
- C1 forged signer revoked after its bench B-T stamp, data in `/DSS`, no source → `TOTAL_PASSED` (c05, c07).
- C2 bench `revoked`, B-T, HTTP source → `REVOKED_NO_POE` (c04).
- C3 bench `revoked`, B-B, HTTP source → `REVOKED_NO_POE` (c02).
- C4 bench `signer` at B-LT and B-LTA (s11, s12 shapes), no source → `TOTAL_PASSED` each (AC3).
- C5 forged signer without CDP or AIA, B-B, no source → `CERTIFICATE_CHAIN_GENERAL_FAILURE` (c08).
- C6 forged signer and forged TSA (its token built by the forge helper with the bench intermediate's key), both revoked after the stamp → `REVOKED_NO_POE` (c14, AC4).

OCSP parsing is reached only by C0, C2, C3 and C4: nacre-revocation's own tests cover the response itself. Checks: the tests of each task with `cargo test -p nacre-validate --test <stem>`; the full suite and `Typecheck` once at the end through `po-run`; conformance at ship, with the bench up (`conformance/README.md`).

## Done when
One commit on `story/s17-validate-revocation` holding the code, the tests, the research and this plan; `cargo test --workspace` and `Typecheck` green through `po-run`; C0 to C6 green against the bench; a review with no open critical finding.
