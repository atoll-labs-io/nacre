# Research — s17-validate-revocation

[Story](../stories.md)

## Structuring facts
- **Two story assumptions are false against DSS 6.5.1** (spike below, bench run on 2026-10-23). A B-T signature whose timestamp comes *after* the revocation gets `INDETERMINATE` / `REVOKED_NO_POE` from DSS, not `TOTAL_FAILED` / `REVOKED` (case c04, constraint `ADEST_IRTPTBST` NOT OK). A signer with no revocation data reachable gets `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE` (`BBB_XCV_IRDPFC` "No revocation data found"), never `TRY_LATER` or `REVOCATION_OUT_OF_BOUNDS_NO_POE` (c08, c17, c18). AC5 (same verdict as DSS) and brief success metric 2 (100 % identical to DSS) decide: Nacre follows DSS, and AC1 and AC3 should be reworded to match.
- DSS ignores freshness: a CRL whose `nextUpdate` passed before the control date is used (`BBB_RFC_IRIF` IGNORED, c19, c20), and so is an OCSP response past its five-minute `nextUpdate` (c11late, c13late). `Crl::status` and `OcspResponse::status` refuse exactly that (`crates/nacre-revocation/src/crl.rs:123-126`, `src/ocsp/response.rs:171-176`), so validation must judge each item at its own `thisUpdate` rather than at the control date.
- Revocation applies at the best-signature-time (BST): the `genTime` of a timestamp whose own TSA path and revocation pass at the control date, otherwise the control date. Revoked strictly after the BST → passed (c05, c07, c23); at or before → `REVOKED_NO_POE`, or `REVOKED_CA_NO_POE` when the revoked certificate is a CA (c24). A TSA revoked before the control date gives no POE (c10, c14, c16).
- `build_chain` cannot judge a TSA path: the leaf's `extendedKeyUsage` must name a document-signing purpose (`crates/nacre-validate/src/chain.rs:418-426`, `53-60`), and a TSA certificate carries `timeStamping` alone. AC4 needs a purpose parameter behind the public signature.
- `nacre-validate` depends on neither `nacre-tsp` nor `nacre-revocation` (`crates/nacre-validate/Cargo.toml:12-23`), and reads only `/DSS /Certs` (`src/validate.rs:236-252`). The bench cannot revoke a certificate after signing (`conformance/pki/generate.sh:57-60`); the spike forged such cases under the bench intermediate, whose key `pki-init` leaves readable in `conformance/pki/out/`.

## Story
Judge the revocation of the signer, and of the TSA, at the date the signature timestamp proves, from `/DSS` data or a `RevocationSource`. AC1: B-T signed before revocation, CRL after it → valid; timestamp after revocation → `TOTAL_FAILED` `REVOKED` (false, see above). AC2: B-B → judged at the control date, revoked → `INDETERMINATE` `REVOKED_NO_POE`. AC3: `/DSS` suffices offline for s11/s12 PDFs; no data, no source → `TRY_LATER` or `REVOCATION_OUT_OF_BOUNDS_NO_POE` (false, see above). AC4: the TSA chain is judged like the signer's. AC5: the cases confronted with DSS give the same indication and sub-indication. Notes: run the spike (brief, finding 6) here.

## Diagnostic — the spike (DSS 6.5.1, bench, 2026-10-23)
Built with a scratch signer in `/tmp` (nothing written in the worktree), certificates forged with `openssl ca` on a copy of the bench PKI, extra CRLs served on `127.0.0.1:18082`. The ETSI norm text is not in the repository and was not consulted; "story" is the story's expectation.

| # | Case | DSS indication / sub | Story |
| --- | --- | --- | --- |
| c01 / c03 | bench `signer`, B-B / B-T | TOTAL_PASSED | — |
| c02 | bench `revoked`, B-B | INDETERMINATE / REVOKED_NO_POE | same (AC2) |
| c04 | `revoked`, B-T, stamped after revocation | INDETERMINATE / REVOKED_NO_POE | TOTAL_FAILED / REVOKED |
| c05 | B-T, revoked 3 s after the stamp, CRL online | TOTAL_PASSED (basic REVOKED_NO_POE, LT process PASSED) | same (AC1) |
| c06 | B-B, revoked after signing | INDETERMINATE / REVOKED_NO_POE | same (AC2) |
| c07 | B-LT, `/DSS` CRL says good, later online CRL revoked after the stamp | TOTAL_PASSED, the later CRL used | — |
| c08 / c09 | no CDP, no AIA, B-B / B-T | INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE | TRY_LATER or REVOCATION_OUT_OF_BOUNDS_NO_POE |
| c17 / c18 | CDP answers 404, B-T / B-B | same as c08 | same as c08 |
| c10 / c15 | good signer, TSA revoked after / before its stamp | TOTAL_PASSED, BST = validation time, timestamp REVOKED_NO_POE | — |
| c14 / c16 | signer revoked after the stamp, TSA revoked after / before it | INDETERMINATE / REVOKED_NO_POE | consistent with AC4 |
| c19 / c20 | CRL `nextUpdate` passed at validation, B-T / B-B | TOTAL_PASSED | — |
| c21 / c22 | CRL issued before the stamp / signing | TOTAL_PASSED | — |
| c23 / c24 | intermediate revoked after the stamp / B-B | TOTAL_PASSED / INDETERMINATE REVOKED_CA_NO_POE | — |
| c25 / c26 | signer expired after the stamp, B-T / B-B | TOTAL_PASSED / INDETERMINATE OUT_OF_BOUNDS_NOT_REVOKED | — |
| c11, c13 | s11 B-LT, s12 B-LTA, also re-run after the OCSP `nextUpdate` | TOTAL_PASSED, `-LT` / `-LTA` | same (AC3) |

Rules read from the detailed reports: revocation acceptance checks `thisUpdate` present, a `nextUpdate` present (`BBB_RFC_NUP`), the issuer found, the certificate covered, data issued after the certificate's `notBefore` (`BBB_XCV_REVOC_AFTER_CERT_NOT_BEFORE`); freshness ignored. DSS caches a CRL per URL across requests (c14 first run read a stale cache): a conformance test gives each forged certificate no CDP and embeds its CRL in `/DSS`. `TOTAL_FAILED` / `REVOKED` appeared in no case. Hypotheses tried and kept: "BST is the stamp's `genTime`" (BST column of c03, c05, c07); "a bad TSA path drops the POE" (c10 BST = validation time). Discarded: "revocation data must be issued after the BST" (c21, c22 pass).

## Current code
- `validate` → `validate_with_anchors(pdf, anchors, at)` → `validate_with` (`src/validate.rs:30-49`). Each signature: integrity (`check`, `:158-167`), later revisions, then `build_chain(signer, CMS certs + /DSS certs, anchors, at)` (`:132-145`). `/DSS` certificates are read only when anchors exist (`:92-96`).
- `Signed` keeps only the signer certificate and the CMS certificates (`:210-232`); the `SignerInfo` (unsigned attributes, signature value) is dropped.
- `SignatureValidation::sound` gives `TRY_LATER` for a valid path (`src/report.rs:109-127`); docs say so (`src/lib.rs:19-27`, `src/report.rs:22-26`). Defects: `Defect` (`report.rs:72-104`), `ChainDefect` with `report()` (`chain.rs:103-149`).
- `build_chain(signer, pool, anchors, at)` public (`chain.rs:168-223`), judges validity, critical extensions, key usage, EKU on the leaf, CA constraints at `at` (`judge`, `:394-454`). Pool capped at 256, later ones ignored (`:22-25`).

## Attachment points
- `validate_with` (`validate.rs:51-150`): after the chain, before `SignatureValidation::sound`.
- `verify` (`validate.rs:215-232`): keep the `SignerInfo`'s signature value and unsigned attributes.
- `dss_certificates` (`validate.rs:236-252`): same walk for `/CRLs` and `/OCSPs`, the keys nacre-pades writes (`crates/nacre-pades/src/dss.rs:101-103`).
- `judge` / `build_chain` (`chain.rs:168`, `:418`): a leaf purpose, signing or time-stamping.
- `Cargo.toml`: add `nacre-tsp`, `nacre-revocation` (path + `version = "0.1.0"`, as `nacre-cms` at `:15`); dev-deps `nacre-tsp`/`nacre-revocation` with `http`, `nacre-conformance` with `http` (today without, `:29`).

## Verified interfaces
- `nacre_tsp::verify_token(token, DigestAlgorithm::Sha256, imprint) -> Result<VerifiedToken, Error>` (`crates/nacre-tsp/src/token.rs:71-119`): CMS, `signingCertificateV2`, critical `timeStamping` EKU, imprint; never the TSA chain nor `genTime`. `VerifiedToken::tsa_certificate()`, `gen_time() -> der::DateTime` (`:40-47`). Token certificates: `nacre_cms::SignedData::from_der(token)?.certificates` (`crates/nacre-cms/src/model.rs:73-79`).
- Signature timestamp: unsigned attribute `1.2.840.113549.1.9.16.2.14`, imprint = SHA-256 of `SignerInfo.signature` (`crates/nacre-pades/src/timestamp.rs:10-11`, `:33-40`). `SignerInfo.unsigned_attrs: Vec<Attribute>` (`model.rs:197-204`), `VerifiedSigner::signer_info()` (`crates/nacre-cms/src/verify.rs:29`).
- `Crl::from_der`, `this_update`, `next_update`, `status(cert, issuer, at) -> Result<CrlStatus, Error>` (`crl.rs:49-143`): refuses wrong issuer, critical extensions, bad signature, missing or passed `nextUpdate`; accepts `thisUpdate` after `at` (`:96`). `CrlStatus::{NotRevoked, Revoked{date, reason}}` (`:34-45`).
- `OcspResponse::from_der`, `produced_at`, `this_update` (first single only), `status(cert, issuer, at) -> Result<OcspStatus, Error>` (`response.rs:51-186`); `unknown` is an error (`:184`). Nonce and `thisUpdate` tolerance are separate checks (`:101-133`), not needed for stored data.
- `nacre_core::RevocationSource::revocation(certificate, issuer) -> Result<RevocationData, Error>`, `RevocationData::{Crl, Ocsp}` `#[non_exhaustive]` (`crates/nacre-core/src/revocation.rs:4-18`). `SubIndication::{RevokedNoPoe, RevokedCaNoPoe, CertificateChainGeneralFailure}` exist (`crates/nacre-core/src/report.rs:63-89`).
- `nacre_revocation` lib doc hands "comparing a revocation date with a signing time" to s17 (`crates/nacre-revocation/src/lib.rs:26-28`).

## Traps
- Three tests assert `TRY_LATER` for a valid path with no revocation data and must turn to `CERTIFICATE_CHAIN_GENERAL_FAILURE`: `tests/validate.rs:363-378`, `tests/attacks.rs:437-455`, `tests/conformance.rs:20-53` (asserts at `:49-52`).
- The bench OCSP `nextUpdate` is five minutes ahead (`conformance/pki/README.md`, Services): a s11 PDF judged later fails `OcspResponse::status` at the control date.
- `x509-cert` `CrlBuilder` exists under the `builder` feature, already a dev-dep (`Cargo.toml:31`); precedent `crates/nacre-revocation/examples/forge_attacks.rs:24-25`, `:96-120`. Token forging precedent: `crates/nacre-tsp/examples/forge_attacks.rs:179-275`. PDF + `/DSS` forging: `crates/nacre-validate/examples/forge_chain_attacks.rs:321-345`.
- A shared test helper unused by one test file breaks `clippy -D warnings`; precedent `crates/nacre-pdf/tests/support/mod.rs:3` (`#![allow(dead_code)]`).
- s16 decision (`docs/decisions-log.md`): unsigned pool data never disqualifies a path. Revocation data is CA-signed, but `/DSS` arrays are attacker-ordered: a cap must not let junk hide genuine data more than the chain's own cap does.
- Document timestamps stay skipped (`validate.rs:67`); archival POE and timestamp levels are s18 (story s18 AC3). The fuzz target calls `validate_with_anchors` (`fuzz/fuzz_targets/validate.rs:22`), which now reaches the new code.
- No migration. `Owns` is `crates/nacre-validate/` only: nothing under `conformance/` changes.

## Open questions
- An OCSP response or CRL without `nextUpdate`: DSS checks `BBB_RFC_NUP`, but no case showed its level; the plan keeps nacre-revocation's refusal for a CRL and accepts an OCSP without one.
- `certificateHold` and `removeFromCRL`: not tried; the plan treats any listed entry as revoked.
- c26 (expired at the control date, not revoked) gives DSS `OUT_OF_BOUNDS_NOT_REVOKED`, while s16 gives `OUT_OF_BOUNDS_NO_POE`; bench certificates never expire, so neither s17 nor the s18 campaign meets it. To file as an issue.
- c15: a timestamp DSS finds invalid still leaves `PAdES-BASELINE-T` as the format: a fact for s18.
- Whether to follow EN 319 102-1 where it differs from DSS was settled by the brief's metric, not by reading the norm.

## Complexity
Story 4 → 4. The POE rule fits in one function once BST is known; the weight is the TSA path, the revocation pool and building cases DSS can judge.

## Split
Not needed.
