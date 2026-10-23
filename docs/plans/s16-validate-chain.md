---
validated: yes
---
# Plan — s16-validate-chain

[Story](../stories.md) · [Research](../research/s16-validate-chain.md)

Branch `story/s16-validate-chain`. Read `docs/research/s16-validate-chain.md` first; this plan builds on it without repeating it.

**Before `/po-execute`: the story's `Owns` must also list `docs/security/attacks/cms.md` and `docs/security/attacks/pades.md`** (research, first structuring fact). Task 7 writes them; without the widening, po-bounds refuses it.

## Story
The signer's chain is built from the CMS and `/DSS` certificates up to a caller-supplied anchor and judged at a control date given as a parameter (RFC 5280, written by Nacre on `x509-cert` models, ADR-0004).
1. Bench root of s02 as anchor → the s06 signer's chain is built and judged valid.
2. No anchor → `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, never `TOTAL_PASSED`.
3. Expired certificate, signing key usage absent, violated basic constraint → the matching EN 319 102-1 sub-indication.
4. A public, PDF-free API of `nacre-validate`, reusable by CAdES, XAdES and JAdES.

## Public API decided here
- `pub struct TrustAnchors` (`Default` = none): `TrustAnchors::from_certificates<'a>(certificates: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, Error>`; each DER parsed once; `Error::TrustAnchor(der::Error)`, kind `InvalidInput`.
- `#[non_exhaustive] pub struct CertificatePath { pub certificates: Vec<Vec<u8>> }`, leaf first, anchor last.
- `pub fn build_chain(signer: &[u8], pool: &[&[u8]], anchors: &TrustAnchors, at: SystemTime) -> Result<CertificatePath, ChainDefect>`.
- `#[non_exhaustive] pub enum ChainDefect` with `pub fn report(&self) -> ValidationReport`: `NoPath` → `NO_CERTIFICATE_CHAIN_FOUND`; `SignerUnreadable` → `NO_SIGNING_CERTIFICATE_FOUND`; `Expired { depth }`, `NotYetValid { depth }` → `OUT_OF_BOUNDS_NO_POE`; `KeyUsage` (leaf), `NotACa { depth }`, `CaKeyUsage { depth }`, `PathLength { depth }` → `CHAIN_CONSTRAINTS_FAILURE`; `UnsupportedCriticalExtension { depth, oid }`, `MalformedExtension { depth }` → `CERTIFICATE_CHAIN_GENERAL_FAILURE`. All `INDETERMINATE`, level `None`. `depth` 0 is the leaf.
- `pub fn validate_with_anchors(pdf: &[u8], anchors: &TrustAnchors, at: SystemTime) -> Result<Vec<SignatureValidation>, Error>`; `validate(pdf)` keeps its signature and means "no anchor" (it calls the new function with `TrustAnchors::default()`; no path can exist, so the date is never read).
- `SignatureValidation` gains `pub chain: Option<CertificatePath>` (the valid path) and `Defect` gains `Chain(ChainDefect)`.
- A signature whose integrity and revisions pass: no path → `defect: None`, `chain: None`, `NO_CERTIFICATE_CHAIN_FOUND` (today's behaviour); a path with a defect → `Defect::Chain`, `digest_verified` and `signature_verified` true, the defect's report; a valid path → `defect: None`, `chain: Some`, `INDETERMINATE` / `TRY_LATER` until s17 judges revocation.

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Certificate signature check (outer = inner algorithm, TBS as received, ECDSA P-256 / RSA PKCS#1 SHA-256) | new code, copied from `crates/nacre-revocation/src/verify.rs:26-29`, `:50-126` and `crates/nacre-revocation/src/crl.rs:168-174` | in the repository but `pub(crate)` in a crate outside `Owns`; neither std nor `x509-cert` verifies signatures |
| Certificate model, extensions, dates | dependency: `x509-cert` 0.3 (`get_extension`, `Time::to_system_time`), `spki`, `p256`, `rsa` | already installed in the workspace (ADR-0004); added to this crate's `Cargo.toml` at the versions `crates/nacre-revocation/Cargo.toml` uses |
| `/DSS /Certs` reader | new code, copied from `crates/nacre-pades/src/archive.rs:152-184` | private in `nacre-pades`, which `nacre-validate` must not depend on outside tests |
| Path search and RFC 5280 judgement | new code | nothing in the repository; ADR-0004 rules out taking judgement from a crate |
| Forging profile in the chain forge | `Small` of `crates/nacre-revocation/examples/forge_attacks.rs:213-250`, copied and given validity, `pathLenConstraint` and an extra extension | an example of another crate cannot be imported |
| Bench signer in the conformance test | `crates/nacre-pades/tests/support/mod.rs:10-69`, copied | a test support module of another crate cannot be imported |

## Tasks
1. [x] **Dependencies and the chain module skeleton.** `Cargo.toml`: deps `x509-cert = "0.3"`, `spki = "0.8"`, `p256 = { version = "0.14", features = ["ecdsa"] }`, `rsa = "=0.10.0-rc.19"`; dev-deps `x509-cert` with `builder`, `p256` with `ecdsa`, `pkcs8`, `pem`, `der` with `pem`, `nacre-conformance = { path = "../nacre-conformance" }` (no version, as `crates/nacre-pades/Cargo.toml` does). `src/chain.rs` with `TrustAnchors`, `CertificatePath`, `ChainDefect` and `report()`; `Error::TrustAnchor` with its kind. Test: `every_variant_has_its_kind` (`src/error.rs:35-49`) gains the `TrustAnchor` row; a table test `every_chain_defect_has_its_report` in `src/chain.rs`, one row per variant, as `report.rs:177-260` does for CMS errors.
2. [x] **Path building.** In `chain.rs`: decode the signer (`SignerUnreadable` on failure) and the pool (unreadable entries skipped, entries not starting with `0x30` skipped). The signer DER equal to an anchor's DER is a path of one. Otherwise depth-first from the signer: a candidate issuer is an anchor or a pool certificate whose `subject` DER equals the child's `issuer` DER, whose `subjectKeyIdentifier` matches the child's `authorityKeyIdentifier` when both exist, and whose key verifies the child's signature over its TBS bytes as received, after checking `signatureAlgorithm` equals `tbsCertificate.signature`. Reaching an anchor closes a path. No certificate twice in a path; at most `MAX_PATH_LEN = 8` certificates below the anchor; at most `MAX_SIGNATURE_CHECKS = 64` verifications per call, after which the search ends as `NoPath` unless a path was already closed. Candidates are tried in a fixed order (anchors first, then pool order) so the result is deterministic. Test: `tests/chain.rs::path_is_built_without_pdf` — from the forged certificates of task 5 as DER, pool in reverse order with a duplicate and an unrelated certificate: path `[leaf, intermediate, root]`; no anchors → `NoPath`; anchor = an impostor with the root's name and another key → `NoPath`.
3. [x] **Judging a closed path** (RFC 5280 §6.1, anchor excluded: neither its validity nor its extensions are judged). For each certificate, leaf first: `notBefore <= at <= notAfter`, else `NotYetValid` / `Expired` with its depth; every critical extension is one of basicConstraints, keyUsage, extendedKeyUsage, subjectKeyIdentifier, authorityKeyIdentifier, subjectAltName, certificatePolicies, cRLDistributionPoints, authorityInfoAccess, else `UnsupportedCriticalExtension` (so a critical nameConstraints or policyConstraints is refused, never ignored); a duplicate or undecodable extension this task reads is `MalformedExtension`. Each certificate above the leaf: `basicConstraints` with `cA` true, else `NotACa`; a `keyUsage` present without `keyCertSign`, else `CaKeyUsage`; its `pathLenConstraint` at least the number of CA certificates below it, else `PathLength`. The leaf: a `keyUsage` present with neither `digitalSignature` nor `nonRepudiation` → `KeyUsage`; absent `keyUsage` accepted (RFC 5280 §4.2.1.3). The first path that judges clean wins; when none does, the defect of the first closed path. Tests: the attack tests of task 6, one per rule.
4. [x] **Wire into `validate`.** `verify` (`src/validate.rs:162-172`) returns the signer DER (`VerifiedSigner::certificate`) and the `SignedData::certificates`; `validate_with` reads `/DSS /Certs` of the last revision once (unfiltered streams only, as `archive.rs:152-154`); for each signature whose match at `src/validate.rs:90-101` reaches `(Ok(()), None, None)`, the pool is its CMS certificates then the `/DSS` ones, and the outcome follows "Public API decided here". `validate_with`'s test-only `max_signatures` parameter stays. `report.rs`: `sound` takes the chain outcome; `defective` maps `Defect::Chain` to `(defect.report(), true, true)`. Doc comments: `lib.rs:1-21`, `validate.rs` doc of `validate`, `report.rs` for the new field and variant. Tests: `tests/validate.rs::chain_from_cms_is_valid_but_revocation_pending` (`chain-cms.pdf`: `defect` none, `chain` `[leaf, intermediate, root]`, `INDETERMINATE` / `TRY_LATER`; the same file through `validate` → `NO_CERTIFICATE_CHAIN_FOUND`, criterion 2), `chain_from_dss_is_valid` (`chain-dss.pdf`, the intermediate only in `/DSS`), `revision_defect_outranks_chain` (`chain-cms.pdf` given a refused revision by the forge, `chain-cms-refused-revision.pdf` → `TOTAL_FAILED` / `FORMAT_FAILURE`, `RevisionNotAllowed`).
5. [x] **Chain forge and corpus.** New example `examples/forge_chain_attacks.rs` (`[[example]]` not needed: one file under `examples/`), deterministic (fixed P-256 secrets, RFC 6979, validity 2026-01-01 to 2036-01-01 unless stated, signing time 2026-10-22T08:00:00Z), writing into `tests/corpus/chain/`: `root.der`, `intermediate.der`, `leaf.der`, `impostor-root.der`; `chain-cms.pdf` (CMS chain leaf + intermediate), `chain-dss.pdf` (CMS chain leaf only, then a revision adding `/DSS /Certs` with the intermediate, through `Update::add_stream` / `set_catalog`), `chain-cms-refused-revision.pdf`; and into `tests/corpus/attacks/`: `chain-impostor-root.pdf` (leaf issued by a self-signed root carried in the CMS, same name as the anchor, other key), `chain-leaf-as-ca.pdf` (intermediate `cA` false), `chain-path-length.pdf` (root → intermediate `pathLen 0` → second CA → leaf), `chain-expired.pdf` (leaf valid until 2026-06-01), `chain-key-usage.pdf` (leaf `keyUsage` `keyCertSign` only), `chain-critical-extension.pdf` (intermediate with an unknown critical extension, OID under `2.999`). `tests/corpus/README.md`: one row per file with its SHA-256, source "written by the cargo example `forge_chain_attacks`", the keys fictitious and fixed in the example. `forge_pades_attacks.rs` untouched. Check: running the forge twice gives identical bytes.
6. [x] **Attack and criterion tests.** `tests/attacks.rs`, a helper `chain_rejected(file) -> ChainDefect` calling `validate_with_anchors` with `root.der` at 2026-10-22, asserting `INDETERMINATE`, `digest_verified && signature_verified`. One test per attack file: `chain_impostor_root_is_rejected` (without the helper: `defect` none, `chain` none, `NO_CERTIFICATE_CHAIN_FOUND`), `chain_leaf_as_ca_is_rejected` (`NotACa { depth: 1 }`, `CHAIN_CONSTRAINTS_FAILURE`), `chain_path_length_is_rejected` (`PathLength { depth: 2 }`), `chain_expired_is_rejected` (`Expired { depth: 0 }`, `OUT_OF_BOUNDS_NO_POE`), `chain_key_usage_is_rejected` (`KeyUsage`, `CHAIN_CONSTRAINTS_FAILURE`), `chain_critical_extension_is_rejected` (`UnsupportedCriticalExtension { depth: 1, .. }`, `CERTIFICATE_CHAIN_GENERAL_FAILURE`). `tests/hostile.rs`: the loop also calls `validate_with_anchors` with `root.der` on every file, so truncated and flipped chain files reach the chain code. `tests/chain.rs::search_is_bounded`: a pool of 200 certificates sharing the intermediate's name and key, none issued by the anchor → `NoPath`, and the test finishes (no timing assertion).
7. [x] **Attack docs** (needs the widened `Owns`). `docs/security/attacks/cms.md:22`: the "Chaîne contournée" paragraph becomes a table in the format of `pades.md`, one row per chain attack file of task 5, its test and result, story s16; the rules of task 3 stated once in French. `docs/security/attacks/pades.md:79`: the "Chaîne de certification" item now says a sound signature ends `NO_CERTIFICATE_CHAIN_FOUND` without an anchor and `TRY_LATER` with a valid chain until s17. Visual check only.
8. [x] **Bench test** (criterion 1). `tests/support/mod.rs` copied from `crates/nacre-pades/tests/support/mod.rs`, plus `bench_certificate("root.cert.pem")`. `tests/conformance.rs::bench_chain_is_valid`, `#[ignore = "conformance"]`: `nacre_pades::sign(UNSIGNED, &BenchSigner::load(), 2026-10-22T08:00Z)`, `validate_with_anchors` with the bench root at 2026-10-22 → `chain` is `[signer, intermediate, root]` by DER, `defect` none, `INDETERMINATE` / `TRY_LATER`. Run it on the bench if one is up; otherwise say so in the verification record and leave it to the conformance CI job.

## Scene viewpoints
—

## Run interdicts
- Empty diff outside `crates/nacre-validate/`, `docs/security/attacks/cms.md`, `docs/security/attacks/pades.md`, `docs/research/s16-validate-chain.md`, `docs/plans/s16-validate-chain.md`, `docs/verif/s16-validate-chain.md`: in particular `crates/nacre-core/`, `crates/nacre-cms/`, `crates/nacre-revocation/`, `crates/nacre-pades/`, the root `Cargo.toml`, `conformance/`, `docs/security/attacks/tsp.md`.
- `examples/forge_pades_attacks.rs` and every existing corpus file keep their bytes (their SHA-256 rows in `tests/corpus/README.md` unchanged).
- No existing test changes its assertions; `validate(pdf)` keeps its signature.
- No clock read in `src/` (`SystemTime::now`, `Instant::now` absent).
- No `[workspace.dependencies]`, no `cms` or `x509-tsp` crate, no network.
- Every public type that holds certificate bytes derives `Debug` (no secret in them); no message names a file path.
- No revocation judgement and no TSA chain: s17.

## The pivot
**A valid chain gives `INDETERMINATE` / `TRY_LATER`, never `TOTAL_PASSED`, until s17 judges revocation**; and the sub-indications of criterion 3 are `OUT_OF_BOUNDS_NO_POE` (validity), `CHAIN_CONSTRAINTS_FAILURE` (key usage, CA flag, CA key usage, path length) and `CERTIFICATE_CHAIN_GENERAL_FAILURE` (unsupported critical extension). Ways it could be wrong:
- DSS 6.5.1 may give a CA-flag or path-length violation `CERTIFICATE_CHAIN_GENERAL_FAILURE`, or only warn on a signing key usage (DSS's default policy). Compare with DSS once the s18 campaign forges the same cases under the bench root; a divergence is an issue, not a reason to change the table here unread.
- `TRY_LATER` may read as "the network failed" to Patelle; the crate doc and `SignatureValidation::chain` must say that `chain: Some` means the path is valid and revocation is not judged yet.
- Search order: if the first clean path is not found because the budget of 64 checks runs out on decoys, a legitimate signature reads `NO_CERTIFICATE_CHAIN_FOUND`. Anchors are tried first and the name/key-id filter runs before any signature check, so an honest chain costs one check per level.

## Files touched
`crates/nacre-validate/Cargo.toml`; `src/{lib.rs, chain.rs, error.rs, report.rs, validate.rs}`; `examples/forge_chain_attacks.rs`; `tests/{chain.rs, attacks.rs, hostile.rs, validate.rs, conformance.rs, support/mod.rs}`; `tests/corpus/chain/*.der`, `tests/corpus/chain/*.pdf`, `tests/corpus/attacks/chain-*.pdf`, `tests/corpus/README.md`; `docs/security/attacks/cms.md`, `docs/security/attacks/pades.md`.

## Test strategy
All at the layer where the rule lives: the chain rules through `validate_with_anchors` on one corpus case each (the attack convention), the PDF-free API through `build_chain` once, the outcome table once.

Automated (13, within the budget of 25):
- unit: `every_variant_has_its_kind` (one row added, not a new test), `every_chain_defect_has_its_report` (1);
- `tests/chain.rs`: `path_is_built_without_pdf`, `search_is_bounded` (2);
- `tests/validate.rs`: `chain_from_cms_is_valid_but_revocation_pending`, `chain_from_dss_is_valid`, `revision_defect_outranks_chain` (3);
- `tests/attacks.rs`: six `chain_*_is_rejected` (6);
- `tests/hostile.rs`: the existing test extended (0 new);
- `tests/conformance.rs`: `bench_chain_is_valid`, ignored, run by the conformance job (1).
Bite checks for the reviewer: removing the CA-flag check turns `chain_leaf_as_ca_is_rejected` red; removing the signature check on a candidate issuer turns `chain_impostor_root_is_rejected` and `path_is_built_without_pdf` red; dropping `/DSS` from the pool turns `chain_from_dss_is_valid` red; returning `TOTAL_PASSED` for a valid path turns `chain_from_cms_is_valid_but_revocation_pending` red.

Visual: task 7's French text, against the attack files and tests it names.

Checks: per task `cargo test -p nacre-validate --test <stem>`; once at the end, through `po-run`, `cargo test --workspace` then `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

## Done when
Every criterion met (criterion 1 by the ignored bench test, run on the bench or by the conformance CI job), the full suite and clippy green, the attack docs updated, the review without an open critical finding, one commit `s16-validate-chain: Construire et juger la chaîne de certificats vers une ancre déclarée` landed through a pull request.
