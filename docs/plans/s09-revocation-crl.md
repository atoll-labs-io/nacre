---
validated: yes
---
# Plan — s09-revocation-crl

[Story](../stories.md) · [Research](../research/s09-revocation-crl.md)

Branch `story/s09-revocation-crl`. Read `docs/research/s09-revocation-crl.md` first; this plan builds on it without repeating it.

Validated autonomously (`Plan validation: autonomous`): no human reviewed this plan. No structural choice is left open: CRL structures from `x509-cert` with the judgement in Nacre (ADR-0004), DER at the contract and the implementation's error boxed in `nacre_core::Error` (ADR-0010), `ureq` behind `http` (ADR-0006), `cargo-fuzz` (ADR-0008), detailed errors with `kind()` (ADR-0012). The reserved ADR-0015 is not used.

## Story
A new crate `crates/nacre-revocation/` reads a DER CRL, verifies it with its issuer's certificate, says whether a certificate is listed at a control date, and, under `http`, implements `nacre_core::RevocationSource` by downloading the CRL named by the certificate's distribution point. Criteria (`docs/stories.md:163-166`):
1. Read issuer, `thisUpdate`, `nextUpdate`, revoked serials with date and reason; verify the signature with the issuer certificate.
2. Under `http`, `RevocationSource` downloads from the distribution point; on s02's PKI `revoked` is listed, `signer` is not.
3. Another issuer, a bad signature or a passed `nextUpdate` is reported as such, never as "not revoked".
4. Hostile CRL → error, never panic; a fuzz target exists.

Decisions taken on the research's open questions:
- **No `nextUpdate`** → refused, `Error::MissingNextUpdate`: freshness cannot be shown (RFC 5280 §5.1.2.5 makes it mandatory).
- **`thisUpdate` after the control date** → accepted: s17 judges a past date with a later CRL (`docs/stories.md:302`).
- **Revocation date after the control date** → still `Revoked { date, reason }`; comparing it with a signing time is s17's judgement. Documented on the type.
- **Scheme** → `http://` only, no TLS dependency (`ureq` with `default-features = false`, as `crates/nacre-conformance/Cargo.toml:18`); a caller needing more injects its own `RevocationSource` (ADR-0006, Neutral). LDAP and `https` points are skipped.
- **Control date type** → `std::time::SystemTime`, compared with `Time::to_system_time()`.
- **v1 CRL** (no version field) → the `der` error `x509-cert` gives; listed in the attacks file as a known limit.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| CRL decoding (`CertificateList`, `RevokedCert`, `CrlReason`, `CrlDistributionPoints`) | dependency `x509-cert` 0.3 (`src/crl.rs:33-97`, `src/ext/pkix/crl.rs:74,121`) | nothing in the repository decodes a CRL |
| Received `tbsCertList` bytes | dependency `der` (`SliceReader`, `tlv_bytes`) | `nacre-cms`'s `nested`/`expect` (`crates/nacre-cms/src/model.rs:390-407`) are `pub(crate)` in a crate outside Owns |
| ECDSA P-256 / RSA PKCS#1 v1.5 SHA-256 verification | new code, copied from `crates/nacre-cms/src/verify.rs:253-273` (~20 lines) | the originals are private to `nacre-cms`, outside Owns; `x509-cert` verifies nothing; making them public is a change to another family |
| Judgement (`Crl::status`) | new code | no CRL judgement exists anywhere; RustCrypto leaves it to Nacre (ADR-0004) |
| HTTP download | dependency `ureq` 3, the agent pattern of `crates/nacre-conformance/src/client.rs:38-44,74-81` | the conformance client only reaches localhost DSS and is `publish = false` |
| Bench paths in the conformance test | `nacre_conformance::pki_dir()` (`crates/nacre-conformance/src/lib.rs:53`) as a dev-dependency | — |
| Forged test CRLs | `x509-cert` `CrlBuilder`/`CertificateBuilder` (feature `builder`), one small `BuilderProfile` impl for leaf and non-`cRLSign` issuer | `cabf::Root` always sets `cRLSign` (`cabf.rs:171`) and cannot name another issuer |
| Error enum, kind test, fuzz crate, hostile test, corpus README, forge example | the shapes of `nacre-cms` (`src/error.rs`, `fuzz/`, `tests/hostile.rs`, `tests/corpus/README.md`, `examples/forge_attacks.rs`) | — |

## Tasks
1. [x] **Crate skeleton and errors.** `crates/nacre-revocation/Cargo.toml` (edition 2024, `rust-version = "1.97"`, MIT OR Apache-2.0, `[lints] workspace = true`; deps `nacre-core` path+version, `der` 0.8 `alloc,oid`, `spki` 0.8, `x509-cert` 0.3, `sha2` 0.11, `p256` 0.14 `ecdsa`, `rsa = "=0.10.0-rc.19"`, `thiserror` 2, optional `ureq = { version = "3", default-features = false }`; feature `http = ["dep:ureq"]`; dev-deps `nacre-core` with `test-signer`, `x509-cert` with `builder`, `p256` with `pkcs8`, `der` with `pem`, `nacre-conformance` path). `src/lib.rs` starts with `#![forbid(unsafe_code)]` and an "Experimental" crate doc saying what is judged and what is left to s17. `src/error.rs`: one `thiserror` enum, `kind()` per ADR-0012: `Der`, `Certificate` → `InvalidInput`; `AlgorithmMismatch`, `SignatureInvalid` → `InvalidSignature`; `WrongIssuer`, `UnsupportedCriticalExtension(oid)`, `UnsupportedAlgorithm(oid)`, `IssuerNotCrlSigner`, `MissingNextUpdate`, `Expired { next_update }`, `NoDistributionPoint` → `Indeterminate`; `Http(ureq::Error)` (`cfg(feature = "http")`) → `Unavailable`. No message carries a URL's query, a path or a key.
   Test: `every_variant_has_its_kind` in `src/error.rs` (pattern `crates/nacre-cms/src/error.rs:117-147`), row count asserted.
2. [x] **Reading.** `src/crl.rs`: `Crl::from_der(&[u8]) -> Result<Crl, Error>` keeps the decoded `CertificateList` and the received `tbsCertList` TLV (cut with a `der::SliceReader`, never re-encoded); trailing bytes after the outer SEQUENCE are an error. Accessors `issuer() -> &Name`, `this_update() -> SystemTime`, `next_update() -> Option<SystemTime>`, `revoked() -> Result<Vec<RevokedEntry>, Error>` where `RevokedEntry { serial: Vec<u8>, date: SystemTime, reason: Option<CrlReason> }` (reason decoded from the entry's `id-ce-cRLReasons` extension; a malformed one is `Der`). Re-export `x509_cert::ext::pkix::CrlReason`. Commit an OpenSSL fixture set in `tests/corpus/openssl/` (P-256 CA, a leaf with `crlDistributionPoints = URI:http://crl.example.test/ca.crl`, a revoked leaf with `keyCompromise`, the CA's CRL with `-crldays 3650`, and an RSA-2048 CA with its own CRL), keys made in a `mktemp -d` and deleted, the commands in `tests/corpus/README.md` as `crates/nacre-cms/tests/corpus/README.md` does.
   Test: `tests/read.rs::openssl_crl_fields_are_read` — issuer equals the CA subject, both dates are those `openssl crl -text` prints (written in the README), one entry whose serial is the revoked leaf's, reason `KeyCompromise`.
3. [x] **Signature.** `Crl::verify_signature(&self, issuer_certificate: &[u8])`, in this order: `signatureAlgorithm` ≠ `tbsCertList.signature` → `AlgorithmMismatch`; issuer `keyUsage` present without `cRLSign` → `IssuerNotCrlSigner`; algorithm/key pair checked as `check_algorithms` does (`crates/nacre-cms/src/verify.rs:177-211`) → `UnsupportedAlgorithm` / `AlgorithmMismatch`; SHA-256 over the received TBS bytes, ECDSA P-256 or RSA PKCS#1 v1.5 → `SignatureInvalid`.
   Tests: `tests/read.rs::openssl_crls_verify_and_one_changed_byte_fails` — the P-256 and RSA CRLs verify with their CA; one byte flipped inside `thisUpdate` gives `SignatureInvalid` (not a decode error).
4. [x] **Judgement.** `Crl::status(&self, certificate: &[u8], issuer: &[u8], at: SystemTime) -> Result<CrlStatus, Error>`, `#[non_exhaustive] enum CrlStatus { NotRevoked, Revoked { date: SystemTime, reason: Option<CrlReason> } }`. Fixed order, each step ends the call: decode both certificates (`Certificate`); CRL issuer DER ≠ certificate's issuer DER or ≠ issuer certificate's subject DER → `WrongIssuer`; any critical CRL extension or critical entry extension → `UnsupportedCriticalExtension(oid)` (covers IDP, delta, `certificateIssuer`); `verify_signature`; `nextUpdate` absent → `MissingNextUpdate`; `nextUpdate < at` → `Expired`; serial lookup by `SerialNumber::as_bytes` → `Revoked` or `NotRevoked`. AKI is not judged (research, fact 5). The order is written in a comment and in the attacks file: each attack case must reach its own rule.
   Tests: `tests/status.rs::listed_leaf_is_revoked_with_date_and_reason`, `::unlisted_leaf_is_not_revoked` (OpenSSL fixtures, `at` = 2027-01-01), `::crl_issued_after_the_control_date_is_accepted` (`at` before `thisUpdate`, still `NotRevoked`).
5. [x] **Attack corpus and attacks file.** `examples/forge_attacks.rs` writes `tests/corpus/attacks/` deterministically (fixed p256 secrets, RFC 6979, fixed dates, `CrlBuilder::new_with_this_update`, never `CrlBuilder::new`), plus the certificates the cases need: `wrong-issuer.der` (validly signed by another CA), `bad-signature.der` (one TBS byte changed after signing), `stale.der` (`nextUpdate` 2026-06-01, judged at 2027-01-01), `no-next-update.der`, `critical-extension.der` (a critical `issuingDistributionPoint`), `algorithm-substitution.der` (outer `signatureAlgorithm` set to `sha256WithRSAEncryption` on an ECDSA CRL), `issuer-not-crl-signer.der` (issuer with `keyUsage digitalSignature` only, from a small `BuilderProfile`), `critical-entry-extension.der` (critical `certificateIssuer` on the leaf's entry). Each case is correctly signed apart from its one defect and lists the leaf, so a skipped rule would answer `Revoked`, not the expected error. `docs/security/attacks/revocation.md` in French, shaped as `docs/security/attacks/cms.md`: one row per case (attack, file, test, error), the check order, and "Hors de ce fichier": hostile DER (task 6), v1 CRL refused, the HTTP source fetching any URL a certificate names (bounded size and time, `http://` only, the caller may inject its own source), revocation in time left to s17.
   Tests: `tests/attacks.rs`, one per case, each asserting the exact `Error` variant (8 tests).
6. [x] **Hostile input and fuzz.** `tests/hostile.rs`: every truncation of the OpenSSL CRL and every length octet of its TLV headers set to `0x00`, `0x7f`, `0x81`, `0xff` (pattern `crates/nacre-cms/tests/hostile.rs`) returns `Err` from `from_der` or from `status`, never a panic; 200-deep nested SEQUENCE returns `Err`. `fuzz/` with its own `[workspace]`, `.gitignore` as `nacre-cms`'s, target `crl`: `from_der`, every accessor, `revoked()`, `verify_signature` and `status` with the fixture CA and leaf (`include_bytes!`) at a fixed date.
   Tests: `tests/hostile.rs::mutated_lengths_and_truncations_are_errors`, `::deep_nesting_is_an_error`.
7. [x] **HTTP source.** Under `cfg(feature = "http")`, `src/http.rs`: `pub struct HttpCrlSource` (agent with `timeout_global(Some(30 s))`, body limit 16 MiB), `HttpCrlSource::new()` and `Default`; `distribution_point(certificate) -> Result<String, Error>` takes the first `fullName` URI starting with `http://` from a `DistributionPoint` without `reasons` and without `cRLIssuer`, else `NoDistributionPoint`. `impl RevocationSource`: GET, read with the limit, `Crl::from_der` on the bytes (garbage is refused before it is labelled a CRL), return `RevocationData::Crl(bytes)`; every failure as `nacre_core::Error::Revocation(Box::new(error))`. `issuer` is unused by a CRL fetch, said in the doc. No other code path opens a connection.
   Tests: unit tests in `src/http.rs`: `distribution_point_of_the_fixture_leaf` (the README's URL) and `certificate_without_point_is_refused` (`TestSigner`'s certificate → `NoDistributionPoint`).
8. [x] **Bench conformance.** `tests/bench.rs`, `#![cfg(feature = "http")]`, `#[ignore = "conformance"]`: reads `signer.cert.pem`, `revoked.cert.pem`, `intermediate.cert.pem` from `nacre_conformance::pki_dir()`, fetches each leaf's CRL through `HttpCrlSource` as `&dyn RevocationSource`, judges it with `Crl::status` against the intermediate at a fixed date (2030-01-01): `revoked` → `Revoked` with `KeyCompromise`, `signer` → `NotRevoked`. No serial or key is hard-coded.
   Test: `revoked_is_listed_and_signer_is_not_on_the_bench` (run in `conformance.yml:41`; locally after `conformance/README.md`'s Run steps).
9. [x] **Full suite and type check**, once, after the last edit: `po-run --story s09-revocation-crl --label test -- 'cargo test --workspace'` and `po-run --story s09-revocation-crl --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`; `cargo fmt --all --check` before commit.

## Scene viewpoints
—

## Run interdicts
- Empty diff outside `crates/nacre-revocation/`, `docs/security/attacks/revocation.md`, `docs/research/s09-revocation-crl.md`, `docs/plans/s09-revocation-crl.md`, `docs/verif/s09-revocation-crl.md`: in particular `Cargo.toml`, `crates/nacre-core/`, `crates/nacre-cms/`, `crates/nacre-conformance/`, `conformance/`, `.github/`.
- No `[workspace.dependencies]`; no `cms` or `x509-tsp` crate (`grep -n 'cms\|x509-tsp' crates/nacre-revocation/Cargo.toml` empty).
- No clock in library code: `grep -rn 'SystemTime::now\|Time::now\|CrlBuilder::new(' crates/nacre-revocation/src` empty.
- No network outside `http`: `cargo tree -p nacre-revocation -e normal` without features lists no `ureq`.
- No output: `grep -rn 'println!\|eprintln!\|dbg!\|log::' crates/nacre-revocation/src` empty.
- No private key committed: `grep -rln 'PRIVATE KEY' crates/nacre-revocation` empty; `Cargo.lock` stays untracked.
- The signature is never checked over a re-encoding: `verify_signature` hashes the stored received TBS bytes (the reviewer reads `src/crl.rs`).
- No `unwrap`/`expect`/`panic`/indexing outside `#[cfg(test)]`, tests and the example (workspace lints, clippy `-D warnings`).

## The pivot
The whole story rests on **refusals being errors and `CrlStatus` holding only usable answers**, in a fixed order. Ways it could be wrong:
- s17 may need to tell "stale" from "wrong issuer" to choose a sub-indication (`TRY_LATER` vs `NO_POE`): compare the `Error` variants with EN 319 102-1 §5.2.5's revocation freshness checker; the variants are distinct, so s17 can match them, but `Expired` must keep its `next_update`.
- Refusing a missing `nextUpdate` may diverge from DSS, which s18's differential campaign will judge: compare with DSS's `CRLToken` handling on such a CRL before s17; flipping it later touches one rule and one test.
- Name equality by DER bytes is stricter than RFC 5280 §7.1 matching (case, spaces in `PrintableString`): it can only produce false `WrongIssuer`, never a false `NotRevoked`. Compare against a CA whose CRL issuer is re-encoded (UTF8String vs PrintableString) if a real PKI fails.

## Files touched
- `crates/nacre-revocation/Cargo.toml`, `src/{lib,error,crl,verify,http}.rs`
- `crates/nacre-revocation/tests/{read,status,attacks,hostile,bench}.rs`
- `crates/nacre-revocation/tests/corpus/{README.md,openssl/*,attacks/*}`
- `crates/nacre-revocation/examples/forge_attacks.rs`
- `crates/nacre-revocation/fuzz/{Cargo.toml,.gitignore,fuzz_targets/crl.rs}`
- `docs/security/attacks/revocation.md`

## Test strategy
Automated, 19 tests, within `Test budget` 25:
- Policy/judgement layer (the heart): `tests/status.rs` 3, `tests/attacks.rs` 8 — one refusal per rule the judgement owns, each on a case that would otherwise answer `Revoked`, so deleting a rule makes its test fail.
- Parsing and signature: `tests/read.rs` 2 (fields; P-256 and RSA verify, one byte breaks it), `tests/hostile.rs` 2.
- Error mapping: 1 exhaustive kind test.
- Adapter (HTTP): 2 unit tests on the distribution-point choice; the download itself is proven once, on the bench, by `tests/bench.rs` 1 (`#[ignore = "conformance"]`, CI conformance job). Body limit and timeout are `ureq`'s, not retested.
- Fuzz target `crl`, run by the CI fuzz job.
Checks: task tests with `cargo test -p nacre-revocation --test <stem>` (and `--lib` for unit tests); full suite and clippy once (task 9).
No visual check: `Surface: endpoint`.

## Done when
- One commit `s09-revocation-crl: <story title, in English as the decisions log rules>` landed through a pull request, describing what, why and how to check (`conformance/README.md` steps, then `cargo test -p nacre-revocation --all-features -- --ignored`).
- `cargo test --workspace` and clippy green; the conformance job green with `revoked_is_listed_and_signer_is_not_on_the_bench`.
- Every criterion: 1 → tasks 2–3; 2 → tasks 7–8; 3 → tasks 4–5 (`wrong-issuer`, `bad-signature`, `stale`); 4 → task 6 and `fuzz/`.
- A review with no open critical finding.
