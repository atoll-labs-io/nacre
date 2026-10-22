---
validated: yes
---
# Plan — s06-pades-bb

[Story](../stories.md) · [Research](../research/s06-pades-bb.md)

Branch `story/s06-pades-bb`. Read `docs/research/s06-pades-bb.md` first; this plan builds on it without repeating it.

No technical choice is left open: signing and layout are nacre-cms and nacre-pdf (ADR-0001, ADR-0004), every dependency is already in the workspace, and the API shape is the story's. The reserved ADR-0013 is not used.

Validated autonomously (`Plan validation: autonomous`): no human reviewed this plan. Criterion 1 → task 4 (`bench_signature_is_pades_baseline_b`); 2 → task 3 (`signature_is_cades_detached_with_time_in_m`); 3 → tasks 3 (`second_signature_takes_a_new_revision`) and 4 (`both_bench_signatures_are_pades_baseline_b`); 4 → task 3 (prefix asserted after the first and the second signature); 5 → tasks 2 and 3, in the concrete form below.

**Criterion 5 is implemented in this concrete form** (issue #9, research's first fact): the bytes reserved for `/Contents` are the length of the CMS written with the longest signature value the signer's algorithm allows, so after embedding, the zeros left equal that longest length minus the real signature length. The lead should rewrite `docs/stories.md:114` to say so; the implementer does not edit `docs/stories.md`.

## Story
Sign a PDF at PAdES-BASELINE-B with a `Signer`, judged `PAdES-BASELINE-B` by DSS.
1. Bench signer + s02 PKI → DSS `TOTAL_PASSED`, `PAdES-BASELINE-B`.
2. `/SubFilter /ETSI.CAdES.detached`; CMS has `signingCertificateV2`, never `signingTime`; the time is `/M` of `/Sig`.
3. A signed PDF takes a second signature in a new revision; DSS: both `PAdES-BASELINE-B`.
4. Original bytes are an exact prefix.
5. `/Contents` reserve = CMS length with the longest signature value (above).

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Revision, `/Sig` dictionary, `/ByteRange`, zero-filled `/Contents`, embedding | already here: `Update::sign` `crates/nacre-pdf/src/revision.rs:136`, `PreparedSignature::{signed_parts, embed}` `:503,512` | — |
| CMS with `signingCertificateV2`, `signingTime` refused | already here: `sign_detached` + `Profile::PADES` `crates/nacre-cms/src/sign.rs:27,45` | — |
| SHA-256 of the two signed parts | installed dependency `sha2` 0.11 (as in `crates/nacre-cms/Cargo.toml:17`) | nothing in the repository hashes a PDF range; `std` has no SHA-256 |
| Signing time type | installed dependency `der::DateTime` (`crates/nacre-cms/Cargo.toml:14`) | no time type in nacre-core; `std::time::SystemTime` has no calendar fields |
| Reserve computation (`src/reserve.rs`) | new code, ~40 lines | nacre-cms exposes no size computation and is not this story's to change; a constant is what criterion 5 forbids |
| `/M` date text `D:YYYYMMDDHHmmSSZ` | `std` (`format!` with `{:04}{:02}…`) over `der::DateTime` getters | nothing in the repository writes PDF dates |
| Field name `SignatureN` | new code, a loop over `Document::signature_fields()` `crates/nacre-pdf/src/document.rs:107` | nacre-pdf takes a name, never chooses one |
| Bench signer (tests only) | new code in `tests/support/mod.rs` over installed `p256` (`pkcs8`, `pem` features) and `der` (`pem`) | `TestSigner` self-signs (`crates/nacre-core/src/test_signer.rs:33,47`) and nacre-core is frozen |
| DSS verdicts | already here: `nacre_conformance::Dss` `crates/nacre-conformance/src/client.rs:48,60`, `pki_dir()` `lib.rs:53` | — |
| Fixture PDF | already here: `conformance/reference/unsigned.pdf`, copied into `tests/corpus/` | the convention puts a crate's test data under its own `tests/corpus/` |

## Tasks
1. [x] **Crate skeleton and error.** `crates/nacre-pades/Cargo.toml`: `name = "nacre-pades"`, `version = "0.1.0"`, `edition = "2024"`, `rust-version = "1.97"`, `license = "MIT OR Apache-2.0"`, a `description`, `[lints] workspace = true`; dependencies `nacre-core`, `nacre-cms`, `nacre-pdf` (each `path` + `version = "0.1.0"`), `sha2 = "0.11"`, `der = { version = "0.8", features = ["alloc"] }`, `x509-cert = "0.3"`, `thiserror = "2"`; dev-dependencies `nacre-core` with `features = ["test-signer"]`, `nacre-conformance = { path = "../nacre-conformance", features = ["http"] }` (**no `version`**, it is `publish = false`), `p256 = { version = "0.14", features = ["ecdsa", "pkcs8", "pem"] }`, `der` with `pem`. `src/lib.rs`: `#![forbid(unsafe_code)]`, crate doc starting with **Experimental** (as `crates/nacre-cms/src/lib.rs:2`), saying B-B only, revocation data never in the CMS, the time is the caller's; `pub use error::Error; pub use sign::sign; pub use der::DateTime;`. `src/error.rs`: `#[non_exhaustive] #[derive(Debug, thiserror::Error)] pub enum Error { Pdf(#[from] nacre_pdf::Error), Cms(#[from] nacre_cms::Error) }`, messages without input-dependent detail beyond the inner error, `pub fn kind(&self) -> nacre_core::ErrorKind` delegating to each inner `kind()`, no wildcard arm.
   Test that fails if wrong: unit test `every_variant_has_its_kind` in `error.rs`, as `crates/nacre-cms/src/error.rs:104-147`: `Pdf(DuplicateField)` → `InvalidInput`, `Pdf(Encrypted)` → `Indeterminate`, `Cms(SignatureInvalid)` → `InvalidSignature`, `Cms(Signer(nacre_core::Error::Signer(..)))` → `Signer`; fails if a variant maps to a fixed kind instead of delegating.
2. [x] **Computed reserve** `src/reserve.rs` (`pub(crate)`). `fn max_signature_len(algorithm: SignatureAlgorithm, certificate: &[u8]) -> Result<usize, nacre_core::Error>`: `EcdsaP256Sha256` → 72 (DER `ECDSA-Sig-Value`, two 33-byte integers); `RsaPkcs1v15Sha256` → length of the raw `subject_public_key` bit string of the certificate's SPKI (`x509_cert::Certificate::from_der`), which always exceeds the modulus length; any other → `nacre_core::Error::Signer("unsupported signature algorithm")`. A private `struct Sizing<'s> { inner: &'s dyn Signer }` implements `Signer`: `algorithm` and `certificate_chain` delegate, `sign_digest` returns `vec![0; max_signature_len(..)?]` and **never calls `inner.sign_digest`**. `fn contents_capacity(signer: &dyn Signer) -> Result<usize, Error>` = `nacre_cms::sign_detached(&[0; 32], &Sizing { inner: signer }, &Profile::PADES, None)?.len()`. Doc comment: the single place s08 adds the timestamp token's reserve to; B-B reserves nothing for a token. Copy `crates/nacre-cms/tests/corpus/openssl/rsa-detached.der` to `crates/nacre-pades/tests/corpus/rsa-detached.der`.
   Test that fails if wrong: unit test `rsa_bound_covers_the_signature` in `reserve.rs`: reads the copied file with `nacre_cms::SignedData::from_der`, takes `certificates[0]` and `signer_infos[0].signature`, asserts `max_signature_len(RsaPkcs1v15Sha256, cert) >= signature.len()` and `< signature.len() + 64` (fails on a bound read from the wrong field or a constant).
3. [x] **`sign`** `src/sign.rs`: `pub fn sign(pdf: &[u8], signer: &dyn Signer, signing_time: DateTime) -> Result<Vec<u8>, Error>`, in this order: `Document::parse(pdf)?`; `contents_capacity(signer)?`; field name = `Signature<N>`, the smallest `N >= 1` no entry of `signature_fields()` carries; entries = one `/M` as `Object::String(b"D:YYYYMMDDHHmmSSZ")` built from `signing_time`; `doc.update().sign(SignatureSpec { field, sub_filter: b"ETSI.CAdES.detached".to_vec(), contents_len: capacity, entries })?`; SHA-256 over both `signed_parts()`; `nacre_cms::sign_detached(&digest, signer, &Profile::PADES, None)?` — the only call that reaches the real signer; `prepared.embed(&cms)?`. Rustdoc on `sign`: what it writes, that the caller supplies the time (`DateTime::from_system_time` for now), that the signer signs once. Copy `conformance/reference/unsigned.pdf` to `crates/nacre-pades/tests/corpus/unsigned.pdf`; `tests/corpus/README.md` gives the source of both corpus files (fictitious document; openssl-made CMS with a public test certificate). `tests/sign.rs` (file-level `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]`, `TestSigner::from_secret(&[0x11; 32])`, time `DateTime::new(2026, 10, 22, 8, 0, 0)`), with a helper that rereads a signed PDF, follows each field's `/V`, returns `/ByteRange`, the decoded `/Contents` and the CMS cut at its DER length (`der::Header`):
   - `signature_is_cades_detached_with_time_in_m`: one field; `/Filter /Adobe.PPKLite`, `/SubFilter /ETSI.CAdES.detached`, `/M` = `D:20261022080000Z`; the CMS's signed attributes hold `oid::SIGNING_CERTIFICATE_V2`, not `oid::SIGNING_TIME`, its `crls` is empty; `verify_detached_digest(SHA-256 of the bytes the ByteRange names)` passes. Fails if a time goes into the CMS, the sub-filter changes, or the digest covers other bytes.
   - `second_signature_takes_a_new_revision`: sign, then sign the result; `once.starts_with(input)` and `twice.starts_with(&once)`; two fields with different names; revisions = original + 2; the first field's `ByteRange` ends at `once.len()`; both CMS verify over their own ranges. Fails if the second signature rewrites the first revision or reuses a name.
   - `reserve_leaves_only_the_signature_slack`: decoded `/Contents` length − CMS length == 72 − `signer_infos[0].signature.len()`. Fails on any constant reserve or a reserve sized another way.
   - `the_signer_signs_once`: a counting `Signer` in the test, wrapping `TestSigner` with a `Cell<usize>`, sees `sign_digest` called exactly once by `sign`. Fails if the dry run delegates to the real signer.
   - `refusal_returns_the_pdf_error`: `sign(b"not a pdf", ..)` gives `Error::Pdf(_)` whose `kind()` is `InvalidInput`, and the counting signer is never called. Fails if signing starts before the document is read.
4. [x] **Bench signer and conformance.** `tests/support/mod.rs`: `pub struct BenchSigner { key: p256::ecdsa::SigningKey, chain: Vec<Vec<u8>> }`, no `Debug`; `BenchSigner::load()` reads `nacre_conformance::pki_dir()` `signer.key.pem` (`SigningKey::from_pkcs8_pem`), `signer.cert.pem` then `intermediate.cert.pem` (`der::pem::decode_vec`, label `CERTIFICATE`), panicking with "start the bench: conformance/README.md" when absent; `Signer` impl as `TestSigner`'s (`crates/nacre-core/src/test_signer.rs:61-72`: digest length check, `sign_prehash` → `DerSignature`). `tests/conformance.rs`, both `#[ignore = "conformance"]`, fixed time `DateTime::new(2026, 10, 22, 8, 0, 0)`, inside the bench certificates' validity (2026-01-01 to 2046-01-01, `conformance/pki/README.md`):
   - `bench_signature_is_pades_baseline_b`: removes a stale `reports_dir()/s06-pades-b.xml`, signs `tests/corpus/unsigned.pdf`, `Dss::from_env()?.validate("s06-pades-b", ..)`: one signature, `TotalPassed`, no sub-indication, `format == "PAdES-BASELINE-B"`, the report file exists.
   - `both_bench_signatures_are_pades_baseline_b`: signs twice, validates `"s06-pades-b-twice"`: two signatures, each `TotalPassed`, no sub-indication, `format == "PAdES-BASELINE-B"`.
   Test that fails if wrong: both fail on a chain DSS cannot build, a missing `signingCertificateV2`, a forbidden `signingTime` (DSS then reports `PAdES-BES` or `PDF-NOT-ETSI`), or a first signature broken by the second revision.
5. [x] **Checks.** `po-run --story s06-pades-bb --label test -- 'cargo test --workspace'` then `po-run --story s06-pades-bb --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`. The conformance tests are not run locally when the bench is down; CI's `conformance.yml` runs them (`cargo test --workspace --all-features -- --ignored`) with no workflow change. If the bench is up locally, run `cargo test -p nacre-pades --test conformance -- --ignored` once and keep `target/conformance/s06-*.json` out of git.
   Test that fails if wrong: the two `po-run` rows of `docs/verif/s06-pades-bb.md`.

## Scene viewpoints
—

## Run interdicts
- Empty diff outside `crates/nacre-pades/` and `docs/` (research, plan, verif): in particular `crates/nacre-core/`, `crates/nacre-cms/`, `crates/nacre-pdf/`, `crates/nacre-conformance/`, `conformance/`, root `Cargo.toml`, `.github/`, `docs/stories.md`, `docs/security/`.
- No `[workspace.dependencies]`, no `Cargo.lock` committed, no `cms` or `x509-tsp` crate, no dependency absent from the workspace today (`cargo tree -p nacre-pades` lists only crates other workspace members already use).
- `crates/nacre-pades/src/` reads no clock: `grep -rn "SystemTime\|Instant" crates/nacre-pades/src` is empty.
- No write to stdout, stderr or a logger in `src/`; no `unsafe`.
- No reserve for a timestamp token, no `/DSS`, no level parameter: s08 and s11.
- Issues #46 and #48 are not fixed here (nacre-pdf belongs to another story).
- No fuzz target: nacre-pades parses nothing itself.

## The pivot
The reserve is the length of a dry-run CMS written by `sign_detached` through a signer that returns a longest-length placeholder. It rests on the CMS length depending on the signature value's length alone. Ways it could be wrong:
- `sign_detached` writes something that varies between the dry run and the real run (a digest of another length, a time): compare `sign.rs:85-104` — the digest is always 32 bytes and no time is passed; `reserve_leaves_only_the_signature_slack` checks the equality on real bytes.
- The bound is too short for a real signer: 72 bytes is the P-256 DER maximum; RSA's bound is checked by `rsa_bound_covers_the_signature`; a signer exceeding it yields `SignatureTooLarge`, never a truncated file (`revision.rs:512-518`).
- The dry run reaches the real key: `the_signer_signs_once` and the `Sizing` code (no `inner.sign_digest`).
Second place to look: DSS's verdict on the first signature once a second revision exists (task 4), and on `ESSCertIDv2` without `issuerSerial` (research, Traps); a failure there points to nacre-cms or nacre-pdf, to be filed, not patched here.

## Files touched
- `crates/nacre-pades/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/reserve.rs`, `src/sign.rs`
- `crates/nacre-pades/tests/sign.rs`, `tests/conformance.rs`, `tests/support/mod.rs`
- `crates/nacre-pades/tests/corpus/unsigned.pdf`, `tests/corpus/rsa-detached.der`, `tests/corpus/README.md`
- `docs/research/s06-pades-bb.md`, `docs/plans/s06-pades-bb.md`, `docs/verif/s06-pades-bb.md`

## Test strategy
Automated, 9 tests, within `Test budget` 25:
- Unit (inside `src/`): `every_variant_has_its_kind` (task 1), `rsa_bound_covers_the_signature` (task 2) — the only places a private bound and the kind mapping can be reached.
- Service (`tests/sign.rs`, `TestSigner`, no network): the four business rules of `sign` (CAdES detached and `/M`, second revision with prefix, computed reserve, one signature only) and one refusal (unreadable PDF, signer untouched). nacre-pdf's own refusals (DocMDP `/P 1`, taken name, oversized slot) are not replayed: they are covered in `crates/nacre-pdf/tests/revision.rs`.
- Conformance (`tests/conformance.rs`, ignored, CI): the two DSS verdicts, the only judge of "baseline B" the criteria name.
Visual checks: none (library). Full suite and clippy once, at the end (task 5).

## Done when
One commit `s06-pades-bb: Signer un PDF au niveau PAdES-BASELINE-B` landed through a pull request; `cargo test --workspace` and clippy green; the CI conformance job green with both s06 tests passing; a review with no open critical finding; the lead has rewritten criterion 5 in `docs/stories.md` and closed or updated issue #9 for s06.
