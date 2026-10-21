---
validated: yes
---
# Plan — s01-workspace-contract

[Story](../stories.md) · [Research](../research/s01-workspace-contract.md)

Branch `story/s01-workspace-contract`. Read `docs/research/s01-workspace-contract.md` first; this plan builds on it without repeating it.

The type boundary and error transport of the contract are settled by [ADR-0010](../decisions/0010-core-contract-speaks-der-and-one-error.md) (accepted by the owner on 2026-10-21): DER bytes at the boundary, object-safe traits, one `nacre_core::Error` with boxed sources. Turned down: an associated `type Error` per trait; RustCrypto types at the boundary.

## Story
Create the cargo workspace, the contract crate `nacre-core` and the CI. Criteria (`docs/stories.md:19-25`), with the research's correction to criterion 2:
1. `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --check` pass locally and in `.github/workflows/ci.yml`.
2. `Signer` (algorithm, certificate chain, sign a digest), `TimestampAuthority` (digest → DER token), `RevocationSource` (certificate **and its issuer** → DER CRL or OCSP response), synchronous, no I/O.
3. `ValidationReport`: indication, sub-indication, level reached, EN 319 102-1 names.
4. A P-256 test signer behind `test-signer`, never default; a contract test verifies it with `p256`.
5. CI runs every target of every `crates/*/fuzz/` for 60 s, with no later workflow edit.
6. `#![forbid(unsafe_code)]` in `nacre-core`; `Cargo.lock` in `.gitignore`.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Lint rule shared by every crate | Platform: cargo `[workspace.lints.clippy]` + `[lints] workspace = true` | Nothing in this repository; `clippy.toml` is outside Owns |
| `Error` enum | Dependency `thiserror` 2 (convention `AGENTS.local.md:97`) | Nothing in the repository; std alone means hand-written `Display`/`source` against the convention |
| The three traits, `RevocationData`, algorithm enums | New code, shaped on Patelle (`lib/src/signer/mod.rs:15-30`, `lib/src/tsa/mod.rs:9-15`) | Patelle is another repository and must stay untouched; std and RustCrypto define no such contract |
| `ValidationReport` and its enums | New code, names copied from DSS 6.5.1 `Indication.java`, `SubIndication.java`, `SignatureLevel.java`, `SignatureProfile.java` | No Rust crate carries EN 319 102-1 indications; the judge's spelling is the one to match (ADR-0007) |
| Test signer key, signature, certificate | Dependencies `p256` 0.14 (`SigningKey`, `PrehashSigner<der::Signature>`) and `x509-cert` 0.3 builder (ADR-0004) | Not installed yet (empty repository); Nacre writes only the glue, no primitive or X.509 code |
| Digest length check | New code, two lines, `DigestAlgorithm::output_len()` | `ecdsa`'s `sign_prehash` accepts other lengths (bits2field), so it would not refuse a SHA-1 or truncated digest |
| Fuzz discovery | `cargo fuzz list` / `cargo fuzz run` (ADR-0008) | No repository code; parsing `fuzz/Cargo.toml` by hand would be new code for what cargo-fuzz answers |

## Tasks
1. [x] **Workspace root.** `Cargo.toml`: a virtual manifest, `[workspace] resolver = "3"`, `members = ["crates/*"]`, and `[workspace.lints.clippy]` with `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` at `"deny"` — nothing else (no `[workspace.dependencies]`, no `[workspace.package]`). `rust-toolchain.toml`: `channel = "1.97"`, `components = ["clippy", "rustfmt"]`, `profile = "minimal"`. `.gitignore`: append `/target` and `Cargo.lock`, keep its two lines (`.gitignore:1-2`). Check: `git check-ignore Cargo.lock target` prints both; `cargo metadata --no-deps` succeeds once task 2 exists. Expect cargo to download 1.97 on first call.
2. [x] **`crates/nacre-core` skeleton.** `Cargo.toml`: `name = "nacre-core"`, `version = "0.1.0"`, `edition = "2024"`, `rust-version = "1.97"`, `license = "MIT OR Apache-2.0"`, `description`, `[lints] workspace = true`. `[dependencies]`: `thiserror = "2"`; optional `p256 = { version = "0.14", features = ["ecdsa", "pkcs8"] }`, `x509-cert = { version = "0.3", features = ["builder"] }`. `[features]`: `default = []`, `test-signer = ["dep:p256", "dep:x509-cert"]`. `[dev-dependencies]`: `nacre-core = { path = ".", features = ["test-signer"] }` (makes `cargo test --workspace` run the contract test; verified in a scratch crate, research Traps), `p256`, `sha2 = "0.11"`, `x509-cert`, `der = "0.8"`. `src/lib.rs`: `#![forbid(unsafe_code)]` first, crate rustdoc in English stating the contract role, module declarations and re-exports. Check: `cargo build -p nacre-core` and `cargo tree -p nacre-core -e normal --depth 1` lists `thiserror` only.
3. [x] **Error and algorithms** (`src/error.rs`, `src/algorithm.rs`). `pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>`. `#[non_exhaustive] #[derive(Debug, thiserror::Error)] pub enum Error`: `DigestLength { expected: usize, actual: usize }`, `Signer(#[source] BoxError)`, `Timestamp(#[source] BoxError)`, `Revocation(#[source] BoxError)`, each with an English message that never prints a secret. `#[non_exhaustive] enum SignatureAlgorithm { EcdsaP256Sha256, RsaPkcs1v15Sha256 }` (s13 needs both, `docs/stories.md:232`) with `fn digest(self) -> DigestAlgorithm`; `#[non_exhaustive] enum DigestAlgorithm { Sha256, Sha384, Sha512 }` with `fn output_len(self) -> usize`. Both `Debug, Clone, Copy, PartialEq, Eq, Hash`. Test: covered by tasks 5 and 6 (the length refusal and the source chain).
4. [x] **The traits** (`src/signer.rs`, `src/timestamp.rs`, `src/revocation.rs`), object-safe, no supertrait, no generic method, no I/O in the crate:
   - `trait Signer { fn algorithm(&self) -> SignatureAlgorithm; fn certificate_chain(&self) -> &[Vec<u8>]; fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, Error>; }` — rustdoc: chain is DER, the signer's own certificate first, then issuers towards the anchor, never empty; `digest` is computed with `algorithm().digest()`; ECDSA output is a DER `ECDSA-Sig-Value` (as Patelle, `lib/src/signer/mod.rs:21`), RSA output the raw signature.
   - `trait TimestampAuthority { fn timestamp(&self, algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<Vec<u8>, Error>; }` — returns the DER `TimeStampToken`; only the imprint leaves the caller (`docs/stories.md:135`). Patelle's `url()` is dropped: naming the endpoint is the implementation's error message.
   - `#[non_exhaustive] enum RevocationData { Crl(Vec<u8>), Ocsp(Vec<u8>) }` and `trait RevocationSource { fn revocation(&self, certificate: &[u8], issuer: &[u8]) -> Result<RevocationData, Error>; }`.
   Test: task 6's `contract_objects.rs` uses all three through `&dyn`.
5. [x] **Validation report** (`src/report.rs`). `#[non_exhaustive] enum Indication { TotalPassed, TotalFailed, Indeterminate }`; `#[non_exhaustive] enum SubIndication` with the 25 EN 319 102-1 values of DSS 6.5.1 `SubIndication.java` (FORMAT_FAILURE … SIGNED_DATA_NOT_FOUND; not DSS's own `ATTESTATION_CONSTRAINTS_FAILURE`) and `pub const ALL: [SubIndication; 25]`; both with `fn as_str(self) -> &'static str` (`"TOTAL_PASSED"`, `"FORMAT_FAILURE"`) and `fn urn(self) -> &'static str` (`urn:etsi:019102:mainindication:total-passed`, `urn:etsi:019102:subindication:FORMAT_FAILURE`). `#[non_exhaustive] enum SignatureForm { CAdES, PAdES, XAdES, JAdES, Pkcs7 }`, `#[non_exhaustive] enum SignatureProfile` mirroring DSS's 16 values (BaselineB … NotEtsi), `struct SignatureLevel { pub form, pub profile }`. `struct ValidationReport` with private fields and constructors `passed(level: Option<SignatureLevel>)`, `failed(sub: SubIndication, level)`, `indeterminate(sub: SubIndication, level)`, getters `indication()`, `sub_indication() -> Option<SubIndication>`, `level()`; `Debug, Clone, PartialEq, Eq`. Tests in `tests/report.rs`: `names_match_dss_6_5_1` (a literal list of the 25 names and 3 indications, compared with `ALL`, `as_str` and `urn`) — fails on any misspelling, missing or extra value; `passed_carries_no_sub_indication` — fails if a constructor mixes indication and sub-indication.
6. [x] **Test signer and contract tests.** `src/test_signer.rs` behind `#[cfg(feature = "test-signer")]`: `pub struct TestSigner { key: p256::ecdsa::SigningKey, chain: Vec<Vec<u8>> }`, **no `Debug`** (`AGENTS.local.md:98`). `TestSigner::from_secret(secret: &[u8; 32]) -> Result<Self, Error>`: `SigningKey::from_slice`, then a self-signed certificate with `CertificateBuilder::new(profile, SerialNumber::from(1u32), validity, spki)` and `.build::<_, p256::ecdsa::DerSignature>(&key)` (x509-cert 0.3, `src/builder.rs:173-178`), profile `cabf::Root::new(false, "CN=Nacre test signer,O=Nacre tests,C=FR")` (C, O, CN required, `cabf.rs:72-99`), validity fixed 2026-01-01 → 2036-01-01 from constants, never the clock; failures map to `Error::Signer`. `sign_digest` refuses a length other than `algorithm().digest().output_len()` with `Error::DigestLength`, then `PrehashSigner<DerSignature>::sign_prehash`. Tests, each file starting with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]`:
   - `tests/contract_signer.rs::signature_verifies_with_chain_key` — decode `certificate_chain()[0]` with `x509_cert::Certificate::from_der`, `VerifyingKey::from_sec1_bytes` on its SPKI, then for a few SHA-256 digests `Signature::from_der` (strict) and `verify_prehash` (shape of Patelle `lib/tests/contract_signer.rs:55-76`); asserts `algorithm() == EcdsaP256Sha256`. Fails if the chain's key is not the signing key, or the output is raw `r||s`.
   - `tests/contract_signer.rs::wrong_digest_length_is_refused` — a 20-byte digest gives `Error::DigestLength { expected: 32, actual: 20 }`. Fails if the guard goes.
   - `tests/contract_objects.rs::implementations_travel_as_trait_objects` — stub `TimestampAuthority` returning `Error::Timestamp(Box::new(std::io::Error::other("tsa down")))`, stub `RevocationSource` returning `RevocationData::Ocsp`, and the `TestSigner`, all called through `&dyn`; asserts `std::error::Error::source(&err)` downcasts to `io::Error` with that message. Fails if a trait stops being object-safe or `#[source]` is dropped.
   Run: `cargo test -p nacre-core --test contract_signer --test contract_objects --test report`.
7. [x] **CI** (`.github/workflows/ci.yml`), on `push` to `main` and `pull_request`:
   - job `check` (ubuntu-latest): checkout; `rustup toolchain install` (no argument: installs the one of `rust-toolchain.toml`); `cargo fmt --all --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace`. No `Cargo.lock` cache key (unversioned).
   - job `fuzz`: a step lists `crates/*/fuzz` with `shopt -s nullglob` into a step output; with none, it prints "no fuzz targets" and the job ends green; otherwise `rustup toolchain install nightly --profile minimal`, `cargo +nightly install cargo-fuzz --locked`, then for each folder, in its crate directory, `cargo +nightly fuzz list` and `cargo +nightly fuzz run <target> -- -max_total_time=60` per target. Bash with `set -euo pipefail`, so a crash fails the job. The loop reads folders and targets only, so s03 onward add targets without touching the workflow.
   Check: the workflow runs green on the pull request; locally, `python3 -I -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" .github/workflows/ci.yml` if PyYAML is present, otherwise the reviewer reads it.

## Scene viewpoints
—

## Run interdicts
- Patelle untouched: `git -C /home/lecrabe/dev/atoll/patelle status --porcelain` empty and `story/s01-sign-decision` still at `4ed5c64`.
- `git diff --name-only main...` lists only `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `crates/nacre-core/**`, `.github/workflows/ci.yml`, `docs/research/s01-workspace-contract.md`, `docs/plans/s01-workspace-contract.md`, `docs/decisions/0010-core-contract-speaks-der-and-one-error.md`. In particular `README.md`, `AGENTS*.md`, `docs/architecture.md`, `docs/stories.md` keep an empty diff.
- No `Cargo.lock`, `clippy.toml`, `rustfmt.toml` or `crates/nacre-core/fuzz/` committed (`nacre-core` parses nothing).
- Root `Cargo.toml` holds `[workspace]` and `[workspace.lints.clippy]` only.
- `nacre-core` features: `default = []`; `cargo tree -p nacre-core -e normal --depth 1` shows `thiserror` alone.
- `grep -rnE "std::(fs|net)|SystemTime|from_now|println|eprintln|unsafe" crates/nacre-core/src` finds nothing but the `forbid` line.
- No `cms`, `x509-tsp`, `ureq` or other network crate in any `Cargo.toml`.
- `TestSigner` derives and implements neither `Debug` nor `Display`.
- Do not add tests for each enum value, nor for `DigestAlgorithm::output_len` pair by pair.

## The pivot
The plan rests on ADR-0010 option 1: DER bytes and one boxed-source `Error` across the traits. It could be wrong if (a) a family needs a typed value the bytes lose — compare with s03's need to read the chain (`docs/stories.md:57`) and s13's PIN states (`:234`), which must survive as a `downcast_ref` on the source; (b) the person prefers associated error types for exhaustive matching — that rewrites tasks 3, 4 and 6. Two smaller hinges: the self dev-dependency is what makes `cargo test --workspace` run the contract tests — check the test output lists `contract_signer` with 2 passed, not 0; and the sub-indication list must equal DSS 6.5.1's `SubIndication.java`, the judge s18 compares against.

## Files touched
`Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `crates/nacre-core/Cargo.toml`, `crates/nacre-core/src/{lib,error,algorithm,signer,timestamp,revocation,report,test_signer}.rs`, `crates/nacre-core/tests/{contract_signer,contract_objects,report}.rs`, `.github/workflows/ci.yml`; already written: this plan, the research, ADR-0010.

## Test strategy
Automated, 5 tests out of a budget of 25, all at the contract layer of `nacre-core` (no service, adapter or persistence layer exists):
- `contract_signer.rs`: 2 (the normal case against the chain's key; the one refusal the signer owns).
- `contract_objects.rs`: 1 (object safety and error-source transport, the rule of ADR-0010).
- `report.rs`: 2 (the DSS/EN names as a data contract; indication/sub-indication consistency).
Not tested on purpose: enum pairs, `Display` texts, getters. `unsafe` forbiddance, default features and lints are checked by the compiler, `cargo tree` and the reviewer.
Checks: `cargo fmt --all --check`; full suite `Test` and `Typecheck` once at the end through `po-run`.
Visual checks: none (library). The CI fuzz job's non-empty branch is first exercised by s03; s03's research must confirm its `fuzz/Cargo.toml` declares its own `[workspace]`.

## Done when
- Every criterion of the story holds, criterion 2 with the issuer argument; ADR-0010 accepted.
- `cargo fmt --all --check`, `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass on toolchain 1.97, the last two recorded by `po-run`.
- Both CI jobs are green on the pull request.
- `docs/research`, `docs/plans` and ADR-0010 committed with the code, in a commit `s01-workspace-contract: Le workspace et le contrat commun signataire, horodatage, révocation, rapport`.
