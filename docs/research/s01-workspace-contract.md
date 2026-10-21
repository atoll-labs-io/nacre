# Research — s01-workspace-contract

[Story](../stories.md)

## Structuring facts
- Story assumption false: `RevocationSource` as "certificat → CRL ou réponse OCSP DER" cannot serve OCSP, whose request is built "pour un certificat et son émetteur" (`docs/stories.md:180`): the trait must take the issuer certificate too. The story's criterion 2 should read "(certificat et son émetteur → CRL ou réponse OCSP DER)".
- Story assumption partly false: "reprendre les traits de Patelle" cannot be a copy. Patelle's `Signer` returns one certificate and knows P-256 only (`patelle story/s01-sign-decision:lib/src/signer/mod.rs:15-30`), its TSA takes a SHA-256 imprint only (`lib/src/tsa/mod.rs:13-14`), its errors are PKCS#11-specific (`lib/src/signer/mod.rs:79-99`), and it builds on `x509-cert` 0.2, `p256` 0.13, `der` 0.7 (`patelle:Cargo.toml:18-23`) where ADR-0004 sets 0.3, 0.14, 0.8 (`docs/decisions/0004-rustcrypto-foundations-and-x509-boundary.md:24`), whose builder API differs.
- The repository holds no code at all: no `Cargo.toml`, no `crates/`, no `.github/` (worktree survey, ADR-0002 `docs/decisions/0002-empty-repository-base.md:21`); this story creates every file it touches.
- The trait boundary types (DER bytes or RustCrypto types) and the way implementation errors travel through the traits are left open by the architecture and every ADR: a structural choice, drafted as ADR-0010 (`status: proposed`) and waiting for a human.
- The CI fuzz loop cannot be exercised by this story: no `crates/*/fuzz/` exists before s03 (`docs/stories.md:60`), so criterion 5 is only provable on the first story that adds a target.

## Story
s01 creates the cargo workspace, the shared contract crate `nacre-core` and the CI. Complexity written: 2. Owns: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `crates/nacre-core/`, `.github/workflows/ci.yml` (`docs/stories.md:17`).

Acceptance criteria (`docs/stories.md:19-25`):
1. `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo fmt --check` pass locally and in `.github/workflows/ci.yml`.
2. `nacre-core` exposes `Signer` (algorithm, certificate chain, signing a digest), `TimestampAuthority` (digest → DER token) and `RevocationSource` (certificate → DER CRL or OCSP response), synchronous and without I/O.
3. `nacre-core` exposes `ValidationReport`: indication (`TOTAL_PASSED`, `TOTAL_FAILED`, `INDETERMINATE`), sub-indication and level reached, with EN 319 102-1 names.
4. A software test signer (P-256, behind feature `test-signer`, never default) signs a digest; a contract test verifies it with `p256`.
5. CI runs every fuzz target of every present `crates/*/fuzz/` for 60 seconds, with no later story editing the workflow.
6. `nacre-core` carries `#![forbid(unsafe_code)]`; `Cargo.lock` is listed in `.gitignore`.

## Current code
- Root: `AGENTS.md`, `AGENTS.local.md`, `README.md`, `IDEE.md`, licences, `.gitignore`, `.polype/`, `docs/`. No Rust file.
- `.gitignore:1-2` holds `.worktrees/` and `.env*` only; neither `Cargo.lock` nor `target/`.
- `README.md` says "Status: framing, no code yet" — owned by s20 (`docs/architecture.md:64`), not by this story.
- Toolchain on this machine: `rustc 1.99.0`, rustup 1.29.1, only `stable`/`1.99` installed; no nightly, no `cargo-fuzz`, no `actionlint`. Rust 1.97 is published (`static.rust-lang.org/dist/channel-rust-1.97.toml` answers 200).

## Attachment points
- `Cargo.toml` — `members = ["crates/*"]`, resolver 3, frozen after s01 (`AGENTS.local.md:91`, ADR-0003 `:18,26`).
- `crates/nacre-core/src/lib.rs` — the three traits and `ValidationReport` (`docs/architecture.md:71`).
- `.github/workflows/ci.yml` — the fuzz job over `crates/*/fuzz/` (`docs/architecture.md:70`).
- Later crates attach by folder only; `crates/<crate>/fuzz/` is two levels deep, so it is **not** matched by `crates/*` and stays outside the workspace.

## Verified interfaces
Patelle, branch `story/s01-sign-decision` (read with `git show`, never modified):
- `lib/src/signer/mod.rs:15-23` — `trait Signer { fn algorithm(&self) -> Algorithm; fn certificate_der(&self) -> &[u8]; fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SignerError>; }`, output is DER `ECDSA-Sig-Value`.
- `lib/src/signer/mod.rs:25-30` — `enum Algorithm { P256 }`; `:46-49` refuses Ed25519 for PAdES.
- `lib/src/tsa/mod.rs:9-15` — `trait TimestampAuthority { fn url(&self) -> &str; fn timestamp(&self, sha256_imprint: &[u8]) -> Result<Vec<u8>, TsaError>; }`.
- `lib/tests/contract_signer.rs:55-76` — the contract shape to reuse: decode the certificate, take its SPKI key, `VerifyingKey::from_sec1_bytes`, `Signature::from_der` (strict DER), `verify_prehash`.
- `lib/tests/support/softhsm.rs:142-171` — deterministic key from a SHA-256 seed, fixed validity, self-signed certificate (written for x509-cert 0.2: `Profile::Leaf`, 6-argument `CertificateBuilder::new`).
- No `RevocationSource` and no report type exist in Patelle.

crates.io on 2026-10-21 (`cargo search`, `cargo info`, crates.io API):
- `p256` 0.14.0 (rust-version 1.85), features `ecdsa`, `pkcs8`, `pem`; depends on `ecdsa` ^0.17, `sha2` ^0.11.
- `ecdsa` 0.17.0: `SigningKey::from_slice` (`signing.rs:95`), `PrehashSigner<der::Signature<C>>` under feature `der` (`signing.rs:307-308`, enabled by `pkcs8`), `VerifyingKey::from_sec1_bytes` (`verifying.rs:84`), `Signature::from_der` (`lib.rs:223`).
- `x509-cert` 0.3.0 (rust-version 1.85), on `der` ^0.8, `spki` ^0.8, `signature` ^3: `CertificateBuilder::new(profile, serial_number, validity, subject_public_key_info)` (`src/builder.rs:173-178`), `Builder::build::<S, Signature>(self, signer)` (`src/builder.rs` trait `Builder`); profiles `cabf::Root::new(emits_ocsp_response, subject)` requiring C, O and CN in the subject (`src/builder/profile/cabf.rs:72-99,116`), `devid::DevId`.
- `sha2` 0.11.1 (rust-version 1.88), `thiserror` 2.0.21, `zeroize` 1.9.1. Every MSRV ≤ 1.97.

DSS 6.5.1, the judge (ADR-0007), `dss-enumerations` on GitHub tag `6.5.1`:
- `Indication.java:40-71` — `TOTAL_PASSED`, `TOTAL_FAILED`, `INDETERMINATE` (URNs `urn:etsi:019102:mainindication:total-passed`…), plus block-level `PASSED`, `FAILED` and DSS's own `NO_SIGNATURE_FOUND`.
- `SubIndication.java` — 25 sub-indications with `urn:etsi:019102:subindication:` URNs (FORMAT_FAILURE … SIGNED_DATA_NOT_FOUND), plus DSS's own `ATTESTATION_CONSTRAINTS_FAILURE` (`urn:cef:dss:`).
- `SignatureLevel.java:52-70` — a level is a pair (form, profile): forms XAdES, CAdES, PAdES, PKCS7, JAdES, CBAdES; `SignatureProfile.java` lists BASELINE_B/T/LT/LTA, EXTENDED_BES/EPES/T/LT/C/X/XL/A/ERS/LTV, AdES, NOT_ETSI (16 values).

Cargo behaviour checked in a scratch crate under `/tmp`: a package may dev-depend on itself with a feature (`[dev-dependencies] self = { path = ".", features = ["test-signer"] }`); `cargo test` then runs a test needing the feature while `cargo build` leaves it off.

## Traps
- `Test` is `cargo test --workspace` without `--all-features` (`AGENTS.local.md:78`): a contract test gated on `#[cfg(feature = "test-signer")]` or `required-features` would be skipped silently. The self dev-dependency above is what makes it run.
- The lint convention (`AGENTS.local.md:96`) denies `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`; `clippy.toml` is outside Owns, so `allow-unwrap-in-tests` is unavailable and integration test files need a crate-level `#![allow(...)]` for these four. `[workspace.lints.clippy]` in the root plus `[lints] workspace = true` per crate keeps the rule in one place; `unsafe_code` must stay a crate attribute, since a workspace `forbid` could not be relaxed by `nacre-pkcs11` (`AGENTS.local.md:95`).
- `rust-toolchain.toml` pinned to 1.97 makes every local `cargo` call download 1.97 and its components on first use (only 1.99 installed). Clippy 1.97 is the judge, locally and in CI.
- The fuzz job needs nightly while the workspace pins 1.97 (ADR-0008 `:28`); `cargo +nightly fuzz` overrides the toolchain file. A `crates/<c>/fuzz/Cargo.toml` sits under the root workspace without being a member: cargo refuses it unless it declares its own `[workspace]` (see Open questions).
- With zero fuzz folders the job must succeed, not fail on an unmatched glob.
- `Cargo.lock` unversioned: CI resolves fresh versions each run (ADR-0003 `:27`); resolver 3 is MSRV-aware, so `rust-version = "1.97"` keeps resolution below it.
- `p256::ecdsa::SigningKey` is a secret: the test signer must not derive `Debug` (`AGENTS.local.md:98`).
- `cargo test` filters by target, not path: a task's tests run as `cargo test -p nacre-core --test <stem>` (`docs/architecture.md:86`).
- No migration, no route, no screen. Patelle stays untouched.

## Open questions
- Does `cargo fuzz init` (current release) write `[workspace] members = ["."]` into `fuzz/Cargo.toml`? If not, s03 must add it by hand; root `exclude` does not take globs as far as research could tell, and the root is frozen after s01. The plan has the CI loop not depend on it, and leaves a note for s03.
- Must `TOTAL_FAILED` and `INDETERMINATE` always carry a sub-indication? The DSS enums do not say; the plan makes it mandatory, which s18 may revisit through a contract story.
- Should DSS's own `ATTESTATION_CONSTRAINTS_FAILURE` and `NO_SIGNATURE_FOUND` be representable? Not EN 319 102-1 names; left out, `#[non_exhaustive]` keeps the door open.
- The story names the indications `TOTAL_PASSED`: that is DSS's spelling; EN 319 102-1 identifies them by URN (`…:total-passed`). The plan exposes both (`as_str` and `urn`).
- Trait boundary types and error transport: ADR-0010, proposed, for a human to settle.

## Complexity
Story: 2 → after reading: 3. No business logic as such, but a public contract every family and Patelle code against, a structural choice (ADR-0010), a pinned toolchain, and a CI job whose main branch cannot run on this story.

## Split
Not required (score 3).
