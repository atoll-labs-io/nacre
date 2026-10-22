---
validated: yes
---
# Plan — s38-error-kind

[Story](../stories.md) · [Research](../research/s38-error-kind.md)

Branch `story/s38-error-kind`. Read `docs/research/s38-error-kind.md` first; this plan builds on it without repeating it.

**Unblocked**: the story was corrected on `main` (PR #57, approved by the owner on 2026-10-22): `crates/nacre-pdf/Cargo.toml` is in `Owns`, and criterion 4 checks the test signer's secret, the PIN being s13's. The lane was re-forked from that `main`.

## Story
Every error of `nacre-core`, `nacre-cms` and `nacre-pdf` gets a coarse `nacre_core::ErrorKind` an application can show to an untrusted party; the detailed enums and their messages stay unchanged (ADR-0012).
1. `nacre-core` exposes `ErrorKind` (`InvalidInput`, `InvalidSignature`, `Indeterminate`, `Signer`, `Unavailable`, `#[non_exhaustive]`) and `Error::kind()`.
2. `nacre-cms` and `nacre-pdf` expose `kind()` on their `Error`; a test checks the kind of every variant.
3. `ErrorKind`'s `Display` is a fixed text, independent of the input.
4. No error message holds a secret: checked with `TestSigner`'s secret (it has no PIN).

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| `ErrorKind` enum and its `Display` | new code in `crates/nacre-core/src/error.rs` | nothing in the repository holds a coarse kind; `std::io::ErrorKind` has other categories and is not ours to extend; `thiserror` derives `Display` with `#[error("...")]`, usable on a unit-variant enum but the derive brings nothing a `match` to `&'static str` does not; either is acceptable |
| `kind()` on three `Error` enums | new code, one `match` each | no existing mapping; a `From` impl would not express "kind of", and a trait would be a new abstraction the story does not ask for |
| `nacre-pdf` → `nacre-core` dependency | the workspace crate already depended on by `nacre-cms` (`crates/nacre-cms/Cargo.toml:13`) | — |
| Tests' failing signer secret | `TestSigner::from_secret` (`test_signer.rs:31`) | — |

## Tasks
1. [x] **`ErrorKind` in `nacre-core`.** In `crates/nacre-core/src/error.rs`: `#[non_exhaustive] #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] pub enum ErrorKind { InvalidInput, InvalidSignature, Indeterminate, Signer, Unavailable }`, each variant's rustdoc giving the meaning of the research's "Kind meanings" table (this is the convention s06 to s37 apply); the enum's doc says it is what may be shown to a third party, and that EN 319 102-1 sub-indications are results, never kinds. `impl fmt::Display` writes a fixed English phrase per kind (`"invalid input"`, `"invalid signature"`, `"indeterminate"`, `"signer failure"`, `"service unavailable"`). `impl Error { pub fn kind(&self) -> ErrorKind }`: `DigestLength` → `InvalidInput`, `Signer` → `Signer`, `Timestamp` and `Revocation` → `Unavailable`, no wildcard arm. Export `ErrorKind` at `lib.rs:26`; one sentence on `kind()` in the crate doc `:9-11`. Test: new `crates/nacre-core/tests/error_kind.rs` — `core_kinds` asserts the kind of each of the 4 variants; `kind_display_is_fixed` asserts the exact text of each of the 5 kinds and that two `DigestLength` errors with different lengths give the same `kind().to_string()`. Fails if a mapping or a text changes, or if `Display` reads a field.
2. [x] **No secret in messages.** In `crates/nacre-core/tests/contract_signer.rs`, `errors_never_show_the_secret`: (a) `TestSigner::from_secret(&[0xFF; 32])` (scalar above the P-256 order, refused by `SigningKey::from_slice`, `ecdsa-0.17.0/src/signing.rs:95`) must be `Err`; (b) a signer from `[0x5A; 32]` given a 31-byte digest must return `Err`. For each error, render `Display`, `{:?}`, `{:#?}`, `kind()` and every `source()` down the chain, and assert none contains the secret in lower or upper hex (`ffff…`, `5a5a…`), as a decimal byte list (`255, 255`, `90, 90`) or as raw bytes. Fails if any error path formats the secret. If (a) unexpectedly succeeds, pick another out-of-range scalar, never a valid one.
3. [x] **`kind()` in `nacre-cms`.** In `crates/nacre-cms/src/error.rs`, `impl Error { pub fn kind(&self) -> nacre_core::ErrorKind }`, no wildcard arm: `Der`, `NotSignedData`, `ForbiddenAttribute`, `ContentMissing`, `ContentAmbiguous`, `DigestLength`, `Certificate` → `InvalidInput`; `AlgorithmMismatch`, `MissingSignedAttributes`, `MissingAttribute`, `DuplicateAttribute`, `AttributeValueCount`, `ContentTypeMismatch`, `MessageDigestMismatch`, `SigningCertificateMismatch`, `SignatureInvalid` → `InvalidSignature`; `SignerCount`, `UnsupportedAlgorithm`, `SignerCertificateNotFound` → `Indeterminate`; `Signer(e)` → `e.kind()`. Test: `#[cfg(test)] #[allow(clippy::unwrap_used)] mod tests` in the same file, `every_variant_has_its_kind`: a table of one sample per variant (20 rows; `der::Error::from(der::ErrorKind::Failed)`, `crate::oid` constants) with its expected kind, plus `Signer(nacre_core::Error::Timestamp(..))` → `Unavailable` to show the delegation. Run: `cargo test -p nacre-cms --lib`.
4. [x] **`kind()` in `nacre-pdf`.** Add `nacre-core = { path = "../nacre-core", version = "0.1.0" }` to `[dependencies]` of `crates/nacre-pdf/Cargo.toml` (same form as `crates/nacre-cms/Cargo.toml:13`). In `crates/nacre-pdf/src/error.rs`, `impl Error { pub fn kind(&self) -> nacre_core::ErrorKind }`, no wildcard arm: `UnsupportedFilter`, `UnsupportedPredictor`, `Encrypted` → `Indeterminate`; every other variant (21 reader defects, 6 writer refusals including `CertifiedNoChanges`) → `InvalidInput`. Test: `#[cfg(test)]` module in the same file, `every_variant_has_its_kind`, one sample per variant (28 rows, `ObjectId::new`), expected kind each. Run: `cargo test -p nacre-pdf --lib`.
5. [ ] **Final checks.** `po-run --story s38-error-kind --label test -- 'cargo test --workspace'`, then `po-run --story s38-error-kind --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`.

## Scene viewpoints
—

## Run interdicts
- Every existing variant, field and `#[error(...)]` text of the three `error.rs` files stays byte-identical: `git diff main...story/s38-error-kind` shows only added lines there (issues #40 and #47 are out of scope).
- No `_ =>` arm in any `kind()` (`grep -n "_ =>" crates/*/src/error.rs` lists nothing new).
- Outside `crates/nacre-core/`, the only files changed are `crates/nacre-cms/src/error.rs`, `crates/nacre-pdf/src/error.rs` and `crates/nacre-pdf/Cargo.toml` (one dependency line); `sign.rs`, `verify.rs`, `crates/nacre-conformance/`, root `Cargo.toml`, `AGENTS.local.md` untouched.
- `nacre-core` gains no dependency; `[workspace.dependencies]` is not added.
- `ErrorKind` has no field and no `From`/`Into` to any error; no `ErrorKind` value is derived from a `SubIndication` or the reverse.
- No `docs/decisions/0013-*` file: the mapping lives inside ADR-0012's decision.

## The pivot
The meaning of each kind, written once in `ErrorKind`'s rustdoc and applied by every later family. Ways it could be wrong:
- Signed-attribute format defects (`MissingAttribute`, `DuplicateAttribute`, …) as `InvalidSignature` follow EN 319 102-1's `FORMAT_FAILURE` under TOTAL-FAILED (`report.rs:64`); a reader who sees them as malformed input would put them in `InvalidInput`. Compare with the DSS verdicts recorded by s02.
- `SignerCertificateNotFound` and `Certificate` are raised when signing too (`sign.rs:77-78`), where the kind is then `Indeterminate` / `InvalidInput` rather than `Signer`. Splitting them needs `sign.rs`, outside `Owns`; left for a later story.
- Delegating `nacre_cms::Error::Signer(e)` to `e.kind()` rather than always `Signer`: true today (cms wraps only signer calls, `sign.rs:70`), but it makes a core `DigestLength` coming back from a signer read as `InvalidInput`.

## Files touched
- `crates/nacre-core/src/error.rs`, `crates/nacre-core/src/lib.rs`
- `crates/nacre-core/tests/error_kind.rs` (new), `crates/nacre-core/tests/contract_signer.rs`
- `crates/nacre-cms/src/error.rs`
- `crates/nacre-pdf/src/error.rs`, `crates/nacre-pdf/Cargo.toml`
- `docs/research/s38-error-kind.md`, `docs/plans/s38-error-kind.md`, `docs/verif/s38-error-kind.md`

## Test strategy
Five automated tests, all at the unit layer where each mapping lives; budget 25.
- `nacre-core/tests/error_kind.rs`: `core_kinds`, `kind_display_is_fixed`.
- `nacre-core/tests/contract_signer.rs`: `errors_never_show_the_secret`.
- `nacre-cms/src/error.rs` and `nacre-pdf/src/error.rs`: one table test each, `every_variant_has_its_kind`. A table rather than one test per variant (testing doctrine, cut 2) because criterion 2 asks for every variant: the mapping is a contract, and each row bites when its arm changes. The compiler, through the no-wildcard `match`, guarantees every variant is mapped; the reviewer checks the table row count equals the variant count (20 and 28).
No visual check: no screen. Surface `endpoint` stays at the library API, exercised by these tests.

## Done when
Five tests and the workspace suite green, clippy clean, the record current in `docs/verif/s38-error-kind.md`, a review with no open critical finding, one commit `s38-error-kind: Une catégorie d'erreur grossière à montrer aux tiers` landed through a pull request.
