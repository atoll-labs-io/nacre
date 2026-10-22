# Research — s38-error-kind

[Story](../stories.md)

## Structuring facts
- **False assumption — the test signer of `nacre-core` has no PIN.** `TestSigner::from_secret(secret: &[u8; 32])` (`crates/nacre-core/src/test_signer.rs:31`) takes a raw P-256 scalar; no PIN exists anywhere in the code (the PIN arrives with `nacre-pkcs11`, `docs/stories.md:232-235`). Criterion 4 must read "the test signer's secret" instead of "the PIN": the story is to be corrected that way, and the test checks that no `Display`, `Debug` or `source` chain of a `TestSigner` error holds the 32 secret bytes.
- **`Owns` limits `nacre-cms` and `nacre-pdf` to their `src/error.rs`** (`docs/stories.md:653`): their per-variant tests cannot go in `tests/` and must be `#[cfg(test)] mod tests` inside `error.rs`, as `filter.rs:178` and `write.rs:122` already do. `sign.rs` and `verify.rs` cannot change either, so a variant raised both when signing and when verifying (`SignerCertificateNotFound`, `Certificate`) gets one kind for both.
- **ADR-0012 fixes the five kinds but not what each one means** (`docs/decisions/0012-detailed-errors-with-a-coarse-kind.md:18`). The meaning is written here (rustdoc of `ErrorKind`) and becomes the convention s06 to s37 follow; it is a mapping rule inside a decided structure, not a new structural choice, so no ADR-0013.
- **Today no message carries a secret**: `p256`'s key error is opaque (`ecdsa-0.17.0/src/signing.rs:95-98` maps every failure to `Error::new()`), `TestSigner` implements neither `Debug` nor `Display` (`test_signer.rs:23-27`). The secret test guards against a future regression, not a present leak.
- `nacre-cms`'s `Error::Signer(#[from] nacre_core::Error)` (`crates/nacre-cms/src/error.rs:66`) wraps any core error, so its kind is the inner error's kind.

## Story
Every Nacre error gets a coarse category an application may show to an untrusted party, while the detailed enum stays for the developer (ADR-0012, option 1).
1. `nacre-core` exposes `ErrorKind` (`InvalidInput`, `InvalidSignature`, `Indeterminate`, `Signer`, `Unavailable`, `#[non_exhaustive]`) and `nacre_core::Error::kind()`.
2. `nacre-cms` and `nacre-pdf` expose `kind()` on their `Error`; every variant has its kind, checked by a test over all variants.
3. `ErrorKind`'s `Display` is a fixed text that never depends on the input.
4. No error message holds a secret: a test checks it with the test signer of `nacre-core` (for its secret, see above).
Notes: contract story; EN 319 102-1 sub-indications are results, never `ErrorKind`; a new `ErrorKind` variant is a contract change.

## Current code
- `crates/nacre-core/src/error.rs:1-20` — `BoxError`; `#[non_exhaustive]` `thiserror` enum `Error` with 4 variants: `DigestLength { expected, actual }` (`:10`), `Signer(BoxError)` (`:13`), `Timestamp(BoxError)` (`:16`), `Revocation(BoxError)` (`:19`). No `impl Error` block.
- `crates/nacre-core/src/lib.rs:9-11` — crate doc: "every trait method returns the single [`Error`]"; `:26` `pub use error::{BoxError, Error};`.
- `crates/nacre-core/src/test_signer.rs:61-72` — `sign_digest` returns `DigestLength` on a wrong length; `:81-83` `signer_error` boxes every builder/key failure into `Error::Signer`.
- `crates/nacre-cms/src/error.rs:3-67` — 20 variants. Raised: `NotSignedData` `model.rs:87`; `DigestLength` `sign.rs:54`, `verify.rs:61`; `Signer(core::Error::Signer(..))` for an unknown algorithm `sign.rs:70`; `SignerCertificateNotFound` `sign.rs:77` (empty chain) and `verify.rs:147`; `Certificate` `sign.rs:78`, `verify.rs:131,140`; `ForbiddenAttribute` `sign.rs:97` (caller asked for an attribute the profile forbids); `ContentAmbiguous`/`ContentMissing` `verify.rs:47-58` (caller arguments); `SignerCount` `verify.rs:78`; `MissingSignedAttributes` `:83`; `ContentTypeMismatch` `:90`; `MessageDigestMismatch` `:106`; `SignatureInvalid` `:116`; `DuplicateAttribute` `:157`; `AttributeValueCount` `:163`; `MissingAttribute` `:174`; `UnsupportedAlgorithm` `:182-231`; `AlgorithmMismatch` `:209`; `SigningCertificateMismatch` `:219,241`.
- `crates/nacre-pdf/src/error.rs:3-113` — 28 variants: 21 reader defects (`TooLarge` … `Limit`), 3 unsupported features (`UnsupportedFilter` `:52`, `UnsupportedPredictor` `:55`, `Encrypted` `:87`), 6 writer refusals (`Unwritable` `:97`, `ReservedEntry` `:100`, `EmptySignatureSlot` `:103`, `DuplicateField` `:106`, `CertifiedNoChanges` `:109`, `SignatureTooLarge` `:112`).
- `crates/nacre-core/src/report.rs:63-89` — the 25 sub-indications; `FormatFailure`, `HashFailure`, `SigCryptoFailure` are TOTAL-FAILED, `NoSigningCertificateFound`, `CryptoConstraintsFailure` INDETERMINATE: the kinds below follow the same split.

## Attachment points
- `crates/nacre-core/src/error.rs` — new `ErrorKind` enum + `impl fmt::Display`, new `impl Error { pub fn kind(&self) -> ErrorKind }`.
- `crates/nacre-core/src/lib.rs:26` — export `ErrorKind`; crate doc `:9-11` gains one sentence on `kind()`.
- `crates/nacre-cms/src/error.rs`, `crates/nacre-pdf/src/error.rs` — `impl Error { pub fn kind(&self) -> nacre_core::ErrorKind }` plus `#[cfg(test)] mod tests`.
- `crates/nacre-pdf/Cargo.toml` — **not owned** and has no `nacre-core` dependency (`Cargo.toml:12-14`): see Open questions.

## Verified interfaces
- `pub enum nacre_core::Error` — `error.rs:7`, variants constructible from other crates (`#[non_exhaustive]` only forbids exhaustive matching outside).
- `pub fn TestSigner::from_secret(&[u8; 32]) -> Result<TestSigner, Error>` — `test_signer.rs:31`; `[0u8; 32]` is a zero scalar `SigningKey::from_slice` refuses (`ecdsa-0.17.0/src/signing.rs:95`).
- `fn sign_digest(&self, &[u8]) -> Result<Vec<u8>, Error>` — `test_signer.rs:61`.
- `der::Error: From<der::ErrorKind>`, `der::ErrorKind::Failed` — `der-0.8.2/src/error.rs:116,210`: builds a `der::Error` in a unit test.
- `pub const fn ObjectId::new(u32, u16)` — `crates/nacre-pdf/src/object.rs:12`.
- `nacre_cms::oid` constants (`crates/nacre-cms/src/oid.rs`) give `ObjectIdentifier` samples.
- Workspace lints deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` (`Cargo.toml:5-9`); unit test modules opt out with `#[allow(...)]` (`filter.rs:179`).

## Kind meanings (proposed, settled in the plan)
| Kind | Meaning | Examples |
| --- | --- | --- |
| `InvalidInput` | the bytes or arguments given are malformed, beyond a limit, or refuse the operation asked | DER/PDF syntax, `TooLarge`, `DigestLength`, `ContentMissing`, `ForbiddenAttribute`, writer refusals, `CertifiedNoChanges` |
| `InvalidSignature` | the input was read and the signature is proven wrong (TOTAL-FAILED family) | `SignatureInvalid`, `MessageDigestMismatch`, `ContentTypeMismatch`, signed-attribute format defects, `AlgorithmMismatch`, `SigningCertificateMismatch` |
| `Indeterminate` | Nacre cannot conclude: unsupported feature or missing material | `UnsupportedAlgorithm`, `SignerCount`, `SignerCertificateNotFound`, `UnsupportedFilter`, `UnsupportedPredictor`, `Encrypted` |
| `Signer` | the signer failed | core `Signer` |
| `Unavailable` | an outside service (timestamp authority, revocation source) failed | core `Timestamp`, `Revocation` |

## Traps
- **`nacre-pdf` does not depend on `nacre-core`** (`crates/nacre-pdf/Cargo.toml:12-14`) and its `Cargo.toml` is outside `Owns`. Returning `nacre_core::ErrorKind` from `nacre_pdf::Error::kind()` needs that dependency line.
- **`nacre-core` is frozen after s01** (`docs/architecture.md:61`): this story is the contract story that may touch it; only additions, no change to existing variants or messages, or every dependant breaks.
- `kind()` matches must have no wildcard arm inside the crates, so a new variant fails to compile until mapped; `#[non_exhaustive]` does not force a wildcard inside the defining crate.
- Parallel lane s02 owns `crates/nacre-conformance/`, which depends on `nacre-core` (`s02 worktree: crates/nacre-conformance/Cargo.toml:17`) and has its own `Error`: an additive change does not break it; giving it `kind()` is s02's or a later story's business.
- Issues #40 (OID-only messages) and #47 (oversized-slot wording) concern `Display` texts of the same files: out of scope, ADR-0012 keeps messages detailed.
- The convention "every `Error` exposes `kind()`" belongs in `AGENTS.local.md` Conventions, a file this lane does not own.
- Tests: `cargo test -p nacre-core --test <stem>`; unit tests of `error.rs` run with `cargo test -p nacre-cms --lib` / `-p nacre-pdf --lib`.

## Open questions
- May this lane add `nacre-core = { path = "../nacre-core", version = "0.1.0" }` to `crates/nacre-pdf/Cargo.toml`, outside `Owns`? The story implies it (criterion 2 asks for one shared `ErrorKind`); the plan treats the one line as part of the story and names it as an interdict exception the reviewer checks. Otherwise `Owns` must be widened by the lead.
- `SignerCertificateNotFound` and `Certificate` come from both signing (`sign.rs:77-78`) and verifying; one kind per variant (`Indeterminate`, `InvalidInput`) is slightly wrong on the signing side, where the signer's chain is at fault. Splitting the variants needs `sign.rs`, outside `Owns`.

## Complexity
2 → 2. Three small enums of mapping, five tests; the only surprises are the missing PIN and the `nacre-pdf` dependency line.

## Split
— (complexity 2).
