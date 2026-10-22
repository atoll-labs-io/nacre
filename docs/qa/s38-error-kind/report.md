# QA — s38-error-kind

[Story](../../stories.md) · [Plan](../../plans/s38-error-kind.md)

Scope: the story's surface, what `git diff main...story/s38-error-kind` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli (row `endpoint` / `api, lib`)
Evidence: transcripts
Tool: Bash. Two scratch crates called the public interface. `probe` depends on `nacre-core` (with `test-signer`), `nacre-cms` and `nacre-pdf`. `probe2` depends on `nacre-core` alone and checks that a downstream crate must add a wildcard arm. Both were built and run against a copy of the branch under `mktemp -d`. The story's own unit tests were also run in that copy.
Origin: —

The diff touches the three `error.rs` files, `crates/nacre-core/src/lib.rs`, two `nacre-core` test files and `crates/nacre-pdf/Cargo.toml`, plus the story's research, plan and verification notes. There is no `docs/designs/s38-error-kind/`. `Install` (`cargo fetch`) and `Build` (`cargo build --workspace --all-features`) both exited 0 in the copy. The source of `probe` is quoted whole at the top of `c1-error-kind.txt`, and the source of `probe2` is in `c1-error-kind-error.txt`.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| C1 — `nacre-core` exposes `ErrorKind` (five variants, `#[non_exhaustive]`) and `nacre_core::Error::kind()` | yes | As expected. `nacre_core::ErrorKind` is importable and has the five variants. `kind()` returns `InvalidInput` for the `DigestLength` errors a `TestSigner` gives on digests of 0, 31, 33 and 4096 bytes. It returns `Signer` for a `Signer` error and `Unavailable` for `Timestamp` and `Revocation` errors that a user builds with their own source (`c1-error-kind.txt`). See finding 1 about `from_secret`. |
| C1 — invalid use: a downstream `match` that lists the five kinds with no wildcard | yes | As expected: the build is refused with `E0004 … ErrorKind is marked as non-exhaustive, so a wildcard _ is necessary`, cargo exit 101 (`c1-error-kind-error.txt`). |
| C2 — `nacre-cms` and `nacre-pdf` expose `kind()`; each variant has its kind; a test checks every variant | yes | As expected. These errors were produced by real calls and each one has a kind. `nacre-cms`: `Der`, `DigestLength`, `ForbiddenAttribute`, `ContentMissing` and `Certificate` give `InvalidInput`. `MessageDigestMismatch` and `SignatureInvalid` (a flipped signature byte) give `InvalidSignature`. `SignerCertificateNotFound` (a signer with an empty chain) gives `Indeterminate`. A failing user signer gives `Signer`. `nacre-pdf`: a clean file opens, and `Encrypted` gives `Indeterminate` (`c2-kind-per-variant.txt`). The two `every_variant_has_its_kind` tests pass in the copy. Their tables hold 21 rows for 20 `nacre-cms` variants (one extra row shows the delegation) and 30 rows for 30 `nacre-pdf` variants. No `kind()` has a `_ =>` arm. The plan says 28 `nacre-pdf` variants, but the enum and the table both count 30. |
| C2 — invalid input to `nacre-pdf` (empty, text, header only, xref loop, off-by-one startxref, malformed `/Prev`) | yes | As expected: each gives an error with `InvalidInput`, a message that names the defect, and no panic (`c2-kind-per-variant-error.txt`). |
| C3 — `Display` of `ErrorKind` is a fixed text that never depends on the input | yes | As expected. The five texts are `invalid input`, `invalid signature`, `indeterminate`, `signer failure` and `service unavailable`. Across 28 errors from different inputs, each kind printed exactly one text (`uniq -c` in `c3-display-fixed-error.txt`). The four digest lengths give four different detailed messages but the same `invalid input`. `core_kinds` and `kind_display_is_fixed` pass (`c3-display-fixed.txt`). |
| C4 — no secret of the test signer in any `Display`, `Debug` or `source` | yes | As expected. The secrets were `[0xFF;32]` and `[0x00;32]` (both refused by `from_secret`) and `[0x5A;32]` (valid, then given a 31-byte digest, directly and through `nacre_cms::sign_detached`). For each error, the probe rendered `Display`, `{:?}`, `{:#?}`, `kind()` and the whole `source()` chain. It searched them for lowercase hex, uppercase hex, decimal lists (with and without spaces) and the raw bytes: none was found (`c4-no-secret.txt`, `c4-no-secret-error.txt`). `errors_never_show_the_secret` passes. |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — an out-of-range secret given to `TestSigner::from_secret` is reported as a signer failure, not as invalid input
Severity: minor
Status: verified
Steps to reproduce:
1. In a crate depending on `nacre-core` with the `test-signer` feature, call `TestSigner::from_secret(&[0xFF; 32])`. That scalar is above the P-256 order.
2. On the returned `Err(e)`, print `e.kind()` and `e`.
3. Repeat with `&[0x00; 32]`.
Capture: docs/qa/s38-error-kind/c4-no-secret-error.txt (both secrets), and docs/qa/s38-error-kind/c1-error-kind.txt (first run)
Expected: the rustdoc of `ErrorKind::InvalidInput` reads "The bytes or arguments given are malformed, beyond a limit, or refuse the operation asked". A secret the caller gave that is not a valid scalar fits that description.
Observed: `kind()` is `Signer` / `"signer failure"`, and `Display` is `the signer failed`. `from_secret` wraps every failure in `nacre_core::Error::Signer`, and the plan maps `Signer` to `ErrorKind::Signer`. So an application that shows the kind tells the third party the signer broke, when the caller gave bad input. `TestSigner` is for tests only, so this matters only for how the convention reads to the later families. It is close to the plan's own pivot about `SignerCertificateNotFound` and `Certificate` at signing time, where the kind also follows the variant and not the caller's situation.

## Not seen
- How later families (s06 to s37) apply the convention — outside this story's diff; nothing to run yet.
- The PIN of a real signer in error messages — the story leaves it to s13; no PKCS#11 signer exists in this tree.
- A real timestamp authority or revocation source failing — they are behind the `http` feature and outside services; the QA built `Timestamp` and `Revocation` errors with its own sources and did not start a service.

Tree: 5e1b79076ba79611c223c4371eab5aad27627022
QA status: complete
