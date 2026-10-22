# Review — s14-validate-integrity

[Story](../stories.md) · [Plan](../plans/s14-validate-integrity.md) · [Verification](../verif/s14-validate-integrity.md)

Diff reviewed: `git diff main...story/s14-validate-integrity`, in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 24dd4fe8fafc8c0a2ea7738d93f851665fd282dc

## When blocked
Not blocked.

## Ownership
I listed the diff with `git diff --name-only main...story/s14-validate-integrity` (43 paths) and checked each one against `Owns: crates/nacre-validate/, docs/security/attacks/pades.md`.
- [x] Every path is inside `Owns`. The only other paths are the story's own pipeline evidence (`docs/plans/`, `docs/research/`, `docs/verif/`, `docs/qa/s14-validate-integrity/`), which is in scope by design.
- [x] No path falls outside `Owns`.
- [x] No path falls inside another running story's `Owns`. The worktrees for s07, s09 and s13 own `nacre-tsp`, `nacre-revocation` and `nacre-pkcs11`, and none of those are touched. s15 shares the same `Owns` but has no worktree yet.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s14-validate-integrity` passes (exit 0), so I reused the record. I also checked it by hand: `git diff --quiet <tree> HEAD -- . ':(exclude)docs'` is clean for `Tree: 46cb77c…` and for the last passing runs (unit suite `5d30eef…` exit 0, type check `875a192…` exit 0). An earlier clippy run exited 101 on an older tree and was superseded. I read the record's "Not proven here" section.
- [x] `po-gate qa-current s14-validate-integrity` passes (exit 0); the story has `Surface: endpoint` and `QA stage: surfaces`. QA reported one verified finding, which I carry into Findings.

## Plan
- [x] Tasks 1–8 are all present. One deviation: the forge is `examples/forge_pades_attacks.rs`, not `examples/forge_attacks.rs` as the plan says (see Findings). The dev-dependency `der` adds the `oid` feature, which the unit table test of `report.rs` needs.
- [x] Run interdicts, checked one by one:
  - `git diff main...story/s14-validate-integrity` over the frozen paths (root `Cargo.toml`, `rust-toolchain.toml`, `.github`, `nacre-core`, `nacre-pdf`, `nacre-cms`, `nacre-pades`, `nacre-conformance`, `conformance`, `docs/stories.md`) is empty.
  - No `[workspace.dependencies]`. Dependencies are exactly those of task 1.
  - `ValidationReport::passed` / `TotalPassed` appear nowhere in `src`.
  - No clock, network, stdout, stderr or logger in `src`.
  - Clippy deny lints hold, according to the record.
  - The corpus is all forged or copied from the repository, and the README sha256 values match the source files.
  - `Cargo.lock` is not tracked (0 hits in `git ls-files`).

## References
- [x] Opened and confirmed: `Document::{parse, signature_fields, object, revisions}`, `SignedData::{from_der, verify_detached_digest}` (`crates/nacre-cms/src/verify.rs:55`), the check order of `verify_with` (algorithms, then digest, then signature, which is what the `digest_verified` mapping relies on), the 20 variants of `nacre_cms::Error` (all 20 appear in the table test), `MAX_INPUT_LEN = 50_000_000` (`crates/nacre-pdf/src/limits.rs:3`), and the `ValidationReport` constructors.
- [x] Values: the sub-indication grades follow EN 319 102-1 (`NO_SIGNING_CERTIFICATE_FOUND` and `CRYPTO_CONSTRAINTS_FAILURE_NO_POE` are INDETERMINATE, structural defects are FORMAT_FAILURE). The SubFilter names follow ISO 32000-2. `MAX_SIGNATURES = 64` is the plan's choice and is commented. DSS parity of these grades is not confirmed (see Not verified).

## Rules
- [x] The `AGENTS.md` conventions hold:
  - `#![forbid(unsafe_code)]` is present.
  - The crate doc says "Experimental".
  - There is one `thiserror` enum, and nothing is logged.
  - Every slice goes through `get` and every sum through `checked_add`.
  - There is a fuzz target, and a corpus with a README.
  - The attack sheet is at `docs/security/attacks/pades.md`.
  - Edition 2024 and rust-version 1.97 are set.
- [x] No accepted ADR is contradicted. Reuse matches the plan's `## Reuse` table, and no helper was duplicated: the hex decoder is local because `nacre-pdf`'s one is private.

## Tests
- [x] Floor: `po-gate floor-guard s14-validate-integrity main` exits 0, so nothing was lowered. It printed an awk locale warning, but the exit code was 0.
- [x] The assertions pin down the acceptance criteria. Each attack test asserts its own `Defect` plus `TOTAL_FAILED`/`FORMAT_FAILURE`, so a case caught by an earlier rule would fail. The forged files are correctly signed over their forged ranges, so no later rule can answer in place of the one under test. None of the six "proves nothing" shapes is present.
- [x] There are 22 tests, within the `Test budget` of 25.
- [x] Bite tests. I ran each mutation against `tests/attacks.rs` (and `tests/validate.rs` for the third), then undid it; `git diff --exit-code crates/nacre-validate/src/validate.rs` came back clean each time.
  - Gap check disabled (`if false && !gap_is_contents(...)`): **1 failing test** (`swa_wrapped_is_rejected`, which got `Indeterminate`, i.e. the wrapped file verified as sound).
  - Later-revision rule disabled (`covers_last_revision` returns `true`): **1 failing test** (`isa_appended_revision_is_rejected`).
  - Byte comparison inside the gap check disabled (`h * 16 + l == byte || true`): **0 failing tests** across 18 tests (see Findings).
- [x] No existing test was made useless; the crate is new.

## Neighbours
- [x] The diff only adds a new crate, so it changes nothing that existing code calls. Nothing else calls `nacre-validate` yet; the `nacre-sig` facade belongs to a later story.

## Lenses
Lenses run: dependencies — new manifests `crates/nacre-validate/Cargo.toml` (sha2 0.11, der 0.8, thiserror 2, plus path crates) and `crates/nacre-validate/fuzz/Cargo.toml` (libfuzzer-sys 0.4). Every one is already used by another workspace crate at the same version and is named by the plan. No version was bumped and no lockfile is tracked. Security, migration and performance were not triggered by any path or content. Because this crate is a signature validator, I still checked by hand that the four byte invariants make every byte outside the gap signed.
- [x] Each lens finding is graded and listed under Findings; the dependencies lens found nothing.

## Findings
- minor — crates/nacre-validate/src/validate.rs:148-154 — The rule "the gap decodes to exactly the `/Contents` bytes" (plan task 3, check 8) is not tested. Forcing the byte comparison to always succeed fails none of the 18 tests in `tests/attacks.rs` and `tests/validate.rs`. Only the shape part (`<`, even hex, `>`, length) is exercised, by `swa_wrapped`.
  - I rate it minor, not major, because no false valid follows from it today. With `a == 0`, `c + d == len` and a well-formed hex gap, a `/Contents` that lives anywhere other than the gap sits in the signed bytes. Its CMS would then have to sign a digest of bytes that contain itself, which is cryptographically infeasible.
  - The fix is a corpus case whose gap is a valid hex string differing from `/Contents`. One way: an indirect `/Contents` pointing to a string elsewhere, with a range forge around another hex run.
- minor — crates/nacre-validate/src/validate.rs:33-36 — This is QA finding 1, verified, carried over. An `Err` from `doc.object(value)` is mapped to `None`, so a `/Sig` dictionary that fails to parse (an oversized integer in `/ByteRange`, deep nesting in `/Contents`) is reported as `Defect::NotASignatureDictionary`, whose doc says "`/V` does not name a dictionary". The verdict (`TOTAL_FAILED`/`FORMAT_FAILURE`) is right, but the diagnosis points at the wrong rule and the parse error is lost. Evidence: `docs/qa/s14-validate-integrity/c2-byterange-error.txt`, `c5-hostile.txt`.
- minor — crates/nacre-validate/examples/forge_pades_attacks.rs:1 — The forge is named `forge_pades_attacks`, while the plan (task 4 and Files touched) names `examples/forge_attacks.rs` with the matching `cargo run` command. The rename is reasonable, since `nacre-cms` already has an example called `forge_attacks` and the two output files would collide in the workspace. But the plan was not updated and gives no reason. The README, the attack sheet and the verification record all use the new name consistently.

## Not verified
- **Sub-indication parity with DSS** (USF/SWA/ISA cases, the CMS error mapping, `UnsupportedSubFilter`, `AlgorithmMismatch` mapped to `SIG_CRYPTO_FAILURE`). The conformance bench was not started, per the driver's instruction and outside this story's criteria. s18's campaign should compare them. This is also QA's Not seen item.
- **The fuzz target under `cargo fuzz`.** I did not run it; it needs nightly and a long run. The record says it ran 20 s outside `po-run`, and QA ran a 21,000-input mutation sweep instead. A person should confirm CI's `fuzz` job picks up `crates/nacre-validate/fuzz` on the next push. This is also QA's Not seen item.
- **Inputs near the bounds** (50 MB, 64/65 signatures). No real-load run was done, and `TooManySignatures` through `validate` itself was not exercised; only the unit test through `validate_with(…, 1)` covers it. This is also QA's Not seen item.
- **Producer tolerance.** Only one third-party signature (LibreOffice, RSA) is under test. The pyHanko files were probed by the research but are not tested. A producer that adds whitespace after the final `%%EOF` is refused as `ByteRangeNotWholeFile` (QA observed this with a single LF). That is a false negative, never a false valid. A person could run `validate` over a few real-world signed PDFs to see whether that strictness is acceptable.
- **Corpus determinism.** I did not rerun the forge. I relied on the record's three identical `sha256sum -c` runs.
- **Full suite and clippy.** I did not rerun them here. I relied on the current record (`Verification mode: record`); only the bite runs were made.

Max severity: minor
Ship allowed: yes
