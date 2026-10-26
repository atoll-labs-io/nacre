# Verification — s48-detect-later-modifications

[Story](../stories.md) · [Plan](../plans/s48-detect-later-modifications.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: ddf2201cff7416eb7910a9ee359ed879fbfd47bf

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project (`E2E: —`) |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- End to end: the project has none. Build: deferred to ship.
- Lint and formatting beyond clippy: `cargo fmt --all` was applied before the runs; formatting is checked again at commit.
- The QA stage (`Surface: endpoint`) checks the validation endpoint on the committed tree.

Bench and local runs, outside `po-run` (results quoted, never re-typed as a pass of a declared check):

- Campaign (`cargo test -p nacre-validate --all-features --test campaign -- --ignored` on a bench started by `conformance/README.md`, then stopped), first on the code of the first two rows below, then again on the fix run's code (review findings closed) with the same lines: "264 cases, 0 differ from DSS under `dss()`." and "264 cases, 94 explained by switches under `strict()`, 0 unexplained." The new cases, identical under both presets:
  - `crates-nacre-validate-tests-corpus-attacks-isa-page-added`, `-isa-reason-redefined`, `-isa-reason-replaced`, `-isa-signature-moved`: `| Signature1 | TOTAL_FAILED / FORMAT_FAILURE / PAdES BaselineB | TOTAL_FAILED / FORMAT_FAILURE / PAdES BaselineB | = |`
  - `conformance-corpus-foreign-public-pdf-signed-added-page`: `| Signature1 | TOTAL_FAILED / FORMAT_FAILURE / PAdES BaselineB | TOTAL_FAILED / FORMAT_FAILURE / PAdES BaselineB | = |`
  - `bench-m1-b-page-added`, `bench-m2-b-reason-replaced`: `| Signature1 | TOTAL_FAILED / FORMAT_FAILURE / PAdES BaselineB | TOTAL_FAILED / FORMAT_FAILURE / PAdES BaselineB | = |`
- Fix loop 1 changed one test file, rustdoc and `pades.md` only, no library code: the campaign and the spoofing-file run were not repeated on it; their lines above still describe the library code this tree holds.
- `pades-spoofing-replaced-reason.pdf` (not committed), scratch crate `s48-repro` outside the worktree, the same two lines on the first run's code and on the fix run's:
  - `[strict] Signature1 -> TotalFailed / Some(FormatFailure) / Some(SignatureLevel { form: PAdES, profile: BaselineB }); defect=Some(SignatureDictionaryChanged)`
  - `[dss] Signature1 -> TotalFailed / Some(FormatFailure) / Some(SignatureLevel { form: PAdES, profile: BaselineB }); defect=Some(SignatureDictionaryChanged)`

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 6feec5eb3d34b98dce18d319a88c31454721e8fe | 2026-10-26T09:24:27Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | fe7612cd88252d0b870c9aa4887fea65f68b1958 | 2026-10-26T09:24:38Z |
| Unit suite | `cargo test --workspace` | 0 | 21662ab977909690be5a05ac6877ff0702aef6c6 | 2026-10-26T09:55:28Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 437384f7755675dacd9ac0a232df9b1f57c12658 | 2026-10-26T09:55:29Z |
| Unit suite | `cargo test --workspace` | 0 | aadc56aa02f406657cace6ec38a915817125b105 | 2026-10-26T10:11:31Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | fbf2a4feb3a1d0104f0bc5a2d2040ca3453f6087 | 2026-10-26T10:11:36Z |
