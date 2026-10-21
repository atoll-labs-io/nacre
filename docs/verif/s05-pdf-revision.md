# Verification — s05-pdf-revision

[Story](../stories.md) · [Plan](../plans/s05-pdf-revision.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: b5f458ef2146c538e8b392b1f2ff472d51179135

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| qpdf | `PATH=/tmp/s05-qpdf/bin:$PATH cargo test -p nacre-pdf --test revision -- --ignored` | the plan's `qpdf_check_is_clean` (criterion 4), qpdf 12.4.2 from conda-forge under `/tmp/s05-qpdf` |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- `qpdf_check_is_clean` ran here only, with qpdf from `/tmp/s05-qpdf`; no CI workflow installs qpdf yet, so it stays `#[ignore = "conformance"]` until s02's `conformance.yml` (ADR-0007) runs it.
- The `revision` fuzz target ran 30 s locally (`cargo +nightly fuzz run revision -- -max_total_time=30`, 1.5 million inputs, no crash) with no seed corpus, so it rarely reached `sign`; the 60 s run is CI's fuzz job.
- `cargo fmt --all --check` passed locally but is not a `po-run` row; formatting is checked again at commit and in CI.
- The writer is proven on the 10 corpus files and the crafted shapes of `tests/revision.rs`; no corpus file has a hybrid newest revision, so hybrid → table rests on the spike and ISO 32000-1 7.5.8.4. No PDF viewer (Acrobat, pdfsig) opened the outputs; signature validation is s14's.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| qpdf | `PATH=/tmp/s05-qpdf/bin:$PATH cargo test -p nacre-pdf --test revision -- --ignored` | 0 | f559efff4c57ac7fc98a2aab487f11ad89a0cc05 | 2026-10-21T23:35:56Z |
| Unit suite | `cargo test --workspace` | 0 | 674960b3c47db866da29cdf33eef713e75fadc6e | 2026-10-21T23:36:03Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | b7b05ae35793926383ae5171bdb1ec9cc4448c29 | 2026-10-21T23:36:13Z |
