# Verification — s08-pades-bt

[Story](../stories.md) · [Plan](../plans/s08-pades-bt.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Tree: f44943855f77df8189829f8b496ec4824541ecd7

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

## Not proven here
The DSS test `bench_signature_is_pades_baseline_t` is `#[ignore = "conformance"]`: it was run by hand against the bench (passed, PAdES-BASELINE-T, TOTAL_PASSED) and is replayed by `.github/workflows/conformance.yml`; `po-run` does not record it. Build is deferred to ship. Formatting runs at commit.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | f31228e996a74b6f60b154cad1fa69ab1d3aa3d0 | 2026-10-22T13:04:56Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | ad5ee2c8f1ac249f75fac19573b98443a0a09e8a | 2026-10-22T13:05:14Z |
