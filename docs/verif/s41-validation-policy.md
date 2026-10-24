# Verification — s41-validation-policy

[Story](../stories.md) · [Plan](../plans/s41-validation-policy.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 951d3dec91a0c024ba9a6cc02aaf743a404d65a9

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The nine conformance tests of task 8 (`tests/conformance.rs`, `#[ignore = "conformance"]`) ran once on the bench started per `conformance/README.md` (fresh PKI, `check.sh` ended `bench ready`), with the seven earlier ones: `cargo test -p nacre-validate --all-features --test conformance -- --ignored --test-threads=1`, 16 passed, DSS agreeing with every verdict the plan writes. Not a `po-run` row; CI's `conformance.yml` reruns them. The bench was stopped afterwards; `patelle-dss` was left running.
- The malformed-extension case checks only that DSS answers with an error (no report written), not that the error is an HTTP 500 specifically.
- The fuzz target was only compiled (`cargo check` in `crates/nacre-validate/fuzz/`), not run; CI's `fuzz` job runs it.
- `cargo fmt` was applied to `nacre-validate` and its fuzz crate, not recorded as a `po-run` row; formatting is checked at commit and in CI.
- Open questions the research leaves to s18's campaign stay unproven: `NotASignatureDictionary` and `UnsupportedSubFilter` stay listed under `dss()`; a repeated extension outside the CMS (in `/DSS` or a token) is judged, not an error; a certificate both expired and revoked gives the revocation first under `dss()`, unobserved on DSS; `/M` after `notAfter` is not judged.
- Build: deferred to ship (no routing or manifest change).
- Fix run (review finding 1): the conformance tests were not rerun on the bench after the fix to the stale-revocation exemption; it changes only `strict()` with no proof of existence, which DSS does not judge, and is pinned by `old_revocation_counts_unless_on_hold`.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 3d5deba1f03e00a36afac76b89f1c0fa755d5449 | 2026-10-24T08:50:23Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 6ae9df7b4ba0b8a32de7f6935dc091eb6521a189 | 2026-10-24T08:50:42Z |
| Unit suite | `cargo test --workspace` | 0 | d25c2970d4824b3cf0cc5594f9af7b2d2d5b9464 | 2026-10-24T09:04:56Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | df68304d825a071116c773c22d00bc9dc50fbd41 | 2026-10-24T09:05:00Z |
