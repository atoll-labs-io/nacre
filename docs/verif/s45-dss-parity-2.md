# Verification — s45-dss-parity-2

[Story](../stories.md) · [Plan](../plans/s45-dss-parity-2.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: d48824cf09406dad7712f167abe8f938d13791e3

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The five conformance tests of task 8 (`tests/conformance.rs`, `#[ignore = "conformance"]`) ran once on the bench started per `conformance/README.md` (fresh PKI, `check.sh` ended `bench ready`), with the twenty-two earlier ones: `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, 27 passed. Not a `po-run` row; CI's `conformance.yml` reruns them. The bench was stopped afterwards; `patelle-dss` was left running.
- The fuzz targets were not run; `nacre-pdf`'s fuzz crate was only checked to compile (`cargo check --manifest-path crates/nacre-pdf/fuzz/Cargo.toml`). CI's `fuzz` job covers them.
- `cargo fmt --all` was applied, not recorded as a `po-run` row; formatting is checked at commit and in CI.
- Left open by the plan's pivot and the research: a delegated OCSP responder expired at the control date (Nacre judges the pair's CA only); the SKI rule on a trust anchor and on a timestamp authority's path; a `startxref` off by more than whitespace (refused under both presets, DSS repairs it); `Revoked` against the issuer rule when both apply.
- Build: deferred to ship (no routing or manifest change).

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 6b08c17b99fadcf2f2f6c82b1a6948f6d2036892 | 2026-10-24T16:39:59Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 35b87a5bc41222abd46c9242afe71f9687bf1f34 | 2026-10-24T16:40:11Z |
