# Verification — s39-error-kind-from-sources

[Story](../stories.md) · [Plan](../plans/s39-error-kind-from-sources.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 2d7daaaff4e1115795781e395267cdba87634617

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`; no manifest changed) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The `#[ignore]`d conformance tests (DSS, SoftHSM) are not run by `cargo test --workspace`; they run in `.github/workflows/conformance.yml`. This story touches none of their paths.
- Formatting is checked at commit time, the production build at ship only if a manifest changed (none did).
- QA of the `endpoint` surface belongs to `/po-qa`, after this commit.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 2821aeca69d54c9fdd45874c95046202797f1855 | 2026-10-23T12:17:23Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | b861641c5a45b9d1e2e887ed5029e7a9a4c39fa0 | 2026-10-23T12:17:40Z |
| Unit suite | `cargo test --workspace` | 0 | 6e855d4a498d4d480bb2ac61fa1dc1ff2e6dbc34 | 2026-10-23T12:18:44Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 7c5020f1dc2f774e827ce2f3e1af0350a1c8f08b | 2026-10-23T12:18:45Z |
