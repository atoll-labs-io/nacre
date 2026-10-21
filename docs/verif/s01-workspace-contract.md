# Verification — s01-workspace-contract

[Story](../stories.md) · [Plan](../plans/s01-workspace-contract.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: c089cbad488fb0b2cc6fd740ae038ea1768d91c1

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The CI workflow itself: it has only been parsed as YAML and its fuzz discovery step run locally on the empty case ("no fuzz targets", exit 0); both jobs going green is proven on the pull request. The non-empty fuzz branch is first exercised by s03.
- `cargo fmt --all --check` passed locally but is not a `po-run` row; formatting is checked again at commit and in CI.
- QA of the `endpoint` surface belongs to `/po-qa` after the commit.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 3de2802d7cdb847aa05c959c68205e5cadfa3372 | 2026-10-21T22:00:14Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 7828aa6329f4c726ce1c4321f032b463a6dacb18 | 2026-10-21T22:00:24Z |
