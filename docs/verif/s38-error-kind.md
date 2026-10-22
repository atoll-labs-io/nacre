# Verification — s38-error-kind

[Story](../stories.md) · [Plan](../plans/s38-error-kind.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 0cdc0afacae25cc2fde4cc136ad72b6869c2576f

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
Build and conformance run at ship or in CI; formatting at commit. Neither the pivot (kind meanings) nor DSS verdicts are compared here.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 75cc5264110cbfd1d0ac1e085816f39d722b9865 | 2026-10-22T08:39:19Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 5b2fe883977eb8d4c9b895e69f0abaf760698a7b | 2026-10-22T08:39:28Z |
| Unit suite | `cargo test --workspace` | 0 | 2d24433901a88ade63e99cc5aeb25c17ed6aeff6 | 2026-10-22T08:39:33Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | dc48c3e02f73fc1acc14ef12c752c82a045c08cb | 2026-10-22T08:39:33Z |
