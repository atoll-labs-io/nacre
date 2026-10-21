# Verification — s04-pdf-read

[Story](../stories.md) · [Plan](../plans/s04-pdf-read.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 0e80566bd24cd4ea9fc3640a52719e42499b4d46

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The fuzz target was not run under libFuzzer here: `cargo-fuzz` is not installed on this machine (`cargo +nightly fuzz --version` fails). The fuzz crate passed `cargo check --manifest-path crates/nacre-pdf/fuzz/Cargo.toml` on 1.97, and a 60 s random-mutation smoke over `tests/corpus/real/` (a scratch program under `/tmp`, release build with overflow checks, 3.7 million inputs) found no panic. The 60 s `parse` run is CI's fuzz job.
- `cargo fmt --all --check` passed locally but is not a `po-run` row; formatting is checked again at commit and in CI.
- The revision rule is proven only on the 10 files of the corpus (see the plan's pivot); other producers are not covered.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 3de06063f32f66ecd5bfd547f599482a13ca442b | 2026-10-21T22:47:58Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | 5e11842f8618eccab0a04f5edb65c5f77198bfcd | 2026-10-21T22:48:05Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | a94865215ad0844d3c05ef8206f9fe04c92926f1 | 2026-10-21T22:48:16Z |
| Unit suite | `cargo test --workspace` | 0 | 5bf2360a8ba33457fe590cc929dc585a2785ac3f | 2026-10-21T22:48:23Z |
