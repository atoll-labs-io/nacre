# Verification — s14-validate-integrity

[Story](../stories.md) · [Plan](../plans/s14-validate-integrity.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 46cb77c117b96c80b7492aca065255da22f8527f

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- DSS parity of the sub-indications (USF, SWA, ISA cases, the CMS error mapping, `UnsupportedSubFilter`) is not checked: no bench run in this story; s18's campaign compares them.
- The fuzz target `crates/nacre-validate/fuzz/` ran once here for 20 s (`cargo +nightly fuzz run validate -- -max_total_time=20`, about 1.17 million runs, no crash), outside `po-run`; CI's `fuzz` job runs it at each push.
- The forge reproduces the corpus byte for byte: run three times (`cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks`), `sha256sum -c` against the first run's sums each time, all identical. Not a `po-run` row.
- `cargo fmt --all --check` passed on the final code, not recorded as a `po-run` row; formatting is checked again at commit and in CI.
- Only one third-party signature (`certified-dss.pdf`, LibreOffice, RSA) goes through `validate` in the tests; the pyHanko files were probed by the research, not tested here.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 0485f878767be917ea9ca849b751777a7982cc6a | 2026-10-22T10:27:27Z |
| Unit suite | `cargo test --workspace` | 0 | 8f15c932833b2a6ae4517bc2281fb1230cba9561 | 2026-10-22T10:27:52Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | d97d1a9efdd16b302c2007538936ce5d80ccf897 | 2026-10-22T10:27:57Z |
| Unit suite | `cargo test --workspace` | 0 | 5d30eef607c40d9638d9153bccf60dbea2ca164a | 2026-10-22T10:28:13Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 875a192f41d01e4ab4e226144a874064c5c3d08e | 2026-10-22T10:28:13Z |
