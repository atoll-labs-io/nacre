# Verification — s10-revocation-ocsp

[Story](../stories.md) · [Plan](../plans/s10-revocation-ocsp.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 8d1796ab53f72b381c97071ba4ead15f909a72c4

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
The bench conformance tests in `crates/nacre-revocation/tests/bench.rs` (`ocsp_says_revoked_and_good_on_the_bench`, new, and `revoked_is_listed_and_signer_is_not_on_the_bench`) are `#[ignore = "conformance"]`: the unit suite skips them and the CI conformance job runs them. Both passed locally with `cargo test -p nacre-revocation --test bench -- --ignored` against the bench's own `pki` container (fresh `pki-init`, then `podman compose -f conformance/compose.yaml up -d pki`, DSS not started), outside this record. The fuzz target `ocsp` is compiled only (`cargo build --bins` in `crates/nacre-revocation/fuzz/`, stable), not fuzzed; `cargo fuzz build` and fuzzing belong to the reviewer and the CI fuzz job. The OpenSSL corpus script of `tests/corpus/README.md` and the `forge_ocsp_attacks` example were run once each (the example twice, byte-identical output). No public OCSP responder was contacted. Fix run 1: the `forge_ocsp_attacks` example was rerun once, its earlier files came out byte-identical and it added `expired-delegate.der` and `expired-delegate-response.der`; the bench tests and the fuzz target were not run again. Build at ship; formatting at commit (`cargo fmt --all --check` passed, and `cargo fmt --check` in the fuzz crate).

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | e02e95b3d9f9a260559a81b1c2cda0a2b036a884 | 2026-10-23T09:16:12Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 39445759a8021acdd73b3ab29c8d60a395d24fc0 | 2026-10-23T09:16:34Z |
| Unit suite | `cargo test --workspace` | 0 | 7a71a1d3f9115c51e48de833fe08683a53426694 | 2026-10-23T09:39:21Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 44ebeacfdbf8bc55b6fe0abac6182c6af06b168c | 2026-10-23T09:39:26Z |
