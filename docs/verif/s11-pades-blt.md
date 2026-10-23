# Verification — s11-pades-blt

[Story](../stories.md) · [Plan](../plans/s11-pades-blt.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 46653e08a812d274f5a0d4ac14886bad38fc3e66

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
The conformance test `bench_signature_is_pades_baseline_lt` (new, in `crates/nacre-pades/tests/conformance.rs`) is `#[ignore = "conformance"]`: the unit suite skips it and the CI conformance job runs it. It passed locally, with the three earlier pades conformance tests, through `cargo test -p nacre-pades --test conformance -- --ignored` against a freshly started bench (`down`, `pki-init`, `up -d`, `check.sh` said `bench ready`); DSS 6.5.1 judged the signature `TOTAL_PASSED` at `PAdES-BASELINE-LT`, report in `target/conformance/s11-pades-lt.xml`, outside this record. No public TSA, OCSP responder or CRL server was contacted. The name-loop guard of the issuer walk has no test (plan, test strategy). Build at ship; formatting at commit (`cargo fmt --all --check` passed).

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 4453e5c0e4eb882812aeae800c9e824f36ecb850 | 2026-10-23T10:18:55Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | 01a49be41c2c456dfa23fee5da6c34d9f14a3811 | 2026-10-23T10:19:06Z |
| Unit suite | `cargo test --workspace` | 0 | b62f5bd38e11b045d0eb73190c34288d5920bb87 | 2026-10-23T10:19:42Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | fdad02030132ca4331f7a9a05cbe2ea36197ef16 | 2026-10-23T10:19:42Z |
