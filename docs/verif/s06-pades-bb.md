# Verification — s06-pades-bb

[Story](../stories.md) · [Plan](../plans/s06-pades-bb.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 3c2e58653aa7444de7094e42919ceacd5ace8ceb

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| Conformance (DSS) | — | the two `#[ignore = "conformance"]` tests of `crates/nacre-pades/tests/conformance.rs`; the bench was down here, so CI's `conformance.yml` runs them |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The two DSS verdicts (criteria 1 and 3: `TOTAL_PASSED`, `PAdES-BASELINE-B`, once and after a second revision) are not proven here: the nacre bench was not running (`127.0.0.1:18080` closed, `conformance/pki/out/` absent), so `cargo test -p nacre-pades --test conformance -- --ignored` was not run. CI's `conformance.yml` runs them; `BenchSigner` has only been compiled, never loaded against a real bench PKI.
- Whether DSS 6.5.1 accepts `ESSCertIDv2` without `issuerSerial` at B-B rests on that same CI run.
- The RSA reserve is proven by `rsa_bound_covers_the_signature` on one OpenSSL RSA-2048 CMS; no RSA signer signed a PDF here.
- `cargo fmt -p nacre-pades` was applied, not recorded as a `po-run` row; formatting is checked again at commit and in CI.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 944e74b78bc1ec3acfc656a0417c30acfdd95036 | 2026-10-22T09:36:40Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | ed12e987dd6c1c3c6b7d2e8dab866b61ec4fa556 | 2026-10-22T09:36:50Z |
