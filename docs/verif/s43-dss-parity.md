# Verification — s43-dss-parity

[Story](../stories.md) · [Plan](../plans/s43-dss-parity.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 7680066e783303f09cec61ec42bf8f6be43a9bd9

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The six conformance tests of task 9 (`tests/conformance.rs`, `#[ignore = "conformance"]`) ran once on the bench started per `conformance/README.md` (fresh PKI, `check.sh` ended `bench ready`), with the sixteen earlier ones: `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, 22 passed, DSS giving every verdict of the research's table. Not a `po-run` row; CI's `conformance.yml` reruns them. The bench was stopped afterwards; `patelle-dss` was left running.
- n04 checks only that DSS answers with an error, not that it is an HTTP 500 specifically.
- The fuzz targets were not run nor rebuilt; only `nacre-pdf`'s `parse` target calls `signature_fields`, and it builds no `SignatureField`. CI's `fuzz` job covers them.
- `cargo fmt` was applied to `nacre-validate` and `nacre-pdf`, not recorded as a `po-run` row; formatting is checked at commit and in CI.
- The research's open questions stay unproven: a missing or non-name `/SubFilter` under `dss()`; `expiredCertsOnCRL` and `archiveCutoff`; the late-data rule on a CA, a TSA or an OCSP response (applied to all alike, observed by DSS on the signer only); which defect DSS reports first when `/M` is missing and revocation fails; a document-timestamp certificate repeating an extension (s18).
- Build: deferred to ship (no routing or manifest change).

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 0827959d4ef22b054665ec24694a4a7b42eb17a6 | 2026-10-24T10:35:14Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | a2b8bb78a0553cfddc5ca4518c6c8c9cf68a918f | 2026-10-24T10:35:25Z |
| Unit suite | `cargo test --workspace` | 0 | f4e2696f1d35dbbd925fea71e48334d722eeac50 | 2026-10-24T10:36:29Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 36c2873d05395d777fdc96a7da1305375a9f0cd5 | 2026-10-24T10:36:29Z |
