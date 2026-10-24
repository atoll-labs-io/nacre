# Verification — s46-dss-parity-3

[Story](../stories.md) · [Plan](../plans/s46-dss-parity-3.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 932699ae8715ed65e7cd43fde3a00fa1b8a15154

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`; `crates/nacre-validate/Cargo.toml` changed, dev `der` gains `derive`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The four conformance tests of task 8 (`tsa_ca_without_key_identifier_policy`, `issuer_of_revoked_data_policy`, `delegated_responder_policy`, `archive_cutoff_policy`, `#[ignore = "conformance"]`) ran once on the bench started per `conformance/README.md` (fresh PKI, `check.sh` ended `bench ready`), with the twenty-seven earlier ones: `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, 31 passed, every DSS verdict the spike's. Not a `po-run` row; CI's `conformance.yml` reruns them. The bench was stopped afterwards; `patelle-dss` was left running. The final change to the forged responder (a `subjectKeyIdentifier`, as the spike's) was made before that run.
- e2 with a proof of existence (the "both presets" shape of AC3) is proven offline only (`delegated_responder_out_of_validity`), not against DSS, as the research says.
- Left open by the plan's pivot: the exemption on a revoked CA at depth > 0, on a `certificateHold` or on delegate-signed data; a delegate of the anchor; a delegate's own revocation; `archiveCutoff` outside `singleExtensions` or critical.
- The fuzz targets were not run; CI's `fuzz` job covers them.
- `cargo fmt --all` was applied, not recorded as a `po-run` row; formatting is checked at commit and in CI.
- Build: deferred to ship (a manifest changed: `crates/nacre-validate/Cargo.toml`, dev `der` features).

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 4ec9f8da63d8049afe42309b6e1bbcb366c69379 | 2026-10-24T19:59:09Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 789c533ffe230d418279947eae40f1b4b3a2053f | 2026-10-24T19:59:25Z |
