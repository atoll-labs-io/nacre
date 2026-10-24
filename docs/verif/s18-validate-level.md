# Verification — s18-validate-level

[Story](../stories.md) · [Plan](../plans/s18-validate-level.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: c86bb0fbd8b765041ca992162760c3b813a33ef2

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`; `crates/nacre-validate/Cargo.toml` changed, dev-dependencies `serde_json`, `ureq`, `base64ct`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The campaign (task 9, `tests/campaign.rs`, `#[ignore = "conformance"]`) ran on the bench started per `conformance/README.md` (fresh PKI, `check.sh` ended `bench ready`), through `sh conformance/campaign/run.sh`: 257 cases (79 committed files, 178 bench cases), 0 difference under `dss()`, 94 differences under `strict()`, all explained, 0 unexplained. Its tables and 252 DSS XML reports are in `conformance/campaign/reports/`. Not a `po-run` row; CI's `conformance.yml` reruns it with the other ignored tests. After that run, only mechanical edits reached the code: `cargo fmt`, clippy's fixes (`std::slice::from_ref`, `.iter()`), a type alias in `tests/level.rs`, rustdoc wording, and one equivalent rewrite of a condition in `level.rs` (`first_counts`). The campaign was not rerun on them.
- The conformance tests (`cargo test -p nacre-validate --all-features --test conformance -- --ignored`, 33 passed, the two new ones `anchor_delegated_responder_policy` and `critical_ocsp_extensions_policy` included) ran once on the same bench, before `/DSS` data were gathered over revisions for the level (the campaign, run after, covers that change). Not a `po-run` row.
- The bench was stopped afterwards (`podman compose -f conformance/compose.yaml down`); `patelle-dss` was left running.
- Left open by the plan's pivot and not observed: R's exemption on a revoked CA or under a non-self-signed anchor; C on an OCSP extension DSS knows and rejects (nonce mismatch); LT through a delegated OCSP response; several document timestamps around several `/DSS` beyond r5–r8 and l30.
- The fuzz targets were not run; CI's `fuzz` job covers them.
- `cargo fmt --all` was applied, not recorded as a `po-run` row; formatting is checked at commit and in CI.
- Build: deferred to ship (a manifest changed: `crates/nacre-validate/Cargo.toml`, dev-dependencies `serde_json`, `ureq`, `base64ct`).
- Fix run 1 (review findings): the campaign ran again through `sh conformance/campaign/run.sh` on a bench started afresh per `conformance/README.md` (`check.sh` ended `bench ready`), on the final code of this run: 257 cases, 0 difference under `dss()`; 94 explained under `strict()`, 0 unexplained; 259 files kept in `conformance/campaign/reports/`, the five `*.error.txt` included (all `HTTP 500` from DSS: wrong password on `hostile-aes256`, no root object on the two xref cases, `repeated extension found: 2.5.29.15` on `n04` and `chain-malformed-extension`). With DSS down, the campaign stopped in 0.00 s with `DSS does not answer at http://127.0.0.1:18080 (io: Connection refused …)`. Neither is a `po-run` row. The bench was stopped afterwards; `patelle-dss` was left running. The conformance tests (`tests/conformance.rs`) were not rerun in this fix run.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 03237c5da137ecd7a4796bee650b74b8496082a4 | 2026-10-24T22:32:51Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | 183f0a642663fd3a8fa956fca0e620e09b3d0035 | 2026-10-24T22:33:22Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | 564ae79052fcb6c775d435b9f2c0090dd17bfd81 | 2026-10-24T22:33:38Z |
| Unit suite | `cargo test --workspace` | 0 | 5475ccb163895193c6eee33859e10d6e9283b3a6 | 2026-10-24T22:35:12Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | e753932c67199d16b63548e309e279143b6f4ab7 | 2026-10-24T22:35:13Z |
| Unit suite | `cargo test --workspace` | 0 | d9ba87d528aeced1054232e83db644a08862df7c | 2026-10-24T23:09:39Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 9c009119f6fb3df7d93c1b3e6abf943194b8b47d | 2026-10-24T23:09:44Z |
