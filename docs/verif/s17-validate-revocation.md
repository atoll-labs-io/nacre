# Verification — s17-validate-revocation

[Story](../stories.md) · [Plan](../plans/s17-validate-revocation.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 10ccc0be1714a32241b5f5939108a7aaf640961c

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- C0 to C6 (`tests/conformance.rs`, `#[ignore = "conformance"]`): run once here, all 7 green, `cargo test -p nacre-validate --all-features --test conformance -- --ignored --test-threads 1`, against the bench started as `conformance/README.md` says (fresh `pki-init`, `check.sh` ended `bench ready`), then stopped with `podman compose -f conformance/compose.yaml down`; Nacre and DSS 6.5.1 gave the same indication and sub-indication on each file. Fix run 1 ran them again the same way, all 7 green, `confront` now also asserting the PAdES level DSS reports, and stopped the bench. Not a `po-run` row; the conformance CI job reruns them.
- Fix run 1's freshness rule (`FRESHNESS_TOLERANCE`, 24 h) is proven by R13 on a `/DSS` CRL only: an old OCSP response, an old answer of a `RevocationSource` and the exact 24 h boundary have no test of their own.
- The pivot's OCSP risk (DSS picking by `thisUpdate` rather than `producedAt`) was not tried with a bench OCSP response past its five-minute `nextUpdate`: C4 judged the `/DSS` within seconds of signing.
- RSA keys, OCSP responses built at test time, a CRL without `nextUpdate`, `certificateHold` / `removeFromCRL` and revocation data carried in the CMS `crls` field are exercised by no test; OCSP parsing is reached only through the bench (C0, C2, C3, C4).
- The 256-item cap, the drop of unreadable items and repeats before it, and the order (signature CMS, then token CMS, then `/DSS` CRLs, then `/DSS` OCSPs) have no test of their own.
- The fuzz target (`fuzz/fuzz_targets/validate.rs`) reaches the new code through `validate_with_anchors`; it was not run in this story.
- `cargo fmt -p nacre-validate` was applied, not recorded as a `po-run` row; formatting is checked at commit and in CI.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 067ee04620fd83973edb336528033dc088224f59 | 2026-10-23T17:03:43Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 75f4a051a995245a73f53be78981c0e09798a8e3 | 2026-10-23T17:04:36Z |
| Unit suite | `cargo test --workspace` | 0 | 53ce26ea8fcad3d365e3ef767884b230c7f3fc15 | 2026-10-23T20:42:47Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 78a719bf505319f65555768b5b16020659f7f726 | 2026-10-23T20:42:51Z |
