# Verification — s13-pkcs11-signer

[Story](../stories.md) · [Plan](../plans/s13-pkcs11-signer.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: f7a7ab015ec9a7576c98c185492665db31f061cd

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- The seven SoftHSM tests (`tests/softhsm.rs`) are `#[ignore = "conformance"]`, so the unit suite skips them; they passed locally on SoftHSM 2.7.0 (`cargo test -p nacre-pkcs11 --test softhsm -- --ignored`, outside this record) and run in `conformance.yml` on Ubuntu's SoftHSM 2.6.1, whose context-specific login is unverified.
- The DSS verdict (`tests/conformance.rs`, `softhsm_signature_is_pades_baseline_b`) was compiled, never run: the bench is down on this machine. CI's conformance job runs it.
- The manual YubiKey run (criterion 5, `crates/nacre-pkcs11/MANUAL.md`) is the person's and is **not run**; `libykcs11`'s always-authenticate handling of slot 9c is unproven until then.
- `FinalTry` and `Locked` are proven only by the unit mapping test; the PIN's zeroization itself is not testable safely and rests on the types and the review.
- `refused_context_pin_is_never_sent_again` shows the signer answers `PinRefused` without a token call after a refusal; on SoftHSM an unguarded signer would stop at `C_SignInit` (`OperationActive`) anyway, so how `libykcs11` treats a refused context login stays for the person's run.
- Build scripts of the new dependencies were read, not run in isolation: `cryptoki-sys` 0.5.0's `build.rs` does nothing without its `generate-bindings` feature, which is not enabled.
- Build at ship; formatting at commit.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | b7e5c25ff94869ee71f3e92999eae5763a1b3394 | 2026-10-22T11:20:03Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 5bc65779df704b9aa10f34032918e56007eaafe0 | 2026-10-22T11:20:08Z |
| Unit suite | `cargo test --workspace` | 0 | 812b9792ab82ea2fc302012ad69ac861e8fc374e | 2026-10-22T11:35:56Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | ccf8f02f7f664546659bff7082f82a869b31b3bf | 2026-10-22T11:36:01Z |
