# Verification — s09-revocation-crl

[Story](../stories.md) · [Plan](../plans/s09-revocation-crl.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 6c54fa21c69a902bb11868ac9d23231dfb745be3

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
The bench conformance test `revoked_is_listed_and_signer_is_not_on_the_bench` is `#[ignore = "conformance"]`: the unit suite skips it and the CI conformance job runs it. On the fix run it passed locally with `HttpCrlSource::allowing_loopback()` against a stand-in server (Python `http.server` on 127.0.0.1:18081 serving the bench PKI's `intermediate.crl` and `root.crl` from `conformance/pki/out/` under `/crl/`), not the bench's own PKI container, outside this record. The fuzz target `crl` is compiled and run by the CI fuzz job only (checked here with `cargo check` on stable, not fuzzed). A DNS name resolving to a non-public address is covered through the same resolver path as an IP literal, not with a real DNS name. Build at ship; formatting at commit (`cargo fmt --all --check` passed).

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | ea43f223a084eb9754df6d60eac1f60b19f6efce | 2026-10-22T09:42:13Z |
| Unit suite | `cargo test --workspace` | 0 | 47ab527c305a11f456d5069e556225407b3ba966 | 2026-10-22T09:42:35Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | f3726c39c79df62c875035e948fc6c17b61b8d0a | 2026-10-22T09:42:42Z |
| Unit suite | `cargo test --workspace` | 0 | 870497db72df9c1b5829ece27af18fe583bd86aa | 2026-10-22T09:43:02Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | d0f066d1a6acd6d8a9e8b8d89c44fd5528bce6eb | 2026-10-22T09:43:03Z |
| Unit suite | `cargo test --workspace` | 0 | 4c431fc7053a6c6b1a91f24f961ac79f603273eb | 2026-10-22T11:39:30Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | c53a0cb1b1cfd45e333529cb89db7eff0158efce | 2026-10-22T11:39:35Z |
