# Verification — s42-tsa-freshness

[Story](../stories.md) · [Plan](../plans/s42-tsa-freshness.md)

Tree: 825d5df45395f8d6ddf71c3e40d0ee4e4e8da09a

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| Conformance | `cargo test -p nacre-validate --all-features --test conformance -- --ignored` | bench started fresh, then stopped |
| End to end | — | deferred to ship |
| Build | — | deferred to ship |

## Not proven here
The DSS campaign (`sh conformance/campaign/run.sh`) passed on a fresh bench on the previous code tree and left `campaign-dss.md` and `campaign-strict.md` unchanged (no new difference); it was not rerun after the doc-line rewraps. The live `http` source, end to end and build at ship.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 4a5f776a7b0e59d00b1f393d57490ccc7de8cc18 | 2026-10-24T23:47:01Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 8788fccb1ce3fe6c0b2f5c94af7102edba651c01 | 2026-10-24T23:47:12Z |
| Conformance | `cargo test -p nacre-validate --all-features --test conformance -- --ignored` | 0 | a415a6979e4da9cf35431dfa9aa0990c65016f67 | 2026-10-25T09:57:55Z |
| Unit suite | `cargo test --workspace` | 0 | d8501ad4cf1b53964a0b176a14fe10b2570c8cca | 2026-10-25T10:01:25Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 100103499c6e6dc678697b83d9f456f62511a2b3 | 2026-10-25T10:01:26Z |
| Unit suite | `cargo test --workspace` | 0 | 59c1c8737c01940add5603c6ce241533d51ce232 | 2026-10-25T10:02:31Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 7c5dab395fdff14212715bdc9b5573ea45f8d39c | 2026-10-25T10:02:32Z |
| Conformance | `cargo test -p nacre-validate --all-features --test conformance -- --ignored` | 0 | dbcc58c6276196235e79387ab55dbea3c58ee5cc | 2026-10-25T10:03:01Z |
