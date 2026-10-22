# Verification — s07-tsp-client

[Story](../stories.md) · [Plan](../plans/s07-tsp-client.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 6a3fea93587690b5d8b8cfd01167810aa45c89c7

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| conformance | `cargo test -p nacre-tsp --test conformance -- --ignored` | plan task 7; against the bench TSA alone (`pki` service of `conformance/compose.yaml`) |
| no-network-deps | `test -z "$(cargo tree -p nacre-tsp -e normal -i ureq -i rustls -i ring 2>/dev/null)"` | plan task 8, criterion 4; written without a pipe so its row stays one table row; the `no-network-deps bite` row runs the same with `--features http` and `test -n` to show it finds them |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
Build at ship (`Build stage: ship-if-route`); formatting checked by hand with `cargo fmt --all --check` before commit. The conformance row ran the TSA of the bench only, not DSS: `conformance.yml` runs it again with the whole bench. The fuzz target was built and run 30 s with `cargo +nightly fuzz run response` (1.17 M runs, no crash), outside `po-run`; CI fuzzes it 60 s. No public TSA was called by any check: DigiCert and FreeTSA answers are recorded files. Tokens signed with SHA-384/512 or P-384 keys stay `Indeterminate` (FreeTSA), by design of this story. Fix run 1: the five new forged cases were each shown to bite by hand, outside `po-run` (each guard of `src/token.rs` disabled in turn turned exactly its own test of `tests/attacks.rs` red, then restored), and so was the `DigestLength` mapping of `src/http.rs` (`tests/http.rs` red without it); the fuzz target was not re-run, since `src/token.rs` is unchanged; `cargo fmt --all --check` was run again by hand.

Verification status: complete
## Runs

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| conformance | `cargo test -p nacre-tsp --test conformance -- --ignored` | 0 | c336afe7dd47d8649aba9dddcdda0dac477c86e5 | 2026-10-22T09:44:25Z |
| no-network-deps | `test -z "$(cargo tree -p nacre-tsp -e normal -i ureq -i rustls -i ring 2>/dev/null)"` | 0 | 4ce11bab24039aa50c45c13397f4c6d290b61d3d | 2026-10-22T09:44:25Z |
| no-network-deps bite | `test -n "$(cargo tree -p nacre-tsp -e normal --features http -i ureq -i rustls -i ring 2>/dev/null)"` | 0 | 66d6ac635c2d09b5df6e409d429968ec4ca23493 | 2026-10-22T09:44:25Z |
| Unit suite | `cargo test --workspace` | 0 | d3008aae4a6822e8f70d1a4a1ba884eb406b069b | 2026-10-22T09:44:33Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 08f08ab55229fbbcb14ecc668be3209ce9d49c55 | 2026-10-22T09:44:36Z |
| conformance | `cargo test -p nacre-tsp --test conformance -- --ignored` | 0 | f43368b2864f10fbf013711be1043b3c45c22943 | 2026-10-22T11:36:28Z |
| no-network-deps | `test -z "$(cargo tree -p nacre-tsp -e normal -i ureq -i rustls -i ring 2>/dev/null)"` | 0 | 650c6a8e2dcfb1901798129bbff8d305433c427e | 2026-10-22T11:36:36Z |
| no-network-deps bite | `test -n "$(cargo tree -p nacre-tsp -e normal --features http -i ureq -i rustls -i ring 2>/dev/null)"` | 0 | 1f775c9886710c977f33ffd0329a30c43e46349b | 2026-10-22T11:36:36Z |
| Unit suite | `cargo test --workspace` | 0 | bef7fef835fbc55b30bf1850ede58fcdbaf9116c | 2026-10-22T11:36:38Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 5fddecf128ee058fb8b7de4d475aeebd5c01837b | 2026-10-22T11:36:42Z |
