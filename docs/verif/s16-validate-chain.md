# Verification — s16-validate-chain

[Story](../stories.md) · [Plan](../plans/s16-validate-chain.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: 566d89d5b59cee43525e4cc7577890040029cef5

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship (`Build stage: ship-if-route`) |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
- Criterion 1 (`bench_chain_is_valid`, `#[ignore = "conformance"]`): run once here, green, against a PKI generated on the host by `sh conformance/pki/generate.sh` (OpenSSL 3.6.5; fixed validity 2026-01-01 to 2046-01-01), with no container started; the generated `conformance/pki/out/` was then deleted. Not a `po-run` row; the conformance CI job reruns it.
- The sub-indications of criterion 3 (`OUT_OF_BOUNDS_NO_POE`, `CHAIN_CONSTRAINTS_FAILURE`, `CERTIFICATE_CHAIN_GENERAL_FAILURE`) and the `TRY_LATER` outcome of a valid chain are the plan's decision, not compared with DSS: the forged PKI is not DSS's anchor. s18 compares.
- The forge `forge_chain_attacks` was run twice: identical SHA-256 for every file. Every earlier corpus file is untouched (`git status` lists only new files); `forge_pades_attacks` was not run. Fix run: run twice again, the four new attack files identical across runs and every earlier chain file unchanged. Fix run 2: run twice again, identical across runs; `chain-dss.pdf` and every other earlier chain file unchanged, except `attacks/chain-extended-key-usage.pdf`, rewritten on purpose (its `extendedKeyUsage` is now non-critical, review fix loop 1 minor), and the new `attacks/chain-dss-junk.pdf`; README rows updated.
- Name matching is DER byte equality of `subject` / `issuer`, stricter than RFC 5280 §7.1 normalisation; an anchor's own validity and extensions are not judged; revocation and the TSA chain are not judged (s17).
- `hostile.rs` drives `validate_with_anchors` over every attack file, the chain ones included. Fix run: the fuzz target now also calls `validate_with_anchors` with `chain/root.der` at 2026-10-22; it was run once by hand, `cargo +nightly fuzz run validate` seeded with the chain PDFs, 60 s, 227 348 runs, no crash. Not a `po-run` row.
- Fix run: the look-alike case of review finding 1 is tested on `build_chain` (`look_alikes_do_not_hide_the_issuer`, 100 look-alikes), not through a PDF carrying them in its CMS or an appended `/DSS`; `validate_with_anchors` passes that pool unchanged to `build_chain`. Fix run 2: the junk `/DSS` case is tested through a PDF (`chain_dss_junk_does_not_hide_the_chain`); the uncertified-graph, broken-twin and pool-cap cases on `build_chain` only. The `certified` filter was disabled once by hand: `uncertified_graph_does_not_hide_the_issuer` failed, the filter was restored.
- RSA certificate paths are still exercised by no test (every corpus key is P-256).
- Fix run 3 (person's decision of 2026-10-23, EKU only): the `extendedKeyUsage` rule now judges the signer alone, and `id-kp-clientAuth` joins `SIGNING_PURPOSES`; an issuer's EKU is still decoded, so a doubled or undecodable one still gives `MalformedExtension`, but that case on an issuer has no test. No corpus file changed and the forge was not rerun: `chain-extended-key-usage.pdf` names `serverAuth` alone and stays refused. The accepted `clientAuth` signer is forged in `tests/chain.rs`, not through a PDF.
- `cargo fmt -p nacre-validate` was applied, not recorded as a `po-run` row; formatting is checked at commit and in CI.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 7adc26bf4ec9d80717e5f359041d4cc66f92dea7 | 2026-10-23T14:59:41Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 101 | 2b92bc859f9d55331530149113ca82cba33d5698 | 2026-10-23T14:59:53Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 2d98de147da0c58896b8baf0f8ba54c5cf3d5c7f | 2026-10-23T14:59:58Z |
| Unit suite | `cargo test --workspace` | 0 | 7438d48d66f1947a26f4236a29d9ed0c7becb6f5 | 2026-10-23T15:00:43Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | b22a1e69cfbbbd5f739c3fbff12632e82e659c4d | 2026-10-23T15:00:43Z |
| Unit suite | `cargo test --workspace` | 0 | d95bd328a3afb59931b4061dcbe4d4337d3e5d43 | 2026-10-23T15:22:26Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 441b543200c4dd986512a6b9f3cebdc2d1f79c1c | 2026-10-23T15:22:31Z |
| Unit suite | `cargo test --workspace` | 0 | 22b28504fc7b31d254795c606ae5ba4e5b7a3d78 | 2026-10-23T15:42:44Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 52016be0063ff85d5a801e21f7fee488f4088c4d | 2026-10-23T15:42:48Z |
| Unit suite | `cargo test --workspace` | 0 | 0bf4a10061e922e58fee74303343843190df0e35 | 2026-10-23T16:10:59Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 7101461de49fbfda4b5b55f4a779bc7905d3ace9 | 2026-10-23T16:11:06Z |
