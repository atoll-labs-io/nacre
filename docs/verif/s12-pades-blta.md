# Verification — s12-pades-blta

[Story](../stories.md) · [Plan](../plans/s12-pades-blta.md)

The link line under the title is part of this template: it is copied with it, never edited after the copy, and is not one of the implementer's lines.

The implementer writes this file before its final runs, then edits only `Tree:`, the `## Checks` table, "Not proven here" and the status line. `po-run` writes the `## Runs` section, one row per launch; no one else touches it. The gate compares the tree of each run with `Tree:` outside `docs/`: a declared check counts only through its runs on that code, and the last of them must have exited 0. Commands are copied exactly from `AGENTS.local.md`.

Order that produces `Tree:` — `git add -A`, then `git write-tree`. The hash therefore names the exact code the checks ran on. This file and the plan's ticks live inside `docs/`, which the comparison leaves out.

Tree: a9ba5c23f4a84a1d7d2268495583fd12a04d944f

## Checks
| Check | Command | Note |
| --- | --- | --- |
| Unit suite | `cargo test --workspace` | |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | |
| End to end | — | no such command in this project |
| Build | — | deferred to ship |

A row with a command is a check you launch through `po-run`. A check not run at this stage, or one the project does not have, gets `—` as its command and says why in Note ("no such command in this project", "deferred to ship").

## Not proven here
The conformance tests `bench_signature_is_pades_baseline_lta` and `extended_signature_stays_pades_baseline_lta` (new, in `crates/nacre-pades/tests/conformance.rs`) are `#[ignore = "conformance"]`: the unit suite skips them and the CI conformance job runs them. They passed locally, with the four earlier pades conformance tests, through `cargo test -p nacre-pades --all-features --test conformance -- --ignored` against a freshly started bench (`down`, `pki-init`, `up -d`, then `check.sh` said `bench ready`, including the new `tsa2` check). DSS 6.5.1 judged both files `TOTAL_PASSED` at `PAdES-BASELINE-LTA`, with the signature timestamp produced by `Nacre Test TSA` and the document timestamp by `Nacre Test Document TSA`, each `PASSED`; after `extend` the third timestamp (`Nacre Test TSA`) is also `PASSED`. The reports are in `target/conformance/s12-pades-lta{,-extended}.{xml,json}`, outside this record. No public TSA, OCSP responder or CRL server was contacted. Fix run (review findings of `docs/reviews/s12-pades-blta.md`): the six pades conformance tests were run again by hand on the fixed code, against a bench started afresh the same way (`check.sh` said `bench ready`, both TSAs included), and all six passed, `bench_signature_is_pades_baseline_lta` and `extended_signature_stays_pades_baseline_lta` among them; the bench was stopped afterwards. The certificate-less token, the non-zero padding and the renewing TSA failure are proven by unit tests only, never against DSS; a signer found in a filtered (compressed) foreign `/DSS` stream is not read, and is refused as missing. The bench shell changes (`conformance/`) are proven only by that `check.sh` run. Build at ship; formatting at commit (`cargo fmt --all --check`).

Second fix run (CI `conformance` failure on PR #101, `Refused { status: 2, fail_info: Some(131072) }`, and the review's major). Root cause, proven by hand and not by a recorded check: `openssl ts -reply` truncates and then rewrites the section's serial file, so a concurrent request that reads it in between is answered "rejection, addInfoNotAvailable" (bit 17 = 131072), with the description "Error during serial number generation" and `a2i_ASN1_INTEGER: short line` on stderr. 40 parallel replies on a copy of the PKI gave 2 rejections. 40 parallel `curl` requests to the bench built before the fix (`tsa` and `tsa2`) gave 2 rejections. With `cgi-bin/tsa` taking one `flock` per section, 60 local replies and 3 x 40 bench requests were all granted, with no duplicate serial. Parallel tests in one binary (T, LT, LTA, extend) reach that window more often on a CI runner. After `down`, `pki-init`, `build pki`, `up -d`, `check.sh` (`bench ready`) and `reference/generate.sh`, `cargo test --workspace --all-features --no-fail-fast -- --ignored` passed everywhere except `nacre-pdf` `qpdf_check_is_clean`, since qpdf is not installed on this host (CI installs it). The pades and tsp conformance tests then passed 5 times in a row. The bench was stopped afterwards. A `/DSS /Certs` stream that is filtered or not a certificate is now left out (unit test `extend_leaves_out_a_dss_stream_that_is_not_a_certificate`), and a signer held only in such a stream is refused as missing. That case was never run against DSS or a foreign file.

Verification status: complete

## Runs
Written by `po-run`, one row per launch. Never edit, reorder or delete a row.

| Check | Command | Exit | Tree | Time (UTC) |
| --- | --- | --- | --- | --- |
| Unit suite | `cargo test --workspace` | 0 | 22f13cfab714a336dd6f9821804c77d209b39fb5 | 2026-10-23T10:56:17Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | c466dcc1b13037e9db764cc1031fa33c72e2d2fe | 2026-10-23T10:56:28Z |
| Unit suite | `cargo test --workspace` | 0 | 485ba936cfcc04d0eed1e222080f977250e26216 | 2026-10-23T11:11:15Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 7711ac4ad01e76ad08a38407ef9b719ed782c2f8 | 2026-10-23T11:11:20Z |
| Unit suite | `cargo test --workspace` | 0 | 17a2ee7a10f36bcc4496bd12d7da0b4744148639 | 2026-10-23T11:34:33Z |
| Type check | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 9de397c804e92f1bc6a45337c874d00ff9213c46 | 2026-10-23T11:34:37Z |
