# Review — s02-conformance-harness

Story: s02-conformance-harness — The conformance bench: pinned DSS, test PKI, TSA, OCSP and CRL server
Worktree: /home/lecrabe/dev/atoll/nacre/.worktrees/s02-conformance-harness
Diff judged: `git diff main...story/s02-conformance-harness` (one commit, 8184c41)
Reviewed tree: 9a7d97d49dd4e549fc26b20e442c3656e89cbb60
Fix loop: 0
Review status: complete
Lenses run: Security (`conformance/pki/cgi-bin/tsa`, `conformance/pki/cgi-bin/ocsp` are HTTP handlers; `Dss::new` builds an HTTP call from a URL taken from `NACRE_DSS_URL`); Dependencies (`crates/nacre-conformance/Cargo.toml` adds `thiserror`, `serde_json`, `base64ct`, optional `ureq`)

## Scope
I checked every changed path against the `Owns` line of s02: `conformance/`, `crates/nacre-conformance/`, `.github/workflows/conformance.yml`. Every path is inside it.
- `docs/plans`, `docs/research` and `docs/verif` for s02 are the story's own pipeline evidence.
- `docs/decisions/0011-bench-pki-tsa-ocsp-on-openssl.md` is added (status A), the plan names it, and it is `accepted`.
- The frozen files all have an empty diff: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `ci.yml`, `crates/nacre-core/` and `docs/stories.md`.
- The other running lane, s38-error-kind, owns `crates/nacre-core/` and two `error.rs` files. None of them overlaps this diff.

## What was relied on and what was run
- **Verification record:** `po-gate verif-current` exits 0 and `Verification mode` is `record`. The unit suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) are taken from the record and were not rerun. Its "Not proven here" section was read.
- **QA:** none required. `Surface` is `—`, so with `QA stage: surfaces` the story does not go to QA.
- **Floor guard:** `po-gate floor-guard s02-conformance-harness main` exits 0. It printed an awk multibyte-locale warning, caused by the binary `unsigned.pdf`.
- **Bench, run by me against the running containers (`nacre-conformance_dss_1`, `nacre-conformance_pki_1`):**
  - `sh conformance/check.sh` exits 0: chain OK, CRL lists serial 2002, TSA token verifies, OCSP gives `good` and `revoked`.
  - `NACRE_DSS_URL=http://127.0.0.1:18080 cargo test -p nacre-conformance --test dss_reference -- --ignored`: 2 passed.
  - `ss -ltn` shows only `127.0.0.1` listeners on 18080 and 18081, and nothing on 8005.
- **Interdicts:**
  - The diff adds no `PRIVATE KEY` line, no `.p12` and no `.key` file.
  - `conformance/pki/out/` and `conformance/reference/out/` are ignored.
  - `cargo tree -p nacre-conformance -e normal` without features shows no `ureq`.
  - `src/` has no `unwrap`, `expect`, `panic!` or indexing.
- **Mutation tests (does each rule fail a test when broken?):**
  1. Removed the host allow-list in `Dss::new` (`client.rs:35`, kept only `!port_is_valid`), then ran `--test client`: 1 of 2 failed (`only_a_dss_on_this_machine_is_accepted`). Restored, `git diff --exit-code` clean.
  2. Accepted `TOTAL_PASSED` with a sub-indication as passed (`report.rs`), then ran `--test report`: 1 of 5 failed (`inconsistent_verdicts_are_errors_not_panics`). Restored, `git diff --exit-code` clean.
- **References opened:** `nacre_core::{Indication, SubIndication::ALL, as_str, SignatureForm::Pkcs7, SignatureProfile::*, ValidationReport::{passed, failed, indeterminate}}` exist with the signatures used (`crates/nacre-core/src/report.rs`). The two recorded fixtures really hold `TOTAL_PASSED` / `PAdES-BASELINE-B` and `INDETERMINATE` / `REVOKED_NO_POE` / `PAdES-BASELINE-B`, with `SignatureLevel` = `N/A`. That confirms the plan's second hinge: the level comes from `SignatureFormat`.
- **Test count:** 9 tests (5 + 2 + 2), within `Test budget` 25, matching the plan.

## Findings
- **minor** — `conformance/pki/openssl.cnf:72,81`, `conformance/check.sh`, `conformance/pki/README.md`, `conformance/README.md:20`: the responders sit at `POST /cgi-bin/tsa` and `POST /cgi-bin/ocsp`, and the leaf certificates' OCSP AIA is `http://127.0.0.1:18081/cgi-bin/ocsp`. Plan tasks 1 and 2 and ADR-0011 option 1 say `/tsa` and `/ocsp`. This is an unrequested change: it is consistent across the bench and documented in both READMEs, but it is the URL s07 and s09/s10 will code against. Either make the plan and ADR wording match through the lead's log, or serve `/tsa` and `/ocsp`, for example with an httpd alias.
- **minor** — `conformance/compose.yaml:5-7,11-19`: the owner's amendment (task 1) asks that the `pki` service, "or a one-shot `pki-init` step it depends on", run `generate.sh` before the responders start. Here `pki-init` is behind a profile with no `depends_on`, so it is a manual step before `up`; the stated reason is that podman-compose does not wait. If someone forgets it locally, stale anchors and CRLs are served, or under Docker the `./pki/out/anchors.p12` bind mount is created as a directory. CI runs the steps in the right order. The deviation is documented, but the dependency the amendment names is not expressed.
- **minor** — `crates/nacre-conformance/src/report.rs` (`parse_response`) is a parser with no cargo-fuzz target, against the convention "Each parser has a cargo-fuzz target" (ADR-0008, `AGENTS.local.md` Conventions). The plan and research justify the exception: it reads a trusted local judge, it is `publish = false`, and panics are denied by lint. It is recorded here so the exception is visible; I am not asking for a change.
- **minor** — `crates/nacre-conformance/tests/dss_reference.rs:34`: `reports_dir().join("pades-baseline-b.xml").is_file()` also passes on a file left by an earlier run, so it does not prove that this call wrote the report. Removing the file before the call, or comparing its mtime, would make the check bite.
- **minor** — `conformance/check.sh` (`wait_for`, and the `curl` calls): `curl` has no `--max-time`. A listener that accepts but never answers would hang past the 300 s deadline, because the deadline is only checked between attempts.

## Not verified
- **Patelle's DSS container:** I could not check that `conformance/dss/Containerfile` and `dss-custom.properties` are faithful copies of Patelle's `story/s01-sign-decision:conformance/dss/`, including the same DSS 6.5.1 SHA-256. po-bounds refused `git -C /home/lecrabe/dev/atoll/patelle show …` (outside the story worktree), and I did not try another route. A person should diff the two files by hand.
- **`.github/workflows/conformance.yml`:** only read; not linted (no `actionlint`) and not run. Docker `network_mode: host`, `--profile init run`, buildx cache, softhsm install and artefact upload are first proven by the pull request's CI run. Someone should watch that first run and confirm `conformance-reports` is uploaded.
- **Recorded fixtures:** `generate.sh --record` was not rerun. The fixtures come from an earlier PKI; I checked their verdict content, not that a rerun reproduces them.
- **Anchor-store failure:** I did not reproduce the implementer's observation that the conformance tests fail when DSS keeps a stale anchor store. Doing so would need a bench restart, which is outside a read-only review.
- **DSS `SignatureFormat` names:** the names for formats beyond the two recorded ones (XAdES-C/X/XL/A/ERS, PKCS7-*, PAdES-LTV) were not confirmed against DSS 6.5.1's `SignatureLevel` enum; only test (d)'s representative names are covered.
- **`cargo fmt --check`:** not a `po-run` row. It is taken from the implementer's statement and the CI.
- **No QA stage:** the QA report has no `## Not seen` to import.

## Verdict
No critical and no major finding. The bench comes up on loopback only, the PKI is regenerated with no key in git, and DSS gives the exact `PAdES-BASELINE-B` and `REVOKED_NO_POE` verdicts. Both mutated rules failed at least one test.

Max severity: minor
Ship allowed: yes

# Review — s02-conformance-harness

Story: s02-conformance-harness — The conformance bench: pinned DSS, test PKI, TSA, OCSP and CRL server
Worktree: /home/lecrabe/dev/atoll/nacre/.worktrees/s02-conformance-harness
Diff judged: `git diff main...story/s02-conformance-harness` (8184c41, e1a747c, fix run 35c7d91)
Reviewed tree: ed224e4f184b96ec558158fbc554519dccdd3ad5
Fix loop: 1
Review status: complete
Lenses run: Security (`conformance/pki/cgi-bin/tsa` and `conformance/pki/cgi-bin/ocsp` are HTTP handlers; `Dss::new` builds an HTTP call from a URL read from `NACRE_DSS_URL`); Dependencies (`crates/nacre-conformance/Cargo.toml` adds `thiserror`, `serde_json`, `base64ct` and an optional `ureq`)

## Scope
I checked all 34 changed paths against the s02 `Owns` line (`conformance/`, `crates/nacre-conformance/`, `.github/workflows/conformance.yml`). Every path is inside it.
- The `docs/plans`, `docs/research`, `docs/verif` and `docs/reviews` files for s02 are the story's own evidence.
- `docs/decisions/0011-bench-pki-tsa-ocsp-on-openssl.md` is a new file (status A), and the plan names it.
- The frozen files have an empty diff: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `.github/workflows/ci.yml`, `crates/nacre-core/` and `docs/stories.md`.
- The only other running lane is s38-error-kind, which is not merged. It owns `crates/nacre-core/`, two `error.rs` files and `crates/nacre-pdf/Cargo.toml`, and none of these overlaps this diff.

## What was relied on and what was run
- **Verification record:** `po-gate verif-current s02-conformance-harness` exits 0, and `Verification mode` is `record`. So the unit suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) are taken from the record and were not rerun. I read its "Not proven here" section.
- **QA:** none. `Surface: —` with `QA stage: surfaces`, so the story does not go to QA.
- **Floor guard:** `po-gate floor-guard s02-conformance-harness main` exits 0. It only printed an awk multibyte warning caused by the binary `unsigned.pdf`.
- **The fix run (35c7d91):**
  - `conformance.yml` now installs `qpdf` next to `softhsm2`, before `cargo test --workspace --all-features -- --ignored`. The test that needs it is on `main`, at `crates/nacre-pdf/tests/revision.rs:381-393` (`qpdf_check_is_clean`, `#[ignore = "conformance"]`, calls `qpdf --check`). A `pull_request` run checks out the merge ref, so that test does reach this workflow. ADR-0007 names `qpdf --check` as the PDF judge, and the lead's log on main (#44) asked for this install.
  - `check.sh` now bounds every `curl` with `--max-time`.
  - `dss_reference.rs` removes the XML report before the call. The previous minor findings on these two points are closed.
- **Mutation tests** (each rule broken on purpose, only its own test file run, then restored and checked with `git diff --exit-code`):
  1. In `report.rs` `level`, I mapped `BASELINE-B` to `BaselineT` and ran `--test report`. 1 of 5 tests failed (`recorded_baseline_b_reads_total_passed_at_pades_baseline_b`). Restored, clean.
  2. In `client.rs` `validate`, I replaced the report-name guard with `if false` and ran `--test client`. 1 of 2 tests failed (`a_report_name_that_leaves_the_report_folder_is_refused_before_any_request`). Restored, clean.
  - The worktree is clean at the end, and the tree still equals the recorded hash.
- **References opened:** these exist in `crates/nacre-core/src/report.rs` with the signatures used:
  - `SignatureForm::Pkcs7` and every `SignatureProfile::Extended*` variant matched in `level`;
  - `SubIndication::ALL` and `as_str`;
  - `ValidationReport::{passed, failed, indeterminate, indication, sub_indication}`.
- **Interdicts:**
  - The diff adds no private key, no `.p12` and no `.key` file.
  - `conformance/pki/out/` and `conformance/reference/out/` are ignored by their own `.gitignore` files.
  - `ureq` sits only behind the `http` feature.
  - `src/` has no `unwrap`, `expect`, `panic!` or indexing.
- **Test count:** 9 tests (5 + 2 + 2), within `Test budget` 25.
- **E2E and build:** this project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`).

## Findings
- **minor** — `conformance/pki/openssl.cnf:72,81`, `conformance/check.sh`, `conformance/README.md:20`, `conformance/pki/README.md:31,39,41`: the responders are served at `POST /cgi-bin/tsa` and `POST /cgi-bin/ocsp`, and the leaf certificates point their OCSP address at `/cgi-bin/ocsp`. Plan tasks 1-2 and the accepted ADR-0011 option 1 (`docs/decisions/0011-bench-pki-tsa-ocsp-on-openssl.md:18`) still say `/tsa` and `/ocsp`. The driver says the lead settled this as an implementation detail, because busybox httpd only runs CGI under `/cgi-bin`. I accept that reason, and I am keeping this minor only so the gap is written down. However, I found no line for it in `docs/decisions-log.md`, neither on this branch, nor on `main`, nor in the root checkout's working copy (`/home/lecrabe/dev/atoll/nacre/docs/decisions-log.md`). That line should be added so s07 and s09/s10 code against the URL that is actually served.
- **minor** — `conformance/compose.yaml:5-7,11-19`: the amendment asks for the `pki` service, "or a one-shot `pki-init` step it depends on", to run `generate.sh` first. Here `pki-init` sits behind a profile with no `depends_on`, so it is a manual step before `up`: podman-compose does not wait for `service_completed_successfully`. The README documents this and CI runs the steps in order. If someone forgets the step locally, stale anchors are served, or under Docker `out/anchors.p12` is created as a directory. Carried over from fix loop 0 and still open.
- **minor** — `crates/nacre-conformance/src/report.rs` (`parse_response`) is a parser with no cargo-fuzz target, against ADR-0008 and the `AGENTS.local.md` conventions. The plan and research justify the exception (the input is a trusted local judge, the crate has `publish = false`, and panics are denied by lint). It is recorded so the exception stays visible; no change is requested. Carried over.

## Not verified
- **The `qpdf` step in CI:** this branch holds no test that calls qpdf, so the step is first proven by the next PR #58 run, on the merge with `main`. A person should check that the `conformance` job is green, including `qpdf_check_is_clean`, and that the `conformance-reports` artefact is uploaded.
- **Merge with current `main`:** `main` has moved (563df8e) past this branch's base (f102cab). po-bounds refused `git merge-tree` (reader mode), and I did not try another route. The pull request's mergeability, or `/po-ship`, has to show that the merge is clean.
- **Order against s38-error-kind:** s38 changes `crates/nacre-core/src/lib.rs` and `error.rs`, which this crate depends on (it imports only the report types). I did not build the two together. Whichever ships second should have its CI run on the combined tree.
- **Fidelity to Patelle's DSS container:** I did not check that `conformance/dss/Containerfile` and `dss-custom.properties` are faithful to Patelle's `story/s01-sign-decision:conformance/dss/`. That repository is outside the worktree. A person should diff the two by hand.
- **The bench itself:** I did not rerun `check.sh` or the two `dss_reference` tests. The record says they passed by hand after the fix, and the CI run on the PR passed the bench and both DSS tests (driver notes). I did not restart the bench to reproduce the stale-anchors failure.
- **`.github/workflows/conformance.yml`:** not linted (no `actionlint`).
- **Recorded fixtures:** `generate.sh --record` was not rerun. The fixtures come from an earlier PKI; I checked their verdict content, not that a rerun reproduces it.
- **DSS `SignatureFormat` names:** names beyond the two recorded ones and test (d)'s representative names were not confirmed against DSS 6.5.1's enum.
- **`cargo fmt --check`:** not a `po-run` row. It rests on the implementer's statement and on CI.
- **QA `## Not seen`:** nothing to import, since the story has no QA stage.

## Verdict
There is no critical and no major finding. The fix run does what CI asked for: it installs `qpdf` for the conformance job, and it closes two earlier minor findings (curl timeouts, and a report-file check that now bites). Both mutated rules failed a test. Three minor findings stay open for a later cycle.

Max severity: minor
Ship allowed: yes

# Review — s02-conformance-harness

Story: s02-conformance-harness — The conformance bench: pinned DSS, test PKI, TSA, OCSP and CRL server
Worktree: /home/lecrabe/dev/atoll/nacre/.worktrees/s02-conformance-harness
Diff judged: `git diff main...story/s02-conformance-harness` (8184c41, e1a747c, 35c7d91, fd0fec2, fix run 1474902)
Reviewed tree: 3eb715fad4ea16a658ffb7e63249644b50c24460
Fix loop: 2
Review status: complete
Lenses run: Security (`conformance/pki/cgi-bin/tsa` and `conformance/pki/cgi-bin/ocsp` are HTTP handlers; `Dss::new` builds an HTTP call from a URL read from `NACRE_DSS_URL`); Dependencies (`crates/nacre-conformance/Cargo.toml` adds `thiserror`, `serde_json`, `base64ct` and an optional `ureq`)

## Scope
- I checked all 34 changed paths against the s02 `Owns` line (`conformance/`, `crates/nacre-conformance/`, `.github/workflows/conformance.yml`). Every path is inside it.
- The `docs/plans`, `docs/research`, `docs/verif` and `docs/reviews` files for s02 are the story's own evidence.
- `docs/decisions/0011-bench-pki-tsa-ocsp-on-openssl.md` is a new file (status A) and the plan names it.
- No other lane is running. `git worktree list` shows only `main` and this worktree, and s38-error-kind has landed on `main` (11fc6fa), so nothing can overlap.
- Fix run 1474902 changes only `.github/workflows/conformance.yml` and this story's verif record.

## What was relied on and what was run
- **Verification record:** `po-gate verif-current s02-conformance-harness` exits 0, and `Verification mode` is `record`. So I did not rerun the unit suite (`cargo test --workspace`) or the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`); I took them from the record. I read its "Not proven here" section.
- **QA:** the story does not go to QA, because its `Surface` is `—` and `QA stage` is `surfaces`.
- **Floor guard:** `po-gate floor-guard s02-conformance-harness main` exits 0. It printed only the awk multibyte warning caused by the binary `unsigned.pdf`.
- **The fix run (1474902):** the examples step now globs `crates/nacre-sig/examples/*.rs` and runs `cargo run -p nacre-sig --example <name> --all-features` for each match. That fixes what failed in CI run 39752193913: `main` holds `crates/nacre-cms/examples/forge_attacks.rs`, and that file is no longer run.
  - I copied the step's script into a temp tree (`/tmp/tmp.3BIBX5TIA1`) with `cargo` stubbed out, holding `nacre-sig/examples/sign_blta.rs`, `nacre-sig/examples/multi/main.rs` and `nacre-cms/examples/forge_attacks.rs`.
  - It ran only `sign_blta` and exited 0. That is the file name s20's criterion names. It also confirms the gap in the first finding below.
- **Mutation test:** in `report.rs` `signature_verdict`, I mapped `(Indeterminate, Some(sub))` to `ValidationReport::failed` and ran only `--test report`. 1 of 5 tests failed (`recorded_revoked_keeps_its_exact_indication_and_sub_indication`). I restored the file and `git diff --exit-code` came back clean. The earlier loops' mutations are reported in the earlier reviews: host allow-list, sub-indication with `TOTAL_PASSED`, the mapping in `level`, and the report-name guard. None of those code paths changed since.
- **Interdicts (unchanged since fix loop 1, rechecked on the new diff):** no private key, `.p12` or `.key` file is added, and `src/` is untouched by the fix.
- **Test count:** 9 tests, within `Test budget` 25.
- **E2E and build:** this project has no `E2E` command (`—`). The build is left to ship (`Build stage: ship-if-route`); the diff changes no routing and no workspace manifest.

## Findings
- **minor** — `.github/workflows/conformance.yml:42-57`: plan task 8 says the step runs "every example of the workspace, found by `cargo metadata --no-deps --format-version 1 | jq` over targets of kind `example`". The fix narrows that to `crates/nacre-sig/examples/*.rs` without amending the plan. The reason is real and stated in the commit and the verif record: `forge_attacks` needs an argument, and issue #6 only asks for s20's example. But the plan no longer describes the step. Either amend task 8, or record the change in the lead's decisions log.
- **minor** — `.github/workflows/conformance.yml:49`: the file glob finds fewer examples than cargo does. Cargo also discovers `examples/<name>/main.rs` and `[[example]]` entries with a custom `path`. My probe showed that `nacre-sig/examples/multi/main.rs` is skipped silently and the step stays green. s20's planned `examples/sign_blta.rs` is a single file, so nothing breaks today. Keeping `cargo metadata` and filtering on `.name == "nacre-sig"` would remove the gap.
- **minor** — `conformance/pki/openssl.cnf:72,81`, `conformance/check.sh`, `conformance/README.md:20`, `conformance/pki/README.md:31,39,41`: the responders are served at `/cgi-bin/tsa` and `/cgi-bin/ocsp`, but plan tasks 1-2 and ADR-0011 option 1 say `/tsa` and `/ocsp`. The driver says the lead settled this as an implementation detail and will log it after this wave's ships. Until then there is no `cgi-bin` line in `docs/decisions-log.md`, on this branch or on `main`. Carried over.
- **minor** — `conformance/compose.yaml:5-7,11-19`: `pki-init` sits behind a profile with no `depends_on`, so it is a manual step before `up`, where the owner's amendment asks for a step the `pki` service depends on. The README documents this and CI runs the steps in order. Carried over.
- **minor** — `crates/nacre-conformance/src/report.rs` (`parse_response`) is a parser with no cargo-fuzz target, against ADR-0008 and the `AGENTS.local.md` conventions. The plan and research justify the exception: the input is a trusted local judge and the crate has `publish = false`. It is listed only so the exception stays visible. Carried over.

## Not verified
- **The new examples step in CI:** I proved it only through the stubbed temp-tree probe. PR #58's head is still ebc4acb, so 1474902 has not been pushed or run. A person should watch the next `conformance` run on the merge with `main`: it should be green, print "no examples", and upload `conformance-reports`.
- **The bench itself:** I did not rerun `check.sh` or the two `dss_reference` tests, because the fix touches neither. The driver notes say CI run 39752193913 passed the bench, both DSS tests and `qpdf_check_is_clean`. I did not restart the bench to reproduce the stale-anchors failure.
- **Merge with current `main`:** `main` (11fc6fa, with s38) is ahead of this branch's base (f102cab). GitHub reports PR #58 as `MERGEABLE`, but I did not build the combined tree; that is the next CI run's job.
- **Fidelity to Patelle's DSS container:** that repository is outside the worktree, so I did not check it. A person should diff `conformance/dss/` against Patelle's `story/s01-sign-decision:conformance/dss/` by hand.
- **`conformance.yml` lint:** not linted, because `actionlint` is not installed here.
- **Recorded fixtures:** `generate.sh --record` was not rerun. The fixtures come from an earlier PKI.
- **DSS `SignatureFormat` names:** names beyond the two recorded ones and test (d)'s set were not confirmed against DSS 6.5.1's enum.
- **`cargo fmt --check`:** it has no `po-run` row; it rests on the implementer's statement and on CI.
- **QA `## Not seen`:** there is nothing to import, since the story has no QA stage.

## Verdict
There is no critical and no major finding. The second fix run limits the examples step to the facade crate, which stops the `forge_attacks` panic while still covering s20's single-file example. It leaves the plan's text behind, and its glob is narrower than cargo's own example discovery: both are minor findings. The mutated rule failed a test. Five minor findings stay open for a later cycle.

Max severity: minor
Ship allowed: yes
