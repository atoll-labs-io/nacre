# Review — s43-dss-parity

[Story](../stories.md) · [Plan](../plans/s43-dss-parity.md) · [Verification](../verif/s43-dss-parity.md)

Diff reviewed: `git diff main...story/s43-dss-parity`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 2b1d3e50ec7d8b8cd132a4fc2d248df048ea4555

## When blocked
- Failure cause: n/a
- Missing: n/a
- Required adaptation: n/a
- Next action: n/a

## Ownership
I listed the diff with `git diff --name-only main...story/s43-dss-parity` and checked each path against `Owns: crates/nacre-validate/, crates/nacre-pdf/, docs/security/attacks/`.
- [x] Every code path is inside `Owns`: 19 files under `crates/nacre-validate/` and `crates/nacre-pdf/`, plus the catalog under `docs/security/attacks/`.
- [x] Pipeline evidence is in scope by construction: research, plan, verif, `docs/qa/s43-dss-parity/`.
- [x] ADR-0027 and ADR-0028 are added (status `A`) and the plan names both, so they are in scope.
- [ ] Outside `Owns`: `docs/decisions/0026-runtime-validation-policy.md` is an existing ADR the diff modifies. It is required by Law 6 (the `superseded-by` link), so it is graded minor below.
- [x] No path is inside another running story's `Owns`: `git worktree list` shows only `main` and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s43-dss-parity` exited 0, so I reused the record (`Verification mode: record`). The last Unit suite (`cargo test --workspace`) and Type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) rows both exited 0. I read its "Not proven here" section: the conformance tests ran once on the bench (22 passed) outside `po-run`, fuzz targets were not rebuilt, and the research's open questions are carried to Not verified.
- [x] `po-gate qa-current s43-dss-parity` exited 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). The QA report has no findings, so none carry over. Its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1 to 10 are each present in the diff. Nothing is outside the plan.
- [x] Run interdicts, checked one by one:
  - The diff is empty outside the allowed paths. `nacre-pades`, `nacre-conformance`, `nacre-core`, `conformance/`, `.github/`, root `Cargo.toml` and `docs/stories.md` are untouched.
  - ADR-0026's body is unchanged: only `superseded-by: [0027]` moved.
  - No level is computed, no document timestamp is judged, and the TSA freshness window is untouched.
  - `strict()` only gets stricter, on the three listed shapes.
  - The existing `tests/attacks.rs` assertions are unchanged; three tests were added.
  - No new dependency, no `[workspace.dependencies]`, no `Cargo.lock`, no `include_str!` outside the crate. The catalog is read at run time from `CARGO_MANIFEST_DIR`.
  - The conformance bench is a local compose, as the record states.

## References
- [x] Every reference I opened exists with the expected signature:
  - `SignedData.certificates: Vec<Vec<u8>>` (`crates/nacre-cms/src/model.rs:77`), `Signed::timestamps`
  - `repeats_extension`, `judge_path` and its two callers (`validate.rs:357`, `:448`)
  - `SignatureSpec`, `Update::sign`, `signed_parts`/`embed`, `sign_detached`, `Profile::PADES`
  - `Stub`, which moved unchanged to `tests/support/mod.rs`
  - the conformance helpers (`confront_signatures`, `nacre`, `forged_signer`, `intermediate_crl`)
- [x] Values that only look right:
  - The SHA-256 of the three new corpus files matches the README rows.
  - The bench PKI's `default_startdate = 20260101000000Z` (`conformance/pki/openssl.cnf:24`) explains why a fixed `/M` of 2026-10-22 passes on the bench.
  - The `/M` boundary uses `>` against `notAfter`, so a `/M` exactly at `notAfter` passes, as QA observed.
  - The late-data window `(not_before..=not_after)` is inclusive at both ends, as QA observed.

## Rules
- [x] `AGENTS.md` conventions respected: no panic paths in non-test code, rustdoc in English, the switch and ADR numbering consistent, no new crate.
- [x] No accepted ADR is contradicted:
  - ADR-0026 asks for a new rule-only-Nacre switch to come through an ADR that supersedes its table, and ADR-0027 does that.
  - The late-data rule and the `/M` rules are applied under both presets as DSS rules, as ADR-0026 says.
  - ADR-0028's `value_unreadable: bool` and `#[non_exhaustive]` are implemented as decided.

## Tests
- [x] Floor: `po-gate floor-guard s43-dss-parity main` exited 0, so nothing was lowered. It printed only an awk locale warning.
- [x] Assertions pin down AC1 to AC8:
  - The isolation tests read the corpus directory and the catalog at run time and compare sets in both directions.
  - Fixtures use fixed dates and their own keys.
  - `Stub` does not reproduce the condition under test: it only answers CRLs.
  - None of the six empty test shapes appears.
- [x] 17 new tests, within `Test budget: 25`, as the plan's strategy counts them.
- [x] Bite 1: in `revocation.rs`, I put the `judge_path` filter back to `verdict.date >= not_before`, removing the late-data rule. Running `--test revocation --test policy`, 1 test failed (`data_issued_after_not_after_does_not_count`). Undone; `git diff --exit-code` is clean.
- [x] Bite 2: in `validate.rs`, I made `after_revocation` return `Ok` on `None => Ok(())`, removing `ClaimedTimeMissing`. Running `--test revocation --test policy --test validate`, 1 test failed (`missing_claimed_time_is_a_constraints_failure`). Undone; clean.
- [x] Bite 3: in `validate.rs`, I removed the timestamp-token certificates from the malformed-extension scan. Running `--test revocation --test policy`, 1 test failed (`malformed_timestamp_certificate`). Undone; clean, and `git status --porcelain` is empty.
- [x] No test was made useless. `expired_not_revoked_is_out_of_bounds_not_revoked` moved its CRL before `notAfter`, as the research trap required, and its assertions are unchanged.

## Neighbours
- [x] I read the other callers of `signature_fields` and `SignatureField`:
  - `nacre-pades` `archive.rs:94` skips `value: None`, which suits an unreadable field.
  - `sign.rs:145` reads names only.
  - `nacre-pdf` `revision.rs:158` reads names only.
  - The `corpus.rs` and `revision.rs` tests and the `parse` fuzz target do not construct a `SignatureField`.
- [x] `judge_path` is shared by the signer path and the TSA path (`validate.rs:448`). There the new rule can only take a proof of time away, never grant one.

## Lenses
Lenses run: none. No changed path names auth, routes, handlers, upload or webhook. No manifest or lockfile changed. There is no server-side code and no HTTP, LLM or file-upload handling in the diff.
- [x] No lens findings.

## Findings
- minor — docs/decisions/0026-runtime-validation-policy.md:8 — This existing accepted ADR is outside the story's `Owns` (`crates/nacre-validate/, crates/nacre-pdf/, docs/security/attacks/`). Only the frontmatter link `superseded-by: [0027]` changed, which Law 6 requires when a new ADR supersedes one, and the plan declares it.
  The gap is in the story's `Owns`, not a breach by the implementer. Leave the code as it is.
- minor — crates/nacre-validate/tests/conformance.rs:813 — `claimed_time_after_not_after` is a time bomb. It pairs a fixed `/M` of `D:20270601000000Z` with a signer whose `notAfter` is `now + 30 days`.
  From 2027-05-02 on, that `/M` is no longer after `notAfter`. Both DSS and Nacre will then give `TOTAL_PASSED`, and the conformance job fails for no code reason.
  Fix: derive the `/M` from `now`, for example `notAfter + 1 day` formatted as a PDF date.

## Not verified
- **AC8 against DSS:** I did not start the bench, so I did not see DSS's side. I relied on the record's statement that the six conformance tests passed once on the bench (22 passed), which is not a `po-run` row. A person should run `cargo test -p nacre-validate --all-features --test conformance -- --ignored` per `conformance/README.md`, or read CI's `conformance.yml` run.
- **QA Not seen, AC1 to AC5 "comme DSS":** QA held Nacre's verdicts to the ones the story names, not to a running DSS, because the bench was not started. Covered by the same bench run.
- **QA Not seen, AC4 "sans niveau ETSI":** this is not observable, because no level is computed yet (s18). The s18 campaign must check `PDF-NOT-ETSI` parity.
- **QA Not seen, AC6 catalog prose:** QA read only the "Ouverte sous" cell. I read the touched rows (`pades.md:10, 32, 33, 42, 86`) but not every prose line of the three catalog pages.
- **The plan's pivot and the research's open questions, all unproven:**
  - The late-data rule for a CA, a TSA or an OCSP response, which DSS was seen applying to the signer only.
  - `expiredCertsOnCRL` and `archiveCutoff`.
  - A missing or non-name `/SubFilter` under `dss()`.
  - Which defect DSS reports first when `/M` is missing and revocation fails too.

  Under `dss()` Nacre may be stricter than DSS on such files. The s18 campaign must forge a bench case for each.
- **`/M` versus a CMS `signing-time` attribute:** I did not check whether DSS uses the CMS `signing-time` attribute when `/M` is absent under `/adbe.pkcs7.detached`. The spike's n12 is reported as `SIG_CONSTRAINTS_FAILURE`, but the attributes of its CMS are not recorded. A bench case with a `signing-time` attribute and no `/M` would settle it.
- **Fuzz targets** were not rebuilt or run here (record: CI's `fuzz` job covers them). The `nacre-pdf` `parse` target only calls `signature_fields`.
- **Ship-stage checks:** the end-to-end suite does not exist (`E2E: —`). The production build is deferred to ship (`Build stage: ship-if-route`, no routing or manifest change).

Max severity: minor
Ship allowed: yes
