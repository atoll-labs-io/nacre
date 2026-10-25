# Review — s42-tsa-freshness

[Story](../stories.md) · [Plan](../plans/s42-tsa-freshness.md) · [Verification](../verif/s42-tsa-freshness.md)

Diff reviewed: `git diff main...story/s42-tsa-freshness`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 2d404ee82a61e92b7ce7392df2469d74cd583532

## When blocked
Not blocked.

## Ownership
Diff listed with `git diff --name-only main...story/s42-tsa-freshness`. Each path was checked against `Owns: crates/nacre-validate/, docs/security/attacks/revocation.md`.
- [x] Every path is inside `Owns`. Five files are under `crates/nacre-validate/` and one is `docs/security/attacks/revocation.md`. The rest is the story's own pipeline evidence: research, plan, verif and `docs/qa/s42-tsa-freshness/`.
- [x] Nothing is outside `Owns`.
- [x] Nothing is inside another running story's `Owns`. The only other worktree is `s19-foreign-corpus`, which owns `conformance/corpus/foreign/`. That does not overlap. Its branch is also an ancestor of `main`.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s42-tsa-freshness` exited 0, so I reused the record. `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on this code. I read the record's "Not proven here": plan task 6 (the bench conformance tests and the campaign) did not run because the bench was not freed. That is carried to Not verified.
- [x] `po-gate qa-current s42-tsa-freshness` exited 0 (`QA status: complete`, current, committed in 907f158). The QA report has no findings, so none are carried over. Its `## Not seen` is carried to Not verified.

## Plan
- [x] Tasks 1–5 are all present, and nothing is outside the plan:
  - Task 1: `fresh_from` was factored and is used at both call sites.
  - Task 2: (a) is rewritten and (b) is added.
  - Task 3: the crate docs are updated.
  - Task 4: the catalogue prose is fixed, row :94 is fixed and a new row is added.
  - Task 5: done, per the po-run rows.
  - Task 6 did not run, and the record says so, as the plan's "Done when" allows.
- [x] Each run interdict was checked:
  - `revocation.rs` changed only in docs (`FRESHNESS_TOLERANCE` comment). `judge_path` and the `fresh` closure are untouched.
  - `policy.rs` changed only in docs: no new field, and `strict()`/`dss()` bodies are untouched. `tests/support/mod.rs` is untouched.
  - The signer site behaves the same: `best_signature_time.is_none().then(|| self.fresh_from()).flatten()` is equivalent to the old `(is_none && switch).then(..)`.
  - Under `dss()`, `fresh_from()` returns `None`, so `issued_from = None` as before.
  - Nothing was touched under `conformance/corpus/foreign/`, `docs/decisions/`, `docs/stories.md` or the root `Cargo.toml`, and no dependency was added.

## References
- [x] Opened and confirmed:
  - `judge_path(path, pool, source, time, issued_from, issuers_at, policy)` at `crates/nacre-validate/src/revocation.rs:290-298`. The `fresh` rule is at :313-316.
  - `FRESHNESS_TOLERANCE` is imported at `validate.rs:18`.
  - `proven_time` is reached from both `judge` (`validate.rs:376`) and `document_time` (`validate.rs:516`).
  - Test helpers: `Pki::tsa`/`stamped`/`judge_under` (`tests/revocation.rs:101-163`) and `strict_without` (`tests/revocation.rs:537`).
- [x] The 24 h value and its `>=` boundary are the existing signer window. QA confirmed the boundary on both CRL and OCSP: exactly 24 h counts, 24 h + 1 s does not.

## Rules
- [x] The `AGENTS.md` conventions are respected: no clock read, no unwrap/panic, no logging, English rustdoc and a French catalogue.
- [x] No accepted ADR is contradicted. ADR-0031's row reads "with no proof of existence", and TSA revocation data has none. The lead logged its decision not to write a new ADR on 2026-10-25 (`docs/decisions-log.md:117`).

## Tests
- [x] Floor: `po-gate floor-guard s42-tsa-freshness main` exited 0, so nothing was lowered.
- [x] The assertions pin down AC1–AC3. They check the sub-indication, the `RevocationDefect`, and that `best_signature_time` is `None` under strict and `Some(stamp)` under the other policies. Both timestamp kinds are covered, and none of the six empty test shapes appears. One known limit: the TSA and the signer share the intermediate in the fixture, so the strict refusal reads through the signer. The `best_signature_time == None` assertion pins down the TSA path directly, and QA's separate-CA PKI covered the rest.
- [x] Within `Test budget`: 1 test added and 1 rewritten, out of 25.
- [x] Bite 1: at `validate.rs:559`, I replaced `self.fresh_from()` with `None` (the TSA window removed). Running `cargo test -p nacre-validate --test revocation` gave 2 failing tests: `old_crl_does_not_pass_a_signature_without_poe` and `stale_crl_does_not_clear_a_timestamp_authority`. I undid it, and `git diff --exit-code` was clean.
- [x] Bite 2: in `fresh_from`, I forced the switch to `true` (the window applied regardless of policy). The same test file gave 2 failing tests: `old_crl_passes_without_the_freshness_switch` and `stale_crl_does_not_clear_a_timestamp_authority`. I undid it, and `git diff --exit-code` was clean.
- [x] The test that asserted the hole (second half of `old_crl_does_not_pass_a_signature_without_poe`) was flipped, not kept.

## Neighbours
- [x] `judge_path` has only two callers, both in `validate.rs`, and both were read. `best_signature_time` feeds the report. The level does not depend on it (ADR-0025, `report.rs:36-38`). No other crate builds a `Purpose::Timestamping` path.

## Lenses
Lenses run: none. No path or content trigger matched: no auth/route/upload/webhook paths, no migration, no manifest or lockfile change, no server-side code.
- [x] No lens findings.

## Findings
- minor — crates/nacre-validate/src/lib.rs:33 — The rewritten module doc line is 128 characters long, while the paragraph around it is wrapped at 100 or fewer.
- minor — crates/nacre-validate/src/validate.rs:91 — The rewritten `validate_with_revocation` doc line is 101 characters long. It is the same unwrapped reflow as the lib.rs line.

## Not verified
- **DSS parity under `dss()` (AC2) against a running DSS.** Plan task 6 did not run: no `cargo test -p nacre-validate --all-features --test conformance -- --ignored` and no `sh conformance/campaign/run.sh`. QA's `## Not seen` says the same. What I saw: `dss()` takes an unchanged path (`issued_from = None`); QA found identical verdicts between this tree and `main` on the forged cases and on the 51 attack-corpus PDFs; and the `dss()` half of the new test passes. A person should start the bench fresh and run both commands before or at ship. They should check that `campaign-dss.md` has 0 differences and that every new `campaign-strict.md` difference is explained by `require_fresh_revocation` alone. The campaign allows at most three switches per difference (`tests/campaign.rs:205-235`), so a case already at three would now go unexplained.
- **`#[ignore = "conformance"]` strict tests on B-T files** (for example `revoked_after_the_bench_stamp_passes`). These may now depend on the bench's CRLs being under 24 h old. I did not run them, for the same bench reason.
- **A live `RevocationSource` over HTTP (`http` feature).** QA's `## Not seen` says it needs a real network or remote service. QA used only an in-memory source. Checking it needs a run against a reachable responder or the bench.
- **The full workspace suite and clippy.** I did not rerun them: I relied on the po-run record. Only the `tests/revocation.rs` file ran here, during the bite checks.

Max severity: minor
Ship allowed: yes

---

# Ship check — s42-tsa-freshness

Review status: blocked
Fix loop: 0
Reviewed tree: 2d404ee82a61e92b7ce7392df2469d74cd583532

## When blocked
- Failure cause: the `conformance` CI job of PR #149 failed. `issuer_out_of_validity_policy` (`crates/nacre-validate/tests/conformance.rs:1248`, s45) asserts under `strict()` `INDETERMINATE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE` with a best-signature-time, and now gets `INDETERMINATE` / `OUT_OF_BOUNDS_NO_POE` (`Chain(Expired { depth: 1 })`). Its fixture feeds the root CRL issued 48 h before the control date; the bench TSA's path (TSA → intermediate → root) now needs that root CRL fresh under `strict()`, so the stamp proves no time. The campaign passed.
- Missing: a green `conformance` job; the bench checks of plan task 6 that did not run.
- Required adaptation: keep what the test proves for s45 under `strict()` (the issuer-validity rule with a proof of existence) on a fixture whose TSA path has fresh data, or state the new strict verdict if s42 changes it by design; then run the bench conformance tests and the campaign.
- Next action: fix run, then `/po-review` at fix loop 1.

## Findings
- major — crates/nacre-validate/tests/conformance.rs:1248 — `issuer_out_of_validity_policy` fails under `strict()` since the TSA freshness window: the fixture's 48 h-old root CRL no longer clears the bench TSA's path.

Max severity: major
Ship allowed: no

---

# Review — s42-tsa-freshness

[Story](../stories.md) · [Plan](../plans/s42-tsa-freshness.md) · [Verification](../verif/s42-tsa-freshness.md)

Diff reviewed: `git diff main...story/s42-tsa-freshness`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: 6060e9892a84260e31f4b53a53a69ae773991ffa

## When blocked
Not blocked.

## Ownership
Diff listed with `git diff --name-only main...story/s42-tsa-freshness`. Each path was checked against `Owns: crates/nacre-validate/, docs/security/attacks/revocation.md` using the overlap rule of the `review-antihallu` skill.
- [x] Every path is inside `Owns`. Six files are under `crates/nacre-validate/`: `src/lib.rs`, `src/policy.rs`, `src/revocation.rs`, `src/validate.rs`, `tests/conformance.rs` and `tests/revocation.rs`. The seventh is `docs/security/attacks/revocation.md`. The other paths are the story's own evidence: research, plan, verif, review and `docs/qa/s42-tsa-freshness/`.
- [x] Nothing is outside `Owns`.
- [x] Nothing is inside another running story's `Owns`. `git worktree list` shows only the main checkout and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s42-tsa-freshness` exited 0, so I reused the record (`Verification mode: record`).
  - It proves `cargo test --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo test -p nacre-validate --all-features --test conformance -- --ignored` on the current code. All three exited 0, and their last rows are dated 2026-10-25T10:02–10:03Z.
  - The record's "Not proven here" says the campaign ran on a fresh bench on the previous code tree, with no new difference, and was not rerun after the fix run. That is carried to Not verified.
- [x] `po-gate qa-current s42-tsa-freshness` exited 0. The report is `QA status: complete`, current and committed in bafab58, and it replays the walk on the fix-run tree.
  - The QA report has no findings, so none are carried over.
  - Its three `## Not seen` items are carried to Not verified.

## Plan
- [x] Tasks 1–6 are present, and the code matches each one:
  - `fresh_from` is shared by both call sites.
  - Test (a) is flipped and test (b) is added.
  - The crate docs are updated, and the catalogue prose, row :94 and the new row are done.
  - The po-run rows are present.
  - Task 6 was ticked by the fix run: the bench conformance run is in the record.
- [x] The fix-run change to `tests/conformance.rs` `issuer_out_of_validity_policy` answers the major finding of the ship check (fix loop 0). It feeds the strict half a file that also carries a root CRL issued 1 h before the control date, so the bench TSA's path (TSA → intermediate → root) is fresh under `strict()`.
  - The comment's claim holds: "the signer, judged at the stamp, still sees the same CA data". The forged CA expired at now − 24 h, so a root CRL issued at now − 1 h falls after its `notAfter`. That kind of data is dropped under every policy (`validate.rs` doc, s43 rule).
  - The s45 assertion (`REVOCATION_OUT_OF_BOUNDS_NO_POE` with a best-signature-time) is kept unchanged. The conformance po-run row exits 0 on this tree.
- [x] Each run interdict was checked:
  - `revocation.rs`: docs only. `judge_path` and its `fresh` closure are untouched.
  - `policy.rs`: docs only. There is no new field, and the `strict()`/`dss()` bodies and `tests/support/mod.rs` are untouched.
  - Signer site: `best_signature_time.is_none().then(|| self.fresh_from()).flatten()` is equivalent to the old expression.
  - `dss()` still gives `issued_from = None`.
  - Nothing changed under `conformance/corpus/foreign/`, `docs/decisions/`, `docs/stories.md` or the root `Cargo.toml`, and no dependency was added.

## References
- [x] Opened and confirmed:
  - The `judge_path` call at `validate.rs:554-563`.
  - `fresh_from` at `validate.rs:519-525`.
  - `FRESHNESS_TOLERANCE` in `revocation.rs:33`.
  - `crl_at`, `bench_key`, `forge::with_dss` and `forge::signed` with `Level::T { tsa }` in `tests/conformance.rs`.
  - `Pki::judge_under`, `stamped`, `document_timestamp` and `strict_without` in `tests/revocation.rs`.
- [x] The 24 h window and its inclusive boundary are the existing signer window. QA confirmed both boundaries on CRL and OCSP: exactly 24 h counts, 24 h + 1 s does not.

## Rules
- [x] The `AGENTS.md` conventions are respected: no clock read in judging code, no unwrap/panic outside tests, no logging, English rustdoc and a French catalogue.
- [x] No accepted ADR is contradicted. Under ADR-0031, the TSA's data has no proof of existence. The lead logged its no-new-ADR decision in `docs/decisions-log.md`.

## Tests
- [x] Floor: `po-gate floor-guard s42-tsa-freshness main` exited 0, so nothing was lowered.
- [x] The assertions pin down AC1–AC3: the sub-indication, the `RevocationDefect`, and `best_signature_time` (`None` under strict, `Some(stamp_time())` under `dss()` and with the switch off). Both timestamp kinds are covered, and none of the six empty test shapes appears.
- [x] Within `Test budget`: 1 test added and 1 rewritten, plus one ignored conformance test adapted, out of 25.
- [x] Bite 1: at `validate.rs:559`, I replaced `self.fresh_from()` with `None`.
  - Ran `cargo test -p nacre-validate --test revocation`: 2 tests failed, `old_crl_does_not_pass_a_signature_without_poe` and `stale_crl_does_not_clear_a_timestamp_authority`.
  - Undid it, and `git diff --exit-code` was clean.
- [x] Bite 2: in `fresh_from`, I replaced `self.policy.require_fresh_revocation` with `true`.
  - Same test file: 2 tests failed, `old_crl_passes_without_the_freshness_switch` and `stale_crl_does_not_clear_a_timestamp_authority`.
  - Undid it, and `git diff --exit-code` was clean.
- [x] The test that asserted the hole was flipped, not kept.

## Neighbours
- [x] `judge_path` has only the two callers in `validate.rs`, and both were read.
  - `proven_time` is reached from `judge` and from `document_time`.
  - `best_signature_time` feeds the report. The level does not depend on it (ADR-0025).
  - The other conformance strict tests on B-T files are covered by the green conformance po-run on this tree.

## Lenses
Lenses run: none. No auth, route, upload or webhook path matched. There is no migration, no manifest or lockfile change, and no server-side code.
- [x] No lens findings.

## Findings
- minor — crates/nacre-validate/src/lib.rs:34 — The fix run did not fix this fix-loop-0 minor: it moved the overlong line instead of rewrapping it. The line is now 121 characters (`//! that keeps an old CRL appended to the `/DSS` from passing a key revoked since, while an old proof of revocation still`), while the paragraph around it is wrapped at 100.
- minor — crates/nacre-validate/src/validate.rs:92 — The same thing happened here: the rewrapped `validate_with_revocation` doc still has a 101-character line (`/// before the best-signature-time still counts, unless its reason is `certificateHold`. A revocation`).

## Not verified
- **The DSS campaign on this exact tree.** `sh conformance/campaign/run.sh` is not a declared check, and the record says it last ran on the previous code tree, with no new difference in `campaign-dss.md` or `campaign-strict.md`. Since then, only doc comments and one `#[ignore = "conformance"]` test changed, none of which the campaign reads. I did not start the bench. A person who wants parity proof on the shipped tree should start the bench fresh, run the campaign, and confirm that both campaign files show 0 unexplained differences.
- **DSS's own verdict under `dss()` (AC2) and the adapted `issuer_out_of_validity_policy`.** I did not run them against a running DSS myself. I relied on the conformance po-run row (exit 0 on this tree). QA's `## Not seen` lists both items, because its driver did not start the bench.
- **A live `RevocationSource` over HTTP (the `http` feature).** QA's `## Not seen`: it needs a real network or remote service, and QA used only an in-memory source. Checking it needs a run against a reachable responder or the bench.
- **Full workspace suite and clippy.** I did not rerun them: I relied on the po-run record. Only `tests/revocation.rs` ran here, during the bite checks.
- **End to end and build.** These are deferred to ship. The project has no E2E command (`E2E: —`), and `Build stage` is `ship-if-route`. No routing or manifest changed.

Max severity: minor
Ship allowed: yes
