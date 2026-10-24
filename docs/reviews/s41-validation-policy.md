# Review — s41-validation-policy

[Story](../stories.md) · [Plan](../plans/s41-validation-policy.md) · [Verification](../verif/s41-validation-policy.md)

Diff reviewed: `git diff main...story/s41-validation-policy`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 079a99ef58bca975f276abe775cac10b1dfbb0a3

## When blocked
- Not blocked.

## Ownership
I listed the diff with `git diff --name-only main...story/s41-validation-policy` and held each path against `Owns: crates/nacre-validate/, crates/nacre-pdf/, docs/security/attacks/`.
- [x] Every path is inside `Owns`:
  - all code is under `crates/nacre-validate/`, and the attack docs are under `docs/security/attacks/`;
  - the plan, research, verif and QA files under `docs/` are the story's own evidence;
  - `docs/decisions/0026-runtime-validation-policy.md` is added (status `A`) and the plan names ADR-0026.
- [x] Nothing is inside another running story's `Owns`. `git worktree list` shows only `main` and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s41-validation-policy` passes (exit 0), so I reused the record:
  - `cargo test --workspace` exited 0, and `cargo clippy --workspace --all-targets --all-features -- -D warnings` exited 0, on code equal to `Tree: 40509263…` outside `docs/`.
  - I read the record's "Not proven here": the conformance tests ran once on the bench without a `po-run` row, and the fuzz target was compiled but not run.
- [x] `po-gate qa-current s41-validation-policy` passes (exit 0). The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). QA finding 1 (verified) is carried to Findings and graded on this review's scale.

## Plan
- [x] Tasks 1 to 10 are all present, and nothing was changed outside the plan. `docs/stories.md` is untouched, as the interdict requires; the AC corrections the plan mentions already sit on `main` (commit 99929eb).
- [x] Run interdicts, checked one by one:
  - **Diff confined to the allowed paths:** yes. `nacre-pdf`, `nacre-core`, `nacre-conformance`, `nacre-revocation`, `.github/`, `conformance/` and `docs/stories.md` are untouched.
  - **Existing assertions unchanged:** no assertion was edited in `tests/attacks.rs`, `chain.rs`, `validate.rs` or `revocation.rs`. `revocation.rs` only gains tests and helpers, and `floor-guard` reports nothing lowered.
  - **Constants kept:** `FRESHNESS_TOLERANCE` is unchanged. The TSA path still gets `issued_from = None` and `Rules::STRICT`.
  - **`build_chain` unchanged:** it passes `Rules::STRICT`. `ChainDefect::report` and `RevocationDefect::report` are untouched.
  - **No new dependency:** no Cargo manifest or lockfile changed, and there is no `cms` or `x509-tsp`.
  - **No public endpoints or bench breakage:** I cannot check this from the diff. The record says the bench was stopped and `patelle-dss` left running.
  - **No level computation:** confirmed.

## References
- [x] I opened the targets of the calls the diff relies on:
  - `nacre_pdf::Error::TrailingData { offset }` at `xref.rs:146-160`; `offset` is the first junk byte, so the prefix is correct;
  - `follow_once` at `validate.rs:590`; `Object::String`;
  - `CrlStatus::Revoked { date, reason }`, `OcspStatus::Revoked { date, reason }`, `CrlReason::CertificateHold`;
  - `der::DateTime::new` / `unix_duration`, and `Certificate::from_der`.
- [x] I checked `certified` in `revisions.rs`. It is read only by `Judge::sneaky` (`:385`), so passing `None` when `refuse_sneaky_signatures` is off disables only the SSA rule, not DocMDP.
- [x] Values:
  - The 24 h window is unchanged.
  - `pdf_date` checks every range: offset hours ≤ 23 and minutes ≤ 59, and the `der::DateTime` checks.
  - The 32-byte input cap is checked.
  - A PDF date with no offset is read as UTC. See Not verified.

## Rules
- [x] `AGENTS.md` conventions are respected:
  - `forbid(unsafe_code)` is unchanged;
  - no unwrap, index or panic outside tests (`split_at_checked`, `get`, `checked_*`);
  - the clock is never read in judging code;
  - the new `Error::MalformedCertificate` maps to `InvalidInput` and carries no path or secret;
  - framing docs are in French, code in English.
- [x] No accepted ADR is contradicted. The code follows ADR-0026 (eight switches, `strict()` as the default).

## Tests
- [x] Floor: `po-gate floor-guard s41-validation-policy main` exited 0; nothing was lowered.
- [x] The assertions pin down AC1 to AC4:
  - each unit test runs under `strict()` and then under `strict()` minus one switch, against committed attack files or a forged `Pki`;
  - none of the six empty test shapes appears;
  - the fixtures are real signed PDFs, and nothing is mocked.
- [x] 12 unit tests (7 in `tests/policy.rs`, 4 in `tests/revocation.rs`, 1 in `date.rs`) plus 9 conformance tests make 21, within the budget of 25.
- [x] Bite:
  - **Exception for old proofs of revocation:** I removed `|| (verdict.revoked.is_some() && !verdict.hold)` (`revocation.rs:222`) and ran `--test revocation`. 1 test failed (`old_revocation_counts_unless_on_hold`). Undone, and `git diff --exit-code` is clean.
  - **`/M` rule:** I replaced `return Err(Defect::ClaimedTimeBeforeCertificate)` (`validate.rs:389`) with `return Ok(())` and ran `--test revocation --test policy`. 1 test failed (`claimed_time_before_not_before_is_a_constraints_failure`). Undone, and `git diff --exit-code` is clean.
  - The worktree status was empty at the end.
- [x] No test is made useless by the story.

## Neighbours
- [x] `build_path`, `judge_path` and `qualify` have only the callers updated in the diff (`validate.rs:190,321,333,412,421`, `chain.rs:202`). No other crate in the workspace calls `nacre_validate`. `SignatureValidation::revoked` was renamed to `after_chain`, and it is crate-private.

## Lenses
Lenses run: security (path `crates/nacre-validate/src/policy.rs` names a policy, and the content is signature and revocation validation). Dependencies did not run: no manifest or lockfile changed. Performance did not run: this is not server-side code.
- [x] The one lens finding is graded below. The other security checks are clean:
  - there is no authorization, HTTP, upload or LLM surface;
  - the new error message reveals nothing;
  - the `dss()` rustdoc opens with the warning and names the attacks it reopens.

## Findings
- major — crates/nacre-validate/src/revocation.rs:220 — Under `strict()`, a stale CRL that lists the signer as revoked on a date after the judged time passes the signature (QA finding 1, verified, `docs/qa/s41-validation-policy/c4-freshness-window-error.txt`).
  The `fresh` closure keeps any stale item whose `revoked.is_some() && !hold`, whatever the revocation date. That item can then be chosen as the latest (`outranks`). Its revocation dated after `time` refuses nothing, so a CRL 25 h old gives `TOTAL_PASSED`. On `main` the window dropped it, which gave `CERTIFICATE_CHAIN_GENERAL_FAILURE`. Such an entry says "not revoked at `time`", which is exactly the data AC4 says the window must drop.
  It is reachable only with a CRL signed by the CA whose `revocationDate` is more than 24 h after its own `thisUpdate`, which a conforming CA does not issue. That is why it is major and not critical. QA rated it minor; I raise it to major because it is a regression of `main`'s strict behaviour in a security rule, and the logic itself is wrong, not only the input.
  Fix: exempt a stale item only when its revocation date is at or before `time`, and add one case to `old_revocation_counts_unless_on_hold`.
  Per Law 7 this is a security finding: it goes to the person, not to the tracker.
- minor — crates/nacre-validate/src/validate.rs:83 — A rustdoc paragraph was reflowed badly. A line holds only "/// before the", and the line above runs past the usual width.
- minor — crates/nacre-validate/src/revocation.rs:198 — The rustdoc line of `judge_path` exceeds the width of the surrounding doc lines. Rewrap it.

## Not verified
- **Conformance against DSS 6.5.1 (AC2, AC5).** I did not start the DSS bench; the nine `#[ignore = "conformance"]` tests rest on the implementer's single run noted in the record, which has no `po-run` row. A person should run `cargo test -p nacre-validate --all-features --test conformance -- --ignored --test-threads=1` on the bench (`conformance/README.md`), or check that CI's `conformance.yml` is green on this tree. This is also an item of the QA report's `## Not seen`: QA did not start DSS, a dependency its driver does not run.
- **AC5, the per-switch conformance tests** (QA `## Not seen`): they need the bench. QA saw the effect of each switch through the library only.
- **AC6, `docs/security/attacks/`** (QA `## Not seen`, left to the review). I read `revocation.md` in full:
  - every switch appears, the stale "s17" mentions are gone, and s17's four attacks are listed;
  - their tests exist in `tests/revocation.rs` and `tests/attacks.rs`.
  I skimmed `pades.md` and `cms.md` and did not read every row. A person should check that each attack row's "Ouverte sous" cell matches its switch.
- **`/M` before `notBefore` on the spike's own file** (QA `## Not seen`): only forged signatures were checked, by QA and by the tests.
- **A `/M` with no UTC offset is read as UTC** (`date.rs`). ISO 32000 leaves the zone unknown in that case, and I did not check what DSS / PDFBox assume. A signer west of UTC who writes no offset could get a false `SIG_CONSTRAINTS_FAILURE` near `notBefore`. A person should compare one such file against DSS during s18's campaign.
- **Open questions the research leaves to s18:**
  - `NotASignatureDictionary` and `UnsupportedSubFilter` stay listed under `dss()`;
  - a repeated extension outside the CMS is judged, not an error;
  - a certificate both expired and revoked has not been observed on DSS;
  - `/M` after `notAfter` is not judged.
- **Fuzzing:** the fuzz target is compiled only, not run here. CI's `fuzz` job covers it.
- **Production build and end-to-end:** the project has no E2E command (`E2E: —`). The build is deferred to ship (`Build stage: ship-if-route`), and no routing or manifest changed.

Max severity: major
Ship allowed: yes

---

# Review — s41-validation-policy

[Story](../stories.md) · [Plan](../plans/s41-validation-policy.md) · [Verification](../verif/s41-validation-policy.md)

Diff reviewed: `git diff main...story/s41-validation-policy`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: f08249ce8005b4acdb5d2812c0faab0bfc044b33

## When blocked
- Not blocked.

## Ownership
I listed the diff with `git diff --name-only main...story/s41-validation-policy` and checked each path against `Owns: crates/nacre-validate/, crates/nacre-pdf/, docs/security/attacks/`.
- [x] Every path is inside `Owns`:
  - all the code is under `crates/nacre-validate/`, and the three attack docs are under `docs/security/attacks/`;
  - the research, plan, verification record, QA files and review under `docs/` are the story's own evidence;
  - `docs/decisions/0026-runtime-validation-policy.md` is a new file (status `A`), and the plan names ADR-0026.
- [x] Nothing is inside another running story's `Owns`. `git worktree list` shows only `main` and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s41-validation-policy` exited 0, so I reused the record (`Verification mode: record`).
  - `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on the code of the fix run (the 09:04 and 09:05 rows).
  - I read "Not proven here". The conformance tests ran once on the bench before the fix and were not rerun after it. The fuzz target was compiled but not run. `cargo fmt` has no `po-run` row.
- [x] `po-gate qa-current s41-validation-policy` exited 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`).
  - The QA report was redone on tree 19da5484… after the fix commit 1b76dd3, and it has no findings: the first QA's finding 1 no longer reproduces.
  - It also adds the boundary case where the revocation is dated exactly at the control date, which gives `REVOKED_NO_POE`.

## Plan
- [x] Tasks 1 to 10 are all present, and nothing was changed outside the plan.
  - The fix commit 1b76dd3 changes only what loop 0's findings asked for: the `fresh` closure in `revocation.rs`, one more case in `old_revocation_counts_unless_on_hold`, rustdoc in `policy.rs`, `validate.rs` and `revocation.rs`, the `revocation.md` row, and the record.
- [x] Run interdicts, checked one by one:
  - **Diff stays inside its paths:** yes. `nacre-pdf`, `nacre-core`, `nacre-conformance`, `nacre-revocation`, `.github/`, `conformance/` and `docs/stories.md` are untouched.
  - **Existing assertions unchanged:** no assertion that exists on `main` was edited. The only test the fix changed, `old_revocation_counts_unless_on_hold`, is new in this story, and it gained a case without losing one.
  - **`FRESHNESS_TOLERANCE` kept:** unchanged. The TSA path still gets `issued_from = None` and `Rules::STRICT`.
  - **`build_chain` kept:** it still passes `Rules::STRICT`. `ChainDefect::report` and `RevocationDefect::report` are untouched.
  - **No new dependency:** no manifest or lockfile changed.
  - **Bench and public endpoints:** this can't be checked from the diff. The record says the bench was stopped.
  - **No level computation:** confirmed.

## References
- [x] Targets opened, beyond those loop 0 already checked:
  - the fix's `verdict.revoked.is_some_and(|date| date <= time)`: `Verdict.revoked` is an `Option<SystemTime>`, and `time` is the best-signature-time `judge_path` receives;
  - `in_validity` and `repeats_extension` (`chain.rs`) and how `validate.rs` uses them;
  - `qualify(…, sneaky)`, which passes `certified` only when `sneaky` is set;
  - the `sneaky_signatures` / `refused_signatures` split in `revisions.rs`.
- [x] Values:
  - The fix's boundary is `<=` on the revocation date. A revocation exactly at `time` stays a proof, which matches the existing rule "a revocation dated at or before `time` refuses the path". QA walked that exact boundary.
  - `control_date()` in the tests (2026-10-23 00:00) comes before the "later" revocation date of 2026-10-23 06:00, so the new case really sits after the judged time.

## Rules
- [x] The `AGENTS.md` conventions are respected:
  - no unwrap, index or panic outside tests;
  - `forbid(unsafe_code)` is unchanged;
  - judging code never reads the clock;
  - `Error::MalformedCertificate` is mapped to `InvalidInput`;
  - code is in English and the attack docs are in French.
- [x] No accepted ADR is contradicted. ADR-0026's eight switches are there, and `strict()` is the default.

## Tests
- [x] Floor: `po-gate floor-guard s41-validation-policy main` exited 0; nothing was lowered.
- [x] The assertions pin down AC1 to AC4.
  - Each unit test judges a committed attack file or a forged `Pki` case under `strict()`, then under `strict()` with one switch off.
  - The fixtures are real signed PDFs and nothing is mocked; none of the six empty test shapes appears.
- [x] 12 unit tests plus 9 conformance tests make 21, within the budget of 25. The fix added no test.
- [x] Bite:
  - **Exception for old proofs of revocation, the guard the fix added:** I replaced `verdict.revoked.is_some_and(|date| date <= time)` with `verdict.revoked.is_some()` (`revocation.rs:223`) and ran `--test revocation`. 1 test failed (`old_revocation_counts_unless_on_hold`). Undone, and `git diff --exit-code` is clean.
  - **`list_unusable_signatures` filter:** I replaced `policy.list_unusable_signatures || !unusable(result)` with `true || …` (`validate.rs:183`) and ran `--test policy`. 1 test failed (`unusable_signatures_switch`). Undone, and `git diff --exit-code` is clean.
  - `git status --porcelain` was empty at the end.
- [x] No test is made useless by the story.

## Neighbours
- [x] `judge_path` has two callers: the signer path (`validate.rs`, with `issued_from`) and the TSA path (with `None`).
  - With `None`, the first branch of `fresh` is always true, so the fix cannot change the TSA path.
  - `build_path`, `qualify` and `after_chain` have no callers the diff missed, and no other crate calls `nacre_validate`.

## Lenses
Lenses run: security (the path `crates/nacre-validate/src/policy.rs` names a policy, and the content is signature and revocation validation). Dependencies did not run: no manifest or lockfile changed. Performance did not run: this is not server-side code.
- [x] Loop 0's security finding is fixed. Under `strict()`, a stale CRL whose entry for the signer is dated after the judged time is dropped again, as on `main`. The bite and the QA boundary walk both confirm it.
- [x] The lens finds nothing new: there is no authorization, HTTP, upload or LLM surface, and the new error message reveals nothing.

## Findings
- minor — crates/nacre-validate/src/policy.rs:57 — The rewrap of the `require_fresh_revocation` rustdoc left one 126-character line ("… `certificateHold`. Off, freshness is ignored: an old "not revoked""), when the doc lines around it are wrapped at about 92. Rewrap the paragraph.
- minor — crates/nacre-validate/src/validate.rs:83 — Loop 0's minor is fixed (the line holding only "before the" is gone), but the fix moved the sentence onto one 140-character line ("… gives [`Defect::Revocation`], `INDETERMINATE` / `REVOKED_NO_POE`"). Rewrap the paragraph.

## Not verified
- **Conformance against DSS 6.5.1 (AC2, AC5).** I did not start the DSS bench. The nine `#[ignore = "conformance"]` tests rest on the implementer's single run before the fix, which has no `po-run` row; the record says they were not rerun after the fix.
  - The fix changes only `strict()` with no proof of existence, a case DSS does not judge, so the `dss()` side should not move.
  - A person should run `cargo test -p nacre-validate --all-features --test conformance -- --ignored --test-threads=1` on the bench (`conformance/README.md`), or check that CI's `conformance.yml` is green on this tree.
  - This is also a QA `## Not seen` item: DSS is a dependency the QA driver did not start.
- **AC5, one conformance test per switch** (QA `## Not seen`): these need the bench. QA saw each switch's effect through the library only.
- **AC6, `docs/security/attacks/`** (QA `## Not seen`, left to the review).
  - I read the `revocation.md` row the fix changed, and it matches the new behaviour.
  - As in loop 0, I did not check every row of `pades.md` and `cms.md`. A person should check that each attack's "Ouverte sous" cell names the right switch.
- **`/M` before `notBefore` on the spike's own file** (QA `## Not seen`): only forged signatures were walked.
- **A `/M` with no UTC offset is read as UTC** (`date.rs`). ISO 32000 leaves the zone unknown in that case, and I did not compare what DSS or PDFBox assume. A person should check one such file against DSS during s18's campaign.
- **Open questions the research leaves to s18:**
  - `NotASignatureDictionary` and `UnsupportedSubFilter` stay listed under `dss()`;
  - a repeated extension outside the CMS is judged, not an error;
  - a certificate both expired and revoked has not been observed on DSS;
  - `/M` after `notAfter` is not judged.
- **Fuzzing:** the target was compiled but not run here. CI's `fuzz` job runs it.
- **Formatting:** `cargo fmt` has no `po-run` row; it is checked at commit and in CI.
- **Production build and end-to-end:** the project has no E2E command (`E2E: —`). The build is deferred to ship (`Build stage: ship-if-route`), and no routing or manifest changed.

Max severity: minor
Ship allowed: yes
