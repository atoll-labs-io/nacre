# Review — s48-detect-later-modifications

[Story](../stories.md) · [Plan](../plans/s48-detect-later-modifications.md) · [Verification](../verif/s48-detect-later-modifications.md)

Diff reviewed: `git diff main...story/s48-detect-later-modifications`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 30336229f2f60854b731de1030d4f3c2bbdad943

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s48-detect-later-modifications` (28 paths) and checked each one against `Owns: crates/nacre-validate/, crates/nacre-pdf/, docs/security/attacks/pades.md, conformance/corpus/foreign/`.
- [x] Every path is inside `Owns`. The other paths are this story's own pipeline evidence (research, plan, verif, qa).
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only main and this story's worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s48-detect-later-modifications` → exit 0, so I reused the record. Under `Verification mode: record` it proves `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` on this code. Its "Not proven here" says: E2E (the project has none, `E2E: —`) and the build (deferred to ship). The campaign and the run on the spoofing file are quoted in the record as runs made outside `po-run`.
- [x] `po-gate qa-current s48-detect-later-modifications` → exit 0. The QA report is complete and current, and it has no findings to carry over. Its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1 to 9 are all in the diff, and there is nothing outside the plan. `tests/corpus/README.md` is the source note that the corpus convention requires, and it is inside `Owns`.
- [x] I checked each run interdict:
  - `ValidationPolicy` is unchanged, with no new field. `strict()`/`dss()` changed in rustdoc only.
  - `revisions.rs` is untouched.
  - No existing file in `tests/corpus/attacks/` or `tests/corpus/*.pdf` is modified: the four `isa-*` files are added, nothing else.
  - `pades-spoofing-replaced-reason.pdf` is absent: `git ls-files` returns nothing.
  - The only PDF added under `conformance/` is `pdf-signed-added-page.pdf`, and its SHA-256 `467573be…a7a2ec` matches the README.
  - `conformance/campaign/reports/` is untouched.
  - No `Cargo.toml` or lockfile changed.
  - s49's families and the bench were not touched.

## References
- [x] I opened every reference and confirmed it: `Document::reachable` (`nacre-pdf/src/document.rs:151`), `Stream { dict, data: Range<usize> }` (`object.rs:95`), `signature_fields`, `catalog`, `ReadOptions`, `SignatureValidation::defective`, and the `end`/`value`/`options` bindings in `validate_with` (`validate.rs:165-300`). The code compiles under the recorded clippy run.
- [ ] Values that only look right: `MAX_PAIRS = 4096` is not confirmed by anything (see Findings). `MAX_DEPTH = 500` is DSS's, according to the research.

## Rules
- [x] The `AGENTS.md` conventions hold:
  - no `unwrap`, `expect` or indexing outside tests;
  - nothing is logged;
  - the walk is bounded;
  - the new attack corpus has its doc rows, cases and rejecting tests;
  - test strings are fictitious.
- [x] No accepted ADR is contradicted: the new rule has no switch, per ADR-0026.

## Tests
- [x] Floor: `po-gate floor-guard s48-detect-later-modifications main` → exit 0, nothing lowered.
- [x] The assertions pin down AC2 to AC4. Each attack test asserts both presets, and the `dss()` assertion is the one that bites. None of the six empty test shapes is present.
- [x] 6 new tests, within the budget of 25.
- [x] Bite. I ran each mutation with `cargo test --no-fail-fast -p nacre-validate --lib --test attacks --test validate --test policy`, plus `--test hostile` for the order mutation. After each one, `git checkout --` and `git diff --exit-code` came back clean.
  - Page-count rule disabled → 4 failing tests: `isa_page_added_is_rejected`, `dss_added_page_fails_under_both_presets`, and two policy contract tests.
  - Field rule disabled → 5 failing tests: the 3 `isa_reason_*`/`isa_signature_moved` tests and 2 policy contract tests.
  - `/Reference`→`/Data` exclusion removed → 1 failing test: `dss_exclusions_and_nothing_else`. No integration test fails, as the plan said.
  - `/F`/`/Type`/`/ITXT` tolerance removed → 1 failing test: `dss_exclusions_and_nothing_else`.
  - Order (new check only after a sound CMS: `.filter(|_| result.is_ok())`) → **0 failing tests** (see Findings).
- [x] No test is made useless by the story.

## Neighbours
- [x] `Defect` is matched only in `report.rs`, and no other crate matches its variants. `changed_since` has a single caller. `revisions.rs` uses `reachable()` on its own.

## Lenses
Lenses run: none. Nothing triggers a lens:
- no auth, route, upload, webhook or HTTP path or content;
- no migration;
- no manifest or lockfile change;
- library code, no server-side code.

## Findings
- major — crates/nacre-validate/src/modifications.rs:41-42 — When the revision read fails, both new checks are skipped (they "fail open"), so a crafted file gets past them under `dss()`.
  - `last.reachable().ok()?` returns `None` whenever any object reachable in the last revision fails to parse or a reader limit is hit. Then neither `PageCountChanged` nor `SignatureDictionaryChanged` is checked.
  - Reproduced by a probe under `/tmp/tmp.4g7eH9CXQW/` that calls the public API. I took `isa-page-added.pdf` and appended one revision whose catalog adds `/Foo 10 0 R`, with object 10 left unterminated. Results:
    - `strict()`: `TOTAL_FAILED / FORMAT_FAILURE`, `RevisionNotAllowed { end: 3433 }`.
    - `dss()`: `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`, `defect=None`.
  - This contradicts the module's own rule ("a bound reached counts as a change: never laxer than DSS") and the story's aim that a modification DSS detects is never let through. PDFBox would most likely still read `/Count 2`; DSS's verdict on this file is unverified.
  - Contained: `strict()` (the default) still refuses the file, and `dss()` is documented as unsafe for trust decisions.
  - Suggested fix: read the page count through `Document::object` rather than a full `reachable()`, and count a failed read of the last revision as a change. A failed read of the signed revision should keep returning `None`, which the plan wants for `byterange-not-whole-file.pdf`.
- major — crates/nacre-validate/src/validate.rs:279-284 — The ordering rule has no committed test.
  - The rule is "format checks before the CMS verdict; a modified file whose CMS fails reads `FORMAT_FAILURE`, never `INDETERMINATE`" (plan, The pivot, "Order"; task 3; `pades.md` control 10). The flags mapping in `SignatureValidation::modified` (`report.rs:194-215`) has no test either.
  - When I restricted the new check to a sound CMS, every test in `attacks`, `validate`, `policy`, `hostile` and the lib still passed. The rule is proven only once, by QA's scratch binary (`ac2-both-presets-error.txt` §2), which is not committed.
  - Suggested fix: add one test, for example a flipped signed byte followed by a page-added revision, expecting `PageCountChanged` and `FORMAT_FAILURE` with `digest_verified == false`.
- minor — crates/nacre-validate/src/modifications.rs:16 — `MAX_PAIRS = 4096` is not confirmed by anything.
  - Every compared value counts as one pair, including array items and identical objects reached by the same reference on both sides. The whole `/V`, `/Rect`, `/AP` subtree is walked down to the first `/Resources`, fonts included.
  - A legitimate signature whose appearance embeds a large font (a long `/W` or `/Widths` array) followed by an allowed later revision (`/DSS`, LTA) would hit the bound. It would then get `SignatureDictionaryChanged` under both presets, where DSS (depth bound only) passes it.
  - No committed file hits the bound: the campaign is at 0 differences. The value should be grounded or raised, and equal references could be short-circuited.
- minor — crates/nacre-validate/src/modifications.rs:42 — `last.reachable()` is recomputed for every signature (up to `MAX_SIGNATURES` = 64), even though it is the same map each time. Each signature with a later revision also re-parses its prefix, on top of `qualify`'s own up to 64 states. Potential impact: hostile-input cost, within existing bounds. Computing it once in `validate_with` would remove the repeat.
- minor — crates/nacre-validate/src/policy.rs:136-138 — The rustdoc reflow of `dss()` left one line much longer than its neighbours ("…key usage forbids signing, a signature under a `/SubFilter` Nacre does not support, a cross-reference section found only by"). Style only.

## Not verified
- **Campaign against a running DSS.** I did not start the DSS bench. "264 cases, 0 differ under `dss()`, 0 unexplained under `strict()`" and the `=` rows for the six new cases and `pdf-signed-added-page` are taken from the verification record. They were run outside `po-run`, on code the record says is this tree. A person can rerun `cargo test -p nacre-validate --all-features --test campaign -- --ignored` on a bench started per `conformance/README.md`.
- **`pades-spoofing-replaced-reason.pdf`.** It is not committed and I did not read it. Its two verdict lines are taken from the record and from the QA report §3.
- **DSS's verdict on my crafted bypass file** and on QA's boundaries is unknown: `/Count` as a real, a name or 0; `/Location` added; `/Type` replaced in the signature dictionary; `/T` renamed; `/TU` added. Same reason as QA gives: no running DSS. Run them through the bench to settle them.
- **A page removed from a multi-page document.** Untested here and in QA, which reached a lower count only as `/Count 0`, since the forged documents start from a one-page file.
- **Stream comparison.** Whether DSS compares streams decoded or raw is still unsettled (research, open question 1). Nacre compares raw bytes, which can only be stricter.
- **The `AP` "second `/Resources`" exclusion.** It mirrors a partial read of DSS's bytecode (research, open question 3). Neither a committed case nor the unit test exercises it.
- **QA `## Not seen`, criterion 1.** It is a document, with no observable behaviour.
- **QA `## Not seen`, criteria 2 and 3 "DSS's verdict" and the campaign.** They need the bench, which QA did not start.
- **QA `## Not seen`, page-count rule on a removed page.** The forged documents have one page.
- **Build.** Deferred to ship (`Build stage: ship-if-route`). No routing or manifest changed.
- **End to end.** The project has none (`E2E: —`).

Max severity: major
Ship allowed: yes

---

# Review — s48-detect-later-modifications

[Story](../stories.md) · [Plan](../plans/s48-detect-later-modifications.md) · [Verification](../verif/s48-detect-later-modifications.md)

Diff reviewed: `git diff main...story/s48-detect-later-modifications`, read by a reviewer that did not write it. Each finding is rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: e9802e20068c89d3520e7ae159cc364c709853a1

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the changed paths with `git diff --name-only main...story/s48-detect-later-modifications` (29 paths) and held each one against `Owns: crates/nacre-validate/, crates/nacre-pdf/, docs/security/attacks/pades.md, conformance/corpus/foreign/`.
- [x] Every code and corpus path is inside `Owns`. The remaining paths are this story's own pipeline evidence: research, plan, verif, qa, and the review from fix loop 0.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s48-detect-later-modifications` exited 0. Under `Verification mode: record`, I relied on the record for `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`: the last `po-run` rows exited 0 on code equal to `Tree:` outside `docs/`.
  - "Not proven here": the project has no end-to-end command (`E2E: —`), and the build is deferred to ship.
  - The campaign and the run on the spoofing file were run outside `po-run`, and the record only quotes them.
- [x] `po-gate qa-current s48-detect-later-modifications` exited 0: QA is complete, on tree `5ea26620…`, and the report is committed. QA has two verified findings, both minor; they are carried below. Its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1 to 9 are present.
- [x] The fix run (`60adafe`) addresses each fix loop 0 finding:
  - The fail-open on an unreadable last revision is closed: the page count is now read leniently through `Document::object`, and a failed `reachable()` counts as `SignatureDictionaryChanged`.
  - The order rule now has a test: `modification_is_judged_before_a_failed_digest`.
  - `MAX_PAIRS` was raised to 65 536, and an identical pair that holds no reference now counts once.
  - `reachable()` of the last revision is now computed once, in `validate_with`.
  - The long rustdoc line was moved, but not fixed (see Findings).
- [x] Run interdicts hold:
  - `ValidationPolicy` fields and `strict()`/`dss()` changed in rustdoc only.
  - `revisions.rs` is untouched.
  - No existing corpus PDF is modified.
  - No path named `*spoofing*` is in git.
  - `conformance/campaign/`, `Cargo.toml` and the lockfile are untouched.

## References
- [x] I opened every reference and checked it:
  - `Document::object` and `Document::reachable` (`crates/nacre-pdf/src/document.rs:136-178`); the `max_reachable` limit (`limits.rs:31`);
  - `SignatureValidation::modified` (`report.rs:197-215`);
  - the binding of `last_objects` (`validate.rs:246-251`), which uses the same `end < pdf.len()` test as the early return of `changed_since`;
  - the `Objects` type, made `pub(crate)` for the new parameter.
- [x] Values that only look right:
  - `MAX_DEPTH = 500` comes from DSS, according to the research.
  - `MAX_PAIRS = 65 536` rests on the claim that no repository field walks more than 20 pairs. Nothing I ran confirms that claim; QA finding 2 shows the bound biting on an artificial shape.

## Rules
- [x] The fix-run code has no `unwrap`, `expect` or indexing outside tests, logs nothing, and keeps every walk bounded.
- [x] The tests use only fictitious strings.
- [x] ADR-0026 holds: the rule has no switch.

## Tests
- [x] Floor: `po-gate floor-guard s48-detect-later-modifications main` exited 0. awk printed a locale warning, but the guard found nothing lowered.
- [x] 8 new tests, within the budget of 25. None of the six "tests that prove nothing" patterns appears. The two fix-run tests patch committed corpus bytes and call the public API.
- [x] Bite. For each mutation I ran `cargo test --no-fail-fast -p nacre-validate --lib --test attacks --test validate --test policy`. After each one I ran `git checkout --`, and `git diff --exit-code` came back clean.
  - **Order** (`.filter(|_| result.is_ok())` on the new check): 1 test fails, `modification_is_judged_before_a_failed_digest`.
  - **Page count of the last revision read through `reachable()` again**, skipping the checks when that read fails: 1 test fails, `unreadable_object_in_the_last_revision_skips_no_check`.
  - **`let Some(last_objects) = last_objects else { return Some(SignatureDictionaryChanged) }` changed to `return None`**: **0 tests fail** (see Findings).
  - **`holds_reference` dropped from the identical-pair shortcut**, so identical references would be skipped: 6 tests fail — `dss_exclusions_and_nothing_else`, `isa_reason_replaced_is_rejected`, `isa_reason_redefined_is_rejected`, and the two policy contract tests.

## Neighbours
- [x] `changed_since` has one caller, and `SignatureValidation::modified` has one too.
- [x] `Defect` variants are matched only in `report.rs`.
- [x] `revisions.rs:151` still calls `reachable()` on its own, unchanged.

## Lenses
Lenses run: none. Nothing in the diff triggers one: no auth, route, upload or HTTP code; no migration; no manifest or lockfile change; no server-side code.

## Findings
- major — crates/nacre-validate/src/modifications.rs:65-67 — The field-comparison half of the fail-open fix has no committed test.
  - Mutation: when `reachable()` of the last revision fails, return `None` instead of `SignatureDictionaryChanged`. Every test in `--lib`, `attacks`, `validate` and `policy` still passes.
  - Why: `unreadable_object_in_the_last_revision_skips_no_check` builds on `isa-page-added.pdf`, so the page-count check (`/Count 2`) refuses the file before the field comparison is reached.
  - Effect of a regression: under `dss()`, a replaced `/Reason` (or a moved `/Rect`) plus one unreadable reachable object would pass again. That is the bypass fix loop 0 reported, reopened for the field half.
  - Only QA's uncommitted scratch binary reaches this path (`ac2-both-presets-error.txt` §5, unreadable `/TU`).
  - Suggested fix: add the same broken-object revision on top of `isa-reason-replaced.pdf`, expecting `SignatureDictionaryChanged` under both presets.
- minor — docs/security/attacks/pades.md:93 — The attack catalogue still says « 4096 paires », but the code now uses `MAX_PAIRS = 65_536` (`modifications.rs:20`). It also does not say that an identical, reference-free pair counts once. This is QA finding 1 (verified), carried over.
- minor — crates/nacre-validate/src/modifications.rs:15-20 — An allowed `/DSS` revision fails a signature whose `/V` holds about 70 000 references: QA saw `TOTAL_FAILED` / `FORMAT_FAILURE` / `SignatureDictionaryChanged` under both presets, `strict()` included. The pair bound counts as a change by design, and DSS (which bounds depth only) would presumably pass the file. The shape is artificial and was never seen in a real file. This is QA finding 2 (verified), carried over.
- minor — crates/nacre-validate/src/policy.rs:139 — The `dss()` rustdoc reflow still leaves one 125-character line ("a cross-reference section found only by skipping whitespace, a CRL issued after a certificate expired, trusted on its"). Fix loop 0 reported it, and the fix run moved the long line instead of rewrapping it. Style only.

## Not verified
- **Campaign against a running DSS.** I did not start the bench, so these results come from the verification record, run outside `po-run`, on the fix run's code: "264 cases, 0 differ under `dss()`, 0 unexplained under `strict()`", with `=` rows for the four `isa-*` files, `m1`, `m2` and `pdf-signed-added-page`. A person can rerun `cargo test -p nacre-validate --all-features --test campaign -- --ignored` on a bench started as `conformance/README.md` says.
- **`pades-spoofing-replaced-reason.pdf`.** It is not committed and I did not read it. Its verdict lines come from the record and from QA §3.
- **DSS's verdict on the new fallbacks.** Unknown for an unreadable object in the last revision, read as null in the page count and as a change in the field comparison. I did not check whether PDFBox's lenient reading agrees, so `dss()` may be stricter than DSS on such files. A related case is a last revision whose `reachable()` fails only on a reader limit (`max_reachable`, the decoding budget) while the signed revision reads fine: it is now `SignatureDictionaryChanged` for every signature with a later revision. Run such a file through the bench to settle it.
- **The `MAX_PAIRS` rationale** ("no field of the repository's PDF files walks more than 20"). I did not measure it.
- **QA `## Not seen`, criterion 1.** It is a document, with no observable behaviour.
- **QA `## Not seen`, criteria 2 and 3 against a running DSS.** The bench was not started. DSS's verdict on QA's boundaries (`/Count` as a real, a name or 0; `/Location`, `/Type`, `/T`, `/TU`; unreadable objects; large `/V`) is unknown.
- **QA `## Not seen`, a page removed from a multi-page document.** The forged documents have one page.
- **Stream comparison, decoded or raw** (research, open question 1), and the `AP` second-`/Resources` exclusion (open question 3). No committed case exercises either.
- **Build.** Deferred to ship (`Build stage: ship-if-route`); no routing or manifest changed.
- **End to end.** The project has none (`E2E: —`).

Max severity: major
Ship allowed: yes

---

# Review — s48-detect-later-modifications

[Story](../stories.md) · [Plan](../plans/s48-detect-later-modifications.md) · [Verification](../verif/s48-detect-later-modifications.md)

Diff reviewed: `git diff main...story/s48-detect-later-modifications`, read by a reviewer that did not write it. Each finding is rated critical, major or minor.

Review status: complete
Fix loop: 2
Reviewed tree: 8748e152e3dae2bf377f8a3679d03f6d1e5ed88d

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the changed paths with `git diff --name-only main...story/s48-detect-later-modifications` and checked each one against `Owns: crates/nacre-validate/, crates/nacre-pdf/, docs/security/attacks/pades.md, conformance/corpus/foreign/`.
- [x] Every code, corpus and doc path is inside `Owns`. The other paths are this story's own pipeline evidence: research, plan, verif, qa, and the reviews from loops 0 and 1.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s48-detect-later-modifications` exited 0. Under `Verification mode: record`, I relied on the record for two checks. Their last `po-run` rows (2026-10-26T10:11Z) both exited 0:
  - `cargo test --workspace`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [x] What the record does not prove:
  - The project has no end-to-end command (`E2E: —`).
  - The build is left to ship.
  - The campaign and the run on the spoofing file were run outside `po-run` and were not repeated after fix commit `ec9dbd5`. The record says so. I checked that the claim holds: `git show ec9dbd5` changes only rustdoc in `policy.rs` and no other library code.
- [x] `po-gate qa-current s48-detect-later-modifications` exited 0. QA status is complete on the code of this tree, and the report is committed (`be040c5`).
  - QA has one verified finding, minor, carried below.
  - QA's `## Not seen` items are listed under Not verified.

## Plan
- [x] Tasks 1 to 9 are present, and the diff holds nothing outside the plan.
- [x] Fix commit `ec9dbd5` addresses each finding from fix loop 1:
  - **Major, the field-comparison fallback had no test.** The commit adds the helper `with_unreadable_object` and the test `unreadable_object_in_the_last_revision_skips_no_field_comparison`, built on `isa-reason-replaced.pdf`. The mutation below shows it bites.
  - **Minor, `pades.md` said 4096 pairs.** It now says 65 536, describes how an identical pair is counted, says how an unreadable object is read, and names both `unreadable_object_*` tests.
  - **Minor, the long rustdoc line in `policy.rs`.** It is rewrapped: no line of `policy.rs` is longer than 100 characters.
  - **Minor, the `MAX_PAIRS` deviation.** It is now documented as a deliberate deviation that is stricter than DSS (see Findings).
- [x] The run interdicts still hold:
  - No `ValidationPolicy` field changed.
  - `revisions.rs` is untouched.
  - No existing corpus PDF changed.
  - No `*spoofing*` file is in git.
  - No `Cargo.toml` or lockfile changed.
  - `conformance/campaign/` is untouched.

## References
- [x] I opened the references used by the fix run's test helper: the `startxref` / `/Prev` parsing over committed corpus bytes, `both_presets`, and `Defect::SignatureDictionaryChanged`. The code they lead to is unchanged since loop 1: `changed_since` at `modifications.rs:36-80`, and `last_objects` at `validate.rs:246-251`.
- [x] Values that only look right:
  - `MAX_DEPTH = 500` is DSS's value, according to the research.
  - The rationale for `MAX_PAIRS = 65 536` is still unmeasured (see Not verified).

## Rules
- [x] The `AGENTS.md` conventions hold. The new helper uses `unwrap` and indexing in an integration test only, where the parsing lints do not apply. Its test strings are fictitious.
- [x] ADR-0026 holds: the rule has no switch.

## Tests
- [x] Floor: `po-gate floor-guard s48-detect-later-modifications main` exited 0. awk printed a locale warning, and nothing was lowered.
- [x] There are 9 new tests, within the budget of 25. None of them falls into the six "tests that prove nothing" patterns: the new test changes committed corpus bytes and calls the public API under both presets.
- [x] Bite. For each mutation I ran `cargo test --no-fail-fast -p nacre-validate --lib --test attacks --test validate --test policy`, then `git checkout --`. `git diff --exit-code` came back clean after each.
  - **Field fallback**: in `modifications.rs:65-67`, `return Some(Defect::SignatureDictionaryChanged)` changed to `return None`. **1 test fails**, `unreadable_object_in_the_last_revision_skips_no_field_comparison`. The gap reported in loop 1 is closed.
  - **Page-count rule disabled** (`if false && before != after`): **6 tests fail**:
    - `isa_page_added_is_rejected`
    - `modification_is_judged_before_a_failed_digest`
    - `unreadable_object_in_the_last_revision_skips_no_check`
    - `dss_added_page_fails_under_both_presets`
    - `dss_opens_only_what_the_catalog_marks`
    - `each_switch_changes_only_what_the_catalog_names`
  - The order, field-rule, `/Reference`→`/Data` and `holds_reference` mutations from loops 0 and 1 are on library code this fix run did not touch.

## Neighbours
- [x] `changed_since` and `SignatureValidation::modified` each have one caller.
- [x] `Defect` variants are matched only in `report.rs`.
- [x] The fix run changed no library signature.

## Lenses
Lenses run: none. Nothing in the diff triggers a lens:
- no auth, route, upload or HTTP code;
- no migration;
- no manifest or lockfile change;
- library code only, no server-side code.

## Findings
- minor — crates/nacre-validate/src/modifications.rs:15-20 — An allowed `/DSS` revision fails a signature whose `/V` reaches about 70 000 references.
  - QA saw `TOTAL_FAILED` / `FORMAT_FAILURE` / `SignatureDictionaryChanged` under both presets, `strict()` included.
  - DSS bounds only the depth, so it would presumably pass this file.
  - The shape is artificial, the deviation is only ever stricter than DSS, and `pades.md:93` now documents it as deliberate.
  - This is QA finding 1 (verified), carried over.

## Not verified
- **Campaign against a running DSS.** I did not start the bench. "264 cases, 0 differ under `dss()`, 0 unexplained under `strict()`" and the `=` rows for these files come from the verification record:
  - the four `isa-*` files;
  - `m1` and `m2`;
  - `pdf-signed-added-page`.

  Those runs were made outside `po-run`, on library code equal to this tree's apart from rustdoc. A person can rerun `cargo test -p nacre-validate --all-features --test campaign -- --ignored` on a bench started as `conformance/README.md` says.
- **`pades-spoofing-replaced-reason.pdf`.** It is not committed, and I did not read it. Its verdict lines come from the record and from QA §3.
- **DSS's verdict on the fallbacks.** These cases may make `dss()` stricter than DSS:
  - an unreadable object in the last revision, which is read as null for the page count and counts as a change in the field comparison;
  - the same after an allowed `/DSS` revision;
  - a `reachable()` that fails only on a reader limit.

  Run such files through the bench to settle it.
- **The `MAX_PAIRS` rationale** ("no field of the repository's PDF files walks more than 20"): not measured.
- **QA `## Not seen`, criterion 1.** It is a document, with no observable behaviour.
- **QA `## Not seen`, criteria 2 and 3 against a running DSS.** QA did not start the bench, so DSS's verdict on QA's boundary cases is unknown:
  - `/Count` as a real, a name or 0;
  - `/Location`, `/Type`, `/T`, `/TU`;
  - unreadable objects;
  - a large `/V`.
- **QA `## Not seen`, a page removed from a multi-page document.** The forged documents have one page.
- **Stream comparison, decoded or raw** (research, open question 1), and **the `AP` second-`/Resources` exclusion** (open question 3). No committed case exercises either.
- **Build.** Left to ship (`Build stage: ship-if-route`). No routing or manifest changed.
- **End to end.** The project has none (`E2E: —`).

Max severity: minor
Ship allowed: yes
