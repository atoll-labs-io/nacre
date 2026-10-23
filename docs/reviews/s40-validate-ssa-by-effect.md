# Review — s40-validate-ssa-by-effect

[Story](../stories.md) · [Plan](../plans/s40-validate-ssa-by-effect.md) · [Verification](../verif/s40-validate-ssa-by-effect.md)

Diff reviewed: `git diff main...story/s40-validate-ssa-by-effect`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: d7b32012c03b3366ee13cb6cc8da3661d5b1b95c

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
Diff listed with `git diff --name-only main...story/s40-validate-ssa-by-effect`, each path held against `Owns: crates/nacre-validate/, docs/security/attacks/pades.md`.
- [x] Every path inside `Owns`. All `crates/nacre-validate/` paths and `docs/security/attacks/pades.md` are inside it. The `docs/plans|research|verif|qa/s40-…` files are this story's own pipeline evidence.
- [x] Outside `Owns`: none
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only this lane.
- [x] The story has an `Owns` line

## Evidence reused
- [x] `po-gate verif-current s40-validate-ssa-by-effect` → exit 0, record reused (`Verification mode: record`). The unit suite `cargo test --workspace` and the type check `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on this code, and were not rerun. Its "Not proven here" section was read and is carried into Not verified.
- [x] `po-gate qa-current s40-validate-ssa-by-effect` → exit 0 (Surface `endpoint`, `QA stage: surfaces`). The QA report has no findings. Its `## Not seen` is carried into Not verified.

## Plan
- [x] Tasks 1 to 6 are present. The lead's recorded decision removed `/AP` from "shown", which removed `appears`, `certified-new-field-no-appearance.pdf` and its test. The diff follows that decision.
- [x] One addition is outside the plan: the scan of new `/FT /Sig` objects outside `/Fields` in `sneaky` (`revisions.rs:352-363`), with `own_widgets` (`:704-717`). It keeps a path s15 covered. See findings.
- [x] Run interdicts, checked one by one:
  - Nothing changed in `nacre-pdf`, `nacre-core`, `nacre-pades`, the root `Cargo.toml` or `crates/nacre-validate/Cargo.toml`.
  - In the corpus, only the README changed, plus the 5 added files. I reran the forge in a temp clone and every corpus file came out byte-identical. The README's SHA-256 values match the files.
  - `report.rs` changed in doc comments only, and no variant was added.
  - No test assertion was removed and no `#[ignore]` was added. `sneaky_refused` now finds the certification by field name instead of `results[0]`, with the same assertions.
  - The DocMDP 1 refusal and the accept rules are unchanged, and `tests/validate.rs` passes.

## References
- [x] `added_here`, `placement`, `with_self`, `own_widgets`, `Placed`, `FormNode.widgets` and `form_nodes` were opened. So were the forge helpers `prepared`, `sign_prepared`, `edited`, `merged_sig`, `register`, `seal` and `certify`. All of them exist, and the type check confirms it.
- [x] Values: Hidden is 2 and NoView is 32. Corners are normalised, a zero area is `Off`, and a NaN area stays visible. An unreadable `/Rect` is `Unknown`, which is visible and matches nothing. These match the plan's rule.

## Rules
- [x] `AGENTS.md` conventions are respected: no panic paths (clippy is clean), no clock, no network, fictitious corpus with its README rows. The exception, a listed shape with no corpus case, is reported below.
- [x] No accepted ADR is contradicted.

## Tests
- [x] Floor: `po-gate floor-guard s40-validate-ssa-by-effect main` → 0, nothing lowered
- [x] The assertions pin criteria 1 to 3: four rejecting tests and one accepting test (`certified_visible_field_signed_is_allowed`). The uncertified invisible second signer is already covered by `twice_signed_first_signature_has_an_allowed_signature_revision`. None of the six empty test shapes appear.
- [x] Five new tests, within `Test budget: 25`.
- [x] Bite 1: dropped the rectangle equality in the exemption (`revisions.rs:381`, exemption keyed on widget id only) → 0 failing tests → undone, `git diff --exit-code` clean.
- [x] Bite 2: made the certified snapshot keep Off/Unknown widgets and exempt by id only (the s15 "existence only" gap) → 4 failing tests (`ssa_zero_rect_shown`, `ssa_hidden_widget_shown`, `ssa_indirect_rect`, `ssa_kid_widget_shown`) → undone, `git diff --exit-code` clean.
- [x] Bite 3: disabled the `forced` removal from `accepted` and the `forced` skips in `signatures` → 1 failing test (`ssa_visible_signature_is_rejected`) → undone, `git diff --exit-code` clean.
- [x] Bite 4, in a temp clone: disabled the scan of new `/FT /Sig` objects outside `/Fields` (`revisions.rs:353`) → 0 failing tests in `attacks` and `validate`. On a probe file the certification then reads `Allowed([Signature])`. The clone was restored, `git diff --exit-code` clean.
- [x] No test was made useless by the story.

## Neighbours
- [x] Callers were read:
  - `signature_value`: its single caller is `signatures`.
  - `refuse_signature`: called from `sneaky` and from the DocMDP 1 branch. Duplicates are now skipped; `validate.rs:84` uses `contains`.
  - `visible`: had no other caller.
  - `new_signature_fields`: the `pages` rule (`:603`).
  - `FormNode`: `field_locks` and `form_fills` are unaffected.

## Lenses
Lenses run: security — content: the PDF signature attack rule (`revisions.rs` sneaky pass, `docs/security/attacks/pades.md`). The dependencies lens did not run: no manifest or lockfile changed.
- [x] The lens findings are graded below.

## Findings
- major — crates/nacre-validate/src/revisions.rs:719 — "The widgets of a field" are still read from the structure (`/Kids` and the field itself, `with_self`), not from what the page draws. Criterion 1 asks for "une apparence … visible sur la page", and `pades.md:68` claims "couvre toutes les formes".
  Probe, forged in a temp clone from the corpus forge helpers. Certified `/P 2`, then one revision adds:
  - a merged signature `Sneaky` in `/Fields`, `/Rect [0 0 0 0] /F 132`, its `/V` signed correctly;
  - a separate visible widget, `/Parent` = `Sneaky`, `/Rect [72 650 400 700]`, overlay `/AP`, listed in page 3 `/Annots` but not in `/Kids`.

  Result: the certification gets `RevisionNotAllowed`, but `Sneaky` gets `defect=None` (INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND). `main` gives the same result, so this is not a regression. It is a shape the by-effect rule was meant to close, and once s16 judges chains it can read as valid.

  Two more shapes follow by reasoning but were not probed:
  - a widget placed at its rect in the certified state but kept invisible by `/OC`, or absent from the page `/Annots`, then made visible while signing;
  - in both, `Sneaky` would be exempt and read sound.

  Fix: derive a field's widgets from the pages' `/Annots` entries whose `/Parent` chain reaches the field, plus `/Kids`. Add a corpus case and a rejecting test.
- major — crates/nacre-validate/src/revisions.rs:352-363 — No test pins the scan of new `/FT /Sig` objects outside `/Fields` (bite 4: 0 failures).
  Without the scan, a visible merged signature that only the page lists is accepted. Probe: the certification reads `Allowed([Signature])` with an overlay drawn over the certified page.
  `pades.md:68` lists "champ de signature hors de /Fields que seule la page affiche" as a covered shape, yet it has no corpus case or rejecting test. That goes against the convention "one corpus case and one rejecting test per attack". The verification record admits the gap.
  Add `ssa-outside-fields.pdf` and a test asserting the certification's `RevisionNotAllowed`.
- major — crates/nacre-validate/src/revisions.rs:381 — The per-widget rectangle equality is untested (bite 1: 0 failures). `pades.md` and the plan state that a moved `/Rect` on a certified, placed field is refused as an SSA.
  Without the equality check, the certification still fails, because `/Rect` is not in `SIGN_KEYS`, but the signature that moved its appearance reads with no defect. QA checked the certification only.
  Add a corpus case with a moved rect and assert `AddedByRevisionNotAllowed` on the signer.
- minor — crates/nacre-validate/src/revisions.rs:704-717 — `own_widgets` copies the kid extraction and the `/T` partition of `form_nodes` (`:762-777`) instead of sharing them. The plan's Reuse names that partition as the source for a field's widgets. Factor one function both use.
- minor — docs/plans/s40-validate-ssa-by-effect.md — The plan still describes what the lead's decision removed:
  - "The rule" defines Shown as placement plus appearance;
  - tasks 1, 4, 5 and 6 still name `appears`, `certified-new-field-no-appearance.pdf`, `certified_new_field_without_appearance_is_allowed`, and "a visible-rect signature with no appearance is not an SSA";
  - the test strategy says six tests.

  The code and `pades.md` follow the decision. The story's notes also list a non-empty `/AP` as part of "visible", and that deviation, which is stricter, is recorded only in the plan.

## Not verified
- DSS and Acrobat parity of the new verdicts: the four refused shapes, the honest prepared-field signing, and the per-widget stricter rule. Left to s18 and s19; a person should compare on DSS.
- Whether real viewers (Acrobat, pdf.js) draw the orphan-`/Parent` widget of the first finding as the `Sneaky` signature. The probe proves only Nacre's verdict; open the probe file in a viewer.
- The `/OC` and "not in `/Annots`" variants of the first finding were reasoned, not forged.
- The fuzz target `crates/nacre-validate/fuzz/` was not run; CI's `fuzz` job runs it.
- `cargo fmt` has no `po-run` row; it is checked at commit and in CI.
- From the QA report's `## Not seen`:
  - Criterion 4 (`pades.md`) has no observable effect through the library; this review read it against the code, see findings.
  - A visible SSA on a P=1 document: the corpus has only an invisible late signature under P=1.
  - An SSA signed with a new key or CMS built for the walk: `qa-sign` makes invisible signatures only.
  - Files from real signers other than pyHanko (Acrobat and others): none in the corpus.
- The end-to-end suite and the production build: the project has no `E2E` command (`—`), and `Build stage: ship-if-route` leaves the build to ship, since no route or manifest changed.

Max severity: major
Ship allowed: yes

---

# Review — s40-validate-ssa-by-effect

[Story](../stories.md) · [Plan](../plans/s40-validate-ssa-by-effect.md) · [Verification](../verif/s40-validate-ssa-by-effect.md)

Diff reviewed: `git diff main...story/s40-validate-ssa-by-effect`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: aa171cb4183bcd7bd9a051527b7599335fa11976

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
Diff listed with `git diff --name-only main...story/s40-validate-ssa-by-effect`, each path held against `Owns: crates/nacre-validate/, docs/security/attacks/pades.md`.
- [x] Every path is inside `Owns`. The `crates/nacre-validate/` paths (source, example, tests, ten new corpus PDFs, README) and `docs/security/attacks/pades.md` are covered. The `docs/plans|research|verif|qa|reviews/s40-…` files are this story's own pipeline evidence.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s40-validate-ssa-by-effect` → exit 0. The record is reused (`Verification mode: record`): `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on this code and were not rerun here. Its "Not proven here" section was read and is carried into Not verified.
- [x] `po-gate qa-current s40-validate-ssa-by-effect` → exit 0 (Surface `endpoint`, `QA stage: surfaces`). The report's one verified finding is carried to Findings. Its `## Not seen` is carried into Not verified.

## Plan
- [x] Tasks 1 to 11 are all present. Fix-run tasks 7 to 11 match the five fix-loop-0 findings:
  - widgets drawn by the pages, plus `/OC` and listing in the certified snapshot;
  - the outside-`/Fields` case;
  - the moved `/Rect` case;
  - one shared `split_kids` (`own_widgets` and `FormNode.widgets` removed);
  - the plan text brought up to date.
  Nothing outside the plan.
- [x] Run interdicts, checked one by one:
  - `git diff --stat` is empty for `crates/nacre-pdf`, `crates/nacre-core`, `crates/nacre-pades`, the root `Cargo.toml`, `crates/nacre-validate/Cargo.toml` and `src/validate.rs`.
  - Corpus: only `README.md` changed (status `M`); the ten PDFs are all additions. Each added PDF's SHA-256 matches its README row.
  - `report.rs` and `lib.rs` changed in doc comments only. No new `Defect`, `RevisionVerdict` or `AllowedChange` variant.
  - No existing test assertion was removed and no `#[ignore]` was added (floor-guard 0). `sneaky_refused` only finds the certification by name now.
  - The DocMDP 1 refusal and the accept rules are unchanged, and `tests/validate.rs` passes.

## References
- [x] Opened and confirmed: `State::widgets`, `placed_signature_widgets`, `drawn_annotations` (`MAX_FIELD_DEPTH` bound and visited set), `split_kids`, `with_self`, `placement`, `added_here`, `refuse_signature`, `Judge::sneaky`, the `forced` set and its removal in `verdict`, and `resolve` / `array_at` / `dict_at`.
- [x] `validate.rs:84` reads `refused_signatures` with `contains`, so the de-duplication is safe.
- [x] Values: Hidden 2 and NoView 32 match ISO 32000. Corners are normalised and a zero area is `Off`. A NaN area stays visible. A `/Rect` that is present but unreadable is `Unknown` (see the finding on its test).

## Rules
- [x] `AGENTS.md` conventions are respected:
  - no indexing or unwrap outside tests;
  - every `/Parent` walk is bounded;
  - no clock and no network;
  - fictitious corpus with README rows and SHA-256 values;
  - one corpus case and one rejecting test per shape listed in `pades.md`.
- [x] No accepted ADR is contradicted.

## Tests
- [x] Floor: `po-gate floor-guard s40-validate-ssa-by-effect main` → exit 0, nothing lowered.
- [x] The assertions pin criteria 1 to 3:
  - nine `sneaky_refused` cases plus `ssa_outside_fields_is_rejected`;
  - one accepting test, `certified_visible_field_signed_is_allowed`;
  - the uncertified invisible second signer is covered by the existing `twice_signed_first_signature_has_an_allowed_signature_revision`.

  No test has any of the six empty shapes: each runs `validate()` on a forged file through the real entry point.
- [x] Ten new tests, within `Test budget: 25`.
- [x] Bite 1: certified snapshot ignores whether a page lists the widget (`revisions.rs:216`) → 1 failing test (`ssa_unlisted_widget_shown_is_rejected`) → undone, `git diff --exit-code` clean.
- [x] Bite 2: certified snapshot ignores `/OC` (`:218`) → 1 failing test (`ssa_layer_widget_shown_is_rejected`) → undone, clean.
- [x] Bite 3: exemption keyed on widget id only, rect equality dropped (`:404`) → 1 failing test (`ssa_moved_rect_is_rejected`) → undone, clean.
- [x] Bite 4: scan of `/FT /Sig` objects outside `/Fields` disabled (`:385`) → 1 failing test (`ssa_outside_fields_is_rejected`) → undone, clean.
- [x] Bite 5: page-listed `/Parent` widgets dropped from `State::widgets` (`:196`) → 1 failing test (`ssa_orphan_widget_is_rejected`) → undone, clean.
- [x] Bite 6: `Placement::Unknown` counted as not shown (`:403`) → 0 failing tests in the whole `nacre-validate` suite → undone, clean. See findings.
- [x] No test was made useless by the story.

## Neighbours
- [x] Callers read:
  - `signature_value`: its only caller is `signatures`, which now skips `forced` ids.
  - `refuse_signature`: called from `sneaky` and from the DocMDP 1 branch; duplicates are skipped.
  - `split_kids`: shared by `form_nodes` (behaviour unchanged, it iterates by reference) and `State::widgets`.
  - `new_signature_fields` / `items_ok`, used by `pages` and `catalog`: a forced field never enters `new_signature_fields`, so the page and `/Fields` changes it brings are refused.
  - `field_locks` and `form_fills`: unaffected.

## Lenses
Lenses run: security — content: the PDF signature-attack rule (`revisions.rs` `sneaky` pass, `drawn_annotations`, `docs/security/attacks/pades.md`). Dependencies did not run (no manifest or lockfile changed). Performance did not run (library, no server code).
- [x] Lens findings are graded below.

## Findings
- major — crates/nacre-validate/src/revisions.rs:403 — The fail-closed branch `Placement::Unknown => true` is untested: bite 6 made it `false` and the whole `nacre-validate` suite stayed green.
  This branch is what refuses a signature whose `/Rect` is present but unreadable: a five-element array, a non-numeric item, or an item whose reference does not resolve.
  Without it, such a new merged signature is accepted by `signatures()`. The certification would then read `Allowed([Signature])` and the signer would carry no defect. A viewer that tolerates the malformed `/Rect` would draw it over the certified page.
  The plan's test strategy says "each branch is reached by a corpus case", which is not true for this one.
  Fix: add a corpus case with an unreadable `/Rect` (for example, one item a reference to a missing object) and a `sneaky_refused` test.
- minor — crates/nacre-validate/tests/attacks.rs:288 — QA finding 1 (verified): on `ssa-outside-fields.pdf`, `validate` returns only `Certification`. The visible `Sneaky` signature is not reported at all, so it carries no `AddedByRevisionNotAllowed`, which falls short of criterion 1's wording for this shape.
  The document is still not read as sound, since the certification gets `RevisionNotAllowed`. The limit is stated in `pades.md` and pinned by the test. The shape is not one of criterion 2's enumerated shapes.
  An application listing signatures will still show one where the page shows two. Listing signature fields outside `/Fields` belongs to a later story, not to this one.

## Not verified
- I did not rerun the corpus forge in a scratch clone: po-bounds refused `git clone` in reviewer mode (`git clone is forbidden in mode reviewer, which runs reading verbs only`). I did not reach the same result another way.
  - What I checked instead: every added PDF's SHA-256 matches its README row, and the existing corpus files are unchanged in the diff.
  - Whether the forge still produces byte-identical output rests on the record's "Not proven here" statement.
  - A person should run `cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks` in a clean checkout and confirm `git status` stays clean.
- DSS and Acrobat parity of the new verdicts was not checked: the refused shapes, the honest prepared-field signing, and the stricter per-widget rule. This is left to s18 and s19; compare on DSS.
- Gaps the record lists, without corpus cases:
  - **Certified widget moved to another page at the same rectangle.** The by-effect rule does not see it; the certification refuses the page change, but the signer reads with no defect.
  - **Kid field outside `/Fields` that inherits `/FT /Sig` without carrying it.** It is not scanned. By reasoning, the certification still refuses the kid and the page, and the signature is not listed, which is the same outcome as `ssa-outside-fields`. Not probed.
  - **`/OC` in the certified state.** It is read as "not placed" whatever the layer configuration.
- The fuzz target `crates/nacre-validate/fuzz/` was not run; CI's `fuzz` job runs it.
- `cargo fmt` has no `po-run` row; formatting is checked at commit and in CI.
- From the QA report's `## Not seen`:
  - Criterion 4 (`pades.md`) has no effect observable through the library; I read it here against the code and found it consistent.
  - A visible SSA on a P=1 document was not walked: the corpus has only an invisible late signature under P=1, so the by-effect pass was seen at P=2 and P=3 only.
  - The SSA verdict on the signer of an invisible counter-case: same-length byte edits break that signer's digest, so only the certification's verdict could be read.
  - Whether a viewer (Acrobat, pdf.js) draws the orphan, unlisted, layer or outside-`/Fields` widgets: Nacre does not render, so open the corpus files in a viewer.
  - Files from real signers other than pyHanko (Acrobat and others): none in the corpus.
- The end-to-end suite and the production build were not run. The project has no `E2E` command (`—`), and `Build stage: ship-if-route` leaves the build to ship, since no route or manifest changed.

Max severity: major
Ship allowed: yes

---

# Review — s40-validate-ssa-by-effect

[Story](../stories.md) · [Plan](../plans/s40-validate-ssa-by-effect.md) · [Verification](../verif/s40-validate-ssa-by-effect.md)

Diff reviewed: `git diff main...story/s40-validate-ssa-by-effect`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 2
Reviewed tree: eed43efe2ab5a841708c3b0b622e26f51d7c5dac

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
Diff listed with `git diff --name-only main...story/s40-validate-ssa-by-effect`. Each path was held against `Owns: crates/nacre-validate/, docs/security/attacks/pades.md`.
- [x] Every path is inside `Owns`. That covers the source, the example, the tests, the 11 added PDFs and the corpus README under `crates/nacre-validate/`, plus `docs/security/attacks/pades.md`. The `docs/plans|research|verif|qa|reviews/s40-…` files are this story's own pipeline evidence.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s40-validate-ssa-by-effect` → exit 0, so the record is reused (`Verification mode: record`). `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` exited 0 on this code; neither was rerun here. The record's "Not proven here" section was read and is carried into Not verified.
- [x] `po-gate qa-current s40-validate-ssa-by-effect` → exit 0 (Surface `endpoint`, `QA stage: surfaces`). The walk covers fix run 2. The report's one verified finding is carried to Findings, and its `## Not seen` is carried into Not verified.

## Plan
- [x] Tasks 1 to 12 are all present.
  - Fix run 2 (task 12) adds the case `ssa-unreadable-rect.pdf` (commit `7aab2d6`), its forge helper and `ssa_unreadable_rect_is_rejected`.
  - It changes nothing under `src/`, as the plan says.
  - It answers the fix-loop-1 major finding (the `Placement::Unknown` branch had no test).
  - Nothing outside the plan.
- [x] Run interdicts, checked one by one:
  - `git diff --stat` is empty for `crates/nacre-pdf`, `crates/nacre-core`, `crates/nacre-pades`, the root `Cargo.toml`, `crates/nacre-validate/Cargo.toml` and `src/validate.rs`.
  - Corpus: only `README.md` changed, and all 11 PDFs are additions. Each added file's SHA-256 matches its README row.
  - I reran the forge into a temp dir (`cargo run -p nacre-validate --example forge_pades_attacks -- /tmp/…/corpus/attacks`). All 42 PDFs it writes are byte-identical to the committed corpus.
  - `report.rs` and `lib.rs` changed in doc comments only. No new `Defect`, `RevisionVerdict` or `AllowedChange` variant.
  - No existing test assertion was removed and no `#[ignore]` was added (floor-guard 0).
  - The DocMDP 1 refusal and the accept rules are unchanged, and `tests/validate.rs` passes (record).

## References
- [x] Opened and confirmed: `placement`, `Placement`, `Placed`, `State::widgets`, `placed_signature_widgets`, `drawn_annotations` (bounded by `MAX_FIELD_DEPTH`, with a visited set), `split_kids`, `with_self`, `Judge::sneaky`, `added_here`, `refuse_signature` (de-duplicated), the `forced` removal in `verdict`, and the forge helpers `merged_sig`, `register`, `seal`, `append` and `next_free` used by the new case.
- [x] Values:
  - Hidden 2 and NoView 32 match ISO 32000.
  - Corners are normalised, a zero area is `Off`, and a NaN area stays visible.
  - An unreadable `/Rect` is `Unknown`: shown, and equal to nothing.
  - The flag set leaves out ToggleNoView (256); see Findings.

## Rules
- [x] `AGENTS.md` conventions are respected:
  - no unwrap or indexing outside tests;
  - every walk is bounded;
  - no clock and no network;
  - the corpus is fictitious, with README rows and SHA-256 values;
  - one corpus case and one rejecting test per shape `pades.md` lists.
- [x] No accepted ADR is contradicted.

## Tests
- [x] Floor: `po-gate floor-guard s40-validate-ssa-by-effect main` → exit 0, nothing lowered.
- [x] The assertions pin criteria 1 to 3:
  - ten `sneaky_refused` cases;
  - `ssa_outside_fields_is_rejected`;
  - the accepting `certified_visible_field_signed_is_allowed`;
  - the existing `twice_signed_first_signature_has_an_allowed_signature_revision` for the uncertified second signer.

  Every test runs `validate()` on a forged file. None has any of the six empty shapes.
- [x] Eleven new tests, within `Test budget: 25`.
- [x] Bite 1: `Placement::Unknown => true` flipped to `false` (`revisions.rs:403`) → 1 failing test (`ssa_unreadable_rect_is_rejected`) → undone, `git diff --exit-code` clean. The fix-loop-1 gap is closed.
- [x] Bite 2: Hidden dropped from the off flags (`flags & (2 | 32)` → `flags & 32`, `revisions.rs:695`) → 1 failing test (`ssa_hidden_widget_shown_is_rejected`) → undone, `git diff --exit-code` clean.
- [x] No test was made useless by the story.

## Neighbours
- [x] No code under `src/` changed since fix loop 1. The callers of what the story changed were reread:
  - `signature_value`: its only caller is `signatures`, which skips `forced` ids.
  - `refuse_signature`: called from `sneaky` and from the DocMDP 1 branch; `validate.rs:84` uses `contains`.
  - `split_kids`: shared by `form_nodes` and `State::widgets`.
  - `new_signature_fields`, read by `pages` and `catalog`: a forced field never enters it.
  - `field_locks` and `form_fills`: unaffected.

## Lenses
Lenses run: security — content: the PDF signature-attack rule (`revisions.rs` `sneaky` pass and `placement`, `docs/security/attacks/pades.md`). Dependencies did not run (no manifest or lockfile changed). Performance did not run (library, no server code).
- [x] Lens findings are graded below.

## Findings
- major — crates/nacre-validate/src/revisions.rs:695 — `placement` reads NoView (32) as `Off` even when ToggleNoView (256) is also set.
  ISO 32000 defines ToggleNoView as inverting NoView on mouse hover and selection, so such a widget appears when the pointer passes over it.
  - Probe (temp copy of the tracked files, forge line 584 changed to `/F 292` = Print | NoView | ToggleNoView, `ssa-visible-signature` rebuilt): a new visible-rect merged signature with the overlay appearance, on the certified `/P 2` file.
  - Result: `Certification` and `Sneaky` both read `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`, with no defect. The certification's revision is accepted as a plain signature.
  - Impact: the SSA overlay that shows on hover reads sound today, and will read valid once s16 judges chains.
  - Not a regression: `visible()` on `main` has the same flag test. The story's notes name only Hidden and NoView, so the gap comes from the notes, not from the implementer.
  - Fix: treat `NoView` together with `ToggleNoView` as shown in the state after (fail closed). Add a corpus case and a `sneaky_refused` test, and a line in `pades.md`.
  - This is a security finding: under Law 7 it goes to the person, not to the issue tracker.
- minor — crates/nacre-validate/tests/attacks.rs:296 — QA finding 1 (verified), carried over: on `ssa-outside-fields.pdf`, `validate` returns only `Certification`.
  The visible `Sneaky` signature is not listed, so it never carries `AddedByRevisionNotAllowed`. The document is still refused (the certification gets `RevisionNotAllowed`). The limit is stated in `pades.md` and pinned by the test.
  The shape is not one of criterion 2's listed shapes. Listing signature fields outside `/Fields` belongs to a later story.

## Not verified
- The ToggleNoView probe proves Nacre's verdict only. Whether Acrobat or pdf.js draw the widget on hover was not checked: open the probe file in a viewer.
- DSS and Acrobat parity of the new verdicts was not checked: the refused shapes, the honest prepared-field signing, and the stricter per-widget rule. This is left to s18 and s19; compare on DSS.
- Gaps the record lists, without corpus cases:
  - **Certified widget moved to another page at the same rectangle.** The by-effect rule does not see it; the certification refuses the page change, but the signer reads with no defect.
  - **Kid field outside `/Fields` that inherits `/FT /Sig` without carrying it.** It is not judged.
  - **`/OC` in the certified state.** It is read as "not placed" whatever the layer state.
- The fuzz target `crates/nacre-validate/fuzz/` was not run; CI's `fuzz` job runs it.
- `cargo fmt` has no `po-run` row; formatting is checked at commit and in CI.
- From the QA report's `## Not seen`:
  - Criterion 4 (`pades.md`) has no effect observable through the library. I read it here against the code and found it consistent.
  - A visible SSA on a P=1 document was not walked: the corpus has only an invisible late signature under P=1, so the by-effect pass was seen at P=2 and P=3 only.
  - The SSA verdict on a counter-case's own signer: same-length byte edits break that signer's digest, so only the certification's verdict could be read.
  - Whether a viewer draws the orphan, unlisted, layer, outside-`/Fields` or unreadable-rect widgets: Nacre does not render.
  - Files from real signers other than pyHanko: none in the corpus.
- The end-to-end suite and the production build were not run. The project has no `E2E` command (`—`), and `Build stage: ship-if-route` leaves the build to ship, since no route or manifest changed.

Max severity: major
Ship allowed: yes

---

# Review — s40-validate-ssa-by-effect

[Story](../stories.md) · [Plan](../plans/s40-validate-ssa-by-effect.md) · [Verification](../verif/s40-validate-ssa-by-effect.md)

Diff reviewed: `git diff main...story/s40-validate-ssa-by-effect`, in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 3
Reviewed tree: 1092e4e99191dcd7d0e85d7da90405da422bc81c

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s40-validate-ssa-by-effect` and held each path against `Owns: crates/nacre-validate/, docs/security/attacks/pades.md`.
- [x] Every path is inside `Owns`:
  - under `crates/nacre-validate/`: the source, the example, the tests, the corpus README and the 12 added PDFs;
  - `docs/security/attacks/pades.md`.
  - The `docs/plans|research|verif|qa|reviews/s40-…` files are this story's own pipeline evidence.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s40-validate-ssa-by-effect` exited 0, so I reused the record (`Verification mode: record`).
  - `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` exited 0 on this code. I did not rerun them.
  - I read the record's "Not proven here" section and carried it into Not verified.
- [x] `po-gate qa-current s40-validate-ssa-by-effect` exited 0 (Surface `endpoint`, `QA stage: surfaces`).
  - The walk covers fix run 3 (commit `7a8574d`).
  - Its one verified finding is carried into Findings.
  - Its `## Not seen` items are carried into Not verified.

## Plan
- [x] Tasks 1 to 13 are present.
  - Fix run 3 (task 13) answers the major from fix loop 2: `placement(objects, widget, after)` reads NoView together with ToggleNoView as shown in the state after and as off in the certified state.
  - It adds `ssa-toggle-noview-shown.pdf`, its forge block, `ssa_toggle_noview_shown_is_rejected`, a README row and a `pades.md` row.
  - Nothing outside the plan.
- [x] Run interdicts, checked one by one:
  - `git diff --stat` is empty for `crates/nacre-pdf`, `crates/nacre-core`, `crates/nacre-pades`, the root `Cargo.toml`, `crates/nacre-validate/Cargo.toml` and `src/validate.rs`.
  - In the corpus, only `README.md` is modified; every PDF is an addition.
  - The new file's SHA-256 (`1cd548c5…173b904`) matches its README row.
  - No new `Defect`, `RevisionVerdict` or `AllowedChange` variant.
  - floor-guard exited 0. It printed an awk locale warning but listed no flag.

## References
- [x] Opened and confirmed:
  - `placement` and its two callers: `placed_signature_widgets` at `revisions.rs:223` (passes `false`) and `Judge::sneaky` at `:405` (passes `true`);
  - the constants `HIDDEN = 2`, `NO_VIEW = 32` and `TOGGLE_NO_VIEW = 256`;
  - the forge helpers `next_free`, `merged_sig`, `register`, `append` and `seal`, used by the new case.
- [x] Values: 2, 32 and 256 match ISO 32000-1 Table 165. Hidden stays off even with ToggleNoView (correct: ToggleNoView inverts NoView only), and `/F 260` (ToggleNoView without NoView) stays shown. QA walked `/F 36`, `/F 294` and `/F 260`.

## Rules
- [x] The `AGENTS.md` conventions hold:
  - no unwrap and no indexing;
  - no clock and no network;
  - the corpus is fictitious, with a README row and its SHA-256;
  - each attack row in `pades.md` has one corpus case and one rejecting test.
- [x] No accepted ADR is contradicted.

## Tests
- [x] Floor: `po-gate floor-guard s40-validate-ssa-by-effect main` exited 0; nothing was lowered.
- [x] None of the six kinds of empty test: every test runs `validate()` on a forged file.
- [x] Twelve new tests, within `Test budget: 25`.
- [x] Bite 1: I disabled the ToggleNoView reading in the state after (`if false && after && …`, `revisions.rs:700`) and ran `--test attacks --test validate`. 1 test failed (`ssa_toggle_noview_shown_is_rejected`). Undone; `git diff --exit-code` clean.
- [x] Bite 2: I made the certified snapshot read ToggleNoView as shown (`placement(…, true)` at `revisions.rs:223`) and ran the whole `nacre-validate` suite. 0 tests failed. Undone; `git diff --exit-code` clean. See Findings.
- [x] No test was made useless by the story.

## Neighbours
- [x] `placement` has only the two callers above. Its new `after` parameter changes nothing on the certified side compared with fix loop 2.
- [x] The other callers the earlier rounds checked are untouched by fix run 3: `signature_value`, `refuse_signature`, `split_kids`, `new_signature_fields`, `field_locks` and `form_fills`.

## Lenses
Lenses run: security, triggered by content: the PDF signature-attack rule (`revisions.rs` `placement` and the `sneaky` pass, `docs/security/attacks/pades.md`). The dependencies lens did not run, since no manifest or lockfile changed. The performance lens did not run, since this is a library with no server code.
- [x] Lens findings are graded below.

## Findings
- minor — crates/nacre-validate/src/revisions.rs:223 — No test covers the certified side of the ToggleNoView rule.
  - Bite 2 made the certified snapshot read a NoView + ToggleNoView widget as placed, and the whole suite stayed green.
  - `pades.md:61` and the plan's task 13 both say that, in the certified state, NoView with ToggleNoView counts as not placed. QA's `## Not seen` names the same gap.
  - The lenient alternative would only exempt a widget that already showed on hover at certification, so this is a stated choice left without a test, not an open attack.
  - Fix: add a corpus case where a NoView + ToggleNoView field certified at its rect is signed, and assert `AddedByRevisionNotAllowed`.
- minor — docs/security/attacks/pades.md:75 — The rule paragraph still defines *placé* as "ni Hidden ni NoView" and does not mention the ToggleNoView exception. Only the table row at `:61` states it.
  - The doc comment on `Placement::Off` (`revisions.rs:104`, "Hidden, NoView, …") has the same gap.
  - Criterion 4 asks for the rule to be described by its effect. Add the ToggleNoView nuance to that paragraph and to the comment.
- minor — docs/plans/s40-validate-ssa-by-effect.md:63 — Plan text is stale after fix run 3:
  - the run interdicts and "Files touched" say "eleven added files";
  - the test strategy and "Done when" say "Eleven new tests".
  - There are twelve of each. The verification record has the right count.
- minor — crates/nacre-validate/tests/attacks.rs:296 — QA finding 1 (verified), carried over: on `ssa-outside-fields.pdf`, `validate` returns only `Certification`.
  - The visible `Sneaky` is never listed, so it never carries `AddedByRevisionNotAllowed`.
  - The document is still refused: the certification gets `RevisionNotAllowed`. The limit is stated in `pades.md` and pinned by the test.
  - This shape is not one of criterion 2's listed shapes. Listing signature fields outside `/Fields` belongs to a later story.

## Not verified
- I did not rerun the corpus forge in this round. I only checked that the new file's SHA-256 matches its README row and that no existing corpus file changed in the diff.
  - Byte-identical output rests on the record ("only the new file appeared") and on the fix-loop-2 review, which reran the forge.
  - A person can confirm it by running `cargo run -p nacre-validate --example forge_pades_attacks -- <tmp dir>` and comparing the output with the committed corpus.
- Viewer behaviour was not checked: whether Acrobat or pdf.js draw the ToggleNoView widget on hover, and the orphan, unlisted, layer, outside-`/Fields` and unreadable-rect widgets. Nacre does not render; open the files in a viewer.
- Parity with DSS and Acrobat for the new verdicts was not checked. It is left to s18 and s19; compare on DSS.
- Gaps the record lists, with no corpus case:
  - a certified widget moved to another page at the same rectangle;
  - a kid field outside `/Fields` that inherits `/FT /Sig` without carrying it;
  - `/OC` in the certified state, read as "not placed" whatever the layer state.
- The fuzz target `crates/nacre-validate/fuzz/` was not run; CI's `fuzz` job runs it.
- `cargo fmt` has no `po-run` row; formatting is checked at commit and in CI.
- From the QA report's `## Not seen`:
  - Criterion 4 (`pades.md`) has no effect observable through the library. I read it against the code here; see the second finding.
  - The certified-state side of ToggleNoView was not walked: the corpus has no such file. It is the first finding.
  - A visible SSA on a P=1 document was not walked: the corpus has only an invisible late signature under P=1.
  - The SSA verdict on a counter-case's own signer could not be read: same-length byte edits break that signer's digest.
  - Files from real signers other than pyHanko: none in the corpus.
- The end-to-end suite and the production build were not run. The project has no `E2E` command (`—`), and `Build stage: ship-if-route` leaves the build to ship, since no route or manifest changed.

Max severity: minor
Ship allowed: yes
