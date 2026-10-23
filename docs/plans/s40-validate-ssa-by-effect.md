---
validated: yes
---
# Plan — s40-validate-ssa-by-effect

[Story](../stories.md) · [Research](../research/s40-validate-ssa-by-effect.md)

Branch `story/s40-validate-ssa-by-effect`. Read `docs/research/s40-validate-ssa-by-effect.md` first; this plan builds on it without repeating it.

## Story
On a certified PDF (DocMDP 1, 2 or 3), a signature whose field shows on the page an appearance that was not visible in the certified state gets `Defect::AddedByRevisionNotAllowed`, and the certification gets `Defect::RevisionNotAllowed`. The rule is one comparison of the field's appearance before and after, whatever its shape: merged or split widget, field added then signed later, field invisible when certified (zero `/Rect`, Hidden widget) made visible while signing, indirect `/Rect`, kid widget changed. Each shape has a corpus case and a rejecting test. A visible field present in the certified state and signed with no other change stays sound (`Allowed([Signature])`); so does an invisible second signer on an uncertified PDF. `docs/security/attacks/pades.md` states the rule by its effect and lists the shapes.

## The rule (settles the research's open questions)
- **Placement** of a widget: `Off` when `/F` has Hidden (2) or NoView (32), when `/Rect` is absent, or when its area is zero; `At([x1, y1, x2, y2])`, corners normalised (min x, min y, max x, max y), when `/Rect` resolves to four numbers of non-zero area; `Unknown` when `/Rect` is present but unreadable. `Unknown` counts as visible and matches nothing.
- **Widgets of a field**: the field itself when merged or without widget kid, its `/Kids` without `/T`, and every annotation a page's `/Annots` lists whose `/Parent` chain reaches the field (fix run, review finding 1).
- **Shown** (state after) = placement not `Off`; `/AP`, the page lists and `/OC` are not read. **Placed** (certified state) = placement `At(rect)`, listed in a live page's `/Annots`, with no `/OC`, whatever `/AP` holds: a prepared empty field gets its `/AP` only when signed (`SIGN_KEYS`, `revisions.rs:24`).
- **Refused**: once the document has a certified state, a signature this revision adds (its `/V` dictionary's `/ByteRange` ends at `after.end`) is refused as soon as one widget of its field is shown and that same widget, of that same field, was not placed at that same rect in the certified state. This is per widget, so stricter than criterion 1's "no appearance of the field": a second visible widget or a moved `/Rect` is also refused. It fails closed and `pades.md` says so.

## Décision du lead à l'exécution (repli de la décision 2)
Le repli prévu par le pivot s'applique : la règle reste fail-closed. `/AP` n'entre pas dans « shown » : une nouvelle signature au `/Rect` visible sans `/AP` sur un document certifié reste refusée comme SSA, comme en s15. Sont donc retirés : la fonction `appears`, le fichier `certified-new-field-no-appearance.pdf` et le test `certified_new_field_without_appearance_is_allowed`. « Shown » = placement autre que `Off`. Les tâches ci-dessous sont écrites après cette décision.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| `placement` | already in this repository for the `/Rect` and `/F` reading: `visible` (`crates/nacre-validate/src/revisions.rs:591-614`); `resolve`, `dict_at`, `array_at` (`:784-807`) reused | std and the installed crates do not read PDF |
| Widgets of a field | already in this repository: the kid partition of `form_nodes` (`:652-667`), factored into `split_kids` that `form_nodes` and `State::widgets` share; the page-listed `/Parent` widgets are new code | — |
| Certified snapshot | new code, on top of `State::form` (`:114`) | `signature_fields()` (`:168-174`) keeps ids only, with no placement |
| By-effect pass | new code; the "`/V` ends at this revision" test is taken out of `signature_value` (`:356-363`) and shared, not copied | the three shape checks (`:316-319`, `:341-345`, `:379-391`) are what the story replaces |
| Forge helpers for a prepared field and its later signing | new code (example only); reuses `register` (`forge_pades_attacks.rs:652`), `sig_placeholder` (`:673`), `overlay_appearance` (`:681`), `seal` (`:689`), `certify` (`:502`), `with_text_field` (`:437`) | `add_signature` and `sneaky_two_steps` (`:566`, `:623`) write fixed bodies; changing them would change the bytes of existing corpus files |

## Tasks
1. [x] **Placement, widgets** (`crates/nacre-validate/src/revisions.rs`). Replace `visible` (`:591-614`) with `fn placement(objects: &Objects, widget: &Dictionary) -> Placement` (private `enum Placement { Off, At([f64; 4]), Unknown }`, as in "The rule"). The widgets of a field: the kids without `/T`, and the field itself when it has `/Subtype /Widget` or no widget kid (fix run: computed by `State::widgets`, which adds the page-listed `/Parent` widgets, instead of a `FormNode.widgets` field). No behaviour changes yet. Test: none of its own; tasks 3 and 5 exercise every branch (zero rect, Hidden, indirect `/Rect`, kid).
2. [x] **Certified snapshot** (same file). `type Placed = HashMap<ObjectId, Vec<(ObjectId, [f64; 4])>>`, field id → its widgets placed `At(rect)`. `State::placed_signature_widgets(&self) -> Placed` over `form` nodes with `signature && !widget_only`, replacing `signature_fields` (`:168-174`). In `qualify` (`:61-69`) `certified_fields` becomes `certified: Option<Placed>`, set once from the first state with a DocMDP level, as today; `diff` and `Judge` take `Option<&Placed>`. Test: task 5's honest case `certified_visible_field_signed_is_allowed` fails if the snapshot drops the placement; the `ssa_zero_rect_shown` test fails if it keeps ids only.
3. [x] **One by-effect pass** (same file). `fn added_here(&self, field: &Dictionary) -> Option<ObjectId>`: the `/V` reference whose dictionary's `/ByteRange` ends at `after.end`, taken out of `signature_value` (`:356-363`), which now calls it. New `Judge::sneaky(&mut self)`, run first in `verdict` (`:264-273`): when `certified` is `Some`, for each `after.form` node with `signature && !widget_only` (sorted ids), the field's `added_here` value and its widgets; a widget is shown when its placement is not `Off`; exempt only when its placement is `At(rect)` and `certified[field]` holds `(widget, rect)`. One shown widget not exempt → push the `/V` into `refused_signatures` (skip if already there) and insert the field id, all its widget ids and the `/V` id into a new `forced: HashSet<ObjectId>`. After `subordinates`, `verdict` removes `forced` from `accepted`, so the revision is `NotAllowed` whatever the accept rules said. Delete `shows_on_certified_page` (`:379-391`) and the checks at `:316-319` and `:341-345`; both loops of `signatures` skip an id in `forced` instead of accepting it. The DocMDP 1 refusal (`:370-373`) stays. Update the doc comments `:33-37` and `:302-304`. Tests: `ssa_visible_signature_is_rejected`, `ssa_split_widget_is_rejected`, `ssa_empty_field_signed_is_rejected` (`tests/attacks.rs:225-238`) stay green; task 5's tests fail if the pass misses a shape.
4. [x] **Corpus** (`crates/nacre-validate/examples/forge_pades_attacks.rs`). New helpers only; existing ones keep their output. `fn prepared(base, objects) -> Vec<u8>`: `base` given extra objects plus `register(field, widget)` in one revision; `fn sign_prepared(pdf, signer, edits: &[(u32, Vec<u8>)], sig: u32) -> Vec<u8>`: one revision writing `sig_placeholder()` as `sig` and `edits`, then `seal`. Base of every case: `form = with_text_field(UNSIGNED)` (`register` needs its indirect AcroForm, `:655-666`). Overlays use `overlay_appearance()`, rect `[72 650 400 700]`. Files:
   - `attacks/ssa-zero-rect-shown.pdf`: merged empty field `Sneaky`, `/Rect [0 0 0 0] /F 4`, certified `/P 2`; signing sets `/V`, the rect, `/AP`.
   - `attacks/ssa-hidden-widget-shown.pdf`: merged `Sneaky`, rect set, `/F 6` (Hidden), `/AP` already there, certified **`/P 3`**; signing sets `/V` and `/F 4`.
   - `attacks/ssa-indirect-rect.pdf`: merged `Sneaky`, `/Rect r 0 R` with `r` = `[0 0 0 0]`, certified `/P 2`; signing sets `/V`, `/AP` and redefines `r` as the rect.
   - `attacks/ssa-kid-widget-shown.pdf`: field `/FT /Sig /T (Sneaky) /Kids [w]`, widget `w` with `/Parent`, `/Rect [0 0 0 0]`, certified `/P 2`; signing sets the field's `/V`, the widget's rect and `/AP`.
   - `certified-visible-field-signed.pdf` (in `tests/corpus/`): merged empty field `Approver`, rect set, `/F 4`, no `/AP`, certified `/P 2`; signing sets `/V`, `/AP`, `/F 132` (Locked), nothing else.
   Run `cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks`; `git status` must show only the five new files. Add their rows, each with its SHA-256 (`sha256sum`), to `tests/corpus/README.md`. Test: task 5.
5. [x] **Tests.** `tests/attacks.rs`: `ssa_zero_rect_shown_is_rejected`, `ssa_hidden_widget_shown_is_rejected`, `ssa_indirect_rect_is_rejected`, `ssa_kid_widget_shown_is_rejected`, each `sneaky_refused(include_bytes!(…))` (`:207-223`: certification `RevisionNotAllowed`, `Sneaky` `AddedByRevisionNotAllowed` at the file's end). `tests/validate.rs`: `certified_visible_field_signed_is_allowed`: `allowed(of(&r, "Certification"), &[&[AllowedChange::Signature]])` and `allowed(of(&r, "Approver"), &[])` — fails if the exemption is lost or keyed on existence only. The uncertified invisible second signer of criterion 3 is already `twice_signed_first_signature_has_an_allowed_signature_revision` (`tests/validate.rs:181-189`). Run `cargo test -p nacre-validate --test attacks --test validate`.
6. [x] **Docs.** `docs/security/attacks/pades.md`: four rows after `:50` (shape, file, test, `s40`, "idem"), the three SSA rows' story column `s15, s40`; rewrite the SSA sentences of `:64` as "The rule" above (shown / placed, per widget, `/AP` read only after, `Unknown` rect visible), name the seven shapes, and add to "Écarts connus" that a second visible widget or a moved `/Rect` is refused, stricter than criterion 1, and that a new visible-rect signature with no `/AP` is still refused as an SSA, as in s15. Doc comments `report.rs:85-88` and `lib.rs:14-15` speak of the effect, not of a "new" signature. Check: reread against the code; `cargo clippy` (doc links).

## Fix run (review `docs/reviews/s40-validate-ssa-by-effect.md`)
7. [x] **Widgets from what the pages draw** (major 1). `State` records the annotations the live pages list (`drawn`) and, per object, the listed annotations whose `/Parent` chain reaches it; a field's widgets add them. In the certified snapshot a widget counts as placed only when listed and without `/OC`. Corpus and tests: `ssa-orphan-widget.pdf`, `ssa-unlisted-widget-shown.pdf`, `ssa-layer-widget-shown.pdf` (`sneaky_refused`).
8. [x] **Signature outside `/Fields`** (major 2). The scan covers new and changed `/FT /Sig` objects outside `/Fields`. `ssa-outside-fields.pdf`, `ssa_outside_fields_is_rejected`: the certification's revision refuses the page, the field, its `/V` and its appearance.
9. [x] **Moved `/Rect`** (major 3). `ssa-moved-rect.pdf`, `ssa_moved_rect_is_rejected`: `Sneaky` gets `AddedByRevisionNotAllowed`.
10. [x] **`own_widgets` duplication** (minor). One `split_kids`, used by `form_nodes` and `State::widgets`; `own_widgets` and `FormNode.widgets` removed.
11. [x] **Stale plan text** (minor). This plan follows the no-`/AP` decision and the real test count.

## Fix run 2 (review fix loop 1)
12. [x] **Unreadable `/Rect`** (major). `ssa-unreadable-rect.pdf`: a new visible merged `Sneaky` on the file certified at `/P 2`, its `/Rect` `[72 650 400 n 0 R]` with `n` never defined; `ssa_unreadable_rect_is_rejected` (`sneaky_refused`) reaches `Placement::Unknown => true`. No code change. The outside-`/Fields` listing minor is left to a later story.

## Fix run 3 (review fix loop 2, granted by the person on 2026-10-23)
13. [x] **ToggleNoView** (major). `placement` reads NoView with ToggleNoView (256) as shown in the state after and as off in the certified state (both fail closed). `ssa-toggle-noview-shown.pdf`: a new visible merged `Sneaky` with `/F 292` on the file certified at `/P 2`; `ssa_toggle_noview_shown_is_rejected` (`sneaky_refused`); one row in `pades.md`.

## Scene viewpoints
—

## Run interdicts
- `git diff main...HEAD -- crates/nacre-pdf/ crates/nacre-core/ crates/nacre-pades/ Cargo.toml` is empty; so is `crates/nacre-validate/Cargo.toml` (no dependency).
- `git diff main...HEAD -- crates/nacre-validate/tests/corpus/` changes `README.md` only, besides the eleven added files: every existing corpus file stays byte-identical.
- `crates/nacre-validate/src/validate.rs` and `src/report.rs` keep their logic: no new `Defect`, `RevisionVerdict` or `AllowedChange` variant; `report.rs` changes in doc comments only.
- No existing test's assertion is edited or removed; no `#[ignore]` added.
- The DocMDP 1 rule (`revisions.rs:370-373`) and the accept rows of `form_fills`, `catalog`, `pages`, `subordinates` keep their behaviour: `tests/validate.rs` passes unchanged.
- Nothing outside `crates/nacre-validate/` and `docs/security/attacks/pades.md` changes, besides this story's `docs/` files.

## The pivot
The rule's two definitions: **placed** in the certified state reads `/Rect`, `/F`, the page lists and `/OC`, **shown** after reads `/Rect` and `/F` only (the lead's decision: no `/AP`), compared per widget at the same normalised rect. Ways it could be wrong:
- *Placed without `/AP` is too lenient*: a prepared visible field with no appearance can be signed with any overlay inside its rect. That is the signing DocMDP 2 and 3 permit on a prepared field (ISO 32000-2, Table 257). Check that `certified-visible-field-signed.pdf` is the only accepting path and that `ssa-zero-rect-shown` still fails.
- *Shown with `/AP` loosens s15*: dropped by the lead's decision; a new visible-rect signature with no `/AP` stays refused, as in s15.
- *Same-rect equality refuses an honest tool* that rewrites a prepared field's `/Rect` while signing (it fails closed, `RevisionNotAllowed` would hit it anyway since `/Rect` is not in `SIGN_KEYS`). Compare with DSS in s18/s19.

## Files touched
`crates/nacre-validate/src/revisions.rs`, `src/report.rs` (doc), `src/lib.rs` (doc), `examples/forge_pades_attacks.rs`, `tests/attacks.rs`, `tests/validate.rs`, `tests/corpus/README.md`, eleven new PDFs (ten in `tests/corpus/attacks/`, one in `tests/corpus/`), `docs/security/attacks/pades.md`.

## Test strategy
Validation layer only, through `validate()` on forged files, as every rule of this crate is tested (`tests/attacks.rs`, `tests/validate.rs`): four rejecting tests, one per new shape, and one accepting test that pins the exemption; the fix run adds five rejecting tests (orphan widget, unlisted widget, layer widget, moved `/Rect`, outside `/Fields`), the second fix run one (unreadable `/Rect`). The three existing SSA tests keep the merged, split and two-step shapes; `twice_signed_first_signature_has_an_allowed_signature_revision` keeps the uncertified second signer. Eleven new tests, budget 25. No unit test: `placement` has no caller but the pass, and each branch is reached by a corpus case. Per task, `cargo test -p nacre-validate --test attacks --test validate`. At the end, through `po-run`: the full suite `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`. No visual check.

## Done when
The eleven tests and the existing suite pass, clippy is clean, the interdicts hold, `pades.md` and the corpus README describe the rule and the new files. Then one commit on `story/s40-validate-ssa-by-effect`, a review with no open critical finding, and the landing through a pull request.
