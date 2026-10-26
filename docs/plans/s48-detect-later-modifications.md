---
validated: yes
---
# Plan — s48-detect-later-modifications

[Story](../stories.md) · [Research](../research/s48-detect-later-modifications.md)

Branch `story/s48-detect-later-modifications`. Read `docs/research/s48-detect-later-modifications.md` first; this plan builds on it without repeating it.

## Story
Refuse, under `strict()` and `dss()`, the modifications after signing that DSS 6.5.1 refuses. The research found the cause: `dss()` turns off `refuse_later_revisions`, and Nacre has no counterpart of DSS's two `FAIL` format checks, "Do signed and final revisions contain equal amount of pages?" (`PdfPageDifference`) and "Is the signature dictionary consistent?" (`PdfSignatureDictionary`). Both checks become rules that both presets apply, with no switch (ADR-0026). `strict()` already refused both files.
- AC1: cause and DSS rule written (done in the research).
- AC2: the rule under both presets; the two DSS files and one bench case per shape get DSS's verdict.
- AC3: `pdf-signed-added-page` in `conformance/corpus/foreign/` with source and licence; `pades-spoofing-replaced-reason` carries a real person's name, is never committed, and a case forged on the bench replaces it; campaign at 0 differences under `dss()` and 0 unexplained under `strict()`.
- AC4: `docs/security/attacks/pades.md` describes each shape, with a corpus case and a rejecting test.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Signed-revision parse and root `/Pages` `/Count` read | already here: `Document::parse_with_options` (`nacre-pdf/src/document.rs:54`), `catalog` (`:123`), `object` (`:136`), the same prefix parse `State::read` does (`revisions.rs:149-150`) | — |
| Deep comparison of a field's `/V`, `/Rect`, `/AP`, `/F` between two revisions, with DSS's exclusions | new code, in a new `crates/nacre-validate/src/modifications.rs` | `same` (`revisions.rs:940`) compares one object by id, without following references and without DSS's exclusions; `Judge` (`revisions.rs:320-692`) qualifies object ids, not one field's subtree; std and the installed crates have no PDF object comparison |
| Two `Defect` variants and their report | already here: `Defect` (`report.rs:88-154`, `#[non_exhaustive]`), `defective` (`report.rs:210-259`) | — |
| Attack corpus cases | already here: `append`, `object`, `with`, `ser` of `examples/forge_pades_attacks.rs:322-450` | — |
| Bench case "page added" | already here: `Document::update` + `Update::set_catalog` (`revision.rs:122`), `forge::signed` (`tests/support/forge.rs:573`) | — |
| Bench case "reason replaced" | new helper `forge::redefine` in `tests/support/forge.rs`, writing one hand-made revision that redefines objects | `Update` can only add objects and rewrite the catalog (`revision.rs:98-131`); the example's `append` cannot be imported by a test |
| Local run on the uncommitted spoofing file | already here: the research's scratch crate `/home/lecrabe/.claude/jobs/4fb763d0/tmp/s48/repro/` (depends on this worktree by path, prints both presets) | — |

## Tasks
1. [x] **Defects.** Add `Defect::PageCountChanged { signed: i64, last: i64 }` (the root `/Pages` `/Count` of the signed revision and of the last one) and `Defect::SignatureDictionaryChanged` to `report.rs`, each mapped in `defective` to `TOTAL_FAILED` / `FORMAT_FAILURE`. Rustdoc: DSS's rule, applied under every policy, judged before the CMS verdict. Test: task 5's tests match on these variants.
2. [x] **The comparison** (`crates/nacre-validate/src/modifications.rs`, `mod modifications;` in `lib.rs`). `pub(crate) fn changed_since(last: &Document<'_>, pdf: &[u8], end: usize, field: &str, value: ObjectId, options: &ReadOptions) -> Option<Defect>`. Parse `pdf[..end]` with `options`; when that fails, or `end` is the end of `pdf`, return `None` (DSS's verdict on `byterange-not-whole-file.pdf` stays as is).
   - Pages: root `/Pages` `/Count` of each revision, as PDFBox reads it: `Integer` as is, `Real` truncated, anything else or absent as 0 (`PDPageTree.getCount`). Different → `PageCountChanged`.
   - Field: the field named `field` in the last revision, and the signed revision's field of the same full name (`signature_fields()`); none in the signed revision → `SignatureDictionaryChanged`. For each key among `V`, `Rect`, `AP`, `F` **present in the signed-revision field**, compare the signed value with the last one structurally: references resolved on each side, dictionaries key by key, arrays item by item, `Integer` equal to the same `Real`, streams by dictionary and raw bytes.
   - DSS's exclusions, nothing else: a difference whose key is `F`, `Type` or `ITXT` while both sides hold it; a key `AP` present before and absent after; anything under a `Data` key reached through a `Reference` key; anything below a second `Resources` inside `AP`. Any other difference → `SignatureDictionaryChanged`.
   - Bounds: iterative walk, depth ≤ 500 (DSS's), at most 4096 compared pairs; a pair already compared is not walked again. A bound reached counts as a change: never laxer than DSS. No `unwrap`, no indexing (crate lints).
   - Test: `dss_exclusions_and_nothing_else` (`#[cfg(test)]` in the module, objects built in memory): `/F` and `/Type` modified, `/AP` removed, and a catalog changed behind `/Reference [<< /Data … >>]` stay equal; `/F` removed, `/Rect` moved, an indirect `/Reason` redefined, and a change under a `Data` key reached without `Reference` each differ. No committed file has a certification `/Data` followed by a later revision (`certified-pyhanko.pdf` and Nacre's own certifications carry none), so this test alone guards that exclusion.
3. [x] **The hook** in `validate_with` (`validate.rs:246-307`). For every checked signature with `end: Some(e)`, call `changed_since(&doc, pdf, e, &field, value, &options)` before the `match` at `:277`. A `Some(defect)` comes first, ahead of the `Err` arm and both revision arms, as DSS runs its format checks before crypto and chain: the report and `defect` are the new defect's, `digest_verified` / `signature_verified` keep what integrity established (`true, true` after a verified CMS; the flags `defective` gives the `verify` error otherwise). `later_revisions` unchanged. Tests: tasks 5 and 6, plus the existing `certified_visible_field_signed_is_allowed`, `certified_form_fill_is_allowed` (`tests/validate.rs:242-258`), `signing_a_certified_p3_document_is_allowed` on `certified-pyhanko.pdf` and the pyHanko tests (`:203-240`), which fail if the rule flags a legitimate later revision under `strict()`.
4. [x] **Attack corpus.** In `examples/forge_pades_attacks.rs` `later_revisions` (`:125`), from the signed `base`, write with `append`: `isa-page-added` (a second page: new page object, `/Pages` redefined with `/Kids` of two and `/Count 2`); `isa-reason-replaced` (the signature dictionary redefined under its own id, `/Reason` changed, `/ByteRange` and `/Contents` byte-identical: the committed, fictitious case of `pades-spoofing-replaced-reason`'s shape); `isa-reason-redefined` (forged with an indirect `/Reason` object signed, then only that object redefined); `isa-signature-moved` (the signed field's `/Rect` changed, all else equal). Every string written is fictitious (no person's name). Regenerate with the command of `docs/security/attacks/pades.md:5`. Check: every existing file of `tests/corpus/attacks/` comes out byte-identical (`git status`).
5. [x] **Rejecting tests** in `tests/attacks.rs`, one per new file: `isa_page_added_is_rejected` (`PageCountChanged { signed: 1, last: 2 }`), `isa_reason_replaced_is_rejected`, `isa_reason_redefined_is_rejected`, `isa_signature_moved_is_rejected` (`SignatureDictionaryChanged`). Each asserts its defect under `validate` (`strict()`) and `TOTAL_FAILED` / `FORMAT_FAILURE` under `validate_with_policy(.., &ValidationPolicy::dss())`: the `dss()` assertion fails if the rule is deleted, which `strict()` alone would hide behind `RevisionNotAllowed`.
6. [x] **The DSS files.**
   - Commit `validation/pdf-signed-added-page.pdf` of esig/dss tag 6.5.1 (`dss-pades/src/test/resources/`) byte-identical as `conformance/corpus/foreign/public/pdf-signed-added-page.pdf` (SHA-256 `467573be2135cb83c17e450a1ea7992f087d79d4f18f5386509020901da7a2ec`, the s19 spike download `/home/lecrabe/.claude/jobs/4fb763d0/tmp/web/dss/validation__pdf-signed-added-page.pdf`; fetch from the tag or take that copy, and check the hash either way). Write `conformance/corpus/foreign/README.md` in the format of `crates/nacre-validate/tests/corpus/README.md`: `File | Source | Licence | SHA-256`, URL and path at the tag, LGPL-2.1, signer the fictitious Nowina `PKI-TEST` `good-user`, no personal data (research, Traps). One sentence below the table: DSS public files that carry a real person's name are read locally only, never committed; a forged case of the same shape stands in (here `pades-spoofing-replaced-reason.pdf`, by `isa-reason-replaced` and the bench case `m2-b-reason-replaced`).
   - Test: `dss_added_page_fails_under_both_presets` in `tests/validate.rs` (`include_bytes!` of the committed file): `PageCountChanged { signed: 1, last: 2 }` under `strict()`, `TOTAL_FAILED` / `FORMAT_FAILURE` under `dss()`.
   - `pades-spoofing-replaced-reason.pdf` (SHA-256 `14b7f31cda8b6966a162c3639d7cb1f092565b8ee95f84734455c3b595174ac2`) stays at `/home/lecrabe/.claude/jobs/4fb763d0/tmp/web/dss/validation__pades-spoofing-replaced-reason.pdf`: run `cargo run -q --manifest-path /home/lecrabe/.claude/jobs/4fb763d0/tmp/s48/repro/Cargo.toml --bin s48-repro -- <that path>` and expect `SignatureDictionaryChanged`, `TOTAL_FAILED` / `FormatFailure` under both presets (DSS's verdict in the spike). Quote the two verdict lines, and only them, in `docs/verif/s48-detect-later-modifications.md`. If that run cannot be made from the implementer's bounds, say so in the record: the QA stage runs it.
7. [x] **Bench cases** in `tests/campaign.rs`: a `modified` method called from `Bench::cases` (`:714-732`), from `forge::signed(&self.signer, Level::B)`: `m1-b-page-added` (`Document::update`, a new page and a new `/Pages` with `/Count 2`, `set_catalog(b"Pages", …)`) and `m2-b-reason-replaced` (new `forge::redefine(pdf, &[(ObjectId, Object)])` in `tests/support/forge.rs`, classic xref section, `/Prev`, same `/Root`, the signature dictionary redefined with another, fictitious `/Reason`). Doc comment names this story and says `m2` stands in for `pades-spoofing-replaced-reason`. Checked by the campaign (task 9).
8. [x] **Documentation.** `docs/security/attacks/pades.md`: a step between 9 and 10 of the ordered list ("signed revision and last revision: same root `/Count`, same signature field and dictionary, DSS's `PdfPageDifference` and `PdfSignatureDictionary`, under every policy"); one row per file of task 4, story s48, result its defect, "Ouverte sous" `aucune` (the policy contract tests `tests/policy.rs:446-489` read it); a line under "Hors de ce fichier" (`:83`) naming `pdf-signed-added-page.pdf` (committed in `conformance/corpus/foreign/public/`), `pades-spoofing-replaced-reason.pdf` (not committed, a real person's name; replaced by `isa-reason-replaced` and `m2`) and the visual comparison DSS only warns about. Rustdoc: `policy.rs:1-15` and the `dss()` doc list these rules as DSS's, under both presets; `lib.rs` crate doc likewise.
9. [x] **Checks.** Task tests as each task ends. Then `po-run --story s48-detect-later-modifications --label test -- 'cargo test --workspace'` and `po-run --story s48-detect-later-modifications --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`. Then the bench (`conformance/README.md:27-30`), `cargo test -p nacre-validate --all-features --test campaign -- --ignored` (not `run.sh`): 0 differences under `dss()`, 0 unexplained under `strict()`, the six new cases (four attack files, `m1`, `m2`) and `conformance-corpus-foreign-public-pdf-signed-added-page` `=` in `target/conformance/campaign-*.md`; their rows quoted in `docs/verif/s48-detect-later-modifications.md`. Stop the bench (`podman compose -f conformance/compose.yaml down`).

## Scene viewpoints
—

## Run interdicts
- No new field in `ValidationPolicy`, and `strict()` / `dss()` unchanged (`policy.rs:108-161`): the rule is DSS's, no switch (ADR-0026).
- `revisions.rs`: `qualify`, `Judge` and their verdicts unchanged; no `LaterRevision` of any existing test changes.
- Every existing file of `crates/nacre-validate/tests/corpus/attacks/` and `tests/corpus/*.pdf` ends with an empty diff.
- `pades-spoofing-replaced-reason.pdf` never enters the worktree, not even uncommitted (the campaign walks `conformance/corpus`, `campaign.rs:326-333`); no file of the diff carries a real person's name: `git diff --stat` lists one PDF under `conformance/`, and the four new attack PDFs hold only fictitious strings.
- `conformance/campaign/reports/` ends with an empty diff (outside `Owns`): do not run `conformance/campaign/run.sh`.
- Root `Cargo.toml` and every crate's `[dependencies]` unchanged; `Cargo.lock` not committed.
- s49's families (sub-indication order, extended levels, timestamps, algorithm mismatch, enveloping CMS, multiple fields) untouched; no other DSS public file added (`pdf-removed-pages.pdf` flags too, research Traps: s49 decides).
- Bench: only `conformance/compose.yaml`; never stop `patelle-dss`, never touch `omniroute`, no public TSA, no online DSS demo.
- No rendering, no visual comparison (DSS only warns on it).

## The pivot
Nacre's new rule must say exactly what DSS 6.5.1's two checks say, read from its bytecode (research, `## Diagnostic`). It can be wrong three ways:
- **Too strict**: a legitimate later revision (`/DSS`, document timestamp, new signature, certified fill) flips under `dss()`. Compare: the campaign's 0 differences, the forecast that no committed file flags, the `certified_*` and `certified-pyhanko` tests under `strict()`. The likely culprit is following `/Reference` → `/Data` (no committed file carries it since s50, so only `dss_exclusions_and_nothing_else` guards it) or comparing a key DSS skips.
- **Too lax**: a shape DSS refuses passes. Compare: `m1`, `m2` and the four attack files judged by DSS in the campaign, and the local run on the spoofing file. If DSS lets `isa-signature-moved` or `isa-reason-redefined` through, `dss()` follows DSS (the rule as DSS has it), `strict()` still refuses through `RevisionNotAllowed`, and the row in `pades.md` says which rule answers.
- **Order**: the new defect before a `verify` error, after the byte-range defects. Compare: DSS's FC block runs before CV and SAV; a modified file whose CMS is unsupported must not read `INDETERMINATE`.

## Files touched
- `crates/nacre-validate/src/modifications.rs` (new), `src/lib.rs`, `src/report.rs`, `src/validate.rs`, `src/policy.rs` (rustdoc only)
- `crates/nacre-validate/examples/forge_pades_attacks.rs`, `tests/corpus/attacks/isa-{page-added,reason-replaced,reason-redefined,signature-moved}.pdf` (new)
- `crates/nacre-validate/tests/attacks.rs`, `tests/validate.rs`, `tests/campaign.rs`, `tests/support/forge.rs`
- `conformance/corpus/foreign/README.md`, `conformance/corpus/foreign/public/pdf-signed-added-page.pdf` (new)
- `docs/security/attacks/pades.md`; `docs/research/`, `docs/plans/`, `docs/verif/s48-detect-later-modifications.md`

## Test strategy
Automated, 6 new tests (budget 25):
- Rule layer, `modifications.rs`: `dss_exclusions_and_nothing_else`, the only test that fails if one exclusion is widened or dropped while the corpus stays green.
- Validation, `tests/attacks.rs`: four rejecting tests, one per shape, each asserting under `dss()` (where only the new rule can refuse) and naming the defect under `strict()`. `isa_reason_replaced_is_rejected` is the committed guard for the spoofing shape.
- Validation, `tests/validate.rs`: `dss_added_page_fails_under_both_presets` on the committed DSS file.
- Existing guards that now cover the rule: the policy contract tests (new rows `aucune`), the `certified_*`, `certified-pyhanko` and pyHanko tests of `tests/validate.rs` (legitimate later revisions stay sound under `strict()`), `hostile.rs` and the fuzz target (no panic).
- Local, not committed: the scratch run on `pades-spoofing-replaced-reason.pdf`, verdicts in the record.
- Conformance (ignored, bench): the campaign with `m1`, `m2`, the four attack files and the public added-page file, against DSS.
No visual check: no screen.

## Done when
One commit `s48-detect-later-modifications: …` landed through a pull request; `cargo test --workspace` and clippy green through `po-run`; the campaign at 0 differences under `dss()` and 0 unexplained under `strict()` on a started bench, recorded in `docs/verif/`; the spoofing file's local verdicts recorded; QA of the `endpoint` surface passed; a review with no open critical finding.
