# Research — s48-detect-later-modifications

[Story](../stories.md)

## Structuring facts
- **Root cause.** Under `dss()`, `refuse_later_revisions: false` (`crates/nacre-validate/src/policy.rs:146`) drops the only rule that refuses these files: the revision verdict is computed (`NotAllowed`) but ignored (`crates/nacre-validate/src/validate.rs:272-276`), so the sound signature reaches the chain and ends `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`. DSS 6.5.1 refuses them with two narrower format checks its default policy sets to `FAIL` (`PdfSignatureDictionary`, `PdfPageDifference`, `policy/constraint.xml:60-61` of `dss-policy-jaxb-6.5.1.jar`), which Nacre lacks: ADR-0026 puts a DSS rule under both presets, and these two were never brought in. Proof in `## Diagnostic`.
- **Story assumption false: Nacre returns `INDETERMINATE` on both files** (AC1, read as under both presets in the story's first version). Under `strict()` both files already give `TOTAL_FAILED / FORMAT_FAILURE` (`Defect::RevisionNotAllowed`), identical to DSS (reproduction below; spike table `campaign-strict.md:41,61` shows `=`). Only `dss()` is laxer. The story's notes were corrected on 2026-10-25; AC1's `INDETERMINATE` holds for `dss()` only.
- **Story assumption false: "aucun interrupteur de `strict()` n'explique l'écart".** `refuse_later_revisions` alone explains it; the defect is that `dss()` keeps no DSS rule behind that switch. `strict()` is not laxer than DSS here. The notes (`docs/stories.md:845`) now say so, but still open with that stale clause before the colon: to delete at the next stories edit.
- **No rendering needed, no ADR.** DSS's visual comparison is `PdfVisualDifference Level="WARN"` (`constraint.xml:63`): it never fails a signature. The two failing rules are structural (page `/Count`, field and signature dictionary compared between the signed and the final revision). ADR-0026 already decides where they go (both presets, no switch); the reserved ADR-0032 is not used.
- The story has no `Fixes` line although it fixes a defect; it was researched under the `diagnostic` skill on the lead's instruction.

## Diagnostic
**Reproduction** (rerun 2026-10-26 on `b8c2079`, same output; scratch crate outside the worktree depending on `nacre-validate` by path, `validate_with_policy`, no anchor, both presets):

| File (esig/dss 6.5.1, `dss-pades/src/test/resources/validation/`) | Revisions (ends) | `strict()` | `dss()` |
| --- | --- | --- | --- |
| `pdf-signed-added-page.pdf` (SHA-256 `467573be…a2ec`) | 18336, 151126 (signed), 152031 | `TOTAL_FAILED / FORMAT_FAILURE`, `RevisionNotAllowed { end: 152031 }`, objects 1, 3, 71-75 refused | `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`, `defect: None`, same revision listed `NotAllowed` |
| `pades-spoofing-replaced-reason.pdf` (`14b7f31c…4ac2`) | 136911, 156916 (signed), 177114 | `TOTAL_FAILED / FORMAT_FAILURE`, `RevisionNotAllowed { end: 177114 }`, objects 39, 42, 45-48 refused | `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`, `defect: None` |
| `pdf-signed-original.pdf` (control, no later revision) | 18336, 151126 | `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND` | same |

DSS reports (spike, `campaign-conformance-corpus-foreign-public-*.json`): `FC` constraint "Do signed and final revisions contain equal amount of pages?" `NOT OK` (`PageDifference: [Page 2]`) for the added page; "Is the signature dictionary consistent?" `NOT OK` (`PDFSignatureDictionary.consistent: false`, `Reason` `DSS testing` → `EVIL` on the same object 42) for the spoofing. Both end `TOTAL_FAILED / FORMAT_FAILURE / PAdES BaselineB`, ahead of the chain and crypto checks.

**Hypotheses**
1. *Nacre does not see the appended revision.* Refutes it: `later_revisions` lists it. **Discarded**: the revision is listed under both presets.
2. *Nacre's qualifier accepts the changes.* Refutes it: verdict `Allowed`. **Discarded**: `NotAllowed` under both presets.
3. *`dss()` switches off the revision refusal and no DSS rule stands in for it.* Refutes it: a `dss()` verdict with a defect, or DSS failing on a check Nacre already has. **Kept**: `defect: None` under `dss()`; the two DSS checks above have no counterpart in `validate.rs` or `revisions.rs` (no read of `/Count`, no comparison of a signed field with its signed-revision state).

**DSS 6.5.1's two rules, read in its bytecode** (`javap -c` of `dss-pades-6.5.1.jar`, `pdfbox-3.0.8.jar` from the bench image `localhost/nacre-dss:6.5.1`):
- *Pages*: `DefaultPdfDifferencesFinder.getPagesDifferences(signed, final)` lists every page number between the smaller and the larger page count; any entry fails the check. The count is `PDDocument.getNumberOfPages()` → `PDPageTree.getCount()` → `root.getInt(/Count, 0)`: the `/Count` of the root `/Pages`, 0 when absent; no walk of the tree. Computed per signature whose bytes do not end the file (`AbstractPDFSignatureService.analyzePdfModifications`), signed revision = bytes `[0, c+d)`.
- *Signature dictionary*: `AbstractPDFSignatureService.verifyPdfSignatureFields` loads the signed revision and calls `PdfSigDictWrapper.checkConsistency`: for each field of the final revision whose `/V` names this dictionary, the signed-revision field of the same name must exist; then for each key of **the signed-revision field** among `V` (first field only), `Rect`, `AP`, `F`, the signed and final values are compared deeply (`DefaultPdfObjectModificationsFinder.find`, references followed, depth 500, `1` = `1.0`). The field is inconsistent when an *undefined* change remains after `PdfObjectModificationsFilter` and `removeTraversalData`. On these chains (no `/Annots` key) that leaves every change except: a modification whose last key is `F`, `Type` or `ITXT`; a deletion whose last key is `AP`; any chain through `Reference` then `Data` (the DocMDP reference to the catalog); `AP` chains holding more than one `Resources`. A key present only in the final field is never examined. A signed revision that yields no dictionary is inconsistent.

## Story
Refuse under `strict()` and `dss()` the later modifications DSS refuses (page added, signature reason replaced). AC1 cause and DSS rule written (above). AC2 the rule under both presets; the two files and one bench case per shape give DSS's verdict. AC3 `pdf-signed-added-page` in `conformance/corpus/foreign/` with source and licence; `pades-spoofing-replaced-reason`, which carries a real person's name, is not committed and a case forged on the bench replaces it; campaign 0 difference under `dss()`, 0 unexplained under `strict()`. AC4 `docs/security/attacks/pades.md` describes each shape with a corpus case and a rejecting test. Complexity 3, depends on s18 and s50 (shipped), `Surface: endpoint` (goes to QA), Owns `crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/pades.md`, `conformance/corpus/foreign/`.

## Current code
- `validate_with` (`validate.rs:164-308`): lists fields, `check` each (`:207-216`, `check` at `:607-629`: `signed_bytes` then `verify`), qualifies the revisions after the oldest signed one (`:238-242`, `revisions::qualify`), then per signature: `Err` from `check` first (`:278`), `AddedByRevisionNotAllowed` (`:279-283`), `RevisionNotAllowed` only under `refuse_later_revisions` (`:272-276`, `:284-286`), else `Context::judge` (chain, revocation, claimed time). `end` is `Some` once the byte range is structurally sound (`:620-626`), even when `verify` then fails.
- `revisions.rs` (1019 lines): `State::read` (`:149-192`) parses the prefix up to a revision end and its reachable objects; `diff`/`Judge` qualify a revision object by object; `same` (`:940-951`) compares two objects, streams by dictionary and raw bytes; helpers `resolve` (`:968`), `dict_at` (`:979`), `references` (`:994`).
- `report.rs`: `Defect` (`:88-154`, `#[non_exhaustive]`); `defective` (`:210-259`) maps `RevisionNotAllowed`/`AddedByRevisionNotAllowed` to `FORMAT_FAILURE` with both verified flags `true` (`:222-224`); a `verify` error keeps its own flags (`:218-221`, `cms_outcome` `:265-293`).
- `policy.rs:1-15` rustdoc lists the DSS rules both presets apply; `lib.rs:1-77` crate doc lists the checks.
- `nacre-pdf`: `Document::parse_with_options` (`document.rs:54`), `catalog` (`:123`), `signature_fields` (`:131`, name, id, value), `object` (`:136`), `update` (`:249`) → `Update::add`/`set_catalog`/`finish` (`revision.rs:98-131`); no way to redefine an existing object.

## Attachment points
- New pure function in `nacre-validate` comparing one signature's signed revision with the final one; called in `validate_with` per checked signature with `end: Some(e)`, `e` before the end of `pdf`, and inserted in the `match` at `validate.rs:277` **before** the `Err` arm and the revision arms (DSS runs its format checks before crypto and chain).
- Two `Defect` variants in `report.rs`, mapped in `defective`.
- Attack corpus: `examples/forge_pades_attacks.rs` (`later_revisions` `:125`, raw `append` `:409`, `object` `:322`, `with` `:329`, `ser` `:336`) writes `tests/corpus/attacks/`; tests in `tests/attacks.rs` (helpers `rejected` `:20`, `refused_by_revision` `:40`).
- Bench cases: `Bench::cases` (`tests/campaign.rs:714-732`), one method per spike group; `forge::signed` (`tests/support/forge.rs:573`).
- Committed corpus walk: `campaign.rs:326-333` already includes `conformance/corpus` (files named `conformance-corpus-foreign-public-<file>`).

## Verified interfaces
- `pub fn validate_with_policy(pdf: &[u8], anchors: &TrustAnchors, at: SystemTime, source: Option<&dyn RevocationSource>, policy: &ValidationPolicy) -> Result<Vec<SignatureValidation>, Error>` (`validate.rs:154`).
- `pub(crate) fn byte_range(doc: &Document<'_>, dict: &Dictionary) -> Option<[usize; 4]>` (`validate.rs:781`).
- `SignatureField { name: String, id: ObjectId, value: Option<ObjectId>, value_unreadable: bool }` (`nacre-pdf/src/acroform.rs:10-19`).
- `Object` variants `Null, Bool, Integer(i64), Real(f64), String, Name, Array, Dictionary, Reference(ObjectId), Stream` (`nacre-pdf/src/object.rs:25-35`); `Dictionary::get`, `iter` (`:73`, `:80`).
- Policy contract tests read `docs/security/attacks/*.md` rows for every file of `tests/corpus/attacks/` (`tests/policy.rs:335-366`, `:446-489`): a new attack file without its row fails them; the verdict compared is field, indication, sub-indication (`:405-440`).

## Traps
- **Forecast on every committed PDF** (shallow probe: root `/Count` and `/V` object of signed vs final revision): of the committed files and s48's two DSS files, only the two DSS files flag; every other committed file with a revision after a signature (the shadow, ISA, EAA and SSA attack files, the legitimate later-revision files (`certified-*`, `fieldmdp-locked-fill`, `fill-and-second-signature`, pyHanko twice and LTA, `chain-dss*`)) is unchanged. Rerun 2026-10-26 on `b8c2079` (after s50), 81 committed PDFs: no committed file flags; `certified-pyhanko.pdf` (`crates/nacre-validate/tests/corpus/`, which replaced `certified-dss.pdf`) has no revision after its signature. A faithful deep comparison must keep it so: the campaign agrees with DSS on all of them today. Outside s48's two files, the spike download `pdf-removed-pages.pdf` (3 → 1 pages) also flags: s49's list decides whether it enters the corpus.
- **`/Reference` → `/Data` → catalog**: a certification dictionary written by DSS reaches the catalog, which every later revision rewrites. Following it flags every such certified document; DSS removes these chains. Since s50 no committed file carries one: `certified-pyhanko.pdf`'s DocMDP `/Reference` has no `/Data` (byte scan), Nacre's own certifications neither.
- Signed revision unreadable (e.g. `byterange-not-whole-file.pdf`, whose prefix does not parse; `dss()` lets it through `signed_bytes`): the rule must stay silent, as the campaign agrees with DSS on it today.
- `cargo test --workspace` runs `tests/policy.rs` contract tests, `tests/attacks.rs`, `tests/validate.rs:203-258` (pyHanko twice and LTA, `signing_a_certified_p3_document_is_allowed` on `certified-pyhanko.pdf`, `certified_*`: sound under `strict()`, which now applies the rule too), `hostile.rs`.
- Regenerating the attack corpus rewrites every file; output is deterministic, so existing files must come out byte-identical.
- The campaign (`--ignored`, bench up) takes minutes; `conformance/campaign/run.sh:16-30` overwrites `conformance/campaign/reports/`, outside `Owns` (s18's). Run the cargo test directly.
- Bench keys change at each start: bench cases are forged at run time, never committed.
- **Corpus data** (rechecked 2026-10-26 on the spike copies): `pades-spoofing-replaced-reason.pdf` carries a real person's name in its `/Author` (`/Info`), so it is never committed (story AC3, decisions log 2026-10-25 and 2026-10-26): the forged cases of the plan stand in for it, and the file is only read locally, outside the worktree. `pdf-signed-added-page.pdf` carries no real name: `/Info` and XMP hold only `Dokument`, `ALIS-PDF 1.05`, `GPL Ghostscript 9.16`; its rendered page shows `Test PDF/A`, `My signature` and an empty letterhead footer whose only value is a Czech organisation number (IČO), no natural person; signature `/Name` `good-user …`; CMS certificates `good-user`, `good-ca`, `root-ca` of the fictitious Nowina `PKI-TEST`. It may be committed with its source and licence (LGPL-2.1).
- No migration, no new dependency, no new parser: the comparison reads objects `nacre-pdf` already parses (fuzz target `crates/nacre-validate/fuzz/` covers `validate`).

## Open questions
1. DSS compares stream binaries after decoding or raw? Raw comparison (Nacre's `same`) can only be stricter. Not settled from the bytecode read; no campaign case depends on it.
2. Should `conformance/campaign/reports/` be refreshed with the two new public files and bench cases? Outside `Owns`; the plan leaves them untouched and reports the run in the verification record.
3. DSS's exact `removeTraversalData` rule for `AP` chains (more than one `Resources`) was read only partly; the plan mirrors it as "stop below a second `/Resources` under `/AP`".

## Complexity
Story 3 → **3**. One comparison function (~150 lines), two `Defect` variants, a hook in `validate_with`, four attack cases, two bench cases, two committed files and documentation. No ADR, no new dependency. Below 5: no split.
