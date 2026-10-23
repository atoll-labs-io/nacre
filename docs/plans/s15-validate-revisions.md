---
validated: yes
---
# Plan — s15-validate-revisions

[Story](../stories.md) · [Research](../research/s15-validate-revisions.md)

Branch `story/s15-validate-revisions`. Read `docs/research/s15-validate-revisions.md` first; this plan builds on it without repeating it.

**Owns.** Research fact 1 asked for `crates/nacre-pdf/` in the story's `Owns`; `main` at `eb3852b` lists it (`docs/stories.md:265`) and this lane is forked from that commit, so tasks 1-2 are inside the lane's bounds.

## Story
Each revision after a signature is listed in that signature's result and qualified: allowed (`/DSS`, document timestamp, new signature, form fill DocMDP permits) or not allowed with the objects it changes (criterion 1). Shadow hide, replace, hide-and-replace (2), EAA and SSA on certified PDFs (3) are detected, never `TOTAL_PASSED`. A B-LTA's `/DSS` and `/DocTimeStamp` revisions are not flagged (4) — proven on pyHanko's LTA file since s12 has not shipped (research, fact 2).

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| `Document::reachable` (graph walk, one resolver) | already in this repository: `Resolver::follow`/`object` with its object-stream cache (`crates/nacre-pdf/src/document.rs:189-212`, `:166`); only a public entry point is new | `Document::object` re-creates the resolver per call (`document.rs:112-120`); no std or dependency reads PDF objects |
| `Document::doc_mdp_level` | already in this repository: `Update::doc_mdp_level` and its `dictionary` helper (`crates/nacre-pdf/src/revision.rs:258-317`), moved, not rewritten | — |
| Revision qualification (`crates/nacre-validate/src/revisions.rs`) | new code | no existing diff of PDF states; `byte_range` and `follow_once` (`crates/nacre-validate/src/validate.rs:115-134`) are reused for the new-signature check |
| FieldMDP reader | new code | nothing reads `/TransformMethod /FieldMDP`; it follows the shape of the DocMDP reader |
| Raw incremental-revision writer in the forge | new code (example only) | `Update` cannot redefine an existing object or write an xref-only revision (research, Current code); `crates/nacre-pdf/tests/support/mod.rs` is a single-revision builder private to `nacre-pdf`'s tests |

## Tasks
1. [x] **`nacre-pdf`: reachable objects.** `pub fn reachable(&self) -> Result<HashMap<ObjectId, Object>, Error>` on `Document`: every indirect object reachable from the newest trailer's `/Root` (the trailer's `/Info` excluded), through references inside dictionaries, arrays and stream dictionaries, each read once through **one** `Resolver` and one budget (`max_total_decoded`). A reference whose lookup gives `ObjectNotFound` is a reference to `null` (ISO 32000-1 7.3.10): left out of the map, the walk goes on; any other error is returned. Iterative (explicit stack). A new `Limits` field `max_reachable: 1_000_000` bounds the map, beyond → `Error::Limit { what: "reachable objects", .. }`. Doc comment says the walk decodes object streams only. Test `reachable_objects_follow_references_once` in `crates/nacre-pdf/tests/corpus.rs`: on `word-pdfmaker-linearized.pdf` (object streams) the map holds the catalog, every page and no xref stream; on a support-built file whose page references a free object, the map omits it without error. Fails if the walk stops at compressed objects, errors on a free reference or reaches the xref stream.
2. [x] **`nacre-pdf`: DocMDP on `Document`.** Move `doc_mdp_level` and its `dictionary` helper from `Update` (`revision.rs:258-317`) to `pub fn doc_mdp_level(&self) -> Result<Option<i64>, Error>` on `Document`; `Update::sign` (`revision.rs:174`) calls it. Doc comment: `None` when not certified, `/P` absent means 2. Test: extend `no_change_certification_refuses_a_signature` (`crates/nacre-pdf/tests/revision.rs:261`) with `doc_mdp_level() == Some(1)`, and assert `Some(3)` on `certified-dss.pdf` in the same file. Fails if the move changes the reading.
3. [x] **Result types.** `crates/nacre-validate/src/report.rs`: `SignatureValidation` gains `pub later_revisions: Vec<LaterRevision>` (empty when the signed bytes end at no revision, step 9). `#[non_exhaustive] pub struct LaterRevision { pub end: usize, pub changed: Vec<ObjectId>, pub verdict: RevisionVerdict }` — `changed` is every reachable object, live or inert, that the revision changes or adds, sorted, whatever the verdict (criterion 1: "avec les objets qu'elle change"); `#[non_exhaustive] pub enum RevisionVerdict { Allowed(Vec<AllowedChange>), NotAllowed { refused: Vec<ObjectId> }, Unreadable }` (`refused` ⊆ `changed`, the objects no rule accepted; `Allowed(vec![])` = nothing visible changed); `#[non_exhaustive] pub enum AllowedChange { Dss, DocumentTimestamp, Signature, FormFill }`. `Defect::LaterRevision` becomes `Defect::RevisionNotAllowed { end: usize }` (first not-allowed or unreadable revision), `TOTAL_FAILED`/`FORMAT_FAILURE` like every structural defect. `crates/nacre-validate/src/error.rs`: `TooManyRevisions { count, max }`, kind `InvalidInput`, a row in `every_variant_has_its_kind`. Re-export the new types from `lib.rs`; `ObjectId` re-exported from `nacre_pdf`.
4. [x] **States and diff.** New `crates/nacre-validate/src/revisions.rs`, `pub(crate) fn qualify(pdf, doc, first: usize) -> Result<Vec<RevisionVerdict>, Error>` for every revision index after `first` (the oldest signed revision). More than 64 such revisions → `Error::TooManyRevisions` (same bound as `MAX_SIGNATURES`, `validate.rs:8-9`). Each state is `Document::parse(&pdf[..revision.end])` and its `reachable()` map, kept two at a time (previous, current); a state that fails to parse or walk makes that revision `Unreadable`. In each state, split the map: **inert** = objects reachable only through the catalog's `/DSS` or `/Metadata` entries; **live** = the rest, reached from the catalog skipping those two keys (a traversal over the map, no new lookup). Diff of revision k: `/Root` id changed → `NotAllowed { refused: [new root] }` at once; else every id of state k whose object differs from state k-1's (absent, or not live there, counts as **new**; inert and live ids both fill `changed`, only live ones go to the rules; streams equal when their dictionaries and raw bytes `pdf[data]` are equal). An empty diff is `Allowed`, with `Dss` when the inert `/DSS` part differs. Test: see task 8 (`shadow_*`), which exercise the three revisions that add no object.
5. [x] **Rules.** Same module. Context per revision k, from state k-1: DocMDP level (task 2) and FieldMDP locks — for each signature field with a `/V` in state k-1, its signature dictionary's `/Reference` entries with `/TransformMethod /FieldMDP` and `/TransformParams /Action /All|/Include|/Exclude /Fields [...]`, field full names compared as raw `/T` bytes joined by `.` (research, Open questions). Each **changed** live object must match one row, else it is listed in `NotAllowed { refused }` (ids sorted):

   | Object | Allowed difference | Kind |
   | --- | --- | --- |
   | catalog | keys `/DSS`, `/Metadata`, `/Extensions`, `/AcroForm` only; `/AcroForm` judged by the next row | `Dss` when `/DSS` differs |
   | AcroForm dict, or the array its `/Fields` names | `/Fields` keeps every old item, added items are new signature fields; `/SigFlags` | — |
   | page (`/Type /Page`), or the array its `/Annots` names | `/Annots` only, keeps every old item, added items are widgets of new signature fields | — |
   | existing signature field (own or inherited `/FT /Sig`) with no `/V` | gains `/V` (and `/AP`, `/AS`): a signature dictionary as in the next table | `Signature` or `DocumentTimestamp` |
   | existing non-signature terminal field or its widget | `/V`, `/AS`, `/AP` only; DocMDP 2 or 3 in force; the field's full name not locked | `FormFill` |

   Each **new** live object must have every referrer in state k among the changed or new objects accepted above, and be one of: a new signature field (merged widget, `/FT /Sig`) whose `/V` is a signature dictionary; that dictionary; an object reached only from the `/AP` of an accepted widget or the `/V` of an accepted field. A **signature dictionary** is accepted when its `/ByteRange` (`byte_range`, `validate.rs:122`) ends at revision k's `end`, and `/Type /DocTimeStamp` + `/SubFilter /ETSI.RFC3161` makes it `DocumentTimestamp`, otherwise `Signature`. Refused whatever the row: a `Signature` under DocMDP 1; a **new** signature widget that is visible (`/Rect` of non-zero area and neither `/F` bit 2 nor 6) when DocMDP is in force — the SSA. No row accepts an added annotation of any other subtype (EAA, including P=3; research, Open questions) nor a form fill without DocMDP (shadow replace through a field). Tests: tasks 7-8.
6. [x] **Wire into `validate`.** `validate.rs`: compute the verdicts once per call (`qualify` from the oldest revision a signature ends at), attach to each signature the verdicts of the revisions after its own (`later_revisions`, with each revision's `end`). Delete `covers_last_revision` and step 10; the revision rule becomes the **last** step, after the CMS verifies: a sound signature with a later revision `NotAllowed` or `Unreadable` → `Defect::RevisionNotAllowed { end }`, report `TOTAL_FAILED`/`FORMAT_FAILURE` like every structural defect, but `digest_verified` and `signature_verified` left `true` (both were checked): a dedicated arm in `defective`, or a constructor of its own. `SignatureValidation::sound`/`defective` take the list. Update `lib.rs` crate doc (no more "refused for now"). Test: `isa_appended_revision_is_rejected` (`tests/attacks.rs:111`) now expects `RevisionNotAllowed` and a `NotAllowed` whose `refused` is non-empty; the cap test reuses `validate_with` style with a 65-revision file built by repeated `Update::finish` — `too_many_revisions_are_refused` (unit, `validate.rs`).
7. [x] **Corpus.** `forge_pades_attacks.rs` gains a raw appender (objects as bytes, a classic xref table, trailer with `/Prev`, `/Root`, `/Size`, `startxref`, `%%EOF`) able to redefine an object, point an entry at an older offset, or change `/Root`, and a certifying signer (`Update::sign` with `/Reference` DocMDP `/P n` in `SignatureSpec::entries` and `/Perms /DocMDP` set on the catalog to the predicted signature id, CMS by `sign_detached`, as `range_forge` does). New files in `tests/corpus/attacks/`, each `unsigned.pdf` prepared by a revision, signed with `TestSigner::from_secret(&[0x11; 32])`, then one hand-written revision:

   | File | After the signature | Expected |
   | --- | --- | --- |
   | `shadow-hide.pdf` | xref-only revision pointing the overlay stream (drawn over the text before signing) at an empty body of the same id already in the signed bytes | `NotAllowed` listing it |
   | `shadow-replace.pdf` | the page's font dictionary redefined (`/BaseFont` changed) | `NotAllowed` |
   | `shadow-hide-and-replace.pdf` | trailer `/Root` switched to a shadow catalog and page tree written before signing | `NotAllowed` |
   | `shadow-late-definition.pdf` | defines an object the signed page already referenced while it was free | `NotAllowed` |
   | `shadow-form-field.pdf` | uncertified, a text field's `/V` and `/AP` changed | `NotAllowed` |
   | `eaa-freetext.pdf` | certified P=2, a `/FreeText` annotation appended to the page `/Annots` | `NotAllowed` |
   | `ssa-visible-signature.pdf` | certified P=2, a new signature field with a visible widget and `/AP`, its CMS valid | `NotAllowed` |

   Legitimate files in `tests/corpus/`: `certified-form-fill.pdf` (P=2, text field filled), `certified-p1-form-fill.pdf` (P=1, same fill), `fieldmdp-locked-fill.pdf` (approval signature locking the field, P=2, then filled); copies of `signed-lta-pyhanko.pdf` and `signed-twice-pyhanko.pdf` from `crates/nacre-pdf/tests/corpus/real/` with their MIT rows. README of `tests/corpus/` gets every file, its source and SHA-256; the forge stays deterministic (rerun it twice, `cmp`).
8. [x] **Tests.** `tests/attacks.rs`: one `<case>_is_rejected` per row of task 7's first table (7), each asserting `TOTAL_FAILED`/`FORMAT_FAILURE`, `Defect::RevisionNotAllowed`, and — for `shadow-hide` and `shadow-hide-and-replace` — the object ids in `refused`. `tests/validate.rs`: `twice_signed_first_signature_has_an_allowed_signature_revision` (nacre `sign` twice: `Allowed([Signature])`, no defect); `pyhanko_twice_signed_is_allowed` (metadata rewrite tolerated); `lta_dss_and_timestamp_are_allowed` — criterion 4: `Sig1` gets `[Allowed([Dss, DocumentTimestamp]), Allowed([Dss])]` with the catalog id in the first revision's `changed`, no defect; `signing_a_certified_p3_document_is_allowed` (`certified-dss.pdf` + nacre `sign`); `certified_form_fill_is_allowed` (`[FormFill]`); `form_fill_under_p1_is_not_allowed`; `locked_field_fill_is_not_allowed`. Each fails if its row of task 5 is removed or widened.
9. [x] **Attack sheet and docs.** `docs/security/attacks/pades.md` (French): check order list with step 10 removed and a last step "chaque révision postérieure est qualifiée"; ISA row → `Defect::RevisionNotAllowed`; the shadow, EAA, SSA rows filled with case, test, s15, result, plus rows for `shadow-late-definition` and `shadow-form-field`; the paragraph `:46` and the provisional-rule bullet `:53` replaced by the rule table of task 5 in short and the divergences of Open questions (P=3 annotations, uncertified fill, `TOTAL_FAILED` mapping). Check: every corpus file in a row, every row's test exists (`grep`).

## Scene viewpoints
—

## Run interdicts
- No file outside `crates/nacre-validate/`, `crates/nacre-pdf/src/`, `crates/nacre-pdf/tests/` and `docs/security/attacks/pades.md` changes (plus `docs/`); `git diff main...story/s15-validate-revisions --stat` shows nothing else.
- `nacre-pdf`'s existing public items keep their signatures; `Revision` gains no field; `Update` behaviour is unchanged (its tests pass untouched, task 2 only adds assertions).
- No new dependency in any `Cargo.toml`; no `[workspace.dependencies]`.
- No rendering, no content-stream parsing: the diff compares objects only (story notes).
- The integrity steps 1-9 and 11-12 of `check` keep their order and defects; s14's 13 other attack tests pass unchanged.
- Findings #75-#77 are not fixed here.
- No private key and no s02 PKI file enters the corpus; every signature uses `TestSigner::from_secret(&[0x11; 32])`.
- Nothing is written under `/tmp`.

## The pivot
**A revision is allowed only when every live object it changes or adds matches the rule table of task 5; everything else is `NotAllowed`.** It could be wrong in three ways:
- Too strict for real signers: an extra key rewritten by Acrobat or pyHanko (`/NeedAppearances`, `/DR`, `/Version`, a non-merged widget) fails a legitimate file. Compare with `signed-twice-pyhanko.pdf` and `signed-lta-pyhanko.pdf` (task 8); s19's foreign corpus is the wider check. Widening a row needs a named key and a test, never a catch-all.
- Too loose: an object reachable both through `/DSS` (inert) and a page counts as live only if the split of task 4 is computed by traversal from the catalog skipping `/DSS`/`/Metadata`; a split by "is under `/DSS`" would whitelist it. Bite: make a page reference a DSS stream and change it.
- Blind to xref-only revisions: a diff driven by the objects a revision writes would miss `shadow-hide`, `shadow-hide-and-replace` and `shadow-late-definition`; the diff compares whole reachable states (task 4).

## Files touched
`crates/nacre-pdf/src/{document.rs,limits.rs,revision.rs}`, `crates/nacre-pdf/tests/{corpus.rs,revision.rs}`; `crates/nacre-validate/src/{lib.rs,report.rs,error.rs,validate.rs,revisions.rs}`, `crates/nacre-validate/tests/{attacks.rs,validate.rs}`, `crates/nacre-validate/examples/forge_pades_attacks.rs`, `crates/nacre-validate/tests/corpus/` (README, 10 new files, 2 copies); `docs/security/attacks/pades.md`.

## Test strategy
Automated, 17 new tests within `Test budget: 25`:
- `nacre-pdf` (2): the reachable walk (task 1); DocMDP assertions folded into the existing test plus one on `certified-dss.pdf` (task 2).
- `nacre-validate` unit (1): `too_many_revisions_are_refused`; the `every_variant_has_its_kind` table gains a row (not a new test).
- `nacre-validate` attacks (7, plus `isa_appended_revision_is_rejected` updated): each corpus case reaches the revision rule because its CMS is valid.
- `nacre-validate` legitimate (7): each allowed row of task 5 and each refusal by DocMDP or FieldMDP.
Rules are tested once, through `validate` on corpus files: the rule table lives in one module and its only caller is `validate`; no per-row unit test duplicates them. `hostile.rs` and the fuzz target cover the new parsing paths unchanged.
Checks: tests of each task with `cargo test -p <crate> --test <stem>`; full suite and clippy once at the end through `po-run`; `cargo fmt --check`.

## Done when
All tasks ticked; `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` green through `po-run`; each acceptance criterion maps to a passing test (1: `later_revisions` asserted in task 8's tests; 2: three `shadow_*` tests; 3: `eaa_freetext`, `ssa_visible_signature`; 4: `lta_dss_and_timestamp_are_allowed`); the attack sheet has no "à écrire par s15" left; one commit on `story/s15-validate-revisions`; review with no open critical finding.

Validated by the planner under `Plan validation: autonomous` (2026-10-22), checked against each criterion: 1 → tasks 3-6 (`later_revisions`, `changed`, verdict); 2 → tasks 4, 7-8 (`shadow_*`); 3 → tasks 5, 7-8 (`eaa_freetext`, `ssa_visible_signature`); 4 → task 8 on pyHanko's LTA file, to be re-run by s12 on its own output (research, fact 2). No human reviewed this plan.
