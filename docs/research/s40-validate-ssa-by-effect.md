# Research — s40-validate-ssa-by-effect

[Story](../stories.md)

## Structuring facts
- No assumption of the story is false. The gap it names is real: the SSA exemption checks only that the field **existed** in the certified state (`crates/nacre-validate/src/revisions.rs:61-69`, `:341-345`), not that it was **visible** there. A certified invisible field made visible while signing leaves the attacker's signature with no defect (s15 review, `docs/reviews/s15-validate-revisions.md:227-232`, probed there).
- The current rule is shape by shape: one check for new merged widgets (`revisions.rs:306-319`, `/FT /Sig` read on the new object itself, `:310`), one for kid widgets (`:386-390`), one for existing empty fields (`:326-345`). No single place compares the field's appearance before and after.
- `visible()` (`revisions.rs:591-614`) reads `/Rect` (indirect arrays and numbers resolved, `:599`, `:604`) and the Hidden/NoView bits (`:596`), but not `/AP`, which the story's notes list as part of "visible".
- The certified snapshot is a `HashSet<ObjectId>` of field ids (`revisions.rs:63`, `:168-174`). To judge by effect it must hold, for each signature field, which widgets were visible and where.
- A prepared empty signature field usually has no `/AP` until it is signed, and signing writes it (`SIGN_KEYS`, `revisions.rs:24`). If "visible in the certified state" required an `/AP`, the honest certify-then-approve workflow would be refused (see Open questions, settled in the plan).

## Story
On a certified PDF (DocMDP 1, 2 or 3), a signature that shows a visible appearance on the page when no appearance of that field was visible in the certified state gets `Defect::AddedByRevisionNotAllowed`, and the certification gets `Defect::RevisionNotAllowed` (criterion 1). This holds for every shape: merged or split field and widget (`/Kids`), field added then signed later, field present but invisible when certified (`/Rect` of zero area, hidden widget) made visible while signing, indirect `/Rect`, kid widget changed. One corpus case and one rejecting test per shape (2). A field already visible in the certified state, signed with no other change, stays sound (`Allowed([Signature])`, no defect); so does a second invisible signer on an uncertified PDF (3). `docs/security/attacks/pades.md` states the rule by its effect and lists the shapes covered (4).

## Current code
- `qualify` (`revisions.rs:41-85`) walks the states from the oldest signed revision; it records `certified_fields` from the first state that has a DocMDP level (`:67-69`) and passes it to `diff` → `Judge`.
- `Judge::verdict` (`:264-288`) runs `signatures`, `form_fills`, `catalog`, `pages`, `subordinates`, then refuses every changed or new live object not in `accepted`.
- `Judge::signatures` (`:305-350`): new objects with `/FT /Sig` and a `/V` ending at this revision are refused as SSA when `shows_on_certified_page` (`:316-319`), else accepted when merged widgets (`:320-324`). Existing empty signature fields gaining `/V` are refused when not in `certified_fields` and visible (`:341-345`), else accepted when only `/V /AS /AP /F` differ and `/F` only gains Locked (`:346-348`, `locks_only` `:577-587`).
- `signature_value` (`:355-375`): the `/V` dictionary's `/ByteRange` must end at `after.end` (`:360-363`); DocTimeStamp → `DocumentTimestamp`; under `/P 1` the signature is refused (`:370-373`).
- `shows_on_certified_page` (`:379-391`) returns false when `before.doc_mdp` is `None` (`:380`), checks the field itself when it is a widget, and its `/Kids` widgets.
- `refuse_signature` (`:393-397`) pushes the field's `/V` id into `refused_signatures`; `validate.rs:83-96` turns that into `AddedByRevisionNotAllowed { end }` for the signature whose own revision it is. A signature refused this way is never accepted, so its field and widgets stay refused and the revision is `NotAllowed` → the earlier signatures get `RevisionNotAllowed` (`validate.rs:86-99`).
- `form_nodes` (`:617-697`): every terminal field and each widget kid (kids without `/T`, `:662-667`), `/FT` inherited (`:648-651`), `has_value` from the terminal's own `/V` (`:669`). A `FormNode` keeps no link from a field to its widgets (`:88-95`).
- `Stream.data` is a `Range<usize>` into the input (`crates/nacre-pdf/src/object.rs:95-98`): an empty appearance stream is `data.is_empty()`, no PDF bytes needed.
- nacre-pdf's own reading agrees: a signature field is a terminal node of type `/Sig`, its `/V` read on the terminal itself, not inherited (`crates/nacre-pdf/src/acroform.rs:153-169`). `Update::sign` writes an invisible merged widget, `/Rect [0 0 0 0] /F 132` (`crates/nacre-pdf/src/revision.rs:183-189`).

## Attachment points
- `revisions.rs:61-69` — the certified snapshot, to become per-field visible widget placements.
- `revisions.rs:264-273` — `Judge::verdict`, where one by-effect pass over the signatures this revision adds plugs in before the accept rules.
- `revisions.rs:305-350`, `:379-391` — the shape-specific checks the pass replaces.
- `revisions.rs:591-614` — `visible`, to split into placement (`/Rect`, `/F`) and appearance (`/AP`).
- `crates/nacre-validate/examples/forge_pades_attacks.rs:220-228` — where the SSA cases are written; helpers `add_signature` (`:566-594`), `sneaky_split` (`:598-619`), `sneaky_two_steps` (`:623-648`), `register` (`:652-670`), `with_text_field` (`:437-451`), `certify` (`:502-512`), `seal` (`:689-707`).
- `crates/nacre-validate/tests/attacks.rs:207-238` — `sneaky_refused` and the three SSA tests.
- `crates/nacre-validate/tests/validate.rs:41-49` (`allowed`), `:181-189`, `:218-228`.
- `docs/security/attacks/pades.md:48-50` (SSA rows), `:64` (the rule paragraph); `crates/nacre-validate/tests/corpus/README.md` (attack table and corpus table, SHA-256 per file).
- Doc comments that describe the SSA by shape: `revisions.rs:33-37`, `report.rs:85-88`, `lib.rs:14-15`.

## Verified interfaces
- `pub(crate) fn qualify(pdf: &[u8], doc: &Document<'_>, first: usize) -> Result<Vec<Qualified>, Error>` (`revisions.rs:41`).
- `pub(crate) struct Qualified { revision: LaterRevision, refused_signatures: Vec<ObjectId> }` (`revisions.rs:31-38`).
- `Defect::AddedByRevisionNotAllowed { end: usize }`, `Defect::RevisionNotAllowed { end: usize }` (`report.rs:84-88`); `RevisionVerdict::Allowed(Vec<AllowedChange>)`, `AllowedChange::Signature` (`report.rs:37-58`).
- `fn visible(objects: &Objects, widget: &Dictionary) -> bool` (`revisions.rs:591`); `resolve`, `dict_at`, `array_at` (`:784-807`) follow at most `MAX_HOPS = 32` references.
- `pub(crate) fn byte_range(doc: &Document<'_>, dict: &Dictionary) -> Option<[usize; 4]>` (`validate.rs:182`).
- Forge: `add_signature(pdf, signer, title, visible: bool, extra) -> Vec<u8>` (`forge_pades_attacks.rs:566`), `register(pdf, field, widget) -> [(u32, Vec<u8>); 2]` — panics unless the AcroForm is indirect with a direct `/Fields` and page 3 has a direct `/Annots` (`:655-666`); `unsigned.pdf` has no AcroForm, `with_text_field` gives one (AcroForm 6, field 7).

## Traps
- **Corpus bytes.** The forge rewrites every corpus file; output is deterministic (`README.md`, "deterministic"). Tests assert object numbers (`attacks.rs:159-197`). Any helper change that shifts numbering in an existing case changes its bytes and may break those asserts: new cases must use new helpers or leave existing output byte-identical.
- **Honest cases already pinned.** `twice_signed_first_signature_has_an_allowed_signature_revision` (`tests/validate.rs:181-189`) is the uncertified invisible second signer of criterion 3; `signing_a_certified_p3_document_is_allowed` (`:218-228`) signs `certified-dss.pdf` with an invisible new field; `pyhanko_twice_signed_is_allowed` (`:191-198`) signs a pre-existing visible field on an uncertified file. All must stay green.
- **DocMDP 1** already refuses every approval signature through `signature_value` (`revisions.rs:370-373`, test `signature_added_under_p1_is_refused_with_its_revision`, `tests/validate.rs:318-332`); a by-effect refusal of the same signature must not push its `/V` twice in a way that changes a result (`validate.rs:84` uses `contains`, so a duplicate is harmless).
- **Certified condition.** `shows_on_certified_page` keys on `before.doc_mdp` (`:380`): a revision that removes `/Perms` makes the next one look uncertified. The snapshot existing is the sturdier condition.
- **`/V` ending here.** Only a signature whose `/ByteRange` ends at `after.end` is "added by this revision" (`:360-363`); the refusal must use the same test so `validate.rs:83-85` attaches the defect to the right signature.
- **Refused ⊆ changed.** `revision_refused` asserts every refused object is in `changed` (`attacks.rs:51`).
- Full suite: `cargo test --workspace`; the fuzz target (`fuzz/fuzz_targets/validate.rs`) calls `validate` and needs no change. No migration, no dependency, `nacre-pdf` untouched.

## Open questions
- **Is `/AP` part of "visible" on both sides?** The notes say visibility reads `/Rect`, `/F` and a non-empty `/AP`. Applied to the certified state, a prepared visible field without `/AP` would read invisible, and signing it — which writes `/AP` — would be refused: the honest workflow of criterion 3. The plan decides (its pivot).
- **Per field or per widget?** Criterion 1 refuses when *no* appearance of the field was visible; the title speaks of making visible "an appearance absent at certification". A field visible at one place when certified that gains a second visible widget, or whose visible `/Rect` moves, falls between the two readings. The plan decides.
- **Shapes beyond the list**: a new kid field inheriting `/FT /Sig` from an existing parent is missed by the new-object loop today (`revisions.rs:310`); a pass over the form tree of the state after (`form_nodes`, `:648-651`) would find it. No corpus case is asked for it.
- **DSS parity** for these verdicts stays unchecked, as for s15 (`docs/reviews/s15-validate-revisions.md:243`); s18/s19 compare.

## Complexity
Story 3 → 3. One rule in one module, but its states (certified snapshot, per-widget placement and appearance, the five shapes) and six forged corpus files make it more than a CRUD change; nothing external, no contract change.

## Split
Not needed below 5.
