# Research — s15-validate-revisions

[Story](../stories.md)

## Structuring facts
1. **False assumption — the `Owns` line is too narrow.** The story owns only `crates/nacre-validate/` and the attack sheet, but `nacre-pdf` exposes no way to read a PDF's objects as a graph at an affordable cost: `Document::object` builds a fresh `Resolver` with a full 256 MB budget and an empty object-stream cache on every call (`crates/nacre-pdf/src/document.rs:112-120`, cache `:166`, decode `:290`), so walking N compressed objects decodes their container N times — a hostile 50 MB file turns that into tens of GB of inflating, against the brief's bounded-time rule. The fix belongs in `nacre-pdf` (one shared-resolver walk), and `po-bounds` refuses any write outside `Owns` read at the fork point (`.polype/hooks/po-bounds.sh:155-198`). **The story must be corrected to own `crates/nacre-pdf/` and the lane re-forked**, as s38 was (`docs/decisions-log.md`, s38 row).
2. **False assumption — no B-LTA from s12 exists.** s12 is not shipped (`ls crates/`: no B-LT/B-LTA code; `crates/nacre-pades/src/lib.rs:19` exports `sign` only). Criterion 4 can be proven on pyHanko's `signed-lta-pyhanko.pdf` (`crates/nacre-pdf/tests/corpus/README.md`, row `signed-lta-pyhanko.pdf`), whose revisions after the signature are exactly "`/DSS` + document timestamp" then "`/DSS` again" (read below); s12 must re-run that test on its own output.
3. The provisional rule is one branch: `covers_last_revision` (`crates/nacre-validate/src/validate.rs:93-94`, `:110-112`) returning `Defect::LaterRevision` (`crates/nacre-validate/src/report.rs:41-42`); one test bites on it (`crates/nacre-validate/tests/attacks.rs:111-114`).
4. A legitimate later revision rewrites more than the story lists: pyHanko's second signature also rewrites the catalog's XMP `/Metadata` stream (object 2) and the `/Info` dictionary (object 8) of `signed-twice-pyhanko.pdf` (xref stream `/Index [2 1 8 1 21 1 26 8]`, offset 26384+), and its LTA file adds `/Extensions /ESIC` to the catalog. A whitelist without `/Metadata` and `/Extensions` fails a legitimate file.
5. A diff by object id must also catch revisions that add no object: an xref entry redirected to an older body in the signed bytes, a `/Root` swapped to a shadow catalog already in the signed bytes, an object defined late that an unchanged object already referenced.

## Story
Each revision after a signature is listed in that signature's result and qualified: allowed (`/DSS`, document timestamp, new signature, form fill permitted by DocMDP) or not allowed, with the objects it changes. Shadow hide, replace, hide-and-replace are detected (never `TOTAL_PASSED`); EAA and SSA on certified PDFs are detected; a B-LTA's `/DSS` and `/DocTimeStamp` revisions are not flagged. Notes: DocMDP P=1/2/3 and FieldMDP decide; compare objects, never rendering.

## Current code
- `validate` (`crates/nacre-validate/src/validate.rs:22-56`): parses once, collects `/Sig` fields with a `/V`, skips document timestamps (`:37`, `:57-59`), caps at 64 signatures (`:9`, `:42-47`), runs `check` per signature.
- `check` (`validate.rs:63-106`): ordered steps 1-12; step 9 finds the revision the signed bytes end at (`:90-91`), step 10 the provisional rule (`:93-94`), then DER prefix and CMS (`:97-105`). `byte_range` (`:122-134`) and `follow_once` (`:115-120`) are reusable.
- Report (`report.rs:4-16`): `SignatureValidation { field, report, digest_verified, signature_verified, defect }`, `#[non_exhaustive]`; every structural defect → `TOTAL_FAILED`/`FORMAT_FAILURE` (`report.rs:60-75`).
- Errors (`crates/nacre-validate/src/error.rs`): `Pdf`, `TooManySignatures`; `kind()` per ADR-0012, table test `every_variant_has_its_kind`.
- `nacre-pdf`: `Revision { end, startxref, xref, trailer }` (`crates/nacre-pdf/src/xref.rs:21-31`); entries of all sections merged newest-first (`xref.rs:253`, `:433`) into one map (`document.rs:18`); no per-revision object list. `Document::parse` refuses trailing bytes after the last `%%EOF` (`xref.rs:146-165`), so `Document::parse(&pdf[..revision.end])` reads the state as of any revision.
- DocMDP: `Update::doc_mdp_level` reads `/Perms /DocMDP → /Reference → /TransformParams /P` (default 2) — private to `Update` (`crates/nacre-pdf/src/revision.rs:258-298`). No FieldMDP reading anywhere.
- A signature revision written by nacre (`revision.rs:136-218`): new sig dict, merged field-widget with `/Rect [0 0 0 0] /F 132 /P`, AcroForm `/Fields` appended or a new AcroForm set on the catalog (`:363-397`), first page rewritten with `/Annots` appended (`:197-204`), and, on xref-stream files, a new xref stream object (`:441-444`).
- Forge (`crates/nacre-validate/examples/forge_pades_attacks.rs`): `Update`-based (`add`, `add_stream`, `set_catalog`, `sign`), a CMS re-signing helper `range_forge` (`:185-212`), `appended_revision` for ISA (`:215-256`). `Update` cannot redefine an existing object nor write an xref-only revision.

## Attachment points
- `validate.rs:93-94`, `:110-112` — the branch to replace; the crate doc (`crates/nacre-validate/src/lib.rs:12-13`) names it.
- `report.rs` — new result fields and the defect replacing `LaterRevision`.
- New module in `crates/nacre-validate/src/` for the qualification.
- `crates/nacre-pdf/src/document.rs` — a public graph walk with one `Resolver`; `revision.rs:258` — DocMDP reader to move onto `Document`.
- `docs/security/attacks/pades.md:38`, `:40-46`, `:53` — the rows "à écrire par s15", check order list (`:9-20`), provisional-rule paragraph.

## Verified interfaces
- `pub fn validate(pdf: &[u8]) -> Result<Vec<SignatureValidation>, Error>` (`validate.rs:22`).
- `Document::parse(&'a [u8])`, `revisions() -> &[Revision]`, `catalog_id()`, `catalog()`, `signature_fields()`, `object(ObjectId) -> Result<Object, Error>` (`document.rs:37-125`).
- `Object` enum, `Dictionary::{get, iter, insert}`, `Stream { dict, data: Range<usize> }` — `PartialEq` derived (`crates/nacre-pdf/src/object.rs`); stream data is a range in the input, so equal streams at different offsets differ unless their bytes are compared.
- `Error::Limit { what, offset }` exists for bounded walks (`crates/nacre-pdf/src/error.rs:94`); `Error::ObjectNotFound` for a free or absent object (`document.rs:223`) — ISO 32000 makes such a reference `null`.
- `Limits` is `pub(crate)` (`crates/nacre-pdf/src/limits.rs:7-29`): `max_total_decoded` 256 MB, `max_object_number` 8,388,607.
- `nacre_pades::sign(pdf, &dyn Signer, DateTime)` (`crates/nacre-pades/src/sign.rs:21`); `TestSigner::from_secret(&[0x11; 32])` used by every committed signature (`forge_pades_attacks.rs:23`, `:36`).
- `nacre_cms::{sign_detached, Profile::PADES}` used for hand-made CMS (`forge_pades_attacks.rs:206`).
- Real fixtures, revisions read with a byte dump:
  - `signed-lta-pyhanko.pdf` (MIT): revs end 739 · 1393 (field `Sig1`, visible `/Rect [10 10 290 70]`) · 25853 (signature `Sig1`, catalog `/Extensions /ESIC`) · 46212 (catalog `/DSS 24 0 R`, page `/Annots` and `/Fields` + field 25 = invisible document timestamp whose `/ByteRange` ends at 46212) · 46884 (DSS dict 24 redefined, new arrays 29-32, an unreferenced VRI 28). All tables, indirect DSS arrays.
  - `signed-twice-pyhanko.pdf` (MIT): first signature `/ByteRange [0 3485 22223 4161]` ends 26384 = rev 1; rev 2 signs the pre-existing visible field 21 (`/V`, `/AP`), rewrites `/Metadata` 2 and `/Info` 8; xref streams and object streams.
  - `certified-dss.pdf` (LGPL-2.1, already in `crates/nacre-validate/tests/corpus/`): certified, `/P 3`; one signature covering the last revision; an empty field `signature-test2`.

## Traps
- **Cost.** Without a shared resolver, any graph walk multiplies object-stream decoding (fact 1). The precedent bound of this crate is 64 × the input (`validate.rs:8-9`): keep the number of revision states parsed and walked at 64 at most, an `Error` beyond.
- **What a revision changes cannot be read from `nacre-pdf` today** (no per-section entries): a diff must compare two parsed states over the objects reachable from `/Root`; a full reachable map of each state is needed anyway to know every referrer of a changed object (an object both in `/DSS` and on a page must not be whitelisted as DSS).
- **Stream equality**: compare dictionaries and the raw bytes `pdf[data]`, not `Stream` values (offsets differ).
- **Check order is a contract** (`docs/security/attacks/pades.md:7-22`, `validate.rs:61-62`): moving the revision step changes the sheet's numbered list and `isa_appended_revision_is_rejected`.
- Tests that will run: `crates/nacre-validate/tests/{validate,attacks,hostile}.rs`, unit tests of `report.rs` and `error.rs`; `nacre-pdf` tests `revision.rs` (`no_change_certification_refuses_a_signature` at `crates/nacre-pdf/tests/revision.rs:261` exercises the DocMDP reader).
- The fuzz target `crates/nacre-validate/fuzz/fuzz_targets/validate.rs` calls `validate`; new code is fuzzed with no change.
- Open s14 findings #75-#77 sit in the same files; out of scope.
- `/tmp` is a shared tmpfs near quota: the corpus is written into the crate, never `/tmp`.
- No migration; no new dependency.

## Open questions
- Indication for a revision not allowed: DSS's default policy for "modification after signing" is not established here; `TOTAL_FAILED`/`FORMAT_FAILURE` keeps one mapping with s14 — s18/s19 compare with DSS.
- Form fill after an approval signature in a document that is not certified: no DocMDP grants it, and allowing it lets shadow *replace* through a form field pass. The plan refuses it; DSS and Acrobat may only warn.
- ISO 32000 lets P=3 add annotations; the story's allowed list has none. The plan refuses every added annotation that is not a new signature's widget (EAA on P=3 included).
- A new signature whose widget is visible on a certified document is the SSA; whether a visible widget on a pre-existing field placed by the author is fine is assumed yes (pyHanko fixtures do it).
- FieldMDP names are compared as raw `/T` bytes joined by `.`; a UTF-16 name against a PDFDoc name would not match (no fixture has one).

## Complexity
Story 4 → **4**. Main risk confirmed: telling a legitimate revision from a malicious one, with real files (pyHanko) rewriting objects the story does not list. It also needs two small public additions to `nacre-pdf` the story did not foresee (fact 1); not a 5: no external system, no migration.

## Split
Not required at 4. If the lead prefers not to widen `Owns`, the cut is: a contract-like story owning `crates/nacre-pdf/` that adds the reachable-object walk and a public DocMDP reader, then s15 unchanged on top of it.
