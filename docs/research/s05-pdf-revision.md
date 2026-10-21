# Research — s05-pdf-revision

[Story](../stories.md)

## Structuring facts
- **False assumption — `qpdf --check` runs nowhere today.** `qpdf` is absent locally and from `.github/workflows/ci.yml:1-50` (fmt, clippy, test, fuzz only), which is frozen after s01 (`docs/architecture.md:60`); ADR-0007 (`docs/decisions/0007-dss-local-pinned-conformance-judge.md:22`) names it a CI judge that no workflow installs yet. The criterion can only become an `#[ignore = "conformance"]` test run by hand now, and by s02's `conformance.yml` later.
- **The crate has no writer at all.** `lib.rs:13` declares "editing" out of scope; there is no object serializer, `Dictionary` has no public constructor (`object.rs:55` is `pub(crate)`), and the resolver's constructor is private (`document.rs:141`). Everything the revision writes is new code inside `crates/nacre-pdf/`.
- **"s04 relit le résultat sans erreur" proves little on its own**: the reader checks only objects on followed paths (issue #30, `document.rs:36`), and its identity check at an xref offset (`document.rs:200`) has no biting test (issue #29). `qpdf --check` does bite: a new entry moved by 3 bytes gives `WARNING ... expected n n obj`, exit 3 (spike below).
- **Hidden requirement from dependants that cannot edit this crate**: s06 puts `/M` in the `/Sig` dictionary (`docs/stories.md:111`), s12 reuses this placeholder as a `/DocTimeStamp` (`docs/stories.md:221`), s11 adds `/DSS` through "the same API" (criterion 5). s06, s11, s12 own only `crates/nacre-pades/` (`docs/stories.md:107,194,211`): the API must take caller entries for the signature dictionary, new objects, new streams and a catalog entry.
- **The only certified file in the corpus permits changes**: `certified-dss.pdf` carries DocMDP `/P 3` (qpdf dump), so criterion 1 requires signing it; the refusal (`/P 1`) has no corpus file and must be crafted.

## Story
Append to an existing PDF an incremental revision carrying an invisible signature field, its `/Sig` dictionary (`/Filter /Adobe.PPKLite`, caller's `/SubFilter`), a `/Contents` reserved at the requested size and a `/ByteRange` covering the whole file except `/Contents`; return the ranges to hash, then write the DER signature into `/Contents`.
1. Every s04 corpus PDF keeps its original bytes as an exact prefix.
2. Field, `/Sig` dictionary, reserved `/Contents`, `/ByteRange` over everything but `/Contents`.
3. API gives the ranges, then accepts DER; a signature larger than the slot is an error, no truncated file.
4. The new revision follows the original's xref format (table or stream); s04 rereads it; `qpdf --check` clean.
5. A revision without signature (for s11's `/DSS`) goes through the same API.
Notes: fixed-width `/ByteRange` digits filled afterwards; DocMDP forbidding a new signature → clear error; `/Contents` in hex, zero-padded.

## Current code
- `src/lib.rs:15-28` — modules `acroform document error filter limits object parse xref`; exports `SignatureField, Document, Error, MAX_INPUT_LEN, Dictionary, Object, ObjectId, Stream, Revision, XrefKind`.
- `src/document.rs:13-21` — `Document<'a>` borrows the input; holds `limits`, `revisions`, `entries: HashMap<u32, Entry>`, `catalog_id`, `catalog`, `fields`. `parse` (`:36`) → `parse_with` (`:40`): size check, `xref::read`, refuses `/Encrypt` (`:50`), resolves `/Root` to a `/Type /Catalog` dictionary (`:61-71`), collects signature fields (`:72`).
- `src/document.rs:111-119` — `object(id)` builds a fresh `Resolver` per call; `Resolver::follow` (`:159`, `pub(crate)`) follows reference chains with a hop bound; `lookup` (`:185-195`) picks type-1 or compressed entries; `parse_at` (`:197-210`) refuses a header that is not `id`.
- `src/xref.rs:20-31` — `Revision { end, startxref, xref: XrefKind, trailer }`; `XrefKind::{Table, Stream, Hybrid}` (`:10-17`). `read` (`:56-87`) walks `/Prev`, merging entries newest first (`entries.entry(n).or_insert`, `:253`, `:433`). `group_revisions` (`:92-124`) ends a revision after `startxref Y %%EOF` + one EOL. `find_startxref` (`:146`) searches only the last 1,024 bytes and refuses non-whitespace after the last `%%EOF` (`:155`).
- `src/xref.rs:263-285` — table trailer: `/Prev`, optional `/Size` (`check_size`, `:324-344`, `None` when absent), `/XRefStm` → `Hybrid`. Streams require `/Size` (`:367-368`), `/W` widths ≤ 8 (`:369-379`), optional `/Index` (`:384-404`), any filter decoded by `filter::decode`.
- `src/acroform.rs:18-59` — `signature_fields` follows `/AcroForm` (direct or indirect) and `/Fields` (direct or indirect); `Walk::field` (`:99-181`) builds dotted names, treats kids without `/T` as widgets (`:148`), records terminal `/FT /Sig` fields with `/V` (`:154-170`).
- `src/object.rs:25-36` — `Object` holds decoded strings and names; `Real(f64)` (`:29`); `Dictionary` keeps input order (`:46-48`), `get`/`iter`/`len` public, construction crate-only; `Stream { dict, data: Range<usize> }` points into the input (`:82-85`).
- `src/parse.rs:317-339` — names decode `#xx`; `:436-486` numbers: a `.` makes a `Real`, otherwise `Integer` or a reference. Rereading `1` where `1.0` was written turns a real into an integer.
- `src/error.rs:7-95` — one `#[non_exhaustive]` `thiserror` enum; `Limit { what, offset }` for bounds.
- `src/limits.rs:3` — `MAX_INPUT_LEN = 50_000_000`; `Limits::DEFAULT` (`:14-25`) with `max_depth 64`, `max_hops 32`.
- `Cargo.toml` — deps `thiserror 2`, `miniz_oxide 0.9`; `[lints] workspace = true` (root `Cargo.toml:5-9` denies unwrap/expect/panic/indexing).
- `fuzz/Cargo.toml` — one target `parse`; `edition = "2024"` but no `rust-version` (issue #32).
- `tests/support/mod.rs` — test-only `Pdf` builder (`:18-233`): objects, object streams, xref table or stream, `shift(number, delta)` (`:96`); `minimal()` (`:239`) has `/Pages` with `/Kids [] /Count 0` — no page.
- `tests/corpus.rs:9-28` — `FILES`: 10 real files, revision ends and kinds; newest kinds: T for word-hybrid, libreoffice, chrome, firefox, signed-lta, certified-dss; S for word-pdfmaker, ghostscript, form-xfa, signed-twice. No file's newest revision is `Hybrid`.

## Attachment points
- `src/lib.rs` — new `mod write;` and `mod revision;`, new `pub use`, crate doc `:13` to rewrite ("editing" becomes "appending one incremental revision").
- `src/document.rs` — `impl Document`: add the entry point (`Document::revision()` or similar) and `pub(crate)` access to `follow`, `entries`, `input`, `limits`.
- `src/object.rs:50-78` — `impl Dictionary`: a public way to build one (`new`/`insert`), needed by callers for `/DSS` and extra `/Sig` entries.
- `src/error.rs` — new variants (slot too small, certification forbids, duplicate field, reserved entry, unwritable object).
- `tests/support/mod.rs` — new fixtures (DocMDP `/P 1`, direct AcroForm, indirect `/Fields`, page tree loop, #29 exact shift).
- `fuzz/` — `rust-version`, a second target exercising the writer on hostile input.

## Verified interfaces
- `pub fn Document::parse(bytes: &'a [u8]) -> Result<Document<'a>, Error>` — `document.rs:36`.
- `pub fn revisions(&self) -> &[Revision]` `:85`; `trailer(&self) -> &Dictionary` `:90`; `catalog_id()` `:97`; `catalog()` `:101`; `signature_fields() -> &[SignatureField]` `:106`; `object(id) -> Result<Object, Error>` `:111`.
- `pub(crate) fn Resolver::follow(&mut self, &Object) -> Result<(Option<ObjectId>, Object), Error>` — `document.rs:159`; `Resolver::new` private — `:141`.
- `pub struct SignatureField { name: String, id: ObjectId, value: Option<ObjectId> }` — `acroform.rs:9-16`.
- `pub(crate) enum Entry { Free, InUse { offset, generation }, Compressed { container, index } }` — `xref.rs:34-38`.

## Spike (outside the worktree, `/tmp/s05-spike`, qpdf 12.4.2 from conda-forge in `/tmp/s05-qpdf`)
- `qpdf --check` on all 10 originals: exit 0, no `WARNING`.
- Appending one plain object + an uncompressed xref stream (`/W [1 4 2] /Index [n 2]`, own entry included, `/Prev`, `/Root`) to `ghostscript-pdfa2.pdf` and `word-pdfmaker-linearized.pdf`, and a classic table section to `chrome-print.pdf` and `word-hybrid.pdf`: exit 0, no warning; the linearized file reports "not linearized" (it already did before).
- Same table update with the new entry's offset +3: `WARNING: ... file is damaged`, `expected n n obj`, exit 3. So qpdf catches wrong offsets that the s04 reader may not.
- AcroForm per file: absent in chrome, firefox, ghostscript, libreoffice; indirect in the six others; no corpus file has a direct `/AcroForm` or an indirect `/Fields` → crafted. All corpus files have ≥ 1 page (libreoffice 9, form-xfa 6).
- DocMDP in `certified-dss.pdf`: `/Perms 7 0 R` → `/DocMDP 14 0 R` → `/Reference` → `/TransformMethod /DocMDP /TransformParams 30 0 R` → `/P 3`: every level indirect, so the check must follow references at each step.

## Traps
- **Reals**: `format!("{}", 1.0_f64)` prints `1`; the s04 parser rereads it as `Integer` (`parse.rs:468-485`). `{:?}` switches to exponent notation for large/small values, which PDF forbids. Write `Display` and append `.0` when no `.` appears.
- **Names and strings**: `Object` holds decoded bytes (`object.rs:23`); names must re-escape non-regular bytes and `#` as `#xx`; strings written as hex `<…>` are lossless.
- **Trailer of the new section**: copying the previous trailer wholesale would copy `/XRefStm`, `/W`, `/Index`, `/Length`, `/Filter`, `/DecodeParms` of a stream dictionary. Copy only `/Root`, `/Info`, `/ID`; set `/Prev` to the newest `startxref` and `/Size` to max(old, highest new + 1). A table trailer may lack `/Size` (`xref.rs:330-331`): fall back to the highest entry number + 1.
- **Newest kind `Hybrid`**: no corpus case; a classic table update over it reads correctly (spec 7.5.8.4; word-hybrid's own newest revision is a table over hybrids, `corpus.rs:410-414`).
- **No EOL after the original `%%EOF`**: append one before the new objects; the prefix stays intact.
- **Objects stored in object streams** (catalog in form-xfa, word-pdfmaker…): a rewritten object is written as a plain object with a type-1 entry; the newest section wins (`xref.rs:253`, `:433`).
- **Output size**: a file near 50 MB plus the slot can exceed `MAX_INPUT_LEN`, which the reader then refuses (`document.rs:41-46`); refuse with `TooLarge` at writing time.
- **Hostile structure on new paths**: the writer follows `/Pages`/`/Kids`, `/Annots`, `/Perms` that s04 never reads; loops and depth must be bounded like the reader (`limits.rs:14-25`).
- **Existing signatures**: `signed-twice-pyhanko.pdf`, `signed-lta-pyhanko.pdf`, `certified-dss.pdf` must keep their fields after the update; `certified-dss.pdf` already holds an empty `signature-test2` field — a new field must not reuse a taken full name.
- **`/ByteRange` gap**: by ISO 32000-1 12.8.1 the excluded bytes are the whole hex string including `<` and `>`; s14 will validate exactly that.
- **Tests that run**: `cargo test -p nacre-pdf` runs `corpus.rs`, `hostile.rs` (includes a 50 MB case), `refusals.rs`, unit tests in `filter.rs`, `parse.rs`. `corpus.rs` `FILES` must stay unchanged.
- No migration, no new dependency needed (hex and decimal formatting are `std`).

## Open questions
- Widget placement: invisible widget referenced from the first page's `/Annots` with `/P` (pyHanko and Acrobat practice), or field only? The plan decides; a document with no page (test fixtures) gets no `/P`.
- DocMDP and document timestamps: ISO 32000-2 Table 257 lets DSS and document-timestamp updates through even at `/P 1`. Refuse only an approval signature (`/Type /Sig`)? The plan decides.
- Who installs qpdf in CI: s02's `conformance.yml` (ADR-0007) — to be filed as an issue; this story cannot edit workflows.
- Issues #29 (biting identity test) and #32 (`rust-version` in fuzz crate) sit in this story's Owns; #30 needs a decision on the story text of s04 and #27 needs `docs/security/attacks/pdf.md`, which this story does not own.

## Complexity
Story 3 → **4** after reading: no serializer exists, two xref writers (table and stream), four places the new field can hook into (AcroForm absent / direct / indirect, `/Fields` indirect, page `/Annots` direct or indirect), a DocMDP walk through indirect levels, and fixed-width patching. No dependency, no migration; one crate.

## Split
Not required at 4.
