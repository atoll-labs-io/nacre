---
validated: yes
---
# Plan — s05-pdf-revision

[Story](../stories.md) · [Research](../research/s05-pdf-revision.md)

Branch `story/s05-pdf-revision`. Read `docs/research/s05-pdf-revision.md` first; this plan builds on it without repeating it.

No technical choice is left open: the PDF layer is written by Nacre (ADR-0001), with no new dependency (ADR-0009 lists none for writing), and the API shape follows the story's criteria 3 and 5 and the needs of s06, s11 and s12 quoted in the research. The reserved ADR-0012 is not used.

Validated autonomously (`Plan validation: autonomous`): no human reviewed this plan. Criterion 1 → tasks 3 and 4 (prefix asserted on all 10 files); 2 → task 4; 3 → task 5; 4 → tasks 3 (reread, xref kind) and 7 (qpdf); 5 → task 3; DocMDP note → task 6.

## Story
Append an incremental revision to a parsed PDF: either plain (new objects, a catalog entry — for s11's `/DSS`), or carrying an invisible signature field with a `/Sig` dictionary, a zero-filled `/Contents` of the requested size and a fixed-width `/ByteRange`; hand out the two ranges to hash, then write the DER signature in place.
1. Original bytes are an exact prefix of the result, for each of the 10 real corpus files.
2. Field + `/Sig` (`/Filter /Adobe.PPKLite`, caller's `/SubFilter`) + reserved `/Contents` + `/ByteRange` = whole file minus the `/Contents` hex string.
3. Ranges out, DER in; DER larger than the slot → error, no truncated file.
4. New section follows the newest revision's xref kind (stream → stream; table or hybrid → table); `Document::parse` rereads it; `qpdf --check` exits 0 with no `WARNING`.
5. A revision without signature goes through the same builder.
Notes: DocMDP `/P 1` refuses a new approval signature with a clear error.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Following references on hostile paths (`/Pages`, `/Annots`, `/Perms`) | already here: `Resolver::follow`, `document.rs:159`, exposed through a `pub(crate)` method of `Document` | — |
| Existing field names, newest xref kind, trailer | already here: `signature_fields()` `document.rs:106`, `revisions()` `:85`, `trailer()` `:90` | — |
| Object serializer (`src/write.rs`) | new code | nothing in `src/` writes PDF; `tests/support/mod.rs:112-219` is test-only raw text; `std` has no PDF syntax; a PDF writer crate (`lopdf`) is a new dependency against ADR-0001 |
| Xref table / stream section writer | new code, laid out like `tests/support/mod.rs:157-215` | same as above |
| Hex of `/Contents`, fixed-width decimals | `std` (`write!` with `{:02X}` and width) | nothing in the repository |
| Test fixtures | already here: `support::Pdf` builder, extended with new cases | — |

## Tasks
1. [x] **Housekeeping of s04 findings in this crate.** `fuzz/Cargo.toml`: add `rust-version = "1.97"` (#32). `tests/support/mod.rs`: a `shift_onto(number, other)` option writing object `number`'s xref offset as object `other`'s offset; `refusals.rs`: `xref_entry_pointing_at_another_object_is_refused` asserting `ObjectMismatch { object: 1 0 R, .. }` (#29), and a row in `tests/corpus/README.md` "Crafted cases".
   Test that fails if wrong: the new refusal test turns green when `document.rs:200` compares only "some header" instead of `Some(id)`.
2. [x] **Serializer** `src/write.rs` (`pub(crate)`): `fn object(out: &mut Vec<u8>, &Object) -> Result<(), Error>` for `Null`, `Bool`, `Integer`, `Real` (`Display`, then `.0` appended when the text holds no `.`), `String` as `<HEX>`, `Name` as `/` + bytes with every byte outside `0x21..=0x7E`, every delimiter and `#` written `#xx`, `Array`, `Dictionary` in its stored order, `Reference` as `N G R`; `Object::Stream` → `Error::Unwritable { what: "a direct stream" }`. Recursion bounded by `Limits::max_depth` (`Error::TooDeep`). In `object.rs`: `pub fn Dictionary::new()` and `pub fn insert(&mut self, key: &[u8], value: Object)` (replaces an existing key, keeps keys unique).
   Test that fails if wrong: unit test `written_objects_parse_back_identical` in `write.rs`: a dictionary holding a name with space, `#`, `/` and a byte ≥ 0x80, a string with `(`, `)`, `\` and `0x00`, `Real(1.0)`, `Real(-0.25)`, `Integer(-7)`, nested arrays, a reference, `Null`, `Bool` is written then reparsed with `Parser::object` and compared with `==` (catches `1` for `1.0` and unescaped names).
3. [x] **Plain revision builder** `src/revision.rs`, exported from `lib.rs`: `Document::update(&self) -> Update<'_, 'a>`, with `pub fn add(&mut self, Object) -> Result<ObjectId, Error>`, `pub fn add_stream(&mut self, Dictionary, Vec<u8>) -> Result<ObjectId, Error>` (writes `/Length`, no filter), `pub fn set_catalog(&mut self, key: &[u8], Object)`, `pub fn finish(self) -> Result<Vec<u8>, Error>`. New numbers start at the old size (`/Size` of the newest trailer, else highest entry + 1). `finish`: copy the input; add `\n` when it does not end with CR or LF; write each new or rewritten object (`N G obj … endobj`) recording offsets; rewritten catalog keeps `catalog_id`. Then by `revisions().last().xref`: `Stream` → an uncompressed xref stream object numbered last, `/Type /XRef /W [1 4 2] /Index […] /Size /Prev /Root` (+ `/Info`, `/ID` when the newest trailer has them), its own entry included; `Table`/`Hybrid` → `xref`, contiguous subsections, 20-byte entries `%010d %05d n\r\n`, `trailer << /Size /Prev /Root [/Info] [/ID] >>`. Never copy `/XRefStm`, `/W`, `/Index`, `/Filter`, `/DecodeParms`, `/Length`. End with `startxref\n<offset>\n%%EOF\n`. Output above `MAX_INPUT_LEN` → `Error::TooLarge`. Update `lib.rs:13` doc: one appended revision is in scope, other editing is not.
   Test that fails if wrong: `tests/revision.rs` `every_corpus_file_takes_a_plain_revision` — for the 10 real files: `add` one dictionary, `add_stream` one stream, `set_catalog(b"NacreTest", reference to it)`; asserts `out.starts_with(original)`, `Document::parse(&out)` ok, revision count + 1, old `end`s unchanged, newest kind `Stream` when the original's was `Stream` else `Table`, the catalog entry holds the new reference, `object(id)` of each new object returns that very dictionary / a stream whose data bytes match.
4. [x] **Signature placeholder.** `pub struct SignatureSpec { pub field: String, pub sub_filter: Vec<u8>, pub contents_len: usize, pub entries: Dictionary }` and `Update::sign(self, SignatureSpec) -> Result<PreparedSignature, Error>`, which in order:
   - refuses `entries` holding `Filter`, `SubFilter`, `ByteRange` or `Contents` (`Error::ReservedEntry`), and `contents_len == 0`;
   - refuses a full name already in `signature_fields()` (`Error::DuplicateField { name }`);
   - DocMDP: `catalog /Perms` → `/DocMDP` → `/Reference` items → the one with `/TransformMethod /DocMDP` → `/TransformParams` → `/P` (absent = 2), following references at each level; `/P 1` refuses when the `/Sig` dictionary's `/Type` is `/Sig` (the default) with `Error::CertifiedNoChanges`; a caller `/Type /DocTimeStamp` passes (ISO 32000-2, Table 257);
   - first page: `/Pages` then `/Kids[0]` until `/Type /Page`, at most `Limits::max_depth` levels and `follow` for loops (`Error::Limit { what: "page tree depth" }`); no page → no `/P`;
   - adds the `/Sig` object: `/Type /Sig` (caller entries inserted over it), `/Filter /Adobe.PPKLite`, `/SubFilter`, `/ByteRange` written `[0 0 0 0]` with spaces before `]` up to the 36 bytes of `[0 9999999999 9999999999 9999999999]`, then `/Contents <` + `2 × contents_len` `0` + `>`, last in the dictionary;
   - adds the merged field-widget: `/FT /Sig /T <name> /V sig /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /F 132` (+ `/P page`);
   - hooks it: AcroForm absent → new AcroForm object `/Fields [field] /SigFlags 3`, catalog rewritten with `/AcroForm`; direct → catalog rewritten with the updated dictionary; indirect → AcroForm object rewritten under its id; `/Fields` indirect → that array object rewritten; `/SigFlags` OR 3; page `/Annots` absent or direct → page rewritten, indirect → array object rewritten;
   - lays the file out through task 3's `finish`, then overwrites the `/ByteRange` field in place: `[0 a b c]` where `a` = offset of `<`, `b` = offset after `>`, `c = len − b`, padded with spaces to the same 36 bytes.
   Test that fails if wrong: `every_corpus_file_takes_a_signature_slot` — for the 10 files, `sign` with field `Nacre1`, `/ETSI.CAdES.detached`, 8192: prefix intact; reparse ok; old fields still listed and `Nacre1` last with a `value`; its `/Sig` object has the four entries; `/ByteRange` read back equals `[0, a, b, len − b]` with `out[a] == b'<'`, `out[b − 1] == b'>'`, all bytes between are `0`, `b − a == 2 × 8192 + 2`; for a file with a page, `/P` names a page whose `/Annots` (followed) contains the field id.
5. [x] **Ranges and embedding.** `PreparedSignature`: `pub fn byte_range(&self) -> [usize; 4]`, `pub fn signed_parts(&self) -> [&[u8]; 2]`, `pub fn embed(&self, der: &[u8]) -> Result<Vec<u8>, Error>`: `der.len() > contents_len` → `Error::SignatureTooLarge { len, capacity }` with nothing returned; else a copy with the hex of `der` (upper case) at the start of the slot, zeros after. The `PreparedSignature` is unchanged on error.
   Tests that fail if wrong: `signed_parts_are_the_file_minus_contents` (one table file, one stream file: `parts[0] ++ parts[1]` equals the embedded output with `out[a..b]` removed, and equals it again after `embed`); `oversized_signature_is_refused_whole` (capacity 64: 65 bytes → `SignatureTooLarge { len: 65, capacity: 64 }` and `byte_range()`/`signed_parts()` unchanged; exactly 64 bytes accepted, its hex followed by no zero).
6. [x] **Refusals of the writer** in `tests/revision.rs`, fixtures in `tests/support/mod.rs` (each with one page):
   - `no_change_certification_refuses_a_signature`: crafted catalog `/Perms << /DocMDP 5 0 R >>`, object 5 `/Reference [<< /TransformMethod /DocMDP /TransformParams 6 0 R >>]`, object 6 `/P 1` → `CertifiedNoChanges`; the same file still takes a plain revision and a `/Type /DocTimeStamp` slot.
   - `taken_field_name_is_refused`: `certified-dss.pdf` with `signature-test2` → `DuplicateField`.
   - `reserved_entry_is_refused`: `entries` holding `/Contents` → `ReservedEntry`.
   - `page_tree_loop_is_refused`: `/Pages` whose `/Kids` lead back to itself → an error, not a hang.
   - `field_joins_every_acroform_shape`: direct `/AcroForm`, indirect `/Fields` array, indirect page `/Annots` → each rereads with the new field listed and the indirect array rewritten under its own id.
   Add each crafted case to `tests/corpus/README.md` "Crafted cases".
7. [x] **qpdf judge and fuzz target.** `tests/revision.rs` `qpdf_check_is_clean`, `#[ignore = "conformance"]`: for the 10 files, the plain output of task 3 and the embedded output of task 5 (a 300-byte fictitious DER) written under `env!("CARGO_TARGET_TMPDIR")`, `qpdf --check` exit status 0 and no `WARNING` in stdout or stderr; a missing `qpdf` fails the test. Run it once: `PATH=/tmp/s05-qpdf/bin:$PATH cargo test -p nacre-pdf --test revision -- --ignored` (qpdf 12.4.2 from conda-forge, already installed there by the research; recreate with `micromamba create -p /tmp/s05-qpdf -c conda-forge qpdf` if gone) through `po-run --story s05-pdf-revision --label qpdf`. `fuzz/fuzz_targets/revision.rs` + `[[bin]] revision`: parse, then `sign` a fixed spec and `embed` 16 bytes, errors ignored, never a panic.
   Test that fails if wrong: `qpdf_check_is_clean` (an offset off by 3 makes qpdf print `WARNING … expected n n obj`, research spike).

## Scene viewpoints
—

## Run interdicts
- Empty diff outside `crates/nacre-pdf/`, `docs/research/s05-pdf-revision.md`, `docs/plans/s05-pdf-revision.md` and the verification record: in particular root `Cargo.toml`, `.github/workflows/`, `crates/nacre-core/`, `docs/security/` (#27 stays open).
- `crates/nacre-pdf/Cargo.toml` `[dependencies]` stays `thiserror`, `miniz_oxide`: no new dependency.
- `tests/corpus.rs` `FILES` and the existing tests of `corpus.rs`, `hostile.rs`, `refusals.rs` are unchanged; only additions.
- No real document enters `tests/corpus/`; no file added there at all (every new case is crafted at test time).
- The reader's behaviour is unchanged: `src/xref.rs`, `src/filter.rs`, `src/parse.rs`, `src/acroform.rs` keep an empty diff; `document.rs` only gains methods. #30 is not addressed here.
- New objects are never put in an object stream and the new xref stream carries no `/Filter`.
- No clock read: `/M` reaches the `/Sig` dictionary only through `SignatureSpec::entries`.
- No `unsafe`, no `unwrap`/`expect`/`panic!`/indexing in `src/` (workspace lints).

## The pivot
Everything rests on **laying the whole revision out once with fixed-width placeholders, then patching only the `/ByteRange` digits in place**, over objects re-serialized from s04's parsed form. Ways it could be wrong:
- A re-serialized catalog, AcroForm or page differs in meaning from the original (real written as integer, name escape lost, entry dropped). Compare: `written_objects_parse_back_identical`, and in `every_corpus_file_takes_a_signature_slot` the reread catalog equals the original catalog plus the changed key.
- The patched `/ByteRange` changes the length, or `a`/`b` are off by one around `<` `>`. Compare: `out.len()` before and after patching, `out[a] == b'<'`, `out[b − 1] == b'>'`; qpdf would also flag a shifted xref.
- Offsets in the new xref section are wrong while the s04 reader still opens the file (it checks only followed objects, #30). Compare: every new object reread by id with its content, and `qpdf_check_is_clean`.
Secondary choices a reviewer may question: hybrid → table (no corpus case of a hybrid newest revision); invisible widget hooked to the first page; DocMDP `/P 1` lets `/DocTimeStamp` through.

## Files touched
- `crates/nacre-pdf/src/lib.rs`, `src/error.rs`, `src/object.rs`, `src/document.rs`
- `crates/nacre-pdf/src/write.rs` (new), `src/revision.rs` (new)
- `crates/nacre-pdf/tests/revision.rs` (new), `tests/support/mod.rs`, `tests/refusals.rs`, `tests/corpus/README.md`
- `crates/nacre-pdf/fuzz/Cargo.toml`, `fuzz/fuzz_targets/revision.rs` (new)

## Test strategy
One layer: the crate's public API (a library, no adapters), plus one unit test of the private serializer. 13 new tests, budget 25.
Automated:
- `write.rs` unit: `written_objects_parse_back_identical`.
- `refusals.rs`: `xref_entry_pointing_at_another_object_is_refused` (#29).
- `revision.rs`: `every_corpus_file_takes_a_plain_revision` (criteria 1, 4, 5), `every_corpus_file_takes_a_signature_slot` (1, 2, 4), `signed_parts_are_the_file_minus_contents` (3), `oversized_signature_is_refused_whole` (3), `no_change_certification_refuses_a_signature` (note), `taken_field_name_is_refused`, `reserved_entry_is_refused`, `page_tree_loop_is_refused`, `field_joins_every_acroform_shape`, `qpdf_check_is_clean` (`#[ignore = "conformance"]`, criterion 4).
- Fuzz target `revision`, run by the CI fuzz job (60 s).
Each rule is tested once: the serializer's escapes only in its unit test, refusals only in `revision.rs`. Task tests run with `cargo test -p nacre-pdf --test revision` / `--test refusals` / `--lib`.
Manual: none (no screen; `Surface: endpoint` QA calls the public API).

## Done when
- Every task checked, its tests green; `Full suite` (`cargo test --workspace`) once at the end and `Typecheck` (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) once after the last edit, both through `po-run`; `cargo fmt --all --check` clean.
- `qpdf_check_is_clean` run once with qpdf on `PATH` and recorded through `po-run`.
- Run interdicts hold; `docs/research` and `docs/plans` files committed with the code as `s05-pdf-revision: <story title>`.
- The handback names the open need for s02 to install `qpdf` in `conformance.yml` (ADR-0007), so `qpdf_check_is_clean` runs in CI.
