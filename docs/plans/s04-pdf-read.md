---
validated: yes
---
# Plan — s04-pdf-read

[Story](../stories.md) · [Research](../research/s04-pdf-read.md)

Branch `story/s04-pdf-read`. Read `docs/research/s04-pdf-read.md` first; this plan builds on it without repeating it. No ADR: every choice here follows ADR-0001 (Nacre writes the PDF layer, refuses rather than repairs), ADR-0008 (cargo-fuzz) and ADR-0009 (`miniz_oxide`).

## Story
A crate `nacre-pdf` that opens a PDF and returns its revisions, trailer, catalog and AcroForm signature fields, or refuses it with an error naming the defect (`docs/stories.md:66-82`). Criteria, with the research's corrections:
1. Revisions come from the `startxref`/`/Prev` chain, **not** from each `%%EOF` (research, Structuring facts 1). Each revision's end is the offset just past its `%%EOF` line and its EOL. The trailer, catalog and AcroForm signature fields are returned too.
2. Tables, xref streams (with PNG predictors), object streams and hybrid xref are read. The 10 real files of the spike sit in `tests/corpus/real/`, all read.
3. A broken xref, a corrupt revision or a missing object on a followed path gives a named `Error` variant. No repair.
4. Hostile input gives an error within the **bounds below** (issue #9), never a panic. A fuzz target exists.

### Bounds (answer to issue #9)
| Bound | Value | Error |
| --- | --- | --- |
| Input length, checked before any parsing | ≤ 50,000,000 bytes (`MAX_INPUT_LEN`) | `TooLarge { len, max }` |
| Nesting of arrays and dictionaries | ≤ 64 | `TooDeep { offset }` |
| Object numbers, `/Size` | ≤ 8,388,607 (ISO 32000-1 Annex C) | `Limit { what, offset }` |
| xref sections in the chain | ≤ 1,024, each offset visited once | `XrefLoop { offset }` / `Limit` |
| Indirect hops when resolving one value | each id once, ≤ 32 | `ReferenceLoop { object }` |
| Decoded bytes of one stream | ≤ 32 MiB; an xref stream decodes to exactly `count × (Σ W + predictor byte)` | `DecodedTooLarge { object, max }` / `XrefStream { object, reason }` |
| Decoded bytes per parse (object streams cached, each decoded once) | ≤ 256 MiB | `DecodedTooLarge` |
| AcroForm field tree | depth ≤ 32, each node once, ≤ 65,536 nodes | `FieldLoop { object }` / `Limit` |
| Searches | only `startxref` in the last 1,024 bytes; no other scan of the input | — |

So peak memory stays at or under the input, plus 256 MiB, plus the entry map. Every loop is bounded by one of these counts. Measured bound: every hostile test input fails in under 2 s on a debug build (task 8).

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Crate manifest, lint wiring, error enum | Copy of the pattern `crates/nacre-core/Cargo.toml:1-13`, `src/error.rs:1-20`; dependency `thiserror` 2 | — (first rung holds) |
| FlateDecode | Dependency `miniz_oxide` 0.9 `decompress_to_vec_zlib_with_limit` (ADR-0009) | Nothing in the repository; std has no inflate |
| PNG predictor reversal (≈40 lines) | New code | `miniz_oxide` does not undo predictors; no crate is allowed for it (ADR-0009 covers encodings, and a dependency for 40 lines fails "frugal") |
| Lexer, objects, xref, object streams, revisions, fields | New code | ADR-0001 has Nacre write the PDF layer; `lopdf`/`pdf` crates repair and are turned down by ADR-0001 |
| Fuzz harness | `libfuzzer-sys` 0.4 through cargo-fuzz (ADR-0008) | — |
| Test PDF builder (`tests/support/mod.rs`) | New code, test-only | No crate in the tree writes PDFs; hand-writing offsets in fixture files is the error-prone path the builder removes |

## Tasks
1. [x] **Crate skeleton.**
   - `crates/nacre-pdf/Cargo.toml`: `name = "nacre-pdf"`, `version = "0.1.0"`, edition 2024, `rust-version = "1.97"`, MIT OR Apache-2.0, `description`, `[lints] workspace = true`. Dependencies: `thiserror = "2"` and `miniz_oxide = "0.9"` (default features). No dev-dependency beyond these two.
   - `src/lib.rs`: `#![forbid(unsafe_code)]` first. The rustdoc opens with "**Experimental**: not yet fuzzed at length nor cross-checked against a reference reader" and states the scope: no rendering, no text, no editing, no repair.
   - `src/error.rs`: `#[non_exhaustive] #[derive(Debug, thiserror::Error)] pub enum Error`, English messages carrying the offset or object id. Variants: `TooLarge`, `MissingHeader`, `MissingStartxref`, `TrailingData { offset }`, `NotAnXrefSection { offset }`, `XrefTable { offset, reason: &'static str }`, `XrefStream { object, reason }`, `XrefLoop`, `Syntax { offset, expected: &'static str }`, `TooDeep`, `DuplicateKey { offset }`, `StreamLength { object }`, `UnsupportedFilter { object, filter: String }`, `UnsupportedPredictor { object, predictor: i64 }`, `Decode { object }`, `DecodedTooLarge`, `ObjectNotFound { object }`, `ObjectMismatch { object, offset }`, `ObjectStream { object, reason }`, `ReferenceLoop`, `WrongType { object, expected: &'static str }`, `Encrypted`, `FieldLoop`, `Limit { what: &'static str, offset }`. `object` is an `ObjectId`.
   - `src/limits.rs`: `pub const MAX_INPUT_LEN: usize = 50_000_000;` plus a crate-private `struct Limits` whose `const DEFAULT` holds the table's values, so unit tests can run a guard with small values.
   - Check: `cargo build -p nacre-pdf`. `cargo tree -p nacre-pdf -e normal --depth 1` lists `miniz_oxide` and `thiserror` only.
2. [x] **Objects and lexer** (`src/object.rs`, `src/parse.rs`).
   - Types: `pub struct ObjectId { pub number: u32, pub generation: u16 }` (Copy, Eq, Hash, Ord, Debug, Display `"N G R"`). `pub enum Object { Null, Bool(bool), Integer(i64), Real(f64), String(Vec<u8>), Name(Vec<u8>), Array(Vec<Object>), Dictionary(Dictionary), Reference(ObjectId), Stream(Stream) }`. `pub struct Dictionary` keeps entries in order, with `get(&self, key: &[u8]) -> Option<&Object>`. `pub struct Stream { pub dict: Dictionary, pub data: Range<usize> }` keeps a range into the input, never a copy.
   - The parser works over `&[u8]` with `.get()` only, and recurses through a depth counter that refuses past 64 before descending. It decodes literal strings (escapes, octal, nested parentheses, EOL rules), odd-length hex strings (padded with 0), names (`#xx`), integers (overflow gives `Syntax`), reals, `N G R`, and indirect objects `N G obj … endobj`.
   - A stream's `/Length` is direct, or indirect through a resolver callback. After `stream` comes CRLF or LF. Exactly `Length` bytes must be followed by an optional EOL and `endstream`; otherwise `StreamLength`. There is no search for `endstream`.
   - A dictionary with a duplicate key gives `DuplicateKey`.
   - Unit test `parse::tests::strings_names_and_numbers_decode` (one table of inputs → values). It fails if an escape, the hex padding or `#xx` is wrong.
3. [x] **Filters** (`src/filter.rs`). `decode(stream, object, limits, budget) -> Result<Vec<u8>, Error>`.
   - No `/Filter` returns the bytes as they are. `/FlateDecode`, or `[/FlateDecode]` of length 1, goes through `decompress_to_vec_zlib_with_limit(data, min(per_stream, budget_left))`, and `HasMoreOutput` maps to `DecodedTooLarge`. Any other filter, or any chain, gives `UnsupportedFilter`.
   - `/DecodeParms /Predictor`: 1 or absent leaves the data untouched. 10-15 run PNG reversal per row (each row starts with its type byte 0-4: None, Sub, Up, Average, Paeth), using `/Columns` (default 1), `/Colors` (default 1) and `/BitsPerComponent` (default 8). A row type above 4, or a partial row, gives `Decode`. Predictor 2 and any other value give `UnsupportedPredictor`.
   - Unit tests: `filter::tests::png_rows_are_reversed` (one encoded block using all five row types, compared with its known plain bytes, computed once in Python and pasted in) and `filter::tests::stream_and_parse_budgets_hold` (with `Limits` of 1 KiB per stream and 2 KiB per parse: a 1 KiB + 1 output fails, and three 900-byte streams fail on the third). They fail if a row type is mis-reversed or a cap is not enforced.
4. [x] **Cross-reference and revisions** (`src/xref.rs`).
   - Check `%PDF-` at offset 0, else `MissingHeader`. Find the last `startxref\s+N\s+%%EOF` inside the final 1,024 bytes, else `MissingStartxref`. Only PDF whitespace may follow that `%%EOF`, else `TrailingData`.
   - At `N`: `xref` means a table, `N G obj` a stream, anything else `NotAnXrefSection`.
   - Table: subsections `start count`. Check `count × 20 ≤ bytes remaining` before reading. Each entry is 20 bytes (`nnnnnnnnnn ggggg n|f` + 2-byte EOL), then `trailer` and a dictionary.
   - Stream: `/Type /XRef`, `/W` of 3 widths each ≤ 8, `/Index` (default `[0 Size]`) and `/Size` ≤ 8,388,607. The decoded length must equal `Σcount × ΣW`, else `XrefStream`. A width of 0 takes the spec default (type 1).
   - `/XRefStm` in a table trailer: read that stream's entries after the table's, inside the same section. The stream is not in the chain.
   - Walk `/Prev` with a visited set and the 1,024 cap. Merge entries newest first, then table before `/XRefStm`; the first definition of an object number wins.
   - Group sections into revisions by the research's rule. After each section's end (the end of the trailer dictionary, or `endobj`), read an optional `startxref Y %%EOF` and its EOL. That statement ends a revision only when `Y` is in the chain. Unnamed sections join the revision of the section that reached them through `/Prev`.
   - `pub struct Revision { pub end: usize, pub startxref: usize, pub xref: XrefKind, pub trailer: Dictionary }`, with `pub enum XrefKind { Table, Stream, Hybrid }` (Hybrid = a table with `/XRefStm`). Revisions are listed oldest first. Invariant: the last revision's `end == input.len()`.
   - Tests: task 7's `revisions_match_the_spike`, and task 8's xref refusals.
5. [x] **Document and resolver** (`src/document.rs`).
   - `pub struct Document<'a>`, with `pub fn parse(bytes: &'a [u8]) -> Result<Self, Error>` (length check first).
   - Getters: `revisions(&self) -> &[Revision]`, `trailer(&self) -> &Dictionary` (the newest), `catalog_id(&self) -> ObjectId`, `catalog(&self) -> &Dictionary`, `signature_fields(&self) -> &[SignatureField]`, `object(&self, id) -> Result<Object, Error>` (for s05, with a fresh resolver per call).
   - A newest trailer holding `/Encrypt` gives `Encrypted`.
   - The resolver, private, lives for one parse. A free or absent entry, or a generation mismatch, gives `ObjectNotFound`. A type-1 entry beyond the input, or whose bytes do not start with `N G obj` of that very id, gives `ObjectMismatch`. A type-2 entry needs its container to be a type-1 `/Type /ObjStm`, an index < `/N`, `/First` inside the decoded data, and the index-th header pair naming the requested number; otherwise `ObjectStream`. Objects inside an object stream cannot be streams.
   - Decoded object streams are cached in a `HashMap` for the parse, and charged to the 256 MiB budget once. Following references goes through a visited set and the 32-hop cap.
   - `/Root` must resolve to a dictionary with `/Type /Catalog`, else `WrongType`.
   - Tests: tasks 7 and 8.
6. [x] **Signature fields** (`src/acroform.rs`). `pub struct SignatureField { pub name: String, pub id: ObjectId, pub value: Option<ObjectId> }`.
   - A catalog without `/AcroForm`, or an AcroForm without `/Fields`, has no fields. `/AcroForm`, `/Fields` and each `/Kids` element must resolve, else `ObjectNotFound`.
   - Walk depth-first with a visited set and the depth and count caps. `/FT` and the partial names `/T` are inherited down `/Kids`. A kid with no `/T` is a widget of its parent.
   - A terminal field (no kid carrying `/T`) whose inherited `/FT` is `/Sig` is listed. Its `name` is the dotted full name: UTF-16BE with a BOM is decoded, anything else byte by byte as Latin-1 (enough for the ASCII names of the corpus; documented as such). `value` is the `/V` reference; a direct `/V` gives `WrongType`. Fields are listed in tree order.
   - Tests: task 7's `signature_fields_match_pdfsig`, and task 8's `field_kids_loop_is_refused`.
7. [x] **Real corpus and its tests.**
   - Copy the 10 real files of the research table into `crates/nacre-pdf/tests/corpus/real/` under descriptive names: `word-hybrid.pdf`, `word-pdfmaker-linearized.pdf`, `libreoffice-pdfa3.pdf`, `chrome-print.pdf`, `firefox-print.pdf`, `ghostscript-pdfa2.pdf`, `form-xfa-irs-w9.pdf`, `signed-twice-pyhanko.pdf`, `signed-lta-pyhanko.pdf`, `certified-dss.pdf`. Take them from `/tmp/s04-spike/data/` when the sha256 prefixes match the research. Otherwise re-download from the listed source, or regenerate the two prints and the PDF/A with the commands below and update the README.
   - Copy the hostile pyHanko files into `tests/corpus/hostile/`: `circular-xref-chain.pdf`, `xref-malformed-prev.pdf`, `startxref-off-by-one.pdf`, `aes256.pdf`.
   - `tests/corpus/README.md`, in English: per file its source URL, licence, full sha256, producer, structure (from the research), and for hostile files the attack each one carries. Add the list of crafted hostile cases of task 8. Credit pyHanko (MIT), DSS (LGPL-2.1), W3C (document licence), IRS (public domain) and TDF.
   - The fictitious page used for the prints is copied, as HTML, to `tests/corpus/real/print-source.html` (content: `/tmp/s04-spike/page.html`).
   - Regeneration commands: `chrome-headless-shell --no-sandbox --print-to-pdf=chrome-print.pdf --no-pdf-header-footer file://…/print-source.html`; Firefox 158 via WebDriver BiDi `browsingContext.print` (`/tmp/s04-spike/scripts/ff_print.py`); `gs -dBATCH -dNOPAUSE -dSAFER -sDEVICE=pdfwrite -dPDFA=2 -dPDFACompatibilityPolicy=1 -sColorConversionStrategy=RGB -sOutputFile=ghostscript-pdfa2.pdf chrome-print.pdf`.
   - `tests/corpus.rs` (file-level clippy allow as in `crates/nacre-core/tests/*.rs`), with three tests:
     - `revisions_match_the_spike`: for each file, the exact `end` list and `XrefKind` list of the research table, and `revisions().last().end == len`. Fails if the revision rule falls back to counting `%%EOF` (fw9, table and signed-twice would gain one) or drops the EOL.
     - `signature_fields_match_pdfsig`: `Sig1`/`Sig2` both signed in signed-twice. `Sig1` plus `Timestamp-977301ad-bec9-4cae-a0cd-f6a674c6e465` both signed in signed-lta. `signature-test` signed and `signature-test2` with `value == None` in certified-dss. Empty for the seven others. Fails if `/FT` inheritance, object streams or `/V` are wrong.
     - `catalog_and_trailer_are_read`: for every file, `trailer().get(b"Root")` names `catalog_id()`, `catalog()` has `/Type /Catalog`, and a hybrid revision exists in `word-hybrid.pdf` only. Fails if the newest trailer is not the one returned.
   - Run: `cargo test -p nacre-pdf --test corpus`.
8. [x] **Refusals and hostile input.**
   - `tests/support/mod.rs`: a test-only builder. It appends objects and writes a classic table or an xref stream with correct offsets, and has hooks to corrupt one thing: shift an offset, add a raw trailer key, override `/Length`, add raw bytes after `%%EOF`.
   - `tests/refusals.rs` (criterion 3), each asserting `matches!` on the exact variant:
     - `startxref_off_by_one_is_refused` (`startxref-off-by-one.pdf` → `NotAnXrefSection`)
     - `malformed_prev_is_refused` (`xref-malformed-prev.pdf` → `Syntax`/`XrefTable`, whichever the parser names; assert that one)
     - `xref_entry_pointing_elsewhere_is_refused` (`ObjectMismatch`)
     - `missing_catalog_is_refused` (`/Root 9 0 R` absent → `ObjectNotFound` naming `9 0 R`)
     - `object_stream_index_past_n_is_refused` (AcroForm in an object stream at index `/N` → `ObjectStream`)
     - `encrypted_pdf_is_refused` (`aes256.pdf` → `Encrypted`)
     - `other_filter_on_xref_stream_is_refused` (`/LZWDecode` → `UnsupportedFilter`)
     - `bytes_after_last_eof_are_refused` (`TrailingData`)
   - `tests/hostile.rs` (criterion 4):
     - `xref_prev_loop_is_refused` (`circular-xref-chain.pdf` → `XrefLoop`)
     - `reference_loop_is_refused` (`/Root 5 0 R`; 5 holds `6 0 R`, 6 holds `5 0 R` → `ReferenceLoop`)
     - `field_kids_loop_is_refused` (`FieldLoop`)
     - `wrong_stream_length_is_refused` (object stream `/Length` 10 too short, then past end of file → `StreamLength`)
     - `deep_nesting_is_refused` (1,000,000 `[` inside the catalog → `TooDeep`, no stack overflow)
     - `size_limit_is_50_000_000_bytes` (a builder PDF padded by an unused stream to exactly 50,000,000 bytes parses; one byte more → `TooLarge`)
     - `huge_declared_counts_are_refused` (subsection `0 8388607` in a 1 KB file → `XrefTable`)
     - `xref_stream_with_wrong_decoded_length_is_refused` (`XrefStream`)
     - `hostile_inputs_fail_within_two_seconds`: every input of this file and of `refusals.rs` except the 50 MB one, timed together with `Instant`, under 2 s. It also asserts an `Err` for each.
   - Each test fails when its guard is removed: the loop runs forever or overflows the stack, the allocation aborts, or the wrong variant or `Ok` comes back.
   - Run: `cargo test -p nacre-pdf --test refusals --test hostile`.
9. [x] **Fuzz target.**
   - `crates/nacre-pdf/fuzz/Cargo.toml`: package `nacre-pdf-fuzz`, `version = "0.0.0"`, `publish = false`, edition 2024, `[package.metadata] cargo-fuzz = true`. Dependencies `libfuzzer-sys = "0.4"` and `nacre-pdf = { path = ".." }`. `[[bin]] name = "parse"`, `path = "fuzz_targets/parse.rs"`, `test = false`, `doc = false`, `bench = false`. Its own `[workspace]` with `members = ["."]`.
   - `crates/nacre-pdf/fuzz/.gitignore`: `target`, `corpus`, `artifacts`, `coverage`.
   - `fuzz_targets/parse.rs`: `#![no_main]`. On `Ok(doc)`, touch `revisions()`, `trailer()`, `signature_fields()` and `object(catalog_id())`. Add `#![forbid(unsafe_code)]` too, unless `cargo check` shows the macro trips it; then leave it out with a one-line comment saying why.
   - Check: `cargo check --manifest-path crates/nacre-pdf/fuzz/Cargo.toml` on the pinned toolchain. When `cargo-fuzz` is present (`cargo +nightly fuzz --version`), also run `cargo +nightly fuzz run parse -- -max_total_time=60` from `crates/nacre-pdf`, seeded by copying `tests/corpus/real/*` into `fuzz/corpus/parse/` (ignored). A crash becomes a corpus file under `tests/corpus/hostile/` before its fix (ADR-0008). Record in `docs/verif` whether the local run happened.

## Scene viewpoints
—

## Run interdicts
- `git diff --name-only main...` lists only `crates/nacre-pdf/**`, `docs/research/s04-pdf-read.md`, `docs/plans/s04-pdf-read.md` and the pipeline's `docs/verif/` and `docs/reviews/` files. In particular, the root `Cargo.toml`, `.gitignore`, `.github/workflows/*`, `crates/nacre-core/**`, `docs/security/**`, `docs/stories.md` and `docs/architecture.md` keep an empty diff.
- No dependency other than `thiserror`, `miniz_oxide` (lib) and `libfuzzer-sys` (fuzz crate). No `lopdf`, `pdf`, `flate2`, `nom`, `regex` or `memchr`.
- No repair: there is no fallback that scans the input for `obj`, `xref`, `trailer` or `endstream` when an offset is wrong. The only search is the backward `startxref` lookup in the last 1,024 bytes. Reviewer: grep `src/` for `windows(`, `.find(`, `rfind`, `position(`, and check each hit is that one lookup or works on a slice already bounded by an offset the file gave.
- No `with_capacity` or `vec![_; n]` sized by a number read from the input before it is checked against the bytes remaining.
- `grep -rnE "unsafe|println|eprintln|std::(fs|net)|SystemTime" crates/nacre-pdf/src` finds only the `forbid` line.
- Not in scope: content streams, fonts, pages, text, rendering, DocMDP, writing anything. `Document` exposes no mutation.
- No real personal document in the corpus. In particular, the spike's DSS files `doc-firmado.pdf` and `PAdES-LTA.pdf` carry real signers' names and were deliberately dropped.

## The pivot
Everything rests on the **revision rule**: the `startxref`/`/Prev` chain, a statement naming a chain section closes a revision, and unnamed sections join the revision that reached them. s05 appends after `revisions().last().end`, and validation compares signed ranges with these ends. It could be wrong in three ways:
- A producer writes a statement that names a chain section but is not followed by its own revision, for example an Acrobat linearized file updated twice. Compare with pdfsig's signed ranges on any signed file added later: every signed range must end at some revision end.
- Something other than a statement follows a section, such as comments or junk bytes between `endobj` and `startxref`. The rule then misgroups. Compare with the `%%EOF` positions listed by `inspect_pdf.py`.
- Strict refusals (duplicate keys, the `/Type /Catalog` requirement, 20-byte entries, the header at offset 0) refuse a real file the corpus does not hold. Each is a named variant, so a refusal shows up as a test failure on that file rather than a misread. The implementer stops and reports if any real corpus file is refused, instead of loosening a rule silently.

## Files touched
`crates/nacre-pdf/Cargo.toml`, `src/{lib,error,limits,object,parse,filter,xref,document,acroform}.rs`, `tests/{corpus,refusals,hostile}.rs`, `tests/support/mod.rs`, `tests/corpus/{README.md,real/*,hostile/*}`, `fuzz/{Cargo.toml,.gitignore,fuzz_targets/parse.rs}`. Already written: this plan and the research.

## Test strategy
23 tests, under the `Test budget` of 25. All of them sit at the parser's own layer; the crate has no service, adapter or persistence layer.
- Unit tests (3): string/name/number decoding; PNG row reversal; the stream and parse decode caps, run with small `Limits` because a 32 MiB / 256 MiB bomb in a debug build would cost seconds per run.
- `corpus.rs` (3): criteria 1-2 on real files, each a table over the 10 files.
- `refusals.rs` (8): criterion 3, one named variant per defect.
- `hostile.rs` (9): criterion 4, one per bound of the table, plus the measured time bound.
- Two slots are kept for a fuzz crash, should one appear.
- Not tested: each `Error` message, getters, every PNG predictor number (10-15 share one code path), every `XrefKind` pair.

Checks: `cargo fmt --all --check`, and the fuzz crate's `cargo check` (task 9). `Test` and `Typecheck` run once at the end through `po-run`.

Visual checks: none (library).

## Done when
- The four criteria hold as corrected above, and the bounds table is implemented with the values written here.
- `cargo fmt --all --check`, `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` pass on 1.97; the last two are recorded by `po-run`.
- The fuzz crate passes `cargo check`; CI's fuzz job runs `parse` for 60 s green.
- Research, plan and code are in one commit `s04-pdf-read: <story title>`.
