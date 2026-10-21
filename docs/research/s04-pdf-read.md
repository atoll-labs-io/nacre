# Research — s04-pdf-read

[Story](../stories.md)

## Structuring facts
- **False assumption, criterion 1: a revision is not "each `%%EOF`".** Linearized files (`irs-fw9`, `w3c-table`, pyHanko `signed-twice`) carry a first-page trailer `startxref 0 %%EOF` around byte 450-500 that ends no revision. Word's file has an xref section (offset 89962) that no `startxref` names. Revisions have to come from the `startxref` → `/Prev` chain (rule below). The end offset includes the EOL after `%%EOF`: signature `/ByteRange`s end there (pyHanko `signed-twice`: `%%EOF` ends at 26383, the signed range at 26384).
- **Incomplete assumption, story notes: "FlateDecode only" is not enough.** Every xref stream written by Word, Acrobat and Designer carries `/DecodeParms << /Predictor 12 /Columns n >>` (PNG predictor). `miniz_oxide` does not undo predictors, so Nacre has to write that reversal. Refusing it would refuse Word.
- AcroForm fields and the catalog sit **inside object streams** in 5 of the 10 real files. Listing fields needs xref streams, object streams and inheritance of `/FT` all working; no shortcut reads them.
- No code exists for this story. Only `crates/nacre-core` exists (`crates/nacre-core/src/lib.rs:1-34`), and `nacre-pdf` needs none of it. The crate, its corpus, its fuzz folder and their `.gitignore` are all new, all under `crates/nacre-pdf/` (Owns, `docs/stories.md:72`).
- The strict reading works on the real corpus. All 10 real files, walked from `startxref` along `/Prev` and `/XRefStm`, have every in-use entry at an offset that starts `N G obj`. Every xref and object stream has a direct `/Length` followed by `endstream`, and decodes under zlib-strict. So no repair is needed to read any of them (spike scripts below).

## Story
Open a PDF and return its revisions (end offset of each), its trailer, its catalog and its AcroForm signature fields (`docs/stories.md:66-82`). Criteria:
1. Revisions (end of each `%%EOF`), trailer, catalog, AcroForm signature fields.
2. Classic xref tables, xref streams, object streams and hybrid xref are read. The corpus `crates/nacre-pdf/tests/corpus/` holds PDFs from Word, LibreOffice, Chrome print, Firefox print, a PDF/A, a form and a PDF already signed by a third party, all read.
3. A broken xref, a corrupt revision or a missing object gives an error that names the defect. Nacre never repairs.
4. Hostile input (reference loops, wrong stream length, deep nesting, over 50 MB) gives an error bounded in time and memory, never a panic. A fuzz target exists. Issue #9: the bound must be concrete; the plan states it.

## Spike — the real corpus (brief, "Open risks & spikes")
Gathered on 2026-10-22 into `/tmp/s04-spike/data/`. The scripts `inspect_pdf.py`, `check_streams.py`, `strict_xref.py` and `revisions.py` are in `/tmp/s04-spike/scripts/`. Nothing was copied into the worktree. Revisions are listed oldest first as end offsets; T = table, S = stream, H = table with `/XRefStm`.

| Role | File (source, licence) | sha256[:16] | Producer, version | Structure | Revisions (end) |
| --- | --- | --- | --- | --- | --- |
| Word | `w3c-pdf-links-links.pdf` (W3C WCAG 2.1 working example `pdf-links/links.pdf`, W3C document licence) | 2ddbca838061520a | Creator Microsoft Word, PDF 1.7 | hybrid T+H, 2 ObjStm, Predictor 12, `/W [1 3 1]`,`[1 4 2]` | 81959 T · 82140 H · 90822 T+H · 94902 T |
| Word (PDFMaker) | `w3c-pdf-table-table.pdf` (W3C, `pdf-table/table.pdf`) | a693998ff2a475d1 | PDFMaker 9 for Word, Adobe PDF Library 9, 1.6 | linearized, xref streams, 7 ObjStm, Predictor 12 | 57615 S+S · 66887 S |
| LibreOffice, PDF/A-3b | `tdf-statutes.pdf` (documentfoundation.org/statutes.pdf, public) | 7b76e445d714b793 | LibreOffice 7.3, 1.6, `pdfaid:part 3` | one table, 992 objects, 12 indirect `/Length` | 206397 T |
| Chrome print | `chrome-print.pdf` (generated, fictitious page) | 38ade8a1d7b23954 | Skia/PDF m156 (chrome-headless-shell 156.0.8078.47) | one table, 1.4 | 18950 T |
| Firefox print | `firefox-print.pdf` (generated, same page) | 4699499c3a88b747 | Firefox 158, **Skia/PDF m149**, 1.4 | one table | 25050 T |
| PDF/A-2 | `gs-pdfa2.pdf` (gs 10.08 `-dPDFA=2` from the Chrome print) | 6d9b483819f61013 | Ghostscript 10.08, 1.7 | xref stream with no predictor, 1 ObjStm | 15883 S |
| Form | `irs-fw9.pdf` (irs.gov/pub/irs-pdf/fw9.pdf, US public domain) | 2d420cbb4123dcf1 | Designer 6.5, 1.7, XFA | linearized, 17 ObjStm, Predictor 12, `/Perms /UR3` usage-rights signature (not a field) | 126744 S+S · 140815 S |
| Signed by a third party | `ph-minimal-two-fields-signed-twice.pdf` (pyHanko test data, MIT) | 9aad3553e8ffdf06 | linearized, xref streams | fields `Sig1`, `Sig2`, both signed, signer "Lord Testerino" (test PKI) | 26384 S+S · 50827 S |
| Signed, B-LTA | `ph-pades-lta-dss-indirect-arrs-test.pdf` (pyHanko, MIT) | 30fe330df187588d | 5 tables | `Sig1` + document timestamp field `Timestamp-977301ad-bec9-4cae-a0cd-f6a674c6e465` | 739 · 1393 · 25853 · 46212 · 46884 (all T) |
| Signed and certified | `dss-certified-changes-permitted.pdf` (esig/dss `dss-pades/src/test/resources/validation/dss-2554/`, LGPL-2.1) | 17c74d6c6911cb8b | LibreOffice 5.2, DocMDP | `signature-test` signed, `signature-test2` empty | 127672 T · 152955 T |

Hostile and broken files from pyHanko (MIT, `internal/common-test-utils/src/pyhanko_testing_commons/test_data/data/pdf/`): `circular-xref-chain.pdf` (2b18aef1, `/Prev` 9↔65), `xref-malformed-prev.pdf` (87f0718d, `/Prev (zzz)`), `minimal-startxref-obo1.pdf` (ba3415d7, `startxref` off by one), `minimal-aes256.pdf` (eda8c19f, `/Encrypt`), `minimal-hybrid-xref-mswordstyle.pdf` (29dd43da, an uncompressed xref stream with **no `/Filter`**). `minimal-with-nonexistent-refs.pdf` points at a missing object only from a page (`/Bleh 100 0 R`). `broken-objstream1.pdf` breaks only `/Pages`: its xref puts object 4 at index 3 of an object stream whose `/N` is 3. s04 never follows either path, so both files read cleanly and neither exercises "objet introuvable". The plan crafts those cases on the paths s04 does follow.

Findings that bind the reader:
- **Revision rule**, checked on all 10 files. Walk sections from the last `startxref` along `/Prev`. After each section — the trailer dictionary of a table, or `endobj` of a stream — read an optional `startxref Y %%EOF [EOL]`. A revision ends at each such statement whose `Y` is a section of the chain. A section that no statement names joins the revision of the section whose `/Prev` reached it: the main xref of a linearized file, Word's 89962. A statement whose `Y` is not in the chain (`startxref 0`) ends nothing. The last revision always ends at the file length. Every signed range of the corpus ends at a revision end.
- Hybrid precedence: within one section, the table's entries come before its `/XRefStm` stream's, and newer sections come before `/Prev`. With that order every offset checks out (`strict_xref.py`).
- xref table entries are exactly 20 bytes in every real file, ending in either ` \n` or `\r\n`. The header `%PDF-` is at offset 0 in all files. At most 2 bytes (an EOL) follow the last `%%EOF`.
- Only `FlateDecode` appears on xref and object streams, plus none at all (pyHanko). Predictors seen: none, and 12. Row filters other than Up can appear under predictor 10-15, so all five PNG row types are cheap to accept; TIFF predictor 2 never appears.
- Chrome and Firefox now share one writer (Skia/PDF), so "Chrome and Firefox print" exercise the same structure. Neither Word nor LibreOffice is installed here (`command -v` finds no `soffice`), hence the public samples.
- A document whose `%%EOF`-based count differs from the revision count: `irs-fw9` (3 `%%EOF`, 2 revisions), `w3c-table`, `signed-twice`.

## Current code
- `Cargo.toml:1-9` — workspace `members = ["crates/*"]`, plus `[workspace.lints.clippy]` denying `unwrap_used`, `expect_used`, `panic` and `indexing_slicing`. A new crate joins by its folder alone. The root is frozen (ADR-0003).
- `crates/nacre-core/Cargo.toml:1-28` — the manifest pattern to copy: edition 2024, `rust-version = "1.97"`, MIT OR Apache-2.0, `[lints] workspace = true`, versions declared per crate.
- `crates/nacre-core/src/error.rs:1-20` — the error pattern: one `#[non_exhaustive] #[derive(Debug, thiserror::Error)] enum Error` with English messages.
- `crates/nacre-core/tests/*.rs` — integration tests open with a file-level `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]` (s01 plan, task 6).
- `.github/workflows/ci.yml:19-50` — the fuzz job globs `crates/*/fuzz`, then runs `cargo +nightly fuzz list` and `fuzz run <t> -- -max_total_time=60` inside the crate folder. No edit is needed.
- `.gitignore:1-4` — `.worktrees/`, `.env*`, `/target` (root only) and `Cargo.lock` (any depth).

## Attachment points
- New folder `crates/nacre-pdf/` (crate `nacre-pdf`), picked up by `members = ["crates/*"]`.
- `crates/nacre-pdf/fuzz/` is found by the CI glob (`ci.yml:28`). It is not a workspace member: `crates/*` does not match two levels down.
- The consumer to design for is s05 (`docs/stories.md:84-100`). It needs the bytes kept intact, the last revision's xref kind (table or stream, criterion 4), its trailer (`/Size`, `/ID`, `/Prev`), the catalog and AcroForm, and DocMDP permissions. s04 exposes the first four. DocMDP is s05's.

## Verified interfaces
- `miniz_oxide` 0.9.1 (registry, `src/inflate/mod.rs:195`): `pub fn decompress_to_vec_zlib_with_limit(input: &[u8], max_size: usize) -> Result<Vec<u8>, DecompressError>`, behind the default `with-alloc` feature. The zlib variant checks the header and adler32. `miniz_oxide::deflate::compress_to_vec_zlib(&[u8], u8)` can build fixtures in tests.
- `thiserror` 2 is used by `nacre-core` (`crates/nacre-core/Cargo.toml:13`).
- Toolchain 1.97 is pinned (`rust-toolchain.toml:2`). A `nightly` toolchain was installed on this machine during the research by a `cargo +nightly` probe. `cargo-fuzz` is **not** installed.
- Tools present: `pdfinfo` and `pdfsig` (poppler 26.08), `gs` 10.08, `firefox` 158, `openssl`. Absent: `qpdf`, `mutool`, LibreOffice, Chrome. A chrome-headless-shell download sits in `/tmp/s04-spike/chrome/`.

## Traps
- **`indexing_slicing` is denied** (`Cargo.toml:8`), so every byte access in the parser goes through `.get(..)`. `&data[a..b]` fails clippy.
- **Counts read from input must never size an allocation.** Examples are `0 8388607` in an xref subsection, `/N` of an object stream, `/Size` and `/Index`. Check them against the bytes that remain before reserving.
- **An object stream decoded once per lookup is quadratic.** fw9 has 17 object streams of up to 100 objects. Cache each decoded stream for the length of a parse.
- Recursive object parsing overflows the stack on `[[[[…` unless depth is counted before recursing.
- **The fuzz crate needs its own `[workspace]`.** Without it, cargo walks up to the root workspace, which does not list it, and refuses ("believes it's in a workspace when it's not"). It also needs a `.gitignore` for `target/`, `corpus/` and `artifacts/`, because the root's `/target` is anchored (`.gitignore:3`). The fuzz package's `Cargo.lock` is already ignored.
- `#![forbid(unsafe_code)]` in a fuzz target may clash with the `#[no_mangle]` that `libfuzzer_sys::fuzz_target!` expands to. Check with `cargo check` on the fuzz manifest. The library crate keeps `forbid` regardless.
- The convention wants known attacks in `docs/security/attacks/<format>.md` (`AGENTS.local.md`). That path is outside s04's Owns, and `pades.md` belongs to s14's `nacre-validate` (`docs/stories.md:247`). s04 lists its hostile cases in `crates/nacre-pdf/tests/corpus/README.md`.
- Spec versus story: ISO 32000 reads a reference to a missing object as `null`. On the paths s04 follows (`/Root`, `/AcroForm`, `/Fields`, `/Kids`, `/V`), the story wants an error. That divergence is deliberate.
- `cargo test` filters by target: `cargo test -p nacre-pdf --test <stem>` (`docs/architecture.md:80`).
- No migration, no network at test time, no other crate touched. s02 and s03 own disjoint folders.

## Open questions
- Encrypted PDFs: the story does not say. Strings, including field names, and object streams are encrypted, so s04 cannot read them without a key. The plan refuses them with a named error. Is that right for Patelle, whose input is its own unencrypted decision PDFs?
- Licences: is LGPL-2.1 test data (the DSS file) acceptable in an MIT/Apache repository, if it is listed with its licence in the README? Is the TDF statutes PDF, a public document with no stated licence, acceptable as "public"? The fallbacks are a LibreOffice AppImage export of a fictitious page, and the pyHanko files only.
- The W3C "Word" sample has later incremental edits (4 revisions, probably Acrobat) on top of Word's export. A file straight out of Word's "Save as PDF" was not found among public sources tried. Does it satisfy "produit par Word"?
- 50 MB: the brief writes "Mo". The plan reads it as 50,000,000 bytes, the SI unit, and refuses one byte more.

## Complexity
Story 3 → 3, at the top of it. The parser is the business logic. It has many states (table, stream, hybrid, linearized, object streams, predictors, inheritance) but no third party and no I/O, so not 4. The cost lies in the bound checks and the clippy denials, not in any design unknown.

## Split
Not needed.
