# QA — s04-pdf-read

[Story](../../stories.md) · [Plan](../../plans/s04-pdf-read.md)

Scope: the story's surface, what `git diff main...story/s04-pdf-read` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli (row `endpoint` / `api, lib`)
Evidence: transcripts
Tool: Bash. A scratch binary crate called the public interface of `nacre-pdf` (`Document::parse`, `revisions`, `trailer`, `catalog_id`, `catalog`, `signature_fields`, `object`). It was built and run in a copy of the branch under `mktemp -d`. Independent cross-checks used poppler `pdfinfo` and `pdfsig` and a Python scan for `%%EOF`. The fuzz target was run with `cargo +nightly fuzz`.
Origin: —

The diff touches only `crates/nacre-pdf/` (the crate, its fuzz target, its tests and its corpus) and the story's research, plan and verification notes. There is no `docs/designs/s04-pdf-read/`. `Install` (`cargo fetch`) and `Build` (`cargo build --workspace --all-features`) both exited 0 in the copy. The probe's full source is quoted at the top of `c1-c2-real-corpus.txt`.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| C1 — an opened PDF gives its revisions (end offset of each `%%EOF`), its trailer, its catalog and its AcroForm signature fields | yes | As expected on all 10 real files: revisions, trailer keys, catalog and signature fields are returned (`c1-c2-real-corpus.txt`). Every signed range that `pdfsig` reports ends at a revision end Nacre reports (25853, 46212, 50827, 26384, 152955). The fields match `pdfsig`: `Sig1`/`Sig2` (signed twice), `Sig1` plus a document timestamp (LTA), and `signature-test` signed with `signature-test2` empty (certified). See finding 2 about the wording "each `%%EOF`". |
| C1/C2 — invalid input (no file, empty file, text file, truncated PDF) | yes | As expected: the errors name the defect (`the input does not start with %PDF-`, `no startxref statement in the last 1024 bytes`), exit 1, no panic (`c1-c2-real-corpus-error.txt`). |
| C2 — classic tables, xref streams, object streams and hybrid xref are read; the corpus holds Word, LibreOffice, Chrome print, Firefox print, PDF/A, a form and a third-party-signed PDF, all read | yes | As expected: `Table`, `Stream` and `Hybrid` revisions all appear (word-hybrid reads T, H, H, T). `pdfinfo` confirms the producers: Microsoft Word, Acrobat PDFMaker for Word, LibreOffice 7.3 (PDF/A-3) and 5.2, Chromium/Skia, Firefox/Skia, Ghostscript PDF/A-2, the IRS XFA form, and files signed by pyHanko and DSS. All 10 open with exit 0. |
| C3 — broken xref, corrupted revision or missing object → an error naming the defect; never repaired | yes | As expected on 5 crafted files and 4 corpus files. The errors are: `no cross-reference section at offset 18032`, `the cross-reference entry of 33 0 R points at offset 4112, which does not hold it`, `object 99 0 R not found`, `no cross-reference section at offset 126672` (a wrong `/Prev` into revision 0), `malformed cross-reference table at offset 152291: …`, `the document is encrypted`, `the /Prev chain loops back to offset 9` and `… /Prev is not an offset`. On four of these files poppler's `pdfinfo` rebuilds the file and reports a page, while Nacre refuses (`c3-refusals-error.txt`; the untouched originals are in `c3-refusals.txt`). See finding 1. |
| C4 — hostile input (reference loops, wrong stream length, deep nesting, over 50 MB) → bounded error, never a panic | yes | As expected, under a 1 GiB address-space cap and a 30 s time cap. Every run below exits 1 with no panic, in under 15 ms and at most 52 MB peak memory, which is the 50 MB input itself (`c4-hostile-error.txt`). A reference loop (objects 3 and 4, or `/Root` pointing to itself) gives `reference loop through object …`. A `/Kids` cycle gives `the form field tree loops through …`. A `/Length` that is too short, past the end, `i64::MAX` or -1 gives `stream 3 0 R does not end where its /Length says`. One million `[`, or 200,000 nested `<<`, gives `nest too deep`. A 200 MiB flate bomb in an xref stream gives `decodes to more than 33554432 bytes`. A 50,000,001-byte file gives `the input is 50000001 bytes, more than the 50000000 accepted`. A valid file of exactly 50,000,000 bytes opens (`c4-hostile.txt`). |
| C4 — a fuzz target exists | yes | As expected: `cargo fuzz list` prints `parse`. A 120 s run on nightly, seeded with the 14 corpus files, made 414,148 runs with no crash, timeout, out-of-memory or panic, and left no artifact (`c4-fuzz.txt`). |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — a broken xref entry outside the followed path opens without error
Severity: minor
Status: verified
Steps to reproduce:
1. Copy `crates/nacre-pdf/tests/corpus/real/chrome-print.pdf`. At byte 18062, change the xref entry of object 1 (its `/Info` dictionary) from `0000000015 00000 n ` to `0000000001 00000 n `.
2. Call `Document::parse` on it. It returns `Ok`, with one revision, the trailer, catalog `33 0 R` and 0 signature fields.
3. Call `Document::object(ObjectId::new(1, 0))`. Only now does it return `the cross-reference entry of 1 0 R points at offset 1, which does not hold it`.
Capture: docs/qa/s04-pdf-read/finding-1-xref-entry-not-checked-at-open.txt (the run and its replay)
Expected: the story says "Un PDF à xref cassée … rend une erreur qui nomme le défaut". The plan narrows this to errors "on a followed path" (`docs/plans/s04-pdf-read.md` item 3, and line 35 of the research), so the behaviour may be deliberate.
Observed: a PDF with a broken xref opens. The defect only shows if a caller later asks for that object. The same kind of broken entry on the catalog (`catalog-entry-shifted.pdf`) is refused at open. Either the story's text or the behaviour should change so the two agree.

### Finding 2 — linearized files hold one more `%%EOF` than the revisions reported
Severity: minor
Status: verified
Steps to reproduce:
1. Open `real/form-xfa-irs-w9.pdf`, `real/signed-twice-pyhanko.pdf` and `real/word-pdfmaker-linearized.pdf` with `Document::parse` and list `revisions()`.
2. Scan the same files for every `%%EOF` (the `eofs.py` scan in the transcript).
Capture: docs/qa/s04-pdf-read/c1-c2-real-corpus.txt (two runs of the probe, the scan, and the signed ranges from `pdfsig`)
Expected: the story says "liste de ses révisions (décalage de fin de chaque `%%EOF`)".
Observed: each of these files has three `%%EOF` but only two revisions. The first `%%EOF` sits at 503, 451 and 489: it closes the first-page trailer that linearized files carry (`startxref 0`). This follows the research's corrected rule ("a revision is not each `%%EOF`"), and every signed range from `pdfsig` ends at a reported revision end, so the behaviour looks right for PAdES. The story's wording no longer matches it.

## Not seen
- Behaviour under real load. Also memory near the 256 MiB total decoding budget, spread over many object streams: only one stream bomb was built, and it stops at the 32 MiB per-stream limit.
- Fuzzing longer than 120 s: the story only asks that a fuzz target exists.
- Files from Word or LibreOffice made on this machine: neither program is installed, so only the corpus's public samples were opened.

Tree: 476ab778730628ab31d3148fa1ac156f68779307
QA status: complete
