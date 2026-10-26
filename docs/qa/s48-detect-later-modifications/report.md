# QA — s48-detect-later-modifications

[Story](../../stories.md) · [Plan](../../plans/s48-detect-later-modifications.md)

Scope: the story's surface, what `git diff main...story/s48-detect-later-modifications` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked. This walk follows the fix run `ec9dbd5` (review findings of fix loop 1: one test, rustdoc, `pades.md`; no library code changed since `62c3a58` apart from rustdoc in `policy.rs`) and replaces the QA of tree `5ea26620`.
Driver: scenarios.md of qa-drivers — surface endpoint, platform lib (setting `Platform: lib, cli`; the `cli` row applies only to a `command` surface)
Evidence: transcripts
Tool: Bash — the example binary `qa_s48` quoted by the previous QA, reused unchanged plus one mode `fix2`, written into a `mktemp -d` copy of `git ls-files` (no `.env*` file to copy), calling the public API of `nacre-validate` (`validate`, `validate_with_policy`, `ValidationPolicy::strict()` / `dss()`, `TrustAnchors`, `Defect`) on files on disk and on documents forged at run time from `unsigned.pdf` with `TestSigner`, `nacre_pdf::SignatureSpec` and the story's `tests/support/forge.rs`, included by `#[path]`; the program is quoted whole in `ac2-both-presets.txt`. `cargo fetch` and `cargo build --workspace --all-features` ran in the copy (exit 0). Every scenario was run twice, with identical output; the 127 verdict lines of the QA of tree `5ea26620` came back byte-identical. DSS's `pades-spoofing-replaced-reason.pdf` was read in place from the s19 spike download, outside the worktree and the copy; only its verdict lines were kept.
Origin: —

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 2. `pdf-signed-added-page.pdf` (committed DSS file) under `strict()` and `dss()` | yes | as expected — `TOTAL_FAILED` / `FORMAT_FAILURE`, `PageCountChanged { signed: 1, last: 2 }` under both (`ac2-both-presets.txt` §1) |
| 2. `pades-spoofing-replaced-reason.pdf` (not committed) under both presets | yes | as expected — `TOTAL_FAILED` / `FORMAT_FAILURE`, `SignatureDictionaryChanged` under both (`ac2-both-presets.txt` §3) |
| 2. one case per shape: the four `isa-*` attack files and the bench shapes `m1`, `m2` forged at run time | yes | as expected — page added: `PageCountChanged { 1, 2 }`; reason replaced, reason redefined, signature moved, `m2`: `SignatureDictionaryChanged`; all `TOTAL_FAILED` / `FORMAT_FAILURE` under both; the same B signature with no later revision is `TOTAL_PASSED` (`ac2-both-presets.txt` §1–2) |
| 2. boundaries — `/Count` same, real 1.0 and 1.9, 2 without a kid, 0, a name; field `/F` modified or removed, `/Rect` moved, `/T` renamed, `/TU` added, identical redefinition; signature `/M`, `/Type`, `/Location` | yes | as expected, identical to the previous walk (`ac2-both-presets-error.txt` §1) |
| 2. legitimate later revisions — `/DSS` added, a second signature, two signatures then `/DSS`; every PDF of `tests/corpus/`, `tests/corpus/chain/` | yes | as expected — no new defect, `TOTAL_PASSED` where the anchors are given (`ac2-both-presets-error.txt` §1, §3, §7) |
| 2. the 55 files of `tests/corpus/attacks/` | yes | as expected — only the four `isa-*` files give a new defect (`ac2-both-presets-error.txt` §4) |
| 2. order — a signed byte flipped, then a page-count change or a reason replacement | yes | as expected — the new defect, `FORMAT_FAILURE`, `digest_verified` false; the flipped file alone stays `HASH_FAILURE` (`ac2-both-presets-error.txt` §2) |
| 2. an unreadable object in the last revision: from the catalog of `isa-page-added`, of a kept page count, as the `/Pages` itself, from the signed field's `/TU` | yes | as expected — `PageCountChanged { 1, 2 }`, `SignatureDictionaryChanged`, `PageCountChanged { 1, 0 }`, `SignatureDictionaryChanged`, under both presets; an object absent from every xref (null by the PDF rule) passes under `dss()` (`ac2-both-presets-error.txt` §5) |
| 2. review finding of fix loop 1 — an unreadable object in the last revision on top of `isa-reason-replaced`, `isa-reason-redefined`, `isa-signature-moved`, `m2`; with a replaced `/Reason` or a moved `/Rect` in the same revision | yes | as expected — `SignatureDictionaryChanged`, `TOTAL_FAILED` / `FORMAT_FAILURE` under both presets; built independently of the committed test's helper (`ac2-both-presets-error.txt` §8) |
| 2. an allowed `/DSS` revision, then a revision whose catalog reaches an unreadable object | yes | `SignatureDictionaryChanged` under both presets, as `pades.md` now states (an unreadable object counts as a change); DSS's verdict on this shape is unknown, see `## Not seen` (`ac2-both-presets-error.txt` §8, last two lines) |
| 2. `/V` holding an array of 4 000, 70 000, 200 000 integers, then `/DSS`; the same with its last item changed | yes | as expected — `TOTAL_PASSED` after `/DSS` at every size; `SignatureDictionaryChanged` when the item changes (`ac2-both-presets-error.txt` §6) |
| 2. `/V` holding an array of 1 000, then 70 000 references, then `/DSS` | yes | 1 000: as expected; 70 000: finding 1 |
| 2. two signatures, then `/Count 2` or `Signature2`'s reason replaced | yes | as expected — both signatures `PageCountChanged`; reason: `Signature2` `SignatureDictionaryChanged` under both, `Signature1` `RevisionNotAllowed` under `strict()` and `TOTAL_PASSED` under `dss()`, its own field being unchanged (`ac2-both-presets-error.txt` §7) |
| 2. invalid input — empty, not a PDF, bytes after `%%EOF`, a revision truncated mid-way | yes | as expected — `MissingHeader` / `TrailingData`, kind `InvalidInput`, no panic (`ac2-both-presets-error.txt` §1) |
| 3. `pdf-signed-added-page.pdf` in `conformance/corpus/foreign/` with source and licence | yes | as expected — SHA-256 `467573be…a7a2ec` as the README says, byte-identical to the s19 download, esig/dss 6.5.1 path, LGPL-2.1, fictitious `PKI-TEST` signer (`ac3-corpus.txt`) |
| 3. `pades-spoofing-replaced-reason.pdf` not committed, a forged case stands in | yes | as expected — no such path in the worktree or any commit; no PDF and nothing under `conformance/` changed since `62c3a58`, the names section carried over (`ac3-corpus.txt`) |
| 3. boundary — the DSS file cut at its signed bytes; `/Count 3` | yes | as expected — cut: no defect, `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND` (no anchor); `/Count 3`: `PageCountChanged { 1, 3 }` (`ac3-corpus-error.txt`) |
| 4. `pades.md` describes each shape, with a corpus case and a rejecting test | yes | as expected — four rows, each corpus file and test present; the bound now reads 65 536 pairs, matching `MAX_PAIRS`, with the identical-pair rule and both `unreadable_object_*` tests named (previous finding 1 closed); `isa_` (6), the fix-run tests (1 + 2), `dss_added_page`, `dss_exclusions` and `policy` (14) pass in the copy (`ac4-attacks-doc.txt`) |
| 4. boundary — each `isa-*` file cut at its signed bytes | yes | as expected — no defect under either preset (`ac4-attacks-doc-error.txt`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — an allowed `/DSS` revision fails a signature whose `/V` reaches 65 536 reference pairs
Severity: minor
Status: verified
Steps to reproduce:
1. Sign `unsigned.pdf` with `TestSigner([0x11;32])` through `nacre_pdf::SignatureSpec`, the signature dictionary carrying an extra key whose value is an array of 70 000 references to the `/Pages` object (`qa_s48 big`).
2. Add a `/DSS` revision with `forge::with_dss`, then validate under `strict()` and `dss()` with that certificate as anchor.
Capture: docs/qa/s48-detect-later-modifications/ac2-both-presets-error.txt §6 (last two lines)
Expected: a `/DSS` revision changes nothing under the signed field, so the signature passes, as with 1 000 references or 200 000 integers; DSS bounds only the depth.
Observed: `TOTAL_FAILED` / `FORMAT_FAILURE`, `SignatureDictionaryChanged`, under both presets — `strict()` included, which otherwise accepts that revision. Carried from the previous QA, unchanged; `pades.md` now records it as a deliberate deviation, stricter than DSS, on an artificial shape never seen in a real file.

## Not seen
- Criterion 1, the research establishing the cause — no observable effect through the surface: it is a document, not a behaviour of the library.
- Criterion 2, « donnent le verdict de DSS », and criterion 3, the campaign at 0 differences under `dss()` and 0 unexplained under `strict()` — they need the DSS bench (`conformance/compose.yaml`), a dependency the driver did not start. Nacre's verdicts were held against the verdict the story names for these shapes, not against a running DSS; DSS's verdict on the boundaries exercised here (unreadable objects, including after an allowed `/DSS` revision; `/Count` as a real, a name or 0; `/Location`, `/Type`, `/T`, `/TU`; large `/V` subtrees) is unknown.
- The page-count rule on a page removed from a multi-page document — the forged documents start from the one-page `unsigned.pdf`; a lower count was reached only as `/Count 0` and as an unreadable `/Pages`.

Tree: 69877bfa853771632548531e76bec7873b83c7b9
QA status: complete
