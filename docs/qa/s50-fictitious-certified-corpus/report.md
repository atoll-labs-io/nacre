# QA — s50-fictitious-certified-corpus

[Story](../../stories.md) · [Plan](../../plans/s50-fictitious-certified-corpus.md)

Scope: the story's surface, what `git diff main...story/s50-fictitious-certified-corpus` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: `scenarios.md` of qa-drivers — surface `endpoint`, platform `lib` (of `lib, cli`; no `endpoint` row exists for `cli`)
Evidence: transcripts
Tool: Bash — a copy of the tracked files in a `mktemp -d` directory, `cargo fetch` and `cargo build --workspace --all-features` run there, a throwaway probe crate calling the public interface of `nacre-pdf`, `nacre-pades` and `nacre-validate`, plus `pdfinfo`, `pdfsig`, `openssl`, `sha256sum`, `cmp` and `git grep`
Origin: —

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| AC1 — `certified-dss.pdf` gone from both corpus folders; a third-party certified PDF (DocMDP P=3), fictitious key, one signed and one empty field, under another name, no real name in metadata or certificates | yes | as expected — both old paths absent; `certified-pyhanko.pdf` in both folders, byte-identical; Producer `pyHanko 0.38.0`, no Author/Title/Subject/Creator, no XMP; `/TransformMethod /DocMDP`, `/P 3`; `Certification` signed and valid per `pdfsig`, `Approval` not signed; the CMS carries only `CN=Nacre third-party signer` and `CN=Nacre third-party CA` (`O=Nacre tests, C=FR`) (`ac1-replacement.txt`) |
| AC2 — the new file proves the same things through the library: revisions, fields, DocMDP, third-party signature verified, signature added on the certified document | yes | as expected — revisions 744 T · 9700 T; fields `Certification` (signed) and `Approval` (empty); `doc_mdp_level` = `Some(3)`; signing into `Approval` refused with `DuplicateField`; `validate` gives digest and signature verified, no defect, `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND / PAdES BaselineB`; after `nacre_pades::sign`, `Certification` has `[Allowed([Signature])]` and no defect. Same output from both copies (`ac2-pdf-copy.txt`, `ac2-validate-copy.txt`); the eight repointed tests pass in the copy (`ac2-repointed-tests.txt`) |
| AC2 — invalid inputs | yes | as expected — truncated file: `MissingStartxref`, "no startxref statement in the last 1024 bytes"; not a PDF: `MissingHeader`; one signed byte altered: `MessageDigestMismatch`, `TOTAL_FAILED / HASH_FAILURE`, digest and signature not verified. No panic (`ac2-error.txt`, `ac2-notpdf-error.txt`, `ac2-tampered-error.txt`) |
| AC2 — READMEs give source, licence and sha256 | yes | as expected — both rows give `5bd90785…930e`, which `sha256sum` of each file matches; source "written for this repository with pyHanko 0.38.0", licence "as this repository"; regeneration recipe present (`ac1-replacement.txt`) |
| AC3 — reports no longer cite `certified-dss`; 0 differences under `dss()`, 0 unexplained under `strict()` | yes, on the committed reports | as expected — no report file named or containing `certified-dss`; `campaign-dss.md` holds 0 `≠` rows; `campaign-strict.md` holds 121 `≠` rows, none without a switch; both new files appear on `Certification`, count 1, `=` in both tables (`ac3-campaign-reports.txt`). The campaign itself was not re-run, see Not seen |
| AC4 — no file of the repository holds a real person's name (PDF metadata and corpus certificate subjects) | yes | finding 1 — certificate subjects are all `Nacre …` (`O=Nacre tests`); signers are `Nacre …`, pyHanko's `Alice` and `Lord Testerino`; the old author's surname is absent from every tracked file, text and binary, and no tracked file has sha256 `17c74d6c…`; one Author value remains whose reality the QA cannot settle (`ac4-no-real-name.txt`) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — A first name remains in the `/Author` of a corpus PDF
Severity: minor
Status: verified (the value was read twice; whether it names a real person is not something the surface shows)
Steps to reproduce:
1. From a copy of the tracked files, run `pdfinfo crates/nacre-pdf/tests/corpus/real/word-pdfmaker-linearized.pdf`.
2. Read the `Author:` line.
Capture: docs/qa/s50-fictitious-certified-corpus/ac4-no-real-name.txt: transcript
Expected: AC4 — no PDF metadata in the repository names a real person.
Observed: `Author: Mary` (W3C sample, Acrobat PDFMaker 9.0 for Word). The plan left it out of scope and the verification record lists it as an open question for the lead; it is recorded here so the person decides. Outside the scan AC4 names, `crates/nacre-pdf/tests/corpus/README.md:96` credits pyHanko's author by name (the plan keeps it on purpose).

## Not seen
- AC3, the campaign re-run — the campaign needs the DSS bench (`conformance/compose.yaml`, podman), a dependency this driver did not start and may not start; only the committed reports were read, not a fresh run's.
- AC2, "prouve la même chose" as a judgement on the tests' strength — what a test asserts is the review's concern; the QA saw the library give, on the new file, the results those tests assert.
- `qpdf_check_is_clean` — `#[ignore]`d and `qpdf` is not installed on this machine.

Tree: 3abd54478a574d3519657aa62469e1311eb9830a
QA status: complete
