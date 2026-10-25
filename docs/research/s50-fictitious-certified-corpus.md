# Research — s50-fictitious-certified-corpus

[Story](../stories.md)

## Structuring facts
- The story's assumptions hold. The old file is one blob committed twice (`sha256 17c74d6c…` for both `crates/nacre-pdf/tests/corpus/real/certified-dss.pdf` and `crates/nacre-validate/tests/corpus/certified-dss.pdf`). Its `/Author` reads a real person's full name (`pdfinfo`, in object 5 inside the first signed range). No other committed file holds that name (a case-insensitive `git grep` of the surname is empty, and a byte search of every tracked file finds only those two blobs).
- One correction of detail: the story says "données de test de DSS", the lead says "LibreOffice". Both are true: the file is esig/dss test data written by LibreOffice 5.2, RSA, under the Nowina `PKI-TEST` CA (`crates/nacre-pdf/tests/corpus/README.md:20`).
- Spike (scratch, nothing written in the worktree): pyHanko 0.38.0, run through its Python API on `conformance/reference/unsigned.pdf`, produces exactly the shape needed. It has 2 revisions, both classic tables (`[744, 9700]`). Field `Certification` is signed and certifies at `/P 3`; field `Approval` is empty and visible. Nacre reads both fields, `doc_mdp_level() == Some(3)`, and `validate` gives digest and signature verified, `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND / PAdES BaselineB`. A Nacre `sign` on top gives `Allowed([Signature])`, and reusing `Approval` gives `DuplicateField`.
- The pyHanko CLI cannot certify at `/P 3`: `pyhanko sign addsig --certify` has no permission option (`pyhanko sign addsig --help`), and pyHanko's certification default is `/P 2`. A ~15-line Python script (`MDPPerm.ANNOTATE`) is needed.
- The campaign judges every `*.pdf` under both corpus folders, named by path (`crates/nacre-validate/tests/campaign.rs:302-333`). `run.sh` wipes `conformance/campaign/reports/` and refills it from one run (`conformance/campaign/run.sh:20-28`). Removing the old rows therefore means rerunning the campaign on a started bench.

## Story
s50 replaces the third-party certified PDF of the corpus with a wholly fictitious one, so the repository holds no personal data and the lead can then strip the two old paths from history with `git filter-repo`. The ACs:
1. Both `certified-dss.pdf` copies are gone. In their place is a certified PDF (DocMDP P=3) under another name, made by a third-party tool, signed by a fictitious key, with one signed and one empty field, and with no real name in its metadata or certificates.
2. Every test that read the old file reads the new one and proves the same things: revisions, fields, DocMDP, third-party signature verified, and a signature added on a certified document. The corpus READMEs give the file's source, licence and sha256.
3. The campaign reports no longer cite `certified-dss`. The campaign stays at 0 differences under `dss()` and 0 unexplained under `strict()`.
4. No file of the repository carries a real person's name. The check covers PDF metadata and the certificate subjects of the corpus.

## Current code
Users of the old file (`git grep certified-dss`, outside `docs/{plans,qa,research}` history):

| Where | What it proves |
| --- | --- |
| `crates/nacre-pdf/tests/corpus.rs:37` (`FILES`) | `revisions_match_the_spike` (`:46`): ends `[127672, 152955]`, kinds `[T, T]`, last end = length. `catalog_and_trailer_are_read` (`:94`) |
| `crates/nacre-pdf/tests/corpus.rs:72-75` | `signature_fields_match_pdfsig` (`:59`): `signature-test` signed, `signature-test2` empty, in that order |
| `crates/nacre-pdf/tests/revision.rs:22` (`FILES`, length 10) | `every_corpus_file_takes_a_plain_revision` (`:59`), `…_signature_slot` (`:133`), `qpdf_check_is_clean` (`:435`, `#[ignore = "conformance"]`, needs `qpdf`) |
| `crates/nacre-pdf/tests/revision.rs:280-291` | `doc_mdp_level_reads_the_certification`: `Some(3)` |
| `crates/nacre-pdf/tests/revision.rs:331-339` | `taken_field_name_is_refused`: `signature-test2` → `DuplicateField` |
| `crates/nacre-pdf/tests/acroform.rs:26-45` | `signature_value_that_is_no_reference_is_reported` (ADR-0028): patches the unique `/V 40 0 R` into `/V 7` and `/V <<>>`, same length. Asserts `fields[0]` is `signature-test`, then its value is unreadable and `fields[1]` is untouched |
| `crates/nacre-validate/tests/validate.rs:23` | `const CERTIFIED_DSS = include_bytes!("corpus/certified-dss.pdf")` |
| `crates/nacre-validate/tests/validate.rs:136-145` | `third_party_signature_is_verified`: one entry, `signature-test`, no defect, digest and signature verified |
| `crates/nacre-validate/tests/validate.rs:230-238` | `signing_a_certified_p3_document_is_allowed`: Nacre `sign` → `signature-test` gets `[Allowed([Signature])]` |
| `crates/nacre-pdf/tests/corpus/README.md:20`, `:65-68` (Credits) | the row, and "esig/dss (European Commission, LGPL-2.1)" in the credits. No other nacre-pdf file comes from DSS |
| `crates/nacre-validate/tests/corpus/README.md:17` | the copy's row |
| `conformance/campaign/reports/campaign-dss.md:108-109,145-146`, `campaign-strict.md:115-116,152-153` | `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND / PAdES BaselineB` on both sides, `=` |
| `conformance/campaign/reports/campaign-crates-nacre-{validate-tests-corpus,pdf-tests-corpus-real}-certified-dss.xml` | DSS's XML report for each copy. Neither holds the name (`grep` finds no match) |

`docs/security/attacks/*.md`, `docs/decisions/*` and the source files never name the file.

## Attachment points
- New file, committed twice as identical bytes: `crates/nacre-pdf/tests/corpus/real/certified-pyhanko.pdf` and `crates/nacre-validate/tests/corpus/certified-pyhanko.pdf`. The name follows `signed-twice-pyhanko.pdf` and `signed-lta-pyhanko.pdf`.
- The test lines in the table above. Both README rows. The reports, by one `sh conformance/campaign/run.sh` run.

## Verified interfaces
- `nacre_pdf::Document::parse`, `revisions()` (`.end`, `.xref`), `signature_fields()` (`.name`, `.value`, `.value_unreadable`), `doc_mdp_level() -> Result<Option<i64>, Error>`, `update().sign(SignatureSpec { field, sub_filter, contents_len, entries })`. All were exercised by the spike probe on the new file's shape.
- `nacre_validate::validate(&[u8]) -> Result<Vec<SignatureValidation>, _>`, with fields `field`, `digest_verified`, `signature_verified`, `defect`, `later_revisions`, `report.indication()/sub_indication()/level()`. Also exercised by the spike.
- `nacre_pades::sign(&[u8], &TestSigner, DateTime)` adds an invisible field `Signature1` (spike output).
- pyHanko 0.38.0 API: `signers.SimpleSigner.load(key, cert, ca_chain_files=…)`, `fields.append_signature_field(writer, SigFieldSpec(name, box=…))`, `signers.PdfSignatureMetadata(field_name, certify=True, docmdp_permissions=MDPPerm.ANNOTATE, subfilter=SigSeedSubFilter.PADES)`, `PdfSigner(meta, signer).sign_pdf(writer, output=…)`. The spike ran it.
- The spike output's `/Info` holds only `/Producer (pyHanko 0.38.0)` and `/ModDate`. The CMS carries the leaf `CN=Nacre third-party signer,O=Nacre tests,C=FR` and the CA `CN=Nacre third-party CA,O=Nacre tests,C=FR`, both RSA-2048 and made with `openssl req`. `pdfsig` reports "Signature is Valid" and "issuer isn't Trusted".
- The unique-patch helper `patch` (`crates/nacre-pdf/tests/acroform.rs:13-21`) needs exactly one occurrence. In the spike file the signed field's `/V 11 0 R` occurs once. The implementer re-checks on the committed file.

## Traps
- **Field order matters** to `acroform.rs` (`fields[0]`, `fields[1]`) and to `signature_fields_match_pdfsig` (an exact `Vec`). With both fields appended before signing, `Certification` first, `/Fields` reads `[Certification, Approval]` and the old order (signed, then empty) is kept.
- **Stray PDFs are judged.** Any `*.pdf` left under either corpus folder becomes a campaign case (`campaign.rs:302-319`). All scratch work goes to `/home/lecrabe/.claude/jobs/4fb763d0/tmp/`.
- **A full campaign rerun rewrites every report.** The bench regenerates its keys at each start (`conformance/README.md`), so all ~257 `campaign-bench-*.xml` change content. s18 committed them the same way (`03d3cb5`). The campaign last passed on s42's previous tree (`docs/verif/s42-tsa-freshness.md:17`). Only s42 landed since the reports were committed (`git log 03d3cb5..HEAD`).
- **Bench etiquette.** The compose project is `nacre-conformance` (`conformance/compose.yaml:8`), on ports 18080/18081. `patelle-dss` is another container, on 8080. `podman compose -f conformance/compose.yaml down` never touches it. s42's plan notes that the bench may be held by another lane (s19).
- **No private key in git.** `conformance/README.md`: "No private key is committed, test keys included". The pre-commit hook refuses private keys. The keys live in scratch and are deleted after signing.
- **Not byte-reproducible.** The pyHanko signing time is the wall clock, so the README gives the recipe and the sha256, the same treatment as the browser prints (`crates/nacre-pdf/tests/corpus/README.md:23-32`).
- `qpdf_check_is_clean` is `#[ignore]`d and needs `qpdf`, which is not installed here. The full suite does not run it.
- No migration, no source change, no dependency change: pyHanko is a tool run once in scratch and never enters `Cargo.toml`.

## Open questions
- `word-pdfmaker-linearized.pdf` (W3C working example) holds `/Author Mary` in its Info and XMP. It is a first name alone, in a public W3C sample, and the same file's other records name no person. Does the lead count it under AC4? The plan leaves it as is and reports it.
- The README credits name pyHanko's author ("Matthias Valvekens, MIT"). That is the attribution MIT requires, outside AC4's scope (PDF metadata and certificate subjects), and it stays.
- Should the fictitious certificates also be committed as `.der` next to the PDF? No test needs them: they travel inside the CMS. The plan commits none.

## Complexity
2 → 2. Data and test edits, no code. The only real cost is the campaign rerun on a started bench.

## Split
—
