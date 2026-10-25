---
validated: yes
---
# Plan — s50-fictitious-certified-corpus

[Story](../stories.md) · [Research](../research/s50-fictitious-certified-corpus.md)

Branch `story/s50-fictitious-certified-corpus`. Read `docs/research/s50-fictitious-certified-corpus.md` first; this plan builds on it without repeating it.

## Story
`certified-dss.pdf` carries a real person's name in its signed `/Author`. This story replaces both copies with `certified-pyhanko.pdf`: made by pyHanko, signed by a fictitious RSA key, certified at DocMDP `/P 3`, one signed field `Certification` and one empty visible field `Approval`. After it ships, the lead removes the old paths from history.
1. Both old copies are deleted. The new file, under another name, has no real name in its metadata or certificates.
2. Every test of the old file reads the new one and proves the same things. Both READMEs give the new file's source, licence and sha256.
3. The campaign reports no longer cite `certified-dss`. The campaign stays at 0 differences under `dss()` and 0 unexplained under `strict()`.
4. No PDF metadata and no corpus certificate subject in the repository names a real person.

## Reuse
No new Rust code: the tasks repoint existing tests and replace a data file. The only new text is the pyHanko recipe in the README. It uses pyHanko's public API, because the CLI cannot set `/P 3` (research, Structuring facts).

## Tasks
1. [x] **Make the file, in scratch only** (`/home/lecrabe/.claude/jobs/4fb763d0/tmp/s50-impl/`, never the worktree or its `target/`).
   - Install pyHanko in user space, no `sudo`: `uv venv venv && VIRTUAL_ENV=$PWD/venv uv pip install pyhanko==0.38.0`.
   - Generate the fictitious keys:
     ```sh
     openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3650 -subj "/C=FR/O=Nacre tests/CN=Nacre third-party CA" -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
     openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/C=FR/O=Nacre tests/CN=Nacre third-party signer"
     printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n' > ext.cnf
     openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 3650 -extfile ext.cnf
     ```
   - Run this script with `venv/bin/python -I certify.py <worktree>/conformance/reference/unsigned.pdf certified-pyhanko.pdf .`. It takes no `--timestamp-url` and makes no network call:
     ```python
     import sys
     from pyhanko.sign import signers, fields
     from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
     from pyhanko.sign.fields import MDPPerm, SigFieldSpec
     src, out, keys = sys.argv[1:4]
     signer = signers.SimpleSigner.load(f"{keys}/leaf.key", f"{keys}/leaf.pem", ca_chain_files=(f"{keys}/ca.pem",))
     with open(src, "rb") as f:
         w = IncrementalPdfFileWriter(f)
         fields.append_signature_field(w, SigFieldSpec("Certification"))
         fields.append_signature_field(w, SigFieldSpec("Approval", box=(72, 100, 300, 150)))
         meta = signers.PdfSignatureMetadata(field_name="Certification", certify=True,
             docmdp_permissions=MDPPerm.ANNOTATE, subfilter=fields.SigSeedSubFilter.PADES)
         with open(out, "wb") as o:
             signers.PdfSigner(meta, signer).sign_pdf(w, output=o)
     ```
   - Check the output: `pdfsig` says "Signature is Valid" for `Certification` and "not signed" for `Approval`; `pdfinfo` shows no `Author`; `grep -a '/P 3'` matches. `grep -ac '/V <n> 0 R'` gives 1 for the signed field's value, and `<n>` is noted for task 3.
   - Delete `*.key` once the file is checked.
   - `git rm` both `certified-dss.pdf` copies and copy the new file to `crates/nacre-pdf/tests/corpus/real/certified-pyhanko.pdf` and `crates/nacre-validate/tests/corpus/certified-pyhanko.pdf`; `cmp` says the two are identical.
   - Test able to fail: tasks 2 to 4 all read it.
2. [x] **`crates/nacre-pdf/tests/corpus.rs`.**
   - In `FILES` (`:37`), replace the row with `("certified-pyhanko.pdf", &[<end of revision 0>, <file length>], &[T, T])`, the ends measured on the committed file (spike: `[744, 9700]`).
   - In `signature_fields_match_pdfsig` (`:72-75`), expect `[("Certification", true), ("Approval", false)]`.
   - Test able to fail: `revisions_match_the_spike`, which compares ends, kinds and length, and `signature_fields_match_pdfsig`, which compares names, order and signed state.
3. [x] **`crates/nacre-pdf/tests/revision.rs` and `acroform.rs`.**
   - Rename the entry in `FILES` (`revision.rs:22`).
   - Point `doc_mdp_level_reads_the_certification` (`:281`) at the new file, still expecting `Some(3)`.
   - Point `taken_field_name_is_refused` (`:331-339`) at the new file with `"Approval"` → `DuplicateField { name: "Approval" }`.
   - In `acroform.rs:27-44`, read `real/certified-pyhanko.pdf`, assert `fields[0].name == "Certification"`, and patch `b"/V <n> 0 R"` from task 1 (it must occur exactly once, which `patch` asserts).
   - Test able to fail: each of these four tests, run by `cargo test -p nacre-pdf --test corpus --test revision --test acroform`.
4. [x] **`crates/nacre-validate/tests/validate.rs`.**
   - Change `const CERTIFIED_DSS` (`:23`) to `CERTIFIED_PYHANKO = include_bytes!("corpus/certified-pyhanko.pdf")`.
   - `third_party_signature_is_verified` (`:136-145`): one entry, field `Certification`, `defect` none, digest and signature verified.
   - `signing_a_certified_p3_document_is_allowed` (`:230-238`): `of(&results, "Certification")` gets `[Allowed([Signature])]`.
   - Test able to fail: these two tests, `cargo test -p nacre-validate --test validate`.
5. [x] **READMEs.**
   - `crates/nacre-pdf/tests/corpus/README.md`: replace the `:20` row.
     - Source: "written for this repository with pyHanko 0.38.0 from `conformance/reference/unsigned.pdf`, see below".
     - Licence: "as this repository". sha256 of the committed file.
     - Producer: "pyHanko 0.38.0, certified (DocMDP `/P 3`), RSA, `CN=Nacre third-party signer` under `CN=Nacre third-party CA` (`O=Nacre tests,C=FR`), keys made for it and deleted".
     - Structure: "`Certification` signed, `Approval` empty and visible; revisions <e0> T · <e1> T".
   - Add a short "Regenerating `certified-pyhanko.pdf`" block with task 1's commands and script, saying that a new run gives a new hash and new offsets.
   - In the credits (`:67`), drop "esig/dss (European Commission, LGPL-2.1)", which no longer covers any file.
   - `crates/nacre-validate/tests/corpus/README.md:17`: a row "a copy of `crates/nacre-pdf/tests/corpus/real/certified-pyhanko.pdf` (see its README) …; field `Certification` signed, `Approval` empty | as this repository | <sha256>".
   - Check: `sha256sum` of each file equals its README cell, and `git grep -n certified-dss -- crates conformance` is empty apart from the reports, which task 6 handles.
6. [x] **Campaign.** On a fresh bench (`conformance/README.md`, "Run", project `nacre-conformance` only), run `sh conformance/campaign/run.sh` from the worktree. Then:
   - `campaign-dss.md` holds no `≠` row.
   - Every `≠` row of `campaign-strict.md` carries its switches.
   - Both files have rows `crates-nacre-validate-tests-corpus-certified-pyhanko` and `crates-nacre-pdf-tests-corpus-real-certified-pyhanko` on field `Certification`, with count 1.
   - `grep -rl certified-dss conformance/campaign/reports` is empty.

   Commit the run's whole output, as s18 did. Stop the bench with `podman compose -f conformance/compose.yaml down`. If the bench is held by another lane, or a row unrelated to this file differs, stop and report: that is not s50's defect. Do not fix it, and do not hand-edit the tables.
7. [x] **AC4 scan, written into `docs/verif/s50-fictitious-certified-corpus.md`.**
   - For every `git ls-files '*.pdf'`: `pdfinfo` (Author, Title, Subject, Creator), `pdfinfo -meta` (`dc:creator`) and `pdfsig` signer names.
   - For every committed `*.der`/`*.pem` certificate: `openssl x509 -noout -subject`.
   - Expected: only fictitious or public values, namely `Nacre …`, pyHanko's `Alice` and `Lord Testerino`, Nowina `good-user` (gone after this story), the IRS office code `SE:W:CAR:MP`, and the W3C sample's `Mary`, which is reported as an open question, not changed.
   - Then a case-insensitive `git grep` of the surname is empty, and no tracked file's sha256 is `17c74d6c…`.
   - Then the full suite and the type check through `po-run`.

## Scene viewpoints
—

## Run interdicts
- `crates/*/src/**`, every `Cargo.toml`, `crates/nacre-validate/tests/campaign.rs`, `conformance/campaign/run.sh`: empty diff.
- `docs/plans/`, `docs/qa/`, `docs/research/`, `docs/reviews/` of other stories: empty diff (history, no personal data).
- Every corpus file other than the two removed and the two added keeps its sha256 (`git diff --stat main... -- '*.pdf' '*.der'` lists only those four).
- No private key, no Python file, no pyHanko artefact is committed: `git diff --name-only main...` has no `*.key`, `*.py`, `*.csr`, `*.srl`.
- No `*.pdf` other than the two named is left under `crates/*/tests/corpus/`, since the campaign would judge it.
- No `sudo`. No public TSA, no online DSS demo, no `--timestamp-url`. Never stop or touch `patelle-dss` or `omniroute`; only `podman compose -f conformance/compose.yaml` acts on the bench.
- Scratch under `/home/lecrabe/.claude/jobs/4fb763d0/tmp/` only, never `/tmp` or the worktree's `target/`.
- `word-pdfmaker-linearized.pdf` and the README credit to pyHanko's author stay untouched (out of scope, see the research's open questions).

## The pivot
pyHanko's file has to keep both verdicts equal, DSS's and Nacre's: `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND / PAdES BaselineB` under `dss()`. Nacre's side is proven by the spike, DSS's is not. Ways it could be wrong:
- **DSS reads the level differently.** Possible causes are pyHanko's PAdES attributes, the CA carried in the CMS, or the direct `/Perms` dictionary where the old file had an indirect one. To check: the new rows of `campaign-dss.md`. A `≠` there is a real divergence to report, never a reason to change the file until it agrees.
- **The empty visible field changes a verdict** after Nacre signs on top. Nacre's `sign` adds an invisible new field and `Approval` already exists in the certified state, so the s15 rule should stay silent. To check: `signing_a_certified_p3_document_is_allowed` gives `[Allowed([Signature])]` with no defect.
- **The proof is weaker than before.** The old file was a whole document written by LibreOffice; the new one has Nacre's hand-written page under a pyHanko signing revision. The third-party part, the signature and its revision layout, is what the tests rely on. To check: the CMS, `/ByteRange`, `/Perms` and both fields come from pyHanko, not from Nacre's writer.

## Files touched
- Removed: `crates/nacre-pdf/tests/corpus/real/certified-dss.pdf`, `crates/nacre-validate/tests/corpus/certified-dss.pdf`.
- Added: `crates/nacre-pdf/tests/corpus/real/certified-pyhanko.pdf`, `crates/nacre-validate/tests/corpus/certified-pyhanko.pdf`.
- Edited: `crates/nacre-pdf/tests/{corpus.rs, revision.rs, acroform.rs, corpus/README.md}`, `crates/nacre-validate/tests/{validate.rs, corpus/README.md}`.
- Regenerated: `conformance/campaign/reports/*`.
- Plus: this plan, the research, `docs/verif/s50-fictitious-certified-corpus.md`.

## Test strategy
- No new test: 8 existing tests are repointed (corpus 2, revision 2 plus the `FILES` loops, acroform 1, validate 2), well within `Test budget` (25). Each still fails if its rule is removed: the measured ends, the field names and order, `/P 3`, the duplicate refusal, ADR-0028's unreadable value, the third-party verification, and the allowed signature on a certified document.
- DSS parity is checked by the campaign (task 6), not by a new conformance test.
- Per-task runs: `cargo test -p nacre-pdf --test corpus --test revision --test acroform`, then `cargo test -p nacre-validate --test validate`. Full suite and type check once at the end, through `po-run`.

## Done when
- One commit `s50-fictitious-certified-corpus: …` lands through a pull request.
- `cargo test --workspace` and the clippy check are green, and the campaign shows 0 differences under `dss()` and 0 unexplained under `strict()`.
- QA (Surface `endpoint`) and the review are passed with no open critical finding.
- No tracked file holds the old blob or the name. The lead can then run `git filter-repo` on the two old paths without breaking any test.
