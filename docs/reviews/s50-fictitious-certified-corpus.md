# Review — s50-fictitious-certified-corpus

[Story](../stories.md) · [Plan](../plans/s50-fictitious-certified-corpus.md) · [Verification](../verif/s50-fictitious-certified-corpus.md)

Diff reviewed: `git diff main...story/s50-fictitious-certified-corpus`, in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 3aaafd1a5aa9bba8de15805d3bf7f89f296061d8

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s50-fictitious-certified-corpus` and held each path against `Owns: crates/nacre-pdf/tests/, crates/nacre-validate/tests/, conformance/campaign/reports/`.
- [x] Every path is inside `Owns`. The changed paths are the 270 report files under `conformance/campaign/reports/`, the test and corpus files under the two `tests/` folders, and the story's own `docs/research|plans|verif|qa/s50-…` files, which are in scope by construction.
- [x] Outside `Owns` (major): none.
- [x] Inside another running story's `Owns` (critical): none. `git worktree list` shows only the main checkout and this story's worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s50-fictitious-certified-corpus` passes (rc 0). With `Verification mode: record`, I reused the record and did not rerun `cargo test --workspace` (exit 0) or `cargo clippy --workspace --all-targets --all-features -- -D warnings` (exit 0). I read its "Not proven here": E2E and build are deferred to ship (the project has no `E2E` command), `qpdf_check_is_clean` is ignored, and the `Mary` question is open.
- [x] `po-gate qa-current s50-fictitious-certified-corpus` passes (rc 0; Surface `endpoint`, `QA stage: surfaces`). The QA report's one verified finding (`/Author Mary`) is carried to Findings below.

## Plan
- [x] Tasks 1 to 7 are all present in the diff, and nothing lies outside the plan.
  - Both old copies are deleted.
  - The new file is committed twice, byte-identical (`cmp`). Its sha256 is `5bd90785…930e`, the same in both READMEs.
  - The `FILES` row reads `[744, 9700]`, which matches `wc -c` = 9700.
  - Field expectations are repointed in corpus.rs, revision.rs, acroform.rs (`/V 11 0 R` occurs once) and validate.rs.
  - The README rows, the regeneration recipe and the dropped esig/dss credit are in place.
  - The campaign reports are regenerated: `campaign-dss.md` and `campaign-strict.md` change only the 8 `certified-*` rows each.
- [x] Run interdicts, one by one:
  - `crates/*/src/**`, every `Cargo.toml`, `campaign.rs` and `run.sh` have empty diffs.
  - Among `*.pdf`/`*.der`, only the 4 named files change.
  - No `*.key`, `*.py`, `*.csr` or `*.srl` is committed, and the new PDF holds no `PRIVATE KEY`.
  - Other stories' `docs/` are untouched.
  - No stray PDF is left in the corpus folders.
  - `word-pdfmaker-linearized.pdf` and the pyHanko credit are untouched.
  - The bench, sudo and scratch interdicts concern actions, not the diff, so I could not check them here.

## References
- [x] `Document::parse`, `signature_fields()`, `doc_mdp_level()` (`crates/nacre-pdf/src/document.rs:185`), `update().sign` / `DuplicateField` (`crates/nacre-pdf/src/revision.rs:156-163`), `validate` and `sign`: all exist and the tests use them unchanged.
- [x] Values checked on the file itself:
  - `pdfinfo` shows only Producer `pyHanko 0.38.0`: no Author and no XMP.
  - `pdfsig` shows `Certification` valid, signed by `CN=Nacre third-party signer,O=Nacre tests,C=FR`, and `Approval` not signed.
  - `/P 3` is present.
  - The tree has no blob with sha256 `17c74d6c…`.
  - Neither the old author's name nor the old file name `certified-dss` appears in any tracked blob outside `docs/`, nor in the story's own commit history.

## Rules
- [x] The `AGENTS.md` conventions are respected: test data is fictitious with its source and licence in a README, and no private key is committed.
- [x] No accepted ADR is contradicted. ADR-0028 is still exercised by `acroform.rs`.

## Tests
- [x] Floor: `po-gate floor-guard` returns 1 with 2 flags: the two deleted `certified-dss.pdf` data files. The plan names both and gives the reason (story AC1), so they are graded minor below.
- [x] Each repointed assertion pins the new file's real values (ends, field names and order, `Some(3)`, `DuplicateField "Approval"`, field `Certification` verified, `Allowed([Signature])`). None of them has one of the six empty test shapes.
- [x] No new test: 8 tests are repointed, within `Test budget` (25).
- [x] Bite 1: I disabled the duplicate-field guard (`revision.rs:160`, `&& false`). 1 test failed (`taken_field_name_is_refused`). I undid it and `git diff --exit-code` was clean.
- [x] Bite 2: I forced `doc_mdp_level` to return `Some(2)` instead of `/P` (`document.rs:236`).
  - In `nacre-pdf --test revision`, 2 tests failed, including `doc_mdp_level_reads_the_certification`.
  - In `nacre-validate --test validate`, 2 tests failed.
  - I undid it and `git diff --exit-code` was clean. The final `git status` is clean.
- [x] No test became useless.

## Neighbours
- [x] Outside `docs/`, nothing references `certified-dss` any more. `campaign.rs:329-330` walks the corpus folders by directory, so it picks up the new file without an edit.

## Lenses
Lenses run: none. No lockfile or manifest changed, and there is no server, auth or migration path or content.
- [x] There are no lens findings.

## Findings
- minor — crates/nacre-pdf/tests/corpus/real/certified-dss.pdf, crates/nacre-validate/tests/corpus/certified-dss.pdf — floor-guard flags `test-file-deleted` on both.
  The deletion is the purpose of the story (AC1). The plan names both files under "Files touched", and the new file replaces them in every test that read them.
- minor — crates/nacre-pdf/tests/corpus/real/word-pdfmaker-linearized.pdf — `/Author Mary` (Info and XMP) remains in a public W3C sample (QA finding 1, verified).
  AC4 says no file names a real person, and nobody has settled whether a lone first name in a W3C sample counts. The plan left it as an open question. It touches personal data, so the person decides, not the tracker (Law 7).

## Not verified
- The campaign rerun (AC3): the DSS bench was not started, by me or by QA. I judged only the committed reports: 0 `≠` in `campaign-dss.md`, and in `campaign-strict.md` 121 `≠` rows, all carrying a switch and the same count as on `main`. A person can confirm with `sh conformance/campaign/run.sh` on a started bench.
- Whether the 257 regenerated `campaign-bench-*.xml` differ only through the bench's new keys: their content was not compared line by line.
- `qpdf_check_is_clean`: it is `#[ignore]`d and `qpdf` is not installed. Run `cargo test -p nacre-pdf --test revision -- --ignored` where `qpdf` exists.
- QA's Not seen, "proves the same thing" as a judgement of test strength: I covered it with the review and the two bite tests above. One limit remains, which the plan states openly: the new file's page body comes from Nacre's own writer (`conformance/reference/unsigned.pdf`). Only the CMS, `/ByteRange`, `/Perms` and the fields are third-party, so "third-party document" parsing is weaker than with the old LibreOffice file.
- Historical `docs/plans|qa` of s04, s05, s14, s15 and s18 still name `certified-dss` as a path (no personal data in them). After the planned `git filter-repo`, those references point to a path that no longer exists. The lead should be aware of this before rewriting history.
- I did not run end to end or the production build: the project's `E2E` is `—`, `Build stage: ship-if-route`, and no manifest or route changed.

Max severity: minor
Ship allowed: yes
