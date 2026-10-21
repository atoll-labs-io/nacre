# Review — s05-pdf-revision

[Story](../stories.md) · [Plan](../plans/s05-pdf-revision.md) · [Verification](../verif/s05-pdf-revision.md)

Diff reviewed: `git diff main...story/s05-pdf-revision`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 4aa828754337f5655489e29f06bb07676c75cc2f

## When blocked
- Failure cause: n/a, the review is not blocked
- Missing: n/a
- Required adaptation: n/a
- Next action: n/a

## Ownership
I listed the diff with `git diff --name-only main...story/s05-pdf-revision` and checked each path against `Owns: crates/nacre-pdf/`.
- [x] Every path is inside `Owns`. The 12 code paths are all under `crates/nacre-pdf/`. The rest is the story's own pipeline evidence: `docs/plans/`, `docs/research/`, `docs/verif/` and `docs/qa/s05-pdf-revision/`.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. The only other worktree is s02-conformance-harness, which owns `conformance/`, `crates/nacre-conformance/` and `.github/workflows/conformance.yml`. There is no overlap.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s05-pdf-revision` exited 0, so I reused the record and did not rerun the suite or the type check. I ran the gate as `bash .polype/hooks/po-gate.sh` because `po-gate` is not on PATH. I also checked by hand that the record's `Tree:` b5f458e… and each run tree (qpdf f559eff…, Unit suite 674960b…, Type check b7b05ae…) equal HEAD outside `docs/`. All three runs exited 0. The record's "Not proven here" section is carried into Not verified below.
- [x] `po-gate qa-current s05-pdf-revision` exited 0, and the QA `Tree:` cf9ce0f… equals HEAD outside `docs/`. QA reported three verified findings, and all three are carried into Findings. QA's `## Not seen` items are carried into Not verified.

## Plan
- [x] Tasks 1 to 7 are all present: the housekeeping and the #29 refusal test, the serializer, the plain builder, the signature slot, ranges and `embed`, the writer refusals, and the qpdf test plus the fuzz target. Nothing outside the plan was changed.
- [x] Each run interdict, checked one by one:
  - Empty diff outside the allowed paths: holds. The only extra path is the QA evidence under `docs/qa/`, which is pipeline evidence.
  - `Cargo.toml` and the `[dependencies]` of nacre-pdf: unchanged.
  - The `FILES` list and the existing tests in `corpus.rs`, `hostile.rs` and `refusals.rs`: unchanged. The changes are additions only, including one row added to the refusal list in `support`.
  - Nothing new under `tests/corpus/` apart from README rows.
  - `xref.rs`, `filter.rs`, `parse.rs` and `acroform.rs`: empty diff. `document.rs` only gains methods.
  - New objects are never put in an object stream, and the new xref stream has no `/Filter`.
  - No clock read.
  - No `unsafe`, `unwrap` or indexing in `src/`. The type check record is clean.

## References
- [x] I opened and confirmed every call the diff makes into existing code:
  - `Resolver::follow` (document.rs:189) and `Resolver::new`
  - `Document::trailer`, `catalog`, `catalog_id`, `signature_fields` and `revisions`
  - `Limits` fields (`max_depth`, `max_object_number`, `max_total_decoded`) and `MAX_INPUT_LEN`
  - `ObjectId` (`number: u32`, `generation: u16`, Display `N G R`)
  - `Dictionary` (derives `Default`, has `EMPTY`)
  - `Error` (`#[non_exhaustive]`, so the new variants are safe)
  - `Object::is_name`
  - `Parser::new(..).object()`, which the unit test uses
- [x] Values I checked against their sources:
  - `/W [1 4 2]` matches a `u32` offset and a `u16` generation.
  - Xref table entries are 20 bytes (`%010d %05d n\r\n`).
  - `BYTE_RANGE_WIDTH` is 36 bytes, enough for 10-digit numbers, while `MAX_INPUT_LEN` needs 8.
  - In `/ByteRange`, `a` is the offset of `<` and `b` is just after `>`, so the excluded range includes both delimiters, as ISO 32000 requires.
  - `/F 132` is Print plus Locked.
  - `/SigFlags 3`.
  - `/Size` covers the xref stream's own number.
  - `/Prev` is the `startxref` of the newest revision.
  - The trailer copies only `/Root`, `/Info` and `/ID`, as the research says.
  - Encrypted input is already refused at `document.rs:51`, so dropping `/Encrypt` is not a risk.

## Rules
- [x] `AGENTS.md` conventions are respected: `forbid(unsafe_code)` in the fuzz target, one fuzz target per parser, no new dependency, test data crafted at test time, English code.
- [x] No accepted ADR is contradicted. The PDF writing is Nacre's own (ADR-0001) and no new crate was added (ADR-0009).

## Tests
- [x] Floor: `po-gate floor-guard s05-pdf-revision main` exited 0, so nothing was lowered.
- [x] The assertions pin down criteria 1 to 5 and the DocMDP note. None of the six "tests that prove nothing" shapes appear: the fixtures are minimal one-page PDFs whose ids do not answer for the check under test, there are no mocks, and no `catch`.
- [x] 13 new tests (10 in `revision.rs`, 1 in `refusals.rs`, 1 unit test in `write.rs`, plus the fuzz target) against a budget of 25.
- [x] Bite results. After each change I ran only `cargo test -p nacre-pdf --test revision`, then undid it with `git checkout --`; `git diff --exit-code` was clean each time.
  - `embed` capacity guard disabled (`if false && …`): 1 failing test (`oversized_signature_is_refused_whole`).
  - DocMDP refusal neutralised (`== Some(99)`): 1 failing test (`no_change_certification_refuses_a_signature`).
  - In-place `/ByteRange` patch skipped: 1 failing test (`every_corpus_file_takes_a_signature_slot`).
  - Stream xref forced to a table: 1 failing test (`every_corpus_file_takes_a_plain_revision`).
  - `/SigFlags` setting removed (`n | 3` → `n`, new AcroForm `3` → `0`): **0 failing tests**. See Findings.
- [x] The story makes no test useless.

## Neighbours
- [x] No other crate uses `nacre-pdf` yet (I searched `crates/` for `nacre_pdf` and `nacre-pdf`). Inside the crate, the new `Document` methods are only called by `revision.rs`. `Dictionary::insert` is new. Adding variants to `Error` is safe under `#[non_exhaustive]`. `cargo fmt --all --check` exits 0.

## Lenses
Lenses run: none.
- Security: no auth, route, upload or webhook paths or content.
- Migration: none.
- Dependencies: `fuzz/Cargo.toml` changed only `rust-version` and a `[[bin]]`; no dependency entry moved.
- Performance: no server-side code.
- [x] There were no lens findings to grade.

## Findings
- major — crates/nacre-pdf/src/revision.rs:156 — Field-name validation is incomplete: `sign` only refuses a name already held by a signature field.
  It accepts the full name of an existing non-signature field, which yields two fields with the same fully qualified name. It also accepts a name containing a period, written as a top-level `/T` (revision.rs:184), which readers parse as a field nested under another. ISO 32000-1 §12.7.3.2 requires fully qualified names to be unique and forbids periods in a partial name. The output is a non-conforming PDF that qpdf accepts silently.
  This is QA finding 3, verified, with evidence in `docs/qa/s05-pdf-revision/finding-3-field-name-collision.txt`. I graded it major rather than QA's minor because the API produces a non-conforming file without any error.
  Fix: refuse a `.` in `spec.field`, and check the name against every terminal field name, not only signature fields. That needs the AcroForm walk to list all field names.
- minor — crates/nacre-pdf/src/revision.rs:150 — An oversized slot request is refused with `Error::TooLarge`, whose message says "the input is N bytes".
  N is the computed output size, or `usize::MAX` after an overflow, so the message misstates the input size. This is QA finding 1, verified. A dedicated variant, or wording that names the slot, would fix it.
- minor — crates/nacre-pdf/src/revision.rs:171 — `sub_filter` is written unchecked.
  An empty value or a leading slash (`/#2FETSI.CAdES.detached`) passes and produces a signature no validator recognises. This is QA finding 2, verified. Either refuse an empty value or a leading `/`, or document that the value is not checked.
- minor — crates/nacre-pdf/src/revision.rs:385 — No test reads `/SigFlags`.
  Removing both the `| 3` merge and the `3` on a new AcroForm failed none of the 9 tests in `revision.rs`. The plan's task 4 asks for "`/SigFlags` OR 3", so this rule is untested. An assertion in `field_joins_every_acroform_shape` (fixture `indirect_fields` starts at `/SigFlags 1`) would cover it.
- minor — crates/nacre-pdf/src/document.rs:141 — `Document::follow` builds a fresh `Resolver` on every call, each with the full `max_total_decoded` budget and an empty object-stream cache.
  The writer calls it at each page-tree level (up to 64) and at each level of the DocMDP and AcroForm walks. On a hostile file, the same object stream can therefore be decoded again and again, each time within its own budget, instead of being decoded and charged once as s04's resolver intends. The total stays bounded but grows with the number of calls. Potential impact. Fix: share one resolver, or one shared budget, per `sign` call.
- minor — crates/nacre-pdf/src/write.rs:68 — The writer's depth bound uses `Limits::DEFAULT.max_depth` instead of the document's own `limits()`.
  The plan says `Limits::max_depth`. The behaviour is the same today, but a test built with smaller limits would not reach this guard.

## Not verified
- I did not rerun `qpdf_check_is_clean` (`#[ignore = "conformance"]`). Its only evidence is the one local `po-run` row, with qpdf from `/tmp/s05-qpdf`; no CI workflow installs qpdf yet. A person should get s02's `conformance.yml` (ADR-0007) to install qpdf, so `cargo test -- --ignored` covers it in CI.
- The `revision` fuzz target ran 30 s locally with no seed corpus (from the verification record), so it rarely reached `sign`. QA did not run it. A seeded run should be added, from the corpus files, so `sign`/`embed` are reached, and the CI fuzz job checked.
- No full viewer has opened the outputs; none is installed. Adobe Acrobat was not available to QA, and validity was judged by qpdf, poppler `pdfsig` and Nacre's reader (QA Not seen). A person should open a signed output in Acrobat Reader once.
- A hybrid newest revision other than `word-hybrid.pdf` was not tested: it is the only such case in the corpus (QA Not seen). Hybrid → table rests on the research spike and ISO 32000-1 §7.5.8.4.
- Behaviour near the 50 MB bound with a real large file was not tested; it was reached only through the slot size (QA Not seen).
- Signature validation of a real CMS is out of scope here (s14). QA's OpenSSL/pdfsig check is the only cross-check.
- I did not test the case where `/Fields` and a page's `/Annots` are the same indirect array, or where the caller calls `set_catalog(b"AcroForm", …)` before `sign`. I only read the code: the field would be listed once, from the second rewrite. Neither case is tested.

Max severity: major
Ship allowed: yes
