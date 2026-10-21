# Review — s04-pdf-read

[Story](../stories.md) · [Plan](../plans/s04-pdf-read.md) · [Verification](../verif/s04-pdf-read.md)

Diff reviewed: `git diff main...story/s04-pdf-read`, read by a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 25dbdb61f858f66cd4f6205cf1bf59304089c34d

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-status main...story/s04-pdf-read` and held each path against `Owns: crates/nacre-pdf/` (`docs/stories.md:72`).
- [x] Every path is inside `Owns`. All code, test, corpus and fuzz paths sit under `crates/nacre-pdf/`. The other paths are this story's own pipeline evidence: `docs/research/s04-pdf-read.md`, `docs/plans/s04-pdf-read.md`, `docs/verif/s04-pdf-read.md` and `docs/qa/s04-pdf-read/*`.
- [x] Nothing is outside `Owns`.
- [x] Nothing is inside another running story's `Owns`. The running worktrees are s02 (`conformance/`, `crates/nacre-conformance/`, `.github/workflows/conformance.yml`) and s03 (`crates/nacre-cms/`, `docs/security/attacks/cms.md`); s03 is not merged into main. Neither overlaps. s05 also owns `crates/nacre-pdf/`, but it has no worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s04-pdf-read` (run as `.polype/hooks/po-gate.sh`, because `po-gate` is not on PATH) exited 0.
  - With `Verification mode: record`, I reused the record: `cargo test --workspace` exit 0, and `cargo clippy --workspace --all-targets --all-features -- -D warnings` exit 0 on its last run.
  - Its "Not proven here" says three things: there was no local libFuzzer run, `fmt` has no po-run row, and the revision rule is proven on 10 files only.
- [x] `po-gate qa-current s04-pdf-read` exited 0. The QA report (`docs/qa/s04-pdf-read/report.md`, `QA status: complete`) is current. Its two verified findings are carried into Findings below, and its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1 to 9 are all present and match their descriptions. I found nothing outside the plan.
- [x] Each run interdict, checked one by one:
  - **Paths:** the diff stays within the allowed list. The root `Cargo.toml`, `.gitignore`, workflows, `nacre-core`, `docs/security`, `docs/stories.md` and `docs/architecture.md` are untouched.
  - **Dependencies:** only `thiserror` 2 and `miniz_oxide` 0.9 in the library, and `libfuzzer-sys` 0.4 in the fuzz crate. None of `lopdf`, `pdf`, `flate2`, `nom`, `regex` or `memchr`.
  - **No repair:** I grepped for `windows(`, `.find(`, `rfind` and `position(`.
    - `xref.rs:141-155` is the single backward `startxref` lookup, inside `tail` (the last 1,024 bytes), plus the whitespace check after `%%EOF`.
    - `object.rs:63` is a dictionary key lookup, not an input scan.
    - There is no `endstream` search: `parse.rs` trusts `/Length` exactly.
  - **No allocation sized by unchecked input:** `filter.rs:132-133` sizes its `with_capacity` and `vec![0; row_len]` only after `stride > data.len()` is refused, so both are bounded by decoded data that is already capped at 32 MiB.
  - **The grep for `unsafe|println|eprintln|std::(fs|net)|SystemTime` in `src`** finds only `lib.rs:1` (`#![forbid(unsafe_code)]`).
  - **No mutation:** `Document` exposes no mutation, and nothing reads content streams, pages or text.
  - **No real personal documents:** `pdfsig` on the signed corpus files shows only test identities (good-user / Nowina PKI-TEST, Lord Testerino, Alice @example.com).

## References
- [x] I opened every import, call, API and configuration key and confirmed it.
  - In the registry sources for `miniz_oxide` 0.9.1: `decompress_to_vec_zlib_with_limit(&[u8], usize) -> Result<Vec<u8>, DecompressError>` (`inflate/mod.rs:195`), `DecompressError.status: TINFLStatus` (`:105`) and `TINFLStatus::HasMoreOutput`.
  - `libfuzzer_sys::fuzz_target!` builds under `#![forbid(unsafe_code)]`: QA ran `cargo fuzz` with it.
  - Workspace lints: the root `Cargo.toml` `[workspace.lints.clippy]` denies `unwrap_used`, `expect_used`, `panic` and `indexing_slicing`, and the crate has `[lints] workspace = true`.
- [x] Values checked against their sources:
  - 50,000,000 bytes comes from the story ("plus de 50 Mo").
  - 8,388,607 is the ISO 32000-1 Annex C limit.
  - 1,024 bytes is the tail where `%%EOF` must lie.
  - 20-byte xref entries come from ISO 32000-1 7.5.4.
  - A width-0 type field defaulting to type 1 is 7.5.8.2.
  - Hybrid lookup order (section table, then `/XRefStm`, then `/Prev`) is 7.5.8.4. I checked it on `word-hybrid.pdf`: 61 objects marked free in table 79740 are found through section 81959's `/XRefStm 79271`.
  - A probe that resolves every object of every real corpus file shows no error other than genuinely free entries.

## Rules
- [x] `AGENTS.md` conventions are respected, except that the fuzz crate lacks `rust-version` (minor, below). The rest holds:
  - one `thiserror` enum, returned and never logged;
  - no clock read and no network;
  - `forbid(unsafe_code)`;
  - "Experimental" at the top of the rustdoc;
  - a corpus README with sources and licences;
  - a fuzz target in `crates/nacre-pdf/fuzz/`;
  - `Cargo.lock` ignored at the root.
- [x] No accepted ADR is contradicted: ADR-0001 (Nacre writes the reader, no repair), ADR-0003, ADR-0008 and ADR-0009.

## Tests
- [x] Floor: `po-gate floor-guard s04-pdf-read main` exited 0, so nothing was lowered. It printed two harmless warnings, about NUL bytes and locale, caused by the binary corpus files.
- [x] The assertions pin down criteria 1-4 with exact variants, offsets, revision ends and field names. I found none of the six empty test shapes. The real corpus files are real input, and the builder writes correct offsets and corrupts one thing per case.
- [x] There are 23 tests (3 unit, 3 corpus, 8 refusals, 9 hostile), within `Test budget` 25.
- [x] Bite:
  - **xref `/Prev` loop guard** (`xref.rs:69`, `if !visited.insert(offset)` changed to `… && false`): `--test hostile` gives 1 failing test (`xref_prev_loop_is_refused`). Undone; `git diff --exit-code` is clean.
  - **Revision end includes the EOL after `%%EOF`** (`xref.rs:104`, `p.eol()` commented out): `--test corpus` gives 1 failing test (`revisions_match_the_spike`). Undone; clean.
  - **Revision rule `chain.contains(&y)`** (changed to `true || …`): 0 failures. This change makes no difference, because `filter_map` over chain sections already drops any offset that is not a chain section. It is not a finding. Undone; clean.
  - **Object identity at an xref offset** (`document.rs:189`, `p.object_header() != Some(id)` changed to `.is_none()`): `--test refusals --test hostile` gives **0 failing tests**. Undone; clean. This is a finding (below).
- [x] No existing tests were made useless: the crate is new.

## Neighbours
- [x] The crate is new and nothing else in the workspace calls it yet. The future facade `nacre-sig` and s05 do not exist yet.

## Lenses
Lenses run: dependencies — triggered by `crates/nacre-pdf/Cargo.toml` and `crates/nacre-pdf/fuzz/Cargo.toml`, which add `thiserror`, `miniz_oxide` and `libfuzzer-sys`.
- [x] Each lens finding is graded on the scale and listed under Findings.
  - One dependency per need, each named and justified in the plan.
  - `thiserror` matches `nacre-core`'s.
  - No lockfile is committed.
  - Build scripts: `thiserror` and `libfuzzer-sys` both have a `build.rs`, and no record says they were read (minor, below).

## Findings
- major — crates/nacre-pdf/src/document.rs:189 — No test covers the rule "the bytes at a type-1 offset must start with `N G obj` of that very id". Weakening the check to "any object header" fails no test in `refusals.rs` or `hostile.rs`.
  - `xref_entry_pointing_elsewhere_is_refused` shifts the offset by 3 bytes, into the middle of the header. The header parse fails there whatever the id comparison says, so the test passes with or without the identity check.
  - The code itself is correct today. But if the comparison regressed, an xref entry pointing at another object's valid header would silently return the wrong object, for example a wrong catalog or a wrong signature dictionary.
  - Fix: make the builder's shift land exactly on the neighbouring object's offset (e.g. object 1's entry points at object 2's `2 0 obj`), and assert `ObjectMismatch { object: 1 0 R }`.
- minor — crates/nacre-pdf/src/document.rs:36 — QA finding 1 (verified). A broken xref entry off the followed path is not refused at open: `chrome-print.pdf` with object 1's entry rewritten to offset 1 still parses `Ok`, and only `object(1 0 R)` fails.
  - The plan (Story item 3, "on a followed path") and the research narrow the story's "Un PDF à xref cassée … rend une erreur" on purpose. The story text and the behaviour should be brought into agreement.
  - Evidence: `docs/qa/s04-pdf-read/finding-1-xref-entry-not-checked-at-open.txt`.
- minor — crates/nacre-pdf/src/xref.rs:91 — QA finding 2 (verified). Linearized files (`form-xfa-irs-w9.pdf`, `signed-twice-pyhanko.pdf`, `word-pdfmaker-linearized.pdf`) have three `%%EOF` but report two revisions.
  - This is the research's corrected rule, and every `pdfsig` signed range ends at a reported revision end.
  - The story's wording "décalage de fin de chaque `%%EOF`" no longer matches and should be updated.
- minor — crates/nacre-pdf/fuzz/Cargo.toml:1 — The fuzz crate declares `edition = "2024"` but no `rust-version = "1.97"`. AGENTS.md (ADR-0003) asks for "Edition 2024, `rust-version = "1.97"` in every crate". The plan's task 9 did not list it either.
- minor — crates/nacre-pdf/Cargo.toml:13 — Dependencies lens: no record says the build scripts of the added dependencies were read. `thiserror` 2 has a `build.rs` (rustc probing); `libfuzzer-sys` 0.4 has one that compiles vendored libFuzzer. Both are standard and chosen by ADR, but the plan and research are silent on it.

## Not verified
- **Fuzzing beyond QA's 120 s run** (414,148 runs, no crash). The verification record ran no local libFuzzer session. A person should let CI's 60 s fuzz job run, and fuzz longer before removing "Experimental".
- **(QA Not seen) Behaviour under real load, and memory near the 256 MiB per-parse decode budget** spread over many object streams. Only one 200 MiB flate bomb was built, and it stops at the 32 MiB per-stream cap. No test reaches the per-parse budget through `Document::parse`: only the unit test with small `Limits` does. A person should build a file with nine or more object streams of about 30 MiB each and confirm `DecodedTooLarge`.
- **(QA Not seen) Word or LibreOffice files made on this machine**: neither program is installed, so only the corpus's public samples were read.
- **(QA Not seen) Fuzzing longer than 120 s**: the story only asks that a target exists.
- **The revision rule on producers outside the 10-file corpus**, the plan's pivot: Acrobat incremental saves on linearized files, and junk between `endobj` and `startxref`. A person should add signed files from other producers and compare their `pdfsig` ranges with `revisions()`.
- **The unit suite, type check and `cargo fmt`** were not rerun: I relied on the record, as `Verification mode: record` allows. The end-to-end suite and the build were not run: the project has no `E2E` command, and the build is deferred to ship (`Build stage: ship-if-route`; no route or manifest of an existing crate changed).
- **No `docs/security/attacks/pdf.md`** lists the PDF attacks. The corpus README's hostile table holds them, and `docs/security/attacks/pades.md` belongs to s12. I did not judge whether the per-format attacks convention expects a PDF file of its own; a person should decide whether s05 or s12 carries it.
- **Bite tests not run** on the depth guard, the `/Length` exactness, the decode caps and the AcroForm `/FT` inheritance. I only read those; the tests that name them assert exact variants.

Max severity: major
Ship allowed: yes
