---
validated: yes
---
# Plan — s14-validate-integrity

[Story](../stories.md) · [Research](../research/s14-validate-integrity.md)

Branch `story/s14-validate-integrity`. Read `docs/research/s14-validate-integrity.md` first; this plan builds on it without repeating it.

No technical choice is left open: the crate is in the architecture map, every dependency is already in the workspace (ADR-0001, ADR-0004, ADR-0008), errors follow ADR-0012, and the report type is `nacre-core`'s. The reserved ADR-0014 is not used.

Validated autonomously (`Plan validation: autonomous`): no human reviewed this plan. Criterion 1 → task 3 (`s06_signature_is_verified_but_indeterminate`, `third_party_signature_is_verified`, the hash and signature failure tests); 2 → task 3, checks 5–9, and task 5 (`byterange-*` cases); 3 → tasks 4 and 5 (`usf-*`, `swa-wrapped`, `isa-*`); 4 → task 7; 5 → task 6 and the `Err` path of task 3.

## Story
`validate` proves that each PAdES signature covers the document and is cryptographically valid. Chain, revocation and level stay with s16–s18, so a sound signature ends `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, never `TOTAL_PASSED`.
1. A PDF signed by s06 → one `ValidationReport` per signature, digest and signature verified.
2. A `/ByteRange` not covering the whole file except `/Contents`, overlapping, or outside the file → `TOTAL_FAILED` with its EN 319 102-1 sub-indication.
3. USF, SWA and ISA cases of `crates/nacre-validate/tests/corpus/attacks/` all rejected.
4. `docs/security/attacks/pades.md` lists every published attack on signed PDFs, each with its corpus case and the story rejecting it.
5. Hostile input → an error, never a panic; a fuzz target exists.

**Read literally, criterion 2 rejects every signature followed by a later revision** (research, fact 4). s14 does exactly that, behind one `Defect::LaterRevision` branch that s15 replaces with its qualification of revisions. Until s15, the first signature of a legitimately twice-signed PDF is `TOTAL_FAILED`, where DSS says `TOTAL_PASSED`: never a false valid.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Reading revisions, fields, `/Sig` dictionaries | already here: `Document::{parse, revisions, signature_fields, object}` `crates/nacre-pdf/src/document.rs:37,86,107,112` | — |
| CMS parse and verification against the range digest | already here: `SignedData::{from_der, verify_detached_digest}` `crates/nacre-cms/src/model.rs:84`, `crates/nacre-cms/src/verify.rs:55` | — |
| The per-signature verdict | already here: `ValidationReport::{failed, indeterminate}` `crates/nacre-core/src/report.rs:143-165` | — |
| `SignatureValidation` (field, report, two verified flags, defect) | new code | `ValidationReport` is frozen and holds no flags (`report.rs:136-140`); nothing else names a signature's integrity facts |
| `/ByteRange` and gap checks | new code | nothing in the repository validates a range; `nacre-pdf` only writes one (`revision.rs:212-215`) |
| Cutting the zero padding after the DER | installed dependency `der` 0.8 (`Header::decode`, as `crates/nacre-pades/tests/sign.rs:84-86`) | `nacre-cms` refuses trailing bytes (`model.rs:390-398`) and has no public cut |
| SHA-256 of the two ranges | installed dependency `sha2` 0.11 | `std` has no SHA-256 |
| Hex decoding of the gap | new code, a few lines | no hex decoder is a dependency; `nacre-pdf`'s hex reader is crate-private |
| Attack corpus | already here as a pattern: `crates/nacre-cms/examples/forge_attacks.rs`, writing with `Update` `crates/nacre-pdf/src/revision.rs:98-136` and `nacre_pades::sign` | — |

## Tasks
1. [x] **Crate and error.** `crates/nacre-validate/Cargo.toml`: edition 2024, `rust-version = "1.97"`, MIT OR Apache-2.0, `[lints] workspace = true`; dependencies `nacre-core`, `nacre-pdf`, `nacre-cms` (path + `version = "0.1.0"`), `sha2 = "0.11"`, `der = { version = "0.8", features = ["alloc"] }`, `thiserror = "2"`; dev-dependencies `nacre-core` with `test-signer`, `nacre-pades` (path), `der`. `src/lib.rs`: `#![forbid(unsafe_code)]`, crate doc saying **experimental**, what s14 judges and that the final indication stays `INDETERMINATE` until s16. `src/error.rs`: `#[non_exhaustive] enum Error { Pdf(#[from] nacre_pdf::Error), TooManySignatures { count: usize, max: usize } }`, `kind()` delegating for `Pdf`, `InvalidInput` for the cap. Test: `every_variant_has_its_kind` (unit, table), fails if a variant maps to the wrong kind.
2. [x] **Result types and the CMS mapping.** `src/report.rs`: `#[non_exhaustive] pub struct SignatureValidation { pub field: String, pub report: ValidationReport, pub digest_verified: bool, pub signature_verified: bool, pub defect: Option<Defect> }` (no `Clone` needed) and `#[non_exhaustive] pub enum Defect { NotASignatureDictionary, UnsupportedSubFilter, ContentsMissing, ByteRangeMalformed, ByteRangeNotFromStart, ByteRangeOverlap, ByteRangeOutsideFile, GapNotContents, ByteRangeNotWholeFile, LaterRevision, ContentsNotDer, Cms(nacre_cms::Error) }`; every structural defect gives `TOTAL_FAILED` `FORMAT_FAILURE`. One private function maps a `nacre_cms::Error` to its report (table below), and one fact — the error comes after the digest check (`verify.rs:104-117`) — sets `digest_verified` for `SignatureInvalid`. Test: `every_cms_error_has_its_outcome` (unit, table over every listed variant), fails if one mapping row is wrong.

   | `nacre_cms::Error` | Report |
   | --- | --- |
   | `MessageDigestMismatch`, `DigestLength` | `TOTAL_FAILED` `HASH_FAILURE` |
   | `SignatureInvalid`, `AlgorithmMismatch` | `TOTAL_FAILED` `SIG_CRYPTO_FAILURE` |
   | `SignerCertificateNotFound`, `SigningCertificateMismatch` | `INDETERMINATE` `NO_SIGNING_CERTIFICATE_FOUND` |
   | `UnsupportedAlgorithm` | `INDETERMINATE` `CRYPTO_CONSTRAINTS_FAILURE_NO_POE` |
   | every other variant, and `_` (the enum is `#[non_exhaustive]`) | `TOTAL_FAILED` `FORMAT_FAILURE` |

3. [x] **`pub fn validate(pdf: &[u8]) -> Result<Vec<SignatureValidation>, Error>`** in `src/validate.rs`, through a private `validate_with(pdf, max_signatures)` (`MAX_SIGNATURES = 64`, its reason in one comment: it bounds hashing to 64 × 50 MB). `Document::parse` failure → `Err(Pdf)`. For each field of `signature_fields()` in tree order: no `/V` → skipped (not a signature); `/SubFilter /ETSI.RFC3161` → skipped (a document timestamp, judged by s18); more than the cap among the rest → `Err(TooManySignatures)` before any hashing. Then the checks run in this fixed order, the first failure giving its `Defect` (the order is part of the contract: each corpus case must reach its own rule — say so in one comment):
   1. `/V` resolves (`Document::object`) to a dictionary, else `NotASignatureDictionary`;
   2. `/SubFilter` is `/ETSI.CAdES.detached` or `/adbe.pkcs7.detached`, else `UnsupportedSubFilter`;
   3. `/Contents` is a non-empty string (one reference followed with `Document::object`), else `ContentsMissing` (absent, `null`, other type, empty);
   4. `/ByteRange` (one reference followed) is an array of exactly four integers, each `usize::try_from` ok, else `ByteRangeMalformed`;
   5. `[a, b, c, d]` (signed ranges `a..a+b` and `c..c+d`): `a == 0`, else `ByteRangeNotFromStart`;
   6. `b <= c` (`a` is 0 by now), else `ByteRangeOverlap`;
   7. `c + d` (checked) `<= pdf.len()`, else `ByteRangeOutsideFile`;
   8. `pdf[b..c]` is `<`, an even run of hex digits (either case, no whitespace), `>`, and its decoding equals the `/Contents` bytes, else `GapNotContents`;
   9. `c + d` equals some `Revision.end`, else `ByteRangeNotWholeFile`;
   10. that end is the last revision's (`pdf.len()`), else `LaterRevision` — the single branch s15 replaces;
   11. `/Contents` starts with one DER TLV (`der::Header`) and every byte after it is zero, else `ContentsNotDer`;
   12. SHA-256 of `pdf[0..b]` and `pdf[c..c+d]`, `SignedData::from_der` then `verify_detached_digest`; an error → `Cms(e)` and the task-2 mapping; success → `digest_verified` and `signature_verified` true, report `ValidationReport::indeterminate(NoCertificateChainFound, None)`.
   Every slice through `get`, every sum through `checked_add`. Copy `crates/nacre-pades/tests/corpus/unsigned.pdf` and `crates/nacre-pdf/tests/corpus/real/certified-dss.pdf` into `crates/nacre-validate/tests/corpus/`, with `README.md` giving source, licence and sha256. Tests in `tests/validate.rs` (signer `TestSigner::from_secret(&[0x11; 32])`, time 2026-10-22T08:00:00Z):
   - `s06_signature_is_verified_but_indeterminate`: `nacre_pades::sign(unsigned.pdf)` → one entry, field `Signature1`, both flags true, no defect, `INDETERMINATE` `NO_CERTIFICATE_CHAIN_FOUND`, level `None`. Fails if the range is hashed wrong, the padding cut is wrong, or a `TOTAL_PASSED` slips out.
   - `third_party_signature_is_verified`: `certified-dss.pdf` (RSA, LibreOffice) → exactly one entry (`signature-test`; the empty `signature-test2` skipped), both flags true. Fails if the checks only fit Nacre's own layout.
   - `changed_signed_byte_is_hash_failure`: the s06 PDF with one byte of the page's content stream changed (inside the first signed range) → `TOTAL_FAILED` `HASH_FAILURE`, `digest_verified` false, `defect` `Cms(MessageDigestMismatch)`.
   - `altered_signature_value_is_sig_crypto_failure`: the s06 PDF with the last hex digit of the DER inside `/Contents` changed (the end of the ECDSA `s`) → `TOTAL_FAILED` `SIG_CRYPTO_FAILURE`, `digest_verified` true, `signature_verified` false.
   - unit test `signatures_over_the_cap_are_refused`: a twice-signed s06 PDF through `validate_with(pdf, 1)` → `Err(TooManySignatures { count: 2, max: 1 })`.
4. [x] **Forge.** `examples/forge_attacks.rs`, header and determinism as `crates/nacre-cms/examples/forge_attacks.rs:1-12`, run as `cargo run -p nacre-validate --example forge_attacks -- crates/nacre-validate/tests/corpus/attacks`. Base `B` = `nacre_pades::sign(unsigned.pdf)` as in task 3. A **range forge** takes `Update::sign` on `unsigned.pdf`, `embed(&[])`, rewrites the fixed-width `/ByteRange` text in place (spaces keep the width, `revision.rs:570-582`), hashes the forged ranges where they lie in the file, then writes the CMS hex after `<`: correctly signed apart from its one defect. A **hand dictionary** is an `Update` on `unsigned.pdf` adding a `/Sig` dictionary, a `/FT /Sig` field whose `/V` names it, and `set_catalog(b"AcroForm", …)` with `/Fields` and `/SigFlags 3`. Ranges below are in `PreparedSignature::byte_range` notation, `[0, a, b, c]` with the gap `a..b` (`revision.rs:496-500`). Files, each with the defect its test expects:

   | File | How | Expected |
   | --- | --- | --- |
   | `usf-contents-missing.pdf` | hand dictionary without `/Contents` | `ContentsMissing` |
   | `usf-contents-null.pdf` | `/Contents null` | `ContentsMissing` |
   | `usf-contents-empty.pdf` | `/Contents <>` | `ContentsMissing` |
   | `usf-contents-zeros.pdf` | `Update::sign`, `embed(&[])`: slot left zero | `ContentsNotDer` |
   | `usf-byterange-missing.pdf` | hand dictionary, `/Contents` = B's DER, no `/ByteRange` | `ByteRangeMalformed` |
   | `usf-byterange-null.pdf` | same, `/ByteRange null` | `ByteRangeMalformed` |
   | `usf-byterange-short.pdf` | same, three integers | `ByteRangeMalformed` |
   | `byterange-not-from-start.pdf` | range forge `[1, a-1, b, c]` | `ByteRangeNotFromStart` |
   | `byterange-overlap.pdf` | range forge `[0, b+1, b, c]` | `ByteRangeOverlap` |
   | `byterange-outside-file.pdf` | range forge `[0, a, b, c+1]` | `ByteRangeOutsideFile` |
   | `byterange-not-whole-file.pdf` | range forge `[0, a, b, c-7]` (the last `%%EOF` line unsigned) | `ByteRangeNotWholeFile` |
   | `swa-wrapped.pdf` | range forge `[0, a, b+k, c-k]`: the gap swallows the `>>` and following bytes, room an attacker fills | `GapNotContents` |
   | `isa-appended-revision.pdf` | `B` + one `Update`: a new content stream, page and page tree, `set_catalog(b"Pages", …)`, `finish` | `LaterRevision` |
   | `isa-no-xref.pdf` | `B` + an object appended after `%%EOF`, no section, no trailer | `Err(Pdf(TrailingData))` |

   Corpus `README.md` section `attacks/`, as `crates/nacre-cms/tests/corpus/README.md:33-45`. Check: the example runs twice to identical files (`sha256sum`), noted in the verification record.
5. [x] **Rejecting tests**, `tests/attacks.rs`, one per file of task 4 (14), each asserting the expected `Defect` and `TOTAL_FAILED` `FORMAT_FAILURE` (the `isa-no-xref` test asserts the error and `kind() == InvalidInput`). Named `<case>_is_rejected` in snake case; each fails if its rule, or the check order, is removed.
6. [x] **Hostile input and fuzzing.** `tests/hostile.rs`, `truncated_and_flipped_inputs_never_panic`: for the s06 PDF and every attack file, each prefix at a stride of 97 bytes and each byte flipped to `0xFF` at the same stride go through `validate`; the test only needs to return. `fuzz/` as `crates/nacre-cms/fuzz/` (own `[workspace]`, `.gitignore`), target `validate` calling `nacre_validate::validate(data)`.
7. [x] **Attack sheet** `docs/security/attacks/pades.md`, in French, shaped as `docs/security/attacks/cms.md`: format, corpus, regeneration command, check order; one row per published attack — USF, SWA, ISA (Mladenov, Mainka, Meyer zu Selhausen, Grothe, Schwenk, *1 Trillion Dollar Refund*, CCS 2019), shadow hide / replace / hide-and-replace (Mainka, Mladenov, Rohlmann, NDSS 2021), EAA and SSA on certified PDFs (Rohlmann, Mladenov, Mainka, Schwenk, *Breaking the Specification: PDF Certification*, IEEE S&P 2021) — with case file, test, story and result; the shadow, EAA and SSA rows say "s15", case "à écrire par s15". A "Hors de ce fichier" section: chain (s16), revocation (s17), document timestamps skipped until s18, and the provisional `LaterRevision` rule. Check: every corpus file appears in a row and every row of s14 names an existing test (`grep`).
8. [x] **Full suite and type check**, once, after the last edit: `po-run --story s14-validate-integrity --label test -- 'cargo test --workspace'` and `--label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`; `cargo fmt --all --check` before the commit.

## Scene viewpoints
—

## Run interdicts
- `git diff main...story/s14-validate-integrity -- Cargo.toml rust-toolchain.toml .github crates/nacre-core crates/nacre-pdf crates/nacre-cms crates/nacre-pades crates/nacre-conformance conformance docs/stories.md` is empty.
- No `[workspace.dependencies]`; no dependency outside those of task 1 (`grep -A20 '\[dependencies\]' crates/nacre-validate/Cargo.toml`).
- `grep -rn 'ValidationReport::passed\|TotalPassed' crates/nacre-validate/src` finds nothing: s14 never passes a signature.
- No clock, network, stdout, stderr or logger in `crates/nacre-validate/src` (`grep -rn 'SystemTime\|Instant\|println\|eprintln\|std::net' crates/nacre-validate/src` empty).
- No `unwrap`, `expect`, `panic!` or indexing outside `#[cfg(test)]`, tests and the example (clippy denies them).
- No pdf-insecurity.org sample or real identity committed: every corpus file is forged by the example or copied from a corpus already in the repository, with its source in the README.
- `Cargo.lock` stays untracked.

## The pivot
Integrity rests on four byte invariants — `a == 0`, the gap is exactly the `/Contents` hex string, `c + d` is a revision end, and that end is the file's end — after which every byte the parser reads outside the gap is signed, so the `/Sig` dictionary, its `/ByteRange` and its `/Contents` are the signer's. How it could be wrong:
- **The gap rule is too strict for some producer** (whitespace or a literal string in `/Contents`): compare with the research probe, where pyHanko, LibreOffice and Nacre all write a bare hex run; the third-party test guards the common case.
- **`LaterRevision` as `TOTAL_FAILED` diverges from DSS** (`docs/plans/s06-pades-bb.md:51`, both signatures `TOTAL_PASSED`): deliberate until s15; the reviewer checks the rule is one branch, step 10, nowhere else.
- **Sub-indications differ from DSS** for some cases (the CMS mapping, `UnsupportedSubFilter`): EN 319 102-1 meanings are used; s18's campaign is the judge, not this story.
- **Nacre forging its own attacks shares the validator's blind spots**: the forged files test that each rule exists, the third-party file tests that the rules do not fit only Nacre's layout.

## Files touched
`crates/nacre-validate/{Cargo.toml, src/lib.rs, src/error.rs, src/report.rs, src/validate.rs, examples/forge_attacks.rs, tests/validate.rs, tests/attacks.rs, tests/hostile.rs, tests/corpus/README.md, tests/corpus/unsigned.pdf, tests/corpus/certified-dss.pdf, tests/corpus/attacks/*.pdf (14), fuzz/Cargo.toml, fuzz/.gitignore, fuzz/fuzz_targets/validate.rs}`, `docs/security/attacks/pades.md`, plus this plan and the research.

## Test strategy
22 tests, within `Test budget` 25, all at the service layer (`validate`), since the crate has no adapter:
- unit: `every_variant_has_its_kind`, `every_cms_error_has_its_outcome`, `signatures_over_the_cap_are_refused` (3);
- `tests/validate.rs`: the s06 signature, the third-party signature, hash failure, signature failure (4);
- `tests/attacks.rs`: one per corpus case (14) — the attack sheet links each case to one named test, as for CMS;
- `tests/hostile.rs`: one no-panic sweep (1).
Not tested apart: each `Defect` variant's `FORMAT_FAILURE` (asserted inside the attack tests), each mapping row through a PDF (the table test covers it). The fuzz target runs in CI's `fuzz` job, not in `cargo test`. No conformance test: DSS parity is s18's.

## Done when
Every task ticked; `cargo test --workspace` and clippy green through `po-run`; `cargo fmt --all --check` clean; the forge reproduces the corpus byte for byte; one commit `s14-validate-integrity: …` holding code, corpus, attack sheet, research and plan; a review with no open critical finding.
