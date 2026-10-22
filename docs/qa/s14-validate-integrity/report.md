# QA — s14-validate-integrity

[Story](../../stories.md) · [Plan](../../plans/s14-validate-integrity.md)

Scope: the story's surface, what `git diff main...story/s14-validate-integrity` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli (row `endpoint` / `lib`)
Evidence: transcripts
Tool: Bash, on a `mktemp -d` copy of the tracked files (`cargo fetch`, then `cargo build --workspace --all-features`, exit 0); a scratch crate calling the public interface (`nacre_validate::validate`, with `nacre_pades::sign` and `TestSigner` to produce inputs), quoted whole in `scenario-script.txt`
Origin: —

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| 1. `validate` of a PDF signed by s06 gives one `ValidationReport` per signature, digest and signature verified (`c1-validate-signed.txt`) | yes | as expected: one entry `Signature1`, `digest_verified=true`, `signature_verified=true`, `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`, level `None`; the third-party `certified-dss.pdf` gives the same; a twice-signed PDF gives two entries, the first `TOTAL_FAILED` / `LaterRevision` — the provisional rule documented in the crate doc and `docs/security/attacks/pades.md` |
| 1, invalid input (`c1-validate-signed-error.txt`) | yes | as expected: unsigned PDF → `Ok` with 0 entries; one signed byte altered → `TOTAL_FAILED` / `HASH_FAILURE`, `Cms(MessageDigestMismatch)` |
| 2. `/ByteRange` not whole file, overlapping, outside file → `TOTAL_FAILED` with an EN 319 102-1 sub-indication (`c2-byterange.txt`) | yes | as expected: hand-forged from the s06 PDF without the story's forge, each gives `TOTAL_FAILED` / `FORMAT_FAILURE` with `ByteRangeNotFromStart`, `ByteRangeOverlap`, `ByteRangeOutsideFile`, `ByteRangeNotWholeFile`, `GapNotContents` |
| 2, malformed values (`c2-byterange-error.txt`) | yes | negative, real and five-entry ranges → `ByteRangeMalformed`; an integer too large for the parser → `TOTAL_FAILED` but `NotASignatureDictionary`: finding 1 |
| 3. USF, SWA, ISA cases of `tests/corpus/attacks/` all rejected (`c3-attacks.txt`) | yes | as expected: 13 cases `TOTAL_FAILED` / `FORMAT_FAILURE` with the defect the sheet names, `isa-no-xref.pdf` → `Err` `InvalidInput` (`TrailingData`); the forge regenerates the 14 files byte for byte |
| 3, hand variants outside the corpus (`c3-attacks-error.txt`) | yes | as expected: zeroed `/Contents` → `ContentsNotDer`; unknown `/SubFilter` → `UnsupportedSubFilter`; object after `%%EOF` → `Err` `TrailingData`; a single LF after `%%EOF` → `TOTAL_FAILED` `ByteRangeNotWholeFile` (strict, never a false valid) |
| 4. `docs/security/attacks/pades.md` lists the published attacks (Mladenov et al. 2019–2021), each with its corpus case and the story rejecting it (`c4-attack-sheet.txt`) | yes | as expected: USF, SWA, ISA (CCS 2019), shadow hide / replace / hide-and-replace (NDSS 2021), EAA and SSA (S&P 2021); every corpus file appears in exactly one row, every named test exists in `tests/attacks.rs`; shadow, EAA, SSA rows point at s15 with "à écrire par s15" |
| 5. Hostile input gives an error, never a panic; a fuzz target exists (`c5-hostile.txt`) | yes | as expected: empty, non-PDF, header-only, truncated inputs → `Err` `InvalidInput` with a message naming the cause; 21 000 deterministic random mutations of two signed PDFs → 0 panics; `fuzz/fuzz_targets/validate.rs` calls `validate`. Deep nesting in `/Contents` → `NotASignatureDictionary` (finding 1) |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — An unreadable value inside the `/Sig` dictionary is reported as `NotASignatureDictionary`
Severity: minor
Status: verified
Steps to reproduce:
1. Sign `crates/nacre-validate/tests/corpus/unsigned.pdf` with `nacre_pades::sign` (`TestSigner::from_secret(&[0x11; 32])`, 2026-10-22T08:00:00Z).
2. Rewrite its fixed-width `/ByteRange [0 919 2603 576 …]` text in place as `/ByteRange [0 919 2603 99999999999999999999]` (or `[0 919 18446744073709551615 1]`, or replace the `/Contents` hex string with 840 nested `[`…`]`).
3. Call `nacre_validate::validate` on the file.
Capture: docs/qa/s14-validate-integrity/c2-byterange-error.txt (cases `br-big`, `br-ovf`), docs/qa/s14-validate-integrity/c5-hostile.txt (case `deep.pdf`)
Expected: the defect names what is wrong — `/V` does name a dictionary; its `/ByteRange` (or `/Contents`) is what cannot be read, so `ByteRangeMalformed` (or `ContentsMissing`), or an `Err` saying the object cannot be parsed. The verdict itself (`TOTAL_FAILED` / `FORMAT_FAILURE`) is right.
Observed: `defect=Some(NotASignatureDictionary)`, whose documentation reads "`/V` does not name a dictionary": the parse error of the object is dropped (`validate.rs`, `doc.object(value)` mapped to `None` on any `Err`), so a developer diagnosing a refused signature is pointed at the wrong rule. Never a false valid.

## Not seen
- Agreement of the sub-indications with DSS (conformance bench) — not part of this story's criteria (DSS parity is s18's, plan "Test strategy"); the bench was not started.
- The fuzz target under `cargo fuzz` — needs a nightly toolchain and a long run; the driver ran a 21 000-input mutation sweep through the public interface instead, and only checked that the target exists and calls `validate`.
- Behaviour on large inputs near the 50 MB / 64-signature bounds — real load is out of the driver's reach; `TooManySignatures` is reachable only with 65 signatures and was not exercised.

Tree: e3be979f4a05ef8132547028a2ec5a98208098cb
QA status: complete
