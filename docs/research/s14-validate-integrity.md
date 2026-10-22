# Research — s14-validate-integrity

[Story](../stories.md)

## Structuring facts
- **False assumption (story notes)**: "PDF fictifs reconstruits avec la PKI de s02" cannot hold for a committed corpus: the s02 PKI is regenerated at every bench start and never committed (`conformance/pki/README.md:3-6`), its keys change each run. Committed attack files must be signed with the fixed test key `TestSigner::from_secret(&[0x11; 32])` (`crates/nacre-core/src/test_signer.rs:31`), as `nacre-cms` already does (`crates/nacre-cms/examples/forge_attacks.rs:35,46`). The lead should reword the note in `docs/stories.md:257`.
- **Driver note partly stale**: `verify_detached_digest` (`crates/nacre-cms/src/verify.rs:55`) already has positive tests since s06 (`crates/nacre-pades/tests/sign.rs:139,163`); s14 still exercises it, and it verified three third-party signatures in a probe (below).
- **The frozen report has no room for "digest and signature verified"**: `ValidationReport` holds only indication, sub-indication and level (`crates/nacre-core/src/report.rs:136-140`) and `nacre-core` changes only through a contract story (`docs/architecture.md`, Ownership). Criterion 1's facts must live in a `nacre-validate` type wrapping the report.
- **Criterion 2 read literally makes every non-final signature `TOTAL_FAILED`**: a signature covering a revision followed by others does not cover "tout le fichier". DSS judges both signatures of a Nacre twice-signed PDF `TOTAL_PASSED` (`docs/plans/s06-pades-bb.md:51`), so s14 is stricter than DSS until s15 qualifies later revisions (`docs/stories.md:268`). Never a false valid; a known, provisional false negative.
- `nacre-pdf` exposes no object offsets (`crates/nacre-pdf/src/document.rs:86-125`), and `nacre-validate` may not change it (Owns: `crates/nacre-validate/`, `docs/security/attacks/pades.md`, `docs/stories.md:247`). The `/ByteRange` gap is checked on raw bytes against the parsed `/Contents` value.

## Story
`validate` checks that each PAdES signature covers the document and is cryptographically valid; chain, revocation and level are s16–s18, so a sound signature ends `INDETERMINATE`, never `TOTAL_PASSED`.
1. A PDF signed by s06 → one `ValidationReport` per signature, digest and signature verified.
2. A `/ByteRange` not covering the whole file except `/Contents`, overlapping, or pointing outside → `TOTAL_FAILED` with the EN 319 102-1 sub-indication.
3. USF (empty signature, null `/Contents`, `/ByteRange` absent or inconsistent), SWA, ISA cases of `crates/nacre-validate/tests/corpus/attacks/` all rejected.
4. `docs/security/attacks/pades.md` lists every published attack on signed PDFs (Mladenov et al. 2019–2021), each with its corpus case and the story rejecting it.
5. Hostile input → an error, never a panic; a fuzz target exists.

## Current code
- `crates/nacre-validate/` does not exist; the workspace picks it up by folder (`Cargo.toml:3`, `members = ["crates/*"]`), the root manifest stays untouched.
- `nacre-pdf` (`crates/nacre-pdf/src/lib.rs:16-38`): strict reader; `Document::parse` (`document.rs:37`), `revisions()` oldest first with `Revision.end` just past each `%%EOF` line, the last one equal to the input length (`xref.rs:21-31`), `signature_fields()` in tree order (`document.rs:107`), `object(id)` (`document.rs:112`). `SignatureField { name, id, value: Option<ObjectId> }`, `value` `None` for an empty field (`acroform.rs:9-17`). Data after the last `%%EOF` is refused, `Error::TrailingData` (`error.rs:18-19`). Input capped at 50 MB (`limits.rs:3`).
- `Object::String` holds decoded bytes (`object.rs:25-37`); the writer writes every string in hex (`write.rs:6,19`).
- s06 layout (`crates/nacre-pdf/src/revision.rs:212-215,498-530,546-560`): `/ByteRange` written before `/Contents`, padded with spaces to a fixed width (`:570-582`); `[0, a, b, c]` with `a..b` the hex string `<` and `>` included; `/Contents` is the DER followed by zero bytes up to the reserve (`embed`, `:512-530`).
- `nacre-cms`: `SignedData::from_der` requires the input to end with the `ContentInfo` (`model.rs:84`, `nested` calls `reader.finish()`, `:390-398`), so the zero padding must be cut first, as s06's test does with the DER header length (`crates/nacre-pades/tests/sign.rs:84-86`). `verify_detached_digest(&[u8])` refuses an encapsulated content (`ContentAmbiguous`) and a digest that is not 32 bytes, then runs the shared checks (`verify.rs:55-68`).
- Check order of `verify_with` (`verify.rs:72-123`): signer count → signed attributes present → duplicates → `contentType`/`messageDigest` present → content type → signer certificate → algorithms → `signingCertificateV2` → **message digest** (`:104-107`) → **signature** (`:109-117`). So `MessageDigestMismatch` means "digest not verified", `SignatureInvalid` means "digest verified, signature not".
- `nacre-cms::Error` (`error.rs:6-67`) is `#[non_exhaustive]`; `kind()` at `:71-96`.
- `ValidationReport::{passed, failed, indeterminate}` (`crates/nacre-core/src/report.rs:143-165`); `SubIndication` has all 25 EN 319 102-1 names incl. `FormatFailure`, `HashFailure`, `SigCryptoFailure`, `NoSigningCertificateFound`, `NoCertificateChainFound`, `CryptoConstraintsFailureNoPoe` (`:63-89`).
- `nacre-pades::sign(pdf, &dyn Signer, DateTime)` (`crates/nacre-pades/src/sign.rs:21`): field `Signature1`, deterministic with `TestSigner` and a fixed time (RFC 6979). `unsigned.pdf` lives in `crates/nacre-pades/tests/corpus/` (copied from `conformance/reference/`).
- `Update` public API (`crates/nacre-pdf/src/revision.rs:98-136`): `add`, `add_stream`, `set_catalog`, `finish`, `sign`; `PreparedSignature::{byte_range, signed_parts, embed}`. Enough to forge USF dictionaries (hand-built `/Sig` without `/Contents` or `/ByteRange`) and ISA (a new revision that replaces `/Pages`).

## Probe (run outside the worktree, nothing written in it)
A scratch binary on `nacre-pdf` + `nacre-cms` read each signature, cut `/Contents` at its DER length, hashed the two ranges and called `verify_detached_digest`:

| File (`crates/nacre-pdf/tests/corpus/real/`) | Field | `/ByteRange` | `c + d` | Result |
| --- | --- | --- | --- | --- |
| `signed-twice-pyhanko.pdf` (50827 B) | Sig1 | `0 29541 48279 2548` | 50827 = last end | `Ok` |
| same | Sig2 | `0 3485 22223 4161` | 26384 = revision 1 end | `Ok` |
| `signed-lta-pyhanko.pdf` | Sig1 | `0 2905 25421 432` | 25853 = revision 3 end | `Ok` |
| same | DocTimeStamp (`/SubFilter /ETSI.RFC3161`) | `0 34074 45532 680` | 46212 = revision 4 end | `Err(ContentAmbiguous)` |
| `certified-dss.pdf` (152955 B, RSA, Nowina `PKI-TEST` fictitious CA) | signature-test | `0 128489 147435 5520` | 152955 = last | `Ok` |

In all five, the gap is exactly `<` + an even number of hex digits + `>`, no whitespace, and the padding after the DER is all zeros; `c + d` always equals some `Revision.end`. pyHanko writes `/ByteRange` with leading zeros (`00002905`), still integers.

## Attachment points
- New crate `crates/nacre-validate/` (`Cargo.toml`, `src/`, `tests/`, `tests/corpus/`, `examples/`, `fuzz/`); CI fuzzes any `crates/*/fuzz` without a workflow change (`.github/workflows/ci.yml`, job `fuzz`).
- Fuzz crate pattern: own `[workspace]`, `cargo-fuzz = true` metadata, `.gitignore` (`crates/nacre-cms/fuzz/Cargo.toml`, `crates/nacre-pdf/fuzz/fuzz_targets/revision.rs`).
- Corpus forge pattern: a deterministic cargo example writing the attack files (`crates/nacre-cms/examples/forge_attacks.rs`), a corpus `README.md` with the regeneration command (`crates/nacre-cms/tests/corpus/README.md`), one rejecting test per file (`crates/nacre-cms/tests/attacks.rs`), and the French attack sheet (`docs/security/attacks/cms.md`).

## Verified interfaces
- `nacre_pdf::Document::parse(&[u8]) -> Result<Document, nacre_pdf::Error>`; `.revisions() -> &[Revision]`; `.signature_fields() -> &[SignatureField]`; `.object(ObjectId) -> Result<Object, Error>`.
- `nacre_cms::SignedData::from_der(&[u8]) -> Result<SignedData, nacre_cms::Error>`; `.verify_detached_digest(&[u8]) -> Result<VerifiedSigner<'_>, nacre_cms::Error>`.
- `nacre_core::ValidationReport::indeterminate(SubIndication, Option<SignatureLevel>)`, `::failed(..)`; no public constructor taking anything else.
- `nacre_pades::sign(&[u8], &dyn Signer, DateTime) -> Result<Vec<u8>, nacre_pades::Error>`.
- Every crate error has `kind() -> nacre_core::ErrorKind` (ADR-0012; e.g. `crates/nacre-pades/src/error.rs:15-22`).

## Traps
- Workspace lints deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` (`Cargo.toml:5-9`): every slice of the PDF goes through `get`, every `/ByteRange` sum through `checked_add`, every `i64` through `usize::try_from`.
- `cargo test --workspace` also builds examples; the forge example needs the same `#![allow(...)]` header as `crates/nacre-cms/examples/forge_attacks.rs:7-12`.
- A `/DocTimeStamp` signature (`/SubFilter /ETSI.RFC3161`) encapsulates its `TSTInfo` and fails `verify_detached_digest` with `ContentAmbiguous`: treated as a signature, every B-LTA document would show a `FORMAT_FAILURE`.
- Hashing cost: up to 65,536 fields (`crates/nacre-pdf/src/limits.rs:28`) times a 50 MB file; the brief asks validation in under 2 s (`docs/brief.md:87`). A bound on signatures validated is needed.
- Two references to the same file across crates (`include_bytes!("../../nacre-pdf/...")`) break the per-crate corpus convention (`AGENTS.local.md`, test data in `crates/<crate>/tests/corpus/`): copy the files used, with their source in the README, as s06 did.
- s15 owns the same paths after s14 (`docs/stories.md:265`): the "later revision" rule must sit in one place s15 can replace.
- No migration, no change to `nacre-core`, `nacre-pdf`, `nacre-cms`, `nacre-pades`.

## Open questions
- Sub-indications DSS gives for each USF/SWA/ISA case are not checked here (no bench run in this wave); s18's campaign compares. The plan uses EN 319 102-1 Table 5 meanings: structure → `FORMAT_FAILURE`, digest → `HASH_FAILURE`, signature → `SIG_CRYPTO_FAILURE`.
- `UnsupportedAlgorithm` (e.g. SHA-384) is Nacre's limit, not the signer's fault: `INDETERMINATE` `CRYPTO_CONSTRAINTS_FAILURE_NO_POE` is the plan's pick; DSS may answer otherwise.
- Should a document timestamp appear in the list now (as not judged) or only from s18? The plan leaves it out of the list.
- Is refusing non-zero bytes after the DER in `/Contents` too strict for some producer? All probed producers pad with zeros.

## Complexity
Story 3 → 3. The verification itself is plumbing over `nacre-pdf` and `nacre-cms`; the bulk is the forged corpus (about fourteen files whose single defect must reach its own rule) and the attack sheet.

## Split
Not needed (below 5).
