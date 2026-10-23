---
validated: yes
---
# Plan — s08-pades-bt

[Story](../stories.md) · [Research](../research/s08-pades-bt.md)

Branch `story/s08-pades-bt`. Read `docs/research/s08-pades-bt.md` first; this plan builds on it without repeating it.

Validated autonomously under `Plan validation: autonomous`: no human reviewed this plan. No technical choice deserving an ADR is open — the shape of the level API is the story's (precedent: `docs/plans/s06-pades-bb.md:10`), the token bound is an implementation constant — so the reserved ADR-0017 is not used.

## Story
The PAdES signature carries a signature timestamp so DSS declares it `PAdES-BASELINE-T`. Criteria, **as corrected by the research** (the lead should carry these into `docs/stories.md:146-149`; the implementer does not edit `docs/stories.md`):
1. `sign_at_level(…, Level::T { tsa })` with the s02 local TSA gives a PDF DSS declares `TOTAL_PASSED` at `PAdES-BASELINE-T`. (`sign` stays B-B: other crates call it.)
2. The token sits in the unsigned attribute `id-aa-signatureTimeStampToken` of the `SignerInfo` and time-stamps the signature value.
3. A TSA failure — unreachable, refused, malformed answer — makes signing fail with an error that designates the timestamp authority as its cause; no PDF is returned.
4. The `/Contents` reserve covers any token up to 16 384 DER bytes; a larger token returns an error giving its size and the bound.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Placing the token in the `SignerInfo` | already in this repository: `SignedData::from_der`/`to_der`, `SignerInfo::push_unsigned_attribute`, `Attribute` (`crates/nacre-cms/src/model.rs:84,144,282,289-292`) | — |
| Token reserve | already in this repository: the dry run of `contents_capacity` (`crates/nacre-pades/src/reserve.rs:67-71`), extended with a placeholder token | — |
| TSA call | already in this repository: `TimestampAuthority` (`crates/nacre-core/src/timestamp.rs:4-8`); `HttpTsa` in tests only (`crates/nacre-tsp/src/http.rs:16-62`) | — |
| Imprint | dependency already installed: `sha2` (`crates/nacre-pades/Cargo.toml:16`) | — |
| `Level` enum, `sign_at_level`, OID constant, three error variants | new code, ~80 lines | nacre-core's `SignatureProfile` cannot carry a TSA reference and nacre-core is frozen (s39 owns it); the OID exists nowhere (research, fact 5); nacre-cms and nacre-core are outside `Owns` |

## Tasks
1. [x] **Error variants** `src/error.rs`. Add to `Error`:
   - `Timestamp(#[source] nacre_core::Error)`, message `"the timestamp authority failed"`, `kind()` → `inner.kind()` (never a hard-coded `Unavailable`: ADR-0016 / s39 will let the source set it). No `#[from]`: `nacre_cms::Error` already absorbs `nacre_core::Error` (`crates/nacre-cms/src/error.rs:66`), so the conversion stays explicit.
   - `TimestampToken(#[source] der::Error)`, message `"the timestamp authority returned a token that is not DER"`, kind `InvalidInput`.
   - `TimestampTooLarge { len: usize, max: usize }`, message `"the timestamp token is {len} bytes, more than the {max} reserved"`, kind `InvalidInput`.
   No message carries the token. Never construct `nacre_core::Error::Timestamp` in this crate (s39 changes its constructor).
   Test that fails if wrong: `every_variant_has_its_kind` (`error.rs:28-50`) gains three rows — `Timestamp(nacre_core::Error::Timestamp("x".into()))` → `Unavailable`, `TimestampToken(der::Error::from(der::ErrorKind::Failed))` → `InvalidInput`, `TimestampTooLarge { len: 2, max: 1 }` → `InvalidInput`.
2. [x] **Token placement and reserve** — new `src/timestamp.rs` (`pub(crate)` items unless stated):
   - `const SIGNATURE_TIME_STAMP_TOKEN: ObjectIdentifier` = `1.2.840.113549.1.9.16.2.14` (`id-aa-signatureTimeStampToken`, RFC 3161 App. A / RFC 5126).
   - `pub const TIMESTAMP_TOKEN_MAX: usize = 16_384;` re-exported from `lib.rs`, rustdoc: the largest DER `TimeStampToken` the `/Contents` slot reserves room for (recorded tokens: bench ≈ 1.8 KB, DigiCert ≈ 6 KB).
   - `fn with_token(cms: &[u8], token: Any) -> Result<Vec<u8>, Error>`: `SignedData::from_der(cms)?`, `signer_infos.first_mut()` (none → `Error::Cms(nacre_cms::Error::SignerCount(0))`), `push_unsigned_attribute(Attribute { oid: SIGNATURE_TIME_STAMP_TOKEN, values: vec![token] })`, `to_der()?`. The **only** place the attribute is built, used by both the dry run and the real run.
   - `fn signature_imprint(cms: &[u8]) -> Result<[u8; 32] or Vec<u8>, Error>`: SHA-256 of `signer_infos[0].signature` read through `first()` — the signature value's content octets, nothing else.
   - `fn timestamp_signature(cms: &[u8], tsa: &dyn TimestampAuthority) -> Result<Vec<u8>, Error>`, in this order: imprint; `tsa.timestamp(DigestAlgorithm::Sha256, &imprint).map_err(Error::Timestamp)?`; `token.len() > TIMESTAMP_TOKEN_MAX` → `TimestampTooLarge { len, max }`; `Any::from_der(&token).map_err(Error::TimestampToken)?` (refuses trailing bytes); `with_token(cms, any)`.
   - `src/reserve.rs`: `contents_capacity(signer, timestamped: bool)`. `false` → today's value, unchanged bytes. `true` → `with_token(&dry, placeholder)?.len()` where `placeholder = Any::new(Tag::OctetString, vec![0; TIMESTAMP_TOKEN_MAX - 4])?` — DER length exactly `TIMESTAMP_TOKEN_MAX` (4-byte header `04 82 3F FC`). Update the doc comment (`:62-66`): the T reserve is the dry CMS plus a placeholder token of the maximum length.
   Test that fails if wrong: the tests of tasks 3 and 4 (`level_t_stores_the_token_over_the_signature_value`, `largest_token_fits_with_only_the_signature_slack`).
3. [x] **The level API** `src/sign.rs`, `src/lib.rs`:
   - `#[non_exhaustive] pub enum Level<'a> { B, T { tsa: &'a dyn TimestampAuthority } }`, rustdoc on each variant (B: no timestamp; T: a signature timestamp from `tsa`, which may verify the answer — `HttpTsa` does). No `Debug` derive is required (no lint asks for it); do not implement `Debug` by hand.
   - `pub fn sign_at_level(pdf: &[u8], signer: &dyn Signer, signing_time: DateTime, level: Level<'_>) -> Result<Vec<u8>, Error>`: today's body of `sign` with `contents_capacity(signer, matches!(level, Level::T { .. }))`, then after `sign_detached`, for `Level::T { tsa }`, `cms = timestamp_signature(&cms, tsa)?`, then `embed`. The signer still signs exactly once; the TSA is called once, after the signer.
   - `sign(pdf, signer, signing_time)` keeps its signature and becomes `sign_at_level(pdf, signer, signing_time, Level::B)`; its rustdoc points to `sign_at_level` for higher levels.
   - `lib.rs`: `mod timestamp;`, re-export `sign_at_level`, `Level`, `TIMESTAMP_TOKEN_MAX`; the crate doc (`:1-11`) says B-B and B-T, the token as unsigned attribute over the signature value, no clock read, the TSA reached only through `TimestampAuthority`. `Cargo.toml` `description` says B-B and B-T.
   Tests in `tests/sign.rs`, with a `FakeTsa { token: Vec<u8> or an error, seen: RefCell<Option<(DigestAlgorithm, Vec<u8>)>> }` implementing `TimestampAuthority`, the existing `counting()` signer, and a helper `der_of_len(n)` giving an OCTET STRING whose DER length is exactly `n`:
   - `level_t_stores_the_token_over_the_signature_value`: fake token = `der_of_len(100)`. Read back the CMS with `signatures()`: `unsigned_attrs` holds exactly one attribute, oid `1.2.840.113549.1.9.16.2.14`, one value whose DER equals the fake token; the fake saw `Sha256` and `Sha256(signer_infos[0].signature)`; the CMS verifies with `verify_detached_digest(range_digest(..))`; `/SubFilter` is `ETSI.CAdES.detached`; the signer signed once. Fails on an imprint over anything but the signature value, a token placed elsewhere, or a re-encoding that breaks the signature.
   - `tsa_failure_designates_the_tsa`: fake returns `Err(nacre_core::Error::Timestamp("down".into()))` → `Err(Error::Timestamp(_))`, `kind()` is `Unavailable`, `to_string()` contains `"timestamp authority"`. Fails if the error is swallowed, re-wrapped as `Cms`, or a PDF is returned.
4. [x] **The bound** — tests in `tests/sign.rs`:
   - `largest_token_fits_with_only_the_signature_slack`: fake token = `der_of_len(TIMESTAMP_TOKEN_MAX)`; signing succeeds and decoded `/Contents` length − CMS length == 72 − signature length, as at B-B. Fails if the placeholder is shorter (embed refuses) or longer (slack grows), or if the dry run encodes differently from the real one.
   - `oversized_token_is_refused`: fake token = `der_of_len(TIMESTAMP_TOKEN_MAX + 1)` → `Error::TimestampTooLarge { len: TIMESTAMP_TOKEN_MAX + 1, max: TIMESTAMP_TOKEN_MAX }`, kind `InvalidInput`. Fails if the bound check is missing (the ECDSA slack would let a few extra bytes through `embed`).
   - `malformed_token_is_refused`: fake token = a valid TLV followed by one trailing byte → `Error::TimestampToken(_)`, kind `InvalidInput`. Fails if the token is embedded unchecked.
5. [x] **Conformance** `tests/conformance.rs`, `Cargo.toml`:
   - `[dev-dependencies]` gains `nacre-tsp = { path = "../nacre-tsp", features = ["http"] }` (no version: dev-only, like `nacre-conformance`). Nothing added to `[dependencies]`.
   - `bench_signature_is_pades_baseline_t` (`#[ignore = "conformance"]`): removes `reports_dir().join("s08-pades-t.xml")` first, signs `UNSIGNED` with `BenchSigner::load()`, the fixed `time()` and `Level::T { tsa: &HttpTsa::new("http://127.0.0.1:18081/cgi-bin/tsa") }`; DSS `validate("s08-pades-t", ..)`: one signature, `TotalPassed`, no sub-indication, `format == "PAdES-BASELINE-T"`, report file exists. Fails if DSS sees no valid signature timestamp (it would say `PAdES-BASELINE-B`) or rejects the token.
   - Run it against the bench (`conformance/README.md`) and record the run; if DSS answers anything but `PAdES-BASELINE-T` / `TOTAL_PASSED`, stop and report DSS's sub-indication rather than adjusting the assertion.
6. [x] **Checks** — task tests with `cargo test -p nacre-pades --test sign` and `cargo test -p nacre-pades --lib`; then once, through `po-run`, the full suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`), which also proves nacre-validate and nacre-pkcs11 still compile against `sign`.

## Scene viewpoints
—

## Run interdicts
- Every path outside `crates/nacre-pades/` and `docs/{research,plans,verif,reviews}/s08-pades-bt.md` ends with an empty diff — in particular `crates/nacre-core/`, `crates/nacre-cms/`, `crates/nacre-tsp/`, `crates/nacre-validate/`, `crates/nacre-pkcs11/`, `docs/stories.md`, `CHANGELOG.md`, root `Cargo.toml`.
- `pub fn sign(pdf: &[u8], signer: &dyn Signer, signing_time: DateTime) -> Result<Vec<u8>, Error>` keeps exactly this signature, and its output at B-B stays byte-identical: `reserve_leaves_only_the_signature_slack` and the other existing tests of `tests/sign.rs` pass unmodified.
- `[dependencies]` of `crates/nacre-pades/Cargo.toml` gain nothing; `nacre-tsp` appears under `[dev-dependencies]` only.
- No code under `src/` constructs `nacre_core::Error::Timestamp`, reads the clock, opens a network connection, or indexes/unwraps outside `#[cfg(test)]`.
- No test calls a public TSA; the conformance test uses the bench TSA only.
- The signer is called once and the TSA once per `sign_at_level` call; no dry-run timestamp request.

## The pivot
**The reserve for a token whose size is unknown is a fixed bound, measured through the same encoding path as the real token.** The CMS is signed over a `/ByteRange` that already fixes the slot, and the signer signs once, so the slot is sized before the token exists: the dry CMS gets a placeholder token of exactly `TIMESTAMP_TOKEN_MAX` DER bytes through `with_token`, the function the real token goes through. Ways it could be wrong:
- **The bound is too small for a real TSA.** 16 384 bytes is 2.7× DigiCert's 6 KB token (RSA-4096 with chain); a TSA embedding a long chain or CRLs could exceed it, and the error then names both sizes. Compare with the recorded tokens in `crates/nacre-tsp/tests/corpus/recorded/`. Alternatives turned down: a caller-set bound (an option the story does not ask for); a dry-run timestamp request to measure the token (a second TSA call per signature, a recurring cost with a paid TSA, and the size can still vary by serial and nonce).
- **Dry and real runs drift.** If the placeholder is built or pushed differently from the real token, the capacity is off by length octets; `largest_token_fits_with_only_the_signature_slack` pins the equality on real bytes.
- **nacre-pades does not verify the token.** The trait's implementation owns verification and `HttpTsa` checks status, signature, imprint and nonce (`crates/nacre-tsp/src/response.rs:37-44`); verifying again would add a production dependency on nacre-tsp. A caller's own `TimestampAuthority` that returns an unverified token gets it embedded; DSS (task 5) and later `validate` judge it. A reviewer who thinks pades must verify should raise it as a finding, not as a silent fix.

## Files touched
- `crates/nacre-pades/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/reserve.rs`, `src/sign.rs`, `src/timestamp.rs` (new)
- `crates/nacre-pades/tests/sign.rs`, `tests/conformance.rs`
- `docs/research/s08-pades-bt.md`, `docs/plans/s08-pades-bt.md`

## Test strategy
Automated, 7 new tests plus 3 rows, within `Test budget` 25:
- Service (`tests/sign.rs`, `TestSigner`, fake TSA, no network): placement and imprint (criterion 2), TSA failure (criterion 3), largest token fits exactly and oversized token refused (criterion 4), malformed token refused. The fake TSA returns an arbitrary DER value because nacre-pades does not verify tokens (pivot); it records the imprint it was asked for, which is the rule under test, so the fake does not reproduce the condition it evaluates.
- Unit (`src/error.rs`): three kind rows in the existing table.
- Conformance (`tests/conformance.rs`, ignored, bench DSS + bench TSA): exact level `PAdES-BASELINE-T` (criterion 1, premise 4 of the brief).
- Not replayed: `HttpTsa`'s refusal and verification (`crates/nacre-tsp/tests/`), nacre-pdf's `SignatureTooLarge` (`crates/nacre-pdf/tests/revision.rs`), the B-B rules already in `tests/sign.rs`.
Visual checks: none (library).

## Done when
- All tasks ticked; `cargo test --workspace` and the clippy type check green through `po-run`; the ignored DSS test passes against the bench and its result is recorded.
- One story commit on `story/s08-pades-bt` holding code, research and plan; QA (`Surface: endpoint`), review with no open critical finding, then ship as `s08-pades-bt: Monter une signature PAdES au niveau B-T`.
- The lead carries the corrected criteria 1, 3 and 4 into `docs/stories.md`, and the same `sign_at_level` wording into s11 and s12.
