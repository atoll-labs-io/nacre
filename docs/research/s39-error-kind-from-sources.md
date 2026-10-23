# Research — s39-error-kind-from-sources

[Story](../stories.md)

## Structuring facts
- **False: the `Owns` line cannot hold this story.** Any shape that adds a kind to `nacre_core::Error::Timestamp`/`Revocation` breaks code outside `crates/nacre-core/`, `crates/nacre-tsp/src/`, `crates/nacre-revocation/src/`: `crates/nacre-pades/src/error.rs:65`, `crates/nacre-pades/tests/sign.rs:225`, `crates/nacre-cms/src/error.rs:139` build `nacre_core::Error::Timestamp("x".into())`, and `crates/nacre-revocation/tests/http.rs:131,177` destructure `Revocation(error)` then `downcast`. The local-server harnesses the criteria need live in `crates/nacre-tsp/tests/http.rs:15` and `crates/nacre-revocation/tests/http.rs:39`, also outside `Owns`. `po-bounds` reads `Owns` at the fork point (`docs/decisions-log.md:44`, s38 precedent), so the story must be corrected and the lane re-forked.
- **False: `HttpCrlSource` never checks a CRL signature.** It only parses the body (`crates/nacre-revocation/src/http.rs:96`) and ignores `issuer` (`http.rs:307`); judging is `Crl::status`'s job (`http.rs:28-29`). A badly signed CRL is returned `Ok`, so "une CRL invalide rend `InvalidSignature`" cannot happen at the source; only a malformed CRL fails (`Error::Der` → `InvalidInput`, `crates/nacre-revocation/src/error.rs:111`). The `InvalidSignature` case of a revocation source is `HttpOcspSource`'s replayed response (`http.rs:186`, `NonceMismatch` → `InvalidSignature`, `error.rs:119`).
- **The overlap with s11 is real.** Correcting `Owns` to the pades files overlaps s11-pades-blt, in flight with `Owns: crates/nacre-pades/` (`docs/stories.md:194`, worktree `.worktrees/s11-pades-blt`): s39 must run after s11 ships.
- Both families already compute the right kind: `nacre_tsp::Error::kind()` (`crates/nacre-tsp/src/error.rs:65-87`) and `nacre_revocation::Error::kind()` (`crates/nacre-revocation/src/error.rs:108-139`). The fix is to carry it, never to recompute it, and never to downcast in `nacre-core` (ADR-0016).
- The variant shape is a contract choice ADR-0016 leaves open: drafted as ADR-0020 (`proposed`), waiting for a human.

## Story
As an application developer serving third parties, I want `kind()` of a TSA or revocation error to say its real category, so that I do not retry an attack as an outage. Criteria:
1. `Error::Timestamp` and `Error::Revocation` carry an `ErrorKind` set by the source, `Unavailable` by default; `kind()` returns it.
2. `HttpTsa`: forged or replayed token → `InvalidSignature`; wrong-length imprint → `InvalidInput`; unreachable TSA → `Unavailable`.
3. `HttpCrlSource`: invalid CRL → `InvalidSignature` or `InvalidInput` by cause (false in part, see above); refused address (SSRF) → `InvalidInput`; unreachable server → `Unavailable`.
4. One test per case, on a local server.

Proposed correction of criterion 3: "`HttpCrlSource` : une CRL mal formée rend `InvalidInput` ; une adresse refusée (SSRF) rend `InvalidInput` ; un serveur injoignable rend `Unavailable`. `HttpOcspSource` : une réponse rejouée (nonce) rend `InvalidSignature`." Proposed `Owns`: `crates/nacre-core/`, `crates/nacre-tsp/src/`, `crates/nacre-tsp/tests/http.rs`, `crates/nacre-revocation/src/`, `crates/nacre-revocation/tests/http.rs`, `crates/nacre-cms/src/error.rs`, `crates/nacre-pades/src/error.rs`, `crates/nacre-pades/tests/`.

## Current code
- `crates/nacre-core/src/error.rs:7-20`: `Error` with `DigestLength { expected, actual }`, `Signer(BoxError)`, `Timestamp(BoxError)`, `Revocation(BoxError)`, `#[non_exhaustive]`, thiserror, fixed messages. `kind()` at `:24-30` maps `Timestamp(_) | Revocation(_)` to `Unavailable` (`:28`). `ErrorKind` at `:38-52`, fixed `Display` at `:54-64`.
- `crates/nacre-tsp/src/http.rs:47-62`: `HttpTsa::timestamp` turns `Error::DigestLength` into core `DigestLength` (already `InvalidInput`), everything else into `Error::Timestamp(Box::new(error))` (`:60`).
- `crates/nacre-tsp/src/response.rs:13-45` and `src/token.rs:71-118`: check order: status, token present, signature (`signed.verify`, `token.rs:84`), ESS v2, EKU, imprint (`token.rs:107`), then nonce (`response.rs:40-43`).
- `crates/nacre-revocation/src/http.rs:197-207` (OCSP) and `:301-312` (CRL): `nacre_core::Error::Revocation(Box::new(error))`. `http_error` (`:210-215`) turns the resolver refusal into `Error::NonPublicAddress`.
- `crates/nacre-revocation/src/fallback.rs:18-28`: returns the second source's error unchanged; its test builds `Revocation("unreachable".into())` (`:39`).

## Attachment points
- `crates/nacre-core/src/error.rs`: the two variants, their constructors, `kind()`.
- `crates/nacre-tsp/src/http.rs:60`: pass `error.kind()` with the error.
- `crates/nacre-revocation/src/http.rs:206,311`: same with `nacre_revocation::Error::kind()`.
- Callers to migrate: `crates/nacre-core/tests/error_kind.rs:25-26`, `crates/nacre-core/tests/contract_objects.rs:19`, `crates/nacre-revocation/src/fallback.rs:39`, `crates/nacre-revocation/tests/http.rs:131,177`, `crates/nacre-cms/src/error.rs:139`, `crates/nacre-pades/src/error.rs:65`, `crates/nacre-pades/tests/sign.rs:225`, plus whatever s11 adds.

## Verified interfaces
- `pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>` (`crates/nacre-core/src/error.rs:2`).
- `pub trait TimestampAuthority { fn timestamp(&self, algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<Vec<u8>, Error>; }` (`crates/nacre-core/src/timestamp.rs:4-8`).
- `pub trait RevocationSource { fn revocation(&self, certificate: &[u8], issuer: &[u8]) -> Result<RevocationData, Error>; }` (`crates/nacre-core/src/revocation.rs:14-18`).
- `pub fn kind(&self) -> nacre_core::ErrorKind` on `nacre_tsp::Error` (`crates/nacre-tsp/src/error.rs:65`): `Cms(inner)` → `inner.kind()` (`SignatureInvalid` → `InvalidSignature`, `:131-132` of its test), `NonceMismatch`/`NonceMissing`/`ImprintMismatch` → `InvalidSignature` (`:75-78`), `Http(_)` → `Unavailable` (`:84`), `Der(_)` → `InvalidInput` (`:68`).
- `pub fn kind(&self)` on `nacre_revocation::Error` (`crates/nacre-revocation/src/error.rs:108`): `Der(_)` → `InvalidInput`, `NonceMismatch` → `InvalidSignature`, `NonPublicAddress` → `InvalidInput` (`:135`), `Http(_)` → `Unavailable` (`:137`).
- `HttpTsa::new(url: &str)` (`crates/nacre-tsp/src/http.rs:22`); `HttpCrlSource::new()`/`allowing_loopback()` (`crates/nacre-revocation/src/http.rs:39,47`); `HttpOcspSource::allowing_loopback()` (`:137`).
- Implementers of the two traits, all opened: `HttpTsa`, `HttpCrlSource`, `HttpOcspSource`, `Fallback`, test doubles `DownTsa`/`FixedOcsp` (`crates/nacre-core/tests/contract_objects.rs:17,25`), `FakeTsa` (`crates/nacre-pades/tests/sign.rs:216`), `Failing`/`Fixed` (`fallback.rs:37,45`).
- Tsp fixtures usable by a local server: `tests/corpus/attacks/valid.tsr` and `signature-invalid.tsr`, both over the SHA-256 of `tests/corpus/recorded/data.bin` with nonce `0xd41cbff4fded9d81` (`crates/nacre-tsp/tests/attacks.rs:13-19,22,56`). A fresh `HttpTsa` request draws a random nonce (`src/http.rs:33`), so `valid.tsr` served back is a replay (`NonceMismatch`), and `signature-invalid.tsr` fails at the signature, checked before the nonce.
- `sha2` is a dev-dependency of `nacre-tsp` (`crates/nacre-tsp/Cargo.toml`, `[dev-dependencies]`); `nacre-revocation` turns its own `http` feature on for tests (`crates/nacre-revocation/Cargo.toml`, last dev-dependency), `nacre-tsp` the same (`nacre-tsp = { path = ".", features = ["http"] }`).
- `crates/nacre-tsp/tests/http.rs:15-46`: `serve_once` reads one request and always answers 500; `:48-89` asserts 500 → `Unavailable` and a 31-byte imprint → `InvalidInput` (criterion 2's length case is already met and tested).
- `crates/nacre-revocation/tests/http.rs:39-84`: `serve()` answers CRL on any GET, `base.der` OCSP on `POST /ocsp`, 302 on `/redirect`; `fetch`/`ask` helpers (`:128-133`, `:174-179`) downcast the boxed source to `nacre_revocation::Error`; `ocsp_nonce_mismatch_is_rejected` (`:182-193`) and `loopback_point_is_refused_by_default` (`:148-156`) check the inner kind only, never the core error's.

## Traps
- `impl Into<BoxError>` on a `Box<E>` double-boxes: `Box<io::Error>` is itself an `Error`, so the source becomes `Box<io::Error>` and `downcast_ref::<io::Error>()` fails (`crates/nacre-core/tests/contract_objects.rs:50-54`, `revocation/tests/http.rs:131`). Callers pass the error by value.
- `source()` must stay the implementation's error: ADR-0010 (Consequences) tells callers to `downcast_ref` it, and `contract_objects.rs:50-54` checks it.
- The `Display` of both variants stays fixed (`error.rs:15,18`): the kind must not enter the message (ADR-0012).
- `pades::Error::Timestamp(inner).kind()` forwards to the core kind (`crates/nacre-pades/src/error.rs:33`); `tests/sign.rs:296-297` expects `Unavailable` from a plain failing TSA, which the default keeps.
- `cms::Error::Signer(nacre_core::Error::Timestamp(..))` at `crates/nacre-cms/src/error.rs:139` expects `Unavailable`: the default keeps it.
- s11-pades-blt is in flight on `crates/nacre-pades/` and probably adds a fake `RevocationSource`; after it ships, its new constructions must be migrated too.
- `cargo test --workspace` compiles every test target: one unmigrated caller breaks the whole suite. Clippy runs with `-D warnings`, `--all-features`.
- No migration, no new dependency, no public TSA (story notes).

## Open questions
- Which shape for the kind (ADR-0020, proposed): struct variants with constructors (ranked first), a wrapper type that keeps the tuple variants, or a two-field tuple.
- Does Patelle already implement `TimestampAuthority` or `RevocationSource` against Nacre 0.1? If so, it migrates with any shape but option 2 of ADR-0020.
- Should `HttpCrlSource` verify the CRL signature with `issuer`? Not proposed: it would change s09's contract and break callers passing an empty issuer (`revocation/tests/http.rs:129`).

## Complexity
Story: 2 → after reading: 3. The kinds already exist in both families; the cost is the contract change rippling into four crates, the test harnesses outside `Owns`, and the wait on s11.

## Split
Not needed at 3.
