---
validated: yes
---
# Plan — s39-error-kind-from-sources

[Story](../stories.md) · [Research](../research/s39-error-kind-from-sources.md) · [ADR-0020](../decisions/0020-source-kind-in-struct-variants.md)

Branch `story/s39-error-kind-from-sources`. Read `docs/research/s39-error-kind-from-sources.md` first; this plan builds on it without repeating it.

Technical choice: settled by the person on 2026-10-23 — option 1 of ADR-0020 (struct variants `{ kind, source }`); ADR-0020 accepted. The story corrections this plan assumes landed on main in 0ef3686 (PR #103) and the lane was re-forked from it; s11 and s12 have shipped.

The tasks below follow option 1 of ADR-0020 (`proposed`). They also assume the two story corrections of the research are made in `docs/stories.md` and the lane re-forked after them (s38 precedent, `docs/decisions-log.md:44`): `Owns` widened to `crates/nacre-core/`, `crates/nacre-tsp/src/`, `crates/nacre-tsp/tests/http.rs`, `crates/nacre-revocation/src/`, `crates/nacre-revocation/tests/http.rs`, `crates/nacre-cms/src/error.rs`, `crates/nacre-pades/src/error.rs`, `crates/nacre-pades/tests/`; criterion 3 reworded for the CRL; s11-pades-blt shipped first. Without these, `po-bounds` refuses tasks 4 to 6.

## Story
`kind()` of a timestamp or revocation error says what the source saw, so an application does not retry an attack as an outage. Criteria, as corrected by the research:
1. `Error::Timestamp` and `Error::Revocation` carry an `ErrorKind` set by the source, `Unavailable` by default; `kind()` returns it.
2. `HttpTsa`: forged or replayed token → `InvalidSignature`; wrong-length imprint → `InvalidInput`; unreachable TSA → `Unavailable`.
3. `HttpCrlSource`: malformed CRL → `InvalidInput`; refused address (SSRF) → `InvalidInput`; unreachable server → `Unavailable`. `HttpOcspSource`: replayed response (nonce) → `InvalidSignature`.
4. One test per case, on a local server.

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| The kind each source reports | Already in this repository: `nacre_tsp::Error::kind()` (`crates/nacre-tsp/src/error.rs:65`), `nacre_revocation::Error::kind()` (`crates/nacre-revocation/src/error.rs:108`) | — (first rung) |
| `kind` field and four constructors on `nacre_core::Error` | New code, in `crates/nacre-core/src/error.rs` | Not in the repository; the standard library and thiserror give the `source` plumbing, which the variants keep using, but no kind |
| Local TSA answering 200 with a fixture body | Already in this repository: `serve_once` (`crates/nacre-tsp/tests/http.rs:15`), given the status line and body as parameters | — (first rung) |
| Garbage CRL route, closed-port URL | Already in this repository: `serve()` (`crates/nacre-revocation/tests/http.rs:39`) gains one route; `TcpListener` from std gives the closed port | — (first rung) |
| Forged and replayed tokens | Already in this repository: `tests/corpus/attacks/signature-invalid.tsr`, `valid.tsr`, `recorded/data.bin` of `nacre-tsp` | — (first rung) |

## Tasks
1. [x] **Contract** — in `crates/nacre-core/src/error.rs`, turn the two variants into `Timestamp { kind: ErrorKind, #[source] source: BoxError }` and `Revocation { kind: ErrorKind, #[source] source: BoxError }`, messages unchanged (`:15`, `:18`). Add `pub fn timestamp(source: impl Into<BoxError>) -> Self` and `pub fn revocation(...)` with `ErrorKind::Unavailable`, and `pub fn timestamp_with_kind(kind: ErrorKind, source: impl Into<BoxError>) -> Self`, `pub fn revocation_with_kind(...)`. `kind()` returns the field for both (`:28`). Rustdoc: the default, and that the source is passed by value (a `Box<E>` would be boxed twice). Update the crate doc at `crates/nacre-core/src/lib.rs:9-12` in one sentence. Migrate `crates/nacre-core/tests/contract_objects.rs:19` to `Error::timestamp(io::Error::other("tsa down"))`, keeping its `downcast_ref` check (`:50-54`). In `crates/nacre-core/tests/error_kind.rs:25-26`, replace the two rows by four: both defaults → `Unavailable`, `timestamp_with_kind(InvalidSignature, ..)` → `InvalidSignature`, `revocation_with_kind(InvalidInput, ..)` → `InvalidInput`. Fails if: `kind()` ignores the field (the two non-default rows), or the default is not `Unavailable` (the default rows); `contract_objects` fails if `source()` no longer yields the `io::Error`.
2. [x] **TSA** — `crates/nacre-tsp/src/http.rs:60`: `error => nacre_core::Error::timestamp_with_kind(error.kind(), error)`, the `DigestLength` arm (`:57-59`) unchanged. In `crates/nacre-tsp/tests/http.rs`, give `serve_once` the response to send (status line and body), keep the existing test on a 500, and add three tests: `forged_token_is_invalid_signature` (serves `corpus/attacks/signature-invalid.tsr`, imprint = SHA-256 of `corpus/recorded/data.bin`), `replayed_token_is_invalid_signature` (serves `corpus/attacks/valid.tsr`: the random nonce of the request never matches), `unreachable_tsa_is_unavailable` (a port bound then dropped). Each asserts the core error's `kind()` and `matches!(.., nacre_core::Error::Timestamp { .. })`. Fails if: `http.rs:60` keeps the default kind (the two `InvalidSignature` tests).
3. [x] **Revocation sources** — `crates/nacre-revocation/src/http.rs:206` and `:311`: `nacre_core::Error::revocation_with_kind(error.kind(), error)`. `crates/nacre-revocation/src/fallback.rs:39`: `nacre_core::Error::revocation("unreachable")`. In `crates/nacre-revocation/tests/http.rs`, migrate `fetch` and `ask` (`:131`, `:177`) to `Err(nacre_core::Error::Revocation { source, .. }) => Err(*source.downcast::<Error>().unwrap())`; add a `GET /garbage.crl` route to `serve()` answering bytes that are not DER; add a helper returning the core error, and four tests: `malformed_crl_is_invalid_input`, `refused_crl_address_is_invalid_input` (`HttpCrlSource::new()` on 127.0.0.1), `unreachable_crl_server_is_unavailable` (`allowing_loopback()`, closed port), `replayed_ocsp_response_is_invalid_signature` (`POST /ocsp`, fixed nonce). Each asserts the core error's `kind()`. Fails if: either `map_err` keeps the default (the `InvalidInput` and `InvalidSignature` tests).
4. [x] **Callers outside the two families** — `crates/nacre-cms/src/error.rs:139`: `nacre_core::Error::timestamp("x")`; `crates/nacre-pades/src/error.rs:65`: same; `crates/nacre-pades/tests/sign.rs:225`: `.map_err(nacre_core::Error::timestamp)`; any construction or pattern of the two variants s11 added under `crates/nacre-pades/` (grep `Error::Timestamp(`, `Error::Revocation(` on the rebased tree). Their rows keep `Unavailable`. Fails if: anything was missed — the workspace does not compile; a wrong kind breaks `crates/nacre-pades/tests/sign.rs:297` and the cms/pades kind rows.
5. [x] **Full suite and type check**, once, after the last edit: `po-run --story s39-error-kind-from-sources --label test -- 'cargo test --workspace'`, then `po-run --story s39-error-kind-from-sources --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`.

## Scene viewpoints
—

## Run interdicts
- No `downcast`, `downcast_ref` or `is::<..>()` in `crates/nacre-core/src/` (ADR-0016): `git diff main...story/s39-error-kind-from-sources -- crates/nacre-core/src | grep -n downcast` is empty.
- The `#[error(...)]` texts of `Timestamp` and `Revocation` in `crates/nacre-core/src/error.rs` are byte-identical to `main`; `ErrorKind` and its `Display` (`:38-64`) have an empty diff (no new kind, ADR-0012).
- `crates/nacre-tsp/src/error.rs` and `crates/nacre-revocation/src/error.rs` have an empty diff: the kinds are carried, never remapped.
- `HttpCrlSource` gains no signature check: `crates/nacre-revocation/src/http.rs` changes only at `:206` and `:311`.
- The traits `TimestampAuthority` and `RevocationSource` (`crates/nacre-core/src/timestamp.rs`, `revocation.rs`) have an empty diff.
- No `Cargo.toml` changes; no new dependency; no test contacts a host other than 127.0.0.1.
- No `Box::new(error)` passed to the new constructors (`grep -n "with_kind(.*Box::new" crates` is empty).

## The pivot
Everything hinges on the shape of ADR-0020: struct variants built by constructors, which break every caller once at compile time instead of keeping `Error::Timestamp(e.into())` alive with a silent default. Ways it could be wrong:
- The owner prefers option 2 (no caller outside the families changes, `Owns` stays as written): tasks 1 to 4 are rewritten around a `SourceError` type and a hand-written `std::error::Error` for `nacre_core::Error`; compare with `contract_objects.rs:50-54`, which must still downcast to the `io::Error`.
- `impl Into<BoxError>` double-boxes a caller's `Box<E>`: the reviewer checks every new call site passes the error by value, and that `revocation/tests/http.rs` still downcasts to `nacre_revocation::Error`.
- A source maps a TSA's own malformed answer (`nacre_tsp::Error::Der`) to `InvalidInput`, which reads as the caller's fault; that is `nacre_tsp::Error::kind()`'s existing mapping (`crates/nacre-tsp/src/error.rs:68`), carried unchanged here, not decided here.

## Files touched
`crates/nacre-core/src/error.rs`, `crates/nacre-core/src/lib.rs`, `crates/nacre-core/tests/error_kind.rs`, `crates/nacre-core/tests/contract_objects.rs`, `crates/nacre-tsp/src/http.rs`, `crates/nacre-tsp/tests/http.rs`, `crates/nacre-revocation/src/http.rs`, `crates/nacre-revocation/src/fallback.rs`, `crates/nacre-revocation/tests/http.rs`, `crates/nacre-cms/src/error.rs`, `crates/nacre-pades/src/error.rs`, `crates/nacre-pades/tests/sign.rs`, possibly other files under `crates/nacre-pades/` that s11 adds. Plus `docs/research/`, `docs/plans/`, `docs/decisions/0020-source-kind-in-struct-variants.md`.

## Test strategy
Automated, 7 new tests within the budget of 25, each at the layer that owns its rule:
- Contract (`crates/nacre-core/tests/error_kind.rs`): the default and the carried kind, as rows of the existing `core_kinds` test; no new test function.
- TSA adapter (`crates/nacre-tsp/tests/http.rs`): 3 tests on a local server — forged, replayed, unreachable. The wrong-length case is already covered by `http_tsa_sends_only_the_request_and_reports_failure` (`:85-88`) and not repeated.
- Revocation adapters (`crates/nacre-revocation/tests/http.rs`): 4 tests on a local server — malformed CRL, refused address, unreachable, replayed OCSP response.
- Not tested again: each family's variant-to-kind table, already covered by `every_variant_has_its_kind` in both crates; the `Display` of `ErrorKind` (`kind_display_is_fixed`).
- The unreachable cases pass with the default as well; they guard the criterion, while the `InvalidInput` and `InvalidSignature` cases are the ones that bite when the source's kind is dropped.

Visual checks: none (`Surface: endpoint`, no screen).

## Done when
- One commit on `story/s39-error-kind-from-sources`, landed on `main` through a pull request as `s39-error-kind-from-sources: Le kind() d'une erreur d'horodatage ou de révocation dit sa vraie catégorie`.
- `cargo test --workspace` and the clippy check green through `po-run`, recorded in `docs/verif/s39-error-kind-from-sources.md`.
- ADR-0020 `accepted` (or rewritten for the chosen option), the review with no open critical finding.
