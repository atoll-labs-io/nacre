---
validated: yes
---
# Plan — s07-tsp-client

[Story](../stories.md) · [Research](../research/s07-tsp-client.md)

Branch `story/s07-tsp-client`. Read `docs/research/s07-tsp-client.md` first; this plan builds on it without repeating it.

Validated autonomously (`Plan validation: autonomous`): no human reviewed this plan. No structural choice is left open: `ureq` with rustls is ADR-0006, RFC 3161 written in Nacre on `nacre-cms` is ADR-0004, `cargo-fuzz` is ADR-0008, `kind()` is ADR-0012. The reserved ADR-0014 is not used.

## Story
A new crate `crates/nacre-tsp/` builds a DER `TimeStampReq` (nonce, `certReq`) from a digest, reads a `TimeStampResp` and verifies its token; behind `http`, a `TimestampAuthority` calls a TSA over HTTP. Criteria (`docs/stories.md:128-132`): (1) request, response, imprint, nonce, status and signature checked; (2) differing imprint, nonce or signature rejected, each with its own error; (3) `http` implementation returns a verified token from s02's TSA; (4) no network dependency without `http`; (5) hostile input never panics, a fuzz target, `docs/security/attacks/tsp.md` with replay without nonce, token of another imprint, TSA certificate without `id-kp-timeStamping`, each with its rejected case.

Story correction carried by the research (structuring fact 1): FreeTSA's token (SHA-512, P-384) is **not** verifiable by `nacre-cms`; DigiCert is the public fixture that verifies, FreeTSA is kept as a fixture that must fail `Indeterminate`. The lead files an issue for SHA-384/512 and P-384 in `nacre-cms` (outside this story's `Owns`).

Decisions the research left open, settled here:
- **`signingCertificateV2` is required** (`Error::SigningCertificateMissing`, kind `Indeterminate`): `nacre-cms` checks it against the signer certificate (`crates/nacre-cms/src/verify.rs:97-102`), while a v1 `ESSCertID` would need SHA-1, absent from the tree, and would leave certificate substitution unchecked. Bench and DigiCert carry v2.
- **EKU per RFC 3161 §2.3**: the signer certificate's `ExtendedKeyUsage` is present, critical, and holds `id-kp-timeStamping` alone; otherwise `Error::NotTimestampingCertificate`.
- **Nonce**: 8 bytes from `getrandom::fill`, as OpenSSL's 64 bits; compared as unsigned integers (leading zero octets ignored).

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Reading and verifying the token's `SignedData` | repository: `SignedData::from_der`, `econtent()`, `verify(None)`, `VerifiedSigner::certificate()` (`crates/nacre-cms/src/model.rs:84,180`, `verify.rs:25,45`) | — |
| ASN.1 of `TimeStampReq`, `TimeStampResp`, `PKIStatusInfo`, `TSTInfo`, `MessageImprint` | new code on `der` 0.8 (derive or hand TLVs) | Not in the repository; `x509-tsp` is forbidden (ADR-0004); `der` encodes, Nacre writes the format |
| `genTime` with fractional seconds | new code: a small parser to `der::DateTime` | `der::asn1::GeneralizedTime` refuses fractions (research fact 4) |
| EKU reading | dependency: `x509-cert` 0.3 `get_extension::<ExtendedKeyUsage>()` | — |
| Nonce randomness | dependency already in the tree: `getrandom` 0.4 (via `rsa`, `p256`), now declared directly | std has no CSPRNG |
| HTTP transport | dependency: `ureq` 3, optional, as `crates/nacre-conformance/Cargo.toml:18` | ADR-0006 |
| Forged attack corpus | new code: one cargo example, modelled on `crates/nacre-cms/examples/forge_attacks.rs` | OpenSSL refuses to sign with a certificate lacking the timeStamping EKU and cannot drop a nonce it was asked for |
| Hostile-input harness (`length_offsets`) | copy of `crates/nacre-cms/tests/hostile.rs:23` into the new test | test helpers are not shared across crates; no dev crate exists for it |
| Error enum, `kind()` table test | `thiserror` 2, as `crates/nacre-cms/src/error.rs` | — |

## Tasks
1. [x] **Crate skeleton.** `crates/nacre-tsp/Cargo.toml`: `name = "nacre-tsp"`, `version = "0.1.0"`, edition 2024, `rust-version = "1.97"`, `license = "MIT OR Apache-2.0"`, a description, `[lints] workspace = true`.
   - dependencies: `nacre-core = { path = "../nacre-core", version = "0.1.0" }`, `nacre-cms = { path = "../nacre-cms", version = "0.1.0" }`, `der = { version = "0.8", features = ["alloc", "derive", "oid"] }`, `spki = { version = "0.8", features = ["alloc"] }`, `x509-cert = "0.3"`, `getrandom = "0.4"`, `thiserror = "2"`, `ureq = { version = "3", default-features = false, features = ["rustls"], optional = true }`.
   - `[features] default = []`, `http = ["dep:ureq"]`.
   - dev-dependencies: `nacre-tsp = { path = ".", features = ["http"] }`, `nacre-core` with `test-signer`, `nacre-conformance = { path = "../nacre-conformance" }` (for `pki_dir()`), `sha2 = "0.11"`, `p256 = { version = "0.14", features = ["ecdsa", "pkcs8"] }`, `x509-cert` with `builder`.
   - `src/lib.rs`: `#![forbid(unsafe_code)]`, crate docs saying **experimental**, that only the imprint leaves, that nothing reads the clock.
   - `src/oid.rs`: `id-ct-TSTInfo` 1.2.840.113549.1.9.16.1.4, `id-kp-timeStamping` 1.3.6.1.5.5.7.3.8, `sha384` 2.16.840.1.101.3.4.2.2, `sha512` …2.3 (reuse `nacre_cms::oid::SHA256`, `SIGNING_CERTIFICATE_V2`).
   - `src/error.rs`: one `#[non_exhaustive]` `thiserror` enum, its `kind()`:
     `Der(der::Error)`, `DigestLength{expected,actual}`, `TokenMissing`, `NotTstInfo`, `TstInfoVersion(u8)`, `GenTime`, `Certificate(der::Error)` → `InvalidInput`; `ImprintMismatch`, `NonceMissing`, `NonceMismatch`, `NotTimestampingCertificate` → `InvalidSignature`; `UnsupportedAlgorithm(ObjectIdentifier)`, `SigningCertificateMissing` → `Indeterminate`; `Refused { status: u32, fail_info: Option<u32> }`, `Random(getrandom::Error)`, `#[cfg(feature = "http")] Http(ureq::Error)` → `Unavailable`; `Cms(nacre_cms::Error)` → `inner.kind()`. No message prints token bytes, imprint or nonce (ADR-0012).
   - Test: `every_variant_has_its_kind` in `src/error.rs`, one row per variant and a row count, as `crates/nacre-cms/src/error.rs`.
2. [x] **Request** (`src/request.rs`): `pub struct Request` with `Request::new(algorithm: DigestAlgorithm, imprint: &[u8], nonce: &[u8]) -> Result<Self, Error>` (imprint length checked with `output_len()`, `DigestLength` otherwise; a `DigestAlgorithm` variant unknown here → `UnsupportedAlgorithm` through the wildcard arm), `Request::with_random_nonce(algorithm, imprint)` (8 bytes, `getrandom::fill`, `Random` on failure), `to_der()`. Encoding: `SEQUENCE { INTEGER 1, MessageImprint { AlgorithmIdentifier { oid, NULL }, OCTET STRING }, INTEGER nonce (unsigned), BOOLEAN TRUE }`, no policy, no extensions.
   - Corpus `tests/corpus/recorded/`: `data.bin` and `request.tsq` copied from `/tmp/s07probe/` (research, Recorded material); if `/tmp` lost them, regenerate with `openssl ts -query -data data.bin -sha256 -cert -out request.tsq` on 64 fresh random bytes, and fetch the three answers again (task 3).
   - Tests (`tests/request.rs`): `request_matches_openssl` — `Request::new(Sha256, sha256(data.bin), nonce)` with the nonce of `request.tsq` (constant in the test, from `openssl ts -query -in request.tsq -text`) writes `request.tsq` byte for byte; `wrong_imprint_length_is_refused` → `DigestLength`.
3. [x] **Response and token verification** (`src/response.rs`, `src/token.rs`):
   - `pub fn verify_token(token: &[u8], algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<VerifiedToken, Error>` — the order is a contract: `SignedData::from_der` → `econtent_type == id-ct-TSTInfo` and `econtent` present (`NotTstInfo`) → `verify(None)` (`Cms`) → `signingCertificateV2` among the signed attributes (`SigningCertificateMissing`) → EKU of `VerifiedSigner::certificate()` (`Certificate`, `NotTimestampingCertificate`) → decode `TSTInfo` (version 1 else `TstInfoVersion`; `genTime` parsed by hand, `YYYYMMDDHHMMSS[.f{1,9}]Z`, else `GenTime`) → imprint OID and hash equal to the expected ones (`ImprintMismatch`; parameters absent or NULL).
   - `pub fn verify_response(response: &[u8], request: &Request) -> Result<VerifiedToken, Error>` — decode `TimeStampResp` → status 0 or 1, else `Refused` with `failInfo` bits → token present (`TokenMissing`) → `verify_token` with the request's imprint → nonce present (`NonceMissing`) and equal (`NonceMismatch`).
   - `pub struct VerifiedToken`: `token()` (the received `ContentInfo` TLV, never re-encoded), `tsa_certificate()`, `gen_time() -> der::DateTime`, `policy()`, `serial_number()`, `nonce()`.
   - Corpus `tests/corpus/recorded/`: `bench.tsr`, `digicert.tsr`, `freetsa.tsr` (from `/tmp/s07probe/`, or refetched with `curl -H 'Content-Type: application/timestamp-query' --data-binary @request.tsq` against `http://timestamp.digicert.com` and `https://freetsa.org/tsr`, and `openssl ts -reply -config openssl.cnf -queryfile request.tsq` on a copy of `conformance/pki/` generated under `/tmp`). `tests/corpus/README.md`: source, date, OpenSSL version, commands, "public certificates, random data, no document, no key".
   - Unit test in `src/token.rs`: `gen_time_parsing` — `20261022092550Z` and `20261022092550.125Z` accepted, `20261022092550.Z`, a ten-digit fraction, a missing `Z` and a month 13 refused.
   - Tests (`tests/recorded.rs`): `bench_response_verifies` (token equals the embedded bytes; certificate has the EKU); `digicert_response_verifies` (RSA-4096, the s03 review's request); `freetsa_response_is_indeterminate` (`Cms(UnsupportedAlgorithm(sha512))`, kind `Indeterminate`); `other_nonce_is_rejected` (bench vs the same imprint with another nonce → `NonceMismatch`); `refused_status_is_reported` (inline `30 05 30 03 02 01 02` → `Refused { status: 2, .. }`); `granted_without_token_is_rejected` (inline `30 05 30 03 02 01 00` → `TokenMissing`).
4. [x] **Forged attack corpus and its tests.** `examples/forge_attacks.rs`, deterministic (fixed secret `[0x11; 32]`, RFC 6979, fixed `genTime` `20261022092550.25Z`), answering `recorded/request.tsq`'s imprint and nonce. A self-signed TSA certificate on that key with a hand-built **critical** EKU `Extension` (the `ExtendedKeyUsage` builder default is non-critical, research Verified interfaces). Each file is correct apart from its one defect; `SignedData` built from public fields as `crates/nacre-cms/examples/forge_attacks.rs` does, attributes `contentType` TSTInfo, `messageDigest`, `signingCertificateV2`. Output to `tests/corpus/attacks/`: `valid.tsr`, `nonce-absent.tsr`, `imprint-other.tsr`, `no-timestamping-eku.tsr` (signed by the same key, certificate of `TestSigner::from_secret(&[0x11; 32])`, a CA without EKU), `signature-invalid.tsr` (one bit of the signature flipped), `ess-v1-only.tsr` (`signingCertificate` v1 instead of v2).
   - Tests (`tests/attacks.rs`): `forged_baseline_verifies` (also proves a fractional `genTime` is read); `replay_without_nonce_is_rejected` → `NonceMissing`; `token_of_another_imprint_is_rejected` → `ImprintMismatch`; `certificate_without_timestamping_is_rejected` → `NotTimestampingCertificate`; `altered_signature_is_rejected` → `Cms(SignatureInvalid)`; `ess_v1_only_is_indeterminate` → `SigningCertificateMissing`.
   - `docs/security/attacks/tsp.md`, in French, shaped as `docs/security/attacks/cms.md`: one row per attack (case, test, error), including the other-nonce replay of task 3; regeneration command; "Hors de ce fichier": chain and validity of the TSA certificate (s16), `genTime` against the control date (s14+), SHA-384/512 and P-384 tokens (FreeTSA, issue), BER input.
5. [x] **Hostile input and fuzzing.** `tests/hostile.rs`: `truncated_and_relengthed_responses_never_panic` — every prefix of `bench.tsr` and every length octet changed (helper copied from `crates/nacre-cms/tests/hostile.rs:23`) returns `Err` from `verify_response`; `deep_nesting_and_huge_lengths_are_errors` — 10 000 nested `30 80`/`30 81 ..` and a length of 2^31 return `Err`. `fuzz/` as `crates/nacre-cms/fuzz/` (own `[workspace]`, `.gitignore`), target `response`: `verify_response` with the recorded request and `verify_token` with its imprint, results ignored. Check: `cd crates/nacre-tsp/fuzz && cargo +nightly fuzz build response` if nightly is present, else `cargo check` there.
6. [x] **HTTP authority** (`src/http.rs`, `#[cfg(feature = "http")]`): `pub struct HttpTsa` with `HttpTsa::new(url: &str)`; `ureq::Agent` with a 30 s global timeout; `impl TimestampAuthority`: `Request::with_random_nonce`, `POST` with `Content-Type: application/timestamp-query`, body read with a 1 MiB limit, `verify_response`, return `token()`; every error as `nacre_core::Error::Timestamp(Box::new(e))`.
   - Test (`tests/http.rs`): `http_tsa_sends_only_the_request_and_reports_failure` — a `std::net::TcpListener` on `127.0.0.1:0` in a thread reads one request, answers `HTTP/1.1 500`; the test asserts the header `content-type: application/timestamp-query`, a body equal to a `TimeStampReq` holding the given imprint and `certReq`, and `timestamp()` returning `Err` of kind `Unavailable`.
7. [x] **Conformance against the bench TSA.** `tests/conformance.rs`, `#[ignore = "conformance"]`: `bench_tsa_returns_a_verified_token` — `HttpTsa::new("http://127.0.0.1:18081/cgi-bin/tsa")`, a SHA-256 imprint, `timestamp()` succeeds, `verify_token` on the result passes, and its `tsa_certificate()` equals the DER of `pki_dir()/tsa.cert.pem` (PEM decoded with `der`'s `pem` feature or `x509-cert` `from_pem`). Run it once with the bench up (`conformance/README.md` Run section) through `po-run --story s07-tsp-client --label conformance -- 'cargo test -p nacre-tsp --test conformance -- --ignored'`; if podman cannot start the bench here, say so in the record: `conformance.yml` runs it.
8. [x] **Closing checks.** `po-run --story s07-tsp-client --label no-network-deps -- '! cargo tree -p nacre-tsp -e normal --prefix none | grep -Eq "^(ureq|rustls|ring|webpki)"'`, and once more without `!` and with `--features http` to show the check bites; the full suite through `po-run ... --label test -- 'cargo test --workspace'`; after the last edit, `po-run ... --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'`; `cargo fmt --all --check`.

## Scene viewpoints
—

## Run interdicts
- `git diff main...story/s07-tsp-client` touches only `crates/nacre-tsp/`, `docs/security/attacks/tsp.md`, `docs/research/s07-tsp-client.md`, `docs/plans/s07-tsp-client.md`, `docs/verif/s07-tsp-client.md`: root `Cargo.toml`, `crates/nacre-core/`, `crates/nacre-cms/`, `crates/nacre-conformance/`, `conformance/` and `.github/` end with an empty diff.
- No `x509-tsp`, `cms` or `pkcs7` crate (`cargo tree -p nacre-tsp --all-features -i x509-tsp` finds nothing); no `[workspace.dependencies]`.
- No test, example or fuzz target reaches a public TSA: `freetsa` and `digicert` URLs appear only in `tests/corpus/README.md`.
- No private key in git: `grep -r "PRIVATE KEY" crates/nacre-tsp` is empty; the forge example keeps its secret in code, as s03's.
- No clock read in `src/`: no `SystemTime`, `Instant` or `chrono`.
- No `unwrap`, `expect`, `panic!` or indexing outside `#[cfg(test)]`, tests and the example (workspace lints).
- `nacre-cms` is not extended for SHA-512 or P-384 in this story.

## The pivot
The token's trust rests on `nacre_cms::SignedData::verify(None)` followed by three rules nacre-tsp adds (TSTInfo content type, mandatory `signingCertificateV2`, RFC 3161 EKU), in a fixed order that each forged case must reach. Ways it could be wrong:
- `verify(None)` proves less than assumed — compare `crates/nacre-cms/src/verify.rs:72-123` with RFC 5652 §5.4/§5.6 for an encapsulated content: the `messageDigest` must be over the `eContent` octets, which the recorded bench and DigiCert tokens confirm.
- Requiring `signingCertificateV2` turns away TSAs that only send v1 — compare with the recorded DigiCert token (both) and with any TSA Patelle names; loosening it later needs SHA-1 and a check of the v1 hash.
- A forged case answering for another rule (false test 5) — the reviewer flips each guard and checks that only its own test turns red; `forged_baseline_verifies` must stay green with every guard in place.

## Files touched
`crates/nacre-tsp/{Cargo.toml, src/{lib,error,oid,request,response,token,http}.rs, examples/forge_attacks.rs, tests/{request,recorded,attacks,hostile,http,conformance}.rs, tests/corpus/{README.md, recorded/*, attacks/*}, fuzz/{Cargo.toml,.gitignore,fuzz_targets/response.rs}}`, `docs/security/attacks/tsp.md`, `docs/verif/s07-tsp-client.md`.

## Test strategy
21 tests, within `Test budget` 25. Each names one rule; a guard removed turns exactly its test red.
- Unit (in `src/`): `every_variant_has_its_kind`, `gen_time_parsing`.
- Encoding: `request_matches_openssl`, `wrong_imprint_length_is_refused`.
- Verification on recorded answers: `bench_response_verifies`, `digicert_response_verifies`, `freetsa_response_is_indeterminate`, `other_nonce_is_rejected`, `refused_status_is_reported`, `granted_without_token_is_rejected`.
- Attacks on forged answers: `forged_baseline_verifies`, `replay_without_nonce_is_rejected`, `token_of_another_imprint_is_rejected`, `certificate_without_timestamping_is_rejected`, `altered_signature_is_rejected`, `ess_v1_only_is_indeterminate`.
- Hostile: `truncated_and_relengthed_responses_never_panic`, `deep_nesting_and_huge_lengths_are_errors`.
- Transport: `http_tsa_sends_only_the_request_and_reports_failure` (local socket, no public network).
- Conformance (ignored, bench): `bench_tsa_returns_a_verified_token`.
- Checks, not tests: `no-network-deps` through `po-run`; the fuzz target built.
Task tests run alone with `cargo test -p nacre-tsp --test <stem>`; the full suite and the type check once, at the end, through `po-run`.

## Done when
- Every task ticked, its tests green; `cargo test --workspace` and the clippy type check pass through `po-run`, `cargo fmt --all --check` clean, `no-network-deps` recorded.
- Criterion 1: tasks 2–3; criterion 2: `token_of_another_imprint_is_rejected`, `other_nonce_is_rejected`, `altered_signature_is_rejected`, three distinct errors; criterion 3: task 7; criterion 4: task 8; criterion 5: tasks 4–5.
- One commit on `story/s07-tsp-client` carrying the code, the corpus, `docs/security/attacks/tsp.md`, this plan, the research and the record.
