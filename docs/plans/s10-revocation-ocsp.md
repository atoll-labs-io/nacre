---
validated: yes
---
# Plan — s10-revocation-ocsp

[Story](../stories.md) · [Research](../research/s10-revocation-ocsp.md)

Branch `story/s10-revocation-ocsp`. Read `docs/research/s10-revocation-ocsp.md` first; this plan builds on it without repeating it.

Technical choice: settled by the person on 2026-10-23 — option 1 of ADR-0018 (OCSP structures written in nacre-revocation on der 0.8); ADR-0018 accepted.

The OCSP structures cannot come from `x509-ocsp` as ADR-0004 says: its only release is on `der` 0.7. [ADR-0018](../decisions/0018-ocsp-structures-on-der-08.md) (`proposed`) ranks the options: (1) write them in `nacre-revocation` on `der` 0.8; (2) `x509-ocsp` 0.2.1 with a second `der` 0.7 stack; (3) a git dependency on RustCrypto `master`, unpublishable; (4) wait for `x509-ocsp` 0.3. The tasks below are written for option 1. Under option 2, task 3 becomes a thin conversion layer over `x509-ocsp` 0.2.1 (certificates crossing as DER bytes) and the rest stands.

## Story
Build a DER `OCSPRequest` for a certificate and its issuer with a nonce; read the `BasicOCSPResponse` and verify its signature, CA-signed or delegated (`id-kp-OCSPSigning`).
- AC1 request with nonce; response read; signature verified, CA or delegated responder.
- AC2 against the s02 responder: `revoked` → revoked with its date; `signer` → good.
- AC3 unauthorized responder, different nonce, `thisUpdate` out of tolerance → rejected, each with its own error.
- AC4 hostile response → error, never a panic; fuzz target; OCSP attacks in `docs/security/attacks/revocation.md`.

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| OCSP ASN.1 declarations | new code on `der` 0.8 derive (ADR-0018 option 1) | not in the repo (`grep -i ocsp crates/*/src` finds only `RevocationData::Ocsp`); std has no ASN.1; `x509-ocsp` 0.2.1 is on `der` 0.7 (research, Structuring facts) |
| Signature check of a response and of a delegated certificate | already in the repo: `check_algorithms`, `verify_ecdsa`, `verify_rsa` (`src/verify.rs:57-110`), split out of `verify` | — |
| "Bytes as received" for `tbsResponseData` and a certificate's `tbsCertificate` | already in the repo: the `tlv_bytes` pattern of `Crl::from_der` (`src/crl.rs:49-57`), moved into a shared helper | — |
| Critical-extension refusal | already in the repo: `critical()` (`src/crl.rs:158-167`), made `pub(crate)` | — |
| HTTP agent, address policy, error mapping | already in the repo: `with_policy`, `AddressPolicy`, `http_error` (`src/http.rs:46-56,106-143`) | — |
| Random nonce | dependency already used in the workspace: `getrandom` 0.4, as in `crates/nacre-tsp/src/request.rs:34-37` | std has no CSPRNG |
| SHA-1 for `CertID` | new dependency `sha1` 0.11 (RustCrypto, same family as `sha2` 0.11) | not in `nacre-revocation`; RFC 5019 §2.1.1 asks for SHA-1 in `CertID`; `sha2` alone would make public responders answer `unknown` |
| `OcspStatus` | new code | `CrlStatus` (`src/crl.rs:34-45`) is named and documented for CRLs; renaming it changes s09's API for no AC |
| OCSP-then-CRL fallback | new code, a generic `Fallback<A, B>` source (~15 lines) | nothing in the repo composes sources; asked by the story's note |
| Hostile-input test | already in the repo: `length_offsets` and the mutation loop of `tests/hostile.rs:24-60`, reused in the same file | — |
| Attack corpus writer | already in the repo: the pattern and fixed keys of `examples/forge_attacks.rs`; a second example beside it | a single example would mix two corpora and their regeneration commands |

## Tasks
1. [x] **Split the signature check** in `src/verify.rs`: a `pub(crate) fn verify_signed(algorithm: ObjectIdentifier, spki: &SubjectPublicKeyInfoOwned, tbs: &[u8], signature: &[u8]) -> Result<(), Error>` holding `check_algorithms` + SHA-256 + `verify_ecdsa`/`verify_rsa`; `verify(&Crl, &Certificate)` keeps its outer/inner equality and `cRLSign` checks, then calls it. Move the `tlv_bytes` extraction of `Crl::from_der` into a `pub(crate)` helper (`signed_tbs(bytes) -> Result<Vec<u8>, Error>`) and make `critical()` `pub(crate)`. Test able to fail: the existing `tests/attacks.rs` (9) and `tests/read.rs` stay green unchanged.
2. [x] **Errors** in `src/error.rs`: add `ResponseStatus(u8)` (non-`successful` `OCSPResponseStatus`), `UnsupportedResponseType(ObjectIdentifier)`, `CertificateNotInResponse`, `UnknownCertificate` (`certStatus` `unknown`), `UnauthorizedResponder`, `NonceMismatch`, `ThisUpdateOutOfTolerance { this_update: SystemTime }`, `NoOcspResponder`, `Random(getrandom::Error)`. Kinds: `UnauthorizedResponder`, `NonceMismatch` → `InvalidSignature` (forged or replayed, ADR-0016's wording); `Random` → `Unavailable`; the rest → `Indeterminate`. Reword the enum doc ("a CRL or an OCSP response") and the `NonPublicAddress`/`Http` messages to name neither CRL nor URL ("the revocation source address is not public", "the revocation download failed"). Test able to fail: `every_variant_has_its_kind` with the new rows and counts (21, 23 with `http`).
3. [x] **OCSP structures and request** in `src/ocsp/` (`mod.rs`, `asn1.rs`, `request.rs`): `der` gets the `derive` feature; add `sha1 = "0.11"` and `getrandom = "0.4"`. Private declarations per RFC 6960 §4.1-4.2 (request: `OCSPRequest`, `TBSRequest`, `Request`, `CertID`; response: `OCSPResponse`, `ResponseBytes`, `BasicOCSPResponse` with `certs` kept as raw DER, `ResponseData`, `ResponderID`, `SingleResponse`, `CertStatus`, `RevokedInfo`). Public `OcspRequest::new(certificate, issuer, nonce: &[u8])` and `OcspRequest::with_random_nonce(certificate, issuer)` (32 octets, RFC 8954), `to_der()`, `nonce()`. `CertID`: SHA-1 of the issuer's encoded subject `Name` and of its `subjectPublicKey` bit-string value, and the certificate's serial; nonce extension `1.3.6.1.5.5.7.48.1.2`, non-critical, `extnValue` = DER `OCTET STRING` of the nonce. Test able to fail: `request_cert_id_matches_openssl`, written once task 5 has made its fixture — the `CertID` in OpenSSL's request fixture equals ours for the same pair, decoded with the crate's own declarations through a `#[cfg(test)]` unit test in `src/ocsp/request.rs`.
4. [x] **Response reading and judgement** in `src/ocsp/response.rs`, exported from `lib.rs` with `OcspStatus { Good, Revoked { date, reason: Option<CrlReason> } }` (`#[non_exhaustive]`, like `CrlStatus`):
   - `OcspResponse::from_der(bytes)`: trailing bytes refused; `responseStatus` ≠ 0 → `ResponseStatus`; `responseType` ≠ `id-pkix-ocsp-basic` → `UnsupportedResponseType`; keeps `tbsResponseData` bytes as received. Accessors `produced_at()`, `this_update()` (of the single response, or the first), `nonce()`.
   - `check_nonce(&self, request: &OcspRequest)`: a nonce present and different → `NonceMismatch`; absent → `Ok` (see pivot).
   - `check_this_update(&self, certificate, issuer, at, tolerance: Duration)`: the matching single response's `thisUpdate` outside `[at − tolerance, at + tolerance]` → `ThisUpdateOutOfTolerance`.
   - `status(&self, certificate, issuer, at)`, fixed order, documented as contract like `Crl::status`: (1) parse both certificates (`Certificate`, `IssuerCertificate`); (2) find the `SingleResponse` whose `CertID` matches, computed with its own hash (SHA-1 or SHA-256, other → `UnsupportedAlgorithm`) → else `CertificateNotInResponse`; (3) critical `responseExtensions` or `singleExtensions` → `UnsupportedCriticalExtension`; (4) responder: `ResponderID` names the issuer (`byName` equal to its subject, or `byKey` equal to SHA-1 of its key) → issuer key; otherwise a certificate of `certs` matching the `ResponderID`, whose issuer name is the issuer's subject, whose signature verifies with the issuer key (`verify_signed` over its received `tbsCertificate`), whose EKU holds `id-kp-OCSPSigning` and whose validity covers `producedAt` → its key; anything else → `UnauthorizedResponder`; (5) `verify_signed` over `tbsResponseData` → `SignatureInvalid`/`AlgorithmMismatch`/`UnsupportedAlgorithm`; (6) `nextUpdate` before `at` → `Expired`; a later `thisUpdate` is accepted, as for CRLs; (7) `good` → `Good`, `revoked` → `Revoked`, `unknown` → `UnknownCertificate`.
   Test able to fail: task 5's tests.
5. [x] **OpenSSL corpus** `tests/corpus/ocsp-openssl/` and tests `tests/ocsp_status.rs`: one script, recorded in `tests/corpus/README.md` like the CRL one, makes a throw-away P-256 CA, `leaf`, `revoked` (revocation date fixed in the index, `keyCompromise`), a delegated responder certificate (EKU `OCSPSigning`), `openssl ocsp -no_nonce` requests, and responses from `openssl ocsp -index` signed by the CA (`good.der`, `revoked.der`) and by the delegate (`delegated-good.der`); keys deleted. Tests: `ca_signed_revoked_has_its_date_and_reason`, `ca_signed_good_is_good`, `delegated_responder_is_accepted` (AC1, AC2 offline); dates read with `this_update()`, never hard-coded beyond the fixed revocation date.
6. [x] **Attack corpus** `tests/corpus/ocsp-attacks/` from a new example `examples/forge_ocsp_attacks.rs` (`[[example]] name = "forge_ocsp_attacks"`), deterministic like `forge_crl_attacks`, every response correctly signed apart from its one defect and saying `revoked` for the leaf (a skipped rule would answer "revoked", never the expected error); fixed nonce `N`, `thisUpdate` 2026-10-01, `nextUpdate` 2036-10-01, judged at 2027-01-01. Cases and their tests in `tests/ocsp_attacks.rs`: delegate issued by another CA → `UnauthorizedResponder`; delegate issued by the CA without `OCSPSigning` → `UnauthorizedResponder`; response checked against a request of another nonce → `NonceMismatch`; base response with `check_this_update` at `thisUpdate` + 1 day, tolerance 5 min → `ThisUpdateOutOfTolerance`; byte changed after signing → `SignatureInvalid`; `nextUpdate` 2026-06-01 → `Expired`; critical unknown `singleExtension` → `UnsupportedCriticalExtension`; response about another serial → `CertificateNotInResponse`; `unknown` status → `UnknownCertificate`; `responseStatus` `tryLater` → `ResponseStatus(3)`. One test each (10).
7. [x] **Hostile input and fuzz**: in `tests/hostile.rs`, a second test running the same truncation and length-mutation loop over `ocsp-openssl/revoked.der` through `from_der` + `status`; `fuzz/fuzz_targets/ocsp.rs` (fixed date, never the clock) and its `[[bin]]` in `fuzz/Cargo.toml`. Test able to fail: `mutated_ocsp_lengths_and_truncations_are_errors`; `cargo fuzz build` of the target is the reviewer's to run, not a test.
8. [x] **`HttpOcspSource`** in `src/http.rs` (feature `http`): `new()` / `allowing_loopback()` built on the same `with_policy` agent; `responder_url(certificate)`: first `id-ad-ocsp` (`1.3.6.1.5.5.7.48.1`) access location of `authorityInfoAccess` starting `http://`, else `NoOcspResponder`; `revocation(certificate, issuer)`: `OcspRequest::with_random_nonce`, POST `Content-Type: application/ocsp-request`, redirect refused, body limit 64 KiB, `OcspResponse::from_der` + `check_nonce`, returns `RevocationData::Ocsp(body)`. Tests in `tests/http.rs` (local server returning a fixed response with nonce `N`): `ocsp_nonce_mismatch_is_rejected` (the random request nonce never equals `N`) and `ocsp_loopback_responder_is_refused_by_default` (`NonPublicAddress`, message without the URL).
9. [x] **`Fallback<A, B>`** in `src/fallback.rs`, no feature: a `RevocationSource` that asks `A`, then `B` when `A` fails, returning `B`'s error when both fail. Test `fallback_asks_the_second_source_when_the_first_fails` with two in-test sources (one failing, one returning a fixed `RevocationData::Crl`) — fails if `B` is never asked or if `A`'s success is overridden.
10. [x] **Bench and documents**: `tests/bench.rs` gets `ocsp_says_revoked_and_good_on_the_bench` (`#[ignore = "conformance"]`, `HttpOcspSource::allowing_loopback()`, judged at the response's `this_update()`): `revoked` → `Revoked` whose date equals the bench CRL's date for the same certificate, `signer` → `Good` (AC2). `docs/security/attacks/revocation.md` gets an OCSP section: rule order, a table attack → corpus case → test → error for task 6 and the two HTTP cases, the missing-nonce choice and the `unknown` status under "Hors de ce fichier". `lib.rs` crate doc covers OCSP, keeps "Experimental". Once ADR-0018 is accepted with option 1, ADR-0004's frontmatter gets `superseded-by: [0018]` (frontmatter only). Test able to fail: the bench test, in the conformance workflow.

## Scene viewpoints
—

## Run interdicts
- Root `Cargo.toml`, `Cargo.lock` (absent), `crates/nacre-core/`, every other crate: empty diff (`git diff main...story/s10-revocation-ocsp -- Cargo.toml crates/nacre-core crates/nacre-tsp ...`).
- `tests/attacks.rs`, `tests/read.rs`, `tests/status.rs` and `tests/corpus/openssl/`, `tests/corpus/attacks/`: empty diff — the CRL contract stays as shipped.
- No `x509-ocsp`, `cms`, `x509-tsp` dependency (unless ADR-0018 is settled on option 2, then `x509-ocsp` alone); no `[workspace.dependencies]`.
- No `SystemTime::now`/`Instant::now` anywhere in `crates/nacre-revocation/` (`grep`).
- No URL in any `Error` message or `Debug` output; no `unwrap`/`expect`/`panic!`/indexing outside `#[cfg(test)]`, tests and examples.
- No private key in `tests/corpus/`; the OpenSSL script deletes its temp directory.
- No network call in tests other than `127.0.0.1` servers and the ignored bench test.

## The pivot
The judgement is split in three, by who knows what: the **nonce** is checked where the request was made (`check_nonce`, called by `HttpOcspSource`); **`thisUpdate` freshness** against a date and tolerance the caller gives (`check_this_update`); **revocation at a date** in `status`, which, like `Crl::status`, accepts a `thisUpdate` later than `at` so s17 can judge a signing time with a response fetched afterwards. Ways this is wrong:
- A caller who calls `status` alone gets no freshness check at all → compare with s11/s17's needs; the crate doc must say both checks exist and when to call them.
- Accepting a missing nonce lets a captured, still-valid response be replayed within its `nextUpdate` → compare with RFC 8954 §2.1 and with what DSS does (DSS does not require it); stricter alternative: a `NonceMissing` error, which public pre-signed responders would hit.
- Authorizing the responder by `ResponderID` then by the delegate's issuer name and signature: a delegate whose name matches the issuer's subject but with another key, or a `byKey` hash computed over the wrong bytes (whole SPKI instead of the key bit string), would slip through or wrongly fail → the delegated OpenSSL fixture and the two unauthorized-delegate cases are where to look.

## Files touched
`crates/nacre-revocation/`: `Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/verify.rs`, `src/crl.rs` (helper extraction only), `src/http.rs`, `src/fallback.rs`, `src/ocsp/{mod,asn1,request,response}.rs`, `examples/forge_ocsp_attacks.rs`, `tests/{ocsp_status,ocsp_attacks,hostile,http,bench}.rs`, `tests/corpus/{README.md,ocsp-openssl/,ocsp-attacks/}`, `fuzz/Cargo.toml`, `fuzz/fuzz_targets/ocsp.rs`. `docs/security/attacks/revocation.md`. `docs/decisions/0018-ocsp-structures-on-der-08.md` (status set by `/po-plan`), `docs/decisions/0004-*.md` (frontmatter only, task 10).

## Test strategy
New automated tests, 19, within `Test budget` 25, all at the crate's public API (service layer) except the `CertID` unit test:
- 1 unit: `request_cert_id_matches_openssl` (task 3); the kind table is an existing test extended (task 2).
- 3 interop: OpenSSL CA-signed good, revoked, delegated (task 5).
- 10 attacks, one per rule of `status`, `check_nonce`, `check_this_update`, `from_der` (task 6) — each fixture defective in one point only, so the neutralised rule answers "revoked".
- 1 hostile mutation loop (task 7).
- 2 HTTP adapter tests on a local server (task 8): nonce rejected in the source, address refused.
- 1 fallback (task 9).
- 1 bench, ignored, conformance workflow (task 10).
Cut: no separate test per kind (the table covers it), no RSA OCSP interop (the RSA path is shared with CRLs and covered there), no SHA-256 `CertID` interop test (matched by the same code path; the reviewer may bite it by removing the SHA-256 arm).
Checks: task tests after each task; full suite `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` once at the end through `po-run`.

## Done when
All boxes ticked; `cargo test --workspace` and clippy green through `po-run` in `docs/verif/s10-revocation-ocsp.md`; the bench test passes in the conformance workflow; `docs/security/attacks/revocation.md` lists every OCSP attack with its test; the fuzz target builds; review without open critical finding; one commit `s10-revocation-ocsp: Interroger un répondeur OCSP` landed through a pull request.

## Fix run 1 (review of 2026-10-23)
- [x] major — delegate valid at `producedAt` untested: `expired-delegate` case in `forge_ocsp_attacks` (delegate valid 2025-01-01 to 2026-01-01), test `delegate_expired_at_produced_at_is_unauthorized`, row in `docs/security/attacks/revocation.md`.
- [x] minor — CRL-only wording: `SignatureInvalid`, `Expired`, `AlgorithmMismatch`, `Der`, `IssuerCertificate` messages and rustdoc name CRL and OCSP response, or neither.
- [x] minor — `OcspRequest::new` refuses a nonce outside 1 to 32 octets with a new `Error::NonceLength(usize)` (kind `InvalidInput`, kind table 22/24 rows); test `nonce_outside_one_to_32_octets_is_refused`.
- [x] minor — attacks file says the delegate's own revocation and `id-pkix-ocsp-nocheck` belong to the caller, and in Nacre to s17.
- Left as the lead asked: `kind() = Unavailable` through `RevocationSource` (nacre-core, s39); the ADR-0004 `Owns` note.
Tests: 21 new in the story (19 + 2), within `Test budget` 25.
