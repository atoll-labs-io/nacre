# Review — s07-tsp-client

[Story](../stories.md) · [Plan](../plans/s07-tsp-client.md) · [Verification](../verif/s07-tsp-client.md)

Diff reviewed: `git diff main...story/s07-tsp-client`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: f85bfe72a670c11f2ca5a9d2b5b4ddeafde73f58

## When blocked
- Failure cause: n/a
- Missing: n/a
- Required adaptation: n/a
- Next action: n/a

## Ownership
Diff listed with `git diff --name-only main...story/s07-tsp-client`, each path held against the story's `Owns` by the overlap rule of the `review-antihallu` skill.
- [x] Every path inside `Owns`: 31 paths under `crates/nacre-tsp/`, plus `docs/security/attacks/tsp.md`. The rest is the story's own pipeline evidence (`docs/research/`, `docs/plans/`, `docs/verif/`, `docs/qa/s07-tsp-client/`), which is in scope by construction.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none.
- [x] The story has an `Owns` line: `crates/nacre-tsp/`, `docs/security/attacks/tsp.md`.

## Evidence reused
- [x] `po-gate verif-current s07-tsp-client` → exit 0, so the record is reused (`Verification mode: record`). Outside `docs/`, every `## Runs` tree matches HEAD's code, and I checked each one with `git diff --quiet <tree> HEAD -- . ':(exclude)docs'`. The record covers the unit suite, clippy, conformance (bench TSA alone) and no-network-deps, all at exit 0. Its "Not proven here" section says formatting was checked by hand, fuzzing ran outside `po-run`, and the conformance row ran against the bench TSA only, not DSS.
- [x] `po-gate qa-current s07-tsp-client` → exit 0. The story goes to QA (`Surface: endpoint`, `QA stage: surfaces`). Its one verified finding (Finding 1, the error kind) is carried below. Its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1–8 are all present. Deviations, all small:
  - `UnsupportedAlgorithm` carries a `DigestAlgorithm`, where the plan said `ObjectIdentifier`.
  - There is an extra `src/asn1.rs` helper module.
  - There is an unplanned `sha1` dev-dependency.
  - The no-network-deps command is rewritten, and the record explains why.
- [x] Run interdicts, one by one:
  - Root `Cargo.toml`, `nacre-core`, `nacre-cms`, `nacre-conformance`, `conformance/` and `.github/` have an empty diff.
  - `cargo tree -i x509-tsp` finds no such package. No `[workspace.dependencies]`.
  - No public TSA URL appears in any `.rs` file. The only URLs are `127.0.0.1` and a doc comment.
  - `grep "PRIVATE KEY"` finds nothing.
  - `src/` reads no `SystemTime`, `Instant` or `chrono`.
  - Lints are covered by the clippy row of the record.
  - `nacre-cms` is untouched.

## References
- [x] I opened and confirmed every call the diff makes into other code:
  - in `nacre-cms`: `SignedData::from_der`, `econtent`, `verify(None)` and `VerifiedSigner::{certificate, signer_info}`, plus the ESS v2 check, which runs only when the attribute is present (`crates/nacre-cms/src/verify.rs`, `check_signing_certificate`);
  - in `nacre-core`: `TimestampAuthority` and `Error::Timestamp`, which maps to `Unavailable`;
  - in `ureq` 3.5.0: the `rustls` feature carries webpki roots and the ring provider; redirects default to 10.
- [x] I traced each value to its source:
  - Nonce of 8 bytes: plan, as OpenSSL does.
  - Timeout of 30 s and body limit of 1 MiB: plan task 6.
  - Status 0/1 as granted: RFC 3161 PKIStatus.
  - `failInfo` bit numbering: DER named bits.
  - Fraction of at most 9 digits: a plan choice. RFC 3161 sets no limit.
  - The request DER equals OpenSSL's `request.tsq` byte for byte (test `request_matches_openssl`).
  - Re-running `forge_attacks` into a scratch directory reproduced all six attack files byte for byte.

## Rules
- [x] `AGENTS.md` conventions are respected:
  - `#![forbid(unsafe_code)]`;
  - "experimental" in the crate docs;
  - one `thiserror` enum, and no message prints the token, imprint or nonce;
  - no clock read;
  - network code only behind `http`;
  - a fuzz target under `crates/nacre-tsp/fuzz/` (CI picks it up through the `crates/*/fuzz` glob);
  - corpus `README.md` with its sources;
  - `docs/security/attacks/tsp.md` in French, one corpus case and one test per attack.
- [x] No accepted ADR is contradicted (ADR-0004: no `x509-tsp`/`cms`; ADR-0006: `ureq` behind `http`; ADR-0008: fuzzing).

## Tests
- [x] Floor: `po-gate floor-guard s07-tsp-client main` → exit 0, nothing lowered. awk printed a multibyte-locale warning on the binary corpus files; the exit code was 0.
- [x] Assertions pin down the criteria. None of the six empty test shapes: each forged file differs from `valid.tsr` by one defect, and the fixtures and the HTTP test server reproduce no condition under test.
- [x] Within `Test budget`: 20 tests against 25 (the plan says 21; its own list adds up to 20).
- [x] Bite. I ran only `tests/attacks.rs` and `tests/recorded.rs` (plus `tests/hostile.rs` where marked), and after each mutation `git diff --exit-code` came back clean.
  - `response.rs`: `None => Err(NonceMissing)` changed to `Ok` → **1 failing** (`replay_without_nonce_is_rejected`) → undone.
  - `token.rs:131`: the EKU mismatch changed to `Ok(())` → **1 failing** (`certificate_without_timestamping_is_rejected`) → undone.
  - `token.rs:97`: the `signingCertificateV2` presence check disabled → **1 failing** (`ess_v1_only_is_indeterminate`) → undone.
  - `token.rs:130`: the criticality requirement dropped (`Some((_, usage))`) → **0 failing** (hostile included) → undone.
  - `token.rs:130`: "timeStamping alone" relaxed to `contains` → **0 failing** → undone.
  - `token.rs:82`: the `id-ct-TSTInfo` content-type check disabled → **0 failing** (hostile included) → undone.
  - `token.rs:107`: the imprint hash-algorithm OID comparison removed → **0 failing** → undone.
  - `token.rs:107`: `!parameters_null` removed → **0 failing** → undone.
- [x] No existing test is made useless: the crate is new.

## Neighbours
- [x] No code outside `crates/nacre-tsp/` uses the crate yet. It has no other callers, and the diff changes no existing code.

## Lenses
Lenses run:
- security: `src/http.rs` makes an outbound HTTP call, and `src/token.rs` verifies signatures;
- dependencies: new manifest `crates/nacre-tsp/Cargo.toml` with a dependency list.

The performance lens did not run: there is no server-side code. The security lens found nothing exploitable. The URL is caller configuration, not untrusted input. TLS uses webpki roots. Trust in the token rests on the signature, the ESS v2 binding and the EKU, not on the transport, so a redirect or proxy cannot forge a token. The dependencies lens gives Finding 3.
- [x] Each lens finding is graded and listed below.

## Findings
- major — crates/nacre-tsp/src/token.rs:82,107,130 — Four verification rules the plan lists can be switched off without any test failing. Each was disabled in turn; every test still passed.
  - The `id-ct-TSTInfo` content-type check (line 82). The plan's "The pivot" names it as one of the three rules nacre-tsp adds.
  - The EKU must be critical (line 130).
  - The EKU must hold `id-kp-timeStamping` alone (line 130). RFC 3161 §2.3 requires both of these, and so do the plan and `docs/security/attacks/tsp.md`.
  - The imprint hash-algorithm OID must match (line 107). The plan says "imprint OID and hash equal".

  Today the code is correct, so nothing is broken for users. But the plan's test strategy says "a guard removed turns exactly its test red", and that is false for these four guards. The forged corpus has no certificate with a non-critical EKU or with an extra purpose, no `SignedData` with another content type, and no `TSTInfo` with another hash OID. Fix: add three to four forged cases through `examples/forge_attacks.rs`, each rejected by its own test (the budget leaves room for 5 more).
- minor — crates/nacre-tsp/src/token.rs:103-107 — The rule that the `hashAlgorithm` parameters are absent or NULL is untested (removing `!parameters_null` turns nothing red). It is low-stakes, but it is a guard with no test.
- minor — crates/nacre-tsp/src/http.rs:54 — QA Finding 1 (verified), carried over. Through `TimestampAuthority`, every failure comes back as `nacre_core::Error::Timestamp`, whose kind is `Unavailable`. That includes a forged or replayed token (`ImprintMismatch`/`NonceMismatch`, which `verify_response` itself classes as `InvalidSignature`) and a wrong-length imprint, which is rejected locally before any request is sent.
  - A caller acting on `kind()` would retry a forged token as if the TSA were down. The token is still never accepted, so no silent damage.
  - The wrong-length imprint could map to the contract's own `nacre_core::Error::DigestLength` (`crates/nacre-core/src/error.rs:10`, kind `InvalidInput`) inside this story's `Owns`.
  - Mapping a verification failure to anything but `Unavailable` needs a change to the `nacre-core` contract (outside `Owns`), so it is for a person to decide.
- minor — crates/nacre-tsp/Cargo.toml:32 — Dependencies lens: the dev-dependency `sha1 = "0.11"` (used to forge `ess-v1-only.tsr`) is not named in plan task 1. The comment in the manifest gives the reason, and `sha1` 0.11 was already in the lockfile through another crate. Dev-only.
- minor — crates/nacre-tsp/src/error.rs:44 — `UnsupportedAlgorithm(DigestAlgorithm)` differs from the plan's `UnsupportedAlgorithm(ObjectIdentifier)`. The choice is reasonable, since the variant is only reachable from a `DigestAlgorithm`, but the plan does not record the change.

## Not verified
- **The production build.** Not run: `Build stage: ship-if-route`, and the diff adds a crate manifest, so it runs at ship.
- **End-to-end tests.** The project has none (`E2E: —`).
- **Formatting.** The record says `cargo fmt --all --check` was run by hand, outside `po-run`. I relied on that and did not re-run it.
- **Conformance against the s02 bench.** I did not start the bench (driver note). The bench run is the implementer's `conformance` row, exit 0. CI `conformance.yml` runs it again, and that CI run should be checked before ship.
- **QA `## Not seen`: criterion 3 against the s02 bench itself.** QA did not start the bench either: the s06 lane held its ports. QA ran s02's TSA script on its own PKI and port instead, so it rests on the same implementer row and the CI run.
- **QA `## Not seen`: live public TSAs.** FreeTSA and DigiCert were never called, by rule. Only their recorded answers were tested (DigiCert verifies; FreeTSA stays `Indeterminate`).
- **QA `## Not seen`: real network conditions.** Behaviour on a real network was not shown: the 30 s timeout against a slow TSA, TLS to an `https://` TSA, and redirect handling (ureq follows up to 10 by default). A person should run `HttpTsa` once against a test `https://` TSA they control.
- **QA `## Not seen`: "only the imprint leaves" against a third-party server.** QA showed this only partly, with a local server. The request bytes equal OpenSSL's, which supports it.
- **Fuzzing.** I did not re-run it. The record (30 s, 1.17 M runs) and QA (20 s) report no crash, and CI fuzzes the target for 60 s.
- **SHA-384/512 and P-384 tokens.** They stay `Indeterminate` by the plan's design. The plan says an issue on `nacre-cms` is filed by the lead; I did not check that it exists.

Max severity: major
Ship allowed: yes

# Review — s07-tsp-client

Review status: blocked
Fix loop: 1
Reviewed tree: 66213787fb0f8c8fc2b24273d15b2ff321f1df46

## When blocked
- Failure cause: `po-gate qa-current s07-tsp-client` exited 1 with "po-gate: the code of s07-tsp-client changed after its QA walk; the report no longer matches HEAD — /po-qa s07-tsp-client". The QA report's `Tree:` is `5a29c5e0381dca577296840b5d442e241db14b76`; fix commit fab0657 changed code outside `docs/`, including `crates/nacre-tsp/src/http.rs` (`DigestLength` now mapped to `nacre_core::Error::DigestLength`).
- Missing: a QA report whose `Tree:` matches the code at `story/s07-tsp-client`.
- Required adaptation: walk QA again on the code after the fix run, so the `HttpTsa` error mapping and QA Finding 1 are checked against the current code.
- Next action: `/po-qa s07-tsp-client`, then `/po-review s07-tsp-client`.

## Partial work done before the block
- Each of the five new guards bites (content type, EKU criticality, timeStamping alone, imprint OID, parameters NULL): disabled in turn, exactly one test fails; the `http.rs` `DigestLength` arm too. Undone each time, `git diff --exit-code` clean.
- `nacre_core::Error::DigestLength` exists with kind `InvalidInput`. 25 tests, exactly `Test budget`.

## Findings
- minor — docs/plans/s07-tsp-client.md — The test strategy still says "21 tests"; the fix run brought the count to 25, the full budget, without a line in the plan.
- minor — crates/nacre-tsp/src/http.rs:54 — Carried: a forged or replayed token still reports kind `Unavailable` through `TimestampAuthority`; now the subject of contract story s39 (ADR-0016), not to be fixed in s07.
- minor — crates/nacre-tsp/Cargo.toml:32 — Carried: the dev-dependency `sha1` is not named in plan task 1.
- minor — crates/nacre-tsp/src/error.rs:44 — Carried: `UnsupportedAlgorithm(DigestAlgorithm)` differs from the plan's `ObjectIdentifier`, unrecorded in the plan.

## Not verified
- The whole QA surface on the current code (the block); the remaining review steps on the fix-run diff; production build (at ship); E2E (none); formatting (record's statement); conformance against the s02 bench (implementer row, CI); QA's Not seen items; fuzzing after the fix.

Max severity: minor
Ship allowed: no

---

# Review — s07-tsp-client

[Story](../stories.md) · [Plan](../plans/s07-tsp-client.md) · [Verification](../verif/s07-tsp-client.md)

Diff reviewed: `git diff main...story/s07-tsp-client`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: 58c882ba2ce6197ca19fb030bbf0197b0906d0b4

## When blocked
- Failure cause: n/a
- Missing: n/a
- Required adaptation: n/a
- Next action: n/a

## Ownership
I listed the diff with `git diff --name-only main...story/s07-tsp-client` and checked each path against `Owns`: `crates/nacre-tsp/`, `docs/security/attacks/tsp.md`.
- [x] Every path is inside `Owns`. The paths are under `crates/nacre-tsp/`, plus `docs/security/attacks/tsp.md`, plus the story's own pipeline evidence (`docs/research/`, `docs/plans/`, `docs/verif/`, `docs/qa/s07-tsp-client/`, `docs/reviews/s07-tsp-client.md`).
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. The other lanes own other paths: s09 owns `crates/nacre-revocation/` and `docs/security/attacks/revocation.md`, s13 owns `crates/nacre-pkcs11/`, s15 owns `crates/nacre-validate/` and `docs/security/attacks/pades.md`.
- [x] The story has an `Owns` line.
- The worktree holds one uncommitted change, in `docs/reviews/s07-tsp-client.md`: the blocked fix-loop-1 review appended there. Law 4 allows it during a fix run.

## Evidence reused
- [x] `po-gate verif-current s07-tsp-client` → exit 0. The record is reused (`Verification mode: record`). It covers the unit suite, clippy, conformance (bench TSA only) and no-network-deps, all exit 0, on the post-fix code. Its "Not proven here" section adds three things:
  - formatting was checked by hand;
  - the fuzz target was not re-run after the fix (`src/token.rs` is unchanged);
  - the fix run's bite checks were done by hand.
- [x] `po-gate qa-current s07-tsp-client` → exit 0. This is the second QA walk, on tree `66213787…`, which is the code after `fab0657`. This lifts the block of the previous attempt. Both of its verified findings are carried below. Its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1–8 are present, plus the fix run's five forged cases and tests, and the `DigestLength` mapping in `src/http.rs`.
- Deviations from the plan, all minor (see Findings):
  - Task 6 said "every error as `Timestamp`"; the fix run changed that.
  - The test count says 21; there are 25.
  - `sha1` is a dev-dependency the plan does not name.
  - `UnsupportedAlgorithm(DigestAlgorithm)` was planned as `ObjectIdentifier`.
- [x] Run interdicts, one by one:
  - `nacre-core`, `nacre-cms`, root `Cargo.toml`, `.github` and `conformance` have an empty diff.
  - No public TSA URL appears in code.
  - `src/` reads no clock.

## References
- [x] Opened and confirmed, beyond the previous loop's checks:
  - `nacre_core::Error::DigestLength { expected, actual }` exists, with kind `InvalidInput` (`crates/nacre-core/src/error.rs:10,27`).
  - `DigestAlgorithm` has three variants: Sha256, Sha384 and Sha512 (`crates/nacre-core/src/algorithm.rs:23`).
  - `nacre_cms::oid::DATA` is used by the forge.
  - `asn1::nested` requires the input to be fully consumed (`reader.finish()`), so `TSTInfo` and `TimeStampResp` reject trailing bytes.
  - Contract story `s39-error-kind-from-sources` exists on `main` (`docs/stories.md:664`).
- [x] Values: the five new forged cases each differ from `valid.tsr` by one defect:
  - `contentType` changed together with `eContentType`;
  - an EKU that is not critical;
  - an EKU with an extra `codeSigning` purpose;
  - a SHA3-256 OID on a 32-byte imprint;
  - INTEGER parameters on the hash algorithm.

## Rules
- [x] The `AGENTS.md` conventions hold: `forbid(unsafe_code)`, "experimental", one `thiserror` enum with `kind()`, network code only behind `http`, a fuzz target, the corpus README, and one attack file row per case (11 rows).
- [x] No accepted ADR is contradicted (ADR-0004, ADR-0006, ADR-0008, ADR-0012).

## Tests
- [x] Floor: `po-gate floor-guard s07-tsp-client main` → exit 0. awk printed a locale warning on the binary corpus files; the exit code was 0.
- [x] None of the six kinds of test that prove nothing. Each forged fixture can only be caught by the rule it targets, because the checks run in a fixed order and the content-type case keeps its `contentType` attribute consistent. The HTTP test's short-imprint assertion would read `Unavailable` if a request had gone out.
- [x] 25 tests, exactly `Test budget`.
- [x] Bite: I ran only the test files concerned, and after each change `git diff --exit-code <file>` came back clean.
  - `token.rs:130`: EKU criticality dropped (`Some((_, usage))`) → **1 failing** (`non_critical_timestamping_purpose_is_rejected`) → undone.
  - `response.rs`: `NonceMismatch` arm disabled → **1 failing** (`other_nonce_is_rejected`) → undone.
  - `http.rs:56`: `DigestLength` mapping disabled → **1 failing** (`http_tsa_sends_only_the_request_and_reports_failure`, line 88) → undone.

## Neighbours
- [x] No code outside `crates/nacre-tsp/` uses the crate yet, and the diff changes no existing code.

## Lenses
Lenses run:
- security: `src/http.rs` makes an outbound HTTP call, and `src/token.rs` verifies signatures;
- dependencies: new manifest `crates/nacre-tsp/Cargo.toml`.

The performance lens did not run: there is no server-side code. The security lens found nothing exploitable:
- The URL is caller configuration.
- Trust rests on the signature, the ESS v2 binding and the EKU, which all bite, not on the transport.
- The body is capped at 1 MiB, with a 30 s timeout.

The dependencies lens gives the `sha1` finding below.
- [x] Each lens finding is graded and listed below.

## Findings
- minor — crates/nacre-tsp/src/http.rs:54 — QA Finding 1 (verified), carried over. Through `TimestampAuthority`, a forged or replayed token (`ImprintMismatch`/`NonceMismatch`) still reports kind `Unavailable`. A caller acting on `kind()` would retry it as if the TSA were down. The token is never accepted. The fix belongs to contract story s39 (ADR-0016), outside this story's `Owns`.
- minor — crates/nacre-tsp/src/http.rs:56 — QA Finding 2 (verified). A wrong-length imprint now returns `nacre_core::Error::DigestLength`, whose message reads "the signature algorithm expects 32". There is no signature algorithm in a time-stamp request, so the message points the caller at the wrong input. The kind and the numbers are right. The text lives in `nacre-core` (outside `Owns`), so a person decides whether s39 or another contract change words it neutrally.
- minor — docs/plans/s07-tsp-client.md — The plan is out of date on two points:
  - The test strategy still says "21 tests", but the fix run brought the count to 25, the full budget, and the plan has no line about it.
  - Task 6 still says every error becomes `Timestamp`, which the fix run changed.
- minor — crates/nacre-tsp/Cargo.toml:32 — Dependencies lens, carried over: the dev-dependency `sha1 = "0.11"` is not named in plan task 1. The manifest comment gives the reason, and it is dev-only.
- minor — crates/nacre-tsp/src/error.rs:44 — Carried over: `UnsupportedAlgorithm(DigestAlgorithm)` differs from the plan's `ObjectIdentifier`, and the plan does not record the change.

## Not verified
- **Production build.** Not run: `Build stage: ship-if-route`, and the diff adds a crate manifest, so it runs at ship.
- **End-to-end tests.** The project has none (`E2E: —`).
- **Formatting.** The record says `cargo fmt --all --check` was run by hand. I relied on that and did not re-run it.
- **Conformance against the s02 bench.** I did not start the bench. This rests on the implementer's `conformance` row (exit 0). CI `conformance.yml` runs it again, and that CI run should be checked before ship.
- **QA `## Not seen`: criterion 3 against the s02 bench itself.** QA ran s02's TSA script on its own PKI and port, because the bench is a service QA did not start.
- **QA `## Not seen`: live public TSAs (FreeTSA, DigiCert).** Never called, by the story's rule. Only their recorded answers were tested.
- **QA `## Not seen`: real network conditions.** Timeout against a slow TSA, TLS to an `https://` TSA, and redirects: the scenarios driver cannot show them. A person should run `HttpTsa` once against an `https://` TSA they control.
- **QA `## Not seen`: "only the imprint leaves" against a third-party server.** Shown only partly, with a local server. The request bytes equal OpenSSL's.
- **Fuzzing after the fix.** Not re-run, by me or by the record. `src/token.rs` is unchanged by the fix. CI fuzzes the target for 60 s.
- **The `nacre-cms` issue for SHA-384/512 and P-384 tokens.** I did not check that it was filed.
- **Bite on the other guards.** I did not repeat it on the content-type, extra-purpose, imprint-OID and parameters-NULL guards. The previous blocked attempt and the record report each of them biting.
- **A po-bounds refusal.** It blocked one of my commands, a `git -C` on the main repository root. I read `main:docs/stories.md` through the worktree's git instead, which po-bounds allows. Nothing the review needed was lost.

Max severity: minor
Ship allowed: yes
