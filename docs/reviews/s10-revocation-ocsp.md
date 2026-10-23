# Review — s10-revocation-ocsp

[Story](../stories.md) · [Plan](../plans/s10-revocation-ocsp.md) · [Verification](../verif/s10-revocation-ocsp.md)

Diff reviewed: `git diff main...story/s10-revocation-ocsp`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: a7fe5f4f72c411ec2b1456304b467e06c245a89a

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s10-revocation-ocsp` and checked each path against `Owns: crates/nacre-revocation/, docs/security/attacks/revocation.md`.
- [x] Every path inside `Owns`, except the one below. `docs/plans|research|verif|qa/s10-revocation-ocsp*` are the story's own evidence. `docs/decisions/0018-ocsp-structures-on-der-08.md` is a new ADR (status A) that the plan names, so it is in scope.
- [x] Outside `Owns`: `docs/decisions/0004-rustcrypto-foundations-and-x509-boundary.md` was modified, and a change to an existing ADR is never covered by the ADR rule. The edit is frontmatter only (`superseded-by: [0018]`), which AGENTS.md Law 6 calls for: "a new ADR supersedes it, and only its frontmatter links, `supersedes` and `superseded-by`, ever change". That makes it a gap in the story's `Owns`, graded minor.
- [x] Inside another running story's `Owns`: none. The only other worktree is s15-validate-revisions, which owns `crates/nacre-validate/`, `crates/nacre-pdf/` and `docs/security/attacks/pades.md`. No overlap.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s10-revocation-ocsp` exits 0, so I reused the record under `Verification mode: record`. Its Tree is f159586f…, and both declared checks have a last run with exit 0: `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`. I did not rerun them. The record's "Not proven here" says the bench tests are `#[ignore = "conformance"]` and were run locally outside the record, and that the fuzz target was only built.
- [x] `po-gate qa-current s10-revocation-ocsp` exits 0. The QA report has 3 verified findings, all minor, and they are carried into Findings below. The report has no probable or unverified findings. Its `## Not seen` items are copied under Not verified.

## Plan
- [x] All 10 tasks are present, and nothing in the diff falls outside the plan's Files touched list:
  - The `verify_signed` split and the `signed_tbs` and `critical` helpers are there.
  - The 9 error variants and their kinds are there, with the kind table at 21 and 23 rows.
  - The ASN.1 types, request, response, OpenSSL corpus, attack corpus and example are there.
  - The second hostile loop, the fuzz target, `HttpOcspSource`, `Fallback`, the bench test, the attacks doc section and the ADR-0004 frontmatter change are there.
- [x] Run interdicts, each checked:
  - Root `Cargo.toml`, `crates/nacre-core`, `tests/attacks.rs`, `read.rs`, `status.rs` and `tests/corpus/openssl/` and `attacks/` all show an empty diff (`git diff --quiet` exits 0).
  - No other crate is touched.
  - There is no `x509-ocsp`, `cms`, `x509-tsp` or `[workspace.dependencies]`.
  - `SystemTime::now` and `Instant::now` do not appear in `crates/nacre-revocation/`.
  - No URL appears in error messages; `ocsp_loopback_responder_is_refused_by_default` asserts this on Display and Debug.
  - Outside tests and examples, there is no `unwrap`, `expect`, `panic` or indexing (clippy deny is green in the record).
  - There is no private key in the corpus; the README script ends with `rm -rf $T`, and the example keys are fixed fictitious secrets.
  - Tests use only 127.0.0.1 servers, plus the ignored bench test.

## References
- [x] Opened and confirmed:
  - `RevocationData::Ocsp` (`crates/nacre-core/src/revocation.rs:10`, "A DER `OCSPResponse`").
  - `with_policy`, `http_error` and `AddressPolicy` are reused unchanged.
  - The `getrandom::fill` pattern from `nacre-tsp`.
  - `sha1` 0.11 is already used in `crates/nacre-tsp/Cargo.toml:32`.
  - x509-cert's `AuthorityInfoAccessSyntax` and `ExtendedKeyUsage`.
  - The example includes `src/ocsp/asn1.rs` through `#[path]`.
- [x] Values held against RFC 6960, 8954, 5019 and 5280:
  - OIDs: `id-pkix-ocsp-basic` 48.1.1, nonce 48.1.2, `id-pkix-ocsp-crl` 48.1.3, `id-ad-ocsp` 48.1, `id-kp-OCSPSigning` 3.9, SHA-1 1.3.14.3.2.26, SHA-256 2.16.840.1.101.3.4.2.1.
  - `OCSPResponseStatus` values, with 4 unused.
  - Tagging: ResponderID [1]/[2] EXPLICIT; CertStatus [0]/[2] IMPLICIT NULL and [1] IMPLICIT constructed; nextUpdate [0] and singleExtensions [1] EXPLICIT; responseExtensions [1] EXPLICIT.
  - KeyHash is SHA-1 over the subjectPublicKey bit-string value.
  - Nonce extnValue is an OCTET STRING inside an OCTET STRING.
  - POST with `application/ocsp-request`, a 32-octet nonce, and a 64 KiB body limit as planned.
  - The SHA-1 CertID is proven equal to OpenSSL's by `request_cert_id_matches_openssl`.

## Rules
- [x] AGENTS.md conventions are respected: `forbid(unsafe_code)` is kept, the control date is a parameter, there is one thiserror enum with `kind()`, and the fuzz target and attacks doc are present. The crate doc still says "Experimental".
- [x] No accepted ADR is contradicted. ADR-0018 is accepted (option 1), supersedes 0004, and its counterpart link is set.

## Tests
- [x] Floor: `po-gate floor-guard s10-revocation-ocsp main` exits 0, so nothing was lowered.
- [x] The assertions pin down the acceptance criteria:
  - Every attack fixture says `revoked` apart from its one defect, so a skipped rule cannot pass silently.
  - The HTTP nonce test would succeed if `check_nonce` were removed, so it does guard the check.
  - I found none of the six empty test shapes.
- [x] There are 19 new tests against a budget of 25.
- [x] Bite 1: in `delegate`, ignoring the issuer-signature check on the delegate certificate (`.ok()?` → `.ok();`) makes 1 test fail (`delegate_issued_by_another_key_is_unauthorized`). Undone; `git diff --exit-code` is clean.
- [x] Bite 2: in `delegate`, removing the `id-kp-OCSPSigning` EKU check makes 1 test fail (`delegate_without_ocsp_signing_is_unauthorized`). Undone; clean.
- [x] Bite 3: in `delegate`, disabling the "valid at `producedAt`" check makes **0** tests fail across `ocsp_attacks`, `ocsp_status` and `hostile`. Undone; clean. This rule is untested; see Findings.
- [x] No test was made useless by the story. `hostile.rs` was refactored into a shared loop and the CRL case is kept.

## Neighbours
- [x] No crate outside `nacre-revocation` uses it, so there are no outside callers to read. `Crl::from_der` and `verify` now call the extracted helpers, and the CRL tests (`attacks.rs`, `read.rs`, `status.rs`, `hostile.rs`) pass unchanged in the record.

## Lenses
Lenses run:
- **security**: `src/http.rs` makes an HTTP POST to a URL taken from the certificate's `authorityInfoAccess`, which is untrusted input. It uses the same public-only address policy, no redirect and no proxy as the CRL source; there is a 64 KiB limit; the error messages carry no URL. I found nothing here.
- **dependencies**: `crates/nacre-revocation/Cargo.toml` adds `sha1` 0.11 and `getrandom` 0.4 and turns on `der` `derive`. All three are named and justified in the plan and research, and all are already used by `nacre-tsp`. `getrandom`'s `build.rs` was already in the workspace's build. I found nothing here.

Not run, because the diff has no trigger: migration and performance (no server-side code).
- [x] Each lens finding is graded and listed below (there are none).

## Findings
- major — crates/nacre-revocation/src/ocsp/response.rs:274-279 — The delegate's "valid at `producedAt`" check is not covered by any test.
  Disabling it fails 0 tests, yet rule 4 of `docs/security/attacks/revocation.md` lists it as an authorization rule. The project convention is "one corpus case and one rejecting test per attack", and the OCSP table has no row for an expired or not-yet-valid delegate.
  Today the behaviour is correct: QA saw such a delegate rejected with `UnauthorizedResponder`. But a regression would let a lapsed delegate key sign "good" answers.
  Fix: add an `expired-delegate` case to `forge_ocsp_attacks`, plus its test and its table row.
- minor — crates/nacre-revocation/src/error.rs:23-49 — For an OCSP response, `SignatureInvalid` reads "the CRL signature is invalid" and `Expired` reads "the CRL expired at its nextUpdate". The rustdoc of `AlgorithmMismatch`, `SignatureInvalid` and `Expired` also mentions only CRLs. This is QA finding 1, verified.
- minor — crates/nacre-revocation/src/ocsp/request.rs:28-35 — `OcspRequest::new` accepts a nonce of any length, including an empty one (sent as `04 00`) and one of 4,096 octets. RFC 8954 §2.1 bounds a nonce to 1–32 octets. `with_random_nonce`, the path `HttpOcspSource` uses, is not affected. This is QA finding 2, verified.
- minor — crates/nacre-revocation/src/http.rs (`HttpOcspSource::revocation`) — A caller using the `RevocationSource` trait sees `kind() = Unavailable` for every OCSP refusal, including `NonceMismatch`, which this story maps to `InvalidSignature`. The cause is the mapping `Revocation(_) => Unavailable` at `crates/nacre-core/src/error.rs:28`, which is outside this story's `Owns`. It extends s09's QA finding 1. This is QA finding 3, verified.
- minor — docs/decisions/0004-rustcrypto-foundations-and-x509-boundary.md:8 — The file sits outside the story's `Owns`. The frontmatter-only `superseded-by: [0018]` edit is what AGENTS.md Law 6 requires when a new ADR supersedes an old one, so this is a gap in `Owns`, not an implementer breach. Leave the code as it is.
- minor — docs/security/attacks/revocation.md (rule 4, "Hors de ce fichier") — The revocation status of a delegated responder's own certificate is never checked, and there is no `id-pkix-ocsp-nocheck` handling (RFC 6960 §4.2.2.2.1). The attacks file does not say this is left to the caller or to s17. Add a line naming who owns it.

## Not verified
- I did not run `cargo fuzz build ocsp` or a fuzz session myself. I relied on QA's `cargo +nightly fuzz list` and its 60 s run (884,498 runs, no crash, `c4-fuzz-target.txt`). The CI fuzz job will cover this.
- I did not run the conformance bench test `ocsp_says_revoked_and_good_on_the_bench`; it is ignored in the record. The implementer ran it locally outside the record, and QA ran it against a copy of the s02 PKI. A person should check that the CI `conformance` job is green on the PR.
- From QA `## Not seen`:
  - The bench's own `pki` container (busybox httpd). The walk ran the same CGI script with its own server instead. CI conformance covers it.
  - A public OCSP responder, and pre-signed public responses. The driver only reaches servers it started. A person should try a real CA's responder before relying on it in production.
  - An RSA-signed OCSP response. Both corpora are P-256. The RSA path is shared with CRLs and was seen in s09's QA.
  - The 30 s timeout of `HttpOcspSource`. No scenario served a slow answer.
  - DNS rebinding to a non-public address other than `localhost`. This needs a resolver the driver does not start.
  - `Error::Random`. A `getrandom` failure cannot be caused from outside the process.
  - The CI fuzz job on GitHub Actions. It is a remote service; a local 60 s run was done instead.
- I checked the SHA-256 `CertID` arm only by reading it; the plan cuts its test on purpose. QA exercised a SHA-256 `CertID` request against OpenSSL.

Max severity: major
Ship allowed: yes

---

# Review — s10-revocation-ocsp

[Story](../stories.md) · [Plan](../plans/s10-revocation-ocsp.md) · [Verification](../verif/s10-revocation-ocsp.md)

I reviewed `git diff main...story/s10-revocation-ocsp` in a context that did not write it. Findings are graded critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: f20644f7242fb009a7ce478bee30c8a913e10d6f

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-status main...story/s10-revocation-ocsp` and checked each path against `Owns: crates/nacre-revocation/, docs/security/attacks/revocation.md`.
- [x] Every path is inside `Owns`, except the one ADR file below.
  - `docs/plans|research|verif|qa|reviews/s10-revocation-ocsp*` are the story's own evidence.
  - `docs/decisions/0018-ocsp-structures-on-der-08.md` is a new ADR (status A) that the plan names, so it is in scope.
- [x] Outside `Owns`: `docs/decisions/0004-rustcrypto-foundations-and-x509-boundary.md` is modified. The change is frontmatter only (`superseded-by: [0018]`), and AGENTS.md Law 6 requires it. It is a gap in `Owns`, graded minor.
- [x] Inside another running story's `Owns`: none. The only other worktree is s15-validate-revisions (`crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/pades.md`), and nothing overlaps.
  - `main` has moved by two commits (`ffab3bc`, `dcad61f`), but neither touches `crates/nacre-revocation/`, the attacks file or `docs/decisions/`.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s10-revocation-ocsp` exits 0. Under `Verification mode: record` I reused the last runs of `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`, both with exit 0 on the fix-run code. I did not rerun them.
  - The record's "Not proven here" says the bench tests are `#[ignore = "conformance"]` and were run locally outside the record before the fix, and not again after it.
  - The fuzz target was built only.
- [x] `po-gate qa-current s10-revocation-ocsp` exits 0. This is the second QA walk, on the fix-run code.
  - It has one verified finding, minor, carried below.
  - It confirms that the first walk's findings 1 (CRL-only wording) and 2 (nonce length) are fixed.
  - Its `## Not seen` items are copied under Not verified.
- The project has no `E2E` command (`—`). The production build is left to ship, because the diff changes no routing and no manifest beyond the crate's own `Cargo.toml` dependencies.

## Plan
- [x] All 10 tasks are present, as the fix-loop-0 review established. All four fix-run items are present in commit `2405335`:
  - The `expired-delegate` case: corpus files, the example, the test `delegate_expired_at_produced_at_is_unauthorized` and its row in the attacks table.
  - The `SignatureInvalid`, `Expired`, `AlgorithmMismatch`, `Der` and `IssuerCertificate` wording now names a CRL or OCSP response, or neither.
  - `Error::NonceLength(usize)` is added with kind `InvalidInput`, the kind table goes to 22/24 rows, and the test `nonce_outside_one_to_32_octets_is_refused` is added.
  - The attacks file says that the delegate's own revocation and `id-pkix-ocsp-nocheck` are left to the caller and to s17.
- [x] The two items the lead set aside stay as the plan records them: the `Unavailable` kind (nacre-core, s39) and the ADR-0004 `Owns` note.
- [x] Run interdicts hold:
  - The root `Cargo.toml`, the other crates and the CRL tests and corpora are untouched.
  - There is no `x509-ocsp`, `cms`, `x509-tsp` or `[workspace.dependencies]`.
  - There is no `SystemTime::now` or `Instant::now`.
  - No URL appears in an error message.
  - There is no private key in the corpus.

## References
- [x] I opened `verify_signed`, `signed_tbs`, `critical` (`src/crl.rs:154-176`), `cert_id`, `key_hash`, `with_policy` and the ASN.1 declarations in `src/ocsp/asn1.rs`. Names and signatures match their uses in `response.rs`, `request.rs`, `http.rs` and the fuzz target.
- [x] Values:
  - The nonce bound 1..=32 matches RFC 8954 §2.1.
  - The OIDs and tagging were confirmed against RFC 6960 in fix loop 0 and are unchanged.
  - The delegate's validity is checked against `producedAt`, as the plan says.
  - The fixture's delegate validity (2025-01-01 to 2026-01-01) is before its `producedAt`.

## Rules
- [x] AGENTS.md conventions hold: `forbid(unsafe_code)` is kept, the control date is a parameter, there is one `thiserror` enum and every variant has a `kind()`, the crate doc still says "Experimental", and the fuzz target and the attacks file are present.
- [x] ADR-0018 is accepted with `supersedes: [0004]`, and the counterpart link is set.

## Tests
- [x] Floor: `po-gate floor-guard s10-revocation-ocsp main` exits 0, so nothing was lowered.
- [x] The story adds 21 tests against a budget of 25. I found none of the six empty shapes. Every attack fixture says `revoked` apart from its one defect.
- [x] Bite 1: in `delegate` (`src/ocsp/response.rs:275-276`), I disabled the whole validity condition. 1 test failed (`delegate_expired_at_produced_at_is_unauthorized`). Undone; `git diff --exit-code` is clean.
  - Before that, a mis-parenthesised mutation (`false && a || b`) disabled only the `not_before` half, and **0** tests failed. The "not yet valid at `producedAt`" side is untested; see Findings.
- [x] Bite 2: in `OcspRequest::new` (`src/ocsp/request.rs:29`), I disabled the nonce-length guard. 1 test failed (`nonce_outside_one_to_32_octets_is_refused`). Undone; clean.
- [x] Bite 3: in `status` (`src/ocsp/response.rs:173`), I disabled the `nextUpdate < at` check. 1 test failed (`stale_response_is_rejected`). Undone; clean.
- [x] Fix loop 0 already bit the delegate's issuer-signature check and its EKU check. Each failed 1 test.

## Neighbours
- [x] `Crl::from_der` and `verify` now call the extracted helpers, and the CRL tests pass unchanged in the record. No crate outside `nacre-revocation` calls it.
- [x] The fix run changed only error messages and docs, the new `NonceLength` variant, and the example's `certificate_valid`/`years` refactor. The example regenerates the earlier files byte for byte: the record says so, and QA c3 confirms it.

## Lenses
Lenses run:
- **security** — `src/http.rs` POSTs to a URL taken from the certificate's `authorityInfoAccess`. It uses the same public-only address policy as the CRL source, with no redirect, no proxy, a 30 s timeout and a 64 KiB limit, and no URL in its errors. I found nothing new.
- **dependencies** — `crates/nacre-revocation/Cargo.toml` adds `sha1` 0.11 and `getrandom` 0.4 and turns on `der/derive`. All three are named in the plan and already used by `nacre-tsp`. I found nothing new.

Migration and performance did not run, because the diff has no trigger for them.

## Findings
- minor — crates/nacre-revocation/src/ocsp/response.rs:275 — The "not yet valid at `producedAt`" half of the delegate's validity rule is untested.
  - Disabling the `produced_at < not_before` comparison alone fails 0 tests. Only the `not_after` side has a corpus case (`expired-delegate`).
  - The code is correct as written. A regression on that comparison alone would accept a delegate certificate that is not yet valid.
  - Fix: add a `future-delegate` case (for example valid 2027 to 2036) with its test and its row in the attacks table.
- minor — crates/nacre-revocation/src/http.rs (`HttpOcspSource::revocation`) — Through `RevocationSource`, every OCSP refusal shows `kind() = Unavailable`, including `NonceMismatch` (`InvalidSignature`) and `NonPublicAddress` (`InvalidInput`).
  - The cause is `Revocation(_) => Unavailable` at `crates/nacre-core/src/error.rs:28`, which is outside this story's `Owns`. The lead left it to s39.
  - This is QA finding 1, verified.
- minor — docs/decisions/0004-rustcrypto-foundations-and-x509-boundary.md:8 — This file is outside the story's `Owns`. The frontmatter-only `superseded-by: [0018]` edit is what AGENTS.md Law 6 requires ("only its frontmatter links, `supersedes` and `superseded-by`, ever change"), so this is a gap in `Owns`, not an implementer breach. Leave the code as it is.
- minor — crates/nacre-revocation/src/ocsp/request.rs:26 and crates/nacre-revocation/src/error.rs:99 — The fix run left two rustdoc lines of 152 and 109 columns, where the rest of the crate wraps at 92. Rustfmt does not wrap comments.

## Not verified
- I did not run `cargo fuzz build ocsp` or a fuzz session. I relied on QA's `cargo +nightly fuzz list` and its 60 s run on the fix-run code (1,041,603 runs, no crash, `docs/qa/s10-revocation-ocsp/c4-fuzz-target.txt`). The CI fuzz job covers it.
- I did not run the conformance bench test `ocsp_says_revoked_and_good_on_the_bench`. It is ignored in the record, and the implementer did not rerun it after the fix run. QA ran `tests/bench.rs --ignored` against a copy of the s02 PKI on the fix-run code. A person should check that the CI `conformance` job is green on the PR.
- I checked the SHA-256 `CertID` arm by reading it only; the plan cuts its test on purpose. QA exercised a SHA-256 `CertID` request against OpenSSL.
- From QA `## Not seen`:
  - The bench's own `pki` container (busybox httpd). The walk ran the same CGI script with its own server instead. CI conformance covers it.
  - A public OCSP responder, and pre-signed public responses. The driver reaches only servers it started. A person should try a real CA's responder before relying on it in production.
  - An RSA-signed OCSP response. Both corpora are P-256. The RSA path is shared with CRLs and was seen in s09's QA.
  - The 30 s timeout of `HttpOcspSource`. No scenario served a slow answer.
  - DNS rebinding to a non-public address other than `localhost`. This needs a resolver the driver does not start.
  - `Error::Random`. A `getrandom` failure cannot be caused from outside the process.
  - The CI fuzz job on GitHub Actions. It is a remote service; a local 60 s run was done instead.

Before answering I took the tree again: it is still `f20644f7242fb009a7ce478bee30c8a913e10d6f`, and `git status` is clean after the three bite mutations were undone.

Max severity: minor
Ship allowed: yes
