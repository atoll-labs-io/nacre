# Review — s12-pades-blta

[Story](../stories.md) · [Plan](../plans/s12-pades-blta.md) · [Verification](../verif/s12-pades-blta.md)

Diff reviewed: `git diff main...story/s12-pades-blta`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: eb3a6c90b41a24e2e6cdd70d36c200bdca368175

## When blocked
Not blocked.

## Ownership
I listed the diff with `git diff --name-only main...story/s12-pades-blta` and held each path against `Owns: crates/nacre-pades/, conformance/pki/, conformance/check.sh, conformance/README.md` (`docs/stories.md:211`).
- [x] Every path is inside `Owns`: `crates/nacre-pades/**`, `conformance/pki/{README.md,cgi-bin/tsa,cgi-bin/tsa2,generate.sh,openssl.cnf}`, `conformance/check.sh` and `conformance/README.md`. The remaining paths are the story's own evidence: `docs/research/`, `docs/plans/`, `docs/verif/` and `docs/qa/s12-pades-blta/`.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. Two other worktrees are open: s15-validate-revisions owns `crates/nacre-validate/` and `crates/nacre-pdf/`, and s39-error-kind-from-sources owns `crates/nacre-core/`, `crates/nacre-tsp/src/` and `crates/nacre-revocation/src/`. Neither overlaps this story.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s12-pades-blta` exited 0, so I reused the record (`Verification mode: record`). It covers `cargo test --workspace` (exit 0) and `cargo clippy --workspace --all-targets --all-features -- -D warnings` (exit 0) on code equal to `Tree:` f2558223… outside `docs/`. I read its "Not proven here".
- [x] `po-gate qa-current s12-pades-blta` exited 0 (`Surface: endpoint`, `QA stage: surfaces`). I carried the report's three verified findings into Findings and its `## Not seen` items into Not verified.

## Plan
- [x] Tasks 1 to 9 are all present, and nothing is outside the plan. The tests of `tests/sign.rs` and `tests/conformance.rs` from before this story are unedited: only the import lines and appended tests changed.
- [x] Each run interdict checked:
  - The diff is empty in nacre-pdf, nacre-core, nacre-cms, nacre-revocation, nacre-tsp, nacre-validate, `conformance/dss/`, `compose.yaml`, `.github/`, `docs/stories.md` and the root `Cargo.toml`.
  - `Cargo.toml` changes only its `description`: no new dependency and no `[workspace.dependencies]`.
  - The B, T and LT paths are factored into `to_long_term` with their behaviour unchanged.
  - `src/` reads no clock, opens no connection and does no I/O. It indexes or unwraps nothing: it uses `split_at_checked`, `checked_add` and `try_from`.
  - `extend` takes no time parameter and has no "not due" path.
  - Each TSA is asked once, after `/DSS` is written.
  - The `bench_tsa` section is unchanged; the script now runs `-section "${TSA_SECTION:-bench_tsa}"`, and `bench_tsa` is the default.

## References
- [x] Every reference was opened and confirmed against its source:
  - `Update::sign`/`SignatureSpec`/`PreparedSignature` (nacre-pdf)
  - `SignedData::from_der(..).certificates` (`crates/nacre-cms/src/model.rs:71-84`)
  - `ltv::material` (`ltv.rs:27`), `dss::append` and `dss::vri_key` (`dss.rs:11,81`)
  - `check_token` (`timestamp.rs`), `TIMESTAMP_TOKEN_MAX` (re-exported at `lib.rs:39`, so the rustdoc links resolve)
  - `der` `Header`/`SliceReader`

  Compilation and clippy are proven by the record.
- [x] Values checked: `/SubFilter /ETSI.RFC3161`, `/Type /DocTimeStamp`, no `/M`, and a reserve of 16 384 bytes enforced by `check_token`. The VRI key is the SHA-1 of the whole `/Contents`, the s11 convention. Bench policy `2.999.1.2` is distinct from `2.999.1.1`.

## Rules
- [x] The `AGENTS.md` conventions hold: `forbid(unsafe_code)` is untouched, there are no panics on input, the new error variants carry no bytes or paths, each has a `kind()`, and the crate still says "Experimental".
- [x] No accepted ADR is contradicted. The second TSA stays within ADR-0011 bench tooling, and no new ADR was needed.

## Tests
- [x] Floor: `po-gate floor-guard s12-pades-blta main` exited 0, so nothing was lowered.
- [x] The assertions pin down criteria 1 to 5 at the service level, with real CMS tokens. The fakes record the requests and do not reproduce the choice under test. None of the six empty shapes appears.
- [x] Within `Test budget` 25: 5 service tests, 3 kind rows and 2 conformance tests.
- [x] Bite: four rules disabled, one at a time, each running only `cargo test -p nacre-pades --test sign`. After each I ran `git checkout -- <file>`, and `git diff --exit-code` was clean after the last one.
  - newest timestamp chosen by `end < latest` (oldest) → 1 failing test (`extend_renews_the_newest_document_timestamp`)
  - `extend` skips the `/DSS` revision → 1 failing test (same test)
  - LTA arm wraps a doc-timestamp failure as `LongTerm` instead of `Archive` → 1 failing test (`document_timestamp_failure_returns_the_lt_file`)
  - zero-padding check in `der_prefix` disabled (`archive.rs:115`) → **0 failing tests**, see Findings
- [x] No test is made useless by the story.

## Neighbours
- [x] `Level` is `#[non_exhaustive]`, so callers in nacre-validate and nacre-pkcs11 keep compiling, which the workspace clippy confirms. The two callers of `timestamp_signature` and of the factored `field_name` behave as before.

## Lenses
Lenses run: security — `conformance/pki/cgi-bin/tsa` and `tsa2` (HTTP handlers of the bench). CGI exposes request headers only as `HTTP_*`, so `TSA_SECTION` cannot be set by a client. No finding.
- [x] Each lens finding graded: none.

## Findings
- major — crates/nacre-pades/src/archive.rs:60 — `extend` quietly renews a document timestamp whose token carries no certificates.
  - What happens: `SignedData.certificates` is empty when a TSA ignored `certReq` or a foreign tool stripped the certificates. Then `ltv::material(&[], &[], issuers, ..)` walks nothing, because its queue is seeded only from `chain` and `token_certificates`. `dss::append` writes a `/VRI` entry holding only `/Type /VRI`, and a new timestamp is added.
  - Why it matters: the caller gets `Ok`, yet the previous TSA's certificate and revocation data, which criterion 2 requires, were never stored. That gap is exactly what B-LTA renewal exists to prevent.
  - Evidence: confirmed by reading `ltv.rs:44` and `dss.rs:97-127`, not by a run.
  - Suggested fix: refuse with a `DocumentTimestamp`/`IssuerMissing`-style error, or find the signer certificate in `issuers` or in the existing `/DSS` through the token's ESS signing certificate.
- minor — crates/nacre-pades/src/archive.rs:115 — the "every byte after the DER is zero" rule of `der_prefix` (plan task 5) is covered by no test. Disabling it fails 0 tests: `extend_refuses_a_malformed_document_timestamp` overwrites the first byte, so the tag check fires first. The impact is low, since the trailing bytes feed only the VRI key, but the rule is untested.
- minor — crates/nacre-pades/src/archive.rs:79-81 — `newest_document_timestamp` returns `DocumentTimestamp` ("the newest document timestamp is malformed") as soon as any document timestamp, even an older one, has an unreadable `/ByteRange` or `/Contents`. The message can name the wrong timestamp, and one damaged old timestamp blocks renewal of a sound newest one.
- minor — crates/nacre-pades/src/archive.rs:63 — QA finding 1 (verified): when the renewing TSA fails, `extend` returns a bare `Error::Timestamp` and throws away the `/DSS` revision it built from data already fetched. `sign_at_level` does the opposite and hands back the B-LT file in `Error::Archive`. Evidence: `docs/qa/s12-pades-blta/c2-extend-error.txt`.
- minor — crates/nacre-pades/src/sign.rs (LTA arm) — QA finding 2 (verified): at LTA, the document TSA's chain is neither checked nor stored, so an issuer nacre cannot resolve only surfaces at the first `extend` (`IssuerMissing`). This follows the plan's order, and DSS accepted the bench file. Evidence: `docs/qa/s12-pades-blta/c5-two-tsa-error.txt`.
- minor — crates/nacre-pades/src/archive.rs:61 — QA finding 3 (verified): each `extend` stores the root, the TSA certificates and the CRL in `/DSS` again. This continues the filed s11 finding about missing deduplication. Evidence: `docs/qa/s12-pades-blta/c2-extend.txt`.
- minor — crates/nacre-pades/tests/sign.rs:971 — `let a = stamp.byte_range[1];` reads element `b` of `/ByteRange [a b c d]` while naming it `a`. The comment's reasoning is right; only the name misleads.

## Not verified
- **DSS verdicts** `TOTAL_PASSED` / `PAdES-BASELINE-LTA`, after signing, after `extend` and with two distinct TSAs (criteria 1, 2 and 5).
  - Why: I did not start the bench. The record reports a hand run of the two ignored conformance tests as passed, and QA did not replay it.
  - What I saw: `target/conformance/s12-pades-lta{,-extended}.xml` exist (10:55 UTC, just before the recorded runs), with one `total-passed`, and their JSON names `PAdES-BASELINE-LTA`. Nothing ties those files to the reviewed tree.
  - A person should run `down`, `pki-init`, `up -d`, `sh conformance/check.sh`, then `cargo test -p nacre-pades --all-features --test conformance -- --ignored`, or let `conformance.yml` run in CI.
- **The bench's `tsa2`** (`generate.sh`, `openssl.cnf [bench_tsa2]`, `cgi-bin/tsa2`, the `check.sh` loop and its `^TSA: .*CN *= *<name>$` match against `openssl ts -reply -text` output): proven only by the implementer's reported `check.sh` → `bench ready`, not seen by me or by QA. Same action as above.
- **Real remote OCSP/CRL servers and a real network TSA**: out of reach (QA `## Not seen`). Only loopback servers were used.
- **An RSA signer or TSA, and a document TSA with an OCSP URL**: not exercised; QA used P-256 and CRL-only TSAs (QA `## Not seen`).
- **A foreign LTA file given to `extend`**: QA built every input with nacre (QA `## Not seen`). This includes the certificate-less token case of the major finding, which I established by reading the code, not by a run. A person should feed `extend` an LTA file from pyHanko or DSS, and one whose doc-timestamp token has no `certificates`.
- **Formatting (`cargo fmt --all --check`) and the production build**: left to commit and ship (`Build stage: ship-if-route`; no manifest dependency changed).
- **End to end**: the project has none (`E2E: —`).

Max severity: major
Ship allowed: yes

---

# Review — s12-pades-blta

[Story](../stories.md) · [Plan](../plans/s12-pades-blta.md) · [Verification](../verif/s12-pades-blta.md)

Diff reviewed: `git diff main...story/s12-pades-blta`. I read it in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: 44b3bcec8b48e0b4e45859d154e9aac0cdd01a5a

## When blocked
Not blocked. I took the tree again just before answering and it had not changed, and the worktree is clean.

## Ownership
I listed the diff with `git diff --name-status main...story/s12-pades-blta` and checked each path against `Owns: crates/nacre-pades/, conformance/pki/, conformance/check.sh, conformance/README.md` (`docs/stories.md:211`).
- [x] Every path is inside `Owns`:
  - `crates/nacre-pades/**`
  - `conformance/pki/{README.md,cgi-bin/tsa,cgi-bin/tsa2,generate.sh,openssl.cnf}`
  - `conformance/check.sh`
  - `conformance/README.md`
- [x] The rest is the story's own evidence: `docs/research/`, `docs/plans/`, `docs/verif/`, `docs/reviews/` and `docs/qa/s12-pades-blta/`.
- [x] Nothing is outside `Owns`.
- [x] Nothing is inside another running story's `Owns`. The other open worktrees are s15-validate-revisions (`crates/nacre-validate/`, `crates/nacre-pdf/`) and s39-error-kind-from-sources (`crates/nacre-core/`, `crates/nacre-tsp/src/`, `crates/nacre-revocation/src/`). Neither overlaps this story.
- [x] The fix commit `e618436` changed only `crates/nacre-pades/src/{archive,error}.rs`, `tests/sign.rs` and docs. The second QA commit `aa81653` changed only `docs/qa/`.

## Evidence reused
- [x] `po-gate verif-current s12-pades-blta` exited 0 (`Verification mode: record`). So I reused, without rerunning them, `cargo test --workspace` (exit 0) and `cargo clippy --workspace --all-targets --all-features -- -D warnings` (exit 0), both run on the fixed code. I also read the record's "Not proven here".
- [x] `po-gate qa-current s12-pades-blta` exited 0 (`Surface: endpoint`, `QA stage: surfaces`, QA `Tree:` 576cdbd8…). QA walked the fixed code again. Its three verified findings are listed below, and its `## Not seen` items are under Not verified.

## Plan
- [x] Tasks 1 to 9 are present. The run interdicts still hold after the fix:
  - nothing changed outside `Owns`;
  - no dependency was added (`Cargo.toml` changes only `description`);
  - `src/` reads no clock and does no I/O, and it does not index or unwrap;
  - each TSA is asked once, after `/DSS` is written;
  - `bench_tsa` is unchanged.
- [x] The fix adds `find_signer`, `dss_certificates` and `Error::TimestampSignerMissing`. They answer the previous review's major finding, which is within fix-mode scope.
- [x] Previous findings, each checked:
  - **Major, certificate-less token:** fixed. `extend` now refuses with `TimestampSignerMissing`, or finds the signer in `issuers` or `/DSS`.
  - **Padding rule untested:** fixed by a new test, and it bites (see Tests).
  - **Misleading message:** reworded. Only the newest timestamp's `/Contents` is judged now.
  - **QA finding 1 of the earlier walk:** fixed. `extend` now returns `Error::Archive` carrying the `/DSS` revision.
  - **Variable name:** fixed.

## References
- [x] Opened and confirmed:
  - `nacre_pdf::Stream { dict, data: Range<usize> }` (`crates/nacre-pdf/src/object.rs:95-98`): raw bytes, never decoded;
  - `Document::catalog()` (`document.rs:102`);
  - `ltv::material` (`ltv.rs:27-48`), which parses every pool entry with `Certificate::from_der` and fails on the first that is not one;
  - `SignerIdentifier`, `SubjectKeyIdentifier`, `dss::append` and `dss::vri_key`.
- [x] Compilation and clippy are proven by the record.

## Rules
- [x] The `AGENTS.md` conventions hold:
  - no panics on input, with checked arithmetic and `split_at_checked`;
  - the new variants carry no bytes or paths, and each maps to a kind;
  - the crate doc still says "Experimental".
- [x] No accepted ADR is contradicted.

## Tests
- [x] Floor: `po-gate floor-guard s12-pades-blta main` exited 0.
- [x] None of the six kinds of test that prove nothing appears. The certificate-less fixtures really strip `certificates` from a real CMS token.
- [x] Within `Test budget` 25: 9 service tests, 4 kind rows and 2 conformance tests.
- [x] Bite: I disabled two rules, one at a time, running only `cargo test -p nacre-pades --test sign` each time. After each I ran `git checkout -- crates/nacre-pades/src/archive.rs`, and `git diff --exit-code` was clean.
  - `pool.extend(dss_certificates(..))` removed (the signer is no longer looked up in `/DSS`) → 2 tests fail (`extend_finds_a_certificate_less_token_signer_in_dss`, `extend_needs_the_certificate_of_a_certificate_less_token_signer`).
  - Zero-padding check in `der_prefix` disabled (`… && false`) → 1 test fails (`extend_refuses_a_document_timestamp_padded_with_non_zero_bytes`).

## Neighbours
- [x] `Level` is `#[non_exhaustive]`, and the workspace clippy run proves that the dependents of the new variants still compile.
- [x] `timestamp_signature` and `field_name` behave as before for B, T and LT.

## Lenses
Lenses run: security — `conformance/pki/cgi-bin/tsa` and `tsa2` (HTTP handlers of the bench), unchanged since loop 0. `TSA_SECTION` cannot be set by a client, because CGI passes request headers only as `HTTP_*`. Dependencies did not run: `Cargo.toml` changed only its `description`, and no lockfile is tracked.
- [x] Each lens finding graded: none.

## Findings
- major — crates/nacre-pades/src/archive.rs:79-81 — `extend` refuses a sound file when its `/DSS` holds a filtered (for example FlateDecode) certificate stream.
  - What happens: when the token carries no signer certificate, every raw `/DSS /Certs` stream goes into `pool`, which is then passed to `ltv::material(&certificates, &[], &pool, ..)`. `ltv::material` (`ltv.rs:33-41`) parses every pool entry and returns `Error::Certificate` on the first one that is not DER X.509. A compressed stream is not, because `dss_certificates` returns undecoded bytes (`Stream.data` is a raw range).
  - The result: whenever one `/DSS` certificate is filtered, `extend` fails with `Certificate` (kind `InvalidInput`), even when `find_signer` found the signer among the unfiltered streams.
  - This contradicts the rustdoc of `dss_certificates` ("`find_signer` skips it and the signer stays missing rather than guessed") and the record ("refused as missing").
  - It is contained: it returns an error, damages nothing silently, and nacre's own files hold unfiltered streams. But foreign LTA files often compress their `/DSS` streams.
  - Evidence: established by reading `ltv.rs:33-41`, `object.rs:95-98` and `archive.rs:155-185`. I did not run it.
  - Suggested fix: keep only the `/DSS` entries that parse as `Certificate` before building `pool`, or decode the filters. Add a test with one non-certificate `/Certs` stream.
- minor — crates/nacre-pades/src/archive.rs:62 — QA finding 1 (verified): a file handed back in `Error::Archive` can be finished only by doing the work again. Giving it back to `extend` fetches revocation again and writes a second `/DSS`. A B-LT file from `sign_at_level`'s hand-back gets `NotArchived`, so the public interface cannot raise it to LTA. Evidence: `docs/qa/s12-pades-blta/c2-extend-error.txt`.
- minor — crates/nacre-pades/src/sign.rs:134-138 — QA finding 2 (verified): at LTA, the document TSA's chain is neither checked nor stored. An issuer nacre cannot resolve, or a certificate-less document token, surfaces only at the first `extend`. Evidence: `docs/qa/s12-pades-blta/c5-two-tsa-error.txt`.
- minor — crates/nacre-pades/src/archive.rs:84 — QA finding 3 (verified): each `extend` stores again in `/DSS` the root, the TSA certificates and the CRL already there (about 35 kB per call). This continues the s11 finding about missing deduplication. Evidence: `docs/qa/s12-pades-blta/c2-extend.txt`.

## Not verified
- **DSS verdicts** `TOTAL_PASSED` / `PAdES-BASELINE-LTA` after signing, after `extend` and with two distinct TSAs (criteria 1, 2 and 5).
  - Why: I did not start the bench, and QA did not replay it. Only the record reports a hand run of the six pades conformance tests on the fixed code.
  - What a person should do: run `down`, `pki-init`, `up -d`, `sh conformance/check.sh`, then `cargo test -p nacre-pades --all-features --test conformance -- --ignored`, or let `conformance.yml` run in CI.
- **The bench's `tsa2`** (`generate.sh`, `[bench_tsa2]`, `cgi-bin/tsa2`, `check.sh`): proven only by the implementer's reported `bench ready`. Same action as above.
- **The filtered `/DSS` case of the major finding**: established by reading, not by a run. I may not add a probe test to the worktree. A person should give `extend` an LTA file from DSS or pyHanko whose token lacks certificates and whose `/DSS` streams are compressed.
- **Real remote OCSP/CRL servers and a real network TSA**: out of reach; only loopback servers were used (QA `## Not seen`).
- **An RSA signer or TSA, and a document TSA with an OCSP URL**: not exercised; QA used P-256 and CRL-only TSAs (QA `## Not seen`).
- **A foreign LTA file, including a filtered `/DSS /Certs` stream**: QA built every input with nacre (QA `## Not seen`).
- **The renewing-TSA failure, the certificate-less token and the non-zero padding against DSS**: proven by unit tests only (record).
- **Formatting (`cargo fmt --all --check`) and the production build**: left to commit and ship (`Build stage: ship-if-route`; no routing or dependency manifest changed).
- **End to end**: the project has none (`E2E: —`).

Max severity: major
Ship allowed: yes

---

# Review — s12-pades-blta

[Story](../stories.md) · [Plan](../plans/s12-pades-blta.md) · [Verification](../verif/s12-pades-blta.md)

Diff reviewed: `git diff main...story/s12-pades-blta`, read by a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 2
Reviewed tree: 1a4002b420a2438d76b4b0aa86a59aa6cd13285d

## When blocked
Not blocked. I took the tree again before writing this answer and it still matches the one above. The worktree is clean.

## Ownership
I listed the changed paths with `git diff --name-only main...story/s12-pades-blta` and checked each one against `Owns: crates/nacre-pades/, conformance/pki/, conformance/check.sh, conformance/README.md` (`docs/stories.md`, s12).
- [x] Every code path is inside `Owns`:
  - `crates/nacre-pades/**`
  - `conformance/pki/{README.md,cgi-bin/tsa,cgi-bin/tsa2,generate.sh,openssl.cnf}`
  - `conformance/check.sh`
  - `conformance/README.md`

  The remaining paths are the story's own evidence: `docs/research/`, `docs/plans/`, `docs/verif/`, `docs/reviews/` and `docs/qa/s12-pades-blta/`.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. The other open worktrees do not overlap this story:
  - s15-validate-revisions owns `crates/nacre-validate/`, `crates/nacre-pdf/` and `docs/security/attacks/pades.md`.
  - s39-error-kind-from-sources owns `crates/nacre-core/`, `crates/nacre-tsp/src/` and `crates/nacre-revocation/src/`.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s12-pades-blta` exited 0, so I reused the record (`Verification mode: record`).
  - The last runs were `cargo test --workspace` (exit 0) and `cargo clippy --workspace --all-targets --all-features -- -D warnings` (exit 0), on code equal to `Tree:` a9ba5c23… outside `docs/`.
  - I read its "Not proven here", including the second fix run. It describes the cause of the CI conformance failure (`openssl ts -reply` serial-file race) and the hand-run conformance passes. None of that is a recorded check.
- [x] `po-gate qa-current s12-pades-blta` exited 0. The story goes to QA because its `Surface` is `endpoint` and `QA stage` is `surfaces`.
  - The report's three verified findings are carried into Findings.
  - Its `## Not seen` items are under Not verified.
- [x] I also ran `cargo test -p nacre-pades --test sign` once as a baseline for the bite runs: 25 passed.

## Plan
- [x] Tasks 1 to 9 are all present. Since loop 1, the fix commit `b20a2c2` changes three things:
  - `conformance/pki/cgi-bin/tsa`: `openssl ts -reply` now runs under `flock` per section.
  - `archive.rs:178`: only the `/DSS /Certs` streams that parse as certificates are kept.
  - One new test, `extend_leaves_out_a_dss_stream_that_is_not_a_certificate`.

  The first two answer the loop-1 major and the CI failure on PR #101. Both stay inside `Owns` and inside a fix run's remit.
- [x] Run interdicts hold:
  - The diff is empty in nacre-pdf, nacre-core, nacre-cms, nacre-revocation, nacre-tsp, nacre-validate, `conformance/dss/`, `compose.yaml`, `.github/`, `docs/stories.md` and the root `Cargo.toml`.
  - `Cargo.toml` changes only its `description`.
  - Before this story, `tests/sign.rs` and `tests/conformance.rs` lost only their two `use` lines; their earlier tests are unedited.
  - `src/` uses no clock, no I/O, no indexing and no unwrap.
  - The `bench_tsa` default is unchanged.

## References
- [x] Opened and confirmed:
  - nacre-pdf `Document`, `signature_fields`, `object`, `catalog`, `update().sign`, `PreparedSignature::{signed_parts,embed}`
  - `SignedData::from_der`, `SignerIdentifier`
  - `ltv::material`, `dss::append` and `dss::vri_key`
  - `check_token`, `field_name`
  - `x509_cert::Certificate::from_der`
- [x] The new `flock` call runs in `conformance/pki/Containerfile`, which installs alpine 3.24.3 with its base busybox (flock applet) plus `openssl` and `busybox-extras`. The lock path `$PKI_DIR/<section>.lock` is in the writable state directory that `serve.sh` copies into. The record reports a rebuilt bench passing; I did not run it.
- [x] Values checked: `/SubFilter /ETSI.RFC3161`, `/Type /DocTimeStamp`, no `/M`, `TIMESTAMP_TOKEN_MAX` enforced by `check_token`, VRI key = SHA-1 of the whole `/Contents`, and the newest timestamp chosen by checked `c + d`.

## Rules
- [x] The `AGENTS.md` conventions hold:
  - `forbid(unsafe_code)` is untouched.
  - There are no panics on input.
  - The new variants carry no bytes or paths, and each maps to a kind.
  - The crate doc still says "Experimental".
- [x] No accepted ADR is contradicted. The second TSA stays within the ADR-0011 bench.

## Tests
- [x] Floor: `po-gate floor-guard s12-pades-blta main` exited 0.
- [x] No empty shapes. The new test's fixture adds a FlateDecode stream at the head of `/Certs`; the signer is a separate unfiltered copy, so the fixture cannot answer for the filter.
- [x] Budget: 10 new service tests, 4 kind rows and 2 conformance tests, 16 in all, within `Test budget` 25.
- [x] Bite: two rules disabled in turn. Each run used only `cargo test -p nacre-pades --test sign`, then I ran `git checkout -- <file>` and `git diff --exit-code <file>` came back clean.
  - `archive.rs:178`: the `Certificate::from_der(data).is_ok()` filter replaced by `true` → 1 test fails (`extend_leaves_out_a_dss_stream_that_is_not_a_certificate`).
  - `sign.rs:135`: the LTA arm asks `tsa` instead of `document_tsa` → 4 tests fail (`level_lta_adds_a_document_timestamp_after_dss`, `document_timestamp_failure_returns_the_lt_file`, `extend_renews_the_newest_document_timestamp`, `extend_needs_the_certificate_of_a_certificate_less_token_signer`).

## Neighbours
- [x] `dss_certificates` and `find_signer` are private to `archive.rs`. `check_token` is shared by `timestamp_signature` and `document_timestamp`, and the B/T/LT tests still pass. `Level` is `#[non_exhaustive]`, and the workspace clippy run proves that dependents compile.

## Lenses
Lenses run: security — the bench's HTTP CGI handlers `conformance/pki/cgi-bin/tsa` (new `flock`) and `tsa2`. A client cannot set `TSA_SECTION`, because CGI passes request headers only as `HTTP_*`, so the lock path cannot be steered. Dependencies did not run: `Cargo.toml` changed only its `description`, and no lockfile is tracked.
- [x] Each lens finding graded: none.

## Findings
- minor — crates/nacre-pades/src/archive.rs:84 — QA finding 1 (verified): a file handed back in `Error::Archive` can be finished only by doing the work again. Giving it back to `extend` fetches revocation again and writes a second `/DSS`. The B-LT file that `sign_at_level` hands back gets `NotArchived`, so the public interface cannot raise it to LTA. Evidence: `docs/qa/s12-pades-blta/c2-extend-error.txt`.
- minor — crates/nacre-pades/src/sign.rs:134-138 — QA finding 2 (verified): at LTA, the document TSA's chain is neither checked nor stored. An issuer nacre cannot resolve, or a certificate-less document token, shows up only at the first `extend`. Evidence: `docs/qa/s12-pades-blta/c5-two-tsa-error.txt`.
- minor — crates/nacre-pades/src/archive.rs:83 — QA finding 3 (verified): each `extend` stores again in `/DSS` the root, the TSA certificates and the CRL already there, about 35 kB per call. This continues the s11 finding about missing deduplication. Evidence: `docs/qa/s12-pades-blta/c2-extend.txt`.

The loop-1 major (a filtered `/DSS` stream blocks `extend`) is fixed. The fix is proven by the first bite and by the QA walk on this code (`c2-extend.txt`).

## Not verified
- **DSS verdicts** `TOTAL_PASSED` / `PAdES-BASELINE-LTA` after signing, after `extend` and with two distinct TSAs (criteria 1, 2 and 5).
  - Why: I did not start the bench, and QA did not replay it. Only the record reports hand runs on the fixed code.
  - Action: run `down`, `pki-init`, `build pki`, `up -d`, `sh conformance/check.sh`, then `cargo test -p nacre-pades --all-features --test conformance -- --ignored`, or let `conformance.yml` pass on the PR.
- **The `flock` fix of the bench TSA** and the concurrency that triggered the CI failure.
  - Why: no recorded check covers it; the only evidence is the parallel-request runs the record reports.
  - Action: the green CI `conformance` job on PR #101 is the proof to look for.
- **The bench's `tsa2`** (`generate.sh`, `[bench_tsa2]`, `cgi-bin/tsa2`, `check.sh`).
  - Why: it is proven only by the reported `bench ready`.
  - Action: the same as above.
- **A foreign LTA file** (DSS or pyHanko), including compressed `/DSS` streams.
  - Why: every input was built by nacre; the filtered stream was synthesised (QA `## Not seen`).
  - Action: feed `extend` such a file.
- **Real remote OCSP/CRL servers and a real network TSA**: out of reach; only loopback was used (QA `## Not seen`).
- **An RSA signer or TSA, and a document TSA with an OCSP URL**: not exercised; P-256 and CRL-only TSAs were used (QA `## Not seen`).
- **The certificate-less token, non-zero padding and renewing-TSA failure against DSS**: proven by unit tests only (record).
- **Formatting and the production build**: left to commit and ship (`Build stage: ship-if-route`; no routing or dependency manifest changed).
- **End to end**: the project has none (`E2E: —`).

Max severity: minor
Ship allowed: yes
