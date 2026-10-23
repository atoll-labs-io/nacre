# Review — s16-validate-chain

[Story](../stories.md) · [Plan](../plans/s16-validate-chain.md) · [Verification](../verif/s16-validate-chain.md)

Diff reviewed: `git diff main...story/s16-validate-chain`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: a74e31638a04b516f1287fb086dc97ac9d65512b

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
Diff listed with `git diff --name-only main...story/s16-validate-chain`: 42 paths, each held against `Owns: crates/nacre-validate/, docs/security/attacks/cms.md, docs/security/attacks/pades.md`.
- [x] Every path inside `Owns`. Everything under `crates/nacre-validate/` and the two attack docs is covered. `docs/research/`, `docs/plans/`, `docs/verif/` and `docs/qa/s16-validate-chain/` are the story's own evidence.
- [x] Outside `Owns`: none
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s16-validate-chain`: exit 0, so the record is reused. The unit suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) count as proven for this code and were not rerun. I read its "Not proven here" section, and those items are carried to Not verified.
- [x] `po-gate qa-current s16-validate-chain`: exit 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). QA findings 1 (major) and 2 (minor) are verified, so both are carried to Findings. QA's `## Not seen` is carried to Not verified.

## Plan
- [x] Tasks 1 to 8 are all present, and nothing is outside the plan. One small gap from task 5, about the OID, is listed under Findings.
- [x] Run interdicts, one by one:
  - Nothing changed outside the allowed paths.
  - `forge_pades_attacks.rs` and the existing corpus files are untouched: corpus entries are status `A` only, and the README only gains rows.
  - No existing assertion changed. `hostile.rs` adds calls and the unit test only changes a call signature.
  - `validate(pdf)` keeps its signature.
  - `src/` has no `SystemTime::now` or `Instant::now`.
  - There is no `[workspace.dependencies]`, no `cms` or `x509-tsp` crate, and no network code.
  - The public types holding certificate bytes derive `Debug`, and no message names a file path.
  - No revocation or TSA chain is judged.

## References
- [x] Every API I opened exists:
  - `nacre_cms::VerifiedSigner::certificate` (`crates/nacre-cms/src/verify.rs:25`)
  - `SignedData::certificates` (`crates/nacre-cms/src/model.rs:77`)
  - `nacre_pdf::Stream::data: Range<usize>` (`object.rs:97`)
  - `Document::catalog` (`document.rs:102`)
  - x509-cert 0.3 `get_extension`, which returns an error on a duplicated extension, so `MalformedExtension` is reachable for keyUsage and basicConstraints
  - `Time::to_system_time`
- [x] Values checked:
  - `pathLenConstraint` is compared with `depth - 1`, the number of intermediates below the certificate, which matches RFC 5280 §4.2.1.9. The self-issued exemption is not applied, which makes it stricter.
  - `notAfter` is inclusive.
  - A leaf with no `keyUsage` is accepted (RFC 5280 §4.2.1.3).
  - The search limits, `MAX_PATH_LEN = 8` and `MAX_SIGNATURE_CHECKS = 64`, are the values the plan sets.
  - The list of understood critical extensions has one weak entry, listed under Findings.

## Rules
- [x] `AGENTS.md` conventions are respected: no clock, the control date is a parameter, the `thiserror` enum has `kind()`, no panic paths outside tests, versions are declared per crate, and no `Cargo.lock` is committed. One gap in fuzz coverage is listed under Findings.
- [x] No accepted ADR is contradicted. Path judgement is written by Nacre on x509-cert models (ADR-0001, ADR-0004).

## Tests
- [x] Floor: `po-gate floor-guard s16-validate-chain main` exits 0 (nothing lowered).
- [x] Assertions pin criteria 1 to 4, and none of the six empty test shapes appear. The fixtures come from a deterministic forge, and no mock is involved.
- [x] 13 tests, within the `Test budget` of 25.
- [x] Bite results:
  - Disabling the `cA` check (`chain.rs:312`): 1 test fails (`chain_leaf_as_ca_is_rejected`). Undone, `git diff --exit-code` clean.
  - Making the issuer signature check always true (`chain.rs:273`): 2 tests fail (`chain_impostor_root_is_rejected`, `path_is_built_without_pdf`). Undone, clean.
  - Disabling the CA `keyCertSign` check (`chain.rs:315-319`): **0 tests fail**, across the lib, attacks, chain, validate and hostile suites. Undone, clean.
  - Disabling the `notBefore` check (`chain.rs:282`): **0 tests fail**, across the lib, attacks, chain and validate suites. Undone, clean.
- [x] No test is made useless by the story.

## Neighbours
- [x] No crate outside `nacre-validate` uses it. The fuzz target `crates/nacre-validate/fuzz/fuzz_targets/validate.rs` calls `validate` unchanged. `SignatureValidation` and `Defect` are `#[non_exhaustive]`, so the new field and variant break no caller.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml` adds `x509-cert`, `spki`, `p256` and `rsa =0.10.0-rc.19`, plus dev-dependencies). All of them are named in plan task 1 at the versions `crates/nacre-revocation/Cargo.toml` already uses, and no lockfile is committed. Security, migration and performance did not run: no path or content triggered them.
- [x] Each lens finding is graded and listed below (none from the dependencies lens).

## Findings
- major — crates/nacre-validate/src/chain.rs:24 — A hostile pool can hide a valid chain (QA finding 1, verified).
  - `MAX_SIGNATURE_CHECKS = 64` is shared by every candidate. The name and key-identifier filter (`chain.rs:216-222`) only compares values an attacker chooses.
  - QA reproduced it: 63 certificates that copy the intermediate's subject and `subjectKeyIdentifier`, placed in the pool ahead of the real intermediate, turn a valid path into `NoPath`, i.e. `INDETERMINATE / NO_CERTIFICATE_CHAIN_FOUND`.
  - The pool is the CMS `certificates` set, which the signature does not cover and which sits inside the ByteRange gap, followed by the `/DSS` of the last revision, which anyone can append. So a third party can downgrade a valid signature without touching the signed bytes.
  - It fails closed, so it never becomes a pass.
  - This contradicts the plan's third pivot risk, "an honest chain costs one check per level".
  - This is a security matter: under Law 7 it goes to the person, not to the issue tracker.
- major — crates/nacre-validate/src/chain.rs:315 and :282 — Two judgement rules have no test that fails without them: the CA `keyCertSign` rule (`CaKeyUsage`) and the `notBefore` rule (`NotYetValid`).
  - Disabling either fails 0 tests. The only test that names them, `every_chain_defect_has_its_report`, checks how a variant maps to a report, not the rule itself.
  - `MalformedExtension` is also only reached through that table.
  - Plan task 3 promised "Tests: the attack tests of task 6, one per rule", but task 6 forges only six cases.
  - QA saw the behaviour by hand, so it currently works, but no regression would be caught.
- major — crates/nacre-validate/src/chain.rs:39 — A critical `extendedKeyUsage` is listed as understood but never applied.
  - RFC 5280 §4.2.1.12 says a certificate carrying it "MUST only be used for one of the purposes indicated".
  - Because the leaf's EKU is never read, a signer whose critical EKU allows only, say, `serverAuth` gets a valid path (`chain: Some`, `TRY_LATER`).
  - This is laxer than "a critical extension not processed refuses the path", the rule this list exists for. Either process EKU for the leaf or take it out of `UNDERSTOOD_EXTENSIONS`.
  - The plan chose the list, but the defect is in the code all the same.
  - It is contained: it needs a certificate issued under an anchor the caller trusts.
- minor — crates/nacre-validate/src/validate.rs:139 — `validate` (no anchor) still calls `build_chain` for each sound signature.
  - It runs up to 64 certificate signature checks on certificates from the CMS, although no path can exist.
  - The result is the same, but the work is wasted on every call, and the fuzz target pays for it on every input.
  - A short-circuit when `anchors.is_empty()` would avoid it, as the `/DSS` read already does at :92.
- minor — crates/nacre-validate/fuzz/fuzz_targets/validate.rs — The new parser and judge are only fuzzed through `validate` with no anchor, so `judge` and the `/DSS` reader are never reached by the fuzzer.
  - The convention says each parser has a cargo-fuzz target.
  - The record says the target was not extended. `hostile.rs` partly covers the gap.
- minor — crates/nacre-validate/src/error.rs:17 — A PEM trust anchor is refused with a bare DER tag message (QA finding 2, verified).
  - The message reads `unknown/unsupported ASN.1 DER tag: 0x2d at DER byte 1`, which does not say the input looks like PEM, the form the project's own bench ships.
- minor — crates/nacre-validate/examples/forge_chain_attacks.rs:53 — The unknown critical extension uses OID `1.3.6.1.4.1.32473.1`, not one under `2.999` as plan task 5 states.
  - The corpus README documents the choice (the RFC 5612 documentation arc), and the outcome is the same.

## Not verified
- Criterion 1 on the real bench (`bench_chain_is_valid`, `#[ignore = "conformance"]`).
  - The record says it was run once, green, against a PKI generated on the host, but there is no `po-run` row; QA reproduced it the same way.
  - Who covers it: the conformance CI job, or a person running `cargo test -p nacre-validate --test conformance -- --ignored` with the bench up.
- Criterion 1 with the bench signer's intermediate carried in `/DSS` (QA Not seen). Nacre writes `/DSS` only at B-LT, which needs the bench TSA and OCSP responder. Only the corpus `chain-dss.pdf` was checked.
- DSS's verdict on the same chains (QA Not seen; plan pivot). The sub-indications chosen for the CA flag, path length and key usage, and `TRY_LATER` for a valid path, have not been compared with DSS 6.5.1. The s18 campaign has to compare them.
- QA finding 1 through a PDF (QA Not seen): no PDF with look-alikes in the CMS `certificates` or in an appended `/DSS` was built. My statement that it can be reached from a PDF comes from reading `validate.rs:130-139`, not from running it.
- RSA certificate paths (QA Not seen). Every certificate tried is ECDSA P-256, so `verify_rsa` and `key_kind`'s RSA branch are not exercised by any test.
- Name matching is DER byte equality, stricter than RFC 5280 §7.1. Interoperability with CAs that encode the issuer name differently from the subject was not checked.
- The fuzz target was not run in this review or by the implementer.
- `cargo fmt` is not recorded as a `po-run` row. Formatting is left to the commit hook and CI.
- The end-to-end suite and the production build were not run. The project has no `E2E` command, and `Build stage: ship-if-route` leaves the build to ship. The diff touches a manifest (`Cargo.toml`), so `/po-ship` should run `cargo build --workspace --all-features`.

Max severity: major
Ship allowed: yes

---

# Review: s16-validate-chain

[Story](../stories.md) · [Plan](../plans/s16-validate-chain.md) · [Verification](../verif/s16-validate-chain.md)

Diff reviewed: `git diff main...story/s16-validate-chain`, read in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: b2e3842a4caff6828d75a1927770d03add615de7

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
`git diff --name-only main...story/s16-validate-chain` lists 51 paths. I checked each one against `Owns: crates/nacre-validate/, docs/security/attacks/cms.md, docs/security/attacks/pades.md`.
- [x] Every path is inside `Owns`. The paths under `docs/research/`, `docs/plans/`, `docs/verif/`, `docs/reviews/` and `docs/qa/s16-validate-chain/` are the story's own evidence.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s16-validate-chain` exits 0. With `Verification mode: record`, the unit suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) count as proven for this code, so I did not rerun them. I read "Not proven here" and carried its items to Not verified.
- [x] `po-gate qa-current s16-validate-chain` exits 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). QA finding 1 (major, verified) is carried to Findings, and QA `## Not seen` is carried to Not verified.

## Plan
- [x] Tasks 1 to 8 are present. The fix commit `916a8c2` deals with the findings of fix loop 0:
  - the search budget is replaced by a certification pre-pass plus a step bound;
  - a critical EKU is now enforced (`ExtendedKeyUsage`);
  - four new attack files cover `NotYetValid`, `CaKeyUsage`, `ExtendedKeyUsage` and `MalformedExtension`;
  - `validate` with no anchor short-circuits;
  - the fuzz target now calls `validate_with_anchors`;
  - a PEM anchor gets the named error `TrustAnchorPem`;
  - it also adds a pool cap, `PoolTooLarge`.
- [x] Run interdicts:
  - nothing is changed outside the allowed paths, and no existing corpus file is changed (all are status `A`, the README only gains rows);
  - every README SHA-256 matches its file (checked with `sha256sum`);
  - `validate(pdf)` keeps its signature;
  - no `SystemTime::now` or `Instant::now` in `src/`;
  - no `[workspace.dependencies]`, no `cms` or `x509-tsp` crate, no network code, no `Cargo.lock` committed.

## References
- [x] Opened and confirmed:
  - `VerifiedSigner::certificate` and `SignedData::certificates`, used by `verify` in `validate.rs`;
  - `Document::catalog` and `follow_once` (`validate.rs:255`);
  - x509-cert `get_extension`, `Time::to_system_time` and `CertificateBuilder` in the tests;
  - the reuse sources `nacre-pades/src/archive.rs:152-184` and `nacre-revocation/Cargo.toml`, whose versions are identical.
- [x] Values:
  - `notBefore` and `notAfter` are both inclusive;
  - `pathLenConstraint` is compared with `depth - 1`;
  - an absent leaf `keyUsage` is accepted;
  - `MAX_PATH_LEN = 8`, and the pre-pass loops `1..8` (7 pool levels plus the leaf), which is consistent;
  - Nacre itself writes `/DSS /Certs` streams unfiltered (`nacre-pades/src/dss.rs:101-110`), so the "unfiltered only" reader does not miss Nacre's own B-LT certificates.

## Rules
- [x] The `AGENTS.md` conventions hold:
  - `#![forbid(unsafe_code)]` is present;
  - no panic paths in `src/`;
  - one `thiserror` enum with `kind()`, and both new variants map to `InvalidInput`;
  - the control date is a parameter;
  - versions are declared per crate.
- [x] No accepted ADR is contradicted: the judgement is written by Nacre on x509-cert models (ADR-0001, ADR-0004).

## Tests
- [x] Floor: `po-gate floor-guard s16-validate-chain main` exits 0. Only an awk locale warning was printed, not a flag.
- [x] I found none of the six shapes of test that prove nothing. Fixtures come from the deterministic forge, and there are no mocks.
- [x] The story has 20 new tests (1 unit, 5 chain, 10 attacks, 3 validate, 1 ignored conformance), within the `Test budget` of 25.
- [x] Bite results:
  - Disabling the CA `keyCertSign` check (`chain.rs:436`): 1 test fails (`chain_ca_key_usage_is_rejected`). Undone, `git diff --exit-code` clean.
  - Disabling the critical-EKU purpose check (`chain.rs:417`): 1 test fails (`chain_extended_key_usage_is_rejected`). Undone, clean.
  - Removing the `certified` filter from `Search::walk` (`chain.rs:363`), the rule that replaced the decoy budget: **0 tests fail** across the `chain`, `attacks` and `validate` suites (46, 5 and 18 tests). `search_is_bounded` slows from instant to 13 s but still passes. Undone, clean.

## Neighbours
- [x] Nothing outside `crates/nacre-validate/` uses the crate (checked with `git grep`). The fuzz target and `hostile.rs` call both entry points. `SignatureValidation` and `Defect` are `#[non_exhaustive]`, so the new field and variants break no caller.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml` adds `x509-cert 0.3`, `spki 0.8`, `p256 0.14`, `rsa =0.10.0-rc.19`, plus dev-dependencies).
- Every one is named in plan task 1, and each sits at the version `crates/nacre-revocation/Cargo.toml` already uses, so nothing new enters the workspace and no lockfile moves.
- Security, migration and performance did not trigger: no auth, route, upload or webhook path or content, no migration, no server-side code. The chain's security behaviour is judged under the steps above instead.
- [x] Each lens finding is graded and listed below (none from the dependencies lens).

## Findings
- major — crates/nacre-validate/src/chain.rs:180 — An appended `/DSS` of 255 junk streams turns a valid chain into `CERTIFICATE_CHAIN_GENERAL_FAILURE` (QA finding 1, verified, evidence `docs/qa/s16-validate-chain/finding-1-pool-limit.txt`).
  - `MAX_POOL_LEN` is compared with the raw `pool.len()` before unreadable entries are skipped and duplicates merged. `dss_certificates` (`validate.rs:236-251`) keeps every unfiltered stream without checking that it parses as a certificate. Its reuse source, `nacre-pades/src/archive.rs:178-181`, does check, with `Certificate::from_der`, so the copy has drifted.
  - The effect contradicts the `build_chain` rustdoc ("a certificate no anchor certifies … can hide no path").
  - It fails closed and never becomes a pass.
  - A third party can already strip certificates from the unsigned CMS set or the `/DSS`, so this gives them a cheaper form of a downgrade they already have, not a new one.
  - This is a security matter: under Law 7 it goes to the person, not to the tracker.
- major — crates/nacre-validate/src/chain.rs:363 — The `certified` pre-filter, which fixes fix-loop-0 finding 1, has no test that fails without it.
  - With the filter removed, every test still passes, `look_alikes_do_not_hide_the_issuer` and `search_is_bounded` included:
    - the look-alikes dead-end after one step, because their issuer name is the root's;
    - `search_is_bounded` holds no real intermediate, so `NoPath` is right either way.
  - By reading, without the filter, the 200 self-issued decoys of `search_is_bounded` placed ahead of the real intermediate form a complete graph. That graph uses up `max_steps = (201) * 8` inside the first decoy's subtree, and a valid path then reads `NoPath`.
  - A test with those decoys plus `INTERMEDIATE` at the end of the pool would bite.
- major — crates/nacre-validate/src/chain.rs:196 — Merging pool entries by equal `tbsCertificate` keeps the first copy, even when that copy's signature is broken, and drops the valid one.
  - That copy then fails `signed_by` in `certify`, is never certified, and the real issuer is gone. A twin with corrupted signature bytes, placed ahead of the real intermediate, gives `NoPath`.
  - This contradicts the rustdoc promise that no path can be hidden.
  - I found it by reading, not by running: po-bounds refused the probe clone (see Not verified).
  - In a PDF it gives an attacker nothing new: whoever can place the twin in the unsigned CMS set can also delete the real one.
  - `build_chain` is a public API meant for CAdES, XAdES and JAdES pools that mix sources, which is why I grade it major.
  - It fails closed. Merging only once a copy has verified, or keeping every copy whose TBS matches, would remove it.
- minor — crates/nacre-validate/src/chain.rs:413 — The comment says, under RFC 5280 §4.2.1.12, that "a non-critical [extendedKeyUsage] is advisory".
  - As I recall the RFC, the "advisory" wording comes from RFC 3280. RFC 5280 says "If the extension is present, then the certificate MUST only be used for one of the purposes indicated", with no distinction by criticality.
  - So a signer with a non-critical `serverAuth`-only EKU gets a valid path.
  - This is a deliberate choice, recorded in `docs/security/attacks/cms.md:24`, and may match DSS's default policy. The comment's citation should still be corrected, or the choice confirmed against DSS in s18.
- minor — crates/nacre-validate/examples/forge_chain_attacks.rs:53 — The unknown critical extension uses OID `1.3.6.1.4.1.32473.1`, not one under `2.999` as plan task 5 states.
  - The corpus README documents the choice (the RFC 5612 documentation arc), and the outcome is the same.
  - This was carried from fix loop 0 and is still open.

## Not verified
- **The probe for the merge finding.** po-bounds refused `git clone -q file:///…/s16-validate-chain /tmp/tmp.1IKRf2V1Ni/repo` in reviewer mode ("git clone is forbidden in mode reviewer"), so the merge-by-TBS finding and the "decoys hide the path without the filter" reasoning come from reading.
  - Who covers it: whoever writes the fix-run tests should add both cases to `tests/chain.rs`.
- **Criterion 1 on the real bench.** `bench_chain_is_valid` is `#[ignore = "conformance"]`. The record says it ran once, green, against a host-generated PKI, but there is no `po-run` row; QA reproduced it the same way.
  - Who covers it: the conformance CI job, or `cargo test -p nacre-validate --test conformance -- --ignored` with the bench up.
- **Criterion 1 with `/DSS` as Nacre writes it at B-LT** (QA Not seen). That needs the bench TSA and OCSP responder, which were not started.
- **DSS's verdict on the same chains** (QA Not seen; plan pivot). The sub-indications for the CA flag, path length, key usage and EKU, and `TRY_LATER` for a valid path, were not compared with DSS 6.5.1. That comparison belongs to the s18 campaign.
- **RSA certificate paths** (QA Not seen, record). Every certificate is ECDSA P-256, so no test reaches `verify_rsa` or the RSA branch of `key_kind`.
- **Name matching across encodings** (QA Not seen). Matching is DER byte equality, stricter than RFC 5280 §7.1, and no certificates were forged to test interoperability.
- **The RFC 5280 §4.2.1.12 wording** behind the minor EKU finding comes from my memory of the RFC; I did not check it against the text.
- **The fuzz target.** The record says one hand run (60 s, no crash), with no `po-run` row; I did not run it.
- **`cargo fmt`.** It has no `po-run` row; formatting is left to the commit hook and CI.
- **End to end and build.** The project has no `E2E` command. The diff changes a manifest (`crates/nacre-validate/Cargo.toml`), so with `Build stage: ship-if-route`, `/po-ship` must run `cargo build --workspace --all-features`.

Max severity: major
Ship allowed: yes

---

# Review: s16-validate-chain

[Story](../stories.md) · [Plan](../plans/s16-validate-chain.md) · [Verification](../verif/s16-validate-chain.md)

Diff reviewed: `git diff main...story/s16-validate-chain`, read in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 2
Reviewed tree: 81eaa7e9a00587e72c305c1f3981f28dd440d4fd

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
`git diff --name-only main...story/s16-validate-chain` lists 51 paths. I checked each against `Owns: crates/nacre-validate/, docs/security/attacks/cms.md, docs/security/attacks/pades.md`.
- [x] Every path is inside `Owns`. The paths under `docs/research/`, `docs/plans/`, `docs/verif/`, `docs/reviews/` and `docs/qa/s16-validate-chain/` are the story's own evidence.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s16-validate-chain` exits 0. With `Verification mode: record`, the unit suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) count as proven for this code, so I did not rerun them. I read "Not proven here" and carried its items to Not verified.
- [x] `po-gate qa-current s16-validate-chain` exits 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). The QA report on this code lists no findings. Its `## Not seen` is carried to Not verified.

## Plan
- [x] Tasks 1 to 8 are present.
- [x] Fix commit `f9fb8f3` handles the three majors and the EKU minor from fix loop 1:
  - unreadable and repeated pool entries no longer count toward the cap;
  - a pool past 256 distinct certificates is cut off rather than refused (`PoolTooLarge` removed);
  - copies of one `tbsCertificate` stay separate until one verifies (`certify`, `certified_tbs`);
  - new tests cover the `certified` filter, the broken twin and the junk `/DSS`;
  - EKU is now applied whether or not it is critical. That changes behaviour beyond what the loop-1 minor asked for, but `cms.md` documents it and leaves the DSS comparison to s18.
- [x] Run interdicts:
  - Nothing changed outside the allowed paths.
  - No existing corpus file changed: `README.md` only gains rows, and the one modified corpus file, `chain-extended-key-usage.pdf`, was itself added by this story.
  - All 18 chain SHA-256 rows match their files (`sha256sum -c`).
  - Rerunning `forge_chain_attacks` into a temp dir gives byte-identical files for all 18.
  - `validate(pdf)` keeps its signature.
  - `src/` never reads the clock.
  - There is no `[workspace.dependencies]`, no `cms` or `x509-tsp` crate, no network code, and no committed `Cargo.lock`.

## References
- [x] I opened `nacre_cms::VerifiedSigner::certificate`. `nacre-cms` parses the signer with `Certificate::from_der` (`crates/nacre-cms/src/verify.rs:131`), so `SignerUnreadable` cannot be reached through `validate` and the no-anchor result does not change.
- [x] I opened `SignedData::certificates`, `follow_once`, `Document::catalog`, and in x509-cert `get_extension` and `Time::to_system_time`.
- [x] Values:
  - Both validity bounds are inclusive.
  - `pathLenConstraint` is compared with `depth - 1`.
  - An absent leaf `keyUsage` is accepted.
  - `MAX_PATH_LEN = 8` matches the pre-pass `1..8` levels plus the leaf.
  - The `MAX_POOL_LEN = 256` cap now counts readable, distinct nodes (`chain.rs:184-201`), which matches the rustdoc.

## Rules
- [x] `AGENTS.md` conventions hold:
  - `#![forbid(unsafe_code)]` is present;
  - there are no panic paths in `src/`, and clippy passes;
  - one `thiserror` enum, with `kind()` covering `TrustAnchor` and `TrustAnchorPem`;
  - the control date is a parameter;
  - versions are declared per crate.
- [x] No accepted ADR is contradicted: path judgement is written by Nacre on x509-cert models (ADR-0001, ADR-0004).

## Tests
- [x] Floor: `po-gate floor-guard s16-validate-chain main` exits 0. It printed only an awk locale warning, not a flag.
- [x] None of the six empty test shapes appear. The fixtures come from the deterministic forge (confirmed above), and there are no mocks.
- [x] 23 new tests, within the `Test budget` of 25:
  - 1 unit;
  - 7 in `chain`;
  - 11 in `attacks`;
  - 3 in `validate`;
  - 1 ignored conformance test.
- [x] Bite results. Each mutation was undone, and `git diff --exit-code` came back clean every time.
  - Removing the `certified` filter in `walk` (`chain.rs:366`): 1 failure (`uncertified_graph_does_not_hide_the_issuer`). The loop-1 gap is closed.
  - Counting raw pool entries toward the cap (`chain.rs:184-185`): 1 failure (`pool_is_capped`). `chain_dss_junk_does_not_hide_the_chain` still passes, because the intermediate sits in the CMS ahead of the `/DSS` junk.
  - Merging pool copies by `tbsCertificate` again (`chain.rs:197`): 1 failure (`broken_twin_does_not_hide_the_issuer`).
  - Disabling `pathLenConstraint` (`chain.rs:445`): 1 failure (`chain_path_length_is_rejected`).
  - Restricting the EKU rule to the leaf (`chain.rs:419`): **0 failures** across `attacks`, `chain` and `validate` (47, 7 and 18 tests). See Findings.

## Neighbours
- [x] Nothing outside `crates/nacre-validate/` uses the crate (`git grep`).
- [x] The fuzz target and `hostile.rs` call both entry points.
- [x] `SignatureValidation` and `Defect` are `#[non_exhaustive]`, so the new field and variants break no caller.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml` adds `x509-cert 0.3`, `spki 0.8`, `p256 0.14` and `rsa =0.10.0-rc.19`, plus dev-dependencies).
- All of them are named in plan task 1, at the versions `crates/nacre-revocation/Cargo.toml` already uses. No lockfile is committed.
- Security, migration and performance were not triggered: no auth, route, upload or webhook path or content, no migration, and no server-side code.
- [x] Each lens finding is graded and listed below. The dependencies lens found none.

## Findings
- major — crates/nacre-validate/src/chain.rs:418 — No test covers the `extendedKeyUsage` rule on issuing certificates (depth ≥ 1).
  - Restricting the check to `depth == 0` makes no test fail.
  - `chain_extended_key_usage_is_rejected` only covers the leaf.
  - QA saw a CA with a `serverAuth` EKU give `ExtendedKeyUsage{1}` by hand, but nothing would catch a regression.
  - Checking EKU on CAs is a policy choice: RFC 5280 does not require it, and plan task 3 does not name it. `docs/security/attacks/cms.md:21` states it for "chaque certificat", so it is a documented rule with no test.
  - It fails closed, so the defect is contained.
  - A corpus case with an intermediate carrying a `serverAuth`-only EKU would close the gap. Otherwise, take the rule out and limit EKU to the leaf.
- minor — crates/nacre-validate/examples/forge_chain_attacks.rs:53 — The unknown critical extension uses OID `1.3.6.1.4.1.32473.1`, not one under `2.999` as plan task 5 states.
  - The corpus README documents the choice (the RFC 5612 documentation arc), and the outcome is the same.
  - Carried from fix loops 0 and 1, and still open.
- minor — docs/security/attacks/cms.md:49 — Two small formatting slips:
  - the paragraph "Les sous-indications de DSS 6.5.1…" starts with a stray leading space;
  - the diff adds an empty line inside the "Hors de ce fichier" list after the "Chaîne contournée" item (line 53), which turns it into a loose list.

## Not verified
- **Criterion 1 on the real bench.** `bench_chain_is_valid` is `#[ignore = "conformance"]`. The record says it ran once, green, against a PKI generated on the host, with no `po-run` row. QA reproduced it the same way.
  - To cover it: the conformance CI job, or `cargo test -p nacre-validate --test conformance -- --ignored` with the bench up.
- **Criterion 1 with `/DSS` as Nacre writes it at B-LT** (QA Not seen). That needs the bench TSA and OCSP responder, which were not started. Only an appended `/DSS` revision and `chain-dss.pdf` were checked.
- **DSS's verdict on the same chains** (QA Not seen; plan pivot). Not compared with DSS 6.5.1:
  - the sub-indications for the CA flag, path length, key usage and EKU;
  - enforcing a non-critical EKU and EKU on CAs, which DSS's default policy may not do;
  - `TRY_LATER` for a valid path.

  The s18 campaign has to compare them. The EKU change in `f9fb8f3` widens the possible gap, for example for real qualified certificates whose EKU names only `clientAuth`.
- **The `SIGNING_PURPOSES` list** (`chain.rs:53-59`) has not been checked against Adobe's or DSS's accepted EKU values.
- **RSA certificate paths** (QA Not seen, record). Every corpus and bench key is P-256, so no test reaches `verify_rsa` or the RSA branch of `key_kind`.
- **Name matching across encodings** (QA Not seen). Names are matched by DER byte equality, stricter than RFC 5280 §7.1, and no such certificates were forged.
- **The fuzz target.** The record says one hand run (60 s, no crash), with no `po-run` row. I did not run it.
- **`cargo fmt`.** It has no `po-run` row; formatting is left to the commit hook and CI.
- **End to end and build.** The project has no `E2E` command. The diff touches a manifest (`crates/nacre-validate/Cargo.toml`), so with `Build stage: ship-if-route`, `/po-ship` must run `cargo build --workspace --all-features`.

Max severity: major
Ship allowed: yes

---

# Review — s16-validate-chain

[Story](../stories.md) · [Plan](../plans/s16-validate-chain.md) · [Verification](../verif/s16-validate-chain.md)

Diff reviewed: `git diff main...story/s16-validate-chain`, read in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 3
Reviewed tree: cee5f2467cc3739667013a4153275c20a9288605

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
`git diff --name-only main...story/s16-validate-chain` lists 51 paths. Each was checked against `Owns: crates/nacre-validate/, docs/security/attacks/cms.md, docs/security/attacks/pades.md`.
- [x] Every path is inside `Owns`. The paths under `docs/research/`, `docs/plans/`, `docs/verif/`, `docs/reviews/` and `docs/qa/s16-validate-chain/` are the story's own evidence.
- [x] Outside `Owns`: none.
- [x] Inside another running story's `Owns`: none. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s16-validate-chain` exits 0, so the record is reused. With `Verification mode: record`, the unit suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) count as proven for this code (runs at 16:10:59Z and 16:11:06Z, exit 0). I did not rerun them. I read "Not proven here" and carried its items to Not verified.
- [x] `po-gate qa-current s16-validate-chain` exits 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). The QA report on tree `9b22467f…` lists no findings. Its walk replayed every earlier scenario and added nine EKU scenarios for `7ece192`. Its `## Not seen` is carried to Not verified.

## Plan
- [x] Tasks 1 to 8 are present. This loop reviews fix commit `7ece192` against the loop-2 findings:
  - Loop-2 major (EKU on issuing certificates untested): handled by removing the rule. EKU is now judged on the signer only (`chain.rs:418-426`). The issuer's EKU is still decoded.
  - `id-kp-clientAuth` is added to `SIGNING_PURPOSES` (`chain.rs:53-61`). The loop-2 review did not ask for this. The commit and the record say it follows "the person's decision of 2026-10-23". See Findings and Not verified.
  - Loop-2 minor about the `cms.md` formatting: fixed. The stray space and the loose-list blank line are gone.
  - Loop-2 minor about the OID: still open (see Findings).
- [x] Run interdicts:
  - Nothing changed outside the allowed paths.
  - No corpus file changed in this loop.
  - `src/` does not read the clock.
  - There is no `[workspace.dependencies]`, no `cms` or `x509-tsp` crate, no network code, and no committed `Cargo.lock`.

## References
- [x] I opened every name `7ece192` uses: `ExtendedKeyUsage` (x509-cert `ext::pkix`), `ObjectIdentifier::new_unwrap`, `BuilderProfile` and `ToExtension` in `tests/chain.rs`, and `build_chain` / `TrustAnchors`. The test's `INTERMEDIATE_NAME`, `INTERMEDIATE_SECRET` and `ATTACKER_SECRET` already exist in the same file.
- [x] Values: `1.3.6.1.5.5.7.3.2` is `id-kp-clientAuth` (RFC 5280 §4.2.1.12). The array length (6) matches its entries. `ChainDefect::ExtendedKeyUsage` still maps to `CHAIN_CONSTRAINTS_FAILURE` (`chain.rs:139`).

## Rules
- [x] The `AGENTS.md` conventions hold:
  - `#![forbid(unsafe_code)]` is present;
  - there are no panic paths in `src/`;
  - there is one `thiserror` enum, with `kind()` covering its variants;
  - the control date is a parameter.
- [x] No accepted ADR is contradicted. The path judgement is still written by Nacre on x509-cert models (ADR-0001, ADR-0004).

## Tests
- [x] Floor: `po-gate floor-guard s16-validate-chain main` exits 0. It printed only an awk locale warning, not a flag.
- [x] None of the six empty test shapes appear. `client_auth_signer_is_accepted` builds a real certificate signed by the corpus intermediate's key and calls the public `build_chain`. It uses no mock.
- [x] 24 new tests, within the `Test budget` of 25 (loop 2 counted 23, and this loop adds 1).
- [x] Bite. Each mutation was undone, and `git diff --exit-code crates/nacre-validate/src/chain.rs` came back clean each time.
  - Removing `id-kp-clientAuth` from `SIGNING_PURPOSES`: 1 failure (`client_auth_signer_is_accepted`). `attacks` had 47 tests pass; `chain` had 7 pass and 1 fail.
  - Disabling the signer EKU check (the condition can never be true): 1 failure (`chain_extended_key_usage_is_rejected` in `attacks`; cargo stopped after that binary).
- [x] No test is made useless by the story.

## Neighbours
- [x] Nothing outside `crates/nacre-validate/` uses the crate. `validate_with_anchors`, the fuzz target and `hostile.rs` reach `judge` through `build_chain`. Nothing else reads `SIGNING_PURPOSES`. The meaning of the public `ExtendedKeyUsage { depth }` variant narrowed (depth is always 0 now). It is `#[non_exhaustive]` and keeps its shape, so no caller breaks.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml` adds `x509-cert 0.3`, `spki 0.8`, `p256 0.14`, `rsa =0.10.0-rc.19` and dev-dependencies; this loop leaves them unchanged). All of them are named in plan task 1, at the versions `nacre-revocation` already uses, and no lockfile is committed. Security, migration and performance were not triggered: there is no auth, route, upload or webhook path or content, no migration, and no server-side code.
- [x] Each lens finding is graded and listed below. The dependencies lens found none.

## Findings
- minor — docs/plans/s16-validate-chain.md:42 — The plan does not record the EKU policy as it ships.
  - Task 3 names no `extendedKeyUsage` rule at all. Accepting `id-kp-clientAuth` loosens what a signer may be.
  - The "person's decision of 2026-10-23" behind it is cited only in the commit message of `7ece192` and in the record's Not proven here. No file a later stage reads holds it: not the plan, not `docs/decisions-log.md`.
  - `docs/security/attacks/cms.md:24` documents the resulting rule, so the behaviour is traced. Its origin is not.
  - Fix: add the rule and the decision to plan task 3, or to the decisions log.
- minor — crates/nacre-validate/src/chain.rs:417 — Decoding the issuer's `extendedKeyUsage` is tested by nothing.
  - Removing the issuer-side `get_extension::<ExtendedKeyUsage>()` call would let a doubled or undecodable EKU on a CA through, and no test would fail.
  - The record says so, and QA saw `MalformedExtension{1}` by hand.
  - It fails closed today, so the impact is small.
- minor — crates/nacre-validate/examples/forge_chain_attacks.rs:53 — The unknown critical extension uses OID `1.3.6.1.4.1.32473.1`, not one under `2.999` as plan task 5 states.
  - The comment and the corpus README document the choice (the RFC 5612 documentation arc), and the outcome is the same.
  - Carried from fix loops 0 to 2, and still open.

## Not verified
- **The person's EKU decision itself.** I found no written record of it in the worktree. I trusted the commit message and the record, which cite it. A person should confirm that accepting `id-kp-clientAuth` alone on a signer, and no longer judging the issuer's EKU, is what they decided.
- **Criterion 1 on the real bench.** `bench_chain_is_valid` is `#[ignore = "conformance"]`. The record says it ran once, green, against a PKI generated on the host, with no `po-run` row. QA reproduced it the same way.
  - To cover it: the conformance CI job, or `cargo test -p nacre-validate --test conformance -- --ignored` with the bench up.
- **Criterion 1 with `/DSS` as Nacre writes it at B-LT** (QA Not seen). That needs the bench TSA and OCSP responder, which were not started. Only an appended `/DSS` revision and `chain-dss.pdf` were checked.
- **DSS's verdict on the same chains, including the EKU rule of `7ece192`** (QA Not seen; plan pivot). Not compared with DSS 6.5.1:
  - the sub-indications for the CA flag, path length, key usage and EKU;
  - `clientAuth` signers;
  - EKU on issuing certificates no longer being judged;
  - `TRY_LATER` for a valid path.

  The s18 campaign must compare them.
- **The `SIGNING_PURPOSES` list** (`chain.rs:53-61`) was not checked against Adobe's or DSS's accepted EKU values.
- **RSA certificate paths** (QA Not seen, record). Every corpus and bench key is P-256, so no test reaches `verify_rsa` or the RSA branch of `key_kind`.
- **Name matching across encodings** (QA Not seen). Names are matched by DER byte equality, which is stricter than RFC 5280 §7.1, and no such certificates were forged.
- **The fuzz target.** The record says one hand run (60 s, no crash) before this loop, with no `po-run` row. I did not run it.
- **`cargo fmt`.** It has no `po-run` row; formatting is left to the commit hook and CI.
- **End to end and build.** The project has no `E2E` command. The diff touches a manifest (`crates/nacre-validate/Cargo.toml`), so with `Build stage: ship-if-route`, `/po-ship` must run `cargo build --workspace --all-features`.

Max severity: minor
Ship allowed: yes
