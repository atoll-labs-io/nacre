# Review — s17-validate-revocation

[Story](../stories.md) · [Plan](../plans/s17-validate-revocation.md) · [Verification](../verif/s17-validate-revocation.md)

Diff reviewed: `git diff main...story/s17-validate-revocation`, in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: b496946ed99dbf975f88d91410c7b342f6b2a5ee

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s17-validate-revocation` and held each path against `Owns: crates/nacre-validate/`.
- [x] Every path is inside `Owns`. The 12 code paths are under `crates/nacre-validate/`. The rest is the story's own evidence: `docs/research/`, `docs/plans/`, `docs/verif/` and `docs/qa/s17-validate-revocation/`.
- [x] No path is outside `Owns`.
- [x] No path is in another running story's `Owns`. `git worktree list` shows only main and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s17-validate-revocation` exits 0. With `Verification mode: record`, I relied on the record's runs instead of repeating them: `cargo test --workspace` (exit 0) and `cargo clippy --workspace --all-targets --all-features -- -D warnings` (exit 0), on code equal to `Tree: a9d8bad…` outside `docs/`. I read its "Not proven here" section and carried it to `## Not verified`.
- [x] `po-gate qa-current s17-validate-revocation` exits 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). The QA report lists no verified findings, so none are carried over. Its `## Not seen` items are under `## Not verified`.

## Plan
- [x] Tasks 1–8 are all present in the diff, and nothing lies outside the plan.
- [x] Run interdicts, checked one by one:
  - The diff is empty outside the allowed paths.
  - The public signatures of `build_chain` (`chain.rs:180`) and `validate_with_anchors` are unchanged.
  - `src/` has no `SystemTime::now`, `Instant`, clock read or network use. The source is reached only through `RevocationSource`.
  - Nothing in `src/` returns `TOTAL_FAILED` / `REVOKED`.
  - The root `Cargo.toml` is untouched, there is no `[workspace.dependencies]`, and no `Cargo.lock` is tracked.
  - No corpus file was added, and no bench key is committed: `bench_key` reads `conformance/pki/out` at run time.
  - Document timestamps stay skipped, and no level is given.

## References
- [x] I opened and confirmed every reference the diff makes:
  - `Crl::{from_der,this_update,status}` (`nacre-revocation/src/crl.rs`) and `OcspResponse::{status,produced_at}` (`ocsp/response.rs:141`).
  - `nacre_tsp::verify_token`, `VerifiedToken::{tsa_certificate,gen_time}` (`nacre-tsp/src/token.rs:40-71`).
  - `SignedData::{certificates,crls}`, `SignerInfo::{signature,unsigned_attrs}`, `Attribute::{oid,values}` (`nacre-cms/src/model.rs:77-78,203-204,289-291`) and `VerifiedSigner::signer_info` (`verify.rs:29`).
  - `CertificatePath.certificates`: leaf first, anchor last (`chain.rs:104-110`). So `windows(2)` judges every certificate below the anchor, with the right issuer.
  - `nacre-tsp` and `nacre-revocation` have `default = []`, so `http` is off in the library build.
- [x] Values: the attribute OID `1.2.840.113549.1.9.16.2.14` and the `timeStamping` OID `1.3.6.1.5.5.7.3.8` are correct. The caps of 256 items and 16 tokens follow the plan. "At or before the BST" is confirmed by the QA's 08:00 / 08:00:01 boundary run. The sub-indications follow the research's spike (DSS 6.5.1).

## Rules
- [ ] `AGENTS.md` conventions: one gap on conformance level assertions, and the attack catalogue was not updated (see Findings).
- [x] No accepted ADR is contradicted. The dependencies are RustCrypto plus in-repo crates, and nothing comes from `cms` or `x509-tsp`.

## Tests
- [x] Floor: `po-gate floor-guard s17-validate-revocation main` exits 0, so nothing was lowered.
- [x] The assertions pin down AC1–AC4 on PDFs built at test time. I found none of the six empty test shapes: the stub sources answer real CRLs, and no `catch` swallows an error.
- [x] 19 new tests (R1–R12, U1, C1–C6, with C0 reworked), within `Test budget: 25`.
- [x] Bite proofs:
  - `judge_path`, "latest wins", changed to first-wins: **0** of 12 tests in `tests/revocation.rs` fail. Undone, `git diff --exit-code` clean.
  - Same rule, changed to last-wins: 1 fails (`latest_crl_wins`). Undone, clean.
  - `judge_path`, `date <= time` made always true: 1 fails (`revoked_after_the_timestamp_passes`). Undone, clean.
  - `proven_time`, the TSA's `judge_path` removed: 1 fails (`revoked_tsa_gives_no_poe`). Undone, clean.
- [x] Three tests that assumed `TRY_LATER` were updated (task 6). None became useless.

## Neighbours
- [x] I read the other callers: `fuzz/fuzz_targets/validate.rs:21`, `tests/hostile.rs:35`, `tests/attacks.rs:318`, `tests/validate.rs:359` and `tests/chain.rs`. All still compile and run through the recorded suite. The stale prose in `docs/security/attacks/` is listed under Findings.

## Lenses
Lenses run: dependencies — `crates/nacre-validate/Cargo.toml`, whose dependency list changed (`nacre-tsp` and `nacre-revocation` added, dev-deps get `http`).
- [x] Both added crates are in-repo path crates that the plan names, with no lockfile and no new third-party crate. Nothing to grade.

## Findings
- major — crates/nacre-validate/src/revocation.rs:198-202 — The rule "the latest revocation item decides" is only half tested.
    - Making the code take the first usable item fails no test. R10 (`tests/revocation.rs:392`) lists the newer CRL before the older one, so first-wins and latest-wins give the same answer.
    - The direction that goes unprotected is the dangerous one. A `/DSS` that lists an old "not revoked" CRL before a newer one listing the signer would pass under first-wins.
    - The plan claims R10 holds "whatever the array order". Add the reverse order ([older, newer] → `REVOKED_NO_POE`) to R10.
- major — crates/nacre-validate/src/revocation.rs:56-66, validate.rs:270-275 (security, for the person) — Offline, revocation data the attacker chooses is enough to pass a revoked key.
    - Each item is judged at its own date, freshness is ignored, and data issued before signing is accepted (spike c19–c22, R9).
    - So when no source is given, a B-B signature made with a key revoked before the control date ends `TOTAL_PASSED` if the unsigned `/DSS` carries a genuine CRL from before the revocation. `/DSS` is appended data: anyone holding the compromised key can choose it.
    - This is a deliberate choice, for DSS parity under AC5 (plan, "The pivot"). It is documented as "freshness aside" (`validate.rs` docs).
    - The person should confirm whether `validate_with_anchors` (no source) may give `TOTAL_PASSED` on a B-B signature under that condition, or whether this needs an ADR or a policy knob. It is a security matter (ADR-0077/0090): to bring to the person, not to file on its own.
- minor — crates/nacre-validate/tests/conformance.rs:55-80 — `confront` asserts only the indication and sub-indication from DSS, never the level DSS reports. This misses the convention "A conformance test asserts the exact level DSS reports, never the indication alone" (brief premise 4). Nacre's level is s18's job by plan, but DSS's level (`theirs.level()`) is already readable and could be pinned now.
- minor — docs/security/attacks/cms.md:24,40 and docs/security/attacks/pades.md:79 — These docs still say a valid chain ends `INDETERMINATE` / `TRY_LATER`, and the revocation attacks (forged-key CRL R8, pre-`notBefore` CRL R11, junk `/DSS`) have no entry in the catalogue the conventions require. This is outside `Owns` and the plan forbade touching it, so it is a gap in the story's scope rather than an implementer breach. It needs a follow-up story or a quick change.
- minor — crates/nacre-validate/src/validate.rs:224-235 — The shared `/DSS` CRLs and OCSPs are cloned, parsed and verified again for each signature, because the pool is built per signature (up to `MAX_SIGNATURES` 64). This is a potential impact only, and it is bounded, since the name check comes before the signature check.
- minor — crates/nacre-validate/src/validate.rs:291 — Tokens are verified with SHA-256 only. A foreign B-T signature whose token uses another imprint algorithm (s19's corpus) silently loses its POE. That fails closed, but would differ from DSS, and it is undocumented in the function docs.

## Not verified
- AC5, C0–C6 against DSS 6.5.1: the bench was not started in this review. The record says all 7 were green once, outside `po-run`. A person, or the conformance CI job, should run `cargo test -p nacre-validate --all-features --test conformance -- --ignored --test-threads 1` with the bench up.
- From the QA report's `## Not seen`:
  - AC5 was not reached, because the DSS bench was not started.
  - AC3 was not checked on files from the bench's real HTTP TSA and revocation sources (C4); the QA used stub sources only.
  - OCSP responses as revocation data: every offline scenario used CRLs, and the forge has no OCSP helper. OCSP is reached only by C0, C2, C3 and C4.
  - Real-network behaviour.
- From the record's "Not proven here":
  - The OCSP date DSS picks (`producedAt` versus `thisUpdate`) after the bench's five-minute `nextUpdate`.
  - RSA keys, a CRL without `nextUpdate`, `certificateHold` / `removeFromCRL`, and CRLs carried in the CMS `crls`.
  - The 256-item cap, the drop of duplicates and unreadable items, and the pool order.
  - The fuzz target, which was not run.
  - Formatting, which is not recorded.
- I did not mutate the `genTime <= at` guard (`validate.rs:313`) or the `Purpose::Timestamping` EKU rule. The second overlaps with `verify_token`'s own EKU check, so a mutation would likely fail nothing. The QA covered both by scenario.
- I did not read the EN 319 102-1 text, as the research also notes. Nacre's following DSS rests on the research's spike, which I could not replay.

Max severity: major
Ship allowed: yes

---

# Review — s17-validate-revocation

[Story](../stories.md) · [Plan](../plans/s17-validate-revocation.md) · [Verification](../verif/s17-validate-revocation.md)

Diff reviewed: `git diff main...story/s17-validate-revocation`, read in a context that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: 5f23b2a79cb357ebae5790d1269df53c8ac57617

## When blocked
- Failure cause: —
- Missing: —
- Required adaptation: —
- Next action: —

## Ownership
I listed the diff with `git diff --name-only main...story/s17-validate-revocation` and checked each path against `Owns: crates/nacre-validate/`.
- [x] Every path is inside `Owns`. The 12 code paths are under `crates/nacre-validate/`. The other paths are the story's own evidence: `docs/research/`, `docs/plans/`, `docs/verif/`, `docs/reviews/` and `docs/qa/s17-validate-revocation/`.
- [x] No path is outside `Owns`.
- [x] No path is in another running story's `Owns`. `git worktree list` shows only `main` and this worktree.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s17-validate-revocation` exits 0. The record's `Tree:` is `10ccc0be…`. Its last runs passed on the code of fix run 1: `cargo test --workspace` exited 0, and `cargo clippy --workspace --all-targets --all-features -- -D warnings` exited 0. `Verification mode: record` applies, so I did not repeat them. I read "Not proven here" and carried it to `## Not verified`.
- [x] `po-gate qa-current s17-validate-revocation` exits 0. The QA report is the second walk, after 6ecbc40, and it is committed (b1a203c). It has one verified finding, and I carry it below as finding 3. Its `## Not seen` items are under `## Not verified`.
- The project has no `E2E` command (`—`), so there was nothing to run.

## Plan
- [x] Tasks 1 to 8 are as the fix-loop-0 review found them.
- [x] Fix-run tasks 9 to 12 are all in 6ecbc40:
  - R10 now runs in both array orders.
  - `FRESHNESS_TOLERANCE` is added with R13.
  - `confront` asserts the PAdES level DSS reports.
  - The SHA-256-only imprint is documented.
- [x] The fix run changed nothing outside the plan.
- [x] The run interdicts still hold:
  - No clock or network read in `src/`.
  - The root `Cargo.toml` is untouched.
  - No `Cargo.lock`.
  - No corpus file.
  - The public signatures of `validate_with_anchors` and `build_chain` are unchanged. `judge_path` is `pub(crate)`, and its two callers pass the new argument.

## References
- [x] I opened `SignatureLevel`, `SignatureForm::PAdES`, `SignatureProfile::{BaselineB,BaselineT,BaselineLt,BaselineLta}` and `ValidationReport::level() -> Option<SignatureLevel>` in `crates/nacre-core/src/report.rs:94-175`. They exist as `conformance.rs` uses them.
- [x] `Duration::from_secs` and `SystemTime::checked_sub` are std. At a control date less than 24 h after the epoch, the code falls back to `self.at` and fails closed. The QA confirmed this with `UNIX_EPOCH`.
- [x] The value `FRESHNESS_TOLERANCE = 24 h` comes from the plan's "Deliberate divergence from DSS". The QA confirmed the boundary: exactly 24 h counts, 24 h + 1 s does not.

## Rules
- [ ] One `AGENTS.md` convention gap from fix loop 0 is still open: the attack catalogue (finding 4).
- [x] The conformance level convention ("A conformance test asserts the exact level DSS reports") is now met in `confront`.
- [x] No accepted ADR is contradicted.

## Tests
- [x] Floor: `po-gate floor-guard s17-validate-revocation main` exits 0.
- [x] Six empty test shapes: none.
  - R13 builds a real 25 h-old CRL signed by the intermediate.
  - The second half of R13 shows that the same `/DSS` passes once a timestamp gives a POE. A filter applied unconditionally would fail it.
- [x] Count: 20 new tests, within `Test budget: 25`.
- [x] Bite proofs. Each time I ran only `cargo test -p nacre-validate --test revocation` (13 tests), undid the change, and confirmed it was undone with `git diff --exit-code`:
  - `validate.rs`: `issued_from` replaced by `None` at the signer's `judge_path` call (freshness disabled). **1** failed (`old_crl_does_not_pass_a_signature_without_poe`). Clean.
  - `revocation.rs:215`: latest-wins replaced by first-wins (`|best, _next| best`). **1** failed (`latest_crl_wins`). In fix loop 0 this mutation failed 0, so major 1 of that review is closed. Clean.
  - `revocation.rs:205`: `from.max(not_before)` changed to `from.min(not_before)`. **1** failed (R13). Clean.

## Neighbours
- [x] `judge_path` has two callers: the signer's path in `validate.rs:269` and the TSA's in `validate.rs:311`, which passes `None`. I read both; see finding 1.
- [x] Fuzz, `hostile.rs`, `attacks.rs` and `chain.rs` reach the change through `validate_with_anchors`. The recorded suite covers them.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml`, whose dependency list changed: the in-repo crates `nacre-tsp` and `nacre-revocation`); security, by content (a signature-validation rule on attacker-appended `/DSS` data).
- Dependencies: only in-repo path crates are added, and the plan names them. Nothing to grade.
- Security: see finding 1.

## Findings
- major — crates/nacre-validate/src/validate.rs:311 (security, for the person) — The new freshness rule protects the signer's path but not the TSA's path, and the TSA's path is judged with no proof of existence either.
    - `proven_time` judges the TSA's revocation at the control date with `issued_from = None`. So an old "not revoked" CRL for the TSA, appended to `/DSS`, still passes a TSA key revoked since.
    - This is the attack fix run 1 closed for B-B signers (R13), one level up. Someone holding a compromised TSA key can backdate a token. Combined with a compromised signer key, both revoked, an offline `validate_with_anchors` still gives `TOTAL_PASSED`, because the forged token sets the best-signature-time before the signer's revocation.
    - It is contained: two key compromises are needed. The plan states the choice ("the TSA path judged at the control date keep DSS's rule").
    - I cannot see that the person's 2026-10-23 decision covered the TSA case (see `## Not verified`). Bring it to the person, under ADR-0077/0090, rather than filing it.
    - Possible fix: pass `self.at - FRESHNESS_TOLERANCE` to the TSA's `judge_path`, and add a test with a stale clean TSA CRL.
- minor — crates/nacre-validate/src/revocation.rs:212-216 — The freshness filter also drops stale data that proves a revocation, not only stale "not revoked" data.
    - Revocation is permanent, apart from `certificateHold`, so a 30 h-old CRL listing the signer as revoked is still evidence of the revocation.
    - Today such a signature gives `CERTIFICATE_CHAIN_GENERAL_FAILURE` (`Missing`), not the `REVOKED_NO_POE` that AC2 states. The result still fails closed (`INDETERMINATE`).
    - The plan's "Cost" line names only CAs that publish less than daily, not this change of sub-indication. Restricting the filter to items with `revoked: None` would keep AC2's sub-indication. This is the same defect as finding 3, seen from the code.
- minor — crates/nacre-validate/tests/revocation.rs:457-480 — R13 is the only proof of the freshness rule. Several cases have no test: an old OCSP `producedAt`, an old answer from a `RevocationSource`, the exact 24 h boundary, and a freshness window that ends before `notBefore` (the `max`). The record says so itself. The QA covered the boundary and the source case by scenario.
- minor — docs/qa/s17-validate-revocation/report.md, finding 1 (verified, carried from QA) — Data older than 24 h that lists the signer as revoked gives `INDETERMINATE` / `CERTIFICATE_CHAIN_GENERAL_FAILURE` instead of `REVOKED_NO_POE`. The evidence is `ac2.txt`, `ac2-fresh.txt`, `ac4.txt` and `ac4-near.txt`. It is graded minor because it fails closed and follows from a divergence the plan records. s18 has to list it.
- minor — docs/security/attacks/cms.md:24,40 and docs/security/attacks/pades.md:79 (still open from fix loop 0) — These files still say that a valid chain ends `INDETERMINATE` / `TRY_LATER` "until s17", and the catalogue has no entry for the revocation attacks. Those attacks are: the forged-key CRL (R8), the CRL issued before `notBefore` (R11), junk `/DSS`, and now the stale `/DSS` CRL (R13). The files are outside `Owns`, so this is a gap in the story's scope rather than a fault of the implementer. It needs a follow-up story.
- minor — crates/nacre-validate/src/validate.rs:224-243 (still open from fix loop 0, performance, potential impact) — The `/DSS` revocation pool is rebuilt and re-verified for each signature. It is bounded by `MAX_SIGNATURES` and `MAX_POOL_LEN`.
- minor — crates/nacre-validate/tests/conformance.rs:8-9 — The module docs still say that Nacre and DSS "must agree on the indication and the sub-indication". `confront` now also pins the level DSS reports.

## Not verified
- I could not confirm the person's decision. The plan says the freshness divergence was "decided by the person on 2026-10-23". `docs/decisions-log.md` on `main` (7eaee8f) has no such line, and I saw no other record of it. The lead should confirm the decision is real, log it, and ask whether it covers the TSA path (finding 1).
- AC5, C0 to C6 against DSS 6.5.1, including the new level assertions: I did not start the bench. The record says fix run 1 ran all 7 green, outside `po-run`. A person or the conformance CI job should run `cargo test -p nacre-validate --all-features --test conformance -- --ignored --test-threads 1` with the bench up.
- From the QA report's `## Not seen`:
  - AC5 was not reached, because the bench was not started.
  - AC3 was not checked on files from the bench's real HTTP sources (C4).
  - OCSP was not used as revocation data, so the 24 h window on `producedAt` was not seen. The forge has no OCSP helper.
  - Real-network behaviour was not seen.
- From the record's "Not proven here":
  - The freshness rule on OCSP, on a source answer and at the 24 h boundary (tested by scenario only).
  - The OCSP date DSS picks after the bench's five-minute `nextUpdate`.
  - RSA keys, a CRL without `nextUpdate`, `certificateHold` / `removeFromCRL`, and CRLs carried in the CMS `crls`.
  - The 256-item cap, the drop of duplicates and unreadable items, and the pool order.
  - The fuzz target, which was not run.
  - Formatting, which is not recorded.
- I did not mutate the `genTime <= at` guard or the `Purpose::Timestamping` EKU rule. The fix did not touch them, and the QA covered both by scenario.
- I did not read the EN 319 102-1 text. Nacre's following DSS rests on the research's spike.

Max severity: major
Ship allowed: yes
