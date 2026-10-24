# Review: s18-validate-level

[Story](../stories.md) · [Plan](../plans/s18-validate-level.md) · [Verification](../verif/s18-validate-level.md)

Diff reviewed: `git diff main...story/s18-validate-level`, by a reviewer that did not write it. Findings are rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: f7000cb089d53adc7e80a3b45210cd7a1da625ab

## Ownership
I listed the diff with `git diff --name-only main...story/s18-validate-level` and checked each path against `Owns`: `crates/nacre-validate/`, `crates/nacre-pdf/`, `crates/nacre-revocation/`, `conformance/campaign/`, `docs/security/attacks/`, `docs/decisions/0030-…`.
- [x] Every path is inside `Owns`. Code: `crates/nacre-validate/**`, `crates/nacre-revocation/{src/ocsp/response.rs,tests/ocsp_status.rs}`, `conformance/campaign/**`, `docs/security/attacks/revocation.md`, ADR-0030 (frontmatter only). Covered by construction: the pipeline evidence (research, plan, verif, qa) and the two added ADRs, 0025 and 0031. Both have status `A` and the plan names both.
- [x] Nothing falls inside another running story's `Owns`. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s18-validate-level` exit 0, record reused (`Verification mode: record`). It proves `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` on this code. I read its "Not proven here": the campaign is not a `po-run` row, and the post-campaign mechanical edits were not rerun by the implementer.
- [x] `po-gate qa-current s18-validate-level` exit 0 (story goes to QA: `QA stage: surfaces`, `Surface: endpoint`). The QA tree is current, so QA's rerun of the campaign ("257 cases, 0 differ"; "94 explained, 0 unexplained") ran on this code. Its three verified findings are carried below.

## Plan
- [x] Tasks 1–9 are present: forge helpers, `src/level.rs` (form, B, BES, T, LT, LTA), document timestamp as proof of existence, `OnHold` → `TRY_LATER`, the two switches, `status_ignoring_critical_extensions`, `SWITCHES` at 14, docs and ADRs, the campaign with `run.sh`, README and reports.
  - Two small departures, listed under Findings: the LT pool ignores the policy, and the explanation search goes up to triples.
- [x] Run interdicts, one by one:
  - Diff confined to the listed paths: yes. `crates/nacre-pdf/`, `nacre-core`, `nacre-conformance`, `nacre-pades`, workflows, `conformance/pki/`, `compose.yaml` and `docs/stories.md` are untouched.
  - Bodies of ADR-0026 to 0030 untouched: yes. ADR-0030 changes only `superseded-by: [0031]`.
  - Only R1 and C1 implemented: yes.
  - `OcspResponse::status` unchanged in behaviour: yes. It now calls `judge(..., true)`, and `critical(...)` runs only under `refuse_critical`.
  - `strict()` loosened only by AC3 and the hold rule: yes, as read in the diff.
  - `ChainDefect::report` and `RevocationDefect::report` keep level `None`: yes. The level is set after, by `with_level`.
  - No case excluded from the campaign, no difference allowed under `dss()`: yes, both asserted.
  - No `[workspace.dependencies]`, no `Cargo.lock`, no `cms` or `x509-tsp` crate: yes. `serde_json` is dev-only.
  - Bench down, no public endpoints: per the record and QA.

## References
- [x] Opened and confirmed:
  - `Node`, `signed_by`, `names`, `is_self_signed` and `MAX_PATH_LEN`/`MAX_POOL_LEN`, now `pub(crate)` in `chain.rs`;
  - `Dss` (`Clone`/`PartialEq`, `extend`), `follow_once`, `der_prefix`, `byte_range`, `is_document_timestamp`, `SIGNATURE_TIME_STAMP_TOKEN` and `MAX_TIMESTAMPS` in `validate.rs`;
  - `revisions::MAX_REVISIONS`;
  - `RevocationPool::from_der(_, refuse_critical)`, whose single caller is `validate.rs:366`;
  - `signed_bytes(..., sub_filters)` callers at `:492` and `:598`;
  - `judge_path` callers at `:406` and `:542`. The TSA path uses `.ok()?`, so an `OnHold` gives no proof of time, which is correct.
  - `RevocationDefect` is `#[non_exhaustive]`, so the new variant breaks no downstream match. Clippy `-D warnings` passing on this tree confirms the rest resolves.
- [x] Values checked against the plan or ADR-0025: 16 document timestamps, a window of `MAX_REVISIONS + 1` revisions, 8 pairs per chain, 256 pool items. The `pairs > 0` LT requirement is not confirmed by any DSS case (see Not verified).

## Rules
- [x] `AGENTS.md` conventions hold: no unwrap, panic or indexing in `src/`; English code; French docs; `Cargo.lock` absent; no network outside `http`; the control date is a parameter.
- [x] No accepted ADR is contradicted. Level is structural (ADR-0025). Switches follow ADR-0031, with the hold rule as a rule for both presets (ADR-0026).

## Tests
- [x] Floor: `po-gate floor-guard s18-validate-level main` exit 0, nothing lowered.
- [x] Assertions pin the criteria. I checked fixtures: the "invalid" document timestamp is a zeroed imprint on a real token, and the CMS-CRL case uses real CRLs that validate. None of the six empty test shapes appear.
- [x] Budget: 15 new tests (14 offline or `#[ignore]`d plus 1 in `nacre-revocation`), within 25. The plan said 16, with task 4's two cases folded into one test.
- [x] Bite: four rules disabled, each run on its test files only, each undone and confirmed with `git diff --exit-code`.
  1. Document timestamps dropped from the best-signature-time (`validate.rs:381`, `stamped.min()`): 1 failing test, `document_timestamp_is_a_proof_of_existence`. Restored.
  2. Every chain pair treated as covered (`level.rs:390`, `if false && !revocation.covers`): 3 failing tests in `tests/revocation.rs`: `dss_covering_every_chain_gives_lt`, `cms_revocation_data_does_not_give_lt`, `document_timestamp_over_a_covering_dss_gives_lta`. Restored.
  3. Hold reported as `Revoked` (`revocation.rs:337`, `if false && latest.hold`): 1 failing test, `hold_before_the_stamp_is_try_later`. Restored.
  4. Anchor's delegate always judged (`revocation.rs:363`, `true ||`): 1 failing test, `anchor_delegated_responder_switch`. Restored.
- [x] Tests made useless by the story were adjusted: the `level == None` assertion is dropped from `passed`, as the plan says.

## Neighbours
- [x] `validate_with` now always reads `/DSS` and builds `Structure`, also with no anchors. `judge` returns early with no anchors, so verdicts are unchanged; only the cost grows (see Not verified).
- [x] `Item::verdict`, the source answer and the TSA path judging all received the new flag consistently. `OcspResponse::status` keeps its contract; `critical_single_extension_is_rejected` is untouched.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml`, dev-dependency `serde_json = "1"` added).
- The plan names the dependency and its reason (ADR-0009, already used by `nacre-conformance`).
- It is not a bump, there is no lockfile in git, and nothing duplicates it.
- No lens finding.

## Findings
- major — crates/nacre-validate/tests/campaign.rs:84 — Carried from QA finding 1 (verified). `fn dss` turns any error of the DSS client (connection refused, timeout, HTTP status, unexpected JSON) into `Outcome::Error`, and that counts as agreeing with Nacre's `Err`.
  - Five of the 257 "identical" cases rest on it: `bench-n04-tsa-repeated-ext`, `hostile-aes256`, `hostile-circular-xref-chain`, `hostile-xref-malformed-prev`, `attacks-chain-malformed-extension`.
  - For those five, no DSS XML report and no error text is kept. AC6 ("DSS's XML reports of each campaign kept") and the 100 % claim of AC4 cannot show whether DSS refused the file or the request failed.
  - Fix: count a case as agreeing only on an HTTP error answer from DSS itself, and keep its status and body as the evidence.
- minor — conformance/campaign/run.sh / crates/nacre-validate/tests/campaign.rs:142 — Carried from QA finding 2 (verified). With DSS unreachable, the campaign prints nothing and runs for more than 8 minutes. Every case becomes an "error" difference, and the strict explanation search tries up to 469 policy sets on each. No message names DSS or its URL.
  - Fix: check DSS once at start (the URL answers) and fail fast if it does not.
- minor — crates/nacre-validate/tests/campaign.rs:216 and :228 — Carried from QA finding 3 (verified). In `campaign-strict.md` the explaining switch sits on the `(count)` row, which is marked `=`. The `≠` signature rows have an empty explanation cell: 105 of them. Reading or grepping the table by `≠` shows no explanation, which weakens AC5's "each case listed with the strict rule that explains it".
- minor — crates/nacre-validate/tests/campaign.rs:154 — Departure from plan task 9 ("singles first, then pairs"): `explanation` also searches triples of switches. One strict case is explained only by a triple (`… + ignore_expired_certs_on_crl + refuse_critical_ocsp_extensions`). The plan does not name triples, and they multiply the search cost of finding 2.
- minor — crates/nacre-validate/src/level.rs:86 — Departure from plan task 3, which says "That pool reads OCSP as the policy says (task 7)". `Revocation::covers` always calls `status_ignoring_critical_extensions`, whatever the policy.
  - Under `strict()`, a `/DSS` whose only data for a pair is an OCSP response with a critical extension gives the pair verdict `Missing`, yet the level reads LT.
  - This is consistent with ADR-0025's structural reading ("expired or not"), so it is not a defect. But the plan text and the code disagree, and nothing records the choice. Either align the plan wording or note the choice in the rustdoc of `covers`.

## Not verified
- **The campaign and the conformance tests on the bench** (`tests/campaign.rs`, `tests/conformance.rs` including `anchor_delegated_responder_policy` and `critical_ocsp_extensions_policy`, all `#[ignore = "conformance"]`). I did not start the bench. I rely on QA's run on this exact tree (qa-current passes) for the campaign. The two new conformance tests last ran before the `/DSS`-over-revisions change, per the record. A person should run `cargo test -p nacre-validate --all-features --test conformance -- --ignored` on a started bench, or check CI's `conformance.yml` on the PR.
- **The production build.** It is deferred to ship (`Build stage: ship-if-route`, a manifest changed). It must run at `/po-ship`.
- **End-to-end tests.** The project has no E2E command (`E2E: —`).
- **Fuzz targets.** Not run; CI's `fuzz` job covers them. `Structure::read` now parses up to 65 earlier-revision prefixes and hashes the document once per signature and per later document timestamp, on every `validate` call, anchors or not. Its cost on a large, many-revision hostile file was not measured. A person should watch the fuzz job's timeouts, or time `validate` on a 64-revision file.
- **Level-rule branches no DSS case showed** (the plan's pivot, also in the record):
  - R's exemption on a revoked CA or under a non-self-signed anchor;
  - C on an OCSP extension DSS knows and rejects (nonce mismatch);
  - LT through a delegated OCSP response;
  - several document timestamps around several `/DSS` beyond r5–r8 and l30;
  - more than 16 document timestamps;
  - a signer that is itself the anchor (`pairs > 0` gives no LT).

  A DSS upgrade or s19's foreign corpus should cover them.
- **From the QA report's `## Not seen`:**
  - AC4 on `conformance/corpus/`: the folder does not exist before s19.
  - DSS's verdict on files signed by tools other than Nacre, pyHanko aside: outside the story, s19.
  - Behaviour under real load or on a real network (public TSA, online CRL/OCSP): the driver cannot show it, and the story forbids it.
  - The `.github/workflows/conformance.yml` run of the campaign in CI: a dependency the driver did not start.

Max severity: major
Ship allowed: yes

---

# Review — s18-validate-level

[Story](../stories.md) · [Plan](../plans/s18-validate-level.md) · [Verification](../verif/s18-validate-level.md)

Diff reviewed: `git diff main...story/s18-validate-level`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 1
Reviewed tree: 46adc00c436ae6dcfc3061cdf262bf6c7dd93b4d

## Ownership
I listed the diff with `git diff --name-only main...story/s18-validate-level` and checked each path against the story's `Owns` line: `crates/nacre-validate/`, `crates/nacre-pdf/`, `crates/nacre-revocation/`, `conformance/campaign/`, `docs/security/attacks/`, `docs/decisions/0030-issuer-of-revoked-data-switch-and-archive-cutoff.md`.
- [x] Every path is inside `Owns`.
  - Code: `crates/nacre-validate/**`, `crates/nacre-revocation/{src/ocsp/response.rs,tests/ocsp_status.rs}`, `conformance/campaign/**`, `docs/security/attacks/revocation.md`.
  - ADR-0030: only its frontmatter changes (`superseded-by: [0031]`).
  - Covered by construction: the story's own pipeline files (research, plan, verif, qa, review) and ADR-0025 and ADR-0031. Both ADRs have status `A` and the plan names both.
- [x] Nothing falls inside another running story's `Owns`. `git worktree list` shows only `main` and this lane.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s18-validate-level` exit 0, so the record is reused (`Verification mode: record`).
  - It proves `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` on this code, the fix run's changes included.
  - Its "Not proven here" section says the campaign was rerun in fix run 1, but not as a `po-run` row, and that `tests/conformance.rs` was not rerun in that fix run.
- [x] `po-gate qa-current s18-validate-level` exit 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`).
  - QA walked the fix code (commit `07bcd80`) and reran the campaign on a fresh bench: 257 cases, 0 differ under `dss()`; 94 explained under `strict()`, 0 unexplained.
  - The QA report lists no findings. It says the three findings of the previous QA run no longer reproduce.

## Plan
- [x] Tasks 1–9 are present (checked in fix loop 0; the fix run did not change `src/` except one rustdoc).
  - The fix commit stays within what the fix-loop-0 findings asked for:
    - DSS errors are counted as agreement only when DSS itself sent an HTTP error status;
    - the campaign checks first that DSS answers;
    - the explanation goes on every row marked `≠`;
    - the rustdoc of `covers` now records the choice.
  - Two additions the plan does not name: the dev-dependencies `ureq` and `base64ct` (Findings).
- [x] Run interdicts, one by one:
  - Diff confined to the listed paths: yes.
  - `crates/nacre-pdf/`, `nacre-conformance`, `nacre-core`, `nacre-pades`, workflows, `conformance/pki/`, `compose.yaml` and `docs/stories.md` are untouched.
  - Bodies of ADR-0026 to 0030 untouched: yes.
  - Only R1 and C1 implemented: yes.
  - `OcspResponse::status` keeps its behaviour: yes.
  - `ChainDefect::report` and `RevocationDefect::report` keep level `None`: yes.
  - No case excluded from the campaign, and no difference allowed under `dss()`: yes.
  - No `[workspace.dependencies]`, no `Cargo.lock`, no `cms` or `x509-tsp` crate: yes.
  - Only a local `NACRE_DSS_URL`: yes. `dss_url()` passes the URL through `Dss::new`, which refuses any address off this machine.

## References
- [x] Opened and confirmed:
  - `nacre_conformance::Error::Http(#[from] ureq::Error)` (`crates/nacre-conformance/src/lib.rs:33`);
  - `Dss::new` and `Dss::from_env`, with the same default `http://127.0.0.1:18080` (`client.rs:8`, `:24`, `:48`);
  - the request body of `validate` (`client.rs:69-72`), which `keep_error` copies field for field;
  - ureq 3's `http_status_as_error` and `timeout_global`. Clippy `-D warnings` passing on this tree shows they resolve.
- [x] Values: `keep_error` writes its file under a `name` that `Dss::validate` has already checked (no `/`, `\` or `..`). The five kept `*.error.txt` files hold `HTTP 500` and DSS's body, for example `repeated extension found: 2.5.29.15`.

## Rules
- [x] `AGENTS.md` conventions hold:
  - no unwrap, panic or indexing in `src/` (the new `unwrap`s are in `tests/`);
  - English code, French docs;
  - no `Cargo.lock`;
  - the network is reached only from tests, against the local bench.
- [x] No accepted ADR is contradicted (ADR-0025 structural level; ADR-0031 switches; ADR-0026 hold rule).

## Tests
- [x] Floor: `po-gate floor-guard s18-validate-level main` exit 0, nothing lowered.
- [x] Assertions pin the criteria, and none of the six empty test shapes appear. In the kept reports, 0 of the 121 rows marked `≠` in `campaign-strict.md` lack an explanation, and every file counted `error = error` now has its DSS `.error.txt`.
- [x] Within `Test budget` (25): 15 new tests. The fix run added none.
- [x] Bite: two rules disabled, only `tests/level.rs` run each time, each change undone, and `git diff --exit-code` and `git status --porcelain` clean afterwards.
  1. ESS requirement off (`level.rs:232`, `if false && …`): 1 failing test, `pades_needs_an_ess_attribute`.
  2. `signingTime` dropped from the BES rule (`level.rs:239`): 1 failing test, `signing_time_gives_bes_to_pades_only`.
  - Fix loop 0 already bit four other rules: document-timestamp proof, LT coverage, hold, anchor delegate.
- [x] No test made useless by the story is left behind.

## Neighbours
- [x] The fix touches only `tests/campaign.rs`, `run.sh`, the README, a rustdoc and dev-dependencies. No caller in `src/` changed. `run.sh` copies the `*.error.txt` files only when they exist, so a run without one still works.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml`: dev-dependencies `serde_json`, `ureq`, `base64ct` added); security (content: an HTTP call whose URL comes from `NACRE_DSS_URL` in `tests/campaign.rs`).
- [x] Dependencies: `ureq 3` and `base64ct 1.8` are already in the graph through `nacre-conformance`, at the same versions. There is no lockfile and no bump. The plan names neither (Findings).
- [x] Security: the URL goes through `Dss::new`'s local-only allow-list before any request. No finding.

## Findings
- minor — crates/nacre-validate/Cargo.toml:39-40 — The dev-dependencies `ureq` and `base64ct` were added in the fix run, but the plan's `## Reuse` and `## Run interdicts` name only `serde_json`.
  - Their reason is only in a Cargo comment ("keeps the body of an HTTP error DSS answers, which `nacre-conformance` drops") and in the verification record.
  - With them, `keep_error` (`tests/campaign.rs:115-123`) rebuilds by hand the request body of `nacre-conformance`'s `client.rs:69-72`, a copy that can drift from it. The `assert_eq!` on the replayed status only partly guards against that drift.
  - The cleaner place for this is `nacre-conformance` returning the error body itself, but that crate is outside `Owns`. Better to file it for a later story, and to note the two dev-dependencies in the plan.
- minor — crates/nacre-validate/tests/campaign.rs:19 (`explanation`) — Carried from fix loop 0, still open: the strict-explanation search also tries triples of switches, which plan task 9 does not name ("singles first, then pairs"). The module doc now says triples, but the plan does not.

## Not verified
- **The campaign and the conformance tests on the bench** (`tests/campaign.rs`, `tests/conformance.rs` with `anchor_delegated_responder_policy` and `critical_ocsp_extensions_policy`, all `#[ignore = "conformance"]`).
  - I did not start the bench.
  - For the campaign, including the new HTTP-status rule and the start-up check, I rely on QA's rerun on this code (qa-current passes). Those paths cannot be bitten offline.
  - `tests/conformance.rs` was not rerun after the `/DSS`-over-revisions change, nor in the fix run.
  - A person should run `cargo test -p nacre-validate --all-features --test conformance -- --ignored` on a started bench, or check CI's `conformance.yml` on the PR.
- **What an HTTP 500 means.** The campaign counts a 500 from DSS (an internal exception) as DSS refusing the file. A 500 for an unrelated reason, such as DSS running out of memory, would read as agreement too. The kept bodies show genuine refusals for the five current cases. Whoever regenerates the reports should read each new `*.error.txt`.
- **The production build.** It is deferred to ship (`Build stage: ship-if-route`, a manifest changed); `/po-ship` must run `cargo build --workspace --all-features`.
- **End-to-end tests.** The project has no E2E command (`E2E: —`).
- **Fuzz targets.** Not run; CI's `fuzz` job covers them.
  - `Structure::read` parses up to 65 earlier-revision prefixes on every `validate` call.
  - Its cost on a hostile file with many revisions was not measured.
  - A person should watch the fuzz job's timeouts.
- **Level-rule branches no DSS case showed** (the plan's pivot):
  - R's exemption on a revoked CA or under a non-self-signed anchor;
  - C on an OCSP extension DSS knows and rejects (nonce mismatch);
  - LT through a delegated OCSP response;
  - several document timestamps around several `/DSS` beyond r5–r8 and l30;
  - more than 16 document timestamps;
  - a signer that is itself the anchor (`pairs > 0` gives no LT).

  s19's foreign corpus or a DSS upgrade should cover them.
- **From the QA report's `## Not seen`:**
  - AC4 on `conformance/corpus/`: the folder does not exist before s19.
  - DSS's verdict on files signed by tools other than Nacre, pyHanko aside: outside this story, s19.
  - Real load or a real network (public TSA, online CRL/OCSP): the driver cannot show it, and the story forbids it.
  - The `.github/workflows/conformance.yml` run in CI: a dependency the driver did not start.
  - A DSS that answers the replay in `keep_error` differently from the first request: the bench cannot make DSS change its answer.

Max severity: minor
Ship allowed: yes
