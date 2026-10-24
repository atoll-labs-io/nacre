# Review: s46-dss-parity-3

[Story](../stories.md) · [Plan](../plans/s46-dss-parity-3.md) · [Verification](../verif/s46-dss-parity-3.md)

Diff reviewed: `git diff main...story/s46-dss-parity-3`, in a context that did not write it. Each finding is rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: 72f650ce700dc91cf2c37dd6c55bbff955f00577

## When blocked
- Not blocked.

## Ownership
I listed the diff with `git diff --name-only main...story/s46-dss-parity-3` (30 paths) and held each path against `Owns`: `crates/nacre-validate/`, `crates/nacre-revocation/`, `docs/security/attacks/`, `docs/decisions/0029-misplaced-xref-and-expired-certs-on-crl-switches.md`.
- [x] Every path is inside `Owns`, or is in scope by construction:
  - the story's own research, plan, verif and `docs/qa/s46-dss-parity-3/` files;
  - ADR-0030, which the diff adds (status `A`) and the plan names.
- [x] ADR-0029 is listed in `Owns`. Its diff touches only the frontmatter (`superseded-by: [0030]`), which Law 6 allows. Its status and body are unchanged.
- [x] No other story is running. `git worktree list` shows only `main` and this worktree.

## Evidence reused
- [x] `po-gate verif-current s46-dss-parity-3`: exit 0. I reused the record. Unit suite (`cargo test --workspace`) and type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) both exited 0 on the recorded code. I read its "Not proven here" section.
- [x] `po-gate qa-current s46-dss-parity-3`: exit 0. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). The report lists no findings, so nothing carries over. Its `## Not seen` items are under Not verified below.

## Plan
- [x] All 8 tasks are present and ticked, and the diff matches each one:
  - two accessors in `nacre-revocation`: `delegated_responder` and `archive_cutoff`, built on a shared `responder()` so they cannot drift from `status`;
  - the forging helpers;
  - the SKI check extracted into `ca_without_key_identifier` and applied in `proven_time`;
  - the twelfth switch;
  - the delegate's validity window kept in `Verdict.responder`;
  - `archiveCutoff` fed into `expired_from`;
  - `SWITCHES` grown to 12, the catalogue and ADR link, the rustdoc;
  - 4 conformance tests.
- [x] Each run interdict checked:
  - Nothing outside the allowed paths, and `crates/nacre-pdf`, `nacre-core`, `conformance/`, `.github/` and `docs/stories.md` are untouched.
  - `OcspResponse::status` keeps its behaviour: `responder_key` now goes through `responder()`, and the decisions are the same.
  - `tests/{attacks,ocsp_attacks,hostile}.rs` and the corpora are untouched.
  - `SWITCHES` is the only edit to an existing test. The other `-` lines are one import line and the `[Switch; 11]` → `[Switch; 12]` change.
  - No new dependency. The only manifest edit is `derive` on the dev-dependency `der`.
  - No `Cargo.lock`, no `[workspace.dependencies]`.
  - `level()` is not touched.

## References
- [x] I opened every reference and confirmed it:
  - `in_validity`, `CertificatePath.certificates`, `Item::verdict` and `judge_path`'s two callers (`validate.rs:376`, `:482`);
  - `asn1.rs` included by `#[path]` in `forge.rs`, and `nacre_revocation::OcspRequest::new`;
  - `GeneralizedTime::to_system_time`;
  - OID `1.3.6.1.5.5.7.48.1.6` (RFC 6960 §4.4.4).
  - The workspace compiles under clippy according to the record.
- [x] Values checked:
  - `archiveCutoff` counts when `from <= not_after`, which matches the RFC 6960 meaning (status kept for certificates whose `notAfter` is at or after the cutoff).
  - The delegate window `(not_before..=not_after).contains(&at)` includes both ends, like `in_validity`; QA hit both edges (`notAfter` passes, +1 s fails).
  - `ca_without_key_identifier` reproduces the old loop exactly: certificates below the anchor, `filter_map` decode, skip the leaf, depth taken after the filter.

## Rules
- [x] `AGENTS.md` conventions are respected:
  - no `unwrap`, `expect` or indexing in library code (`.get(..)`, `.ok_or(..)`);
  - no clock read;
  - no I/O;
  - code and rustdoc in English, catalogue in French.
- [x] No accepted ADR is contradicted. ADR-0030 supersedes ADR-0029's switch table and the ADR-0026 rule stands: k1 and e2 are DSS rules applied under both presets, not switches.

## Tests
- [x] Floor: `po-gate floor-guard s46-dss-parity-3 main` exited 0, so nothing was lowered.
- [x] The assertions pin each acceptance criterion with its exact defect and sub-indication.
  - Controls rule out a fixture passing for the wrong reason: a CA with SKI in k1, a delegate valid to 2036 in e3, v5 for the switch, a late cutoff in e4b-like.
  - None of the six empty test shapes. Fixtures are forged per test with distinct keys, and no mock stands in for the rule under test.
- [x] 9 new automated tests, within the `Test budget` of 25.
- [x] Bite, each run on `tests/revocation.rs` only, then undone with `git checkout --`. A final `git diff --exit-code` showed a clean tree.

  | Rule disabled | Failing tests |
  | --- | --- |
  | Revoked-data skip forced off (`false && …`) | 1: `issuer_of_revoked_data_switch` |
  | Skip widened to every depth when the switch is off (`revoked.is_some()` guard removed) | 3: `issuer_of_revoked_data_switch` (v5), `delegated_responder_out_of_validity`, `issuer_out_of_validity_is_revocation_out_of_bounds` |
  | Delegate validity check disabled | 1: `delegated_responder_out_of_validity` |
  | `archive_cutoff` ignored (`expired_from = None`) and the SKI check removed from `proven_time`, together in one run | 2: `archive_cutoff_switch` and `tsa_ca_without_key_identifier_proves_no_time`, each failing on its own rule |

- [x] No test became useless.

## Neighbours
- [x] I read the other callers:
  - `responder_key` (used only by `status`) and `delegate()` (used only by `responder()`);
  - `judge_path`, which has two callers, both updated to take `&ValidationPolicy`.
  - The TSA path keeps `issuers_at = None`, so the delegate rule does not reach it. The plan says so.
  - `after_revocation` keeps its depth semantics through the extracted helper.

## Lenses
Lenses run: dependencies (`crates/nacre-validate/Cargo.toml`, dev-dependency `der` gains the `derive` feature)
- [x] The dependencies lens found nothing:
  - the plan names the change and its reason (forge.rs decodes the OCSP structures through `asn1.rs`);
  - the version is unchanged and no package is added;
  - `Cargo.lock` stays out of git.

## Findings
- minor — crates/nacre-validate/src/policy.rs:118 — the `dss()` rustdoc line runs to 143 columns. The `archiveCutoff` and revoked-data clauses were appended without rewrapping, and `cargo fmt` does not wrap comments. Rewrap it like the neighbouring lines (`revocation.rs:266-267` exceed 100 only because they hold intra-doc link targets, which is fine).

## Not verified
- **The four `#[ignore = "conformance"]` tests (AC6) against DSS.** I did not start the DSS bench. The record says they ran once with all 31 conformance tests passing, but that run is not a `po-run` row.
  - To cover it: start the bench per `conformance/README.md` and run `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, or watch CI's `conformance.yml` on the PR.
- **QA Not seen, criterion 6:** QA did not start the bench either, so it saw only Nacre's side of each family.
- **QA Not seen, "comme chez DSS" in criteria 1 to 4:** these were held against the verdicts the story and ADR-0030 name, not against a running DSS.
  - DSS's verdict on a `certificateHold`, on a revoked CA at depth > 0 combined with v3, and on the trust anchor's delegated responder is unknown. Nacre skips the hold and the v3+v5 combination with the switch off, and refuses the anchor's delegate at depth 1 under both presets.
  - These are the plan's own pivot risks, to be compared with DSS once s18's campaign forges them.
- **e2 with a proof of existence** (the "both presets" shape of AC3) is proven offline only (`delegated_responder_out_of_validity`), not against DSS.
- **`archiveCutoff` placed in `responseExtensions` or marked critical:** Nacre ignores or refuses it (QA observed this). Whether DSS/BouncyCastle reads it there is not known.
- **A delegated responder's own revocation** is still not judged, as the catalogue says.
- **Fuzz targets** were not run; CI's `fuzz` job covers them.
- **Production build** is deferred to ship (`Build stage: ship-if-route`, a manifest changed). The project has no E2E command (`E2E: —`).
- **The full unit suite and clippy** were not rerun here. Under `Verification mode: record` I relied on the current record, as the gate confirmed.

Max severity: minor
Ship allowed: yes
