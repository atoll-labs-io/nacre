# Review: s45-dss-parity-2

Reviewed tree: 6b9ed813ea630670273db74c1e2837ddc94097a3
Fix loop: 0
Branch: story/s45-dss-parity-2 (worktree /home/lecrabe/dev/atoll/nacre/.worktrees/s45-dss-parity-2), diff `git diff main...story/s45-dss-parity-2`
Lenses run: Security (path `crates/nacre-validate/src/policy.rs`; content: signature `/SubFilter` and revocation-data acceptance rules)
Review status: complete

## Scope check (Owns)
Every changed path is in scope:
- **Covered by the `Owns` line.** Everything under `crates/nacre-pdf/`, `crates/nacre-validate/` and `docs/security/attacks/`, plus `docs/decisions/0027-unsupported-sub-filter-switch.md`. The change to 0027 is frontmatter only (`superseded-by: [0029]`).
- **Added ADR named by the plan.** `docs/decisions/0029-misplaced-xref-and-expired-certs-on-crl-switches.md` has status `A`.
- **The story's own pipeline evidence.** `docs/plans/`, `docs/research/`, `docs/verif/`, `docs/qa/s45-dss-parity-2/`.

`git worktree list` shows no other story lane, so no other running story owns any of these paths.

## What was relied on
- **Unit suite and type check (`Verification mode: record`).** `po-gate verif-current s45-dss-parity-2` passed (exit 0). The record is complete, and `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0 on the current code outside `docs/`. I did not rerun them.
- **QA.** `po-gate qa-current s45-dss-parity-2` passed (exit 0): the report is complete, committed and on this tree. It has no findings, so there was nothing to carry over. Its `## Not seen` items are listed under Not verified below.
- **Floor guard.** `po-gate floor-guard s45-dss-parity-2 main` exited 0: nothing was lowered.
- **End-to-end and build.** The project has no `E2E` command (`—`). The build is left to ship (`ship-if-route`), and no manifest or routing changed.

## Plan conformity
- **Tasks 1–9 are all present in the diff:**
  - `ReadOptions` and the misplaced-xref tolerance in `crates/nacre-pdf/src/xref.rs`;
  - the two switches;
  - the `/SubFilter` reach;
  - `expiredCertsOnCRL` (`revocation.rs`);
  - `IssuerOutOfBounds` at the control date, after `Missing` and `Revoked`;
  - `CaKeyIdentifierMissing` in `after_revocation`, below the anchor, after the validity loop and before `/M`;
  - the corpus regenerated;
  - eleven `SWITCHES` and the catalogue rows;
  - five conformance tests;
  - the ADR links and the rustdoc.
- **The plan's run interdicts hold:**
  - `refusals.rs` and `hostile.rs` are untouched;
  - nothing in `nacre-pades`, `nacre-revocation`, `nacre-core` or `conformance/`;
  - no `Cargo.toml` or lockfile change.
- **Every `## Reuse` row is honoured:** `Parser::skip_whitespace` (whitespace only, no comments), `in_validity`, `CertificateList`, `SubjectKeyIdentifier`, `SubIndication::RevocationOutOfBoundsNoPoe`.
- **References opened and confirmed:** `in_validity` (`chain.rs:514`), `CertificatePath.certificates: Vec<Vec<u8>>`, `forge::patch` (pads with spaces, so the `/ByteRange` stays valid), `docs/decisions-log.md` (lines 105–106, the person's choice cited by ADR-0029).
- **Neighbours.** No caller of `Defect`, `RevocationDefect` or `ValidationPolicy` exists outside `nacre-validate`. Both enums are `#[non_exhaustive]`. `parse_with`, `xref::read`, `judge_path` and `qualify` have no callers beyond the ones the diff updates.
- **Corpus.**
  - All 30 SHA-256 entries in `crates/nacre-validate/tests/corpus/README.md` whose paths resolve match the files, every row this story touched included. The other 25 rows name `attacks/` files by bare name and could not be resolved by my check.
  - Running `forge_chain_attacks` again into a temp copy (`/tmp/tmp.4GHctm7uO9/corpus`) gives a byte-identical corpus, so the regeneration is reproducible.
- **Values checked:**
  - `2.5.29.60` is `id-ce-expiredCertsOnCRL` (RFC 5280 §5.2.7), decoded as `GeneralizedTime`.
  - The extension is read from the same DER bytes whose signature `Crl::status` checks.
  - `from <= not_after` is the right reading of "keeps entries for certificates expired since `from`".
- **Test count.** 12 new tests, within the budget of 25.

## Bite (each mutation undone; `git diff --exit-code` clean after each)
| Rule disabled | Tests run | Failed |
| --- | --- | --- |
| Issuer-validity check skipped (`issuers_at.filter(\|_\| false)`, `revocation.rs`) | `--test revocation --test policy` | 1 (`issuer_out_of_validity_is_revocation_out_of_bounds`) |
| `expiredCertsOnCRL` honoured whatever the switch (`\|\| (true`, `revocation.rs`) | same | 1 (`expired_certs_on_crl_switch`) |
| SKI check skipped (`.skip(usize::MAX)`, `validate.rs`) | same | 1 (`ca_without_key_identifier_is_a_general_failure`) |
| Whitespace skip removed (`if true \|\| !options.misplaced_xref`, `xref.rs`) | `nacre-pdf --test options`; `nacre-validate --test policy` | 1; 3 (`misplaced_xref_switch`, both isolation tests) |
| Missing `/SubFilter` refused with the switch off (`validate.rs`) | `--test policy` | 1 (`missing_sub_filter_switch`) |

## Findings
- **minor** — `crates/nacre-pdf/src/lib.rs:12`: the new crate-doc sentence was not rewrapped. The line `//! section whose stated offset lands on whitespace before it. Every count, length and depth read from` runs past the 100-column width of the surrounding rustdoc. Fix: rewrap the paragraph.

## Not verified
- **The five conformance tests against DSS (AC7, and the "comme DSS" half of AC1–AC5).** They are `#[ignore = "conformance"]` and need the DSS bench. I did not start it. The record says they ran once (27 passed), but not through `po-run`, so I have no evidence on this tree. To cover it: start the bench per `conformance/README.md`, run `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, then bring the bench down. CI's `conformance.yml` also runs them.
- **From QA `## Not seen`:**
  - criterion 7 against a running DSS (bench not started);
  - criteria 1–5 checked against the verdicts the story names, not against DSS;
  - criterion 2 "sans niveau ETSI" cannot be told apart, because no level is computed yet (s18).
- **Fuzz targets.** Not run; `crates/nacre-pdf/fuzz/fuzz_targets/parse.rs` (now parsing with the option on as well) was only compile-checked by the implementer. CI's fuzz job covers them.
- **Cases left open by the plan's pivot and by ADR-0029, not forged by anyone:**
  - a delegated OCSP responder out of validity at the control date (Nacre judges only the pair's CA);
  - SKI on a trust anchor and on a timestamp authority's path;
  - a `startxref` off by more than whitespace (DSS repairs it, Nacre refuses it under both presets);
  - `Revoked` against the issuer rule when both apply.

  s18's campaign should check each against DSS.
- **Formatting.** Not checked by me; it is checked at commit and in CI.

Max severity: minor
Ship allowed: yes
