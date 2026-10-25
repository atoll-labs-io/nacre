---
validated: yes
---
# Plan — s42-tsa-freshness

[Story](../stories.md) · [Research](../research/s42-tsa-freshness.md)

Branch `story/s42-tsa-freshness`. Read `docs/research/s42-tsa-freshness.md` first; this plan builds on it without repeating it.

## Story
Under `ValidationPolicy::strict()`, the revocation of every TSA's chain, for signature and document timestamps alike, counts a "not revoked" only when it was issued at most 24 h before the control date (AC1). Under `dss()` the verdict stays DSS's (AC2). A test with a stale TSA CRL shows the rejection under `strict()` (AC3). The rule sits under the existing `require_fresh_revocation` switch: no new switch, no new public API.

Correction carried from the research: on the TSA path the window does not depend on a proof of existence. The TSA path is judged at the control date, and Nacre gives its revocation data no proof of existence. "Revoked since" cannot be written into the file: the test shows that the stale "not revoked" no longer clears the TSA.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Start of the 24 h window for a TSA path | already in this repository: the expression at `crates/nacre-validate/src/validate.rs:385-386` and the `issued_from` parameter of `judge_path` (`revocation.rs:290-298`, rule at `:313-316`) | — (first rung holds; the expression is moved into one private method so the two call sites share it, no new logic) |
| Test of the stale TSA CRL | already in this repository: fixture `Pki`, `stamped()`, `judge_under`, `crl`, `with_dss`, `document_timestamp`, `strict_without` (`tests/revocation.rs`, `tests/support/forge.rs:825`) | — |

## Tasks
1. [x] **One window, two callers.** In `crates/nacre-validate/src/validate.rs`, add a private method on `Context`, e.g. `fn fresh_from(&self) -> Option<SystemTime>`. It returns `self.at.checked_sub(FRESHNESS_TOLERANCE).unwrap_or(self.at)` when `self.policy.require_fresh_revocation` is set, `None` otherwise. Use it at `:385-386`, which becomes `best_signature_time.is_none().then(|| self.fresh_from()).flatten()` or equivalent; the signer's behaviour must not change. In `proven_time` (`:542`), pass `self.fresh_from()` as `issued_from` instead of `None`; keep `issuers_at = None`. Test able to fail: task 2's test, and the flipped assertion of task 2.
2. [x] **Tests, `tests/revocation.rs`.**
   - (a) Rewrite the second half of `old_crl_does_not_pass_a_signature_without_poe` (`:490-492`). It asserts the hole today. On the same B-T with the 25 h-old intermediate CRL, under `strict()` (via `pki.judge`), expect `refused(…, CertificateChainGeneralFailure)` with `RevocationDefect::Missing { depth: 0 }` and `best_signature_time == None`. Update its doc comment.
   - (b) Add one test, `stale_crl_does_not_clear_a_timestamp_authority` (name free). Use the stale intermediate CRL of 2026-10-21T23:00Z plus `pki.root_crl(&[])` as `crls`, on two files: `with_dss(&pki.stamped(), &[], &crls)` (signature timestamp) and `document_timestamp(&with_dss(&pki.basic(), &[], &crls), &pki.tsa(None))` (document timestamp, since `document_time` reaches `proven_time` too). Judge each with `pki.judge_under(…, control_date(), …)`. Under `ValidationPolicy::strict()`: `refused(…, CertificateChainGeneralFailure)` gives `Missing { depth: 0 }`, and `best_signature_time == None`. Under `ValidationPolicy::dss()` and under `strict_without(|p| p.require_fresh_revocation = false)`: `passed`, with `best_signature_time == Some(stamp_time())`. Prototyped in scratch on the fixed code: exactly these six verdicts.
   - Removing `self.fresh_from()` at `:542` must turn (a) and the strict half of (b) green-to-red. Run `cargo test -p nacre-validate --test revocation`.
3. [x] **Docs in the crate say the new rule.** Rewrite each sentence that limits the window to signatures with no timestamp, so it also says that a TSA path counts only fresh "not revoked" data under `require_fresh_revocation`:
   - `policy.rs:62-66`: the switch.
   - `policy.rs:135-136`: the unsafe list of `dss()`. Add "a stale 'not revoked' clearing a timestamp authority".
   - `revocation.rs:24-33`: `FRESHNESS_TOLERANCE`. Drop "a signature with a proof of existence keeps DSS's rule" for the signer-only wording.
   - `revocation.rs:262-266` if it needs it.
   - `validate.rs:82-91`, `:383-384` and `:517-521` (`proven_time`).
   - `lib.rs:31-36`.

   Say the offline consequence once, in `policy.rs`: an old archive whose TSA has only old data proves no time under `strict()` unless a `RevocationSource` answers. English, sparse. Check: `cargo doc`-safe links. The type check of task 6 runs clippy on the crate, docs included.
4. [x] **Catalogue.** In `docs/security/attacks/revocation.md`:
   - Fix the prose at `:87` ("Sans preuve d'existence (aucun horodatage)…") so the TSA path is included.
   - Fix row `:94`: drop "avec un horodatage, il compte, comme pour DSS". Under `strict()` a timestamp whose TSA has only stale data no longer proves a time.
   - Add one row: "Vieux « non révoqué » ajouté au `/DSS` pour faire passer la clé d'une TSA révoquée depuis". It names `stale_crl_does_not_clear_a_timestamp_authority` and `old_crl_does_not_pass_a_signature_without_poe`, story `s42`, result `RevocationDefect::Missing` on the TSA path, no proof of time, then the signer judged under its own window (`CERTIFICATE_CHAIN_GENERAL_FAILURE` here). "Ouverte sous": `` `dss()` (`require_fresh_revocation`) ``.

   French, like the page. Check: `cargo test -p nacre-validate --test policy` (the catalogue parser) stays green.
5. [x] **Full suite and type check.** Run `po-run --story s42-tsa-freshness --label test -- 'cargo test --workspace'` once every task is done, then `po-run --story s42-tsa-freshness --label typecheck -- 'cargo clippy --workspace --all-targets --all-features -- -D warnings'` after the last edit.
6. [x] **Bench checks, when the lead frees the bench.** The coordinator holds the bench for the s19 lane during planning; never stop `patelle-dss`. Start the bench fresh, so its CRLs are under 24 h old (`conformance/README.md`). Run `po-run --story s42-tsa-freshness --label conformance -- 'cargo test -p nacre-validate --all-features --test conformance -- --ignored'`. Then run `sh conformance/campaign/run.sh`. Expected: `campaign-dss.md` 0 differences; `campaign-strict.md` 0 unexplained, any new strict difference explained by `require_fresh_revocation`. Stop the bench with `podman compose -f conformance/compose.yaml down`. If the bench is not freed before review, write in `docs/verif/s42-tsa-freshness.md` that these two checks did not run and why. The reviewer and `/po-ship` then see it, and nobody claims parity unchecked.

## Scene viewpoints
—

## Run interdicts
- `crates/nacre-validate/src/revocation.rs`: no logic change (docs only). `judge_path`'s signature and its `fresh` closure (`:313-316`) keep an empty logic diff.
- `crates/nacre-validate/src/policy.rs`: no new field. `strict()` and `dss()` bodies keep an empty diff. No new switch, so `tests/support/mod.rs` `SWITCHES` keeps an empty diff.
- The signer's window keeps its condition `best_signature_time.is_none()`. Under `dss()`, `proven_time` and `judge` pass `issued_from = None` exactly as before.
- No file under `conformance/corpus/foreign/` (s19 lane). No edit to `docs/decisions/`: no ADR in this story, ADR-0032 unused. No edit to `docs/stories.md`. No root `Cargo.toml` edit, no new dependency.
- Never call a public TSA or the online DSS demo, never stop `patelle-dss`, never touch `omniroute`. Scratch only under `/home/lecrabe/.claude/jobs/4fb763d0/tmp/`.

## The pivot
The rule goes on `proven_time` under `require_fresh_revocation`, unconditionally (not only "with no proof of existence"). The TSA path is judged at the control date with no POE for its own data. How it could be wrong:
- **Too wide.** Under `strict()`, a legitimate offline archive (B-LT/B-LTA) whose TSA has only old CRLs now proves no time, and the signer then falls under its own window. Compare with AC1, which asks exactly this, and with the campaign rows under `strict()`: each new difference must be explained by `require_fresh_revocation` alone. A case already needing three switches would go unexplained (`tests/campaign.rs:205-235`).
- **ADR needed after all.** ADR-0031's table row (`docs/decisions/0031-…md:57`) reads "with no proof of existence". This plan reads the TSA's data as having no POE, so the row already covers it. If the lead reads it as a widening, as ADR-0030 treated `ignore_expired_certs_on_crl` → OCSP, a superseding ADR is owed, and ADR-0032 is reserved for it.
- **Old revocation still decisive.** The window keeps an old non-hold revocation dated at or before `time` = control date (`revocation.rs:315`). Check that `revoked_tsa_gives_no_poe` (`tests/revocation.rs:345`) stays green unchanged.

## Files touched
- `crates/nacre-validate/src/validate.rs`
- `crates/nacre-validate/src/policy.rs` (docs)
- `crates/nacre-validate/src/revocation.rs` (docs)
- `crates/nacre-validate/src/lib.rs` (docs)
- `crates/nacre-validate/tests/revocation.rs`
- `docs/security/attacks/revocation.md`
- `docs/research/s42-tsa-freshness.md`, `docs/plans/s42-tsa-freshness.md`, `docs/verif/s42-tsa-freshness.md`

## Test strategy
- Automated, service layer (`tests/revocation.rs`): one test flipped (a), one test added (b). Two tests out of a budget of 25. (b) covers both timestamp kinds and the three policies (`strict()`, `dss()`, `strict()` minus the switch) on the same files. Bite: removing the window at `validate.rs:542` reds (a) and the strict half of (b). Turning the switch off greens them, which shows the rule belongs to `require_fresh_revocation`. No unit test of `fresh_from` (it is covered through (b), and through the existing `old_crl_does_not_pass_a_signature_without_poe` first half and `old_crl_passes_without_the_freshness_switch` for the signer site).
- Existing guards that must stay green: `policy.rs` `each_switch_changes_only_what_the_catalog_names` and `dss_opens_only_what_the_catalog_marks` (green with the fix in scratch), `revoked_tsa_gives_no_poe`, `old_revocation_counts_unless_on_hold`.
- No new conformance test. AC2 rests on `dss()` taking an unchanged path (`issued_from = None`), on (b)'s `dss()` half, and on the campaign rerun of task 6.
- Visual checks: none (`Surface: endpoint`; QA under `QA stage: surfaces` drives the endpoint).

## Done when
- Tasks 1-5 ticked, and task 6 run, or its absence recorded in the verification record.
- `cargo test --workspace` and clippy green through `po-run`.
- Under `strict()`, a stale "not revoked" no longer clears a TSA for either timestamp kind. Under `dss()`, the verdicts are unchanged.
- The catalogue no longer says that a timestamp makes an old CRL count.
- One commit `s42-tsa-freshness: …` with research, plan and record, reviewed with no open critical, landed through a pull request.
