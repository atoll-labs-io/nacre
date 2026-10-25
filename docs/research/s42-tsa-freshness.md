# Research — s42-tsa-freshness

[Story](../stories.md)

## Structuring facts
- Cause, as the s17 review found it: `Context::proven_time` judges the TSA path with `issued_from = None` under every policy (`crates/nacre-validate/src/validate.rs:542`), so a "not revoked" CRL of any age clears the TSA at the control date. A signature timestamp (`validate.rs:376`) and a document timestamp (`validate.rs:514`) both go through that one function.
- An existing test asserts the hole: `old_crl_does_not_pass_a_signature_without_poe` expects a B-T whose only intermediate CRL is 25 h old to pass with a proof of existence (`crates/nacre-validate/tests/revocation.rs:490-492`). The catalogue row says the same (`docs/security/attacks/revocation.md:94`: "avec un horodatage, il compte, comme pour DSS"). Both contradict AC1 and must flip. This is the one test the fix breaks (run in scratch, see `## Diagnostic`).
- The window already exists and the fix reuses it: `judge_path(…, issued_from, …)` drops a "not revoked" issued before `issued_from` and keeps an old non-hold revocation dated at or before `time` (`crates/nacre-validate/src/revocation.rs:313-316`). The signer's start of window is `self.at - FRESHNESS_TOLERANCE` under `require_fresh_revocation` (`validate.rs:385-386`).
- Correction to the story's wording: "la même fenêtre que celle du signataire sans preuve d'existence". The TSA path is judged at the control date (`validate.rs:534`, `:542`, `time = self.at`), and Nacre never gives its revocation data a proof of existence. So the window applies to every TSA path under `strict()`, whether or not another timestamp exists. The signer's window still depends on POE (`validate.rs:385`).
- "Une clé de TSA révoquée depuis" cannot appear in the test file: the revocation lives only in the newer CRL the attacker leaves out. The test shows that a 25 h-old "not revoked" no longer clears the TSA. The case where a CRL in the file proves the TSA revoked is already covered by `revoked_tsa_gives_no_poe` (`tests/revocation.rs:345`).

## Diagnostic
The story carries no `Fixes` line. It still repairs a defect (s17 review, security major), so the cause was checked before planning.
- Reproduction, on HEAD 72cfd21 with no file written in the worktree: the existing assertion at `tests/revocation.rs:490-492` passes today. A B-T with a 25 h-old intermediate CRL (21st 23:00, control date 23rd 00:00) gets `TOTAL_PASSED` and `best_signature_time = Some(stamp)` under `validate_with_revocation`, which applies `strict()`.
- H1 (kept): the cause is the `None` at `validate.rs:542`. To refute it, pass the window there in a copy of the tree and see whether that verdict holds. Done in `/home/lecrabe/.claude/jobs/4fb763d0/tmp/s42/` with `cargo test -p nacre-validate --no-fail-fast`: only `old_crl_does_not_pass_a_signature_without_poe` fails, at `revocation.rs:206` (`passed`). Every other non-ignored test passes, including `policy.rs` `each_switch_changes_only_what_the_catalog_names` and `dss_opens_only_what_the_catalog_marks`.
- H2 (discarded): `judge_path` ignores `issued_from` for depth > 0. Refuted: the `fresh` closure is built per certificate inside the loop (`revocation.rs:301-333`).

## Story
Under `ValidationPolicy::strict()`, the revocation of each TSA's chain (signature timestamps and document timestamps) accepts only data issued at most 24 h before the control date. An older CRL that says "not revoked" does not count (AC1). Under `dss()`, the verdict stays DSS's (AC2). A test with a stale TSA CRL and a TSA key revoked since shows the rejection under `strict()` (AC3). Owns: `crates/nacre-validate/`.

## Current code
- `validate.rs:330-438` `Context::judge`: builds one `RevocationPool` from the CMS CRLs, the token CRLs, the `/DSS` CRLs and the OCSP responses (`:356-366`). Then it computes the best-signature-time as the min over the signature timestamps (`:368-377`) and the later document timestamps (`:378-381`), then the signer's `issued_from` (`:385-386`), then `judge_path` on the signer (`:406-414`).
- `validate.rs:522-545` `proven_time`: verifies the token, builds the TSA path at `self.at` (`Purpose::Timestamping`, `Rules::STRICT`), refuses a CA without SKI, then calls `judge_path(&path, pool, self.source, self.at, None, None, self.policy)`. If the token verifies, it returns `genTime` when that is at or before `self.at`.
- `validate.rs:486-515` `document_time`: hashes the document timestamp's signed bytes, then calls `proven_time`.
- `revocation.rs:290-372` `judge_path`: with `issued_from = None`, every verifying item within the certificate's validity counts. The latest one decides.
- `policy.rs:62-66`: the switch's doc says "With no proof of existence…", and `dss()`'s doc lists "for a signature with no timestamp, a stale…" (`policy.rs:135-136`).

## Attachment points
- `validate.rs:542`: the only change in logic, the `None` replaced by the window when `self.policy.require_fresh_revocation` is set.
- `validate.rs:385-386`: the same expression for the signer. Factor it into one private `Context` method used by both sites.
- Docs to bring in line (same crate): `policy.rs:62-66` and `:135-136`, `revocation.rs:24-33` (`FRESHNESS_TOLERANCE`: "a signature with a proof of existence keeps DSS's rule"), `validate.rs:82-91` (`validate_with_revocation`: "With a best-signature-time from a timestamp, freshness is not judged"), `validate.rs:383-384`, `validate.rs:517-521` (`proven_time`), `lib.rs:31-36`.
- Outside Owns but writable (po-bounds lets any `docs/` path through, `.polype/hooks/po-bounds.sh:5`): `docs/security/attacks/revocation.md:87` (prose "Sans preuve d'existence (aucun horodatage)…") and `:94` (row). One new row for the TSA attack.

## Verified interfaces
- `pub(crate) fn judge_path(path: &CertificatePath, pool: &RevocationPool, source: Option<&dyn RevocationSource>, time: SystemTime, issued_from: Option<SystemTime>, issuers_at: Option<SystemTime>, policy: &ValidationPolicy) -> Result<(), RevocationDefect>` (`revocation.rs:290-298`).
- `pub(crate) const FRESHNESS_TOLERANCE: Duration` = 24 h (`revocation.rs:33`), already imported in `validate.rs:18`.
- `ValidationPolicy::require_fresh_revocation: bool`, on in `strict()` (`policy.rs:116`), off in `dss()` (`policy.rs:149`). `SWITCHES` lists it (`tests/support/mod.rs:136-138`).
- Test fixture `Pki` (`tests/revocation.rs:33-160`): root, intermediate, then signer and TSA, both under the intermediate. `stamped()` gives a B-T at 2026-10-22T08:00Z. `judge` runs `validate_with_revocation` at 2026-10-23T00:00Z. `judge_under(pdf, at, policy)` takes a policy. `intermediate_crl` and `root_crl` are dated 22nd 10:00 (14 h, fresh). `document_timestamp(pdf, &dyn TimestampAuthority)` comes from `forge` (`tests/support/forge.rs:825`). `strict_without` is at `revocation.rs:499`, `control_date()` at `:495`.

## Traps
- The signer and the TSA share the intermediate in `Pki`. One stale intermediate CRL therefore leaves the TSA with no data: under `strict()` it proves no time, so the signer falls under its own window and gets `Missing` → `CERTIFICATE_CHAIN_GENERAL_FAILURE`, `best_signature_time = None`. Under `dss()` the same file still gives `TOTAL_PASSED` with POE. Both hold on one file.
- `policy.rs` `each_switch_changes_only_what_the_catalog_names` parses every catalogue page (`tests/policy.rs:340-380`). It keys only rows naming a corpus file of `tests/corpus/attacks/`. A `revocation.md` row that names tests and no corpus file is ignored by it. It passed in scratch with the fix.
- Campaign (`tests/campaign.rs:205-235`): a `strict()` difference must be explained by at most three switches. A case that needed three before and now also needs `require_fresh_revocation` would go unexplained. The campaign gives Nacre the bench revocation source (`campaign.rs:9-10`), and that source answers with the bench's current CRLs. The bench regenerates its keys and CRLs at start (`conformance/campaign/README.md`), so the risk is low on a fresh bench. A bench up for over 24 h could move strict rows. Same for the `#[ignore = "conformance"]` tests that confront `strict()` on B-T files (e.g. `revoked_after_the_bench_stamp_passes`, `tests/conformance.rs:248`).
- The bench cannot be started in this pass (coordinator message): the campaign and conformance runs are checks for the implementer's run, when the lead frees the bench.
- Consequence to write in the docs: under `strict()`, offline, an old archive whose TSA has only old CRLs gets no proof of time; a `RevocationSource` that answers fresh data restores it. This is the intended Nacre-only departure.
- No migration, no new dependency. The public API does not change: `#[non_exhaustive]` struct, no new field.

## Open questions
- Does the switch widening need an ADR? ADR-0031's table (`docs/decisions/0031-…md:57`, inherited from ADR-0026 `:38`) says "with no proof of existence, count only 'not revoked' data issued within 24 h". A TSA's revocation data has no proof of existence in Nacre, so the row already covers it: the code only failed to apply it. The plan writes no ADR, and the reserved ADR-0032 stays unused. If the lead reads it as a widening like ADR-0030's (which widened `ignore_expired_certs_on_crl` to OCSP), it needs a superseding ADR, which the planner did not write.

## Complexity
2 → 2. One logic line and one factored helper, one test flipped, one test added, docs in line.

## Split
—
