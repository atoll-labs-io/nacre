# Decisions log

What the project lead decided alone, one row per decision, appended and never rewritten: `Date` is `YYYY-MM-DD`, `Story` is a story id or `—` when the decision concerns no single story.
A decision the person took is not logged here: it is an ADR or a story.

| Date | Story | Decision | Reason |
| --- | --- | --- | --- |
| 2026-10-21 | s01-workspace-contract | Launched alone in wave 1 | Every other story depends on it |
| 2026-10-21 | s01-workspace-contract | Ran the planner although `Install` (`cargo fetch`) failed in the fresh worktree | No `Cargo.toml` exists before s01, which creates it |
| 2026-10-21 | s01-workspace-contract | Implementer on `Model strong` (opus) | The research rescored the story from 2 to 3, above `Light up to: 2` |
| 2026-10-22 | s01-workspace-contract | Recorded the QA report from the qa subagent's answer and made the evidence commit | The harness refused the subagent's own write of `report.md` |
| 2026-10-22 | s01-workspace-contract | Re-review at `Fix loop: 1` with no code change | The first review carried no `Review status:` line, so `po-gate ship-allowed` refused it; one `Max attempts` unit spent |
| 2026-10-22 | s01-workspace-contract | Checked by hand that Patelle was untouched (status empty, `story/s01-sign-decision` at `4ed5c64`) | The reviewer could not run git outside the story worktree |
| 2026-10-22 | s01-workspace-contract | Landing commit and pull request titled in English, not with the French story title | The owner's global rule requires commit messages in English |
| 2026-10-22 | s01-workspace-contract | Held review finding 2 (invalid test-signer secret, vague error) out of the issue tracker | Its text bears on a secret, which `/po-ship` keeps with the person (ADR-0077) |
| 2026-10-22 | s02-conformance-harness | Launched in wave 2 with s03 and s04 (disjoint Owns), ADR-0011 reserved | Its only dependency, s01, shipped |
| 2026-10-22 | s02-conformance-harness | Lane handed to the person: plan waits for the technical choice of ADR-0011 (bench PKI, TSA, OCSP on OpenSSL) | The planner drafted a structural choice; ADR-0077 sends it to a human |
| 2026-10-22 | s03-cms-signed-data | Launched in wave 2, ADR-0012 reserved (unused) | Its only dependency, s01, shipped |
| 2026-10-22 | s04-pdf-read | Launched in wave 2, ADR-0013 reserved (unused) | Its only dependency, s01, shipped |
| 2026-10-22 | s03-cms-signed-data | Plan approved without a human (planner, `Plan validation: autonomous`) | No technical choice waiting |
| 2026-10-22 | s04-pdf-read | Plan approved without a human (planner, `Plan validation: autonomous`) | No technical choice waiting |
| 2026-10-22 | s03-cms-signed-data | Implementer on `Model strong` (opus) | Research rescored complexity 3 → 4, above `Light up to: 2` |
| 2026-10-22 | s04-pdf-read | Implementer on `Model strong` (opus) | Complexity 3, above `Light up to: 2` |
| 2026-10-22 | s04-pdf-read | Let the implementer copy the DSS certified PDF (LGPL-2.1) and the TDF statutes PDF (no stated licence) into the public test corpus, credited in its README | The plan settled it; the licence question was sent to the person, who can still ask for the fallback corpus |
| 2026-10-22 | s03-cms-signed-data, s04-pdf-read | Recorded both QA reports from the qa subagents' answers and made the evidence commits | The harness refused the subagents' own writes of `report.md` |
| 2026-10-22 | s03-cms-signed-data, s04-pdf-read | Added a driver note to the reviewer prompt that `Review status:` is required | s01's first review lacked it and cost a re-review |
| 2026-10-22 | s04-pdf-read | Shipped before s03 | Its review passed first |
| 2026-10-22 | s03-cms-signed-data, s04-pdf-read | Shipped with a major finding open each (pivot or identity rule without a biting test), filed as #35 and #29 | Each reviewer allowed the ship; the code is correct, only the regression guard is missing |
| 2026-10-22 | s03-cms-signed-data, s04-pdf-read | Landing commits and pull requests titled in English | The owner's global rule requires commit messages in English |
| 2026-10-22 | s05-pdf-revision | Launched alone in wave 3, ADR-0012 reserved (unused) | Its dependency s04 shipped; every other unshipped story waits on s02, itself waiting for the person's ADR-0011 choice |
| 2026-10-22 | s05-pdf-revision | Plan approved without a human (planner, `Plan validation: autonomous`) | No technical choice waiting |
| 2026-10-22 | s05-pdf-revision | Implementer on `Model strong` (opus) | Research rescored complexity 3 → 4 |
| 2026-10-22 | s05-pdf-revision | Recorded the QA report from the qa subagent's answer and made the evidence commit | The harness refused the subagent's own write of `report.md` |
| 2026-10-22 | s05-pdf-revision | Shipped with a major finding open (field-name validation incomplete), filed as #46 | The reviewer allowed the ship |
| 2026-10-22 | — | Filed #44 asking s02's `conformance.yml` to install qpdf | s05's `qpdf --check` test is `#[ignore = "conformance"]` and no workflow installs qpdf |
| 2026-10-22 | — | Closed #32 by hand | Fixed by s05 (PR #45); the PR body's second "fixes" did not auto-close it |
| 2026-10-22 | s02-conformance-harness | Amended the plan with the owner's test-key decision (PKI regenerated at each bench start) and reran the implementer on its staged work | The first run's commit was refused for committing private keys; the owner chose "no key in git" |
| 2026-10-22 | s02-conformance-harness | Added a daily schedule to `conformance.yml` (task 8) | The owner asked to catch drift at once; `Cargo.lock` is not versioned |
| 2026-10-22 | s02-conformance-harness | Kept the responders at `/cgi-bin/tsa` and `/cgi-bin/ocsp` instead of `/tsa` and `/ocsp` (ADR-0011's wording) | busybox httpd runs CGI only under `/cgi-bin/`; s07, s09 and s10 code against these URLs |
| 2026-10-22 | s02-conformance-harness | Checked by hand that `conformance/dss/` matches Patelle's pinned DSS (same 6.5.1 archive and SHA-256; only the planned port, anchor-store and comment edits differ) | The reviewer could not read Patelle's repository |
| 2026-10-22 | s02-conformance-harness | Fix run 1: install `qpdf` in `conformance.yml` (#44) | The ship's CI failed on s05's `qpdf_check_is_clean` |
| 2026-10-22 | s02-conformance-harness | Fix run 2: run only `nacre-sig` examples in CI instead of every workspace example | The ship's CI ran s03's `forge_attacks` generator, which needs an argument; `Max attempts` reached, the ship then passed |
| 2026-10-22 | s02-conformance-harness | Stopped and removed the local bench containers left running by the implementer | Their worktree had been removed at cleanup |
| 2026-10-22 | s38-error-kind | Removed the first s38 worktree (`--force`, its research and plan backed up and restored) and re-forked it from the corrected story | The story's Owns had to include `crates/nacre-pdf/Cargo.toml`, and po-bounds reads Owns at the fork point |
| 2026-10-22 | — | Restored s38 in `docs/stories.md` (PR #57) | A lead script had built PR #56 from a stale `docs/stories.md` in the wrong worktree and removed s38 |
| 2026-10-22 | s38-error-kind | Implementer on `Model light` (sonnet) | Complexity 2, at `Light up to: 2` |
| 2026-10-22 | s38-error-kind | Held two review findings mentioning the test signer's secret out of the tracker | Their text bears on a secret (ADR-0077) |
| 2026-10-22 | — | Closed #44 by hand | Fixed by s02 (PR #58) |
| 2026-10-22 | s07-tsp-client, s09-revocation-crl, s13-pkcs11-signer | Re-ran QA after each fix run 1, then the review at `Fix loop: 1` | A review blocked on stale QA spends no attempt; the lead had skipped QA once before |
| 2026-10-22 | s07-tsp-client, s09-revocation-crl, s13-pkcs11-signer, s15-validate-revisions, s08-pades-bt | Wrote the qa subagents' reports to `docs/qa/<id>/report.md` verbatim | The harness refused the subagents' Write on report files; the lead transcribes as it does for reviews |
| 2026-10-22 | s13-pkcs11-signer | Waited for the `conformance` job before merging PR #79 | The reviewer asked that the SoftHSM 2.6.1 run be read; 7/7 passed |
| 2026-10-22 | — | Ship script: also hold findings mentioning `unsafe`; read a multi-line `Lenses run:` block | ADR-0013 `deny`/`forbid` finding; s07 issues #82–#85 were filed although its security lens ran |
| 2026-10-22 | s07-tsp-client | Landing title taken from the story ("Obtain and verify an RFC 3161 time-stamp token") | The first landing commit used a shorter title |
| 2026-10-22 | s15-validate-revisions | Plan validated without a human; stricter-than-ISO rules kept (annotations under P=3, fill on an uncertified document) | Fails closed; raised to the person |
| 2026-10-22 | s15-validate-revisions | Held the ship after loop 0 (four majors) and after loop 1 (one major) for the person | Security-relevant verdicts; the person chose a fix run after loop 0 |
| 2026-10-22 | s08-pades-bt, s10-revocation-ocsp | Opened both lanes; held s39 back | s39's Owns `crates/nacre-revocation/src/` overlaps s10's `crates/nacre-revocation/`; s10 comes first in `docs/stories.md` |
| 2026-10-22 | s08-pades-bt, s10-revocation-ocsp | Reserved ADR-0017 and ADR-0018, skipping 0015 | 0014 was s15's; 0015 left as a gap rather than risk a collision |
| 2026-10-22 | s08-pades-bt | Plan validated without a human; implementer on `Model light` (sonnet) | Complexity 2 |
| 2026-10-22 | s10-revocation-ocsp | Lane sent to the person: ADR-0018 (OCSP structures) | `x509-ocsp` 0.2 is on `der` 0.7; the plan holds `Technical choice: waiting for a human` |
| 2026-10-23 | s08-pades-bt | Merged PR #87 after reading `bench_signature_is_pades_baseline_t ... ok` in the conformance log | Criterion 1 was seen by neither QA nor the reviewer |
| 2026-10-23 | s08-pades-bt, s11-pades-blt, s12-pades-blta | Reworded criteria to `sign_at_level`, the TSA designated as the cause, a declared token bound | `sign` keeps its signature for its callers outside s08's Owns (s08 research) |
| 2026-10-23 | s10-revocation-ocsp | Started fix run 1 although the review allowed the ship | Its one major was an untested security rule (delegate valid at `producedAt`); same call the person made for s15 loop 0 |
| 2026-10-23 | s10-revocation-ocsp | Plan validated after the person chose ADR-0018 option 1 | Technical choice settled |
| 2026-10-23 | s11-pades-blt | Plan validated without a human; re-asked the reviewer once for the findings shape | `po-gate findings-shape` refused `- **[minor] …**` items |
| 2026-10-23 | s11-pades-blt, s39-error-kind-from-sources | Opened both lanes after s10 shipped; reserved ADR-0019 and ADR-0020 | s39's overlap with s10 was gone |
| 2026-10-23 | s39-error-kind-from-sources | Lane sent to the person: ADR-0020 and whether revocation data is checked by the source | The plan holds `Technical choice: waiting for a human`; its Owns must widen into `crates/nacre-pades/` |
| 2026-10-23 | s12-pades-blta | Widened Owns with `conformance/pki/`, `conformance/check.sh`, `conformance/README.md` and re-forked the lane | Criterion 5 needs a second bench TSA; po-bounds reads Owns at the fork point; no running lane owns `conformance/` |
| 2026-10-23 | s11-pades-blt | Reworded criterion 1 with `issuers` | The s11 plan's corrected criterion |
| 2026-10-23 | — | Closed or labelled the misfiled s02/s07 issues through octo; kept #65 open | The person delegated it; #65's input is the local DSS only |
| 2026-10-23 | s12-pades-blta | Started fix run 1 although the review allowed the ship | Its major: `extend` returned `Ok` without storing the previous TSA's data |
| 2026-10-23 | s12-pades-blta | Shipped after loop 1 despite a fail-closed interop major, then held the merge when CI's conformance job failed | Majors do not block; a failed ship goes back to a fix run |
| 2026-10-23 | s12-pades-blta | Fix run 2 on the CI failure: root cause first | Concurrent `openssl ts -reply` calls raced on the bench TSA's serial file; fixed with `flock`, proven by parallel requests and a green CI run |
| 2026-10-23 | s11-pades-blt | Filed #95–#99, held one finding mentioning "token" | Keyword filter of the ship script |
| 2026-10-23 | s12-pades-blta | Held every finding for the person | The security lens ran on the bench CGI scripts |
| 2026-10-23 | s39-error-kind-from-sources | Widened Owns and reworded the CRL criterion, added the OCSP one; re-forked the lane | ADR-0020 option 1 (chosen by the person) breaks callers in nacre-pades, nacre-cms and two test harnesses; `HttpCrlSource` never verifies a CRL signature |
| 2026-10-23 | s39-error-kind-from-sources | Kept "the source does not judge the CRL signature; s17 does" | The person answered the ADR only; this is the plan's default and fails no caller |
| 2026-10-23 | s15-validate-revisions | Fix run 3 then ship with one open major | The person granted the third run past `Max attempts`, then chose to ship and open s40 |
| 2026-10-23 | s40-validate-ssa-by-effect | Wrote the story the person asked for; made s16 depend on it | The open SSA shape leaves an attacker's signature without a defect; once s16 judges chains it could read as valid |
| 2026-10-23 | — | Ship script also holds findings mentioning SSA, sneaky or attacker | The s15 major becomes the s40 story, not a public issue |
| 2026-10-23 | s40-validate-ssa-by-effect | Fix runs 1 and 2 although the reviews allowed the ship; fix run 3 granted by the person | Each major was an SSA shape or an untested guard, the story's very purpose |
| 2026-10-23 | s40-validate-ssa-by-effect | Kept a visible-rect signature without `/AP` refused, against the planner's proposal | Loosening a security rule is not decided in passing |
| 2026-10-23 | s16-validate-chain | Widened Owns with `docs/security/attacks/cms.md` and `pades.md`, re-forked the lane | Both attack files hand the chain check to s16 (stories review major) |
| 2026-10-23 | s16-validate-chain | Accepted the plan's `INDETERMINATE / TRY_LATER` for a valid chain until s17 judges revocation | Fail closed; matches s17's no-data criterion |
| 2026-10-23 | s16-validate-chain | The person chose the EKU rule: judged on the signer only, critical or not, `id-kp-clientAuth` accepted; issuers' EKU decoded but not judged | Many PIV and qualified signing certificates carry `clientAuth`; RFC 5280 does not require EKU on CAs; DSS parity left to s18 |
| 2026-10-23 | s16-validate-chain | Fix runs 1 and 2 although the reviews allowed the ship; fix run 3 granted by the person | Each major was a downgrade path through unsigned data or an untested guard |
| 2026-10-23 | s16-validate-chain | Unsigned pool data (CMS `certificates`, `/DSS`) treated as hints that can never disqualify a path | Review and QA showed a third party could downgrade a valid signature without touching signed bytes |
| 2026-10-23 | s17-validate-revocation | Reworded AC1 and AC3 to the verdicts DSS 6.5.1 gives (`REVOKED_NO_POE`, `CERTIFICATE_CHAIN_GENERAL_FAILURE`) | The planner's spike (26 cases) showed DSS never gives the original ones; AC5 and the brief's success metric 2 require DSS's verdicts |
| 2026-10-23 | s17-validate-revocation | The person chose option 1: a signature without proof of existence accepts only revocation data issued at most 24 h before the control date (`FRESHNESS_TOLERANCE`) | Without it a stale "not revoked" CRL appended to `/DSS` passes a revoked B-B signer; deliberate divergence from DSS, to be listed by s18 |
| 2026-10-23 | s17-validate-revocation | Shipped at fix loop 1 with a held security major: the TSA path keeps DSS's rule, without the 24 h window | Needs two key compromises; the fix belongs to the person's decision, not to a third fix run |
| 2026-10-23 | s18-validate-level | The person chose ADR-0025 option A: the reported level is structural, as DSS 6.5.1 computes it | The s18 spike showed DSS keeps -T/-LTA on an invalid timestamp; one rule set, one oracle |
| 2026-10-23 | s18-validate-level | The person required 100 % identity with DSS, with no excluded case, and asked that stories be adapted | Brief metric 2; USF, `isa-no-xref` and `chain-malformed-extension` must follow DSS too |
| 2026-10-23 | s41-validation-policy | The person chose a runtime `ValidationPolicy` with `strict()` by default and `dss()` on request, one switch per Nacre rule, over cargo features | Feature unification would impose one mode on the whole graph and forbid testing both |
| 2026-10-23 | s41-validation-policy | The person chose that the 24 h window drops only "not revoked" data | An old proof of revocation stays a proof; restores `REVOKED_NO_POE` |
| 2026-10-23 | s42-tsa-freshness | The person chose a separate story for the TSA-path freshness window (s17 review, held security major) | Exploiting it needs two key compromises |
| 2026-10-23 | s18-validate-level | Paused the s18 lane after its first plan and created s41 and s42; s18 now depends on s41 | 100 % DSS needs the policy first; both own `crates/nacre-validate/` |
| 2026-10-24 | s41-validation-policy | Aligned AC1 and AC2 on the planner's findings: eight switches instead of five, out-of-period certificates judged after revocation as DSS does, `nacre-pdf` already reports trailing data; complexity 5 → 4; lane re-forked | The three added switches keep today's strict behaviour, which AC2 needs to flip under `dss()`; c26 shows `OUT_OF_BOUNDS_NOT_REVOKED` |
| 2026-10-24 | s41-validation-policy | Fix run 1 although the review allowed the ship | The major was a regression of `strict()` on a security rule (stale CRL revoking after the judged time) |
| 2026-10-24 | s43-dss-parity | The person split s18: the six `dss()` divergences s41 left become s43, before s18 | Smaller reviews; s18 keeps the level and the campaign |
| 2026-10-24 | s43-dss-parity | The person chose a ninth switch `refuse_unsupported_sub_filters` (on in `strict()`) and that `nacre-pdf` reports a non-reference `/V` instead of failing, a breaking change of `SignatureField` | `strict()` never gets laxer; the campaign needs DSS's verdict on both |
| 2026-10-24 | s18-validate-level | The person chose that the campaign covers every corpus, `nacre-pdf`'s hostile and real files included; s18 Owns gains `crates/nacre-pdf/` | 100 % DSS with no exclusion |
| 2026-10-24 | s18-validate-level | AC2 reworded: ESS `signingCertificate` v1 also gives a baseline level | Spike case n09 |
| 2026-10-24 | s44-feature-matrix | Turned the person's request "tester que les activations de crate fonctionnent proprement" into s44 (CI over every feature combination) and an AC of s20 for the facade | Today CI runs `--all-features` and the default set only, and dev-dependencies re-enable `http` |
| 2026-10-24 | s43-dss-parity | Turned the person's request "s'assurer que les atténuations ne laissent rien passer" into two ACs: each switch turned off alone changes only the verdicts its rule explains, over the whole attack corpus | Read "atténuations" as the policy switches that relax a rule |
