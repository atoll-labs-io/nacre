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
