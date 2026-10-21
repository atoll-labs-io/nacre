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
