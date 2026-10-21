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
