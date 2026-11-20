# Review — <id>

[Story](../stories.md) · [Plan](../plans/<id>.md) · [Verification](../verif/<id>.md)

<`po record` writes these lines, `Method version:`, `Recorded:` and the `Oracle:` line under `## Tests`; the answer starts below this note.>

Diff reviewed: `git diff <Target branch>...story/<id>`, in a context that did not write it. Findings rated critical, major or minor.

Review status: <complete | blocked>
Fix loop: <0 for the first review, then 1, 2>
Reviewed tree: <40 hex — git rev-parse 'story/<id>^{tree}', taken first>

## When blocked
- Failure cause: <what failed, with the error>
- Missing: <evidence, file, setting or access>
- Required adaptation: <what must change before retrying>
- Next action: <command or human action>

## Ownership
Diff listed with `git diff --name-only <Target branch>...story/<id>`, each path held against the story's `Owns` by the overlap rule of the `review-antihallu` skill.
- [ ] Every path inside `Owns`
- [ ] Outside `Owns` → major: <path — the `Owns` line it missed>
- [ ] Inside another running story's `Owns` → critical: <path — the story holding it and its worktree>
- [ ] No `Owns` line on this story → unverifiable scope, reported as such

## Evidence reused
- [ ] `po-gate verif-current <id>` → <passes, record reused | fails or missing → suite and type check run here>
- [ ] `po-gate qa-current <id>` (a story that goes to QA, `AGENTS.md` Law 1) → <passes, verified QA findings carried to Findings | fails → review blocked | not required: the story does not go to QA>

## Plan
- [ ] Each task present; nothing outside the plan
- [ ] Each run interdict checked, named one by one

## References
- [ ] Every import, call, API and configuration key confirmed
- [ ] No value that only looks right

## Rules
- [ ] `AGENTS.md` conventions respected
- [ ] No accepted ADR contradicted

## Tests
- [ ] Floor: `po-gate floor-guard <id> <Target branch>` → <0 nothing lowered | 1 each flag graded, listed under Findings | 2 review blocked>
- [ ] Assertions pin the acceptance criteria; none of the six empty test shapes
- [ ] Within `Test budget`, or the excess justified in the plan
- [ ] Bite: <rule disabled> → <N> failing tests → undone, `git diff --exit-code` clean
- [ ] Tests the story made useless removed, or kept with a reason

## Neighbours
- [ ] Callers of the changed code read; nothing broken

## Lenses
Lenses run: <security | migration | dependencies | performance — each with the path or content that triggered it | none>
- [ ] Each lens finding graded and listed under Findings

## Findings
- <critical|major|minor> — <path>:<line> — <the problem>
<one list item per finding, opening with its severity as above; its further lines indented under it; never a heading; `none` when there is none; a finding never starts with `Ship allowed:`, which closes the verdict block; a finding bearing on security opens `- <severity> — [security] — `, and `po record` keeps its text off the repository>

## Not verified
<what this review did not check, why, and what a person should do; every item of the QA report's `## Not seen`; for a `scene` story, each viewpoint no capture shows>

Max severity: <critical | major | minor | none>
Ship allowed: <yes | no>
