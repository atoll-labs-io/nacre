# Review — <id>

[Story](../stories.md) · [Plan](../plans/<id>.md) · [Verification](../verif/<id>.md)

Diff reviewed: `git diff <Target branch>...story/<id>`, in a context that did not write it. Findings rated critical, major or minor.

Review status: <complete | blocked>
Fix loop: <0 for the first review, then 1, 2>
Reviewed tree: <40 hex — git rev-parse 'story/<id>^{tree}', taken before the review starts>

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
- [ ] `po-gate verif-current <id>` → <passes, record reused | fails or missing → suite and type check run here, with results>
- [ ] `po-gate qa-current <id>` (a story that goes to QA, `AGENTS.md` Law 1) → <passes, verified QA findings carried to Findings | fails → review blocked | not required: the story does not go to QA>

## Plan
- [ ] Each task present; nothing outside the plan
- [ ] Each run interdict checked, named one by one

## References
- [ ] Every import, call, API and configuration key opened and confirmed
- [ ] No value that only looks right

## Rules
- [ ] `AGENTS.md` conventions respected
- [ ] No accepted ADR contradicted

## Tests
- [ ] Floor: `po-gate floor-guard <id> <Target branch>` → <0 nothing lowered | 1 each flag graded, listed under Findings | 2 review blocked>
- [ ] Assertions pin down the acceptance criteria; none of the six empty test shapes
- [ ] Within `Test budget`, or the excess is justified in the plan
- [ ] Bite: <rule disabled> → <N> failing tests → undone, `git diff --exit-code` clean
- [ ] Tests made useless by the story are removed, or keeping them is explained

## Neighbours
- [ ] Other callers of the changed code read; nothing broken

## Lenses
Lenses run: <security | migration | dependencies | performance — each with the path or content that triggered it | none>
- [ ] Each lens finding graded on the scale above and listed under Findings

## Findings
- <critical|major|minor> — <path>:<line> — <the problem>
<one list item per finding, opening with its severity as above; its further lines indented under it; never a heading; `none` when there is none; a finding never starts with `Ship allowed:`, since any line that does closes the review's verdict block>

## Not verified
<what this review did not check, why, and what a person should do instead; every item of the QA report's `## Not seen`; for a `scene` story, each viewpoint no capture shows>

Max severity: <critical | major | minor | none>
Ship allowed: <yes | no>
