---
track: flow
validated: no
---
# Plan (short track) — <id>

[Story](../stories.md)

Written by the planner. On the short track this one file stands in for both the research and the plan: there is no `docs/research/<id>.md`. Keep it to about 150 lines.

## Verified facts
<What the code actually does around this story, each fact opened in the code and given with its `path:line`. Any assumption of the story that proved wrong comes first. The implementer and the reviewer read this section in place of a research file.>

## Escalation signals
<Each escalation signal, marked `absent`, with where it was checked — once on the story text before reading the code, once after reading it. A signal present sends the story to the full track and no short plan is written: the planner takes that track in the same lane, and a technical choice also puts the line `Technical choice: waiting for a human` in that plan, as the planner's `## Limits` says.>

| Signal | Before reading the code | After reading the code |
| --- | --- | --- |
| Migration | absent — <where checked> | absent — <where checked> |
| New screen | absent — <where checked> | absent — <where checked> |
| Authorization or tenant scope | absent — <where checked> | absent — <where checked> |
| API contract | absent — <where checked> | absent — <where checked> |
| New dependency | absent — <where checked> | absent — <where checked> |
| Technical choice that deserves an ADR (library, pattern, data model) | absent — <where checked> | absent — <where checked> |
| Defect to fix (`Fixes` or `Corrige` line) | absent — <where checked> | absent — <where checked> |

## Story
<restatement and acceptance criteria>

## Reuse
<For each piece of new code the tasks write, the first rung that holds and why each rung above it fails. The rungs, in this order: already in this repository, cited by `path:line`; the standard library or the platform; a dependency already installed; new code. Add no option, setting or abstraction the story does not ask for. The ladder never cuts validation at a trust boundary, security, or the error handling that keeps data from being lost. A plan that writes no new code says so in one line instead of leaving this section out.>

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |

## Acceptance tests
<The oracle: the tests the plan's author wrote from the story's acceptance criteria, before any code, in files of their own that the story's `Owns` lists. Each test goes through the interface the tasks below fix, never an internal detail. One test per acceptance criterion that a test can check, each counted in `Test budget`. The implementer adds its own tests to other files, so no sum moves, and changes an oracle file only through `## Oracle changes` of the verification record. For a story where no criterion can be checked by a test (purely visual), or an exploration story, which its measure judges, write `—` with its reason in place of both tables. The sum is exactly what `cksum < <path>` prints, taken once the file is written.>

| Oracle file | cksum |
| --- | --- |
| `<path>` | `<crc> <size>` |

| Criterion | Test |
| --- | --- |

## Tasks
<Six at most; more means the story leaves the short track.>

1. [ ] <task — and the test able to fail for it>
2. [ ] <task>

## Scene viewpoints
<Only for a story whose `Surface` is `scene`; write `—` for any other. One line per viewpoint to capture, giving its scene, its position, its target, what it must show, and its framing, scale and light. A line that names no scene aims at the project's main scene. The QA captures these viewpoints and the review judges the scene against them.>

## Run interdicts
<One line each: files that must end with an empty diff, commands not to run, nearby work out of scope. Only what a reviewer can verify.>

## Files touched
<expected list>

## Test strategy
<Which test at which layer, following the testing-doctrine skill, within `Test budget`.>

## Done when
<the repository's definition of done, applied to this story>
