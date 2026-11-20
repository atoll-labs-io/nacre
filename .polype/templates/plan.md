---
validated: no
---
# Plan — <id>

[Story](../stories.md) · [Research](../research/<id>.md)

Branch `story/<id>`. Read `docs/research/<id>.md` first; this plan builds on it without repeating it.

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
1. [ ] <task — and the test able to fail for it, or for a purely visual task the visual check>
2. [ ] <task>

## Scene viewpoints
<Only for a story whose `Surface` is `scene`; write `—` for any other. One line per viewpoint to capture, giving its scene, its position, its target, what it must show, and its framing, scale and light. A line that names no scene aims at the project's main scene. The QA captures these viewpoints and the review judges the scene against them.>

## Run interdicts
<One line each: files that must end with an empty diff, commands not to run, nearby work that is out of scope. Only write what a reviewer can verify.>

## The pivot
<The decision this plan rests on and the two or three ways it could be wrong, each with what to compare it against. It tells the reviewer where to start looking, not where to stop.>

## Files touched
<expected list>

## Test strategy
<Which test at which layer, following the testing-doctrine skill, within `Test budget`. Automated tests and visual checks in separate lists.>

## Done when
<the repository's definition of done, applied to this story>
