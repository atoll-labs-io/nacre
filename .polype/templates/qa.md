# QA — <id>

[Story](../../stories.md) · [Plan](../../plans/<id>.md)

Scope: the story's surface, what `git diff <Target branch>...story/<id>` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: <driver file(s) of qa-drivers> — surface <surface>, platform <platform>
Evidence: <captures | transcripts | logs and recordings>
Tool: <the tool of the session that took the evidence>
Origin: <the address `Dev` printed when it started, the only one visited, or — when the driver serves nothing>

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| <criterion, route, command or scene> | <yes | no> | <as expected | finding N | not reached — reason> |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding <N> — <short title>
Severity: <critical | major | minor>
Status: <verified | probable | unverified>
Steps to reproduce:
1. <first action, from the starting point the driver names>
2. <next action>
Capture: <docs/qa/<id>/<file>: capture, transcript or log | none — reason>
Expected: <what the story or the design says should happen>
Observed: <what the surface did>

## Not seen
- <criterion or item> — <why: behind a sign-in, no observable effect, the surface could not reach that state, only real hardware, an iOS simulator or a headset would show it, the walk stopped>

Tree: <40 hex — git rev-parse 'story/<id>^{tree}', taken before the walk>
QA status: <complete | blocked>
