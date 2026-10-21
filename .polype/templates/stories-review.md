# Stories review — <product>

Stories reviewed: `docs/stories.md`, against `<docs/prd.md | docs/brief.md>`, in a context that did not write them. Findings rated critical, major or minor.

Review status: <complete | blocked>

## When blocked
- Failure cause: <what failed, quoting what was found>
- Missing: <file, section or setting>
- Required adaptation: <what must change before retrying>
- Next action: <command or human action>

## Coverage
| Scope item | Source section | Covered by | Covered |
| --- | --- | --- | --- |
| <core-loop line, angle, wedge or premise> | <## Core loop \| ## Angle \| the wedge \| ## Premises> | <story ids, or none> | <yes \| no> |

## Exclusions
| Excluded item | Source section | Revived by | Revived |
| --- | --- | --- | --- |
| <graveyard feature or non-goal> | <## Graveyard \| ## Wedge & non-goals> | <story ids, or none> | <yes \| no> |

## Checks
- [ ] Exclusions: no story revives an excluded item, under any name — a PRD's graveyard feature or a brief's non-goal
- [ ] No technical layer dressed as a story; contract stories meet their conditions
- [ ] Every criterion can be checked by one test
- [ ] Dependency order: no dependency on a later or unknown id
- [ ] Complexity: no 5 left unsplit, every 4 names its risk
- [ ] Ids: `s<number>-<slug>`, unique, numbered in file order
- [ ] Owns: every story declares one; no two stories with no dependency between them hold entries that overlap by the overlap rule of check 8 of the `stories-review` skill

## Findings
<one per line: severity — story id — the problem>

## Not verified
<what this review did not check, why, and what a person should do instead>

Max severity: <critical | major | minor | none>
Stories ready: <yes | no>
