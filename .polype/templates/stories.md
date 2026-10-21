# Stories — <product>

Each story is a slice a user can actually use, described precisely enough that an agent builds it without asking. Its id, `s<number>-<short-slug>`, names every file the pipeline writes for it and its branch `story/<id>`.

**Complexity scale** — 1: simple create/read/update/delete · 2: a form, storage and a list · 3: business logic or several states · 4: third-party integration, payments or roles · 5: real time, migrations or external systems. A 4 names its main risk. A 5 is split before anyone plans it.

## <id> — <title>
**As** <who> **I want** <what> **so that** <why>.

- **Complexity**: <1–5>
- **Depends on**: <ids, or none>
- **Surface**: <what a person checks once the story ships: `screen` · `command` · `endpoint` · `scene` · `behaviour`, one the project's `Platform` admits by the table of the `agentic-stories` skill, or `—` when nothing is seen or run>
- **Owns**: <paths this story is allowed to change, each in backticks and separated by commas: a file path, a folder ending in `/`, or a glob where `*` stays inside one path segment and `**` spans any number of segments; any other text on the line is refused; stories whose entries overlap, by the overlap rule of check 8 of the `stories-review` skill, never run at the same time>
- **Fixes**: <optional, only on a story that fixes a defect: the defect and where it is recorded (`Issue tracker`, a defects file, a review finding); written `Corrige` in a French stories file. A story with this line takes the full track and is researched under the `diagnostic` skill>

### Acceptance criteria
- [ ] <an observable result, precise enough to turn into a test>

### Notes for the agent
<context a person would infer and an agent has to be told: files concerned, constraints, pitfalls, the screen or flow to imitate if there is one>
