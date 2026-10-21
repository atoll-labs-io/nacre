# nacre — Polype settings

This file is the project's. Polype's installer never rewrites it; `/po-setup` writes it once and you edit it afterwards. Rules live in `AGENTS.md`, which the installer regenerates — do not edit that one.

Format: one `Name: value` per line inside the blocks below, with no comment after the value (anything after the colon is the value, except a final `(forge)` or `(chosen)` on `Ship confirmation`, which records where the value came from). After a change, rerun the installer so the conventions at the bottom reach `AGENTS.md`.

## Pipeline

```
Merge mode:        pr
Target branch:     main
Plan validation:   autonomous
Ship confirmation: automatic (chosen)
Test budget:       25
Verification mode: record
Full suite:        execute-end
E2E stage:         ship
E2E scope:         nominal
E2E browsers:      —
Build stage:       ship-if-route
Platform:          lib, cli
QA stage:          surfaces
Issue tracker:     github
Worktree root:     .worktrees/
ADR directory:     docs/decisions/
Entry mode:        new
Design source:     —
Design skill:      —
Design tool:       —
Story track:       auto
Flow threshold:    2
Parallel:          3
Max attempts:      2
Tracker:           none
Model strong:      opus
Model light:       sonnet
Light up to:       2
Project CLAUDE file: absorbed
```

| Setting | Values |
| --- | --- |
| Merge mode | `pr` — a pull request to the target branch, landed as one commit · `local` — only for a repository without a remote: the commit lands on this machine and nothing is pushed |
| Target branch | where finished stories land |
| Plan validation | `human` — you approve each plan · `autonomous` — the planner approves its own and says so; the default, since a human is asked only for the reasons ADR-0077 names |
| Ship confirmation | `human` — you approve each merge · `automatic` — the review gate is enough. A final `(forge)` means the value follows the repository and `/po-ship` keeps it in line at each ship; `(chosen)` is the person's choice on a solo repository, never rewritten by an agent; no suffix reads `(forge)`. A collaborative repository gives `human (forge)` whatever the line says |
| Test budget | maximum tests per story before the plan must justify more |
| Verification mode | `record` — a review reuses a current verification record · `rerun` — a review repeats the checks |
| Full suite | where the complete unit suite runs: `execute-end` · `ship` · `both` |
| E2E stage | where end-to-end tests run: `ship` · `ci` · `—` |
| E2E scope | how much end-to-end runs; `nominal` means one happy path |
| E2E browsers | browsers used before ship, e.g. `chromium`; `—` leaves the project default. Ship always uses all of them |
| Build stage | where the production build runs: `ship-if-route` (only when routing or a manifest changed) · `ship` · `ci` · `—` |
| Platform | what the project builds, one or more of `web` · `mobile` · `cli` · `api` · `lib` · `xr` · `robot`, separated by commas; it decides which boilerplate profiles `/po-setup` offers and which `Surface` a story may declare (ADR-0054, ADR-0055) |
| QA stage | `screens` — /po-qa walks the screens a story touches before its review · `surfaces` — /po-qa checks every story whose `Surface` is not `—`, with the driver of that surface (ADR-0054) · `—` — no QA stage |
| Issue tracker | where ideas, features and defects to handle are filed, and the findings a shipped review leaves open: `github` · `taskwarrior` · `—`; `—` sends them to the person |
| Worktree root | folder that holds story worktrees, ending with `/`; kept out of git by `.gitignore` |
| ADR directory | where the project's ADRs live, with its own numbering; ends with `/` |
| Entry mode | where the project starts: `replace` — build an internal replacement of a paid SaaS · `adapt` — a competing product with its own angle · `new` — an idea from scratch · `—` not chosen yet |
| Design source | who draws the screens: `internal` — screens drawn in the repository by an agent skill · `external` — a tool outside the repository · `—` means design commands stop and ask |
| Design skill | skill that draws the screens when `Design source` is `internal`; `—` otherwise |
| Design tool | tool the screens come from when `Design source` is `external`; `—` otherwise |
| Story track | `full` — every story walks every stage · `flow` — every story takes the short track · `auto` — the short track up to `Flow threshold` |
| Flow threshold | highest story complexity allowed on the short track when `Story track` is `auto` |
| Parallel | how many story lanes the fleet driver runs at once |
| Max attempts | fix runs a story gets before the fleet driver hands it to a human |
| Tracker | where the fleet publishes story state: `none` · `github` when the repository has a remote |
| Model strong | the model every deciding subagent (planner, designer, reviewer, qa, stories-reviewer) runs on: a name the Agent tool accepts, or `—` for the session's model |
| Model light | the model the implementer runs on for a story whose complexity is at most `Light up to`: a name the Agent tool accepts, or `—` for the session's model |
| Light up to | highest story complexity whose implementer runs on `Model light`; `—` means never |
| Project CLAUDE file | `absorbed` — the installer moves a root `CLAUDE.md` or `CLAUDE.local.md` into `AGENTS.local.md` and the pre-commit refuses one at any depth (ADR-0086) · `kept` — both stay, the root `CLAUDE.md` starts with `@AGENTS.md` and the pre-commit lets them through (ADR-0089); with the line missing nothing is touched, and the installer, `check` and `po-session` name the setting |

## Commands

```
Package manager:   —
Install:           —
Test:              —
Typecheck:         —
E2E:               —
Build:             —
Dev:               —
```

Agents run these exactly as written. `—` means the project has no such command, and no agent will make one up. `Test` has to accept paths to test files, so a single task's tests can run alone. `Dev` starts the development server, or whatever serves what a person looks at (the web render of a mobile app), and prints the address it serves; `—` when the project has nothing to serve. QA of a `screen` surface needs it; the other drivers start what they check themselves.

## Conventions

<< layout, stack, patterns, naming, commit style >>
