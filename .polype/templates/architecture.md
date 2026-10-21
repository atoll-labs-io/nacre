# Architecture — <project>

Written by `/po-architect`, committed on the target branch. Research and planning read it before touching the code. Change it through `/po-architect` again: a decision that changes gets a new ADR superseding the old one.

## Base
- **Name**: <boilerplate name, "scaffolded default: <generator>" or "empty repository">
- **Origin**: <repository URL or generator command, version or commit>
- **Licence**: <licence of the base>
- **Profile**: <`boilerplates/<name>/profile.md` used as the starting point, or "analysis only">
- **Decision**: [ADR-<NNNN>](<ADR directory, relative to docs/><NNNN>-<slug>.md)

## Map
Where each kind of code lives, as found in the base. Each line names a path that was opened.

| Kind | Path | Example |
| --- | --- | --- |
| Routes / pages | <path> | <path:line> |
| Domains / features | <path> | <path:line> |
| Shared core | <path> | <path:line> |
| Migrations | <path> | <path:line> |
| Policies / access rules | <path> | <path:line> |
| UI components | <path> | <path:line> |

## Capabilities
One row per capability the project needs; a capability it does not need says so in the Brick column.

| Capability | Brick | Alternatives | ADR |
| --- | --- | --- | --- |
| <database> | <brick in use> | <bricks that could replace it> | [ADR-<NNNN>](<ADR directory, relative to docs/><NNNN>-<slug>.md) |

## Ownership
The paths a story may own alone, and the shared ones that only a contract story may change.
- <path> — <owned by one story at a time | shared: contract story only>

## Attachment points
Where new work plugs into the base: registration files, route tables, menus, schema entry points.
- <path:line> — <what gets added there>

## Commands
Quoted from `AGENTS.local.md`, never decided here.

| Setting | Value |
| --- | --- |
| Package manager | <value> |
| Install | <value> |
| Test | <value> |
| Typecheck | <value> |
| E2E | <value> |
| Build | <value> |

## Conventions
The rules live in the « Conventions » section of `AGENTS.local.md`, which every agent loads through `AGENTS.md`. This file does not repeat them.
