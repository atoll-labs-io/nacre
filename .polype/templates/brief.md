---
product: <product name>
status: interviewing
date: <YYYY-MM-DD>
---
# Brief — <product>

`/po-brief` fills this file theme by theme, following the `interrogation` skill. `status` moves from `interviewing` to `approved` once, at `/po-brief`'s commit, when every exit criterion holds and every theme was approved on its own question; the brief is never shown again for reading.

**One-liner.** <What the product does and for whom, in one sentence a stranger understands.>

## Problem & evidence
<The last concrete time the problem cost someone something: who, when, what it cost.>

## Consumer & job
<The exact person or program that uses it, at which moment of their work, to do what.>

## Status quo & incumbents
<What people do today instead, the tools already on the market with their limits, and why extending one of them loses.>

## Wedge & non-goals
<The single capability that would be used daily if it were the only one shipped.>

Non-goals, at least three:
- <what this product will deliberately not do>

## Success metric
<The observable number or behaviour that says it works within a stated delay, how it is measured, and the one that would say it failed.>

## Premises
1. <A declarative sentence the brief rests on, agreed by the user.>

## Gap map
Status is one of `answered`, `defaulted`, `open risk`, `N/A`. A dimension marked ★ in the skill never stays blank.

| Dimension | Status | Evidence, default or risk |
| --- | --- | --- |
| <dimension> | <status> | <the evidence, the reversible default, or the risk and how to retire it> |

## Pre-mortem findings
Outcome is one of `accepted`, `refuted`, `spike`.

| Finding | Outcome | Reasoning |
| --- | --- | --- |
| <likely cause of failure, tied to a sentence or gap of this brief> | <outcome> | <why, in the user's words> |

## Alternatives considered

| Approach | Effort | Risk | What it gives up |
| --- | --- | --- | --- |
| <approach, the chosen one first> | <effort> | <risk> | <what is lost> |

## Open risks & spikes
- <risk or spike> — <how and when it gets retired>
