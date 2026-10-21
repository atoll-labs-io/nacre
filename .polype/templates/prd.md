---
target: <the SaaS this product replaces or competes with>
mode: <replace | adapt>
status: draft
date: <YYYY-MM-DD>
---
# PRD — <product>

`/po-prd` fills this file one validated section at a time. `status` stays `draft` until every section has been approved on its own question; `/po-prd` then sets it to `approved` at its commit, and never asks for the document to be read again.

## Target
<The SaaS in question, its vendor, and which of its plans or modules are in view.>

## Mode
<`replace`: an internal replacement, to stop paying for it and keep the data at home. `adapt`: a competing product that brings an angle of its own.>

## Why
<What is wrong with the target today — cost, lock-in, missing capability — in the user's words.>

## Core loop
The few features people actually open the target for, the 20 % that carries its value. Complexity uses the scale of `templates/stories.md`. A feature scored 4 or 5 stays here only if its justification says why the product fails without it; otherwise it moves to the graveyard.

| Feature | Complexity (1–5) | Justification |
| --- | --- | --- |
| <feature> | <1–5> | <why the product is useless without it> |

## Graveyard
Everything the target does that this product deliberately will not do. Listing it keeps it from creeping back in through a story.

| Feature | Why it is left out |
| --- | --- |
| <feature> | <reason> |

## Angle
<What this product does better than the target. In `replace` mode, either the internal gain beyond parity, or the words "parity only". In `adapt` mode, the angle as it stands after the challenge: the evidence of pain, the exact consumer, the success signal.>

## Need
<The problem to solve, stated without naming a feature.>

## Users
<Who uses it, how many, how often, with which rights.>

## Constraints
<Data to migrate, hosting, compliance, budget, deadlines, systems it must talk to.>

## Success criteria

| Criterion | Target | How it is measured |
| --- | --- | --- |
| <criterion> | <number or threshold> | <source of the measurement> |
