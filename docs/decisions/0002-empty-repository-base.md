---
adr: 0002
title: Nacre starts from an empty repository
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0002 — Nacre starts from an empty repository

## Context and Problem Statement
`/po-architect` found no base: the repository holds only the licences, `README.md`, `IDEE.md` and Polype's files. Nacre is a library, not an application, so it has no authentication, tenancy or billing foundation to inherit from a boilerplate.

## Considered Options
- **Empty repository, assumed** — story s01 creates the cargo workspace and the common contract.
- **Scaffolded default** — `cargo new --lib`, committed before any story.
- **A boilerplate** — Polype's catalogue offers only `rust-cli` (rust-starter), shaped around a binary.

## Decision Outcome
Chosen option: **empty repository, assumed**, because s01 already owns the workspace root and the shared contract, and `cargo new --lib` would produce a single-crate layout that ADR-0003 turns down. `rust-cli` targets a binary, which the brief puts in V2.

### Consequences
- Good, because the layout is decided once, by ADR-0003, with no scaffold to undo.
- Bad, because s01 is a sequential foundation: every other story waits for it.
- Neutral: after s01, the only sequential chains are the ones the stories' `Depends on` lines declare; s03 and s04 can run side by side.
