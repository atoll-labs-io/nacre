---
adr: 0003
title: A cargo workspace with one crate per family and the nacre-sig facade
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0003 — A cargo workspace with one crate per family and the nacre-sig facade

## Context and Problem Statement
Each signature family must be activatable alone (brief, premise 6), and agents build stories side by side, which they can only do when two stories never edit the same file (`docs/stories.md`, Owns).

## Considered Options
Ranked by the owner's criteria (open source, frugal, scalable, easy for an AI to handle):
- **Workspace, one crate per family, a facade crate** — `members = ["crates/*"]` in a root `Cargo.toml` that no story edits after s01; `crates/nacre-<family>/` per family; `crates/nacre-sig/` re-exports each family behind its feature. Each story owns its crate folder.
- **One crate with a module and a feature per family** — the same features, but every story edits the same `Cargo.toml` and `src/lib.rs`, so no two stories can run in parallel.
- **Separate repositories per family** — independent releases, at the cost of cross-repository changes for every contract change.

## Decision Outcome
Chosen option: **workspace, one crate per family, a facade crate**, because it is the only option that keeps stories parallel while giving the facade the per-feature compilation the brief asks for.

Settings that come with it:
- Rust edition 2024, resolver 3; MSRV 1.97 (stable 1.99 minus two, brief, Interface contract), set in `rust-toolchain.toml` and each crate's `rust-version`.
- `Cargo.lock` is not versioned: two stories that each add a crate would otherwise conflict on it. CI resolves the latest compatible versions on every run.
- Each crate declares its own dependency versions, since the root `Cargo.toml` is frozen after s01.
- Only `nacre-sig` is meant for users; the family crates are published too, as its dependencies, under `nacre-<family>` names.

### Consequences
- Good, because stories own disjoint folders and run in parallel; `cargo tree` on the facade proves what a feature pulls in.
- Bad, because a dependency version is repeated in each crate that uses it and can drift; an unversioned lock file makes a CI run depend on the day's crates.io.
- Neutral: if version drift bites, a later ADR moves shared versions to `[workspace.dependencies]` through a contract story.
