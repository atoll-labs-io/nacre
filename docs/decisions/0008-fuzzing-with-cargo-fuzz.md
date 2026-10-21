---
adr: 0008
title: Fuzzing with cargo-fuzz, one fuzz folder per crate
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0008 — Fuzzing with cargo-fuzz, one fuzz folder per crate

## Context and Problem Statement
Every parser of hostile input is fuzzed in CI before its feature ships (brief, Security & abuse), and story s01's CI runs every `crates/*/fuzz/` target without later stories editing the workflow.

## Considered Options
Ranked by the owner's criteria:
- **`cargo-fuzz` (libFuzzer)** — the most documented Rust fuzzer; needs a nightly toolchain, used in CI for the fuzz job only.
- **`afl.rs`** — strong, but slower to set up and to run in CI.
- **`bolero`** — one harness for fuzzing and property tests, a smaller community.
- **Property tests alone (`proptest`)** — finds less in parsers than coverage-guided fuzzing.

## Decision Outcome
Chosen option: **`cargo-fuzz`**, because it is the frugal and well-known default, and a fuzz folder per crate keeps each story inside its own Owns.

### Consequences
- Good, because a new crate's targets are picked up by the CI's glob, as s01's criterion 5 requires.
- Bad, because the fuzz job needs nightly while the crates build on stable MSRV.
- Neutral: each crash found becomes a corpus case under `crates/<crate>/tests/corpus/` before it is fixed.
