---
adr: 0016
title: Timestamp and revocation errors carry the kind their source sets
status: accepted
date: 2026-10-22
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0016 — Timestamp and revocation errors carry the kind their source sets

## Context and Problem Statement
ADR-0012 gives every error a coarse `kind()`. In `nacre-core`, `Error::Timestamp` and `Error::Revocation` always map to `Unavailable`, whatever happened inside the source: a forged or replayed timestamp token, a CRL with a bad signature or an address refused for SSRF all read as a passing outage (s07 and s09 reviews, 2026-10-22). An application that retries on `Unavailable` would treat an attack as a transient failure.

## Considered Options
1. **The variants carry an `ErrorKind` set by the implementation**, `Unavailable` being the default — the source knows what failed.
2. **Guess the kind by downcasting the boxed source to known error types** — fragile, and `nacre-core` must not depend on the family crates.
3. **Keep `Unavailable` for every such error** — the cause stays readable in `source()` only.

## Decision Outcome
Chosen option: **1**, chosen by the owner on 2026-10-22, because only the source can tell an attack from an outage, and the contract stays independent of the families. A source that rejects a forged or replayed answer says `InvalidSignature`; a caller's invalid input says `InvalidInput`; an unreachable service says `Unavailable`. This refines ADR-0012, which stays accepted.

### Consequences
- Good, because `kind()` stays meaningful for timestamp and revocation failures.
- Bad, because the frozen `nacre-core` contract changes, which needs the contract story s39 and touches every `TimestampAuthority` and `RevocationSource` implementation.
- Neutral: `Unavailable` remains the default, so an implementation that sets nothing keeps today's behaviour.
