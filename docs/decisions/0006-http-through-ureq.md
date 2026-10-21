---
adr: 0006
title: The http feature uses ureq, a blocking client
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0006 — The http feature uses ureq, a blocking client

## Context and Problem Statement
Nacre's core is synchronous and does no I/O; the TSA, CRL, OCSP and CSC calls go through injected traits, with a default implementation behind the `http` feature (brief, Interface contract).

## Considered Options
Ranked by the owner's criteria:
- **`ureq` 3** — blocking, no async runtime, rustls by default: the most frugal.
- **`reqwest` with its blocking API** — pulls tokio into every caller of the feature, against a synchronous core.
- **`minreq` or `attohttpc`** — lighter still, but less maintained and with thinner TLS support.

## Decision Outcome
Chosen option: **`ureq`**, because it matches the synchronous core without dragging an async runtime into callers; Patelle, which runs on tokio, calls Nacre from `spawn_blocking` or injects its own client.

### Consequences
- Good, because without `http` no crate pulls a network dependency, which `cargo tree` proves (s07, s20).
- Bad, because an async caller wraps the calls itself.
- Neutral: TLS through rustls; a caller needing the platform's certificate store provides its own transport.
