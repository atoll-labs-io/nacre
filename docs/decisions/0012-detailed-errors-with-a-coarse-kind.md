---
adr: 0012
title: Errors stay detailed for the developer, with a coarse kind for third parties
status: accepted
date: 2026-10-22
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0012 — Errors stay detailed for the developer, with a coarse kind for third parties

## Context and Problem Statement
The owner asked that Nacre's errors give no detail an attacker could learn from. Story criteria so far ask for errors that name the defect, and the brief's success metric requires `validate` to return the same indication and sub-indication as DSS in 100 % of cases.

## Considered Options
Ranked by the owner's criteria (open source, frugal, scalable, easy for an AI to handle); all are equally open source and frugal.
1. **Detailed typed errors plus a coarse `kind()`** — each crate keeps its detailed `thiserror` enum for the calling developer; `nacre-core` defines a closed `ErrorKind` (`InvalidInput`, `InvalidSignature`, `Indeterminate`, `Signer`, `Unavailable`) and every crate's `Error` exposes `kind()`; an application answering an untrusted party shows only the kind.
2. **One opaque error for everything** — breaks the verifiable conformance the brief asks for (sub-indications identical to DSS), ADR-0010's single error carrying its source, and criteria of stories already shipped (s03, s04, s05).
3. **Detail behind a `diagnostics` feature, opaque by default** — two behaviours to build and test for every error, and conformance tests would run on a build users never get.

## Decision Outcome
Chosen option: **1. Detailed typed errors plus a coarse `kind()`**, chosen by the owner on 2026-10-22, because a signature check over public documents by open-source code has no oracle to hide: an attacker runs the same code locally and sees every step, so an opaque error would only blind the developer and Patelle. The real leak is secret material, which no message may carry.

Rules that follow:
- `validate`'s sub-indications (EN 319 102-1) are results, not errors, and are returned unchanged.
- No error message, `Debug` or `Display` carries a PIN, key, token or file path.
- `ErrorKind`'s `Display` is a fixed text that never depends on the input.

### Consequences
- Good, because conformance stays checkable against DSS, and applications get one safe value to show outside.
- Bad, because every crate must map each of its variants to a kind, and a new variant must be mapped too.
- Neutral: adding `ErrorKind` to the frozen `nacre-core` is the contract story s38.
