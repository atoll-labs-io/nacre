---
adr: 0020
title: Timestamp and revocation errors hold their kind in struct variants built by constructors
status: accepted
date: 2026-10-23
scope: story s39-error-kind-from-sources
supersedes: []
superseded-by: []
---

# ADR-0020 — Timestamp and revocation errors hold their kind in struct variants built by constructors

## Context and Problem Statement
ADR-0016 decides that `nacre_core::Error::Timestamp` and `Error::Revocation` carry an `ErrorKind` set by the source, `Unavailable` by default, but not the shape of those variants in the frozen contract. Today both are tuple variants over a `BoxError` (`crates/nacre-core/src/error.rs:16,19`), built as `Error::Timestamp("x".into())` or `Error::Revocation(Box::new(e))` in four crates, and callers `downcast_ref` their source (ADR-0010, Consequences). Whatever shape is chosen is breaking to change later, for every family and for Patelle.

## Considered Options
Ranked by the owner's criteria; all three are equally open source and frugal, and none adds a dependency.
1. **Struct variants with constructors** — `Timestamp { kind: ErrorKind, source: BoxError }` and the same for `Revocation`; `Error::timestamp(source)` and `Error::revocation(source)` give `Unavailable`, `Error::timestamp_with_kind(kind, source)` and `Error::revocation_with_kind(kind, source)` set it. `source()` stays the implementation's error.
2. **Tuple variants over a new wrapper type** — `Timestamp(SourceError)` where `SourceError` holds the kind and the boxed error, with `From<&str>`, `From<String>`, `From<BoxError>` and its own `downcast`, so that `Error::Timestamp("x".into())` still compiles. Keeping `source()` on the implementation's error then needs a hand-written `std::error::Error` for `nacre_core::Error` instead of thiserror.
3. **Two-field tuple variants** — `Timestamp(ErrorKind, BoxError)`: breaks the same callers as option 1, with positional fields.

Against the criteria:
- Scalable: options 1 and 3 break today's callers once, at compile time, in eight places of four crates before any release (`version = "0.1.0"`); option 2 breaks none of them but grows the public contract by one type that mirrors `Box<dyn Error>`. All three let the twenty family stories to come set the kind the same way.
- Easy for an AI: option 1 has named fields and two constructors whose names say the default; option 3 relies on the order of two fields; option 2 adds a type, conversions, a hand-made `downcast` and a hand-written `Error` impl, and `Error::Timestamp(e.into())` keeps compiling with the default kind, the very oversight ADR-0016 was written against.

## Decision Outcome
Proposed option: **1. Struct variants with constructors**, because it keeps the contract to the types it already has and makes every caller restate, once, which kind it means. Waiting for the owner's decision.

### Consequences
- Good, because `kind()` reads the field, the `Display` stays fixed, and `source()` keeps pointing at the implementation's error.
- Bad, because `nacre-cms`, `nacre-pades`, `nacre-tsp` and `nacre-revocation` tests and sources change with the contract, so story s39's `Owns` must cover them and s39 runs after s11-pades-blt.
- Neutral: an implementation that calls `Error::timestamp(e)` or `Error::revocation(e)` keeps today's `Unavailable`.
