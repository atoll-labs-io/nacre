---
adr: 0005
title: PKCS#11 through cryptoki
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0005 — PKCS#11 through cryptoki

## Context and Problem Statement
Story s13 signs with a key kept on a token (YubiKey over `libykcs11`, OpenSC, SoftHSM in CI). PKCS#11 is a C API, not a signature format: binding it is FFI, the one place where `unsafe` is allowed (brief, Security & abuse).

## Considered Options
Ranked by the owner's criteria:
- **`cryptoki` 0.12** (Parallaxsecond, Apache-2.0) — maintained, safe wrapper, used by Patelle's s01 with SoftHSM and the YubiKey.
- **Nacre's own bindings** (`bindgen` on the PKCS#11 headers) — more `unsafe` code in Nacre, no gain for the exercise, which is about formats.
- **`pkcs11` crate** — older and unmaintained.

## Decision Outcome
Chosen option: **`cryptoki`**, because it is maintained, permissively licensed, and already proven on the hardware Patelle uses.

### Consequences
- Good, because `unsafe` stays inside `cryptoki`; `nacre-pkcs11` itself can keep `forbid(unsafe_code)` unless a call needs otherwise.
- Bad, because a token quirk `cryptoki` does not expose needs an upstream change.
- Neutral: the YubiKey PIV spike of the brief runs in s13's research.
