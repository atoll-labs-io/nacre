---
adr: 0013
title: One isolated unsafe C_Sign call in nacre-pkcs11 for keys that need the PIN at every signature
status: accepted
date: 2026-10-22
scope: story s13-pkcs11-signer
supersedes: []
superseded-by: []
---

# ADR-0013 — One isolated unsafe C_Sign call in nacre-pkcs11 for keys that need the PIN at every signature

## Context and Problem Statement
ADR-0005 chose `cryptoki` so that `unsafe` would stay inside it. A YubiKey PIV key in slot 9c carries `CKA_ALWAYS_AUTHENTICATE`: the PIN must be given again (`C_Login` with `CKU_CONTEXT_SPECIFIC`) between `C_SignInit` and `C_Sign`. `cryptoki` 0.12.1, the latest release, runs both steps in one `Session::sign` and offers no call for that sequence; upstream added `Session::sign_single` (rust-cryptoki PR #357, merged 2026-02-20) but has not released it.

## Considered Options
Ranked by the owner's criteria (open source, frugal, scalable, easy for an AI to handle):
1. **One raw `C_Sign` call through `cryptoki-sys`, isolated in `crates/nacre-pkcs11/src/raw.rs`** — the only `unsafe` in Nacre, allowed for `nacre-pkcs11` by the conventions; proven on SoftHSM.
2. **Refuse keys that need the PIN at every signature until `cryptoki` releases `sign_single`** — no `unsafe`, but the owner's YubiKey cannot sign in slot 9c and s13's criterion 5 falls.
3. **Depend on `cryptoki`'s git main branch** — no `unsafe` in Nacre, but an unreleased dependency blocks publishing `nacre-sig` on crates.io.

## Decision Outcome
Chosen option: **1**, chosen by the owner on 2026-10-22, because it keeps the YubiKey usable now and confines the exception to one function. The rest of `nacre-pkcs11` keeps `#![forbid(unsafe_code)]` everywhere but `raw.rs`, which states its safety contract.

### Consequences
- Good, because Patelle's YubiKey signs in slot 9c with the PIN asked at every signature.
- Bad, because Nacre now carries one `unsafe` block, which a later reviewer must re-read whenever `cryptoki-sys` changes.
- Neutral: once `cryptoki` releases `Session::sign_single`, a story replaces `raw.rs` with it and this ADR is superseded.
