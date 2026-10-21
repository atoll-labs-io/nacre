---
adr: 0010
title: The nacre-core contract speaks DER bytes and returns one core error
status: accepted
date: 2026-10-21
scope: story s01-workspace-contract
supersedes: []
superseded-by: []
---

# ADR-0010 — The nacre-core contract speaks DER bytes and returns one core error

## Context and Problem Statement
Story s01 writes the `Signer`, `TimestampAuthority` and `RevocationSource` traits every family crate and Patelle code against, and `nacre-core` is frozen after it (`docs/architecture.md:61`). ADR-0004 says who parses PKIX structures, not what types cross the contract, and no ADR says how an implementation's error (a PKCS#11 PIN refusal, an HTTP failure) travels through a trait method. Both choices are breaking to change later: every family and Patelle would move with them.

## Considered Options
Ranked by the owner's criteria (open source or self-hostable, frugal, scalable, easy for an AI to handle); all options are equally open source.
1. **DER bytes at the boundary, object-safe traits, one `nacre_core::Error`** — certificates, tokens, CRLs and OCSP responses cross the traits as DER `Vec<u8>` / `&[u8]`; trait methods return `nacre_core::Error`, whose `Signer`, `Timestamp` and `Revocation` variants carry the implementation's own error as a boxed `source`. `nacre-core` depends on `thiserror` only by default.
2. **DER bytes at the boundary, an associated `type Error` per trait** — the same bytes, each implementation names its own error type.
3. **RustCrypto types at the boundary (`x509_cert::Certificate`, `der::Any`), an associated `type Error`** — typed values, no re-parsing between crates.

Against the criteria:
- Frugal: option 1 keeps RustCrypto out of `nacre-core`'s default build; options 2 and 1 tie on runtime cost; option 3 pulls `x509-cert` into every crate's contract, though the families pull it anyway.
- Scalable: options 1 and 2 survive RustCrypto's 0.x breaking releases (ADR-0004, Consequences) without breaking the contract; option 3 breaks `nacre-core`, every family and Patelle (today on `x509-cert` 0.2) in lockstep at each `x509-cert` or `der` major. Option 1 lets a caller hold `&dyn Signer` or a `Vec<Box<dyn RevocationSource>>` of mixed implementations (CRL then OCSP fallback, s10); options 2 and 3 force the caller to name one error type per object.
- Easy for an AI: option 1 has one error type to match and no generics; option 2 adds one associated type per trait; option 3 adds both and version pinning across crates.

## Decision Outcome
Chosen option: **1. DER bytes at the boundary, object-safe traits, one `nacre_core::Error`**, because it is the only option that keeps the frozen contract independent of RustCrypto's release cadence and lets callers inject mixed implementations as trait objects. Chosen by the owner on 2026-10-21.

### Consequences
- Good, because a RustCrypto major bump touches the family crates only, never the contract; Patelle can inject its own `Signer` whatever its `x509-cert` version.
- Bad, because each family re-parses the DER it receives (a certificate chain is decoded by `nacre-cms`, again by `nacre-validate`), and a caller matching on a PKCS#11 PIN state must `downcast_ref` the boxed source to `nacre_pkcs11::Error`.
- Neutral: the cost of re-parsing is small next to the 1 s budget for a 10 MB PDF (brief, Quality attributes); if it shows, a family can cache its decoded chain without changing the contract.
