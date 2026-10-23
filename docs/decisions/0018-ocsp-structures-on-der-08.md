---
adr: 0018
title: OCSP structures written in nacre-revocation on der 0.8
status: accepted
date: 2026-10-22
scope: story s10-revocation-ocsp
supersedes: [0004]
superseded-by: []
---

# ADR-0018 — OCSP structures written in nacre-revocation on der 0.8

## Context and Problem Statement
ADR-0004 takes the OCSP structures from `x509-ocsp` 0.2. That release, the only usable one on crates.io (2024-01-08), is built on `der` 0.7, `spki` 0.7 and `x509-cert` 0.2, while every Nacre crate is on `der` 0.8 and `x509-cert` 0.3 (`crates/nacre-revocation/Cargo.toml`). The `der` 0.8 port exists only as an unpublished `0.3.0-pre` on RustCrypto's `master`, and Nacre is published on crates.io (brief, Product & distribution), which refuses git dependencies. Story s10 needs the OCSP request and response now. This ADR replaces ADR-0004 in part only: the OCSP line; the rest of ADR-0004 stands.

## Considered Options
Ranked by the owner's criteria (open source or self-hostable, frugal in hardware, scalable, easy for an AI to handle), then by the rest:
1. **Write the OCSP structures in `nacre-revocation` on `der` 0.8, with `der`'s derive** — the subset RFC 6960 needs (`OCSPRequest` to encode; `OCSPResponse`, `BasicOCSPResponse`, `ResponseData`, `ResponderID`, `SingleResponse`, `CertStatus` to decode, and to encode for the forged corpus), about 150 lines of declarations modelled on RFC 6960 §4.1-4.2 (and on `x509-ocsp` master, same MIT OR Apache-2.0 licence). One dependency stack; publishable; the decoding is strict DER from `der`, and the fuzz target added by s10 covers it. Cost: one more structure set to keep, which ADR-0004 wanted to avoid.
2. **`x509-ocsp` 0.2.1 as published** — follows ADR-0004 to the letter, but pulls a second RustCrypto stack (`der` 0.7, `spki` 0.7, `x509-cert` 0.2, `const-oid` 0.9) into every user of `nacre-revocation`: heavier builds, two `Certificate` types that do not mix (certificates crossing the boundary are re-encoded), and a line RustCrypto no longer develops.
3. **A git dependency on `x509-ocsp` 0.3.0-pre from RustCrypto `master`** — the right types, but `cargo publish` refuses it, so `nacre-revocation` and the `nacre-sig` facade could not be published.
4. **Wait for `x509-ocsp` 0.3 on crates.io** — no date announced; blocks s10, then s11 and s17.

## Decision Outcome
Proposed option: **1**, because it is the only one that keeps a single, current dependency stack and stays publishable now; option 2 passes the frugality criterion over, options 3 and 4 do not deliver. When `x509-ocsp` 0.3 is published on `der` 0.8, a later story may swap the declarations for it behind the same public API, which exposes no structure type.

### Consequences
- Good, because one `der`/`x509-cert` stack serves CRL and OCSP, and the public API (`OcspRequest`, `OcspResponse`) hides the declarations, so a later swap to `x509-ocsp` 0.3 changes no caller.
- Bad, because Nacre maintains and fuzzes OCSP declarations RustCrypto also writes.
- Neutral: revisit once `x509-ocsp` 0.3 reaches crates.io. ADR-0004 stays accepted except for its OCSP line, and gets `superseded-by: [0018]` in its frontmatter once this ADR is accepted.
