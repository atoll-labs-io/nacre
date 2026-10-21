---
adr: 0004
title: RustCrypto foundations, and where the X.509 boundary lies
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0004 — RustCrypto foundations, and where the X.509 boundary lies

## Context and Problem Statement
ADR-0001 keeps primitives, ASN.1/DER and X.509 with RustCrypto and has Nacre write the formats. The stories review (issues #14 and #17) asks whether RFC 5280 path validation and the OCSP structures fall on the RustCrypto side of that line.

## Considered Options
- **RustCrypto holds the data models and encodings of PKIX; Nacre holds every judgement** — `der`, `spki`, `x509-cert` (certificates, CRLs) and `x509-ocsp` (OCSP structures) are used as they are; Nacre writes path validation (RFC 5280), revocation judgement, and every signature format, the RFC 3161 request and `TSTInfo` included.
- **RustCrypto holds certificates and CRLs only; Nacre writes the OCSP structures on `der`** — what story s10's notes assumed; one more parser to fuzz, for a structure RustCrypto already publishes.
- **Nacre writes X.509 too** — turned down by the brief's first non-goal.

## Decision Outcome
Chosen option: **RustCrypto holds the data models and encodings of PKIX; Nacre holds every judgement**, because it reads ADR-0001 literally (formats are Nacre's, X.509 is RustCrypto's) and leaves Nacre one parser fewer to secure. RFC 3161 stays Nacre's: its token is a CMS `SignedData`, a format, and `x509-tsp` is not used.

Crates and versions at 2026-10-21: `der` 0.8, `spki` 0.8, `x509-cert` 0.3, `x509-ocsp` 0.2, `p256` 0.14, `sha2` 0.11, `ed25519-dalek`, `rsa` 0.10 (release candidate). `rsa` is used for verification only: signing goes through a `Signer`, so the Marvin timing issue of private-key operations does not apply. The crate `cms` is not used (ADR-0001).

### Consequences
- Good, because every structure Nacre parses itself is a signature format, which is what the exercise is about.
- Bad, because Nacre follows RustCrypto's breaking releases (0.x versions) on `der` and `x509-cert`.
- Neutral: story s10's note « écrire les structures OCSP sur `der` » is superseded by this ADR; s10 parses through `x509-ocsp` and keeps its fuzz target on Nacre's judgement code.
