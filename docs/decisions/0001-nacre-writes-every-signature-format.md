---
adr: 0001
title: Nacre writes every signature format itself, on RustCrypto primitives
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0001 — Nacre writes every signature format itself, on RustCrypto primitives

## Context and Problem Statement
Patelle's story s01 found that no Rust library produces conformant PAdES baseline under a permissive licence with a hardware key: `ades-rs` 0.2 emits `PAdES-BES` (forbidden `signing-time`, no `/DSS`, no B-LTA), `pdf_signer` is GPL-3.0 and PKCS#12 only. The brief (`docs/brief.md`) sets Nacre as one library grouping every signature family, each behind a cargo feature, for ATOLL LABS's own use and as a deliberate exercise.

## Considered Options
- **A. Nacre complete** — every format written from scratch (CMS and the AdES profiles, PDF, RFC 3161, validation, PKCS#11 signer, then XML-DSig/XAdES, JWS/JAdES, COSE, OpenPGP, `sshsig`, minisign), first milestone PAdES B-B to B-LTA.
- **B. Nacre facade** — Nacre writes AdES, TSP, validation, PKCS#11 and the PDF layer; OpenPGP, SSH, minisign, COSE and JWS delegate to `rpgp`, `ssh-key`, `minisign`, `coset`.
- **C. DSS sidecar for Patelle** — Patelle signs and validates through a local DSS, no Rust library.
- **D. Fix `ades-rs` upstream** — remove `signing-time`, add `/DSS` and B-LTA.

## Decision Outcome
Chosen option: **A. Nacre complete**, because the exercise of writing each format is the project's purpose (brief, premises 1 and 3); B was the brief's recommendation and is turned down only for that reason. C leaves the Rust gap and brings Java into Patelle against its ADR-0003; D would still require writing `/DSS`, B-LTA and validation on a CAdES-shaped base Nacre does not own.

Primitives (SHA-2, ECDSA, RSA, EdDSA), ASN.1/DER and X.509 stay with RustCrypto and are never rewritten. The PDF layer is written by Nacre, limited to what PAdES needs, and refuses a PDF it cannot read cleanly instead of repairing it.

### Consequences
- Good, because every format and its behaviour on hostile input is under atoll's control, and one API covers signer, certificate, timestamp and validation across families.
- Bad, because ten families of parsers must be fuzzed and checked against every known attack before each feature ships, by a single maintainer; the first milestone date (25/10/2026) was kept against the brief's advice.
- Neutral: option B stays the simplification to revisit; each family written for the exercise is marked experimental until fuzzed and compared with its reference crate.
