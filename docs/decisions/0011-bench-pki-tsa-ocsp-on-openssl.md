---
adr: 0011
title: The bench's test PKI, TSA, OCSP responder and CRL server run on OpenSSL in one small container
status: accepted
date: 2026-10-22
scope: story s02-conformance-harness
supersedes: []
superseded-by: []
---

# ADR-0011 — The bench's test PKI, TSA, OCSP responder and CRL server run on OpenSSL

## Context and Problem Statement
Story s02 must ship a replayable test PKI, a local RFC 3161 TSA, an OCSP responder and an HTTP server for the CRL, next to DSS 6.5.1 (ADR-0007). No ADR and no line of `docs/architecture.md` says what implements them, and s07, s09, s10, s11, s12, s17, s18 and s19 will all be judged against what is chosen. DSS itself only embeds a self-signed TSA reachable through its own JSON service (`/services/rest/timestamp-service/getTimestampResponse`, `tsp-config.xml` in the 6.5.1 image), not an RFC 3161 HTTP endpoint, and has no OCSP responder.

## Considered Options
Ranked by the owner's criteria (open source or self-hostable, frugal in hardware, scalable, easy for an AI to handle); every option is open source.
1. **OpenSSL in one Alpine container** — a shell script drives `openssl req`/`ca` to build the PKI; `busybox httpd`, bound to `127.0.0.1`, serves the CRLs as static files and answers `POST /tsa` with `openssl ts -reply` and `POST /ocsp` with `openssl ocsp -index … -reqin -respout`, both as CGI scripts. A few megabytes, no runtime beyond OpenSSL, which ADR-0007 already counts among the reference tools (`openssl cms`).
2. **Test servers written in Rust inside `nacre-conformance`** — built on RustCrypto; the TSA token is a CMS `SignedData`, which Nacre may only write itself (ADR-0001, ADR-0004: no `cms` crate), so the judge's fixture would share code with the code it judges.
3. **EJBCA Community in a container** — a real CA with an OCSP responder, but its TSA is an Enterprise feature, and it adds a second JVM of about 1 GB next to DSS.
4. **DSS's own services** — no RFC 3161 HTTP endpoint and no OCSP responder; the judge would also issue the tokens it judges.
5. **A Python toolchain (`cryptography`, a small HTTP server)** — workable, but brings a language and its packages into the repository for three fixtures.

Against the criteria:
- Frugal: option 1 is a few megabytes and one process; option 3 costs about 1 GB of memory; options 2 and 5 cost a build toolchain each.
- Scalable: not a concern for test fixtures; option 1's single-request CGI is enough for a test suite run in sequence.
- Easy for an AI: option 1 is documented OpenSSL commands an agent can rerun by hand; option 2 means writing and fuzzing two servers; option 3 is configured through a web console.

## Decision Outcome
Chosen option: **1. OpenSSL in one Alpine container**, chosen by the owner on 2026-10-22, because it is the most frugal, needs no new language, and keeps the fixtures independent of Nacre's code. The owner's own reasons: it is light enough to run on a laptop; it does not limit what can be tested, since OpenSSL can issue any edge case later stories need (expired or not-yet-valid certificates, wrong key usage or EKU, revocation at a chosen date, OCSP `unknown`); and testing must go deep and catch drift at once, because many atoll projects will depend on Nacre. For that reason the conformance workflow also runs on a daily schedule: `Cargo.lock` is not versioned (ADR-0003), so a dependency release on crates.io is caught within a day even when no pull request is open.

### Consequences
- Good, because the PKI script and both responders are plain OpenSSL invocations a person can replay, and OpenSSL is already a reference tool of the project.
- Bad, because `openssl ts` and `openssl ocsp` behave like OpenSSL, not like the TSAs and responders met in the wild; s07 and s10 keep a recorded answer from a public service as a fixture for that reason (s07 notes).
- Neutral: the Alpine and OpenSSL versions are pinned in `conformance/pki/Containerfile`; moving them regenerates nothing but may change the bytes the responders return.
