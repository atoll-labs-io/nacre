---
adr: 0007
title: DSS 6.5.1, run locally in a container, judges conformance; reference tools cross-check the other formats
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0007 — DSS 6.5.1, run locally in a container, judges conformance

## Context and Problem Statement
Premise 4 of the brief makes a local DSS at a pinned version the judge of every AdES feature, on the exact level it reports. Formats without an AdES profile (COSE, OpenPGP, sshsig, minisign) need another judge.

## Considered Options
- **DSS `esig/dss-demonstrations` 6.5.1, built into a container from a SHA-256-checked archive, called through its REST validation API** — the version and the `Containerfile` Patelle's s01 already proved (Patelle ADR-0008); run by `conformance/compose.yaml` with podman locally and docker in GitHub Actions.
- **pyHanko as a second judge** — useful for the foreign corpus (s19), not as the judge: Python, and not the Commission's reference.
- **The Commission's online DSS demo** — turned down: documents would leave the machine (brief, Security & abuse).

## Decision Outcome
Chosen option: **DSS 6.5.1 in a local container**, because it is the reference the brief names and is already working next door. For formats DSS does not cover, the judge is the reference tool of each format, run in CI: `openssl cms` (CMS), `qpdf --check` (PDF structure), `xmlsec1` (XML-DSig), `gpg` and `rpgp` (OpenPGP), `ssh-keygen -Y` (sshsig), `minisign` (minisign), `coset` and `josekit` (COSE, JWS), SoftHSM 2 (PKCS#11 in CI).

### Consequences
- Good, because every conformance claim has a judge that is not Nacre.
- Bad, because the DSS image is about 880 MB and takes minutes to build; the conformance workflow caches it.
- Neutral: moving to a later DSS version is a new ADR, with the whole campaign rerun on it.
