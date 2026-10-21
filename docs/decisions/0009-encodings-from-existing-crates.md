---
adr: 0009
title: Encodings and containers come from existing crates
status: accepted
date: 2026-10-21
scope: framing
supersedes: []
superseded-by: []
---

# ADR-0009 — Encodings and containers come from existing crates

## Context and Problem Statement
ADR-0001 has Nacre write the signature formats and keeps encodings with existing crates, as DER stays with RustCrypto. The later families sit on four more encodings: DEFLATE (PDF streams), XML, JSON, CBOR, and on the ZIP container (ASiC).

## Considered Options
Ranked by the owner's criteria; one choice per encoding:
- **DEFLATE: `miniz_oxide`** — pure Rust; over `flate2` with a C backend.
- **XML: `roxmltree`** — read-only tree with resolved namespaces and positions, no external entities, which C14N and the XXE refusal need; over `quick-xml` (streaming, Nacre would rebuild the tree) and `xml-rs` (slower, less maintained). Nacre writes C14N output itself.
- **JSON: `serde_json`**, with `preserve_order` where JAdES needs the header order kept.
- **CBOR: `ciborium`** — over `minicbor` (no_std focus, a smaller community); deterministic encoding checked by Nacre.
- **ZIP: `zip`** — pure Rust; ASiC rules (stored `mimetype` first, paths, sizes) enforced by Nacre on top.
- **Writing these encodings in Nacre** — turned down: they are not signature formats, so they are outside the exercise ADR-0001 sets.

## Decision Outcome
Chosen option: **the crates above**, because each is open source, pure Rust and widely used, and none is a signature format.

### Consequences
- Good, because each later family story knows its encoding crate without an ADR of its own.
- Bad, because a parser bug in one of these crates reaches Nacre; each family keeps its own fuzz target over the crate's output.
- Neutral: swapping one of them is a new ADR and a story behind the same family API.
