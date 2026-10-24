---
adr: 0028
title: nacre-pdf reports a signature field whose /V is not a reference instead of refusing the file
status: accepted
date: 2026-10-24
scope: story s43-dss-parity
supersedes: []
superseded-by: []
---

# ADR-0028 — `nacre-pdf` reports a signature field whose `/V` is not a reference instead of refusing the file

## Context and Problem Statement
`Document::parse` refuses a whole PDF when a terminal `/FT /Sig` field holds a `/V` that is neither absent, `null` nor a reference (`crates/nacre-pdf/src/acroform.rs:155-163`, `Error::WrongType`, "signature value reference"). DSS 6.5.1 reads the same file and lists no signature (s18 spike n08, `/V 7`; s43 spike v1, `/V <<>>`). `validate` therefore returns an error where DSS gives a verdict, and the s18 campaign cannot reach 100 %. The fix sits in `nacre-pdf`, whose `SignatureField` (`acroform.rs:8-16`) is public and not `#[non_exhaustive]`: any change to what it carries breaks its users.

## Considered Options
- **`nacre-pdf` reports the field.** The field is listed with no value and a mark saying its `/V` could not be read; `validate` lists it as `TOTAL_FAILED` / `NotASignatureDictionary` under `strict()` and leaves it out under `dss()`, through the existing "unusable signatures listed" switch. A breaking change of `SignatureField`.
- **`nacre-pdf` reads such a `/V` as an empty field** (`value: None`), under both presets. One line, no API change, but `strict()` then skips a broken signature field without a word.
- **Leave the error.** A file DSS reads stays outside the campaign.

## Ranking the options
None adds a dependency or a cost. The second hides a malformed signature from `strict()`, which would list nothing where today it refuses the file: laxer, against ADR-0026. The third breaks the person's 100 % with no excluded case. The first keeps a verdict on the field under `strict()`, matches DSS under `dss()`, and reuses a switch that already exists. Rank: **report the field**, then read it as empty, then leave the error.

## Decision Outcome
Chosen option: **`nacre-pdf` reports the field**, decided by the person on 2026-10-24, the break of `SignatureField` accepted (`docs/decisions-log.md`, s43-dss-parity). No preset gets laxer, and the change stays inside one existing switch.

How the mark is carried is an implementation detail the s43 plan settles, not the person: a `value_unreadable: bool` next to `value`, which stays `None` for such a field, and `SignatureField` made `#[non_exhaustive]`. The other shape, an enum replacing `value`, would break `crates/nacre-pades/src/archive.rs:94-95` and the tests of three crates, outside the story's `Owns`.

### Consequences
- Good, because a file with one broken signature field is still read, and its other signatures judged.
- Bad, because a user that builds or exhaustively destructures `SignatureField` breaks; none does in this repository. A caller reading `value` alone sees such a field as empty: `nacre-pades` does, which suits it, since it never signs into an existing field.
- Neutral: a `/V` that is a reference to something other than a dictionary stays `value: Some(_)`; `nacre-validate` judges it (`Defect::NotASignatureDictionary`).
