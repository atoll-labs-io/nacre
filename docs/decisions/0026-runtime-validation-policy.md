---
adr: 0026
title: Validation rules that only Nacre applies are switches of a runtime ValidationPolicy, strict by default
status: accepted
date: 2026-10-23
scope: story s41-validation-policy
supersedes: []
superseded-by: [0027]
---

# ADR-0026 — Validation rules that only Nacre applies are switches of a runtime `ValidationPolicy`, strict by default

## Context and Problem Statement
The s18 spike against DSS 6.5.1 (`docs/research/s41-validation-policy.md`) found that several rules of `nacre-validate` give a verdict DSS does not give. These are the rules on revisions (s15), SSA (s40), key usage, validity and malformed extensions (s16), revocation freshness (s17), and USF and trailing data (s14). The person wants two things at once: 100 % identity with DSS for the campaign (brief, success metric 2; `docs/decisions-log.md:91`), and Nacre's protections kept by default. One build has to deliver both verdicts.

## Considered Options
- **Runtime policy.** A `ValidationPolicy` value, passed to the validation, holds one switch per rule that only Nacre applies. `ValidationPolicy::strict()` turns them all on and is what `validate`, `validate_with_anchors` and `validate_with_revocation` apply. `ValidationPolicy::dss()` turns them all off. The model is DSS's XML validation policies.
- **Cargo features.** A `dss` feature of `nacre-validate` turns the strict rules off at compile time.
- **Runtime policy plus a cargo feature that forbids lax presets.** The runtime policy as above, and a feature that makes `dss()` and any switch turned off unavailable.

## Ranking the options
All three are open source and frugal, and none adds a dependency. They differ on "scalable" and "easy for an AI to handle". Cargo unifies features across the dependency graph. With the feature option, one crate of an application's graph that turns on `dss` switches every other user of `nacre-validate` to DSS's rules, Patelle included. A single build also cannot test both modes. The third option brings the same unification back, in the other direction: one crate that turns on the forbidding feature takes `dss()` away from the whole graph, the campaign included. The runtime policy keeps the choice with each caller and each call, and one `cargo test` exercises both presets. Rank: **runtime policy**, then the third option, then cargo features.

## Decision Outcome
Chosen option: **runtime policy**, decided by the person on 2026-10-23 (`docs/decisions-log.md:92`). Feature unification would impose one mode on the whole dependency graph and make it impossible to test both. The person also decided that, under `strict()`, the 24 h window drops only "not revoked" data (`docs/decisions-log.md:93`).

The switches s41 introduces, each on in `strict()` and off in `dss()`, one per rule only Nacre applies:

| Switch | Rule it keeps on | Story |
| --- | --- | --- |
| later revisions | refuse a later revision no rule allows, a DocMDP 1 approval signature, and signed bytes that do not end with a revision | s15, s14 |
| sneaky signatures | refuse a signature that shows an appearance absent at certification | s40 |
| trailing data | refuse a file with data after its last `%%EOF` | s14 |
| unusable signatures listed | list a field whose `/Contents` or `/ByteRange` is unusable, as `TOTAL_FAILED` | s14 |
| signer key usage | judge the signer's `keyUsage` and `extendedKeyUsage` | s16 |
| validity before revocation | refuse an out-of-range certificate before its revocation is judged (`OUT_OF_BOUNDS_NO_POE`) | s16 |
| malformed extensions judged | give a verdict, not an error, on a certificate that repeats an extension | s16 |
| fresh revocation | with no proof of existence, count only data issued within 24 h before the control date | s17 |

A rule that DSS applies and Nacre lacks, such as the `/M` before the signer's `notBefore`, is no switch. It applies under both presets, so `strict()` is never laxer than DSS.

### Consequences
- Good, because Patelle keeps every protection without asking for it, and the s18 campaign runs `dss()` in the same build as the strict tests.
- Bad, because a caller who picks `dss()` accepts attacks that `strict()` closes: shadow attacks, SSA, ISA, a stale "not revoked" CRL. The rustdoc of `dss()` says so first, and `docs/security/attacks/` names, for each attack, the policy that leaves it open.
- Neutral: each future rule that only Nacre applies adds a switch and a row here, through a new ADR that supersedes this table. A DSS upgrade (ADR-0007) reruns each switch's conformance test.
