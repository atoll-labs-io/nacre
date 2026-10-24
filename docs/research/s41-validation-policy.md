# Research — s41-validation-policy

[Story](../stories.md)

## Structuring facts
- **AC1's switch list is short of what AC2 asks under `dss()`.** Three DSS behaviours of AC2 are not among AC1's five switches, and `strict()` must keep the opposite. They are: USF files listed with no signature, `chain-malformed-extension` as an error, and the order of validity and revocation for an out-of-range certificate. Each one becomes a switch too, so there are 8 in all (table below). Today all three are fixed: `validate.rs:158-170` lists every field with a `/V`, `chain.rs:441-443` makes a repeated extension a verdict, and `chain.rs:424-429` judges validity before any revocation.
- **AC2's "expired or not yet valid → `CERTIFICATE_CHAIN_GENERAL_FAILURE`" holds only when no revocation data covers the certificate** (s18 spike, c40 and c41). When the data says "not revoked", DSS 6.5.1 gives `INDETERMINATE` / `OUT_OF_BOUNDS_NOT_REVOKED` (s17 research, c26, issue #124). So DSS judges revocation first and validity second, while Nacre stops at `ChainDefect::Expired`/`NotYetValid` → `OUT_OF_BOUNDS_NO_POE` (`chain.rs:149`).
- **AC1 says `nacre-pdf` must report the data after `%%EOF` instead of failing. It already does**: `Error::TrailingData { offset }` holds the first byte after the last `startxref … %%EOF` (`crates/nacre-pdf/src/xref.rs:146-166`). Under `dss()`, `validate` can parse `pdf[..offset]` again and judge that prefix. `crates/nacre-pdf/` stays untouched, and `Document::parse` keeps refusing for writers (`nacre-pdf/tests/refusals.rs:95`).
- The person settled the main design on 2026-10-23 (`docs/decisions-log.md:92-93`): one runtime `ValidationPolicy`, `strict()` by default, `dss()` on request, written up as ADR-0026. Every switch guards a rule that already exists. Two things change in `strict()` itself: the `/M` check (AC3) and the stale-revocation proof (AC4).
- In the docs, "until s17" is French ("jusqu'à s17", "tant que … (s17)"), and the stale mentions sit in `docs/security/attacks/pades.md:79-82` and `cms.md:24,49`.

## Story
A `ValidationPolicy` holds one switch per rule that only Nacre applies. `strict()` turns them all on and is the default of `validate`, `validate_with_anchors` and `validate_with_revocation`. `dss()` turns them all off and gives DSS 6.5.1's verdict on every divergence the s18 spike found. AC3: `strict()` also applies the `/M` before `notBefore` rule. AC4: under `strict()`, the 24 h window drops only "not revoked" data; an old proof of revocation still counts, except `certificateHold`. AC5: one conformance test per switch, giving DSS's verdict under `dss()` and the strict one under `strict()`. AC6: `docs/security/attacks/` gives, for each attack, the rule that closes it and the policy that leaves it open, and adds s17's revocation attacks.

## The switches

| Switch (on in `strict()`) | Rule today | Under `dss()` (DSS 6.5.1, spike) |
| --- | --- | --- |
| later revisions (s15) | `RevisionNotAllowed` and the DocMDP 1 `AddedByRevisionNotAllowed` (`validate.rs:214-229`); `ByteRangeNotWholeFile` (`validate.rs:419-421`) | the 15 non-SSA files of the 29 (`certified-p1-*`, `docmdp-reference-cap`, `fieldmdp-locked-fill`, `fill-and-second-signature`, `chain-cms-refused-revision`, `eaa-freetext`, `isa-appended-revision`, `shadow-*`), plus `byterange-not-whole-file` and a JavaScript `/OpenAction` after a bench B (l37): judged as if nothing were appended, `TOTAL_PASSED` on the bench |
| sneaky signatures (s40) | `Judge::sneaky` (`revisions.rs:372-419`), whose result goes into `refused_signatures` and `forced` | the 14 `ssa-*` files accepted |
| trailing data (s14) | `Error::Pdf(TrailingData)` (`attacks.rs:155-162`) | `isa-no-xref` judged as DSS judges a sound file (no anchor: `INDETERMINATE` / `NO_CERTIFICATE_CHAIN_FOUND`) |
| unusable signatures listed (s14) | `ContentsMissing`, `ContentsNotDer`, `ByteRangeMalformed` give `TOTAL_FAILED` (`attacks.rs:68-108`) | the 7 `usf-*` files: no signature listed |
| signer key usage (s16) | leaf `keyUsage`/EKU for `Purpose::Signing` (`chain.rs:444-466`) | c42 (`keyCertSign` only) and c43 (EKU `serverAuth`) pass |
| validity before revocation (s16) | `Expired`/`NotYetValid` stop the walk (`chain.rs:424-429`) | revocation first: no data → `CERTIFICATE_CHAIN_GENERAL_FAILURE` (c40, c41), "not revoked" → `OUT_OF_BOUNDS_NOT_REVOKED` (c26) |
| malformed extensions judged (s16) | `MalformedExtension` → `CERTIFICATE_CHAIN_GENERAL_FAILURE` (`attacks.rs:429-435`) | DSS answers HTTP 500 on `chain-malformed-extension` (the leaf repeats `keyUsage`, `examples/forge_chain_attacks.rs:200-216`): `validate` returns an error |
| fresh revocation (s17) | `issued_from` = control date − 24 h with no POE (`validate.rs:304-306`) | `issued_from: None`: freshness ignored (s17 c19, c20) |

Both policies apply the `/M` check: a `/M` before the signer's `notBefore` gives `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE` (DSS `BBB_SAV_ISQPSTWSCVR`), and Nacre has no such rule today.

## Current code
- `validate_with` (`validate.rs:149-243`) parses the file, collects the fields (skipping document timestamps), runs `check` (`:375-384` → `signed_bytes` `:388-423`, `verify` `:436-465`) and `qualify` (`revisions.rs:45-89`), and reads `/DSS` only when there are anchors (`:191-195`). It then picks the first defect in this order: integrity, the signature's own revision refused, a later revision refused, then `Context::judge` (`:261-335`) for timestamps, chain and revocation.
- `Qualified.refused_signatures` (`revisions.rs:35-42`) mixes two refusals: DocMDP 1 (`signature_value`, `:478-481`, s15) and SSA (`sneaky`, `:414-418`, s40).
- `build_path` (`chain.rs:190-247`) runs `judge` (`:420-486`) on each path that reaches an anchor. The public `build_chain` (`:180-187`) is the strict signing purpose.
- `judge_path` (`revocation.rs:188-224`) keeps only the items issued at or after `max(notBefore, issued_from)`, then lets the latest one decide. `Item::verdict` (`:70-91`) drops the reason, which `CrlStatus::Revoked { reason }` (`nacre-revocation/src/crl.rs:39-44`) and `OcspStatus::Revoked { reason }` (`ocsp/response.rs:39-44`) both carry.
- `SignatureValidation::defective` (`report.rs:158-187`) maps each `Defect` to its report. `Error` (`error.rs:5-21`) has no variant for a malformed certificate.
- Nothing reads `/M`. `nacre-pades` writes it as `D:YYYYMMDDHHmmSSZ` (`nacre-pades/src/sign.rs:194-197`), and no PDF date parser exists in the workspace.

## Attachment points
- New `src/policy.rs`: `ValidationPolicy` with `strict()`, `dss()` and `Default` = strict. New `validate_with_policy(pdf, anchors, at, source, &policy)`; the three existing entry points call it with `strict()` (`validate.rs:92-147`).
- `validate_with`: re-parse the prefix on `TrailingData`; drop the USF signatures; reject a CMS certificate that repeats an extension; gate `added_by`/`refused`.
- `signed_bytes`: `ByteRangeNotWholeFile` gated, end = `c + d`.
- `qualify(…, sneaky: bool)`, plus a separate list for SSA in `Qualified`.
- `build_path(…, purpose, rules)` with two rules: the signer's key usage, and validity in the walk.
- `Context::judge`: after `judge_path` passes, check the out-of-range certificate, then `/M`.
- `judge_path`: keep stale revocation verdicts that are not holds.
- Rustdoc: `lib.rs:1-38`, `validate.rs:81-139`, `report.rs:73-115`. Fuzz target `fuzz/fuzz_targets/validate.rs:19-22`.

## Verified interfaces
- `nacre_pdf::Error::TrailingData { offset: usize }` (`nacre-pdf/src/error.rs:18-19`); `Document::parse(&[u8])` (`document.rs:37`).
- `Defect`, `Error` and `ChainDefect` are `#[non_exhaustive]` (`report.rs:77`, `error.rs:3`, `chain.rs:113`), so adding variants is not breaking.
- `SubIndication::{SigConstraintsFailure, OutOfBoundsNotRevoked}` exist (`nacre-core/src/report.rs:70,82`). So does `CrlReason::CertificateHold` (x509-cert `ext::pkix::CrlReason`).
- `der::DateTime::new(y, mo, d, h, mi, s)` checks the ranges, and `x509_cert::time::Time::from(..).to_system_time()` converts (`attacks.rs:316-318`).
- Test support: `forge::{issue, crl, signed, with_dss, ChainSigner, ForgedTsa, Role}` (`tests/support/forge.rs:47-331`). `issue` pins validity to 2026-01-01..2036-01-01 (`:116-138`), and `signed` pins `/M` to 2026-10-22T08:00Z (`:304-308`). The conformance helpers are `confront`, `forged` and `RevokingSource` (`tests/conformance.rs:48-147`), with the bench certificates' `default_startdate = 20260101000000Z` (`conformance/pki/openssl.cnf:24,38`). `Dss::validate` keeps the JSON and the XML (`nacre-conformance/src/client.rs:60-89`).

## Traps
- Every existing test calls `validate`, `validate_with_anchors` or `validate_with_revocation`, so `strict()` must keep each of their verdicts. The new `/M` rule breaks none of them: the forged and bench certificates start on 2026-01-01, and `/M` is 2026-10-22.
- With the revision switch off, `qualify` still runs: `later_revisions` stays listed, and `TooManyRevisions` stays an error.
- With the SSA switch off but revisions on, a `ssa-*` file can still be refused by a s15 rule (`ssa-outside-fields` refuses objects 3, 11, 12, 13, `attacks.rs:302-307`). The SSA switch test must use `ssa-visible-signature.pdf`.
- `ByteRangeOutsideFile` (`validate.rs:412-415`) is checked against the slice that is passed in. Under the trailing-data switch, that slice is the prefix.
- Validity can only be judged after revocation once a path is returned, which today happens only for a clean one (`chain.rs:380-384`).
- The chain corpus carries no revocation data, so under `dss()` the chain cases fall to `RevocationDefect::Missing` (`attacks.rs:440-462`).
- DSS caches CRLs per URL (s17 research): forged certificates carry no CDP, and their CRLs go in `/DSS`. The bench regenerates its keys at every start, so conformance cases are forged at run time.
- No migration and no new dependency.

## Open questions
- `/M` after the signer's `notAfter` ("`/M` hors validité", stories.md:328): not observed. Only "before `notBefore`" is planned. An unreadable `/M` leaves the rule out.
- A certificate that is both expired and revoked, under `dss()`: which comes first, `REVOKED_NO_POE` or out of range? The plan takes revocation first, as DSS's order suggests; nothing has observed it.
- USF under `dss()`: only `ContentsMissing`, `ContentsNotDer` and `ByteRangeMalformed` were observed unlisted. `NotASignatureDictionary` and `UnsupportedSubFilter` stay listed until a case shows otherwise.
- Repeated extension: observed only on a CMS leaf. A certificate repeated in `/DSS` or in a timestamp token is not covered.
- Trailing data longer than the 1,024-byte tail gives `MissingStartxref` (`xref.rs:146-148`) whatever the policy. DSS probably reads such a file; this is not planned.
- Under `strict()`, a stale proof of revocation against a fresh "not revoked": the latest still decides, as AC4 is worded.
- The TSA path keeps `issued_from: None` (`validate.rs:363`). That is s42.

## Complexity
Story 5 → 4. The size came from the merged `isa-no-xref` story, but no xref reconstruction is needed (fact 3). Every switch guards an existing rule. The new code is small: a PDF date parser, the validity-after-revocation step and the stale-proof filter. The weight is the bench cases. Main risk: a DSS branch the spike did not see (open questions).

## Split
Not needed at 4. If the lead still wants a cut, the clean one is the `/M` rule (AC3, a date parser, its own conformance case). It touches no switch and could ship as its own story.
