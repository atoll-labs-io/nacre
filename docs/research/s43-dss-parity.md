# Research — s43-dss-parity

[Story](../stories.md)

## Structuring facts
- **AC2's "Sous `dss()`" is false: DSS drops revocation data issued after a certificate's `notAfter` for any certificate, and `strict()` is laxer than DSS there today.** A B-T whose signer was valid at the stamp and has expired since, with a "not revoked" `/DSS` CRL issued after its `notAfter`, is `CERTIFICATE_CHAIN_GENERAL_FAILURE` in DSS and `TOTAL_PASSED` under both presets (s43 spike e1; e2, the CRL issued before `notAfter`, passes on both sides). By ADR-0026 a rule DSS applies is no switch: both presets apply it, in `judge_path` (`crates/nacre-validate/src/revocation.rs:233`). AC2 should read "sous les deux préréglages" for the dropped data; under `strict()` the expired signer of n01 stays `OUT_OF_BOUNDS_NO_POE`, validity being judged first.
- The six shapes of the s18 spike are confirmed on the current code (s41 landed, `7aa21e8`); three are fixed inside existing switches (`unusable`, malformed extensions, late data), two are rules for both presets (`/M`), one is the ninth switch (ADR-0027). An unreadable `/M` is DSS's missing `/M` (m1).
- AC5 covers two shapes in two places: a `/V` that is not a reference makes `Document::parse` fail (`crates/nacre-pdf/src/acroform.rs:155-163`, ADR-0028); a reference to a non-dictionary is already read and listed `TOTAL_FAILED` under both presets (`validate.rs:148-151`, `:473`), where DSS lists nothing (n08b, v2): `unusable` (`validate.rs:431-436`) must take `NotASignatureDictionary`.
- AC6 cannot be checked on today's corpus without revocation data: with the chain root as anchor and no data, a signer key-usage file with its switch off ends `CERTIFICATE_CHAIN_GENERAL_FAILURE` like a sound one and like `chain-expired.pdf` under `dss()` (`tests/policy.rs:177-190`, `:213-225`), so "opened" cannot be told from "not opened". The catalog's "Ouverte sous" column is free text with `idem` rows (`docs/security/attacks/pades.md:51-63`, `cms.md:38`): no test can read it as it stands.

## Story
Under `dss()`, give DSS 6.5.1's verdict on each shape s41 left; keep `strict()` at least as strict as DSS and as today. AC1: no `/M`, or `/M` after the signer's `notAfter` → `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE` under both presets. AC2: expired signer, `/DSS` data issued after `notAfter` → `CERTIFICATE_CHAIN_GENERAL_FAILURE` under `dss()`; data issued before keeps today's verdict. AC3: under `dss()`, a signature-timestamp certificate repeating an extension is an error; under `strict()` it stays a defect. AC4: ninth switch `refuse_unsupported_sub_filters`; off, a sound CMS under another `/SubFilter` is `TOTAL_PASSED` with no ETSI level; an ADR completes ADR-0026's table. AC5: `nacre-pdf` reports a `/V` that is not a reference to a dictionary; `strict()` lists the signature failed, `dss()` does not list it. AC6: over the whole attack corpus, `strict()` minus one switch, for each of nine, changes only the verdicts that switch's rule explains, each named in `docs/security/attacks/`. AC7: under `strict()` every catalogued attack stays rejected; under `dss()` only those marked « ouverte sous `dss()` » open. AC8: one conformance test per shape, DSS's verdict under `dss()` and the strict verdict under `strict()`.

## Diagnostic — spikes against DSS 6.5.1
s18's second pass (n01–n16, `/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-saved2/research.md`) and an s43 pass (`/home/lecrabe/.claude/jobs/4fb763d0/tmp/s43-spike/src/bin/forge3.rs`, bench started and stopped 2026-10-24, on this worktree's code). Nacre judged with the bench root, `SystemTime::now()`, no source.

| # | Shape | `dss()` today | `strict()` today | DSS |
| --- | --- | --- | --- | --- |
| n11, n12 | no `/M` (PAdES, PKCS7) | as strict | `TOTAL_PASSED` once revocation passes | `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE` |
| m1 | `/M (garbage)`, `/DSS` CRL | `TOTAL_PASSED` | `TOTAL_PASSED` | `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE`, `PAdES-BES` |
| n02 | `/M` after the signer's `notAfter`, signer valid now | `TOTAL_PASSED` | `TOTAL_PASSED` | `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE` |
| n01, n01c | B, signer expired, `/DSS` CRL after `notAfter` (revoking / not) | `REVOKED_NO_POE` / `OUT_OF_BOUNDS_NOT_REVOKED` | `OUT_OF_BOUNDS_NO_POE` | `CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| n01b, n01d | the same, CRL before `notAfter` | `REVOKED_NO_POE` / `OUT_OF_BOUNDS_NOT_REVOKED` | `OUT_OF_BOUNDS_NO_POE` | as `dss()` |
| e1 | B-T, signer valid at the stamp, expired now, `/DSS` CRL after `notAfter` | `TOTAL_PASSED` | `TOTAL_PASSED` | `CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| e2, e3 | the same, CRL before `notAfter`; signer still valid | `TOTAL_PASSED` | `TOTAL_PASSED` | `TOTAL_PASSED` |
| n04 | signature-timestamp token certificate repeating `keyUsage` | `TOTAL_PASSED`, no best-signature-time | same | HTTP 500 |
| n05 | a `/DSS`-only certificate repeating `keyUsage` | `TOTAL_PASSED` | same | `TOTAL_PASSED` |
| n06, n07 | `/SubFilter` `adbe.x509.rsa_sha1` / unknown, sound CMS | `TOTAL_FAILED` / `FORMAT_FAILURE` | same | `TOTAL_PASSED`, `PDF-NOT-ETSI` |
| n08, v1 | `/V 7`, `/V <<>>` | `Error::Pdf(WrongType)` | same | no signature |
| n08b, v2 | `/V` referencing a stream / a missing object | listed `TOTAL_FAILED` / `FORMAT_FAILURE` | same | no signature |

Hypothesis "DSS drops data issued after `notAfter` only for a certificate out of validity at the judged time" (s18's reading of n01): refuted by e1, where the signer is valid at the best-signature-time. Kept: "DSS drops data issued after the certificate's `notAfter`" (n01/n01b, n01c/n01d, e1/e2 differ only by the CRL's `thisUpdate`).

## Current code
- `validate_with` (`crates/nacre-validate/src/validate.rs:126-249`): fields with `value: None` skipped (`:145-147`); a value naming no dictionary keeps `dict: None` (`:148-151`); document timestamps skipped (`:152-154`); `check` per signature (`:165-170`); unusable ones dropped when `list_unusable_signatures` is off (`:171`); with `judge_malformed_extensions` off, `Error::MalformedCertificate` when the CMS certificates or the signer repeat an extension (`:173-186`), timestamp tokens not scanned.
- `check` (`:441-463`) reads `/M` with `pdf_date` (`src/date.rs:11`), `None` when absent or unreadable (`:447-452`); takes only `whole_file: bool`. `signed_bytes` refuses `dict: None` (`:473`), then any `/SubFilter` outside `SUB_FILTERS` (`:24`, `:475-478`).
- `Context::judge` (`:268-356`): no anchor → sound with no path (`:274-276`); best-signature-time from `proven_time` (`:304-308`, `:396-423`), whose TSA path uses `Rules::STRICT` (`:411-418`), so a repeating TSA certificate gives no proof of time under both presets; then `judge_path` and `after_revocation` (`:332-334`).
- `after_revocation` (`:361-391`): validity when judged after revocation (`:375-379`), then `/M` < signer `notBefore` → `Defect::ClaimedTimeBeforeCertificate` (`:380-389`); nothing when `/M` is missing or after `notAfter`.
- `judge_path` (`src/revocation.rs:201-243`): per certificate below the anchor, data issued at or after `notBefore` (`:212-217`, `:233`) and fresh; the latest decides. Shared by the signer's and the TSA's paths.
- `ValidationPolicy` (`src/policy.rs:11-60`), `strict()` (`:64-75`), `dss()` (`:85-96`): eight `bool`s, `#[non_exhaustive]`; `dss()`'s rustdoc lists the attacks it opens (`:77-84`).
- `Defect` (`src/report.rs:84-130`, `#[non_exhaustive]`); `defective` maps `ClaimedTimeBeforeCertificate` to `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE`, path kept by `after_chain` (`:162-176`, `:196-200`).
- `nacre_pdf::SignatureField { name, id, value: Option<ObjectId> }` (`crates/nacre-pdf/src/acroform.rs:8-16`), exhaustive; `Walk::field` refuses a non-reference `/V` (`:155-163`).

## Attachment points
- `/M` rules: `after_revocation`, after the `notBefore` check; two new `Defect` variants mapped beside `ClaimedTimeBeforeCertificate` (`report.rs:196`).
- Late data: the filter of `judge_path` (`revocation.rs:233`), `notAfter` read with `notBefore` (`:212-217`).
- TSA certificates: the `Error::MalformedCertificate` scan (`validate.rs:173-186`) also over `SignedData::from_der(token).certificates` of `Signed::timestamps` (`:513`), as `judge` reads them (`:281-283`).
- Ninth switch: `ValidationPolicy`, `strict()`, `dss()`; `check`/`signed_bytes` take the policy instead of `whole_file`.
- `/V`: `acroform.rs:155-169` and `SignatureField`; `validate.rs:144-156` lists a field with `value_unreadable` as `NotASignatureDictionary`; `unusable` (`:431-436`) gains `NotASignatureDictionary`.
- Corpus: `examples/forge_pades_attacks.rs` writes new `attacks/*.pdf` deterministically (`:30-111`); rejection tests in `tests/attacks.rs`; switch tests in `tests/policy.rs`; conformance in `tests/conformance.rs` (`:510-766`).

## Verified interfaces
- `validate_with_policy(pdf, anchors, at, source, policy)` (`validate.rs:116-124`). `SignatureValidation { field, report, digest_verified, signature_verified, defect, later_revisions, chain, best_signature_time }` (`report.rs:11`), built by `sound`, `after_chain`, `defective` (`:136-213`).
- Test support: `forge::{key, issue_with(Role, …, Extensions), crl, ForgedTsa, signed, with_dss, Extensions::RepeatedKeyUsage, Role::Tsa}` (`tests/support/forge.rs:57-418`); `forge::signed` always writes `/M` 2026-10-22T08:00Z (`:392-396`), as `nacre_pades::sign` does (`crates/nacre-pades/src/sign.rs:103`). `Stub` answers each issuer's CRL (`tests/revocation.rs:320-342`). `Pki::{basic_valid, stamped, tsa, judge_under}` (`tests/revocation.rs:99-190`).
- Conformance helpers: `nacre` (`tests/conformance.rs:65`), `confront_signatures` (`:121`), `confront_error` (`:153`), `forged_signer` (`:453`), `intermediate_crl` (`:482`).
- Chain corpus: fixed secrets root `[0x31; 32]`, intermediate `[0x32; 32]` (`examples/forge_chain_attacks.rs:43-44`), certificates in `tests/corpus/chain/*.der`; `chain-expired` leaf `notAfter` 2026-06-01 (`:80-82`); same `key()` as `forge::key` (`:369`, `forge.rs:57`).
- `nacre-pades` reads `field.value` only to skip empty fields (`crates/nacre-pades/src/archive.rs:94-95`) and names only (`sign.rs:144-150`); nobody outside `acroform.rs` builds a `SignatureField`.

## Traps
- `expired_not_revoked_is_out_of_bounds_not_revoked` (`tests/revocation.rs:532-565`) uses `Pki::intermediate_crl`, issued at 10:00 (`:128-132`), for a signer expired at 09:00 (`:534`): the late-data rule turns it into `CERTIFICATE_CHAIN_GENERAL_FAILURE`; its CRL must move before `notAfter`. Its catalog row (`revocation.md:96`) changes with it.
- Any test with a passing chain and no `/M` flips to `SIG_CONSTRAINTS_FAILURE`; every PAdES writer here sets `/M`, so only new helpers lack it.
- `chain-expired.pdf`'s `/M` (2026-10-22) is after its `notAfter`: the `/M` rule is reached only once revocation passed, which never happens for it.
- The isolation test must read `docs/security/attacks/*.md` and list `tests/corpus/attacks/` at run time, from `CARGO_MANIFEST_DIR`: `include_str!` of a path outside the crate breaks a packaged build.
- `SignatureField` gains a field: `nacre-pdf`'s `corpus.rs:81-83` and every reader of `.value` keep compiling.
- The bench writes `conformance/pki/out/` (ignored); conformance tests run with `--ignored` only.
- No migration.

## Open questions
- A missing or non-name `/SubFilter` under `dss()`: not observed; the plan keeps it refused under both presets.
- A CRL carrying `expiredCertsOnCRL` or an OCSP response carrying `archiveCutoff`: DSS may keep late data then (not observed, no bench case); Nacre reads neither, so it stays stricter under both presets.
- The late-data rule for a CA or a TSA certificate, and for OCSP (Nacre dates a response by `producedAt`): not observed; `judge_path` applies it to every certificate and item alike.
- Which defect DSS reports first when `/M` is missing and revocation fails too: not observed; Nacre keeps chain and revocation first, as for the `notBefore` rule.
- A document-timestamp token certificate repeating an extension: s18 judges document timestamps.

## Complexity
Story 3 → 4. Each rule is a few lines, but the story also changes a public type of `nacre-pdf`, adds two corpus files, turns the catalog into a contract a test reads, needs revocation data for the chain corpus in that test, and adds six bench tests.

## Split
Not needed at 4.
