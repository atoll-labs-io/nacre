---
validated: yes
---
# Plan — s43-dss-parity

[Story](../stories.md) · [Research](../research/s43-dss-parity.md)

Branch `story/s43-dss-parity`. Read `docs/research/s43-dss-parity.md` first, its spike table especially; this plan builds on it without repeating it. ADR-0027 (ninth switch) and ADR-0028 (`/V` reported by `nacre-pdf`) are accepted: the person chose both on 2026-10-24.

## Story
Under `dss()`, DSS 6.5.1's verdict on the six shapes s41 left; `strict()` never laxer than DSS nor than today. AC1: no `/M`, or `/M` after the signer's `notAfter` → `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE` under both presets. AC2: expired signer, `/DSS` data issued after `notAfter` → `CERTIFICATE_CHAIN_GENERAL_FAILURE` under `dss()`; data issued before keeps today's verdict. AC3: under `dss()`, a signature-timestamp certificate repeating an extension is an error; under `strict()`, a defect. AC4: switch `refuse_unsupported_sub_filters`; off, a sound CMS under another `/SubFilter` is `TOTAL_PASSED` with no ETSI level; ADR-0027. AC5: `nacre-pdf` reports a `/V` that is not a reference to a dictionary; `strict()` lists it failed, `dss()` does not list it. AC6: over the attack corpus, `strict()` minus one switch, for each of nine, changes only what that switch's rule explains, each named in the catalog. AC7: under `strict()` every catalogued attack stays rejected; under `dss()` only those marked « ouverte sous `dss()` » open. AC8: one conformance test per shape.

Corrections the lead makes to the story text (outside `Owns`):
- AC2: the late data is dropped "sous les deux préréglages", as DSS does for a signer valid at the stamp too (research, e1); under `strict()` the expired signer of n01 stays `OUT_OF_BOUNDS_NO_POE`.
- AC1: "sans `/M`" becomes "sans `/M` lisible" (m1).
- AC3: "sous `strict()`, il reste jugé comme un défaut": the TSA path gets the defect, the timestamp proves no time, the signature is judged at the control date (n04).

## Reuse

| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Signature with a chosen `/SubFilter` and `/M` (tests) | `Update::sign(SignatureSpec)`, `PreparedSignature::signed_parts`/`embed`, `nacre_cms::sign_detached(…, &Profile::PADES, None)`, as the spike's `custom` (`s18-spike2/src/bin/forge2.rs:26-46`) | `forge::signed` and `nacre_pades::sign` always write `/M` and the PAdES `/SubFilter` (`forge.rs:392-396`, `sign.rs:103`) |
| Fresh CRLs for the chain corpus (tests) | `forge::crl` (`forge.rs:208`) with `forge::key(&[0x32; 32])`, `forge::key(&[0x31; 32])` and `tests/corpus/chain/{intermediate,root}.der` | — |
| Revocation source for the isolation test | `Stub` (`tests/revocation.rs:320-342`), moved to `tests/support/mod.rs` | — |
| Corpus files | `examples/forge_pades_attacks.rs` (`:30-111`, `hand`, `sign_inner`) | — |
| `/M` defects | `Defect` and its mapping beside `ClaimedTimeBeforeCertificate` (`report.rs:129`, `:196-200`), `after_revocation` (`validate.rs:361-391`) | — |
| Late data | the `notBefore` filter of `judge_path` (`revocation.rs:212-217`, `:233`) | — |
| TSA certificate scan | `repeats_extension` (`chain.rs:530`), `SignedData::from_der(token).certificates` as `judge` does (`validate.rs:281-283`) | — |
| Unreadable `/V` | `SignatureField` (`acroform.rs:8-16`) gains one `bool` | an enum replacing `value` breaks `nacre-pades` (`archive.rs:94-95`), outside `Owns` (ADR-0028) |
| Catalog reader (isolation test) | `std::fs::read_to_string`, `str::split('|')`, `std::fs::read_dir` from `CARGO_MANIFEST_DIR` | no markdown crate is a dependency; `include_str!` outside the crate breaks a packaged build |

## Tasks
1. [x] **Test support.**
   - Move `Stub` from `tests/revocation.rs:320-342` to `tests/support/mod.rs`, unchanged.
   - `forge::custom_signed(signer, sub_filter: &[u8], claimed: Option<&[u8]>) -> Vec<u8>`: `unsigned.pdf` signed once, field `Signature1`, `/M` written only when `claimed` is given, built from the Reuse row.
   - `forge::patch(pdf, from, to) -> Vec<u8>`: replaces the last occurrence of `from` by `to` padded with spaces to the same length (the spike's `patch`, `s43-spike/src/bin/forge3.rs`).

   No test of its own: tasks 3 to 9 use them.
2. [x] **`nacre-pdf` reports a non-reference `/V`** (ADR-0028).
   - `SignatureField` becomes `#[non_exhaustive]` and gains `pub value_unreadable: bool`, documented: "`/V` is present but neither `null` nor a reference; `value` is then `None`".
   - `Walk::field` (`acroform.rs:155-169`) records such a field instead of returning `Error::WrongType`. The crate documentation of `Document::signature_fields` (`document.rs:106-109`) says so.

   Test, new `crates/nacre-pdf/tests/acroform.rs`: a signed document whose `/V` is patched to `7`, then to `<<>>`, parses; its field is listed with `value: None`, `value_unreadable: true`. The unpatched file gives `false`. Without the change, `Document::parse` fails.
3. [x] **`validate` lists it under `strict()`, drops it under `dss()`.**
   - In `validate_with` (`validate.rs:144-156`), a field with `value_unreadable` is listed with `Defect::NotASignatureDictionary`, its value id becoming an `Option` in the tuple; the SSA and DocMDP filter (`:215-220`) matches only a `Some`.
   - `unusable` (`:431-436`) also covers `NotASignatureDictionary` (n08b, v2). The rustdoc of `list_unusable_signatures` (`policy.rs:31-34`) and of `Defect::NotASignatureDictionary` (`report.rs:85-86`) say both shapes.
   - Corpus, through `forge_pades_attacks`: `attacks/usf-v-direct.pdf` (`/V 7`) and `attacks/usf-v-stream.pdf` (`/V` naming the page's content stream), each with its row and SHA-256 in `tests/corpus/README.md`.

   Tests:
   - `usf_v_direct_is_rejected` and `usf_v_stream_is_rejected` in `tests/attacks.rs`, through `rejected` (`:20-31`): `NotASignatureDictionary`.
   - `unusable_signatures_switch` (`tests/policy.rs:123-143`) gains both files: not listed with the switch off.
4. [x] **Ninth switch `refuse_unsupported_sub_filters`** (ADR-0027).
   - Field, `strict()` true, `dss()` false (`policy.rs:13-96`). Its rustdoc says "Off, any other `/SubFilter` name is verified as a detached CMS and gets no ETSI level". `dss()`'s list of opened attacks adds it.
   - `check` and `signed_bytes` (`validate.rs:441-503`) take `&ValidationPolicy` instead of `whole_file`. With the switch off, any `Object::Name` passes step 2. A missing or non-name `/SubFilter` stays `UnsupportedSubFilter` under both presets (research, open questions).
   - Corpus: `attacks/subfilter-unsupported.pdf`, a sound CMS of the test key under `/SubFilter /adbe.x509.rsa_sha1`, with its README row.

   Tests:
   - `subfilter_unsupported_is_rejected` in `tests/attacks.rs`: `UnsupportedSubFilter`.
   - `unsupported_sub_filters_switch` in `tests/policy.rs`: with the switch off, `sound` (`:36-49`).
5. [x] **Signature-timestamp certificates in the malformed-extension scan** (AC3). With `judge_malformed_extensions` off, the scan of `validate.rs:173-186` also covers the `certificates` of each `SignedData` in `Signed::timestamps`. `/DSS` certificates stay out (n05). Update the rustdoc of the switch (`policy.rs:48-54`) and of `validate_with_policy` (`validate.rs:112-115`).

   Test in `tests/revocation.rs`, with `Pki`: a B-T whose TSA certificate (`issue_with(Role::Tsa, …, Extensions::RepeatedKeyUsage)`) repeats `keyUsage`, the signer's CRLs in `/DSS`. Under `strict()`: `TOTAL_PASSED`, `best_signature_time` `None`. With the switch off: `Error::MalformedCertificate`.
6. [x] **The two `/M` rules, under both presets.** In `after_revocation`, after the `notBefore` check (`validate.rs:380-389`):
   - no `/M`, or one `pdf_date` cannot read, gives new `Defect::ClaimedTimeMissing`;
   - a `/M` after the signer's `notAfter` gives new `Defect::ClaimedTimeAfterCertificate`.

   Both are mapped like `ClaimedTimeBeforeCertificate` (`report.rs:196-200`): `INDETERMINATE` / `SIG_CONSTRAINTS_FAILURE`, path kept. Rustdoc: `Defect`, `validate_with_revocation` (`validate.rs:86-89`), `lib.rs:37-38`.

   Tests in `tests/revocation.rs`, `Pki` signer, CRLs in `/DSS`, under `strict()` and `dss()`:
   - `missing_claimed_time_is_a_constraints_failure`: rows no `/M` and `/M (garbage)`;
   - `claimed_time_after_not_after_is_a_constraints_failure`: `/M` `D:20270601000000Z` on a signer valid at the control date.
7. [x] **Late data, under both presets.** In `judge_path` (`revocation.rs:201-243`), an item issued after its certificate's `notAfter` is not usable, read from the same certificate as `notBefore` (`:212-217`). This rule is no switch (ADR-0026, ADR-0027); its rustdoc and that of `validate_with_revocation` (`validate.rs:72-86`) say so.

   Tests in `tests/revocation.rs`:
   - `expired_not_revoked_is_out_of_bounds_not_revoked` (`:532-565`) takes a CRL issued before the signer's `notAfter` (`crl` at 08:00), its assertions unchanged (n01d).
   - New `data_issued_after_not_after_does_not_count`, two rows:
     - (a) B, expired signer, CRL after `notAfter`, `judge_validity_before_revocation` off → `RevocationDefect::Missing`, `CERTIFICATE_CHAIN_GENERAL_FAILURE` (n01c);
     - (b) B-T, signer valid at the stamp and expired at the control date, CRL after `notAfter`, under `strict()` → the same (e1).
8. [x] **The catalog as a contract, and the isolation tests** (AC6, AC7).
   - Catalog, in `docs/security/attacks/{pades,cms,revocation}.md`:
     - every row whose case is a file of `crates/nacre-validate/tests/corpus/attacks/` holds in its last column, « Ouverte sous », the backticked name of each switch whose being turned off alone changes its verdict. The cell starts with `` `dss()` `` when the attack opens under `dss()`, with `aucune` otherwise. No `idem` in that column; the column's paragraph (`pades.md:24`) says this format;
     - rows for the three new files;
     - the order of the checks, steps 1 and 2 (`pades.md:9-10`);
     - the `/M` line (`pades.md:83`), the TSA certificates of `chain-malformed-extension` (`cms.md:41`), and `revocation.md:96` with a row for the late data.
   - Two tests in `tests/policy.rs`. Each judges every `*.pdf` of `tests/corpus/attacks/`, read at run time, with the chain root at 2026-10-22T00:00Z. The source is `Stub` answering a "not revoked" CRL of the chain intermediate and of the root, issued 2026-10-21T12:00Z and forged at test time (Reuse). The verdict of a file is its `Error` variant, or the list of (field, indication, sub-indication) of its signatures.
     - `each_switch_changes_only_what_the_catalog_names`: for each of the nine switches, the files whose verdict under `strict()` minus that switch differs from `strict()` are exactly the rows whose cell names it. Every file appears in exactly one row, and every backticked name in those cells is one of the nine.
     - `dss_opens_only_what_the_catalog_marks`: a file is opened when its verdict under `dss()` differs from `strict()` and `dss()` lists a signature with no defect. The opened files are exactly the rows whose cell starts with `` `dss()` ``.
   - Under `strict()`, rejection stays proven by `tests/attacks.rs`, one test per file, unchanged but for task 3 and 4's additions.
   - When the two tests disagree with the catalog, each difference is read against the switch's rule. A cell is corrected only when the rule explains the change. Any other difference stops the run and goes to the lead.
9. [x] **Six conformance tests**, `#[ignore = "conformance"]`, in `tests/conformance.rs` with `confront_signatures`, `confront_error`, `nacre`, `forged_signer`, `intermediate_crl`, task 1's helpers and the bench source. Each asserts DSS's verdict and Nacre's under `dss()`, then Nacre's under `strict()`:
   - `claimed_time_missing`: no `/M`, and `/M (garbage)` → `SIG_CONSTRAINTS_FAILURE` under both presets (n11, m1);
   - `claimed_time_after_not_after`: n02 → the same, under both;
   - `data_issued_after_not_after`:
     - n01c → `CERTIFICATE_CHAIN_GENERAL_FAILURE` under `dss()`, `OUT_OF_BOUNDS_NO_POE` under `strict()`;
     - n01d → `OUT_OF_BOUNDS_NOT_REVOKED` under `dss()`;
     - e1 → `CERTIFICATE_CHAIN_GENERAL_FAILURE` under both;
   - `malformed_timestamp_certificate_policy`: n04 → DSS and `dss()` error; `strict()` `TOTAL_PASSED`, no best-signature-time;
   - `unsupported_sub_filters_policy`: n06 and n07 → `TOTAL_PASSED` under `dss()`, `TOTAL_FAILED` / `FORMAT_FAILURE` under `strict()`;
   - `unreadable_signature_value_policy`: n08 and n08b → no signature from DSS and `dss()`; one `TOTAL_FAILED` under `strict()`.

   Run them on the bench (`conformance/README.md`): `cargo test -p nacre-validate --all-features --test conformance -- --ignored`, then `podman compose -f conformance/compose.yaml down`. A verdict that differs from the research's table stops the run and goes to the lead.
10. [x] **Docs.**
    - `docs/decisions/0026-runtime-validation-policy.md`: frontmatter `superseded-by: [0027]`, nothing else (Law 6); its status stays `accepted`, since only its table is replaced.
    - The rustdoc of `lib.rs:5-51` and `validate.rs:33-115` covers the three rules for both presets and the ninth switch.

## Scene viewpoints
—

## Run interdicts
- Empty diff outside `crates/nacre-validate/`, `crates/nacre-pdf/`, `docs/security/attacks/`, the research, this plan, ADR-0027, ADR-0028 and the one frontmatter line of ADR-0026. In particular `crates/nacre-pades/`, `crates/nacre-conformance/`, `crates/nacre-core/`, `conformance/`, `.github/`, `Cargo.toml` (root) and `docs/stories.md` stay untouched.
- The body of ADR-0026 is unchanged.
- Out of scope: no level computed (s18), no document timestamp judged (s18), the TSA path's freshness window (`validate.rs:420`, s42), no CI or feature matrix (s44).
- `strict()` keeps every verdict it gives today, except three that get stricter: a missing or unreadable `/M` and a `/M` after `notAfter` (task 6); data issued after `notAfter` (task 7); a non-reference `/V`, now listed `TOTAL_FAILED` instead of `Err` (task 3). No verdict of `strict()` moves towards `TOTAL_PASSED`.
- The existing assertions of `tests/attacks.rs` are unchanged.
- A catalog cell is never edited only to turn task 8's tests green (task 8, last bullet).
- No new dependency, no `[workspace.dependencies]`, no `Cargo.lock`, no `include_str!` of a path outside the crate.
- No public TSA, no online DSS demo, no `NACRE_DSS_URL` other than local; never stop `patelle-dss`, never touch `omniroute`; the bench is down at the end.

## The pivot
That the late-data rule is DSS's for every certificate and item, and belongs in `judge_path` for both presets. The spike saw it on the signer only, with CRLs (n01–n01d, e1, e2). How it could be wrong:
- DSS keeps late data for a CA, a TSA or an OCSP response, or honours `expiredCertsOnCRL` / `archiveCutoff`. `dss()` would then be stricter than DSS on such a file. Compare with the s18 campaign, which forges bench cases per shape.
- The isolation test's "verdict" (indication and sub-indication per field) misses a change of defect within one sub-indication. Compare `Debug` of the defects on the rows where a switch changes nothing.
- "Opened" (a signature with no defect under `dss()` where `strict()` refused) mislabels a row. Then the catalog and the criterion disagree, and task 8's last bullet sends it to the lead.

## Files touched
- `crates/nacre-pdf/src/{acroform.rs, document.rs}`, `crates/nacre-pdf/tests/acroform.rs`.
- `crates/nacre-validate/src/{policy.rs, validate.rs, revocation.rs, report.rs, lib.rs}`.
- `crates/nacre-validate/tests/{attacks.rs, policy.rs, revocation.rs, conformance.rs, support/mod.rs, support/forge.rs}`.
- `crates/nacre-validate/examples/forge_pades_attacks.rs`, `crates/nacre-validate/tests/corpus/attacks/{usf-v-direct,usf-v-stream,subfilter-unsupported}.pdf`, `crates/nacre-validate/tests/corpus/README.md`.
- `docs/security/attacks/{pades,cms,revocation}.md`.
- `docs/decisions/0026-runtime-validation-policy.md` (frontmatter), `0027-unsupported-sub-filter-switch.md`, `0028-pdf-reports-unreadable-signature-value.md`.

## Test strategy
Every rule lives in `nacre-validate` or `nacre-pdf` (service layer); there is no adapter.

New automated tests, 17 within the budget of 25:
- task 2: 1, in `nacre-pdf`, where the reading lives;
- task 3: 2 rejection tests, one per corpus file, as `tests/attacks.rs` does for each; the switch row extends an existing test;
- task 4: 2, the strict refusal and the switch off;
- task 5: 1, both presets in one test;
- task 6: 2, one per rule;
- task 7: 1, two rows; one changed test;
- task 8: 2;
- task 9: 6, one per shape (AC8), DSS as the judge.

Each switch's rule keeps its own test in `tests/policy.rs` or `tests/revocation.rs`. Task 8 adds no rule; it proves that the switches touch nothing else.

The conformance tests run only with `--ignored`, on the bench at execute and in CI. The tests of each task run alone; the full suite and clippy run once at the end, through `po-run --story s43-dss-parity`.

Visual checks: none (`Surface: endpoint`).

## Done when
- Every AC holds: the six shapes give DSS's verdict under `dss()` on the bench, and task 8's two tests pass.
- Business tests green; `cargo test --workspace` and clippy green through `po-run`; a review with no open critical finding.
- One commit, landed through a pull request.
