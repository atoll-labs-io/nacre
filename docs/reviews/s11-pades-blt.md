# Review: s11-pades-blt

The ship is allowed. There are no critical or major findings, only six minor ones.

Reviewed tree: acb8c8e33197a051fd559bdf0d249bc77ebc556b
Fix loop: 0
Review status: complete
Lenses run: Dependencies (`crates/nacre-pades/Cargo.toml` adds `sha1 = "0.11"` to `[dependencies]` and `nacre-revocation` to `[dev-dependencies]`)

## Scope
- Every changed path is under `crates/nacre-pades/`, which is the story's `Owns` line. The rest is the story's own pipeline files: research, plan, verification record, QA folder.
- The story touches no file owned by a running lane. `s15-validate-revisions` owns `crates/nacre-validate/`, `crates/nacre-pdf/` and `docs/security/attacks/pades.md`. `s39-error-kind-from-sources` owns `crates/nacre-core/`, `crates/nacre-tsp/src/` and `crates/nacre-revocation/src/`.
- No file in `nacre-pdf`, `nacre-core`, `nacre-cms`, `nacre-revocation`, `conformance/` or `docs/stories.md` was changed, as the plan forbids.

## What I relied on
- **Verification record:** `po-gate verif-current` exit 0. With `Verification mode: record`, the last runs on this code passed: `cargo test --workspace` and `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0. I did not rerun them.
- **QA:** `po-gate qa-current` exit 0, so the QA report covers this code. Its 4 verified findings are carried below as findings 1 to 4.
- **Lowered checks:** `po-gate floor-guard s11-pades-blt main` exit 0. Nothing was lowered.
- **Test count:** 6 new tests plus 5 error-kind rows, within the budget of 25.

## Checks done
- **Plan against diff:** tasks 1 to 7 are all present.
  - The `Error` variants and their `kind()` follow ADR-0016 (the kind comes from the source).
  - `SignedPdf` prints only its length in `Debug`.
  - The issuer walk keeps a visited set keyed on the DER bytes, so each certificate is handled once and the walk ends after at most the pool size.
  - The `/DSS` merge keeps earlier entries. The VRI key is computed over `/Contents` including its zero padding.
  - Any failure after `embed` returns `LongTerm` carrying the B-T file.
  - `src/` builds no `nacre_core::Error`, reads no clock and indexes or unwraps nothing.
- **What the diff calls:** `Update::add`, `add_stream`, `set_catalog` and `finish` (`crates/nacre-pdf/src/revision.rs:98-133`) exist as used. So do `Document::catalog`, `catalog_id` and `object`, `RevocationSource::revocation(certificate, issuer)` and the `#[non_exhaustive]` `RevocationData`.
  - The slot capacity is in bytes. `embed` rejects a CMS longer than `slot.len`, which is the same value as `contents_len = capacity`, so the padding length used for the VRI key is correct.
- **Bite.** Each rule was disabled, then only `cargo test -p nacre-pades --test sign` was run. Every file was restored and checked with `git diff --exit-code`.

  | Rule disabled | Tests that failed |
  | --- | --- |
  | Skip asking about a self-signed certificate (`ltv.rs`) | 1 |
  | Zero padding in the VRI key (`dss.rs`) | 1 |
  | Wrapping later errors in `LongTerm` (`sign.rs`) | 2 |
  | Passing no token certificates to the walk (`sign.rs`) | 3 |

- **Probe on a real file** (scratch crate under `/tmp/tmp.ZSP7MxOYAG/`): signing `crates/nacre-pdf/tests/corpus/real/signed-lta-pyhanko.pdf` at LT works. That file stores its `/Certs`, `/CRLs`, `/OCSPs` and `/VRI` as indirect objects. They were merged correctly: Certs 5→7, CRLs 1→2, VRI 1→2.
- **Values:** the VRI key with padding matches pyHanko's corpus file (research, line 9). No timestamp or size limit changed.
- **Other callers:** `nacre-validate` (`src/validate.rs:174`) and the `nacre-pkcs11` example use only `sign`, which is unchanged. `Level` and `Error` are `#[non_exhaustive]`, so the new variants break no caller.
- **Dependencies lens:** `sha1 0.11` is already used in the workspace (`crates/nacre-revocation/Cargo.toml:18`) and shares `digest 0.11` with `sha2`. The plan names both additions. `Cargo.lock` stays out of git. No `[workspace.dependencies]` was added. Nothing to report.

## Findings
- **[minor] A malformed `issuers` list is only detected after the signer has signed and the TSA has answered** (QA finding 1, verified). `crates/nacre-pades/src/ltv.rs:34-43` parses the pool inside `material`, which runs after `embed`. With a PKCS#11 card or a paying TSA, this costs one signature and one timestamp. The B-T file is still returned, and this follows the plan (task 4). Fix: parse `issuers` before signing.
- **[minor] `Error::Certificate` does not say which list holds the bad item, or where** (QA finding 2, verified). `crates/nacre-pades/src/error.rs` prints "a certificate is not X.509 DER", which does not say whether the item is in the signer's chain, the token or `issuers`. Fix: add the list and the index to the variant.
- **[minor] A second LT signature stores again in `/DSS` the certificates and CRLs already there** (QA finding 3, verified). `crates/nacre-pades/src/dss.rs:104-118` adds about 3.4 kB per signature. The plan accepts this (task 3). It is worth reconsidering before s12's `extend` adds more.
- **[minor] Bytes that are not revocation data are stored in `/DSS` and the call succeeds** (QA finding 4, verified). In `crates/nacre-pades/src/ltv.rs:73-80`, the data `RevocationData::Crl` carries is stored without even a DER shape check. The caller gets a file that looks LT, gets no error, and no validator would call it LT. The plan chose "store without judging". Fix: add a minimal check that the data is a DER `CertificateList` or `OCSPResponse`, or record that s17 owns this.
- **[minor] The issuer is chosen by subject name only, first match wins** (`crates/nacre-pades/src/ltv.rs:63-70`). When two certificates in the pool share a subject (a renewed CA with a new key), the wrong issuer can be passed to `RevocationSource`. The usual result is a revocation failure, which returns `LongTerm` with the B-T file, so the damage is contained. The plan names this risk and defers path building to s17. Only a certificate with a matching name is ever passed as issuer, as the plan's pivot asks. Fix: break ties on the authority and subject key identifiers.
- **[minor] The merge path for an existing `/DSS` whose arrays or `/VRI` are indirect objects has no test** (`crates/nacre-pades/src/dss.rs:26-75`, `resolve`, `array` and `dictionary`). `second_lt_signature_keeps_the_earlier_dss` only covers nacre's own layout, which uses direct arrays and a direct `/VRI`. pyHanko writes the indirect form. My probe shows that path works today, but no test protects it, and s12 depends on it.

## Not verified
- **Criterion 1, DSS saying `TOTAL_PASSED` at `PAdES-BASELINE-LT`:** I did not replay it. `bench_signature_is_pades_baseline_lt` is `#[ignore = "conformance"]`. The verification record says one hand run passed against DSS 6.5.1, with the report outside git, and QA lists it as not seen. To cover it, run `cargo test -p nacre-pades --test conformance -- --ignored` against `conformance/compose.yaml`, or check the CI conformance job on the pull request.
- **The name-loop guard (two certificates issuing each other):** no test, no QA walk, and no mutation, because these tests cannot build such a pair. I only read the code: the visited set ends the walk. To cover it, add a crafted pair of certificates as a corpus case.
- **Revocation through a real remote OCSP responder or CRL server, and under network latency:** QA used only servers on loopback (QA, Not seen). To cover it, do one hand run against a public test PKI.
- **An RSA signer or TSA, and an OCSP response signed by a delegated responder:** not exercised by QA or by these tests. To cover it, run the conformance bench with an RSA profile.
- **Two certificates in the pool sharing a subject:** not tested (finding 5). To cover it, add a corpus case with a renewed CA.
- **The story text in `docs/stories.md`:** the plan asks the lead to add `issuers` to criterion 1's wording there. That is the lead's job, outside this diff.

Max severity: minor
Ship allowed: yes

---

# Review — s11-pades-blt

[Story](../stories.md) · [Plan](../plans/s11-pades-blt.md) · [Verification](../verif/s11-pades-blt.md)

Diff reviewed: `git diff main...story/s11-pades-blt`, in a context that did not write it. Findings rated critical, major or minor.

Review status: complete
Fix loop: 0
Reviewed tree: acb8c8e33197a051fd559bdf0d249bc77ebc556b

## When blocked
- Failure cause: none, the review is complete
- Missing: none
- Required adaptation: none
- Next action: none

## Ownership
I listed the diff with `git diff --name-only main...story/s11-pades-blt` and held each path against `Owns: crates/nacre-pades/`.
- [x] Every path is inside `Owns`, apart from the story's own research, plan, verification record and QA folder, which are in scope by rule.
- [x] No path is outside `Owns`.
- [x] No path is inside another running story's `Owns`. `s15-validate-revisions` owns `crates/nacre-validate/`, `crates/nacre-pdf/` and `docs/security/attacks/pades.md`. `s39-error-kind-from-sources` owns `crates/nacre-core/`, `crates/nacre-tsp/src/` and `crates/nacre-revocation/src/`.
- [x] The story has an `Owns` line.

## Evidence reused
- [x] `po-gate verif-current s11-pades-blt` → passes, so the record is reused. On this code, the last runs of `cargo test --workspace` and of `cargo clippy --workspace --all-targets --all-features -- -D warnings` both exited 0. I did not rerun them.
- [x] `po-gate qa-current s11-pades-blt` → passes. The story goes to QA (`QA stage: surfaces`, `Surface: endpoint`). Its 4 verified QA findings are carried to Findings.

## Plan
- [x] Tasks 1 to 7 are all present, and nothing is outside the plan. One edit to `docs/stories.md` (adding `issuers` to criterion 1) falls to the lead, outside this diff.
- [x] Each run interdict holds:
  - The diff is empty outside `crates/nacre-pades/` and the story's evidence files.
  - The existing B and T tests pass unmodified.
  - `[dependencies]` gains only `sha1`, `nacre-revocation` is a dev-dependency only, and there is no `[workspace.dependencies]`.
  - `src/` builds no `nacre_core::Error`, reads no clock, opens no connection, prints nothing, and indexes or unwraps nothing.
  - Revocation is asked only after `embed`, so after the TSA has answered.
  - The CMS gets no CRL, no OCSP response and no `adbe-revocationInfoArchival` attribute.
  - The tests reach no public service.

## References
- [x] Every call opened and confirmed:
  - `Update::add`, `add_stream`, `set_catalog` and `finish` (`crates/nacre-pdf/src/revision.rs:98-133`).
  - `Document::catalog`, `catalog_id` and `object`.
  - `RevocationSource::revocation(certificate, issuer)` and the `#[non_exhaustive]` `RevocationData` (`crates/nacre-core/src/revocation.rs`).
  - `SignedData::from_der(..).certificates`.
  - `nacre_conformance::pki_dir`.
- [x] No value that only looks right:
  - The `/Contents` slot capacity is in bytes: `embed` checks the CMS against `slot.len`, which is the `contents_len = capacity` it was given. So the zero padding used for the VRI key has the right length.
  - Including that padding in the VRI key matches pyHanko's corpus file (research, line 9).

## Rules
- [x] The `AGENTS.md` conventions are respected: `forbid(unsafe_code)` is unchanged, no panics on input, errors are returned, `SignedPdf` prints only its length in `Debug`, and messages carry no secret or path.
- [x] No accepted ADR is contradicted: `Revocation` and `LongTerm` take their `kind()` from their source, as ADR-0016 requires.

## Tests
- [x] Floor: `po-gate floor-guard s11-pades-blt main` → exit 0, nothing lowered.
- [x] The assertions pin down criteria 1 to 4. None of the six empty test shapes appears: the recording revocation source records what it is asked and does not reimplement the walk.
- [x] Within `Test budget`: 6 new tests plus 5 error-kind rows, out of 25.
- [x] Bite. Each rule was disabled, then only `cargo test -p nacre-pades --test sign` was run. Each change was undone and `git diff --exit-code` was clean.

  | Rule disabled | Tests that failed |
  | --- | --- |
  | Skip asking about a self-signed certificate (`ltv.rs`) | 1 |
  | Zero padding in the VRI key (`dss.rs`) | 1 |
  | Wrapping later errors in `LongTerm` (`sign.rs`) | 2 |
  | Passing no token certificates to the walk (`sign.rs`) | 3 |

- [x] No test was made useless by the story.

I also ran a probe in a scratch crate under `/tmp/tmp.ZSP7MxOYAG/`. Signing `crates/nacre-pdf/tests/corpus/real/signed-lta-pyhanko.pdf` at LT merged its indirect `/Certs`, `/CRLs`, `/OCSPs` and `/VRI` correctly: Certs 5→7, CRLs 1→2, VRI 1→2.

## Neighbours
- [x] The other callers are `crates/nacre-validate/src/validate.rs:174` and `crates/nacre-pkcs11/examples/sign_pdf.rs:17`. Both use only `sign`, which is unchanged. `Level` and `Error` are `#[non_exhaustive]`, so the new variants break no caller.

## Lenses
Lenses run: dependencies (`crates/nacre-pades/Cargo.toml` adds `sha1 = "0.11"` and the dev-dependency `nacre-revocation`)
- [x] Nothing to grade:
  - `sha1 0.11` is already used in the workspace (`crates/nacre-revocation/Cargo.toml:18`) and shares `digest 0.11` with `sha2`.
  - The plan names both additions.
  - `Cargo.lock` stays out of git.

## Findings
- minor — crates/nacre-pades/src/ltv.rs:38 — A malformed `issuers` list is only found after the signer has signed and the TSA has answered (QA finding 1, verified).
  The certificate pool is parsed inside `material`, which runs after `embed`. With a PKCS#11 card or a paying TSA, this wastes one signature and one timestamp. The B-T file is still returned, as plan task 4 intends. Fix: parse `issuers` before signing.
- minor — crates/nacre-pades/src/error.rs:50 — `Error::Certificate` ("a certificate is not X.509 DER") does not say which list holds the bad item, or at what position (QA finding 2, verified).
  The item can be in the signer's chain, the token's certificates or `issuers`. Fix: add the list and the index to the variant.
- minor — crates/nacre-pades/src/dss.rs:110 — A second LT signature stores again in `/DSS` the certificates and CRLs already there, about 3.4 kB per signature (QA finding 3, verified).
  The plan accepts this (task 3). It should be reconsidered before s12's `extend` makes it grow further.
- minor — crates/nacre-pades/src/ltv.rs:75 — Bytes that are not a CRL or an OCSP response are stored in `/DSS`, and the call succeeds (QA finding 4, verified).
  The caller gets a file shaped like LT that no validator would call LT, and no error. This matches the plan's "store without judging". Fix: add a minimal DER shape check, or record that s17 owns it.
- minor — crates/nacre-pades/src/ltv.rs:65 — The issuer is picked by subject name alone, and the first match wins.
  When two certificates in the pool share a subject (a renewed CA with a new key), the wrong issuer can be passed to the `RevocationSource`. The usual result is a revocation failure, which returns `LongTerm` with the B-T file, so the damage is contained. The plan names this risk and defers path building to s17. Fix: break ties on the authority and subject key identifiers.
- minor — crates/nacre-pades/src/dss.rs:26 — The merge of an existing `/DSS` whose arrays or `/VRI` are indirect objects (`resolve`, `array`, `dictionary`) has no test.
  `second_lt_signature_keeps_the_earlier_dss` (`crates/nacre-pades/tests/sign.rs:676`) only covers nacre's own layout, with direct arrays and a direct `/VRI`. pyHanko writes the indirect form. My probe shows the path works today, but nothing protects it, and s12 depends on it.

## Not verified
- **Criterion 1, DSS saying `TOTAL_PASSED` at `PAdES-BASELINE-LT`:** I did not replay it. The test is `#[ignore = "conformance"]`. The verification record reports one hand run that passed against DSS 6.5.1, with the report outside git, and QA lists it under Not seen. A person should run `cargo test -p nacre-pades --test conformance -- --ignored` against `conformance/compose.yaml`, or check the CI conformance job on the pull request.
- **The name-loop guard (two certificates issuing each other):** no test, no QA walk and no mutation, because these tests cannot build such a pair. I only read the code: the visited set keyed on DER bytes ends the walk. A person should add a crafted pair of certificates as a corpus case.
- **Revocation through a real remote OCSP responder or CRL server, and under network latency:** QA only used servers on loopback (QA, Not seen). A person should do one hand run against a public test PKI.
- **An RSA signer or TSA, and an OCSP response signed by a delegated responder:** not exercised by QA or by these tests (QA, Not seen). A person should run the conformance bench with an RSA profile.
- **Two certificates in the pool sharing a subject:** not tested (see the ltv.rs:65 finding). A person should add a corpus case with a renewed CA.

Max severity: minor
Ship allowed: yes
