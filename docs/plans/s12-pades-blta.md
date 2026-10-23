---
validated: yes
---
# Plan — s12-pades-blta

[Story](../stories.md) · [Research](../research/s12-pades-blta.md)

Branch `story/s12-pades-blta`. Read `docs/research/s12-pades-blta.md` first; this plan builds on it without repeating it.

Validated autonomously under `Plan validation: autonomous`: no human reviewed this plan.

**`Owns` now covers the bench.** The first draft was blocked because the story's `Owns` held `crates/nacre-pades/` only. Since `efc717a` (PR #100) it reads `crates/nacre-pades/`, `conformance/pki/`, `conformance/check.sh`, `conformance/README.md`. The lane was forked again from that commit, so `po-bounds` lets through the bench writes of task 1 and the README edit of task 7.

Each criterion was checked against the plan:
- criterion 1 is covered by tasks 3, 4 and 8;
- criterion 2 by tasks 5, 6 and 8;
- criterion 3 by task 5 and the run interdicts;
- criterion 4 by tasks 6 and 8;
- criterion 5 by tasks 1, 4 and 8.

No technical choice deserving an ADR is open. The `Level::LTA` shape and `extend`'s signature belong to the story (precedent: s11 plan). A second TSA section of the same OpenSSL bench stays within ADR-0011. So the reserved ADR-0021 is not used.

## Story
`sign_at_level(…, Level::LTA { tsa, revocation, issuers, document_tsa })` makes B-LT, then appends a `/DocTimeStamp` revision (`/SubFilter /ETSI.RFC3161`) whose token, from `document_tsa`, covers everything before it.

`extend(pdf, tsa, revocation, issuers)` works on a PDF that holds a document timestamp. It appends a `/DSS` update holding the newest document timestamp's TSA chain with its revocation data, under a `/VRI` key for that timestamp, then a new document timestamp from `tsa`. It reads no clock and never refuses because of "too early".

Every earlier revision stays a byte prefix. DSS says `TOTAL_PASSED` / `PAdES-BASELINE-LTA` for an LTA file made with two distinct bench TSAs, and again after `extend`.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Document timestamp slot, byte range, embedding | already in this repository: `Update::sign` with `entries /Type /DocTimeStamp`, `signed_parts`, `embed` (`crates/nacre-pdf/src/revision.rs:136-227,495-528`) | — |
| Token size and DER checks | already in this repository: the checks of `timestamp_signature` (`crates/nacre-pades/src/timestamp.rs:44-60`), split out into one function both callers use | — |
| TSA chain and its revocation for `extend` | already in this repository: `SignedData::from_der(..).certificates` (`crates/nacre-cms/src/model.rs:77,84`), `ltv::material` (`crates/nacre-pades/src/ltv.rs:27`), `dss::append` and `dss::vri_key` (`crates/nacre-pades/src/dss.rs:11,81`) | — |
| Field name `Signature<N>` | already in this repository: `sign.rs:77-81`, moved into one function | — |
| DER token cut out of a padded `/Contents` | dependency already installed: `der` `Header::decode` + `SliceReader` (`Cargo.toml:18`), about 10 lines | `crates/nacre-validate/src/validate.rs:158` `der_prefix` is private, and pades cannot depend on nacre-validate (it is pades' dependent) |
| `Level::LTA`, `extend`, newest-timestamp choice, error variants | new code, about 150 lines in `src/archive.rs` | no crate writes or renews a document timestamp |
| Second bench TSA | already in this repository: `leaf()` in `conformance/pki/generate.sh:48-54`, the `[bench_tsa]` section, `cgi-bin/tsa` | — |

## Tasks
1. [x] **Second bench TSA** in `conformance/pki/` and `conformance/check.sh`.
   - `generate.sh`: `echo 01 > tsa2.serial`, and `leaf tsa2 "Nacre Test Document TSA" v3_tsa`, issued by the intermediate like `tsa`, so the OCSP responder and the CRL cover it.
   - `openssl.cnf`: a `[bench_tsa2]` section copied from `[bench_tsa]`, with `serial`, `signer_cert` and `signer_key` set to `tsa2.*` and `default_policy = 2.999.1.2`.
   - `cgi-bin/tsa`: run `openssl ts -reply -section "${TSA_SECTION:-bench_tsa}"`. A new `cgi-bin/tsa2` runs `TSA_SECTION=bench_tsa2 exec` on `tsa` next to it.
   - `check.sh`: also query `/cgi-bin/tsa2` and verify its token against `tsa2.cert.pem`, exactly as the existing TSA check does (`:36,49`).
   - `pki/README.md` gets the `tsa2` rows and the endpoint.
   Check: `sh conformance/check.sh` prints `bench ready` on a fresh `pki-init` and `up`.
2. [x] **Errors** in `src/error.rs`:
   - `Archive { signed: SignedPdf, #[source] source: Box<Error> }`, message `"the B-LT signature could not be raised to B-LTA: {source}"`, `kind()` → `source.kind()`; `signed` is the B-LT file;
   - `NotArchived`, message `"the PDF holds no document timestamp to extend"`, kind `InvalidInput`;
   - `DocumentTimestamp(&'static str)` for a newest document timestamp whose `/ByteRange` or `/Contents` cannot be read (not one DER SEQUENCE followed by zeros), kind `InvalidInput`, carrying no bytes.

   No variant carries a token, a key or a path.
   Test that fails if wrong: `every_variant_has_its_kind` gains three rows. One is `Archive { source: Box::new(IssuerMissing{..}) }` → `Indeterminate`, which fails if `Archive` hard-codes a kind.
3. [x] **Document timestamp** in a new `src/archive.rs`: `pub(crate) fn document_timestamp(pdf: &[u8], tsa: &dyn TimestampAuthority) -> Result<Vec<u8>, Error>`.
   - It parses the PDF and picks the field name through the function moved out of `sign.rs:77-81`.
   - It calls `update().sign(SignatureSpec { sub_filter: b"ETSI.RFC3161", contents_len: TIMESTAMP_TOKEN_MAX, entries: { /Type /DocTimeStamp } })`, with no `/M`.
   - It takes SHA-256 over `signed_parts()` and asks `tsa.timestamp(Sha256, digest)` once. An error becomes `Error::Timestamp`.
   - It checks the token with the length and DER checks of `timestamp_signature`, moved into `pub(crate) fn check_token(&[u8]) -> Result<Any, Error>` in `timestamp.rs` and used by both, then calls `embed(&token)`.
   Test that fails if wrong: task 6's `level_lta_adds_a_document_timestamp_after_dss`.
4. [x] **The level** in `src/sign.rs`:
   - `Level::LTA { tsa, revocation, issuers, document_tsa: &'a dyn TimestampAuthority }`, with rustdoc: `tsa` time-stamps the signature, `document_tsa` the document, and the two may be distinct.
   - The `LTA` arm runs the `LT` arm's code (factored, not copied), which still wraps an LT failure in `LongTerm` with the B-T file.
   - On the B-LT bytes it then calls `archive::document_timestamp(&lt, document_tsa)`. Any error there becomes `Error::Archive { signed: SignedPdf(lt), source }`.
   - The reserve stays `!matches!(level, Level::B)`.
   - The rustdoc of `sign_at_level`, the crate doc (`lib.rs:2-19`) and the `Cargo.toml` `description` now cover B-LTA and `extend`.
   Test that fails if wrong: task 6's tests. The tests of `tests/sign.rs` pass without being edited.
5. [x] **`extend`** in `src/archive.rs`, re-exported from `lib.rs`: `pub fn extend(pdf: &[u8], tsa: &dyn TimestampAuthority, revocation: &dyn RevocationSource, issuers: &[Vec<u8>]) -> Result<Vec<u8>, Error>`.
   - Among the signature fields, the `/V` dictionaries whose `/SubFilter` is `ETSI.RFC3161` are the document timestamps. There is none → `NotArchived`, before the TSA or the source is asked anything.
   - The newest is the one whose `/ByteRange` `c + d` is largest (checked arithmetic). Its `/Contents` bytes go in whole into `dss::vri_key(&contents, contents.len())`. Its DER prefix, the length taken from the header and every byte after it zero, goes through `SignedData::from_der(..)?.certificates`. A malformed one → `DocumentTimestamp`.
   - Then `ltv::material(&certificates, &[], issuers, revocation)`, `dss::append(pdf, &key, &material)`, and `document_timestamp(&with_dss, tsa)`.
   - Rustdoc: the caller decides when to call it, and nothing here reads a clock or judges whether renewal is due.
   - No indexing or unwrapping.
   Test that fails if wrong: task 6's extend tests.
6. [x] **Service tests** in `tests/sign.rs`, reusing `FakeTsa`, `cms_token`, `chained`, `recording`, `dss()`, `signatures()` and `range_digest`, with an `sign_lta` helper like `sign_lt`:
   - `level_lta_adds_a_document_timestamp_after_dss`: the signer chain is `[leaf, ec-ca]`, `tsa = cms_token([revoked, ec-ca])` and `document_tsa = cms_token([leaf, ec-ca])`, a distinct instance. The test checks:
     - there are two signatures, and the last one has `/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161` and no `/M`;
     - its DER prefix equals the token `document_tsa` returned;
     - `document_tsa.seen == (Sha256, range_digest(out, its /ByteRange))`, and that range ends at the end of the file;
     - each TSA was asked exactly once;
     - the revisions are those of the input plus 3;
     - `dss(&out[..revisions[n-2].end])` is `Some` (the `/DSS` comes before the timestamp);
     - `out` starts with the input.

     It fails if the timestamp comes before `/DSS`, if the wrong TSA is used, or if the imprint misses a range.
   - `document_timestamp_failure_returns_the_lt_file`: `document_tsa` fails. The result is `Err(Archive { signed, source })` with `source` being `Timestamp` and kind `Unavailable`. `signed.0` holds `/DSS` and one signature, and no `/DocTimeStamp`.
   - `extend_renews_the_newest_document_timestamp`: LTA, then `extend` with `cms_token([revoked, ec-ca])`, then `extend` again. After each call:
     - the output starts with the input;
     - there is one more `/VRI` key, equal to the upper-hex SHA-1 of the whole `/Contents` of the newest document timestamp before the call; the second call uses the second timestamp's key, which fails if extend takes the first in field order;
     - that entry lists the timestamp token's certificates and their revocation streams;
     - the source was asked only for the token's non-self-signed certificates;
     - there is one more document timestamp, covering the whole file;
     - the earlier `/VRI` keys keep their references.
   - `extend_refuses_a_pdf_without_document_timestamp`: an LT file → `NotArchived`, kind `InvalidInput`. Neither the TSA nor the source was asked.
   - `extend_refuses_a_malformed_document_timestamp`: an LTA file whose doc-TST `/Contents` has its first byte overwritten in place with hex `00` (same length, so the file still parses) → `DocumentTimestamp`, with no panic.
7. [x] **Bench README**: `conformance/README.md`, ports table, lists `POST /cgi-bin/tsa2`.
8. [x] **Conformance** in `tests/conformance.rs`, `#[ignore = "conformance"]`, each removing its report first. Both use `Level::LTA` with `tsa: HttpTsa(".../cgi-bin/tsa")`, `document_tsa: HttpTsa(".../cgi-bin/tsa2")`, `revocation: Fallback::new(HttpOcspSource::allowing_loopback(), HttpCrlSource::allowing_loopback())` and `issuers: [bench_certificate("root.cert.pem")]`.
   - `bench_signature_is_pades_baseline_lta` validates as `"s12-pades-lta"`. It expects one signature, `TotalPassed`, no sub-indication, and `format == "PAdES-BASELINE-LTA"` (criteria 1 and 5).
   - `extended_signature_stays_pades_baseline_lta`: the same LTA, then `extend(.., &HttpTsa(".../cgi-bin/tsa"), ..)`. It checks that the output starts with the LTA file, then validates as `"s12-pades-lta-extended"` with the same expectations (criteria 2 and 4).

   Run both against a freshly started bench. If DSS answers anything else, stop and report the sub-indication and the timestamp section of the XML report (research, open question 1) instead of loosening the assertion.
9. [x] **Checks**. The task tests run with `cargo test -p nacre-pades --test sign` and `cargo test -p nacre-pades --lib`. Then, once each through `po-run`: `cargo test --workspace`, then `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

## Scene viewpoints
—

## Run interdicts
- The diff is empty outside `crates/nacre-pades/`, `conformance/pki/`, `conformance/check.sh`, `conformance/README.md` and this story's `docs/` files. In particular it is empty in `crates/nacre-pdf/`, `crates/nacre-core/`, `crates/nacre-cms/`, `crates/nacre-revocation/`, `crates/nacre-tsp/`, `crates/nacre-validate/`, `conformance/dss/`, `conformance/compose.yaml`, `.github/`, `docs/stories.md` and the root `Cargo.toml`.
- No new dependency in `crates/nacre-pades/Cargo.toml`, and no `[workspace.dependencies]`.
- `Level::B`, `Level::T` and `Level::LT` outputs are unchanged. The existing tests of `tests/sign.rs` and `tests/conformance.rs` pass without being edited.
- `src/` reads no clock, opens no connection, constructs no `nacre_core::Error`, writes nothing to stdout or stderr, and indexes or unwraps nothing outside `#[cfg(test)]`. `extend` takes no time or age parameter and has no "not due yet" path.
- For one `sign_at_level` call at LTA, the signer signs once, `tsa` is asked once and `document_tsa` once, the document TSA only after `/DSS` is written. In `extend`, the TSA is asked once, after `/DSS`.
- The bench TSA `tsa` and its token are unchanged: the s08 and s11 conformance tests keep passing.
- No test calls a public TSA, OCSP responder or CRL server.

## The pivot
**B-LTA is one more revision on the finished B-LT bytes, and `extend` renews only the newest document timestamp: it adds that timestamp's TSA chain and revocation to `/DSS` under its own `/VRI` key, then a fresh timestamp.** Ways it could be wrong:
- **DSS wants the latest document TSA's data inside the file.** If DSS 6.5.1 does not fetch it online, the first LTA could come back `INDETERMINATE` on its archive timestamp. Compare against the timestamp section of `s12-pades-lta.xml`. The answer would be a second `/DSS` revision after the timestamp, the way pyHanko does it, not a weaker assertion.
- **The "newest" choice.** A foreign file could carry a document timestamp whose `/ByteRange` does not end at a revision end. Picking by `c + d` still finds the latest one written. The reviewer checks the arithmetic is checked and that no field order is assumed.
- **Renewal scope.** ETSI EN 319 142-1 asks at least for the previous timestamp's validation data. Not refreshing the signature's own chains is a choice, and it matches criterion 2. If a reviewer reads the standard otherwise, that is a finding, not a silent extension.
- Turned down: reusing `LongTerm` for a failed document timestamp, which would throw away the fetched `/DSS`; letting `extend` turn a B-LT file into B-LTA, which does a different job under the same name; one TSA serving both roles in the bench, which fails criterion 5.

## Files touched
- `crates/nacre-pades/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/sign.rs`, `src/timestamp.rs`, `src/archive.rs` (new)
- `crates/nacre-pades/tests/sign.rs`, `tests/conformance.rs`
- `conformance/pki/generate.sh`, `openssl.cnf`, `cgi-bin/tsa`, `cgi-bin/tsa2` (new), `README.md`; `conformance/check.sh`, `conformance/README.md`
- `docs/research/s12-pades-blta.md`, `docs/plans/s12-pades-blta.md`

## Test strategy
Automated: 5 new service tests, 3 kind rows and 2 conformance tests, within `Test budget` 25.
- **Service** (`tests/sign.rs`; test key, real CMS tokens, the recording source, no network) covers:
  - the order and the content of the timestamp (criteria 1 and 4, distinct TSAs at the API);
  - the B-LT file handed back on failure;
  - `extend` renewing the newest timestamp twice (criteria 2, 3 and 4);
  - the two refusals.

  The fakes record what was asked and do not reproduce the choice under test.
- **Unit** (`src/error.rs`): the kind rows.
- **Conformance** (ignored; bench DSS, both TSAs, OCSP, CRL): the exact level `PAdES-BASELINE-LTA`, after signing and after `extend` (criteria 1, 2 and 5; brief premise 4).
- **Not replayed**: the s11 walk and merge, the `HttpTsa` checks, nacre-pdf's slot rules.
- **Manual**: `sh conformance/check.sh` → `bench ready` with `tsa2`.

## Done when
- All tasks are ticked. `cargo test --workspace` and the clippy type check are green through `po-run`. Both ignored DSS tests pass against a fresh bench, and their result is recorded.
- One story commit on `story/s12-pades-blta`, then QA (`Surface: endpoint`), then a review with no open critical finding, then the ship as `s12-pades-blta: Monter une signature PAdES au niveau B-LTA et l'étendre plus tard`.
