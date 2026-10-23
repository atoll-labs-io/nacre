---
validated: yes
---
# Plan — s11-pades-blt

[Story](../stories.md) · [Research](../research/s11-pades-blt.md)

Branch `story/s11-pades-blt`. Read `docs/research/s11-pades-blt.md` first; this plan builds on it without repeating it.

Validated autonomously under `Plan validation: autonomous`: no human reviewed this plan. Each criterion was checked against the plan: 1 by tasks 3, 4 and 6; 2 by tasks 2, 3 and 5; 3 by task 4 and `level_lt_adds_nothing_to_the_cms`; 4 by tasks 1, 4 and 5. No technical choice deserving an ADR is open. The shape of `Level::LT` belongs to the story (precedent: `docs/plans/s08-pades-bt.md:10`). `sha1` is a RustCrypto primitive under ADR-0004. Handing back the B-T bytes inside an error follows from criterion 4. So the reserved ADR-0019 is not used.

## Story
After the B-T signature, `sign_at_level(…, Level::LT { tsa, revocation, issuers })` appends one revision holding `/DSS` (`/Certs`, `/CRLs`, `/OCSPs`, `/VRI`). That revision covers the signer's chain and the TSA's chain with their revocation data, and DSS says `TOTAL_PASSED` / `PAdES-BASELINE-LT`. Nothing is added to the CMS. If a certificate's revocation (or its issuer) cannot be obtained, the error names that certificate and carries the B-T file. Correction from the research: `Level::LT` also takes `issuers`, the certificates (typically the trust anchor) that neither the signer's chain nor the token carries. The lead should note in `docs/stories.md` that criterion 1's `{ … }` holds them; the implementer does not edit `docs/stories.md`.

## Reuse
| New code | Rung that holds | Why each rung above fails |
| --- | --- | --- |
| Writing `/DSS` objects and the catalog entry | already in this repository: `Update::add_stream`, `add`, `set_catalog`, `finish` (`crates/nacre-pdf/src/revision.rs:98-132`) | — |
| Reading the TSA's certificates | already in this repository: `nacre_cms::SignedData::from_der(..).certificates` (`crates/nacre-cms/src/model.rs:73-93`) | — |
| Subject/issuer names and their display | dependency already installed: `x509-cert` (`crates/nacre-pades/Cargo.toml:18`, `Name: Display`) | — |
| Fetching revocation | already in this repository: `RevocationSource` (`crates/nacre-core/src/revocation.rs:14-18`); `Fallback`, `Http*Source::allowing_loopback` in tests only | — |
| VRI key (SHA-1) | new dependency `sha1 = "0.11"` | std has no SHA-1; `sha2` has none; `sha1 0.11` is already in the workspace (`crates/nacre-revocation/Cargo.toml:18`), same `digest 0.11` as `sha2` |
| Issuer walk, `/DSS` merge and write, `LongTerm` wrapping, `SignedPdf` | new code, ~200 lines | nacre-revocation judges one certificate and never builds a path (`crates/nacre-revocation/src/lib.rs:26-28`). No crate in the repository writes `/DSS`. nacre-pdf and nacre-core are outside `Owns` |

## Tasks
1. [x] **Errors** `src/error.rs`. Add to `Error`, none carrying a key, token or path:
   - `Revocation { certificate: String, #[source] source: nacre_core::Error }`, message `"no revocation data could be obtained for {certificate}"`; `kind()` → `source.kind()` (ADR-0016: never hard-code `Unavailable`).
   - `IssuerMissing { certificate: String }`, message `"the issuer of {certificate} is in neither the chains nor the issuers given"`; kind `Indeterminate`.
   - `RevocationUnsupported { certificate: String }` for a future `RevocationData` variant (`_` arm), kind `Indeterminate`.
   - `Certificate(#[source] der::Error)`, a chain or token certificate that is not X.509 DER; kind `InvalidInput`.
   - `LongTerm { signed: SignedPdf, #[source] source: Box<Error> }`, message `"the B-T signature could not be raised to B-LT: {source}"`, so the displayed message names the certificate; `kind()` → `source.kind()`.
   - `pub struct SignedPdf(pub Vec<u8>)` with a hand-written `Debug` that prints only `len` (precedent `crates/nacre-pdf/src/revision.rs:61-69`): a `{:?}` of the error must not print the document. Re-export it from `lib.rs`.
   `certificate` is the subject's `Name` `Display` (RFC 4514). Never construct `nacre_core::Error::*` in `src/`.
   Test that fails if wrong: `every_variant_has_its_kind` (`error.rs:47`) gains rows. `Revocation{source: nacre_core::Error::Revocation("x".into())}` → `Unavailable`. `IssuerMissing` → `Indeterminate`. `RevocationUnsupported` → `Indeterminate`. `Certificate(der::Error::from(der::ErrorKind::Failed))` → `InvalidInput`. `LongTerm{source: Box::new(IssuerMissing{..})}` → `Indeterminate`, which fails if `LongTerm` hard-codes a kind. Plus a unit test `signed_pdf_debug_hides_the_bytes`: `format!("{:?}", SignedPdf(b"%PDF-secret".to_vec()))` does not contain `secret` and contains `11`.
2. [x] **Validation material** — new `src/ltv.rs`, `pub(crate)`:
   - `struct Material { certificates, crls, ocsps: Vec<Vec<u8>> }`, each deduplicated by bytes, in first-seen order.
   - `fn material(chain: &[Vec<u8>], token_certificates: &[Vec<u8>], issuers: &[Vec<u8>], source: &dyn RevocationSource) -> Result<Material, Error>`. The pool is the three lists parsed once with `Certificate::from_der` (`Error::Certificate`). The queue starts as `chain` then `token_certificates`. A visited set keyed on DER bytes ensures each certificate is handled once, so name loops end. For each certificate taken from the queue: push it to `certificates`; if `subject == issuer` it is an anchor and gets no request; else take the first pool certificate whose subject equals its issuer, or return `IssuerMissing`; call `source.revocation(cert, issuer)` and map an error to `Revocation { certificate, source }`; push `Crl` to `crls`, `Ocsp` to `ocsps`, and any other variant to `RevocationUnsupported`; queue the issuer. No indexing, no unwrap.
   Test that fails if wrong: task 5's `level_lt_writes_dss_after_the_signature` (anchor not asked, shared issuer asked once) and `missing_issuer_names_the_certificate`.
3. [x] **`/DSS` revision** — new `src/dss.rs`, `pub(crate) fn append(pdf: &[u8], vri_key: &str, material: &Material) -> Result<Vec<u8>, Error>`:
   - `Document::parse(pdf)?`. Read any existing `catalog()./DSS`: a `Reference` goes through `doc.object(id)`, a direct dictionary is taken as is, anything else is `nacre_pdf::Error::WrongType { object, expected: "DSS dictionary" }`. Its `/Certs`, `/CRLs`, `/OCSPs` (direct array, or a reference to one through `doc.object`) have their items copied unchanged. Its `/VRI` entries are copied unchanged. Its other keys are kept.
   - Each certificate, CRL and OCSP response becomes one `add_stream(Dictionary::new(), der)`, raw DER with no filter. New references are appended after the existing ones. There is no deduplication against an earlier revision's streams.
   - The VRI entry `<< /Type /VRI /Cert [..] /CRL [..] /OCSP [..] >>` lists this signature's own streams, with an empty array left out. It goes in through `add`, and `/VRI` maps `vri_key` (a name) to it.
   - The new `/DSS` dictionary, with direct arrays, an array left out when empty, and a direct `/VRI` dictionary, goes in through `add`, then `set_catalog(b"DSS", Reference(id))`, then `finish()`.
   - `fn vri_key(cms: &[u8], capacity: usize) -> String`: upper-case hex SHA-1 of `cms` followed by `capacity - cms.len()` zero bytes (saturating). That is the decoded `/Contents` with its padding, which pyHanko's corpus file proves (research).
   Test that fails if wrong: task 5's `level_lt_writes_dss_after_the_signature` (layout, VRI key) and `second_lt_signature_keeps_the_earlier_dss`.
4. [x] **The level** `src/sign.rs`, `src/timestamp.rs`, `src/lib.rs`, `Cargo.toml`:
   - `Level::LT { tsa: &'a dyn TimestampAuthority, revocation: &'a dyn RevocationSource, issuers: &'a [Vec<u8>] }`, with rustdoc. `issuers` holds the certificates the chains lead to that neither `signer.certificate_chain()` nor the token carries, typically the trust anchor.
   - `timestamp_signature` returns `(cms, token_der)`, and T ignores the token. The reserve uses `contents_capacity(signer, !matches!(level, Level::B))`, so LT reserves exactly as T does.
   - At LT, in this order: sign, timestamp, `embed`. Then the token's certificates come from `SignedData::from_der(&token)?.certificates`. Then `ltv::material(signer.certificate_chain(), &those, issuers, revocation)`, `dss::vri_key(&cms, capacity)` and `dss::append(&signed, ..)`. **Any** error after `embed` becomes `Error::LongTerm { signed: SignedPdf(b_t), source: Box::new(e) }`. Errors before `embed` stay as today.
   - Rustdoc of `sign_at_level`, crate doc (`lib.rs:5-15`) and `Cargo.toml` `description` now cover B-LT: `/DSS` in a revision after the signature, nothing in the CMS, revocation only through `RevocationSource`. `[dependencies]` gains `sha1 = "0.11"`; `[dev-dependencies]` gains `nacre-revocation = { path = "../nacre-revocation", features = ["http"] }`.
   Test that fails if wrong: task 5's tests. All existing tests of `tests/sign.rs` pass unmodified.
5. [x] **Service tests** `tests/sign.rs` and `tests/corpus/`:
   - Copy into `tests/corpus/pki/`, with their source noted in `tests/corpus/README.md`: from `crates/nacre-revocation/tests/corpus/openssl/`, `ec-ca.der` (self-signed), `leaf.der`, `revoked.der` (both issued by ec-ca) and `ec-ca.crl`; from `ocsp-openssl/`, `good.der`.
   - Helpers. `Chained { inner: TestSigner, chain: Vec<Vec<u8>> }` signs with the test key and presents `chain`; pades never checks the key against the certificate. `cms_token(chain)` is the output of `nacre_cms::sign_detached(&[0; 32], &Chained{..}, &Profile::CMS, None)`, a real `SignedData` carrying `chain`, answered by the existing `FakeTsa`. `Recording` is a `RevocationSource` that returns `Ocsp(good.der)` for `leaf`, `Crl(ec-ca.crl)` otherwise, records every certificate asked, and can be told to fail for one certificate. `dss(pdf)` reads `/DSS` back through `Document::object` and slices each stream's raw bytes from its `data` range.
   - `level_lt_writes_dss_after_the_signature`: signer chain `[leaf, ec-ca]`, token chain `[revoked, ec-ca]`, `issuers = []`. Checks:
     - `/Certs` bytes are exactly `{leaf, revoked, ec-ca}`, three streams.
     - `/CRLs == [ec-ca.crl]` and `/OCSPs == [good.der]`.
     - the source was asked for `leaf` and `revoked` once each, never for `ec-ca`.
     - `/VRI` has one key, equal to the upper-hex SHA-1 of the decoded `/Contents` (padding included), and its entry references the streams of `/Cert`, `/CRL` and `/OCSP`.
     - there is one more revision than at B-T, and the signature's `/ByteRange` ends where that revision begins.

     Fails on a missing TSA chain, an anchor asked, a lost dedup, a key hashed without padding, or `/DSS` written before the signature.
   - `level_lt_adds_nothing_to_the_cms`: the read-back CMS has `crls` empty, `certificates == [leaf, ec-ca]`, and exactly one unsigned attribute (the token). Fails if revocation leaks into the CMS.
   - `unavailable_revocation_names_the_certificate_and_returns_bt`: `Recording` fails for `revoked`. The result is `Err(LongTerm { signed, source })` with `source` being `Revocation { certificate, .. }` and `certificate` containing `Nacre OpenSSL CRL fixture revoked`. `to_string()` contains it too, and `kind()` is `Unavailable`. `signed.0` parses, has one signature whose CMS carries the token, and has no `/DSS`. Fails if the error is swallowed, the B-T is dropped, or the name is missing.
   - `missing_issuer_names_the_certificate`: signer chain `[leaf]`, token chain `[revoked]`, `issuers = []` → `LongTerm` over `IssuerMissing` naming `Nacre OpenSSL CRL fixture leaf`, kind `Indeterminate`, B-T returned in `signed`; the same call with `issuers = [ec-ca]` succeeds and `/Certs` holds ec-ca. Fails if `issuers` is ignored or a missing issuer is skipped silently.
   - `second_lt_signature_keeps_the_earlier_dss`: LT, then LT again on the result. `/VRI` has two keys and the first one's reference is unchanged; `/Certs`, `/CRLs`, `/OCSPs` start with the first `/DSS`'s references. Fails if the earlier `/DSS` is replaced.
6. [x] **Conformance** `tests/conformance.rs`, `tests/support/mod.rs`:
   - `support`: `pub fn bench_certificate(name: &str) -> Vec<u8>` (PEM to DER, the code at `support/mod.rs:19-27`), used by `BenchSigner::load` too.
   - `bench_signature_is_pades_baseline_lt` (`#[ignore = "conformance"]`). It removes `reports_dir().join("s11-pades-lt.xml")` first. It signs `UNSIGNED` with `BenchSigner::load()`, `time()`, and `Level::LT` built from three parts: `tsa: &HttpTsa::new("http://127.0.0.1:18081/cgi-bin/tsa")`, `revocation: &Fallback::new(HttpOcspSource::allowing_loopback(), HttpCrlSource::allowing_loopback())` and `issuers: &[bench_certificate("root.cert.pem")]`. It then calls DSS `validate("s11-pades-lt", ..)` and expects one signature, `TotalPassed`, no sub-indication, `format == "PAdES-BASELINE-LT"`, and the report file present.
   - Run it against the bench (`conformance/README.md`). DSS may answer anything other than `PAdES-BASELINE-LT` / `TOTAL_PASSED`; in that case stop and report DSS's sub-indication and the report's revocation section instead of changing the assertion.
7. [x] **Checks**. Task tests with `cargo test -p nacre-pades --test sign` and `cargo test -p nacre-pades --lib`. Then once, through `po-run`, the full suite (`cargo test --workspace`) and the type check (`cargo clippy --workspace --all-targets --all-features -- -D warnings`).

## Scene viewpoints
—

## Run interdicts
- Every path outside `crates/nacre-pades/` and `docs/{research,plans,verif,qa,reviews}/s11-pades-blt.md` (and `docs/qa/s11-pades-blt/`) ends with an empty diff. In particular: `crates/nacre-pdf/`, `crates/nacre-core/`, `crates/nacre-cms/`, `crates/nacre-revocation/`, `crates/nacre-tsp/`, `conformance/`, `docs/stories.md`, root `Cargo.toml`.
- `sign` and `Level::B` / `Level::T` outputs are unchanged: the existing tests of `tests/sign.rs` and `tests/conformance.rs` pass without edits, apart from the `support` refactor, which keeps `BenchSigner::load()`'s behaviour.
- `[dependencies]` gains `sha1` only. `nacre-revocation` appears under `[dev-dependencies]` only. No `[workspace.dependencies]`.
- `src/` constructs no `nacre_core::Error`, reads no clock, opens no connection, writes nothing to stdout or stderr, and indexes or unwraps nothing outside `#[cfg(test)]`.
- For one call, the signer signs once and the TSA is asked once. The revocation source is asked once per distinct non-self-signed certificate and never before the TSA has answered.
- At LT the CMS carries no CRL, no OCSP and no certificate beyond the signer's chain. No `adbe-revocationInfoArchival` attribute.
- No test calls a public TSA, OCSP responder or CRL server.

## The pivot
**B-LT is a second step on the finished B-T file. Its material is the set of certificates reached by walking issuers by name from the signer's chain and the token's certificates, with the caller's `issuers` as the only extra source.** Ways it could be wrong:
- **DSS wants something the walk does not give.** Examples: revocation data for the root, or a freshness the root CRL issued at bench start does not meet, since it is older than the signature timestamp (research, open question 1). Compare against the `s11-pades-lt.xml` revocation and LTV sections. A freshness verdict is a bench limitation to report, not a reason to add data to the CMS.
- **Name matching picks the wrong issuer** when two pool certificates share a subject (a renewed CA). The first match wins, and DSS would then see revocation signed by the wrong key. Chains are judged in s17; the reviewer should check that only a name-equal certificate is ever passed as `issuer`.
- **The VRI key convention.** It is pinned by pyHanko's file (`signed-lta-pyhanko.pdf`, padded `/Contents`) and DSS does not require VRI for LT. If the reviewer finds ISO 32000-2 or Acrobat says otherwise, it is a finding. Turned down: hashing the DER alone, which disagrees with the corpus.
- Turned down: fetching revocation before signing, which loses the TSA chain and breaks criterion 4's "B-T returned"; returning `Ok(B-T)` on failure, which hides the failure; refusing a PDF that already has `/DSS`, which blocks s12's `extend`.

## Files touched
- `crates/nacre-pades/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/sign.rs`, `src/timestamp.rs`, `src/ltv.rs` (new), `src/dss.rs` (new)
- `crates/nacre-pades/tests/sign.rs`, `tests/conformance.rs`, `tests/support/mod.rs`, `tests/corpus/README.md`, `tests/corpus/pki/{ec-ca.der,leaf.der,revoked.der,ec-ca.crl,good.der}` (copies)
- `docs/research/s11-pades-blt.md`, `docs/plans/s11-pades-blt.md`

## Test strategy
Automated: 6 new tests plus 5 kind rows, within `Test budget` 25.
- Service (`tests/sign.rs`, test key, real CMS token, recording source, no network): DSS layout, both chains, dedup, anchor skipped and VRI key (criteria 1 layout and 2); CMS untouched (criterion 3); revocation failure and missing issuer (criterion 4); earlier `/DSS` kept. The revocation fake returns real DER that pades stores without judging. The rules under test are which certificates get asked and where the answers land; the fake records the asks and does not reproduce that logic.
- Unit (`src/error.rs`): the kind rows, and `SignedPdf`'s `Debug`.
- Conformance (ignored, bench DSS, TSA, OCSP and CRL): exact level `PAdES-BASELINE-LT` (criterion 1, brief premise 4).
- Not tested: the name-loop guard. A real A↔B loop needs a certificate builder these tests lack. The visited set is a plain read for the reviewer, who checks that each certificate is handled at most once and that the walk ends after at most as many steps as the pool holds.
- Not replayed: `Fallback`, the `Http*Source` address policy, `HttpTsa` verification, nacre-pdf's writer rules.
Visual checks: none (library).

## Done when
- All tasks ticked. `cargo test --workspace` and the clippy type check green through `po-run`. The ignored DSS test passes against the bench and its result is recorded.
- One story commit on `story/s11-pades-blt` with code, research and plan. QA (`Surface: endpoint`), a review with no open critical finding, then ship as `s11-pades-blt: Monter une signature PAdES au niveau B-LT avec le dictionnaire /DSS`.
- The lead adds `issuers` to criterion 1's wording in `docs/stories.md`.
