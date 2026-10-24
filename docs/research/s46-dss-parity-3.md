# Research — s46-dss-parity-3

[Story](../stories.md)

## Structuring facts
- **AC3 cannot hold on case e2 under `strict()`.** e2 is a B-B with no proof of existence and an OCSP response produced 3 days ago, so `require_fresh_revocation` drops that response before any issuer rule runs (`crates/nacre-validate/src/validate.rs:350-351`, `src/revocation.rs:271-274`). The result is `CERTIFICATE_CHAIN_GENERAL_FAILURE`, which is stricter (spike `run4/forge5.txt`, e2 `STRICT`). The new rule applies under both presets. `strict()` reaches it only with a proof of existence or data younger than 24 h, so the "both presets" test uses such a shape. The lead may reword AC3.
- **AC2 cites v5 as a case of the exemption, but v5 is its control.** In v5 the data on the signer says "good", and the exempt "revoked" data concerns the CA, whose issuer is the anchor and is never judged (`revocation.rs:298-306`). v5 must keep `REVOCATION_OUT_OF_BOUNDS_NO_POE` with the switch off, as in DSS.
- **The four families sit in three places.**
  - **A (k1)**: `proven_time` (`validate.rs:455-491`) skips the SKI check that `after_revocation` runs on the signer's path (`:428-435`).
  - **B (v3)**: the issuer pass of `judge_path` (`revocation.rs:298-306`).
  - **C (e2)**: `OcspResponse` hides its delegate (`crates/nacre-revocation/src/ocsp/response.rs:211-224`).
  - **D (e4, e5)**: `Item::verdict` gives an OCSP response no `expired_from` (`revocation.rs:85-88`), and `OcspResponse` exposes no single extension (`response.rs:188-206`, private).
- **`judge_path` already takes 7 arguments**, which is clippy's limit (`revocation.rs:250-258`, workspace lints, `-D warnings`). The twelfth switch cannot be an eighth argument: pass `&ValidationPolicy` in place of the `expired_certs_on_crl` bool.
- **The code is the spike's.** Spike 4 ran on `7448b6e`, and HEAD `f3da64b` only changes docs. Its verdicts (`/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-spike3/run4/forge4.txt`, `forge5.txt`) stand for this tree.

## Story
`dss()` gives DSS 6.5.1's verdict on families A–D of s18's fourth spike, and `strict()` never gets laxer.
- AC1: on a TSA path, a CA below the anchor without SKI takes any proof of existence from its token, under both presets (k1).
- AC2: a twelfth switch `judge_issuer_of_revoked_data`, on in `strict()`. Off, "revoked" data escapes its issuer's validity rule (v3); on, the rule applies as today.
- AC3: a delegated OCSP responder valid at `producedAt` and out of validity at the control date gives `REVOCATION_OUT_OF_BOUNDS_NO_POE`, under both presets (e2). `nacre-revocation` exposes the delegate's certificate.
- AC4: `ignore_expired_certs_on_crl` also covers OCSP `archiveCutoff`. Off, such a response counts for an expired certificate (e4, e5); on, it is dropped.
- AC5: an ADR adds both to ADR-0029's table. The isolation tests cover twelve switches, and the catalogue names them.
- AC6: one conformance test per family: DSS's verdict under `dss()`, the strict one under `strict()`.

Out of scope: level, document timestamps, campaign (s18); xref recovery (s47); TSA freshness (s42); feature matrix (s44).

## Diagnostic — spike 4 (DSS 6.5.1 on the bench, 2026-10-24)
Scratch crate `/home/lecrabe/.claude/jobs/4fb763d0/tmp/s18-spike3/`: `src/bin/forge4.rs` (k, v1–v3), `forge5.rs` (e, v5, v6). The bench gives every certificate SKI (`conformance/pki/openssl.cnf:55-76`). Forged certificates carry no CDP or AIA, so DSS reads only the `/DSS`.

| # | Shape | Nacre `dss()` | Nacre `strict()` | DSS |
| --- | --- | --- | --- | --- |
| k1 / k2 | T 5 d ago, TSA under a root-issued CA without SKI; signer revoked 1 h ago / sound | `TOTAL_PASSED` | same | `REVOKED_NO_POE` / `TOTAL_PASSED` |
| v2 / v3 | T 5 d ago, CA expired yesterday, signer revoked 6 d / 4 d ago (CA CRL 3 d ago) | `REVOKED_NO_POE` / `REVOCATION_OUT_OF_BOUNDS_NO_POE` | same | `REVOKED_NO_POE` / **`TOTAL_PASSED`** |
| v5 | T 5 d ago, CA expired yesterday and revoked 4 d ago by the root, signer "good" | `REVOCATION_OUT_OF_BOUNDS_NO_POE` | same | same |
| v6 | v3 with a valid CA (control) | `TOTAL_PASSED` | same | same |
| e1 | B, issuer-signed OCSP built in Rust (control) | `TOTAL_PASSED` | same | same |
| e2 / e3 | B, delegate (EKU `OCSPSigning`, `ocsp-nocheck`) valid at `producedAt` 3 d ago, expired yesterday / still valid | `TOTAL_PASSED` | `GENERAL_FAILURE` (freshness) | **`REVOCATION_OUT_OF_BOUNDS_NO_POE`** / `TOTAL_PASSED` |
| e4 / e4b | B, signer expired yesterday, OCSP produced 1 h ago with `archiveCutoff` 60 d back / none | `GENERAL_FAILURE` | `OUT_OF_BOUNDS_NO_POE` | **`OUT_OF_BOUNDS_NOT_REVOKED`** / `GENERAL_FAILURE` |
| e5 | e4 with T 5 d ago | `GENERAL_FAILURE` | same | **`TOTAL_PASSED`** |

Hypotheses, each kept after a refutation attempt:
- **"DSS applies the SKI rule to the TSA path's CAs."** Kept on k1. Under it, k2 still passes in DSS: there the token is dropped, and nothing was revoked.
- **"Data saying revoked skips the issuer rule."** Kept on v3. v5 tried to refute it: there the out-of-bounds CA signed a "good", and DSS refuses.
- **"A delegate is judged at the control date."** Kept on e2 against e3. Its validity at `producedAt` is already required (`response.rs:274-278`; o2/o3 agree today).
- **"`archiveCutoff` is OCSP's `expiredCertsOnCRL`."** Kept on e4 and e5 against e4b. The extension was placed in `singleExtensions` (RFC 6960 §4.4.4; `forge5.rs:232`), non-critical.

## Current code
- `Context::judge` (`validate.rs:307-403`):
  - pool of CMS, token and `/DSS` CRLs and `/DSS` OCSPs (`:332-341`);
  - best-signature-time from `proven_time` (`:343-347`); freshness window only without it, under `require_fresh_revocation` (`:350-351`);
  - `build_path`, then `judge_path(…, Some(self.at), !ignore_expired_certs_on_crl)` (`:371-379`), then `after_revocation` (`:409-450`): validity under `dss()`, then the SKI of each CA at depth ≥ 1 below the anchor → `Defect::CaKeyIdentifierMissing { depth }` (`:428-435`), then `/M`.
- `proven_time` (`:455-491`): `verify_token`, `build_path` at `self.at` under `Rules::STRICT`, then `judge_path(…, None, None, …)`. No SKI check.
- `revocation.rs`:
  - `Item { Crl(Crl, Option<SystemTime>), Ocsp(OcspResponse) }` (`:64-68`);
  - `Item::verdict` dates a CRL by `thisUpdate`, an OCSP response by `producedAt`, and calls `status` at that date (`:84-119`);
  - `Verdict { date, revoked, hold, expired_from }`, `Copy` (`:136-144`);
  - `judge_path` (`:250-308`): per pair, the latest usable verdict decides (`:287-291`); the `within` gate (`:281-286`); a revocation at or before `time` returns `Revoked` (`:292-296`); then the issuer pass over `path[1..last]` at `issuers_at` → `IssuerOutOfBounds { depth }` (`:298-306`).
- `OcspResponse` (`response.rs`):
  - `status` refuses unknown critical single extensions (`:155`), then takes `responder_key` (`:157`), which is the issuer's key or that of an authorized delegate of `certs`. `delegate()` checks the name, issuer, signature, `OCSPSigning`, and validity at `producedAt` (`:245-281`).
  - Neither the delegate nor `singleExtensions` is public.
- `ValidationPolicy`: eleven `pub bool` (`policy.rs:16-84`), `strict()` (`:88`), `dss()` with its warning (`:104-129`), `#[non_exhaustive]`.

## Attachment points
- **A.** Extract the SKI loop of `after_revocation` (`validate.rs:428-435`) into a helper over a path's certificates below the anchor. Call it in `proven_time` after `build_path`, returning `None` on a missing SKI.
- **B.** In `judge_path`, keep each pair's deciding `Verdict`. In the issuer pass, skip a depth whose verdict has `revoked.is_some()` (necessarily after `time`) when `!policy.judge_issuer_of_revoked_data`.
- **C.** Add `pub fn delegated_responder(&self, issuer: &[u8]) -> Result<Option<Vec<u8>>, Error>` to `OcspResponse`: the DER of the authorized delegate, `None` when the issuer signed. `delegate()` returns the certificate as well as its key.
  - `Item::verdict` keeps the delegate's validity in `Verdict`, as a window of two `SystemTime`, so `Verdict` stays `Copy`.
  - The issuer pass also requires that window to hold `issuers_at`, at every depth, the anchor's delegates included → `IssuerOutOfBounds { depth }`.
- **D.** Add `pub fn archive_cutoff(&self, certificate: &[u8], issuer: &[u8]) -> Result<Option<SystemTime>, Error>` to `OcspResponse`: the `1.3.6.1.5.5.7.48.1.6` single extension of the matching response, an unreadable value counting as absent. `Item::verdict` puts it in `expired_from`, and the gate at `:281-286` is unchanged.
- **Switch.** Add a field to `policy.rs`. `judge_path` takes `&ValidationPolicy` instead of its last bool, from both callers (`validate.rs:371-379`, `:479-487`).

## Verified interfaces
- `judge_path(path, pool, source, time, issued_from, issuers_at, expired_certs_on_crl: bool) -> Result<(), RevocationDefect>` (`revocation.rs:250-258`), `pub(crate)`.
- `RevocationDefect { Revoked, Missing, IssuerOutOfBounds }`, `#[non_exhaustive]`, `report()` (`revocation.rs:36-62`). No new variant is needed.
- `in_validity(&Certificate, SystemTime, depth) -> Result<(), ChainDefect>` (`chain.rs:514-527`).
- `OcspRequest::new(certificate, issuer, nonce)` builds a SHA-1 `CertID` (`crates/nacre-revocation/src/ocsp/request.rs:28-35`). Tests can read that `CertID` back through `asn1.rs` (`ocsp/asn1.rs`), which is self-contained and included by `#[path]` in `examples/forge_ocsp_attacks.rs:16-18`. `asn1.rs` needs `der`'s `derive` feature, which `nacre-validate`'s dev `der` lacks (`crates/nacre-validate/Cargo.toml`).
- Test corpora:
  - `nacre-revocation/tests/corpus/ocsp-openssl/`: `delegated-good.der`, `responder.der`, `good.der`, `ca.der`, `leaf.der`, read by `tests/ocsp_status.rs:15-48`;
  - `tests/corpus/ocsp-attacks/`: no `archiveCutoff`.
- `forge` (`crates/nacre-validate/tests/support/forge.rs`):
  - `Role { Ca, Signer, Tsa }`, with the key usage matched exhaustively (`:67-71`, `:113-118`);
  - `Extensions::WithoutKeyIdentifier` (`:82`), `issue_with` (`:191`), `crl` (`:220`), `crl_with_expired_certs_on_crl` (`:269`), `ForgedTsa`, `signed`;
  - `with_dss(pdf, certs, crls)` writes no `/OCSPs` (`:509-528`).
- Offline harness: `Pki` and `judge_under`, stamp 2026-10-22T08:00Z, control 2026-10-23 (`tests/revocation.rs:32-224`, `:495-505`). Bench harness: `confront_signatures`, `nacre`, `forged_ca`, `crl_at` (`tests/conformance.rs:121-151`, `:1157-1203`).
- Isolation:
  - `SWITCHES: [Switch; 11]` (`tests/policy.rs:317-347`), read by `each_switch_changes_only_what_the_catalog_names` and `dss_opens_only_what_the_catalog_marks` (`:481-524`) over `tests/corpus/attacks/`;
  - catalogue rows: `docs/security/attacks/revocation.md:88-99` and `cms.md:30-51`.

## Traps
- **Clippy's argument count** on `judge_path`: see the structuring facts.
- **A critical `archiveCutoff`** makes `status` refuse the whole response (`response.rs:155`). Only the non-critical form is in scope (RFC 6960 makes it non-critical in practice).
- **`delegated_responder` must apply the same authorization as `status`** (`delegate()`, `:245-281`). Otherwise an unauthorized certificate in `certs` would be judged in its place.
- **The isolation tests do not bite on switches 11 and 12.** No file of `tests/corpus/attacks/` has their shapes; s45 left the eleventh the same way. Their bite is in the per-switch tests of `tests/revocation.rs`.
- **After task A, k2 under `strict()`** (TSA without SKI, sound signer) loses its proof of existence, so freshness applies. This is stricter, and allowed.
- **No committed corpus** has a TSA path under a SKI-less CA: every forged CA gets one (`forge.rs:125-131`), and so does the bench's. Existing tests stay green.
- **`passed()`** (`tests/revocation.rs:204-211`) asserts level `None`. Keep it: s18 changes it.
- **The bench** regenerates keys at start: conformance cases are forged at run time and never committed. Never stop `patelle-dss`; stop the bench afterwards.
- No migration.

## Open questions
- Unobserved, the plan follows the ADR-0030 reading:
  - a delegated responder of the anchor;
  - a delegate's own revocation (`ocsp-nocheck`, `revocation.md:108`);
  - the exemption on a revoked CA at depth > 0, on a `certificateHold`, or on data signed by a delegate.
- e2 with a proof of existence (the "both presets" shape) was not run on DSS. The conformance test confronts e2 as forged and checks `strict()` offline.

## Complexity
Story 4 → **4**. There are four rules in two crates and two small public accessors in `nacre-revocation`. Neither choice is open (ADR-0030). OCSP forging and four bench tests add test code, not risk.

## Split
Not needed.
