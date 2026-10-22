# Research — s02-conformance-harness

[Story](../stories.md)

## Structuring facts
- **False assumption — "avec des ancres données"**: DSS 6.5.1's REST validation input `DataToValidateDTO` has no anchor field (`signedDocument`, `originalDocuments`, `policy`, `cryptographicSuite`, `validationTime`, `evidenceRecords`, `tokenExtractionStrategy`, `signatureId`; read from `GET /services/rest/validation/openapi.json` on the running 6.5.1 image). Anchors are server configuration: a PKCS#12 store named in `dss-custom.properties` and mounted at start (Patelle `conformance/dss/dss-custom.properties:4-6`, `conformance/dss/README.md:20-43`). Criterion 3 should read "avec les ancres du banc".
- **False assumption — "le rapport XML"**: the REST service is JSON only (WADL of `/services/rest/validation`: `application/json` in and out). The response has the keys `SimpleReport`, `DetailedReport`, `DiagnosticData` (JSON) and `validationReportDataHandler`, a base64 ETSI `ValidationReport` XML (`xmlns="http://uri.etsi.org/19102/v1.4.1#"`), observed on a live call. The XML that can be kept is that ETSI report; the simple report is read from JSON.
- **Trap — the level is `SignatureFormat`, not `SignatureLevel`**: in each `signatureOrTimestampOrEvidenceRecord[].Signature`, `SignatureFormat` holds `PAdES-BASELINE-B`; `SignatureLevel` is the qualification (`{"value":"N/A"}`), observed live; Patelle reads `SignatureFormat` (Patelle `lib/tests/support/dss.rs:35-48`).
- **Convention conflict**: "No crate opens a network connection outside the implementations behind its `http` feature" (`AGENTS.local.md:100`). The DSS client must sit behind an `http` feature of `nacre-conformance`, enabled by a self dev-dependency as `crates/nacre-core/Cargo.toml:24` does for `test-signer`.
- No ADR nor `docs/architecture.md` says what implements the TSA, OCSP responder and CRL server (`docs/architecture.md:23,55`; ADR-0007 names DSS and reference tools only). DSS has no RFC 3161 HTTP endpoint: its TSA is a `KeyEntityTSPSource` on a bundled self-signed key (`WEB-INF/classes/config/tsp-config.xml` in the image) behind its JSON `timestamp-service`. Drafted as ADR-0011 (proposed).

## Story
A replayable bench: `conformance/compose.yaml` runs DSS pinned, a local RFC 3161 TSA, an OCSP responder and a CRL HTTP server; `conformance/pki/` generates root, intermediate, signer, TSA, revoked certificates and the CRL by a rerunnable script with published test keys; `nacre-conformance` (`publish = false`) submits a file to DSS's REST validation and returns indication, sub-indication and level from the simple report, keeping the XML report under `target/conformance/`; one test submits a reference signed PDF shipped with the bench and checks the exact level; `.github/workflows/conformance.yml` starts the bench, runs the tests marked conformance and publishes the reports as artefacts. Complexity 4, risk: DSS's API and report shape change between versions.

## Current code
- Workspace: `Cargo.toml:3` `members = ["crates/*"]`, workspace clippy lints `Cargo.toml:5-9`; a new crate joins by its folder. `.gitignore:3` ignores `/target`, `.gitignore:4` `Cargo.lock`.
- Only crate: `crates/nacre-core/` (frozen after s01, `docs/architecture.md:61`). `ValidationReport` with private fields and three constructors enforcing the sub-indication invariant (`crates/nacre-core/src/report.rs:136-178`): `passed(level)`, `failed(sub, level)`, `indeterminate(sub, level)`. `SubIndication::ALL` and `as_str()` spell DSS names (`report.rs:44-58`). `SignatureForm` `{CAdES, PAdES, XAdES, JAdES, Pkcs7}` (`report.rs:94-100`), `SignatureProfile` mirrors DSS (`report.rs:105-122`), `SignatureLevel { form, profile }` public fields (`report.rs:126-129`). No DSS-string parser exists: `as_str()` only goes enum → string (`report.rs:15-20`).
- `TestSigner::from_secret` self-signs its own certificate (`crates/nacre-core/src/test_signer.rs:31-49`): it cannot carry the bench PKI's chain.
- CI: `.github/workflows/ci.yml:17` runs `cargo test --workspace` (ignored tests skipped), `ci.yml:15-16` fmt and clippy `--all-targets --all-features` over every crate, fuzz job over `crates/*/fuzz` (`ci.yml:19-50`).
- No `conformance/`, no `crates/nacre-conformance/`, no `.github/workflows/conformance.yml` yet.

## Attachment points
- `crates/nacre-conformance/` — new crate, picked up by `Cargo.toml:3`; lints through `[lints] workspace = true` (`crates/nacre-core/Cargo.toml:9-10`).
- `conformance/` — new: `compose.yaml`, `dss/`, `pki/`, `reference/`; later `campaign/` (s18) and `corpus/foreign/` (s19) (`docs/architecture.md:23,62`).
- `.github/workflows/conformance.yml` — new; the conformance convention points at it (`AGENTS.local.md:106`).

## Verified interfaces
- DSS REST validation: `POST /services/rest/validation/validateSignature`, body `{"signedDocument":{"bytes":<base64>,"name":…},"originalDocuments":[],"policy":null,"signatureId":null}` (Patelle `lib/tests/support/dss.rs:19-28`; accepted by the live 6.5.1 image). Response keys verified live: `validationReportDataHandler`, `DiagnosticData`, `SimpleReport`, `DetailedReport`. Signature entry keys: `Indication`, `SubIndication`, `SignatureFormat`, `SignatureLevel`, `Id`, `SigningTime`, `BestSignatureTime`, `SignedBy`, `CertificateChain`, `AdESValidationDetails`, … Entries are `{"Signature":{…}}` or timestamp/evidence-record items in the same array.
- An unsigned PDF answers 200 with `SignaturesCount: 0` and `signatureOrTimestampOrEvidenceRecord: null` (live).
- DSS signing REST for the reference PDF: `POST /services/rest/signature/one-document/getDataToSign` and `/signDocument` (paths listed by the live OpenAPI); a probe signing a scratch PDF this way returned `SignatureFormat: PAdES-BASELINE-B`.
- Default policy of the image: "QES AES/QC AES TL based" (`SimpleReport.ValidationPolicy`, live); `dss.properties` sets `dataloader.connection.timeout = 5000` and `server.tomcat.max-http-post-size=-1` (image `WEB-INF/classes/dss.properties`).
- Patelle's container: `Containerfile:4-24` — Maven build of `esig/dss-demonstrations` 6.5.1, archive SHA-256 `ece634c5…b840` checked (`Containerfile:7,11`), Tomcat 11.0.27 JRE 25, `dss-custom.properties` copied to `/usr/local/tomcat/lib/` (`Containerfile:22`). `dss-custom.properties:4-8` sets a PKCS12 trusted keystore and `cron.tl.loader.enable = false`. Image already built locally as `localhost/patelle-dss:6.5.1` (878 MB) and running as `patelle-dss` on `127.0.0.1:8080`.
- The DSS image has `bash` but neither `curl` nor `wget` (checked with `podman exec`).
- Host tooling: OpenSSL 3.6.5 (`openssl ts`, `openssl ocsp -index -port -nmin -ndays`), `jq`, `curl`, `podman` 6.1.4, `podman-compose`, `softhsm2-util`; no `java`/`keytool`, no `busybox`.
- `base64ct` 1.8 is already in the dependency graph through `spki`/`pem-rfc7468` (`Cargo.lock:18-19`); `ureq` (ADR-0006) and `serde_json` (ADR-0009) are settled bricks, not yet in the graph.

## Traps
- **Port 8080 is taken** locally by Patelle's DSS. Nacre's bench needs its own ports.
- **URLs inside certificates** (CRL distribution point, OCSP AIA) are fetched by DSS from inside its container and, later, by s09/s10 tests from the host. With bridge networking, a compose service name does not resolve on the host and `127.0.0.1` inside DSS is DSS itself. Host networking with every listener on `127.0.0.1` makes one URL valid for both.
- Tomcat in host networking binds `0.0.0.0:8080` and the shutdown port `8005` by default: both must be rewritten.
- `openssl ocsp -port` binds every interface (no address argument); `openssl ts` has no server mode. Both can answer one request from files (`-reqin/-respout`, `-queryfile/-out`), hence a CGI.
- Alpine ships `httpd` in `busybox-extras`, not in base `busybox` (to confirm when building).
- `openssl ts -reply` increments a serial file: the TSA state must be writable while the PKI files stay read-only.
- DSS fetches revocation for the signer and the intermediate: the root must publish a CRL too, or DSS may answer `INDETERMINATE` for the intermediate.
- CRL `nextUpdate` in the past may make DSS reject the CRL as not fresh; generated files are committed, so they must last (long validity, documented regeneration).
- Anchors without Java: `openssl pkcs12 -export -nokeys -jdktrust anyExtendedKeyUsage` (OpenSSL ≥ 3.2) makes a store Java reads as trusted entries; unproven with DSS. Fallback: `keytool` from inside the DSS image (Patelle README:35-39).
- `ureq` 3 caps `read_json` at 10 MB by default; DSS answers with detailed report and diagnostic data, which grow with the document.
- `clippy::indexing_slicing` is denied outside tests (`Cargo.toml:9`): read JSON through `.get()`, never `value["…"]`.
- The new crate's tests run in `ci.yml` (`cargo test --workspace`): offline tests must not need DSS; conformance tests carry `#[ignore = "conformance"]` (`AGENTS.local.md:106`).
- s01's tests use `#![allow(clippy::unwrap_used, …)]` at the top of each test file (`crates/nacre-core/tests/report.rs:1-6`).
- Issue #6: s13 (SoftHSM PDF judged by DSS in CI) and s20 (example run in CI) own neither workflow; `conformance.yml` can pick them up generically (install SoftHSM, run every workspace example) so neither story edits it.
- Patelle is read only (`git show story/s01-sign-decision:…`), never modified.

## Open questions
- Will DSS read the OpenSSL-made `-jdktrust` PKCS#12 as anchors? Settled by the first `TOTAL_PASSED`, else fall back to `keytool`.
- What exact verdict does DSS give a B-level PDF signed by the revoked certificate (`TOTAL_FAILED/REVOKED` or `INDETERMINATE/REVOKED_NO_POE`)? It is recorded from DSS, never guessed.
- s06 needs a `Signer` carrying the bench chain; `TestSigner` cannot (`test_signer.rs:31-49`) and `nacre-core` is frozen. s06 can write one in its own tests from the bench's P-256 key; the lead may want s06's notes to say so.
- The story's criterion 3 wording (anchors, XML report) and the s13/s20 notes (issue #6) are for the lead to correct in `docs/stories.md`; this lane cannot edit it.
- Fuzz target: `nacre-conformance` parses DSS's JSON, a trusted local judge, and is never published; the plan does not give it a fuzz target (`AGENTS.local.md:103`). The reviewer may disagree.

## Complexity
Story 4 → 4. Three containers, a host network, a CI workflow with a cached 880 MB image and a parser of DSS's report; the risk the story names (DSS's API and report shape) is real but already observed on the pinned version. Not 5: no migration, no real-time path, and the parts are separable in order.

## Split
Not needed at 4.
