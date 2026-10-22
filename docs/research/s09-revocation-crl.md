# Research — s09-revocation-crl

[Story](../stories.md)

## Structuring facts
- Story assumption true but incomplete: `x509-cert` 0.3 does read `CertificateList` (`x509-cert-0.3.0/src/crl.rs:33-37`), but declares `TbsCertList.version` as a required `Version` (`crl.rs:88`) although RFC 5280 makes it optional: a **v1 CRL (no version field) fails to decode** (read, not probed). Every CA of interest, OpenSSL included when it writes extensions (`conformance/pki/generate.sh:61`), issues v2. The plan accepts that a v1 CRL is an error, documented, rather than writing a CRL parser.
- Nothing in RustCrypto verifies a CRL signature: Nacre writes it. The only verifiers in the repository are private to `nacre-cms` (`crates/nacre-cms/src/verify.rs:253-273`, ECDSA P-256 and RSA PKCS#1 v1.5 SHA-256), and `nacre-cms` is outside this story's Owns. The signature must be checked over the **received** `tbsCertList` bytes, never a re-encoding: `der` re-sorts a `SET OF` on decode (s03 research, `der-0.8.2/src/asn1/set_of.rs:626-636`), and names carry `SET OF`.
- "Signalée comme telle, sans être prise pour « non révoqué »" decides the API shape: the judgement returns a two-state status (not revoked / revoked with date and reason) only after every refusal, and each refusal (other issuer, bad signature, `nextUpdate` passed, plus the RFC 5280 refusals listed below) is its own `Error` variant. No variant of the status can stand for an unusable CRL.
- The bench already gives what criterion 2 needs: leaves carry `crlDistributionPoints = URI:http://127.0.0.1:18081/crl/intermediate.crl` (`conformance/pki/openssl.cnf:69,78`), the intermediate CRL lists `revoked` with reason `keyCompromise` (`generate.sh:57-58`), the certificates sit as PEM in `conformance/pki/out/` reached through `nacre_conformance::pki_dir()` (`crates/nacre-conformance/src/lib.rs:53`), and `conformance.yml:41` runs `cargo test --workspace --all-features -- --ignored`, so an `#[ignore = "conformance"]` test under the `http` feature runs in CI with no workflow edit. Serials (`revoked` is 2002, `generate.sh:25,53-55`) and keys change at each start: the test must read them from the files, never hard-code them.
- `x509-cert`'s `CrlBuilder` (feature `builder`, `x509-cert-0.3.0/src/builder.rs:579-660`) can forge test CRLs deterministically with a p256 key, but copies the **issuer's own AKI** into the CRL when the issuer has one (`builder.rs:612-630`), which names the issuer's issuer. Judging the CRL's AKI would make every forged CRL from an intermediate wrong; the plan does not judge AKI (the signature proves the key).

## Story
s09 creates `crates/nacre-revocation/` and `docs/security/attacks/revocation.md` (Owns, `docs/stories.md:160`). Complexity 3, depends on s02, Surface `endpoint` (`docs/stories.md:157-159`). Criteria (`docs/stories.md:163-166`):
1. A DER CRL is read: issuer, `thisUpdate`, `nextUpdate`, revoked serials with date and reason; its signature is verified with the issuer's certificate.
2. Under feature `http`, `RevocationSource` downloads the CRL from the certificate's distribution point; against s02's PKI the revoked certificate is listed, the signer is not.
3. A CRL from another issuer, with an invalid signature, or stale (`nextUpdate` before the control date) is reported as such, never taken for "not revoked".
4. A hostile CRL gives an error, never a panic; a fuzz target exists.

Notes (`docs/stories.md:169`): structures from `x509-cert`, Nacre writes fetching and judgement; the control date is a parameter, never the clock (s17 judges at a timestamp's date).

Later consumers: s10 adds OCSP in the same crate behind the same trait (`docs/stories.md:175,186`); s11 embeds CRL bytes in `/DSS` (`:197-200`); s17/`nacre-validate` judges revocation in time with this crate's API (`:293-303,378`).

## Current code
- `crates/nacre-revocation/` does not exist (`ls crates`: `nacre-cms`, `nacre-conformance`, `nacre-core`, `nacre-pdf`). `docs/security/attacks/` holds `cms.md` only.
- Workspace root `Cargo.toml:3` `members = ["crates/*"]` (a new folder joins alone; root frozen, ADR-0003); `:5-9` workspace clippy lints denying `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, taken by `[lints] workspace = true` (`crates/nacre-cms/Cargo.toml:9-10`).
- Contract, `crates/nacre-core/src/revocation.rs:5-18`: `#[non_exhaustive] enum RevocationData { Crl(Vec<u8>), Ocsp(Vec<u8>) }`, `trait RevocationSource { fn revocation(&self, certificate: &[u8], issuer: &[u8]) -> Result<RevocationData, Error>; }`. `nacre_core::Error::Revocation(BoxError)` (`crates/nacre-core/src/error.rs:19`) maps to `ErrorKind::Unavailable` (`error.rs:28`).
- Reference family `nacre-cms`: one `thiserror` enum with `kind()` and an exhaustive kind test (`crates/nacre-cms/src/error.rs:3-148`); lib doc says "Experimental" (`src/lib.rs:2-3`); fuzz crate with its own `[workspace]` (`fuzz/Cargo.toml`), target decodes then exercises every method (`fuzz/fuzz_targets/signed_data.rs`); `fuzz/.gitignore` = `target corpus artifacts coverage`; hostile length-mutation test (`tests/hostile.rs:1-60`); deterministic attack corpus written by `examples/forge_attacks.rs`, regenerated by `cargo run -p nacre-cms --example forge_attacks -- <dir>` (`tests/corpus/README.md`); OpenSSL fixtures made with throwaway keys deleted afterwards, commands in the README.
- HTTP pattern, `crates/nacre-conformance/src/client.rs:11-12,38-44,74-81`: `ureq::Agent::config_builder().timeout_global(Some(..))`, `.into_body().with_config().limit(N).read_to_vec()`; `ureq = { version = "3", default-features = false, …, optional = true }` behind `http = ["dep:ureq"]` (`crates/nacre-conformance/Cargo.toml:18,22`).
- Bench CRL: v2, CRL extensions `authorityKeyIdentifier` (`openssl.cnf:81-82`) and the CRL number OpenSSL adds from `*.crlnumber`, all non-critical; `nextUpdate` 7300 days after generation (`openssl.cnf:26,40`); ECDSA P-256 everywhere (`conformance/pki/README.md`).

## Attachment points
- New crate `crates/nacre-revocation/` (Cargo.toml, `src/`, `tests/`, `tests/corpus/`, `examples/`, `fuzz/`). Nothing else is registered anywhere: CI's fuzz loop globs `crates/*/fuzz` (`.github/workflows/ci.yml:28,45`), the conformance workflow runs every ignored test (`conformance.yml:41`).
- `impl nacre_core::RevocationSource` for an HTTP source behind `http`; its own error travels boxed in `nacre_core::Error::Revocation`.
- Dev-dependency `nacre-conformance = { path = "../nacre-conformance" }` for `pki_dir()` (publish = false, `crates/nacre-conformance/Cargo.toml:8`; a path dev-dependency does not block publishing `nacre-revocation`).

## Verified interfaces
- `x509_cert::crl::{CertificateList, TbsCertList, RevokedCert}` with pub fields `tbs_cert_list`, `signature_algorithm`, `signature: BitString`; `TbsCertList { version, signature, issuer: Name, this_update: Time, next_update: Option<Time>, revoked_certificates: Option<Vec<RevokedCert>>, crl_extensions: Option<Extensions> }`; `RevokedCert { serial_number: SerialNumber, revocation_date: Time, crl_entry_extensions: Option<Extensions> }` (`x509-cert-0.3.0/src/crl.rs:33-97`).
- `x509_cert::ext::pkix::CrlReason` (ENUMERATED, OID `id-ce-cRLReasons`, `AssociatedOid`) (`src/ext/pkix/crl.rs:121-140`); `CrlDistributionPoints(Vec<DistributionPoint>)` (`crl.rs:74`); `IssuingDistributionPoint` (`crl/dp.rs:27`).
- `Time::to_system_time()` (feature `std`, default) and `to_unix_duration()`; `UtcTime` is 1970–2049 (`src/time.rs:28-65`). `SerialNumber` decodes at most 21 octets (`src/serial_number.rs:39-42`), `as_bytes()` (`:67`).
- `TbsCertificate::get_extension::<T>() -> Result<Option<(bool, T)>, _>` (`src/certificate.rs:265`). `cabf::Root` sets `keyCertSign | cRLSign` (`src/builder/profile/cabf.rs:171`).
- `CrlBuilder::new_with_this_update(issuer: &Certificate, CrlNumber, Time)`, `.with_next_update(Option<Time>)`, `.with_certificates(iter)`, then `Builder::build::<_, DerSignature>(&key)` (pattern of `crates/nacre-core/src/test_signer.rs:38-44`).
- ureq 3.5: `ConfigBuilder::timeout_global`, `max_redirects`, `BodyWithConfig::limit` (`ureq-3.5.0/src/config.rs:583,761`, `src/body/build.rs:101`); default read limit 10 MB.
- `der` bounds nesting at 64 (`der-0.8.2/src/reader/position.rs:20`).

## Traps
- `cargo test --workspace` (CI) compiles without `http`; clippy runs `--all-features` (`AGENTS.local.md`, `ci.yml`). The HTTP code and its tests must compile both ways: gate the conformance test file with `#![cfg(feature = "http")]` or `[[test]] required-features`.
- Bench PEM files: reading them needs `der`'s `pem` feature in dev-dependencies (`crates/nacre-cms/Cargo.toml:27` does the same).
- RFC 5280 §5.1.1.2: `signatureAlgorithm` must equal `tbsCertList.signature`; a CRL whose two differ is an algorithm-substitution vector. §5.2/§5.3: a CRL or entry with an unrecognised **critical** extension must not be used; that covers `issuingDistributionPoint` (partitioned/indirect CRLs), `deltaCRLIndicator` and `certificateIssuer`, none of which the bench emits.
- §6.3.3 (f): the issuer certificate must carry `cRLSign` when it has a `keyUsage`. The bench intermediate has it (`conformance/pki/openssl.cnf:59`, `v3_intermediate`); `TestSigner`'s root does too (`cabf.rs:171`).
- A forged-corpus example (`examples/forge_attacks.rs`) is a tool needing an argument; CI runs examples of `nacre-sig` only (decisions log, s02 fix run 2), so it is safe.
- Fuzz needs nightly and `cargo-fuzz`, absent locally (s03 research); the target is compiled by CI only.
- Tests never read the clock in library code; a conformance test may, but a fixed control date is simpler since `nextUpdate` is 20 years ahead.
- s10 will extend this crate (Owns overlap): it runs after s09 ships, no conflict this wave. Lanes s06 (`crates/nacre-pades/`) and s07 (`crates/nacre-tsp/`) share no path.

## Open questions
- A CRL without `nextUpdate` (RFC 5280 says MUST be present, DSS may still accept it): refuse it as unusable, or accept it as fresh forever? The plan decides.
- `thisUpdate` after the control date: s17 judges in the past with a later CRL, which is the normal case; refusing it would break s17. The plan decides not to refuse it.
- HTTP scheme: `http://` only (CRLs are signed; RFC 5280 §4.2.1.13 expects HTTP or LDAP) or `https://` too, which pulls rustls? The plan decides.
- Revocation date after the control date: report "revoked with date" and leave the comparison to s17, or judge it here? The plan decides.

## Complexity
Story 3 → 3. Every piece has a pattern in the repository (`nacre-cms` for errors, verifiers, fuzz, corpus and example; `nacre-conformance` for ureq and the bench); the judgement is a fixed sequence of RFC 5280 checks. The work is broad (crate, HTTP source, corpus, fuzz, conformance test) but not deep.

## Split
Not needed at 3.
