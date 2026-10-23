# Research — s10-revocation-ocsp

[Story](../stories.md)

## Structuring facts
- **False assumption (story note):** « écrire les structures OCSP sur `der` » was superseded by ADR-0004 (`docs/decisions/0004-rustcrypto-foundations-and-x509-boundary.md:20`), which picks `x509-ocsp` 0.2. **But ADR-0004's premise is false too:** `x509-ocsp` 0.2.1, its only usable release (crates.io, 2024-01-08), depends on `der ^0.7`, `spki ^0.7`, `x509-cert ^0.2`, `const-oid ^0.9`, while every Nacre crate is on `der 0.8` / `x509-cert 0.3` (`crates/nacre-revocation/Cargo.toml:13-15`). The `der 0.8` port exists only as unpublished `0.3.0-pre` on RustCrypto's `master`, and Nacre is published on crates.io (`docs/brief.md:84,89`), which refuses git dependencies. Where the OCSP structures come from is therefore an open structural choice: drafted as ADR-0018 (`proposed`).
- The bench responder signs with the CA itself (`conformance/pki/cgi-bin/ocsp:21-23`): a delegated responder (`id-kp-OCSPSigning`) is never exercised by the bench and must come from the corpus.
- `RevocationSource::revocation(certificate, issuer)` has no date and no nonce (`crates/nacre-core/src/revocation.rs:17`), and no crate reads the clock (`AGENTS.md`, Conventions; `crates/nacre-revocation/src/lib.rs:19-20`): the nonce can only be checked inside the source that made the request, and the `thisUpdate` tolerance only against a date the caller gives.
- Story complexity 3; after reading, 4: own ASN.1 decoding (if ADR-0018 keeps option 1), a second signature path (delegated certificate verified by the issuer), a shared HTTP policy, two corpora.

## Story
Build a DER `OCSPRequest` (RFC 6960) for a certificate and its issuer with a nonce; read the `BasicOCSPResponse` and verify its signature, whether signed by the CA or by a delegated responder (`id-kp-OCSPSigning`).
- AC1 request with nonce; response read; signature verified, CA-signed or delegated.
- AC2 against the s02 responder: `revoked` certificate → revoked with its date; `signer` → good.
- AC3 unauthorized responder, different nonce, `thisUpdate` out of tolerance → rejected, each with its own error.
- AC4 hostile response → error, never a panic; a fuzz target; OCSP attacks added to `docs/security/attacks/revocation.md`.
Note: same `RevocationSource` trait as s09; the caller chooses OCSP, CRL, or OCSP then CRL.

## Current code
- `crates/nacre-revocation/src/lib.rs:22-32` — modules `crl`, `error`, `http` (feature), `verify`; exports `Crl`, `CrlStatus`, `RevokedEntry`, `Error`, `HttpCrlSource`, `CrlReason`. Crate doc says "Experimental" (`:3`).
- `src/crl.rs:49-57` — `Crl::from_der` keeps the `tbsCertList` bytes as received (`tlv_bytes` on the inner reader); `status` (`:102-147`) applies a fixed rule order documented as contract (`:108-109`): parse → issuer names → critical extensions → signature → `nextUpdate` → serial lookup. `thisUpdate` after `at` is accepted (`:100`).
- `src/verify.rs:23-55` — `verify(&Crl, &Certificate)`: outer/inner algorithm equality (`:26`), `cRLSign` (`:30-36`), then `check_algorithms` (`:57-88`, ECDSA P-256 SHA-256 and RSA PKCS#1 v1.5 SHA-256 only), SHA-256 prehash over the received bytes, `verify_ecdsa`/`verify_rsa` (`:90-110`). The key-level part is not reachable without a `Crl`.
- `src/error.rs:10-64` — one `thiserror` enum, `#[non_exhaustive]`; `kind()` (`:67-87`); unit test `every_variant_has_its_kind` asserts the row count, 12 then 14 with `http` (`:120,125`). Messages of `NonPublicAddress` and `Http` name "CRL" (`:57,62`).
- `src/http.rs:28-104` — `HttpCrlSource` (`new`, `allowing_loopback`, `distribution_point`); agent: 30 s, no redirect, no proxy (`:46-56`); `AddressPolicy` resolver refusing non-public addresses (`:121-143`, `allowed` `:145`); `http_error` maps the refusal (`:106-111`); `RevocationSource` impl boxes the crate error into `nacre_core::Error::Revocation` (`:197-208`).
- Tests: `tests/read.rs`, `status.rs` (3), `attacks.rs` (9, one per CRL attack), `hostile.rs` (truncation + length mutation, helper `length_offsets` `:24-45`), `http.rs` (3, local `TcpListener` server `:34-65`), `bench.rs` (1, `#[ignore = "conformance"]`, `HttpCrlSource::allowing_loopback`).
- Corpus: `tests/corpus/openssl/` (keys deleted after generation, `tests/corpus/README.md:3-5`: the `ec-ca` key no longer exists, so no new OpenSSL OCSP response can be signed by it); `tests/corpus/attacks/` written by `examples/forge_attacks.rs` (`[[example]] forge_crl_attacks`, `Cargo.toml:40-43`), deterministic fixed P-256 secrets `0x21..0x23` (`examples/forge_attacks.rs:39-41`).
- Fuzz: `fuzz/Cargo.toml` own workspace, one `[[bin]] crl`; `fuzz/fuzz_targets/crl.rs` fixed date, never the clock.

## Attachment points
- `src/lib.rs` — new `mod ocsp;` and exports; crate doc rewritten to cover OCSP.
- `src/verify.rs` — split a key-level `verify_signed(algorithm, spki, tbs, signature)` out of `verify`, reused by OCSP for the response and for a delegated responder's certificate.
- `src/error.rs` — new variants and their `kind()` rows; the unit test's counts.
- `src/http.rs` — the agent construction and `AddressPolicy` shared by a second source `HttpOcspSource` (POST `application/ocsp-request`).
- `Cargo.toml` — `der` feature `derive`; `sha1` (CertID, see Open questions) and `getrandom` (nonce) as normal dependencies; a second `[[example]]`.
- `fuzz/Cargo.toml` — second `[[bin]] ocsp`.
- `docs/security/attacks/revocation.md` — an OCSP section, same shape as the CRL table.

## Verified interfaces
- `nacre_core::RevocationData::Ocsp(Vec<u8>)` documented as "A DER `OCSPResponse`" (`crates/nacre-core/src/revocation.rs:9-10`) — already in the contract, no core change needed.
- `nacre_core::Error::Revocation(BoxError)` → `kind()` always `Unavailable` (`crates/nacre-core/src/error.rs:28`); ADR-0016 changes this through s39, not shipped (no kind field today).
- `x509-cert 0.3.0`: `AuthorityInfoAccessSyntax(Vec<AccessDescription>)` (`ext/pkix/access.rs:19,57`), `ExtendedKeyUsage(Vec<ObjectIdentifier>)` (`ext/pkix/keyusage.rs:133`); `CrlReason` already re-exported (`src/lib.rs:32`).
- `der_derive 0.8.0` and `sha1 0.11.0` are in the local registry; `nacre-tsp` already uses `der` with `derive` and `getrandom = "0.4"` (`crates/nacre-tsp/Cargo.toml:15,18`), its nonce made by `getrandom::fill` (`crates/nacre-tsp/src/request.rs:34-37`) — the pattern to copy.
- `nacre-tsp` checks its nonce in the response path (`crates/nacre-tsp/src/response.rs:40-42`: `NonceMissing`, `NonceMismatch`).
- `nacre_conformance::pki_dir()` (`crates/nacre-conformance/src/lib.rs:53`) gives the bench PKI; the bench leaves carry `authorityInfoAccess = OCSP;URI:http://127.0.0.1:18081/cgi-bin/ocsp` (`conformance/pki/openssl.cnf:70,79`); the responder sets `nextUpdate` 5 min ahead and echoes the nonce (`cgi-bin/ocsp:23`, `conformance/pki/README.md:69-70`); `conformance/check.sh:55-68` already proves `good`/`revoked` with the OpenSSL client.
- `x509-ocsp` crates.io versions: `0.2.1` (der 0.7), `0.2.0` yanked, `0.1.0-pre.0`, `0.0.0`. `master` Cargo.toml: `0.3.0-pre`, `der 0.8`, `x509-cert 0.3`, MIT OR Apache-2.0.

## Traps
- **Owns overlap with s39** (`docs/stories.md:670`: `crates/nacre-revocation/src/`): whichever lands second rebases its error mapping. If s39 lands first, `RevocationSource` impls set a kind on `nacre_core::Error::Revocation`; the OCSP source must then set `InvalidSignature` for `NonceMismatch`/`UnauthorizedResponder`/`SignatureInvalid`.
- The CRL rule order is a documented contract (`src/crl.rs:108-109`, `docs/security/attacks/revocation.md:7-14`); the `verify.rs` split must keep every `tests/attacks.rs` case answering its own error.
- `every_variant_has_its_kind` asserts exact counts (`src/error.rs:120,125`): every new variant moves them.
- Bench keys and serials change at each start (`conformance/pki/README.md:55-56`): the bench test may not hard-code a date or serial; it can compare the OCSP revocation date with the CRL's, both read from `intermediate.index`.
- The bench's `revoked` revocation time is the generation time, not a fixed date.
- `openssl ocsp` stamps `thisUpdate` with the current time (no option to fix it): an OpenSSL-made fixture has generation-dependent dates; tests must read `this_update()` from it rather than hard-code it.
- The CRL `openssl/` keys are gone: new OpenSSL OCSP fixtures need their own throw-away CA, generated in one script recorded in the corpus README.
- No migration. No change to the root `Cargo.toml` (ADR-0003) — the fuzz crate keeps its own workspace.
- `Error` messages must never carry a URL (`tests/http.rs` asserts it for `NonPublicAddress`); the OCSP URL comes from the certificate, hence untrusted, hence the same address policy as the CRL source.

## Open questions
- **Structure source (ADR-0018)** — own decoding on `der 0.8` (ranked first), `x509-ocsp 0.2.1` beside a second `der 0.7` stack, a git dependency, or waiting for `0.3`. Waits for a human.
- **CertID hash** — RFC 5019 §2.1.1 asks lightweight clients to use SHA-1 in `CertID` (an identifier, not a signature); OpenSSL and DSS accept SHA-256. The plan sends SHA-1 for interoperability and matches responses in SHA-1 or SHA-256.
- **Missing nonce** — many public responders serve pre-signed responses without a nonce (RFC 8954 §2.1). The plan accepts a missing nonce and rejects a different one; freshness then rests on the caller's `thisUpdate` check. A reviewer may want this stricter.
- **`thisUpdate` tolerance** — a judgement at the signing time (s17) sees later responses as normal, like CRLs (`src/crl.rs:100`); the plan keeps that in `status` and puts the tolerance in a separate check against a caller-given date. s17 may want another shape.
- **`unknown` certStatus** — the plan returns an error (nothing may read as "good"); s17 decides how it maps to an indication.

## Complexity
Story 3 → 4. The story counted on a ready-made OCSP parser; none fits the `der 0.8` stack. Delegated-responder verification adds a certificate-signature check and an EKU rule, and the delegated case is absent from the bench. Not a 5: the trait, the HTTP policy, the signature primitives and the corpus pattern all exist.

## Split
Not needed at 4. If a split were wanted: (a) structures, request, response reading and judgement with the corpus; (b) `HttpOcspSource`, fallback, bench test.
