# Research — s08-pades-bt

[Story](../stories.md)

## Structuring facts
- **False assumption 1 — "`sign` au niveau T" (criterion 1).** `nacre_pades::sign(pdf, signer, signing_time)` (`crates/nacre-pades/src/sign.rs:21`) has no level, and it is called outside this story's `Owns` (`crates/nacre-pades/` only): `crates/nacre-validate/src/validate.rs:180,186`, `crates/nacre-validate/tests/validate.rs:20`, `crates/nacre-validate/tests/hostile.rs:20`, `crates/nacre-validate/examples/forge_pades_attacks.rs:38`, `crates/nacre-pkcs11/tests/conformance.rs:66`, `crates/nacre-pkcs11/examples/sign_pdf.rs:57`. Changing its signature breaks two crates the story may not touch. **Correction for the lead (`docs/stories.md:146`)**: level T is reached through a new `sign_at_level(pdf, signer, signing_time, Level::T { tsa })`; `sign` stays B-B and unchanged. s11 (`:197`) and s12 (`:214`) say "`sign` au niveau LT/LTA" and need the same wording.
- **False assumption 2 — "une erreur qui nomme la TSA" (criterion 3).** `TimestampAuthority` (`crates/nacre-core/src/timestamp.rs:4-8`) exposes one method and no name or address: nacre-pades cannot name *which* TSA. **Correction**: the error designates the TSA as the cause — a `nacre_pades::Error::Timestamp` whose message says "timestamp authority" and whose source is the TSA's own error (an `HttpTsa` error already carries its cause, `crates/nacre-tsp/src/http.rs:54-60`).
- **Criterion 4 can only be a bound.** The token arrives after the CMS is signed over a `/ByteRange` that already fixes the `/Contents` slot (`crates/nacre-pdf/src/revision.rs:42-52`, `:512-518`); the signer signs exactly once (`crates/nacre-pades/src/sign.rs:19-20`, tested at `tests/sign.rs:180-187`). So the slot reserves room for a token up to a fixed maximum, and a larger token is refused. Concrete form for the story: *the reserve covers any token up to 16 384 DER bytes; a larger one returns an error giving both sizes.*
- The token goes into the `SignerInfo` without re-signing: `SignedData::to_der` writes a decoded value back byte for byte, unsigned attributes apart (`crates/nacre-cms/src/model.rs:142-143`), and `SignerInfo::push_unsigned_attribute` exists (`model.rs:280-284`).
- The `id-aa-signatureTimeStampToken` OID (1.2.840.113549.1.9.16.2.14) is defined nowhere: not in `crates/nacre-cms/src/oid.rs:1-32`, not in `crates/nacre-tsp/src/oid.rs`. nacre-pades defines it.

## Story
s08-pades-bt: the PAdES signature carries a signature timestamp so DSS declares it `PAdES-BASELINE-T`.
1. Signing at level T with the s02 local TSA gives a PDF DSS declares `TOTAL_PASSED` at `PAdES-BASELINE-T`.
2. The token sits in the unsigned attribute `signature-time-stamp` of the `SignerInfo` and time-stamps the signature value.
3. An unreachable TSA or a refused answer makes signing fail with an error that designates the TSA; no partial PDF is returned.
4. The `/Contents` reserve covers the token; a token too large gives a clear error.
Note: the TSA call goes through `TimestampAuthority` (s01); unit tests inject a fake TSA, conformance tests the local one.
Surface `endpoint`, `QA stage: surfaces` → the story goes to QA.

## Current code
- `crates/nacre-pades/src/sign.rs:21-45` — `sign`: `Document::parse` → `contents_capacity(signer)` (`:23`) → field name `Signature<N>` (`:25-29`) → `/M` entry (`:31-32`) → `doc.update().sign(SignatureSpec{..., contents_len: capacity, ...})` (`:34-39`) → SHA-256 over `signed_parts()` (`:41-44`) → `nacre_cms::sign_detached(&digest, signer, &Profile::PADES, None)` (`:45`), the only call reaching the signer → `prepared.embed(&cms)` (`:46`).
- `crates/nacre-pades/src/reserve.rs:62-71` — `contents_capacity(signer)`: length of a dry-run CMS written through `Sizing`, a signer returning a zero placeholder of the longest signature length (`:35-58`). Its doc (`:65-66`) names it "the single place a later level adds the timestamp token's reserve to". Unit test `rsa_bound_covers_the_signature` (`:73-97`).
- `crates/nacre-pades/src/error.rs:1-21` — `Error { Pdf(#[from] nacre_pdf::Error), Cms(#[from] nacre_cms::Error) }`, `#[non_exhaustive]`, `kind()` delegates; test `every_variant_has_its_kind` (`:23-50`).
- `crates/nacre-pades/src/lib.rs:1-19` — crate doc says it signs "at PAdES-BASELINE-B, and only that level"; re-exports `DateTime`, `Error`, `sign`.
- `crates/nacre-pades/Cargo.toml:13-27` — deps: nacre-core, nacre-cms, nacre-pdf, sha2, der, x509-cert, thiserror; dev-deps: nacre-core `test-signer`, nacre-conformance `http`, p256, der `pem`. No nacre-tsp.
- `crates/nacre-pades/tests/sign.rs` — five service tests with `TestSigner`; `signatures()` helper (`:62-96`) rereads each field's `/V`, `/ByteRange`, `/Contents` and the CMS cut at its DER length; `reserve_leaves_only_the_signature_slack` (`:168-178`) asserts slack == 72 − signature length.
- `crates/nacre-pades/tests/conformance.rs` — two `#[ignore = "conformance"]` DSS runs at B-B with `BenchSigner` (`tests/support/mod.rs`), fixed time 2026-10-22T08:00:00Z (`:218-221`).

## Attachment points
- `reserve.rs:67-71` `contents_capacity` — grows a token placeholder for level T, nothing for B.
- `sign.rs:45-46` — between `sign_detached` and `embed`: decode the CMS, time-stamp the signature value, push the attribute, re-encode.
- `error.rs:4-21` — new variants and their kinds.
- `lib.rs:17-19` — re-export the new function, the level type and the token bound.
- `tests/sign.rs`, `tests/conformance.rs` — new tests; `Cargo.toml` `[dev-dependencies]` gains `nacre-tsp` with `http` for `HttpTsa`.

## Verified interfaces
- `nacre_core::TimestampAuthority::timestamp(&self, algorithm: DigestAlgorithm, imprint: &[u8]) -> Result<Vec<u8>, nacre_core::Error>` (`crates/nacre-core/src/timestamp.rs:4-8`); returns the DER `TimeStampToken`.
- `nacre_core::Error::Timestamp(#[source] BoxError)`, message "the timestamp authority failed", kind `Unavailable` (`crates/nacre-core/src/error.rs:23-24,36`). ADR-0016 (accepted) and story s39 (`docs/stories.md:664-676`, owns `crates/nacre-core/`) will make that kind come from the source: nacre-pades must delegate to `inner.kind()` and never construct `nacre_core::Error::Timestamp` itself, or s39 would have to edit this crate.
- `nacre_tsp::HttpTsa::new(url)` (`crates/nacre-tsp/src/http.rs:23-31`) implements the trait (`:47-62`): it verifies the response — status, token signature, imprint, nonce (`crates/nacre-tsp/src/response.rs:37-44`) — before returning the token; a refused status becomes `nacre_tsp::Error::Refused` (`response.rs:37-39`), wrapped as `nacre_core::Error::Timestamp`.
- `nacre_cms::SignedData::from_der` (`model.rs:84`), `to_der` (`:144`), `signer_infos: Vec<SignerInfo>` (`:79`), `SignerInfo.signature: Vec<u8>` and `unsigned_attrs: Vec<Attribute>` (`:203-204`), `push_unsigned_attribute` (`:282`), `Attribute { oid, values: Vec<Any> }` (`:289-292`); unsigned attributes written under `[1]`, DER-sorted (`:274-276`).
- `nacre_pdf::Error::SignatureTooLarge { len, capacity }` from `PreparedSignature::embed` (`crates/nacre-pdf/src/revision.rs:111-112,512-518`); a 50 MB output cap at `revision.rs:145-155`.
- Bench TSA: `http://127.0.0.1:18081/cgi-bin/tsa` (`crates/nacre-tsp/tests/conformance.rs:14`, `conformance/README.md:20`); its token carries the TSA certificate and the intermediate (`conformance/pki/openssl.cnf`, section `bench_tsa`, `certs = intermediate.cert.pem`), the root being DSS's only anchor (`conformance/pki/README.md`, `anchors.p12`).
- Recorded token sizes (`crates/nacre-tsp/tests/corpus/recorded/`, `openssl asn1parse`): bench ≈ 1.8 KB, FreeTSA ≈ 4.6 KB, DigiCert (RSA-4096, chain) ≈ 6.0 KB.
- `nacre_conformance::level` reads `PAdES-BASELINE-T` (`crates/nacre-conformance/src/report.rs:142`).

## Traps
- **Byte-identical B-B.** nacre-validate's and nacre-pkcs11's tests sign through `sign` and some rely on its exact layout (forged attacks in `crates/nacre-validate/examples/forge_pades_attacks.rs`); the B path's reserve must not change (`tests/sign.rs:168-178` guards it).
- **What the imprint covers.** RFC 3161 Appendix A and EN 319 122-1: the hash of the *value* of the `signature` field — the OCTET STRING's content octets, `SignerInfo.signature` as held (`model.rs:203,236`), not its TLV, not the signed attributes, not the `/ByteRange` digest.
- **Dry run and real run must encode alike**: the placeholder token must go through the same decode → push → `to_der` path as the real one, or the capacity drifts by a few length octets.
- **DER length monotony.** A token of DER length ≤ the placeholder's length never produces a longer CMS: length fields only grow with content.
- **No index, no unwrap** outside `#[cfg(test)]` (workspace lints, `Cargo.toml:5-9`): take the signer info with `first_mut()`.
- **Time.** The conformance test's `/M` is the fixed 2026-10-22T08:00Z and the token's `genTime` is the bench's clock: never pass a `/M` in the future of the TSA.
- **Conformance runs need the bench** (`conformance/README.md`); CI runs them with `cargo test --workspace --all-features -- --ignored` (`.github/workflows/conformance.yml:41`).
- Running worktrees: s10 (`crates/nacre-revocation/`), s15 (`crates/nacre-validate/`) — neither overlaps `crates/nacre-pades/`. No migration.
- `CHANGELOG.md` belongs to s20; not touched here.

## Open questions
- Should nacre-pades verify the token it receives (`nacre_tsp::verify_token`)? The trait leaves verification to the implementation and `HttpTsa` already verifies imprint and nonce; verifying again would add a production dependency on nacre-tsp. The plan decides: no, and says why.
- Which bound for the token? Recorded tokens reach 6 KB; the plan decides 16 384 bytes, about 2.7× DigiCert's.
- Will DSS 6.5.1 accept the bench token with the TSA chain built from the token's own certificates? Expected yes (intermediate inside the token, root trusted); only the conformance run settles it.

## Complexity
Story 2 → 2. One crate, one extra step between signing and embedding, a placeholder in the existing dry run, three error variants, one DSS run. What looked like a signature change of `sign` is avoided by an additive function. The story leaves the short track for other reasons: it goes to QA (`Surface: endpoint`, `QA stage: surfaces`) and it extends the crate's public API.

## Split
Not needed.
