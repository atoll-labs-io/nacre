# Research — s06-pades-bb

[Story](../stories.md)

## Structuring facts
- **Criterion 5 is not testable as written** (issue #9): "calculée, et non une constante arbitraire" says how the code looks, not what it does. **The story needs a correction in `docs/stories.md:114`** (for the lead). The concrete form this research proposes: *the space reserved for `/Contents` is the length of the CMS written with the longest signature value the signer's algorithm can produce, so the zeros left after the embedded CMS are exactly the longest signature length minus the real one* (72 minus the real length for ECDSA P-256). A fixed constant fails that equality.
- **"Le signataire de test et la PKI de s02" are not compatible**: `TestSigner` signs its own certificate (`crates/nacre-core/src/test_signer.rs:33`, chain of one at `:47`), so DSS would never chain it to the bench anchor, and `nacre-core` is frozen (`docs/architecture.md:61`). The conformance tests need a `Signer` written in `crates/nacre-pades/tests/`, built from the bench's `signer.key.pem` (PKCS#8 P-256, `conformance/pki/generate.sh:29`) and the chain `signer.cert.pem` + `intermediate.cert.pem` (`generate.sh:53`), found through `nacre_conformance::pki_dir()` (`crates/nacre-conformance/src/lib.rs:53`). Same finding as `docs/research/s02-conformance-harness.md:57`.
- **Almost all the work is already done**: `nacre_cms::sign_detached` with `Profile::PADES` writes `signingCertificateV2` and refuses `signingTime` (`crates/nacre-cms/src/sign.rs:27,45-126`); `nacre_pdf::Update::sign` lays out the revision, the `/Sig` dictionary, `/ByteRange` and the zero-filled `/Contents`, and `PreparedSignature::embed` fills it (`crates/nacre-pdf/src/revision.rs:136-227,512`). s06 is the glue in a new crate `crates/nacre-pades/` plus the size computation.
- **The size can be computed exactly without a second signature**: calling `sign_detached` with a wrapper signer that returns a placeholder of the longest length gives a CMS whose length differs from the real one only by the signature's length (spike below: 841 vs 840 bytes, the real ECDSA value being 71 bytes). The real `Signer` must then be called once only: a hardware token counts its uses (s13).
- **Two nacre-pdf defects stay out of this story's reach** (it owns `crates/nacre-pades/` only, `docs/stories.md:107`): #48, `/SubFilter` unchecked (`revision.rs:171`), and #46, a field name checked only against signature fields (`revision.rs:156-163`). s06 avoids both by passing a constant `/SubFilter` and a generated name without a period; a collision with a non-signature field named `SignatureN` stays possible and cannot be seen from nacre-pades (`Document` lists signature fields only, `crates/nacre-pdf/src/document.rs:107`).

## Story
Sign a PDF at PAdES-BASELINE-B with a `Signer`, so that DSS reports `PAdES-BASELINE-B`, without `ades-rs`'s deviations.
1. `sign` with the test signer and the s02 PKI → DSS `TOTAL_PASSED`, `PAdES-BASELINE-B`.
2. `/SubFilter /ETSI.CAdES.detached`; the CMS carries `signing-certificate-v2`, never `signing-time`; the signing time goes into `/M` of the `/Sig` dictionary.
3. An already signed PDF takes a second signature in a new revision; DSS reports both `PAdES-BASELINE-B`.
4. The original bytes are an exact prefix of the result.
5. The `/Contents` reserve is enough at B-B and is computed (see the correction above).
Notes: revocation data never goes into the CMS (s11 puts it in `/DSS`); plan now for the reserve s08's timestamp will need.

## Current code
- `crates/nacre-pades/` does not exist. The workspace picks it up by its folder (`Cargo.toml:3`, `members = ["crates/*"]`); workspace lints deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` (`Cargo.toml:5-9`), taken by `[lints] workspace = true` in each crate (`crates/nacre-pdf/Cargo.toml:9-10`).
- `crates/nacre-cms/src/sign.rs:45-126` — `sign_detached(digest, &dyn Signer, &Profile, Option<Time>) -> Result<Vec<u8>, Error>`: checks the digest length (`:51-58`), maps the algorithm to its identifier and refuses an unknown one before signing (`:59-74`), parses the signer certificate (`:76-83`), builds `contentType`, `messageDigest`, `signingCertificateV2` (`:85-92`), adds `signingTime` only when given (`:93-95`), refuses what the profile forbids (`:96-98`), calls `signer.sign_digest` once (`:101`), puts the whole chain, sorted, in `certificates` (`:103-104`), no CRLs (`:114`).
- `crates/nacre-cms/src/sign.rs:137-142` — `ESSCertIDv2` with `certHash` only, no `issuerSerial`.
- `crates/nacre-pdf/src/revision.rs:42-52` — `SignatureSpec { field, sub_filter, contents_len, entries }`. `Update::sign` (`:136-227`): refuses reserved entries (`:137-141`), an empty slot (`:142-144`), an output over 50 MB (`:145-155`), a field name taken by a signature field (`:156-163`), an approval signature on a DocMDP `/P 1` document (`:172-176`); writes `/Type /Sig`, the caller's entries, `/Filter /Adobe.PPKLite`, `/SubFilter` (`:165-171`); adds an invisible widget on the first page and hooks it into `/AcroForm` with `/SigFlags 3` (`:182-203`); fills the fixed-width `/ByteRange` (`:205-221`).
- `crates/nacre-pdf/src/revision.rs:498-528` — `byte_range()`, `signed_parts()` (the two signed slices), `embed(der)` (hex at the start of the slot, zeros after; larger than the slot → `Error::SignatureTooLarge`).
- `crates/nacre-conformance/src/client.rs:48-89` — `Dss::from_env()` and `validate(name, bytes) -> Reports`; `Reports.signatures` are `SignatureVerdict { id, format, report }` in report order (`report.rs:10-28`). `tests/dss_reference.rs:27-40` is the pattern for an `#[ignore = "conformance"]` test: indication, sub-indication and exact `format`.

## Attachment points
- New crate `crates/nacre-pades/` (`Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/sign.rs`, `src/reserve.rs`, `tests/`). No other file changes: CI's fuzz job and conformance job find it by folder (`.github/workflows/ci.yml:28`, `.github/workflows/conformance.yml`, `cargo test --workspace --all-features -- --ignored`).
- nacre-pades parses nothing itself (nacre-pdf and nacre-cms do), so no fuzz target is due under ADR-0008.

## Verified interfaces
- `nacre_core::Signer { fn algorithm(&self) -> SignatureAlgorithm; fn certificate_chain(&self) -> &[Vec<u8>]; fn sign_digest(&self, &[u8]) -> Result<Vec<u8>, Error> }` (`crates/nacre-core/src/signer.rs:4-17`). ECDSA comes back as DER `ECDSA-Sig-Value`, RSA raw.
- `SignatureAlgorithm::{EcdsaP256Sha256, RsaPkcs1v15Sha256}`, `#[non_exhaustive]` (`crates/nacre-core/src/algorithm.rs:1-9`).
- `nacre_cms::{sign_detached, Profile::PADES, SignedData::from_der, SignedData::verify_detached_digest, oid}` (`crates/nacre-cms/src/lib.rs:20-27`, `verify.rs:55`). `from_der` refuses trailing bytes (`model.rs:396`): a test reading `/Contents` back must cut the zero padding at the DER length.
- `nacre_pdf::{Document::parse, Document::signature_fields, Document::object, Document::update, Dictionary::{new, insert}, Object::String}` (`crates/nacre-pdf/src/lib.rs:47-53`, `document.rs:37,107,112,123`, `object.rs:55,65`). `/Contents` reads back as `Object::String` of the decoded bytes, padding included.
- `nacre_pdf::Error::kind()` and `nacre_cms::Error::kind()` exist (`crates/nacre-pdf/src/error.rs:117`, `crates/nacre-cms/src/error.rs:71`); `CertifiedNoChanges`, `DuplicateField`, `SignatureTooLarge` map to `InvalidInput` (`crates/nacre-pdf/src/error.rs:145-149`).
- `der::DateTime` (already a dependency of nacre-cms, `crates/nacre-cms/Cargo.toml:14`) carries year to second and is what nacre-cms tests use for times (`crates/nacre-cms/tests/sign.rs:14,27`).
- Bench files: `out/signer.key.pem`, `signer.cert.pem`, `intermediate.cert.pem`, `root.cert.pem`, all ECDSA P-256 (`conformance/pki/README.md`, `generate.sh:28-55`); `out/` is absent in this worktree (generated by `pki-init`), so conformance tests run in CI or on a started bench only.
- `conformance/reference/unsigned.pdf` is committed, one page, hand-written; `nacre-pdf` parses it and takes two successive signatures (spike).

## Spike (outside the worktree, `/tmp/s06-probe`, nothing written here)
A scratch crate on the worktree's crates: dry run of `sign_detached` with a placeholder signer returning 72 bytes, `Update::sign` with `contents_len` = that length and `/M`, SHA-256 of `signed_parts()`, real `sign_detached` with `TestSigner`, `embed`. Run on `conformance/reference/unsigned.pdf`, then again on the result: dry 841 / real 840 both times, original bytes a prefix, the reread finds fields `Signature1` (7 0 R) and `Signature2` (10 0 R), 3 revisions. Not judged by DSS or qpdf (neither runs here).

## Traps
- **Signer called twice**: a dry run that reaches the real `sign_digest` would consume a YubiKey touch or a PIN try. The placeholder must wrap the signer and never delegate `sign_digest`.
- **RSA bound**: the real RSA value is as long as the modulus; the subject public key bit string of the signer certificate is always longer (it holds the modulus and the exponent in a DER sequence), so its length is a safe bound without an RSA parser. ECDSA P-256 DER is at most 72 bytes (two 33-byte integers + headers). A signer returning more than the bound (a broken PKCS#11 conversion) ends in `SignatureTooLarge`, never in a truncated file.
- **DER length octets**: a longer placeholder can only add length octets, never remove them, so the dry length stays an upper bound.
- **Clock**: no crate reads the clock to judge (`AGENTS.local.md`, conventions); signing is not judging, but a caller-supplied time keeps tests deterministic (RFC 6979 ECDSA is deterministic, so a fixed PDF and time give fixed bytes).
- **`/M` syntax**: ISO 32000 date `D:YYYYMMDDHHmmSSZ`; nacre-pdf writes strings as given (`write.rs`), so the bytes are the ones built.
- **`issuerSerial` absent from `ESSCertIDv2`** (`sign.rs:137-142`): s03 left DSS's acceptance to this story's conformance run (`docs/research/s03-cms-signed-data.md:58`). If DSS refuses B-B for it, the fix belongs to nacre-cms (another story), not here.
- **First signature after the second revision**: DSS runs modification detection; the second revision adds an annotation, an AcroForm entry and a field, which signing is allowed to add. Only the conformance run can confirm both stay `TOTAL_PASSED`.
- **dev-dependency on `nacre-conformance`** (`publish = false`, `crates/nacre-conformance/Cargo.toml:8`): it must be a path without `version`, so `cargo publish` of nacre-pades drops it.
- Every crate's `Error` exposes `kind()` (ADR-0012); crates test it with an `every_variant_has_its_kind` table (`crates/nacre-cms/src/error.rs:104-147`).

## Open questions
- Does the public `sign` take only `(pdf, signer, signing_time)`, leaving s08 to add the level and the TSA? The plan decides: yes, no option the story does not ask for; nacre-pades has one owner at a time and is not yet published.
- How much does s06 "provide" for s08's token? A B-B signature cannot know a token's size; the plan keeps the size in one function that s08 extends, and reserves nothing for a token at B-B.
- Does DSS 6.5.1 accept `ESSCertIDv2` without `issuerSerial` at B-B? Only the CI conformance run answers.

## Complexity
Story 3 → 3. Signing and layout already exist (s03, s05); what remains is the glue, the computed reserve, a bench signer in tests and two conformance runs, all inside one new crate. Above `Flow threshold` 2: full track.

## Split
Not needed (below 5).
