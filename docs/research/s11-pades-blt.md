# Research — s11-pades-blt

[Story](../stories.md)

## Structuring facts
- **Incomplete assumption: the signer's chain and the token do not reach every issuer.** `RevocationSource::revocation(certificate, issuer)` needs the issuer of each certificate (`crates/nacre-core/src/revocation.rs:17`), but the bench signer's chain stops at the intermediate (`crates/nacre-pades/tests/support/mod.rs:19`) and the bench TSA's token carries only the TSA and intermediate certificates (`conformance/pki/openssl.cnf:91`). The intermediate's revocation comes from the root CRL, so `Level::LT { … }` has to take the missing issuers (the trust anchor) from the caller. The criteria stand; the variant carries one more field.
- **Nothing today returns a PDF together with an error.** `sign_at_level` returns `Result<Vec<u8>, Error>` (`crates/nacre-pades/src/sign.rs:46-51`) and `Error` has no field that carries bytes (`crates/nacre-pades/src/error.rs:4-25`). Criterion 4 (B-T returned on failure) needs a variant that carries the B-T file.
- **The `/DSS` revision can be written with what nacre-pdf already offers.** It goes on a fresh `Document::parse` of the B-T output, with `Update::add_stream`, `add`, `set_catalog` and `finish` (`crates/nacre-pdf/src/revision.rs:98-132`). Nothing in nacre-pdf (outside `Owns`) changes.
- **VRI key = upper-case hex SHA-1 of the whole decoded `/Contents`, zero padding included.** Checked on `crates/nacre-pdf/tests/corpus/real/signed-lta-pyhanko.pdf`: its `/VRI` key `37E8639579D2B652A64AB624A22D3823AC6FA4F1` is the SHA-1 of the 11 257 padded bytes, not of the 7 505-byte DER. SHA-1 is not yet a dependency of nacre-pades (`crates/nacre-pades/Cargo.toml:12-19`).
- **The bench's HTTP revocation sources refuse 127.0.0.1 by default.** `HttpCrlSource::allowing_loopback` and `HttpOcspSource::allowing_loopback` exist for tests (`crates/nacre-revocation/src/http.rs:47,137`), and `Fallback` chains OCSP then CRL (`crates/nacre-revocation/src/fallback.rs:70-80`).

## Story
B-LT: after the B-T signature, append a revision holding a `/DSS` with `/Certs`, `/CRLs`, `/OCSPs` covering the signer's chain and the TSA's chain, each with its revocation data, plus one `/VRI` entry for the signature. DSS must judge it `TOTAL_PASSED` at `PAdES-BASELINE-LT`.
1. `sign_at_level(…, Level::LT { … })` appends the `/DSS` revision; DSS says `TOTAL_PASSED`, `PAdES-BASELINE-LT`.
2. `/DSS` covers both chains with their revocation data; one `/VRI` entry per signature.
3. Nothing is added to the CMS.
4. A certificate whose revocation cannot be obtained makes the LT step fail with an error naming it, and the B-T signature is still handed back.

## Current code
- `crates/nacre-pades/src/sign.rs:13-22`: `#[non_exhaustive] pub enum Level<'a> { B, T { tsa: &'a dyn TimestampAuthority } }`. `sign_at_level` (`:46-80`) parses, sizes the reserve with `contents_capacity(signer, matches!(level, Level::T { .. }))` (`:53`), prepares the slot, hashes the byte range, `sign_detached` (`:75`), then timestamps at T (`:76-78`) and `embed`s (`:79`). `embed` pads with `0` hex digits after the DER (`crates/nacre-pdf/src/revision.rs:512-528`).
- `crates/nacre-pades/src/timestamp.rs:43-59`: `timestamp_signature(cms, tsa) -> Result<Vec<u8>, Error>` returns only the CMS. The token's DER is parsed as `Any` (`:57`) and then dropped, so the caller cannot reach the TSA's certificates.
- `crates/nacre-pades/src/reserve.rs:69-79`: `contents_capacity(signer, timestamped)` gives the slot size, in bytes, of the decoded `/Contents`. That is the length the VRI key must hash.
- `crates/nacre-pades/src/error.rs:4-38`: variants `Pdf`, `Cms`, `Timestamp`, `TimestampToken`, `TimestampTooLarge`, and `kind()`. The kind table test is at `:47`.
- `crates/nacre-pades/src/lib.rs:5-15`: the crate documentation covers B-B and B-T and says "Revocation data never goes into the CMS".

## Attachment points
- `Level` (`sign.rs:13`): new variant `LT { … }`. The enum is `#[non_exhaustive]`, so the callers in nacre-validate and nacre-pkcs11 tests (which call `sign`) do not break.
- `sign_at_level` (`sign.rs:53,76-79`): LT reserves like T, keeps the token, then runs a second step on the embedded B-T bytes.
- A new module `src/dss.rs` (or two: chain plus writing). The crate already has one module per concern (`reserve.rs`, `timestamp.rs`).
- `Error` (`error.rs`) gets new variants, plus their rows in `every_variant_has_its_kind`.
- Tests: `tests/sign.rs` (fakes `FakeTsa` at `:202-228`, `counting()` at `:49`, `signatures()` at `:65`), and `tests/conformance.rs` (pattern at `:72-97`).

## Verified interfaces
- `nacre_core::RevocationSource::revocation(&self, certificate: &[u8], issuer: &[u8]) -> Result<RevocationData, Error>`, where `RevocationData::{Crl(Vec<u8>), Ocsp(Vec<u8>)}` is `#[non_exhaustive]` (`crates/nacre-core/src/revocation.rs:4-18`). A future variant needs a `_` arm.
- `nacre_core::Error::kind()`: `Revocation(_)` → `Unavailable` (`crates/nacre-core/src/error.rs:41-47`). ADR-0016 lets the source set it later, so pades must delegate and never hard-code it.
- `Signer::certificate_chain()`: own certificate first, then issuers "towards the trust anchor", never empty (`crates/nacre-core/src/signer.rs:8-10`). Whether the anchor is included is not said.
- `nacre_cms::SignedData::from_der` reads a `ContentInfo`, and `certificates: Vec<Vec<u8>>` holds the raw DER of each certificate (`crates/nacre-cms/src/model.rs:73-93`). It parses a `TimeStampToken` the same way.
- `x509_cert::Certificate` (already a dependency, `Cargo.toml:18`): `tbs_certificate().subject()` / `.issuer()`, and `Name: Display` (`x509-cert-0.3.0/src/name.rs:296`). That covers matching issuers by name and naming a certificate in an error.
- `nacre_pdf::Document`: `catalog()`, `catalog_id()`, `object(id)` (one hop, references left unfollowed), `update()` (`crates/nacre-pdf/src/document.rs:98-125`). `Object::{Array, Dictionary, Reference, Name, String}` and `Dictionary::{new, insert, get, iter}` are public (`crates/nacre-pdf/src/object.rs:24-90`). `nacre_pdf::Error::WrongType { object, expected }` is public and maps to `InvalidInput`.
- `Update::set_catalog(key, value)` clones the newest catalog, so the `/AcroForm` written by the signature revision is kept (`revision.rs:122-127`). `Update::new` numbers new objects after `/Size` (`:83-95`).
- Bench (`conformance/pki/README.md`, `openssl.cnf:58-81`): root is self-signed and the only DSS anchor. The intermediate has CRL DP `root.crl` and no OCSP. Signer and TSA have CRL DP `intermediate.crl` and OCSP `http://127.0.0.1:18081/cgi-bin/ocsp`, signed by the intermediate itself (`conformance/pki/cgi-bin/ocsp:21-23`). OCSP `nextUpdate` is +5 min, the CRLs +7300 days. `nacre_conformance::pki_dir()` and `reports_dir()` are at `crates/nacre-conformance/src/lib.rs:53,68`.
- pyHanko reference layout (`signed-lta-pyhanko.pdf`): `/DSS << /Certs [..] /VRI << /<KEY> n R >> /OCSPs [..] /CRLs [..] >>`, each item a stream of raw DER. The VRI entry is `<< /Type /VRI /Cert [..] /CRL [..] /OCSP [..] >>` and lists the signature's material from both chains. Its second `/DSS` revision rewrites the dictionary under the same object id and keeps the earlier entries.
- Unit-test PKI already in the repository: `crates/nacre-revocation/tests/corpus/openssl/ec-ca.der` (self-signed CA), `leaf.der` and `revoked.der` (both issued by it), `ec-ca.crl` (checked with `openssl x509 -subject -issuer`).

## Traps
- **Existing `FakeTsa` tokens are bare OCTET STRINGs** (`tests/sign.rs:230-250`), not CMS. LT must read the token's certificates with `SignedData::from_der`, which these fakes would fail. LT tests therefore need a real CMS token: a `nacre_cms::sign_detached` output whose signer's chain is the fake TSA's certificates works, because pades never verifies the token (s08 pivot). The T tests stay as they are.
- **The VRI key covers the padding.** It hashes the CMS followed by `capacity - cms.len()` zero bytes. Hashing the DER alone gives a key that pyHanko and Acrobat would not match.
- **The signer has already signed when LT fails.** A hardware signer (PIN counter, s13) cannot be asked again, so *every* failure after `embed` (revocation, a malformed existing `/DSS`, a write error) must hand back the B-T bytes, not only the revocation failure.
- **The order is fixed by criterion 4.** Revocation is fetched after the timestamp, and the TSA's certificates are only known after the TSA answers. This also gives revocation data newer than the timestamp, which DSS's freshness checks prefer.
- **An existing `/DSS` (earlier LT signature, s12's `extend`, `certified-dss.pdf`) must not be dropped.** Replacing the catalog entry silently strips the earlier signatures of their LT material. Its arrays may be indirect (pyHanko's file is named "indirect-arrs").
- **Issuer walking runs on untrusted input.** Certificates from the token and from `issuers` are caller or TSA data. Name loops (A issued by B, B by A) must end: keep a visited set, which is bounded by the pool size.
- **A self-signed certificate is an anchor** and gets no revocation request. The bench root has no CRL DP, so asking would fail.
- **Duplicates:** the bench signer and the TSA share the intermediate, so it gets one request, one `/Certs` stream and one CRL stream.
- **`Error` derives `Debug`** (`error.rs:3`). A variant carrying the B-T PDF would print the whole document, which may hold personal data, in a `{:?}`. The precedent is `PreparedSignature`'s manual `Debug`, which prints only lengths (`crates/nacre-pdf/src/revision.rs:61-69`).
- **Conformance:** `Fallback::new(HttpOcspSource::allowing_loopback(), HttpCrlSource::allowing_loopback())` needs `nacre-revocation` with `http` as a dev-dependency. The root has to be read from `pki_dir()/root.cert.pem`.
- No migration. Tests that will run: `tests/sign.rs` (11 tests), the `error.rs` kind table, `tests/conformance.rs` (ignored), and nacre-validate / nacre-pkcs11, which call `sign`.

## Open questions
- Does DSS 6.5.1 count `PAdES-BASELINE-LT` when the intermediate's only revocation is the root CRL issued at bench start, before the signature timestamp? `nextUpdate` lies 20 years ahead, so a freshness check at validation time should pass, but only the live run settles it (plan pivot).
- "One `/VRI` entry per signature": the plan reads it as one entry for the signature this call makes, plus every VRI entry already present kept as is. Earlier signatures get no new data, because fetching their revocation is s12's `extend`.
- Does a delegated OCSP responder certificate need to go into `/Certs`? The bench responder is the intermediate itself, so it is not exercised here. DSS reads the certificates carried inside the response.

## Complexity
3 → 3. The writing side is plain use of `Update`. The work lies in issuer walking, merging an existing `/DSS`, and handing back the B-T bytes on every late failure. It needs one new dependency (`sha1`, RustCrypto, the same family as `sha2`; ADR-0004) and no change outside `Owns`.

## Split
Not needed.
