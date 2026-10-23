# Research — s12-pades-blta

[Story](../stories.md)

## Structuring facts
- **False assumption: `Owns: crates/nacre-pades/` cannot meet criterion 5.** The bench has one TSA. It generates a single TSA certificate (`conformance/pki/generate.sh:54`), the OpenSSL configuration has one TSA section (`conformance/pki/openssl.cnf:84-99`), and the HTTP service has one endpoint (`conformance/pki/cgi-bin/tsa:21`). Two distinct TSAs that DSS accepts need a second TSA certificate issued under the bench root and a second endpoint, which means changes to `conformance/pki/` and `conformance/check.sh`. Those paths belong to s02 (`docs/stories.md:36`, shipped). `po-bounds` reads `Owns` from `docs/stories.md` at the lane's fork point (`.polype/hooks/po-bounds.sh:155-163`), so this lane cannot widen it. The story needs `conformance/pki/` and `conformance/check.sh` added to its `Owns`, and the lane must start again from a fork point that holds that line.
- **The `/DocTimeStamp` slot already exists in nacre-pdf.** `SignatureSpec.entries` overrides `/Type` (`crates/nacre-pdf/src/revision.rs:165-169`). The doc comment names `/Type /DocTimeStamp` (`:49`). DocMDP `/P 1` does not block a document timestamp (`:172-176`), and `crates/nacre-pdf/tests/revision.rs:272` exercises it. `/Filter /Adobe.PPKLite` is always written (`:170`). No change is needed in nacre-pdf.
- **Everything `extend` needs is already reachable.** The signature fields expose `/V` (`crates/nacre-pdf/src/acroform.rs:9-16`). `/Contents` reads back as `Object::String` holding the decoded bytes, padding included (`crates/nacre-pdf/src/object.rs:24-31`). The token's certificates come from `SignedData::from_der(..).certificates` (`crates/nacre-cms/src/model.rs:77,84`). The s11 walk `ltv::material` (`crates/nacre-pades/src/ltv.rs:27-86`) and the `/DSS` merge `dss::append` (`crates/nacre-pades/src/dss.rs:81-130`) fit as they are.
- **The B-LT step is already separate from signing.** `long_term` (`crates/nacre-pades/src/sign.rs:123-140`) runs on the finished B-T file and wraps any failure in `Error::LongTerm`, which carries the B-T file (`crates/nacre-pades/src/error.rs:54-60`). B-LTA is one more step, run on the B-LT bytes.

## Story
B-LTA: after the `/DSS` revision of B-LT, append a document timestamp revision (`/Type /DocTimeStamp`, `/SubFilter /ETSI.RFC3161`, `/Contents` holding an RFC 3161 token over the `/ByteRange`). Later, `extend` adds a `/DSS` update holding the validation data of the previous document timestamp's TSA, then a new document timestamp. The caller picks the TSA of each timestamp.
1. `sign_at_level(…, Level::LTA { … })` adds the `/DocTimeStamp` revision after `/DSS`; DSS says `TOTAL_PASSED`, `PAdES-BASELINE-LTA`.
2. `extend` on an LTA PDF adds an updated `/DSS` (revocation of the previous TSA), then a new document timestamp; DSS still says `PAdES-BASELINE-LTA`.
3. `extend` never decides when it is called.
4. The bytes of every earlier revision stay intact as a prefix.
5. An LTA PDF made with two distinct TSAs, one for the signature and one for the document, is accepted by DSS.

## Current code
- `crates/nacre-pades/src/sign.rs:15-36`: `#[non_exhaustive] Level { B, T { tsa }, LT { tsa, revocation, issuers } }`.
  - `sign_at_level` (`:68-120`) sizes the reserve with `contents_capacity(signer, !matches!(level, Level::B))` (`:75`), picks the field name `Signature<N>` (`:77-81`), signs, then matches on the level (`:98-119`).
  - LT embeds the signature, then runs `long_term(&signed, &cms, capacity, &token, signer, revocation, issuers)` (`:112-117`).
- `crates/nacre-pades/src/timestamp.rs:44-60`: `timestamp_signature(cms, tsa) -> (cms_with_token, token)`. It checks `token.len() <= TIMESTAMP_TOKEN_MAX` (16 384, `:15`) and that the token is one DER value (`Any::from_der`, `:58`).
- `crates/nacre-pades/src/dss.rs:11-22`: `vri_key(cms, capacity)` is the upper-case hex SHA-1 of `cms` followed by `capacity - len` zeros. For a document timestamp read back from a file, that is the SHA-1 of the whole decoded `/Contents`: `vri_key(&contents, contents.len())`.
- `crates/nacre-pades/src/dss.rs:81-130`: `append` keeps an existing `/DSS` (direct or indirect, arrays direct or indirect) and appends new streams and one `/VRI` entry.
- `crates/nacre-pades/src/ltv.rs:27-86`: `material(chain, token_certificates, issuers, source)`. It walks issuers by name, never asks about a self-signed certificate, and asks once per distinct certificate.
- `crates/nacre-pades/src/error.rs:6-61`: the variants up to `LongTerm` (`:54-60`). `SignedPdf` (manual `Debug`) is at `:65-73`, `kind()` at `:77-91`, `every_variant_has_its_kind` at `:100`.
- `crates/nacre-pades/src/lib.rs:2-19`: the crate doc covers B-B to B-LT. `Cargo.toml:7` `description` names B, B-T and B-LT.

## Attachment points
- `Level` (`sign.rs:15`) gets a new variant `LTA { tsa, revocation, issuers, document_tsa }`. `#[non_exhaustive]` keeps callers outside (nacre-validate, nacre-pkcs11 tests calling `sign`) compiling.
- `sign_at_level` (`sign.rs:98-119`) gets an `LTA` arm that does what `LT` does, then a document timestamp on the B-LT bytes.
- A new module `src/archive.rs` holds the document timestamp (prepare the slot, hash the range, ask the TSA, embed) and `pub fn extend`. The crate has one module per concern (`reserve.rs`, `timestamp.rs`, `ltv.rs`, `dss.rs`).
- The field-name choice (`sign.rs:77-81`) is needed by both kinds of revision, so it is factored into one function.
- `Error` gets new variants and their kind-table rows.
- Tests go in `tests/sign.rs`, which already has the helpers: `FakeTsa` (`:204-228`, records the imprint), `cms_token` (`:380`), `chained` (`:372`), `recording` (`:391`), `dss()` (`:446`), `signatures()` (`:67`, decodes `/Contents` and the DER prefix), `range_digest` (`:102`). Conformance tests go in `tests/conformance.rs` (pattern at `:100-134`).
- The bench changes go in `conformance/pki/generate.sh`, `openssl.cnf`, `cgi-bin/`, `README.md`, and in `conformance/check.sh` (`:36,49`) and `conformance/README.md` (ports table). All of these are outside the current `Owns`.

## Verified interfaces
- `TimestampAuthority::timestamp(&self, DigestAlgorithm, imprint) -> Result<Vec<u8>, Error>` (`crates/nacre-core/src/timestamp.rs:4-8`). `HttpTsa::new(url)` checks the token against the imprint (`crates/nacre-tsp/src/http.rs:22,47`).
- `Update::sign(SignatureSpec { field, sub_filter, contents_len, entries }) -> PreparedSignature`; `signed_parts()`, `byte_range()`, `embed(der)` (`crates/nacre-pdf/src/revision.rs:42-52,136-227,495-528`). `embed` refuses a DER longer than the slot (`SignatureTooLarge`).
- `Document::signature_fields()` returns the fields in tree order, `SignatureField.value: Option<ObjectId>`; `Document::object(id)` follows one hop (`crates/nacre-pdf/src/document.rs:107-121`). `/ByteRange` reads back as `Object::Array` of `Object::Integer`. The test helper `signatures()` (`tests/sign.rs:67-100`) reads it this way.
- nacre-validate already tells a document timestamp apart by `/SubFilter /ETSI.RFC3161` (`crates/nacre-validate/src/validate.rs:57-59`). Its private `der_prefix` (`:158-167`) is the shape pades needs for "the DER token inside a padded `/Contents`". pades cannot depend on nacre-validate, which takes pades as a dev-dependency.
- `der` 0.8 `Header::decode`, `SliceReader::position()` and `Header::length()` are used in `tests/sign.rs:89-91`. The crate already depends on `der` (`Cargo.toml:18`).
- Bench: the signature TSA is `http://127.0.0.1:18081/cgi-bin/tsa`. Its token carries the TSA and intermediate certificates (`openssl.cnf:90-91`). The TSA certificate is a leaf of the intermediate, so the bench OCSP responder knows it (`generate.sh:48-54`, the responder reads `intermediate.index`). `openssl ts -reply` takes `-section <name>` to pick another TSA section of the same configuration. `serve.sh` serves every script of `cgi-bin/` (`Containerfile:8-9`).

## Traps
- **The order inside LTA is fixed.** Sign, signature timestamp, embed, `/DSS`, then the document timestamp over everything before it. The document TSA must be asked after `/DSS` is written: its imprint is the hash of the doc-TST revision's byte range, which includes the `/DSS` revision.
- **A failure after the signer has signed hands back the best finished file.** A failure in the LT step keeps today's `LongTerm` with the B-T file. A failure of the document timestamp must hand back the B-LT file, because the signer cannot sign again (s13, PIN counter) and the revocation data is already fetched. `LongTerm`'s doc says `signed` is B-T, so a new variant is needed rather than reusing it.
- **`extend` must pick the newest document timestamp**, the one whose `/ByteRange` ends latest, not the first in field order. A file with several timestamps (after a first `extend`) would otherwise refresh data for an old TSA. Fields are listed in tree order, not time order (`crates/nacre-pdf/src/acroform.rs:18-59`).
- **The previous token is inside a zero-padded `/Contents`.** `SignedData::from_der` refuses trailing bytes, so the DER prefix has to be cut out first (header length). A `/Contents` that is not one DER SEQUENCE followed by zeros is hostile input: it must give an error, never a panic, and no indexing.
- **The VRI key of a document timestamp** hashes the whole decoded `/Contents`, the same convention as s11 (pyHanko layout, research s11).
- **Data for the document TSA at LTA time.** Its chain is not in `/DSS` after the first LTA (it is unknown before the answer), and ETSI puts it in at the next `extend`. If DSS judges the latest archive timestamp from data it fetches itself, that is fine. If it refuses, see Open questions.
- **Duplicates across revisions.** Each `extend` stores the intermediate certificate and its CRL again (s11 review, minor, `dss.rs:104-118`). That is about 3 kB per renewal, and renewals are years apart. Deduplicating against foreign streams that may be filtered is out of scope; it stays the filed s11 finding.
- **nacre-validate flags `LaterRevision`** for any revision after a signature (`crates/nacre-validate/src/validate.rs:94,110-112`). This is already true at LT. Qualifying the revision belongs to s15, not here.
- The tests that will run are `tests/sign.rs` (the s11 tests must keep passing unmodified), the `error.rs` kind table, `tests/conformance.rs` (ignored), and nacre-validate / nacre-pkcs11, which call `sign`. No migration.

## Open questions
- Does DSS 6.5.1 as configured fetch revocation online for the latest document timestamp's TSA? `conformance/dss/dss-custom.properties` disables nothing but the trusted-list loader. Only a live run settles it. If it is offline, the first LTA may come back `INDETERMINATE` on the archive timestamp. The response would then be to also add the document TSA's data in a second `/DSS` revision after the timestamp (the pyHanko option), not to change the assertion.
- Should `extend` refuse a PDF with no document timestamp, or turn a B-LT file into B-LTA? The story says "on a PDF already LTA". The plan refuses, with an error naming the cause, so that `extend` does not silently do a different job.
- Should `extend` also refresh the revocation data of the signature's own chains? Criterion 2 names only the previous TSA. The plan keeps to that, which is also the minimum ETSI EN 319 142-1 asks for when renewing.

## Complexity
3 → 3. The pades side reuses s11's walk and merge whole and adds about 150 lines (one module, one variant, two error variants). The bench side is a second TSA section, certificate and endpoint, about 20 lines of shell and configuration. The real cost is the `Owns` correction and starting the lane again.

## Split
Not needed. If the lead prefers not to widen `Owns`, the second-ranked cut is a bench story (`conformance/pki/` and `conformance/check.sh`: a second TSA) that s12 depends on. s12 would keep `Owns: crates/nacre-pades/` and still need to fork after that story has shipped.
