# Test corpus of `nacre-validate`

Every subject, key and document here is fictitious or public test material.

| File | Source | Licence | SHA-256 |
| --- | --- | --- | --- |
| `unsigned.pdf` | a copy of `crates/nacre-pades/tests/corpus/unsigned.pdf`, itself a copy of `conformance/reference/unsigned.pdf`: one page of fictitious text written by hand for the conformance bench | as this repository | `e2519bc6fee13afbd4470f516b3de4a2e65abbd3da43493a411cc81ff430f86e` |
| `signed-twice-pyhanko.pdf` | a copy of `crates/nacre-pdf/tests/corpus/real/signed-twice-pyhanko.pdf`, from pyHanko test data, <https://github.com/MatthiasValvekens/pyHanko>, `internal/common-test-utils/src/pyhanko_testing_commons/test_data/data/pdf/minimal-two-fields-signed-twice.pdf`; `Sig2` signed in the first revision, then `Sig1`, a pre-existing visible field, signed in the second, which also rewrites the XMP metadata and `/Info` | MIT | `9aad3553e8ffdf0674eef661a9418089093cb98aa0fd1940bde87bf09a1a36af` |
| `signed-lta-pyhanko.pdf` | a copy of `crates/nacre-pdf/tests/corpus/real/signed-lta-pyhanko.pdf`, from pyHanko test data, same folder, `pades-lta-dss-indirect-arrs-test.pdf`; `Sig1` followed by a revision adding the `/DSS` and a document timestamp, then one extending the `/DSS` | MIT | `30fe330df187588d204519e0eff373de50a10c0fac08483368ccfc7420c1c1e4` |
| `certified-form-fill.pdf` | written by the cargo example below: `unsigned.pdf` given a text field `Name`, certified at DocMDP `/P 2`, then the field filled | as this repository | `1870c3ec2650bda37ec6d50b15f38ab02dffe3e6d5fed0b4f62f9df70eb642fb` |
| `certified-p1-form-fill.pdf` | the same, certified at `/P 1` | as this repository | `078eff3228e997301eeaa0d4562f6a9cac19a346d6d6d6a11fcf97aa6e686d4d` |
| `fieldmdp-locked-fill.pdf` | the same, certified at `/P 2`, then an approval signature whose FieldMDP reference locks `Name`, then the field filled | as this repository | `a870a9c2a68b275ee2b89ee624c7c491781ba41701c872d1434c69811e4dcf24` |
| `fill-and-second-signature.pdf` | the same, not certified: signed as `Signature1`, then one revision fills the field and adds the invisible signature `Bob` | as this repository | `89a7046d0fb972834ff3255ca011de4f99614fdd53ee2af2f8f8231914edc4e2` |
| `certified-p1-second-signature.pdf` | the same, certified at `/P 1`, then one revision adds the invisible signature `Late` | as this repository | `1406d21464074d94250a408279d037b361b60ef7346b59c69ec6b9a7f0b0380d` |
| `docmdp-reference-cap.pdf` | `certified-form-fill.pdf`, then a revision whose catalog names a DocMDP signature dictionary holding 40 `/Reference` entries, over the reader's cap of 32, then a revision adding the invisible signature `Late` | as this repository | `09cff22277a0d9c0866a258cef42214d5dfc968a29b97dbc3c4d019c2f90e600` |
| `certified-dss.pdf` | a copy of `crates/nacre-pdf/tests/corpus/real/certified-dss.pdf`, from esig/dss test data, <https://github.com/esig/dss>, `dss-pades/src/test/resources/validation/dss-2554/certified-changes-permitted.pdf`; written by LibreOffice 5.2, RSA, signed by the fictitious Nowina `PKI-TEST` CA; field `signature-test` signed, `signature-test2` empty | LGPL-2.1 | `17c74d6c6911cb8beed4430de172256bd5bed6bdccc4c5cc7c1be95aee0e1d2b` |

## `attacks/`

One file per known attack on signed PDFs, listed in `docs/security/attacks/pades.md` and
each rejected by its own test in `tests/attacks.rs`. Every file is `unsigned.pdf` given one
signature with exactly one defect; where a CMS is present, it is made by the fictitious test
key `TestSigner::from_secret(&[0x11; 32])` of `nacre-core` over the bytes its `/ByteRange`
names, so no other rule can answer in place of the one aimed at.

The later-revision cases are `unsigned.pdf`, sometimes prepared by a revision written
before signing, signed, then given one revision that is not allowed; each signature is
sound, so only the revision rule can refuse it.

| File | After the signature | SHA-256 |
| --- | --- | --- |
| `shadow-hide.pdf` | before signing, object 6 is written empty, then redefined as a white overlay over the page's text; after, an xref-only revision points 6 back at its empty body | `8b1a54336e5e86dcbc460e2b2ce3771db65a43fdedd7eb2df16b3f1a7c7f6636` |
| `shadow-replace.pdf` | the page's font 5 redefined (`/BaseFont /Courier`) | `8e042ba87f84f7a09998653b7dbb80471bfe36eba73b99ef00366f39ceb7730e` |
| `shadow-hide-and-replace.pdf` | before signing, a second catalog 7 and its page tree, unreferenced; after, a trailer whose `/Root` is 7 | `77a851bf745a18481f3eff06fb6f6127c090abdf6e416c6f51d82a6633e063d8` |
| `shadow-late-definition.pdf` | before signing, the page refers to object 50 while it is free; after, 50 is defined as a content stream | `33e97d907dd4d5097af386d792041ada0e182597efc8fb7126b4afb02835b0bc` |
| `shadow-fill-late-definition.pdf` | certified at `/P 2`, the page referring to object 50 while it is free: the text field `Name` filled, its new appearance written as 50, which the page then draws too | `3980fcd18c69c8aa1d81face5daf26fe252438a2ac944e5c8061538597b2ae2a` |
| `shadow-dss-page.pdf` | before signing, stream 7 is both in the `/DSS` (`/Certs`) and drawn by the page; after, 7 redefined as a white overlay | `9b7d5261137f5fd225e90ef4728b0d9cd9e76bb9eee41ed9cfeb9299b08bc2cf` |
| `shadow-form-field.pdf` | not certified: the text field `Name` given a new `/V` and appearance | `3d7193381858f0c4665003bc3c50e0f5c339cddb4515e9345057d6cc813e018c` |
| `eaa-freetext.pdf` | certified at `/P 2`: a `/FreeText` annotation added to the page | `3883711986eea89b1b3e89d6f27b7d23e2896188bf63ba6f87a85faf72074210` |
| `ssa-visible-signature.pdf` | certified at `/P 2`: a new signature `Sneaky`, its widget visible and drawing over the page, its CMS correct | `05cba62e6e73bd2469ea082cbf9503f18eb1aa6811fbbbfb8064a187ea7ae57f` |
| `ssa-split-widget.pdf` | certified at `/P 2`: the same signature `Sneaky`, its field and its visible widget written as separate objects (`/Kids`, `/Parent`) | `775f55742a50554964bba343060804793dca9eff33685a49072018d4b72abc86` |
| `ssa-empty-field-signed.pdf` | certified at `/P 2`: one revision adds an empty visible signature field `Sneaky`, the next signs it, its CMS correct | `68dab81152412ec84fa7424c35a727b0110930fbd8bc6eacbfb60e2f1b439190` |

The files are the output of a cargo example, deterministic (RFC 6979 ECDSA, a fixed signing
time), which also writes the six forged files of the table above into `tests/corpus/`.
Regenerate them from the repository root with:

```sh
cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks
```
