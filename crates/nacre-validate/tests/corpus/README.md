# Test corpus of `nacre-validate`

Every subject, key and document here is fictitious or public test material.

| File | Source | Licence | SHA-256 |
| --- | --- | --- | --- |
| `unsigned.pdf` | a copy of `crates/nacre-pades/tests/corpus/unsigned.pdf`, itself a copy of `conformance/reference/unsigned.pdf`: one page of fictitious text written by hand for the conformance bench | as this repository | `e2519bc6fee13afbd4470f516b3de4a2e65abbd3da43493a411cc81ff430f86e` |
| `certified-dss.pdf` | a copy of `crates/nacre-pdf/tests/corpus/real/certified-dss.pdf`, from esig/dss test data, <https://github.com/esig/dss>, `dss-pades/src/test/resources/validation/dss-2554/certified-changes-permitted.pdf`; written by LibreOffice 5.2, RSA, signed by the fictitious Nowina `PKI-TEST` CA; field `signature-test` signed, `signature-test2` empty | LGPL-2.1 | `17c74d6c6911cb8beed4430de172256bd5bed6bdccc4c5cc7c1be95aee0e1d2b` |

## `attacks/`

One file per known attack on signed PDFs, listed in `docs/security/attacks/pades.md` and
each rejected by its own test in `tests/attacks.rs`. Every file is `unsigned.pdf` given one
signature with exactly one defect; where a CMS is present, it is made by the fictitious test
key `TestSigner::from_secret(&[0x11; 32])` of `nacre-core` over the bytes its `/ByteRange`
names, so no other rule can answer in place of the one aimed at.

The files are the output of a cargo example, deterministic (RFC 6979 ECDSA, a fixed signing
time). Regenerate them from the repository root with:

```sh
cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks
```
