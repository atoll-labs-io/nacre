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
| `certified-visible-field-signed.pdf` | the same, given an empty signature field `Approver` placed on the page with no appearance, certified at `/P 2`, then `Approver` signed: `/V`, an appearance and the Locked flag, nothing else | as this repository | `7bd716b3e00e272a8e81c9b8a7eb380ac212e7c170213ee8d49b3c46c02226fd` |
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
| `ssa-zero-rect-shown.pdf` | given the text field `Name` and an empty signature field `Sneaky` whose `/Rect` is `[0 0 0 0]`, certified at `/P 2`: signing `Sneaky` sets its rectangle and an appearance drawing over the page | `a138a512b26cc975c95090800b5401c7ce0b0b8d8b8cfa9d6ed42b6fd7ac76fe` |
| `ssa-hidden-widget-shown.pdf` | the same field `Sneaky`, placed and with its appearance but Hidden (`/F 6`), certified at `/P 3`: signing it clears Hidden (`/F 4`) | `6875bc4258e00ef22dc6151da2a08f5c60a15c4a6c6782d624a131aee42e68ec` |
| `ssa-indirect-rect.pdf` | the same field `Sneaky`, its `/Rect` an indirect `[0 0 0 0]`, certified at `/P 2`: signing it redefines that array as a visible rectangle and adds an appearance | `4283be2e088f1a2f5978aac6a22b3f72cd46fbdd60e58ecde66caae7b3523007` |
| `ssa-kid-widget-shown.pdf` | a signature field `Sneaky` and its separate widget kid of `/Rect [0 0 0 0]`, certified at `/P 2`: signing the field gives the kid a visible rectangle and an appearance | `edd00793c9e8529e3b8861e12f7d7b1f2b102e5a6fcd228cc10062ebd16e0027` |
| `ssa-orphan-widget.pdf` | given the text field `Name`, certified at `/P 2`: one revision adds a signature `Sneaky`, merged with an invisible widget, and a second visible widget whose `/Parent` is `Sneaky`, listed by page 3 but not in the field's `/Kids` | `9e4cc14e367416df275678511efb383874fc93281ba46e274609e6c648b9086f` |
| `ssa-outside-fields.pdf` | the same certified file: one revision adds a visible merged signature `Sneaky` that page 3 lists and `/Fields` does not | `16d2368c2afc5948aac28cd1ceba7059ba0f69c771e559ca280df25dc3ca3388` |
| `ssa-unlisted-widget-shown.pdf` | an empty signature field `Sneaky` with a visible rectangle, in `/Fields` but in no page's `/Annots`, certified at `/P 2`: signing it adds an appearance and lists it on page 3 | `7ce32f8c22af3f0e05cd2b068ed1da7529ef8dc13c7d8835286261e68c35d388` |
| `ssa-layer-widget-shown.pdf` | the field `Sneaky`, placed and with its appearance, in an optional content group the default configuration turns off (`/OC`, `/OCProperties`), certified at `/P 2`: signing it removes `/OC` | `18c042963ef8abffd3e7f67ef4c031aea212f21fc6b906e62c588174e4904092` |
| `ssa-moved-rect.pdf` | the field `Sneaky`, placed at `[72 650 400 700]` with no appearance, certified at `/P 2`: signing it adds an appearance and moves its rectangle to `[72 100 400 150]` | `2d85c9219a7415f5639be6120291e1f456fe9797adbeb04eb13ac31312b3596e` |
| `ssa-unreadable-rect.pdf` | given the text field `Name`, certified at `/P 2`: one revision adds a visible merged signature `Sneaky` whose `/Rect` cannot be read, its last item a reference to an object the file never defines | `a35ed3a82d11ef42329d990451f1b87cc49889bd4379030c744e2c3909a2b69f` |
| `ssa-toggle-noview-shown.pdf` | the same certified file: one revision adds a visible merged signature `Sneaky` flagged Print, NoView and ToggleNoView (`/F 292`), so it shows on hover | `1cd548c5d8d32c83a03b2d2a0526951083973ada7bf0f8d08505d627d173b904` |

The signature dictionary cases added by s43 are `unsigned.pdf` given one signature field:

| File | Content | SHA-256 |
| --- | --- | --- |
| `usf-v-direct.pdf` | the field `Signature1`, its `/V` the direct integer `7` | `eac6e01191bc5df312ecd122dc81767d6cb26dc488dfd7fe1725ebc6db8c1a15` |
| `usf-v-stream.pdf` | the field `Signature1`, its `/V` naming the page's content stream `4 0 R` | `19f1c68c654206d982e84368d8cac6fb908a1f646292546f4b541a9dffb8f7e4` |
| `subfilter-unsupported.pdf` | signed by the test key, its CMS correct, under `/SubFilter /adbe.x509.rsa_sha1` | `b41b83e330810930884b7607fab905da7a24ce50c8cfdd8721e89041393400c5` |

The files are the output of a cargo example, deterministic (RFC 6979 ECDSA, a fixed signing
time), which also writes the seven forged files of the table above into `tests/corpus/`.
Regenerate them from the repository root with:

```sh
cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks
```

## `chain/` and the chain attacks

A fictitious PKI and the PDFs signed under it, read by `tests/chain.rs`, `tests/validate.rs`
and `tests/attacks.rs` with `chain/root.der` as trust anchor at 2026-10-22. Every file is
written by the cargo example `forge_chain_attacks`; its P-256 keys are fictitious and fixed
in the example, the subjects are `O=Nacre tests,C=FR`, every certificate is valid from
2026-01-01 to 2036-01-01 unless stated, every PDF is `unsigned.pdf` signed at
2026-10-22T08:00:00Z, its CMS correct and carrying the chain named.

| File | Content | SHA-256 |
| --- | --- | --- |
| `chain/root.der` | self-signed root `CN=Nacre chain root`, CA, `keyCertSign`, `cRLSign` | `a1192fb1bcdbb43d21d99805bd9040a3847bf9b65a988d267c93ff27653c9a71` |
| `chain/intermediate.der` | `CN=Nacre chain intermediate`, issued by the root, CA, `keyCertSign`, `cRLSign` | `e2d6f541f734de8f17bc8bd0a5d12d4a0c56752fcd96f3cecb5685f3795b6cc0` |
| `chain/leaf.der` | `CN=Nacre chain signer`, issued by the intermediate, not a CA, `digitalSignature`, `nonRepudiation` | `8577bf14a4b82d9a8a25e7842f8da998bc5f34755e0894c887f99aebcf9b46eb` |
| `chain/impostor-root.der` | self-signed, the root's name, another key | `60537e32081f76ef20828332749aa6bf6f686f84f83b43ef58ab55c95ef2b0ba` |
| `chain/chain-cms.pdf` | signed by the leaf, the CMS carrying the leaf and the intermediate | `4a51e92a3884d46473a69b01c1f99f46096ac4dc7a1864ce12dd65114e43e8a2` |
| `chain/chain-dss.pdf` | signed by the leaf, the CMS carrying the leaf alone, then a revision adding a `/DSS` whose `/Certs` holds the intermediate, unfiltered | `a84bea31f37eb9c676dc6a302180934ffc515a3e34bcdde3f1234dc4d031abff` |
| `chain/chain-cms-refused-revision.pdf` | `chain-cms.pdf`, then a revision setting a catalog `/OpenAction`, which no rule allows | `f9c6461d0111f8039d26f79115cd0b55fe756b713303f23ae61f02207259ab2b` |
| `attacks/chain-impostor-root.pdf` | a leaf issued by the impostor root, the CMS carrying both | `848a03ed3aba7f9ec9e50a2224b7ba8469cbc966304f9a386f727fe6b9cab327` |
| `attacks/chain-leaf-as-ca.pdf` | the leaf, under an intermediate of the same name and key issued by the root with `cA` false | `d93863ab748c08204e6c22d375c9db5c792163774ca18551617a4a44fab2ad7e` |
| `attacks/chain-path-length.pdf` | root, then `CN=Nacre chain constrained CA` with `pathLenConstraint` 0, then `CN=Nacre chain second CA`, then a leaf | `a6f122b5c9723749dc049901cecabf5fcb068885fb7d5326a7b7b90ccc223e1a` |
| `attacks/chain-expired.pdf` | a leaf valid until 2026-06-01, under the intermediate | `4a2e980bd30053eeac19efb45196fdcced5253e9395ad1340ff4cacb0bf8ca38` |
| `attacks/chain-key-usage.pdf` | a leaf whose `keyUsage` is `keyCertSign` alone, under the intermediate | `8ef4df00549a7b807fa995d4da6588364f278dfdc96a6ca229e843d5ff2c3903` |
| `attacks/chain-critical-extension.pdf` | the leaf, under an intermediate of the same name and key carrying a critical extension `1.3.6.1.4.1.32473.1` (the arc RFC 5612 reserves for documentation), its value `NULL` | `4aaf05cb6338148dc199237945a1039a0cc19ee8f8028ae9bc2f663a48b30a80` |
| `attacks/chain-not-yet-valid.pdf` | a leaf valid from 2027-01-01, under the intermediate | `1df76f56382773f7d46a595fa76aa07dc2b1c4265b6310c367fb451f2f8ebff3` |
| `attacks/chain-ca-key-usage.pdf` | the leaf, under an intermediate of the same name and key issued by the root, `cA` true, `keyUsage` `digitalSignature` alone | `159abae7a5870cf1619065de688adbc0a59cfe8f9910979497ed8c3d9b4b0df4` |
| `attacks/chain-extended-key-usage.pdf` | a leaf with a non-critical `extendedKeyUsage` holding `serverAuth` alone, under the intermediate | `921920f158b7a9a70cc9e331313129176005558bf008ea3673f776760a4c3b87` |
| `attacks/chain-malformed-extension.pdf` | a leaf carrying `keyUsage` twice, under the intermediate | `8dcb80dc0e42465478443c5932afeb11e941f1cdfc80776a12d0a865706db3c7` |
| `attacks/chain-dss-junk.pdf` | `chain/chain-cms.pdf`, then a revision adding a `/DSS` whose `/Certs` lists 300 unfiltered streams, each a DER `SEQUENCE` of one `INTEGER` (0 to 299), none a certificate | `850e3ce3141326e8f57c9a0ab9289673e0d790af2126f665be0435189cf7569c` |

Regenerate them from the repository root with:

```sh
cargo run -p nacre-validate --example forge_chain_attacks -- crates/nacre-validate/tests/corpus
```
