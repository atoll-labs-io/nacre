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
| `certified-pyhanko.pdf` | a copy of `crates/nacre-pdf/tests/corpus/real/certified-pyhanko.pdf` (see its README): written with pyHanko 0.38.0, certified at DocMDP `/P 3`, signed by a fictitious RSA key; field `Certification` signed, `Approval` empty | as this repository | `5bd9078558e2a1e6eb2ffbc565de000bd13f28bdb9acbecbf8b92bf3a018930e` |

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
| `isa-page-added.pdf` | a second page 9 added and the page tree 2 redefined with two `/Kids` and `/Count 2` (s48) | `8a5f81d1b497f85821f48e31260a3e14b7250862aef9df70ea861368b80623bb` |
| `isa-reason-replaced.pdf` | signed with `/Reason (Approved)`; the signature dictionary redefined under its own id, `/Reason` `Rejected`, `/ByteRange` and `/Contents` unchanged (s48) | `65b0339a26f0922b941b4eb11fb66f749775213bd53add1db928fa9bdbfa020d` |
| `isa-reason-redefined.pdf` | signed with an indirect `/Reason` object `(Approved)`; only that object redefined, `(Rejected)` (s48) | `393780c93a8c42c26572917fda426907940b6699a6d4c82592dd531ed76da1e0` |
| `isa-signature-moved.pdf` | the signed field's `/Rect` changed from `[0 0 0 0]` to `[72 72 272 122]`, all else equal (s48) | `60b8a8296e62250c91ded27527d82d9ead5e9339ff5db1c16bce8dd95fd6170e` |

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
2026-01-01 to 2036-01-01 unless stated, every CA carries a `subjectKeyIdentifier` (the first
20 bytes of the SHA-256 of its public key), every PDF is `unsigned.pdf` signed at
2026-10-22T08:00:00Z, its CMS correct and carrying the chain named.

| File | Content | SHA-256 |
| --- | --- | --- |
| `chain/root.der` | self-signed root `CN=Nacre chain root`, CA, `keyCertSign`, `cRLSign` | `cc5ef9336b9240f22ba2bf25b3f285f4fed1b14c2b45fa0353e7830ff1d6c442` |
| `chain/intermediate.der` | `CN=Nacre chain intermediate`, issued by the root, CA, `keyCertSign`, `cRLSign` | `d1ebc6723565432e4a7aa68883057d66794a6e51eff84268e2850a11e8fafbc0` |
| `chain/leaf.der` | `CN=Nacre chain signer`, issued by the intermediate, not a CA, `digitalSignature`, `nonRepudiation` | `8577bf14a4b82d9a8a25e7842f8da998bc5f34755e0894c887f99aebcf9b46eb` |
| `chain/impostor-root.der` | self-signed, the root's name, another key | `d40e2a45884be8c5d9208458efcb054377af2142d41f4c98e9c0f91e151d1aeb` |
| `chain/chain-cms.pdf` | signed by the leaf, the CMS carrying the leaf and the intermediate | `70cdbb04bf6fd96208f7528bd04008391ac3bbb7bb17bc97b225e5a8706b834a` |
| `chain/chain-dss.pdf` | signed by the leaf, the CMS carrying the leaf alone, then a revision adding a `/DSS` whose `/Certs` holds the intermediate, unfiltered | `46a46872c29855b3d0088023f86682ec3e500654ba908127954d33a992b5259b` |
| `chain/chain-cms-refused-revision.pdf` | `chain-cms.pdf`, then a revision setting a catalog `/OpenAction`, which no rule allows | `d17bd3e28ebfe800b167c64c95f0e059c6f6d9f4d87b0f4c3f01d2375779ca80` |
| `attacks/chain-impostor-root.pdf` | a leaf issued by the impostor root, the CMS carrying both | `93f15f21f12358e51f022052499393d590bc0fdc88c104a72ebfb228cc0c1648` |
| `attacks/chain-leaf-as-ca.pdf` | the leaf, under an intermediate of the same name and key issued by the root with `cA` false | `d93863ab748c08204e6c22d375c9db5c792163774ca18551617a4a44fab2ad7e` |
| `attacks/chain-path-length.pdf` | root, then `CN=Nacre chain constrained CA` with `pathLenConstraint` 0, then `CN=Nacre chain second CA`, then a leaf | `4a3619135508edb319121754927be7622ce129223286e149a2b6520daf9fc286` |
| `attacks/chain-expired.pdf` | a leaf valid until 2026-06-01, under the intermediate | `1a979d8d9c9b7507a42cc3387d090443aa8cc40722401f9215e4efee9a19b2cb` |
| `attacks/chain-key-usage.pdf` | a leaf whose `keyUsage` is `keyCertSign` alone, under the intermediate | `d3710f606fa405417981e16dbd4062dc9ba722d63091d753cf0c7fee148654c1` |
| `attacks/chain-critical-extension.pdf` | the leaf, under an intermediate of the same name and key carrying a critical extension `1.3.6.1.4.1.32473.1` (the arc RFC 5612 reserves for documentation), its value `NULL` | `71ec1e00a32393b368e3c93ca56f6ab36d49213c73dcdeb2f1f63f331cb366f5` |
| `attacks/chain-not-yet-valid.pdf` | a leaf valid from 2027-01-01, under the intermediate | `c50feee0b56f60da80a4529a71bc91eef052a923500d61aaa0dc04ce0f45eb28` |
| `attacks/chain-ca-key-usage.pdf` | the leaf, under an intermediate of the same name and key issued by the root, `cA` true, `keyUsage` `digitalSignature` alone | `e7c3772def4d34a9702b123d6c5190cbeab69201a8e499373a7e93ad15196539` |
| `attacks/chain-extended-key-usage.pdf` | a leaf with a non-critical `extendedKeyUsage` holding `serverAuth` alone, under the intermediate | `b6790a7d346073b477ed94dc005b9fd35ebdcd82b54f4ed216607474e28a142f` |
| `attacks/chain-malformed-extension.pdf` | a leaf carrying `keyUsage` twice, under the intermediate | `a1c0ac5febcaa91a5ea9fbcfe17c8d0b315f5ef690c7c9ebaa5e479acf063c84` |
| `attacks/chain-dss-junk.pdf` | `chain/chain-cms.pdf`, then a revision adding a `/DSS` whose `/Certs` lists 300 unfiltered streams, each a DER `SEQUENCE` of one `INTEGER` (0 to 299), none a certificate | `fc3bd170c9db462d77daa21df4e7a40ae2295763d969bafe12f5d78c4b422c13` |
| `attacks/xref-misplaced-startxref.pdf` | `chain/chain-cms.pdf`, then an empty update (an `xref` table with no entry and a trailer whose `/Prev` names the previous section) whose `startxref` names the end of line just before that `xref` | `2b1365755b879c6aaeb4e07c87c53be94dfdf9769adab25a4211aa2075827fb0` |

Regenerate them from the repository root with:

```sh
cargo run -p nacre-validate --example forge_chain_attacks -- crates/nacre-validate/tests/corpus
```
