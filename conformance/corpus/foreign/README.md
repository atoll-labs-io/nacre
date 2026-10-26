# Foreign corpus of the conformance campaign

Signed files written by other tools, read by the campaign (`crates/nacre-validate/tests/campaign.rs`) and by the tests that name them. Every file is public test material whose signer and content are fictitious.

| File | Source | Licence | SHA-256 |
| --- | --- | --- | --- |
| `public/pdf-signed-added-page.pdf` | a byte-identical copy of esig/dss, tag `6.5.1`, `dss-pades/src/test/resources/validation/pdf-signed-added-page.pdf`, <https://github.com/esig/dss/blob/6.5.1/dss-pades/src/test/resources/validation/pdf-signed-added-page.pdf>: one page signed, then a revision adding a second page; signed by `good-user` of Nowina's fictitious `PKI-TEST` (`good-ca`, `root-ca`); no personal data | LGPL-2.1 | `467573be2135cb83c17e450a1ea7992f087d79d4f18f5386509020901da7a2ec` |

DSS public files that carry a real person's name are read locally only, never committed; a forged case of the same shape stands in for each, here `pades-spoofing-replaced-reason.pdf` by the attack case `crates/nacre-validate/tests/corpus/attacks/isa-reason-replaced.pdf` and the bench case `m2-b-reason-replaced`.
