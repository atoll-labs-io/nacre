# nacre-pdf test corpus

Every file here is public or fictitious. No real personal document enters this folder.
Revision ends are listed oldest first; T = classic table, S = cross-reference stream,
H = table with `/XRefStm` (hybrid).

## `real/` — files the reader must read

| File | Source | Licence | sha256 | Producer | Structure |
| --- | --- | --- | --- | --- | --- |
| `word-hybrid.pdf` | W3C WCAG 2.1 working example, <https://www.w3.org/WAI/WCAG21/working-examples/pdf-links/links.pdf> | W3C document licence | `2ddbca838061520aefe7d1deb87e33426ced0c28b7a282a9e658603610037c13` | Microsoft Word, PDF 1.7, with later incremental updates | hybrid, 2 object streams, Predictor 12, `/W [1 3 1]` and `[1 4 2]`; revisions 81959 T · 82140 H · 90822 H (+ an unnamed table at 89962) · 94902 T |
| `word-pdfmaker-linearized.pdf` | W3C, <https://www.w3.org/WAI/WCAG21/working-examples/pdf-table/table.pdf> | W3C document licence | `a693998ff2a475d128c11644fbf02374249f08ac134d526a4d9b913d8b5834a5` | Acrobat PDFMaker 9 for Word, Adobe PDF Library 9, PDF 1.6 | linearized, xref streams, 7 object streams, Predictor 12; revisions 57615 S+S · 66887 S |
| `libreoffice-pdfa3.pdf` | The Document Foundation statutes, <https://www.documentfoundation.org/statutes.pdf> | public document published by TDF, no stated licence | `7b76e445d714b793c0471d0c901b1d0a05494e1628915f2db2217aba0fbebf90` | LibreOffice 7.3, PDF 1.6, PDF/A-3b | one table, 992 objects, 12 indirect `/Length`; revision 206397 T |
| `chrome-print.pdf` | generated from `print-source.html` (fictitious page) | as this repository | `38ade8a1d7b23954308deae78cfbabf6923aa11569565cdd0f86178830e9868e` | Skia/PDF m156 (chrome-headless-shell 156.0.8078.47), PDF 1.4 | one table; revision 18950 T |
| `firefox-print.pdf` | generated from `print-source.html` | as this repository | `4699499c3a88b7475155461788ca6172ed103ff3dd825736d8a2e29575752500` | Firefox 158, Skia/PDF m149, PDF 1.4 | one table; revision 25050 T |
| `ghostscript-pdfa2.pdf` | generated from `chrome-print.pdf` | as this repository | `6d9b483819f610136c9f3a6870ec777a1476571dc5a35201164db3cfa8700afb` | Ghostscript 10.08, PDF 1.7, PDF/A-2 | xref stream without predictor, 1 object stream; revision 15883 S |
| `form-xfa-irs-w9.pdf` | IRS Form W-9, <https://www.irs.gov/pub/irs-pdf/fw9.pdf> | US public domain | `2d420cbb4123dcf1fb82595b2359cfbb5d81f00b9df9d359fcc7af361d093f53` | Designer 6.5, PDF 1.7, XFA | linearized, 17 object streams, Predictor 12, a `/Perms /UR3` usage-rights signature that is not a field; revisions 126744 S+S · 140815 S |
| `signed-twice-pyhanko.pdf` | pyHanko test data, <https://github.com/MatthiasValvekens/pyHanko>, `internal/common-test-utils/src/pyhanko_testing_commons/test_data/data/pdf/minimal-two-fields-signed-twice.pdf` | MIT | `9aad3553e8ffdf0674eef661a9418089093cb98aa0fd1940bde87bf09a1a36af` | pyHanko | linearized, xref streams; fields `Sig1` and `Sig2`, both signed by pyHanko's test PKI; revisions 26384 S+S · 50827 S |
| `signed-lta-pyhanko.pdf` | pyHanko test data, same folder, `pades-lta-dss-indirect-arrs-test.pdf` | MIT | `30fe330df187588d204519e0eff373de50a10c0fac08483368ccfc7420c1c1e4` | pyHanko | 5 tables; field `Sig1` and document timestamp field `Timestamp-977301ad-bec9-4cae-a0cd-f6a674c6e465`; revisions 739 · 1393 · 25853 · 46212 · 46884 (all T) |
| `certified-dss.pdf` | esig/dss test data, <https://github.com/esig/dss>, `dss-pades/src/test/resources/validation/dss-2554/certified-changes-permitted.pdf` | LGPL-2.1 | `17c74d6c6911cb8beed4430de172256bd5bed6bdccc4c5cc7c1be95aee0e1d2b` | LibreOffice 5.2, certified (DocMDP) | `signature-test` signed, `signature-test2` empty; revisions 127672 T · 152955 T |
| `print-source.html` | the fictitious page the prints were made from | as this repository | `69fb33f85eda28534ce2d8429dc373f410c128e6cf782f9bd13f7dead3533950` | — | — |

Regenerating the prints and the PDF/A:

- `chrome-headless-shell --no-sandbox --print-to-pdf=chrome-print.pdf --no-pdf-header-footer file://<path>/print-source.html`
- Firefox 158 through WebDriver BiDi `browsingContext.print` on the same page (a standard-library
  websocket client was used; any BiDi client does).
- `gs -dBATCH -dNOPAUSE -dSAFER -sDEVICE=pdfwrite -dPDFA=2 -dPDFACompatibilityPolicy=1 -sColorConversionStrategy=RGB -sOutputFile=ghostscript-pdfa2.pdf chrome-print.pdf`

A regenerated file has another hash and other offsets: update this table and
`tests/corpus.rs` together.

## `hostile/` — files the reader must refuse

| File | Source | Licence | sha256 | Attack | Refusal |
| --- | --- | --- | --- | --- | --- |
| `circular-xref-chain.pdf` | derived from pyHanko's `circular-xref-chain.pdf` (same folder as above): its 19-byte xref entries are padded to the 20 bytes ISO 32000-1 requires and the offsets recomputed, so the reader reaches the loop instead of refusing the first entry | MIT | `5d2000cd4e4fea9535c4daf55ea34c96cda5fb4efca900a069deb90bd073541e` | two tables whose `/Prev` point at each other (9 ↔ 66) | `XrefLoop` |
| `xref-malformed-prev.pdf` | derived from pyHanko's `xref-malformed-prev.pdf` the same way | MIT | `5b0ea91e8136e2eb34d2c212e0b3489f39a52700b92a755b82635b11a4b2a7d1` | `/Prev (zzz)` | `XrefTable` "/Prev is not an offset" |
| `startxref-off-by-one.pdf` | pyHanko's `minimal-startxref-obo1.pdf`, unchanged | MIT | `ba3415d754e4af196921df012c59784cbb508873cdf1288f757e7676aebaf30e` | `startxref` points one byte before `xref` | `NotAnXrefSection`; read with `ReadOptions::misplaced_xref` |
| `aes256.pdf` | pyHanko's `minimal-aes256.pdf`, unchanged | MIT | `eda8c19fae7b63e715f0936d0359b698bc81ab69107e159507842f08dce8b69a` | AES-256 encryption (`/Encrypt`) | `Encrypted` |

### Crafted cases

Built at test time by `tests/support/mod.rs`, never stored:

| Case | Attack or defect | Refusal |
| --- | --- | --- |
| `xref_entry_pointing_elsewhere` | the catalog's xref offset moved 3 bytes | `ObjectMismatch` |
| `xref_entry_pointing_at_another_object` | the catalog's xref entry holds the offset of object 2, a well-formed `2 0 obj` | `ObjectMismatch` |
| `missing_catalog` | `/Root 9 0 R` with no object 9 | `ObjectNotFound` |
| `object_stream_index_past_n` | the AcroForm stored at index `/N` of its object stream | `ObjectStream` |
| `other_filter_on_xref_stream` | an xref stream under `/LZWDecode` | `UnsupportedFilter` |
| `bytes_after_last_eof` | `garbage` after the last `%%EOF` | `TrailingData` |
| `reference_loop` | `/Root 5 0 R`, object 5 is `6 0 R`, object 6 is `5 0 R` | `ReferenceLoop` |
| `field_kids_loop` | two fields each listing the other in `/Kids` | `FieldLoop` |
| `stream_length_too_short`, `stream_length_past_end` | an object stream whose `/Length` is 10 bytes short, or runs past the end of the file | `StreamLength` |
| `deep_nesting` | 1,000,000 `[` inside the catalog | `TooDeep` |
| 50,000,001 bytes | a valid file padded one byte past `MAX_INPUT_LEN` | `TooLarge` |
| `huge_declared_counts` | subsection `0 8388607` in a 1 KB file | `XrefTable` |
| `xref_stream_wrong_decoded_length` | an xref stream one byte longer than its `/W` × `/Index` | `XrefStream` |
| `certified_no_changes` | DocMDP `/P 1` reached through `/Perms`, an indirect `/DocMDP` and indirect `/TransformParams`; a new approval signature is refused, a plain revision and a `/DocTimeStamp` slot are not | `CertifiedNoChanges` |
| `page_tree_loop` | a `/Pages` node whose `/Kids` lists itself; the writer looks for the first page | `Limit` "page tree depth" |
| `direct_acroform`, `indirect_fields`, `indirect_annots` | not defects: the AcroForm and page shapes the signature field is hooked into (direct `/AcroForm`; indirect `/Fields`; indirect page `/Annots`) | accepted |

## Credits

pyHanko (Matthias Valvekens, MIT), esig/dss (European Commission, LGPL-2.1), W3C (W3C
document licence), the US Internal Revenue Service (public domain) and The Document
Foundation.
