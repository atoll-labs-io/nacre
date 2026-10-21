# QA — s05-pdf-revision

[Story](../../stories.md) · [Plan](../../plans/s05-pdf-revision.md)

Scope: the story's surface, what `git diff main...story/s05-pdf-revision` touches on it, and the acceptance criteria its user can observe through it; nothing else was checked.
Driver: scenarios.md — surface endpoint, platform lib, cli (row `endpoint` / `api, lib`)
Evidence: transcripts
Tool: Bash. A scratch binary crate called the public interface of `nacre-pdf`: `Document::parse`, `update`, `Update::add`, `add_stream`, `set_catalog`, `finish`, `sign`, `PreparedSignature::byte_range`, `signed_parts` and `embed`. It was built and run in a copy of the branch under `mktemp -d`. The checks against other tools used qpdf 12.4.2 (`qpdf --check`, `--json`), poppler 26.08.0 (`pdfsig`, `pdfinfo`) and OpenSSL 3.6.5 (`openssl cms -sign -cades` with a self-signed key made for this QA and thrown away afterwards).
Origin: —

The diff touches only `crates/nacre-pdf/` (the crate, its fuzz target, its tests) and the story's research, plan and verification notes. There is no `docs/designs/s05-pdf-revision/`. `Install` (`cargo fetch`) and `Build` (`cargo build --workspace --all-features`) both exited 0 in the copy. The full source of the probe is quoted at the top of `c1-c4-c5-plain-revision.txt`.

## Coverage
| Criterion or item | Reached | Result |
| --- | --- | --- |
| C1 — appending a revision to each PDF of s04's corpus keeps the original bytes identical, as a prefix of the new file | yes | As expected on all 10 real files, for a plain revision and for a signed one. `starts_with` is true and `cmp -n <original size>` finds the bytes identical (`c1-c4-c5-plain-revision.txt`, `c2-c3-c4-signature-slot.txt`). Each original revision keeps its `end` when the output is read again. |
| C2 — invisible signature field, `/Sig` with `/Filter /Adobe.PPKLite` and the caller's `/SubFilter`, `/Contents` reserved at the requested size, `/ByteRange` over the whole file except `/Contents` | yes | As expected on all 10 files with `Nacre1` / `ETSI.CAdES.detached` / 8192. The field has `/FT /Sig`, `/Rect [0 0 0 0]` and `/F 132`. The `/Sig` dictionary has `/Type /Sig`, `/Filter /Adobe.PPKLite` and the `/SubFilter` asked for. `/Contents` holds 16384 hex digits between `<` and `>`. `/ByteRange` is `[0 a b c]` with `b + c` equal to the file length. poppler `pdfsig` reports "Total document signed" and ranges that match (`c2-c3-c4-signature-slot.txt`). See finding 2 about `/SubFilter` values. |
| C2 — invalid spec (reserved `/Contents` or `/ByteRange` entry, empty slot, slot too large, taken signature field name) | yes | Each is refused with an error that names it, exit 1, no panic: `the signature dictionary entry /Contents is set by the writer`, `the signature slot must hold at least one byte`, `a signature field named signature-test2 already exists` (`c2-c3-signature-slot-error.txt`). See finding 1 about the wording of the "slot too large" refusal, and finding 3 about names taken by other kinds of field. |
| C3 — the API hands out the ranges to hash, then accepts the DER and writes it into `/Contents` | yes | As expected. `signed_parts()[0] ++ [1]` was signed by OpenSSL, independently of Nacre, and embedded. `pdfsig` then reports "Signature is Valid" for the new signature on all 10 files. The signatures already in `certified-dss`, `signed-twice-pyhanko` and `signed-lta-pyhanko` stay valid. A second Nacre signature over a Nacre-signed file leaves the first one valid (`c2-c3-c4-signature-slot.txt`). The DER hex sits at the start of the slot and is followed by zeros only. |
| C3 — a signature larger than the slot gives an error, with no truncated file | yes | As expected: 65 bytes into a 64-byte slot gives `the signature is 65 bytes, more than the 64 reserved`, exit 1, and no file is returned. `byte_range()` is unchanged afterwards. Exactly 64 bytes is accepted and fills the slot with no zero left (`c2-c3-signature-slot-error.txt`). |
| C4 — the new revision follows the original's xref format (table or stream); s04 reads the result again; `qpdf --check` passes with no warning | yes | As expected. Table files get a table and stream files get a stream: `form-xfa-irs-w9`, `ghostscript-pdfa2`, `signed-twice-pyhanko` and `word-pdfmaker-linearized` take `Stream`. `word-hybrid`, whose newest revision is hybrid, takes `Table`, as the plan chose. `Document::parse` reads every output. Over 10 plain outputs, 10 signed outputs and the double-signed file, `qpdf --check` exits 0 with no `WARNING` (`grep -ci warning` → 0). `pdfinfo` opens all of them. |
| C5 — a revision without a signature (for s11's `/DSS`) goes through the same API | yes | As expected: `Document::update()` → `add`, `add_stream`, `set_catalog(b"NacreQA", ref)` → `finish()` works on all 10 files. The new dictionary reads back equal, the stream's data reads back as `hello DSS`, and the catalog entry points at it (`c1-c4-c5-plain-revision.txt`). Non-PDF, truncated and missing inputs are refused before any writing (`c1-c4-c5-plain-revision-error.txt`). |
| Note — a DocMDP-certified PDF that forbids a new signature is refused with a clear error | yes | As expected on a crafted `/P 1` file: `the document is certified with no changes allowed (DocMDP /P 1)`, exit 1. The same file still takes a plain revision and a `/Type /DocTimeStamp` slot. A `/P 2` file and the real `certified-dss.pdf` take an approval signature (`c2-c3-signature-slot-error.txt`). |

## Findings
Status rule: **verified** means the steps were replayed and reproduced the defect, and an evidence file holds it; **probable** means it was seen once, or no evidence file could be kept; **unverified** means it is suspected from what the surface showed, not seen happening.

### Finding 1 — a slot too large is refused with an error about "the input" that misstates its size
Severity: minor
Status: verified
Steps to reproduce:
1. Parse `crates/nacre-pdf/tests/corpus/real/chrome-print.pdf` (18,950 bytes) with `Document::parse`.
2. Call `doc.update().sign(SignatureSpec { contents_len: 30_000_000, .. })`. Then do it again with `contents_len: usize::MAX`.
Capture: docs/qa/s05-pdf-revision/finding-1-slot-too-large-wording.txt (run and replay)
Expected: an error that says the requested slot is too large. The other refusals of `sign` name what the caller gave (`/Contents`, the slot, the field name).
Observed: `Error::TooLarge` with the message `the input is 60018950 bytes, more than the 50000000 accepted`, and `the input is 18446744073709551615 bytes, …` for `usize::MAX`. The input is 18,950 bytes. The message reports a computed output size, or a sentinel after overflow, as the size of the input. The refusal itself is correct.

### Finding 2 — `/SubFilter` is written as given, even empty or with a leading slash
Severity: minor
Status: verified
Steps to reproduce:
1. Parse `chrome-print.pdf`, then call `sign` with `sub_filter: b"".to_vec()`, then again with `sub_filter: b"/ETSI.CAdES.detached".to_vec()`, and `embed` any DER.
2. Run `pdfsig` on each output.
Capture: docs/qa/s05-pdf-revision/finding-2-subfilter-unchecked.txt (run and replay)
Expected: the story leaves `/SubFilter` to the caller, and the field's doc says "without its slash". It is not stated whether a value that cannot be used should be refused.
Observed: both calls succeed. The file holds `/SubFilter /` or `/SubFilter /#2FETSI.CAdES.detached`, and `qpdf --check` passes. `pdfsig` reports "Signature Type: unknown" and never verifies the signature. The slash is a likely mistake, since every text on PDF spells the name with it, and it silently produces a signature no validator recognises. This is a question for the story or the API: check the value, or document that it is not checked.

### Finding 3 — the new field may take the full name of an existing non-signature field, or contain a period
Severity: minor
Status: verified
Steps to reproduce:
1. Parse `real/form-xfa-irs-w9.pdf`. Its first field is the text field `topmostSubform[0].Page1[0].f1_01[0]`.
2. Call `sign` with `field: "topmostSubform[0].Page1[0].f1_01[0]"`, then `embed`.
3. List the AcroForm fields of the output with `qpdf --json --json-key=acroform`.
4. Do the same with `field: "a.b"`.
Capture: docs/qa/s05-pdf-revision/finding-3-field-name-collision.txt (run and replay)
Expected: the plan refuses only a name already held by a signature field (`DuplicateField`), and the story says nothing about names. ISO 32000 requires fully qualified field names to identify one field, and forbids a period in a partial name (`/T`).
Observed: both calls succeed. In the first output two fields share the full name `topmostSubform[0].Page1[0].f1_01[0]`, one `/Tx` and one `/Sig`. In the second, the top-level `/T` is `a.b`, which a reader parses as field `b` under `a`. qpdf prints no warning, and `pdfsig` lists the field under both names. This is a gap in what the API checks, not a broken file, and it could be closed by checking against every field name, not only signature fields.

## Not seen
- Opening the outputs in Adobe Acrobat or another full viewer: none is installed. Validity was judged by qpdf, poppler `pdfsig` and Nacre's own reader.
- A file whose newest revision is a hybrid section other than `word-hybrid.pdf`. It is the only such case in the corpus.
- Behaviour near the 50 MB bound with a real large file. The bound was reached only through the slot size (finding 1).
- The fuzz target `revision`. The story's criteria do not ask for it, and it was not run.

Tree: cf9ce0f12d97b9979ea77def52def45c61591843
QA status: complete
