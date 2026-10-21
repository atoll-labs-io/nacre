//! A test-only PDF writer: it lays objects out, writes a cross-reference table or stream
//! with correct offsets, and corrupts exactly one thing when a test asks it to.
#![allow(dead_code)]

use std::collections::BTreeMap;

#[derive(Clone, Copy)]
pub enum Xref {
    Table,
    /// A cross-reference stream, FlateDecode unless another filter name is given (the
    /// data is then left raw under that name).
    Stream {
        filter: Option<&'static str>,
    },
}

#[derive(Clone)]
pub struct Pdf {
    objects: Vec<(u32, Vec<u8>)>,
    compressed: Vec<(u32, Vec<u8>)>,
    object_stream: u32,
    object_stream_n: Option<usize>,
    object_stream_length_delta: i64,
    root: u32,
    trailer_extra: String,
    xref: Xref,
    xref_stream_extra_bytes: usize,
    shift: Option<(u32, i64)>,
    shift_onto: Option<(u32, u32)>,
    after_eof: Vec<u8>,
}

impl Pdf {
    pub fn new(xref: Xref) -> Self {
        Self {
            objects: Vec::new(),
            compressed: Vec::new(),
            object_stream: 0,
            object_stream_n: None,
            object_stream_length_delta: 0,
            root: 1,
            trailer_extra: String::new(),
            xref,
            xref_stream_extra_bytes: 0,
            shift: None,
            shift_onto: None,
            after_eof: Vec::new(),
        }
    }

    /// An object whose body (what lies between `N 0 obj` and `endobj`) is `body`.
    pub fn object(mut self, number: u32, body: impl AsRef<[u8]>) -> Self {
        self.objects.push((number, body.as_ref().to_vec()));
        self
    }

    /// A stream object with a correct `/Length`.
    pub fn stream(self, number: u32, dict_entries: &str, data: &[u8]) -> Self {
        let mut body =
            format!("<< {dict_entries} /Length {} >>\nstream\n", data.len()).into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\nendstream");
        self.object(number, body)
    }

    /// Puts an object in the document's object stream, numbered `container`.
    pub fn compressed(mut self, container: u32, number: u32, body: &str) -> Self {
        self.object_stream = container;
        self.compressed.push((number, body.as_bytes().to_vec()));
        self
    }

    /// Declares an object stream `/N` other than its real count.
    pub fn object_stream_n(mut self, n: usize) -> Self {
        self.object_stream_n = Some(n);
        self
    }

    /// Declares an object stream `/Length` off by `delta`.
    pub fn object_stream_length_delta(mut self, delta: i64) -> Self {
        self.object_stream_length_delta = delta;
        self
    }

    pub fn root(mut self, number: u32) -> Self {
        self.root = number;
        self
    }

    /// Adds raw entries to the trailer (or xref stream) dictionary.
    pub fn trailer(mut self, raw: &str) -> Self {
        self.trailer_extra.push(' ');
        self.trailer_extra.push_str(raw);
        self
    }

    /// Writes the xref offset of `number` moved by `delta`.
    pub fn shift(mut self, number: u32, delta: i64) -> Self {
        self.shift = Some((number, delta));
        self
    }

    /// Writes the xref offset of object `other` as the offset of `number`.
    pub fn shift_onto(mut self, number: u32, other: u32) -> Self {
        self.shift_onto = Some((number, other));
        self
    }

    /// Appends bytes to the xref stream's decoded data, so it no longer matches `/W`.
    pub fn xref_stream_extra_bytes(mut self, n: usize) -> Self {
        self.xref_stream_extra_bytes = n;
        self
    }

    pub fn after_eof(mut self, bytes: &[u8]) -> Self {
        self.after_eof = bytes.to_vec();
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
        let mut in_use: BTreeMap<u32, usize> = BTreeMap::new();
        let mut packed: BTreeMap<u32, (u32, usize)> = BTreeMap::new();
        let mut write = |out: &mut Vec<u8>, number: u32, body: &[u8]| {
            in_use.insert(number, out.len());
            out.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\nendobj\n");
        };
        for (number, body) in &self.objects {
            write(&mut out, *number, body);
        }
        if !self.compressed.is_empty() {
            let mut header = String::new();
            let mut objects = Vec::new();
            for (index, (number, body)) in self.compressed.iter().enumerate() {
                header.push_str(&format!("{number} {} ", objects.len()));
                objects.extend_from_slice(body);
                objects.push(b'\n');
                packed.insert(*number, (self.object_stream, index));
            }
            let mut data = header.clone().into_bytes();
            data.extend_from_slice(&objects);
            let n = self.object_stream_n.unwrap_or(self.compressed.len());
            let length = data.len() as i64 + self.object_stream_length_delta;
            let mut body = format!(
                "<< /Type /ObjStm /N {n} /First {} /Length {length} >>\nstream\n",
                header.len()
            )
            .into_bytes();
            body.extend_from_slice(&data);
            body.extend_from_slice(b"\nendstream");
            write(&mut out, self.object_stream, &body);
        }
        let highest = in_use
            .keys()
            .chain(packed.keys())
            .max()
            .copied()
            .unwrap_or(0);
        let onto = self
            .shift_onto
            .and_then(|(n, other)| in_use.get(&other).map(|&at| (n, at)));
        let offset_of = |number: u32, offset: usize| match (self.shift, onto) {
            (Some((n, delta)), _) if n == number => (offset as i64 + delta) as usize,
            (_, Some((n, at))) if n == number => at,
            _ => offset,
        };
        let xref_at = out.len();
        match self.xref {
            Xref::Table => {
                assert!(packed.is_empty(), "object streams need an xref stream");
                let size = highest + 1;
                out.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
                for number in 0..size {
                    let line = match in_use.get(&number) {
                        Some(&offset) => format!("{:010} 00000 n \n", offset_of(number, offset)),
                        None => "0000000000 65535 f \n".to_owned(),
                    };
                    out.extend_from_slice(line.as_bytes());
                }
                out.extend_from_slice(
                    format!(
                        "trailer\n<< /Size {size} /Root {} 0 R{} >>\n",
                        self.root, self.trailer_extra
                    )
                    .as_bytes(),
                );
            }
            Xref::Stream { filter } => {
                let own = highest + 1;
                in_use.insert(own, xref_at);
                let size = own + 1;
                let mut rows = Vec::new();
                for number in 0..size {
                    let (kind, field2, field3): (u8, u32, u16) =
                        match (in_use.get(&number), packed.get(&number)) {
                            (Some(&offset), _) => (1, offset_of(number, offset) as u32, 0),
                            (_, Some(&(container, index))) => (2, container, index as u16),
                            _ => (0, 0, 0xFFFF),
                        };
                    rows.push(kind);
                    rows.extend_from_slice(&field2.to_be_bytes());
                    rows.extend_from_slice(&field3.to_be_bytes());
                }
                rows.extend(std::iter::repeat_n(0u8, self.xref_stream_extra_bytes));
                let (filter, data) = match filter {
                    None => (
                        "/FlateDecode",
                        miniz_oxide::deflate::compress_to_vec_zlib(&rows, 6),
                    ),
                    Some(name) => (name, rows),
                };
                let mut body = format!(
                    "<< /Type /XRef /Size {size} /W [1 4 2] /Root {} 0 R /Filter {filter} /Length {}{} >>\nstream\n",
                    self.root,
                    data.len(),
                    self.trailer_extra
                )
                .into_bytes();
                body.extend_from_slice(&data);
                body.extend_from_slice(b"\nendstream");
                out.extend_from_slice(format!("{own} 0 obj\n").as_bytes());
                out.extend_from_slice(&body);
                out.extend_from_slice(b"\nendobj\n");
            }
        }
        out.extend_from_slice(format!("startxref\n{xref_at}\n%%EOF\n").as_bytes());
        out.extend_from_slice(&self.after_eof);
        out
    }

    /// Builds the document with an unused stream object sized so the file is exactly `len`
    /// bytes long.
    pub fn build_padded_to(&self, len: usize) -> Vec<u8> {
        let mut padding = 0usize;
        loop {
            let pdf = self.clone().stream(999, "", &vec![b'0'; padding]).build();
            if pdf.len() == len {
                return pdf;
            }
            padding = (padding as i64 + len as i64 - pdf.len() as i64) as usize;
        }
    }
}

pub const CATALOG: &str = "<< /Type /Catalog /Pages 2 0 R >>";
pub const PAGES: &str = "<< /Type /Pages /Kids [] /Count 0 >>";

/// A valid two-object document, for the cases that corrupt one thing in it.
pub fn minimal(xref: Xref) -> Pdf {
    Pdf::new(xref).object(1, CATALOG).object(2, PAGES)
}

pub fn corpus(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/corpus/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The refusal cases of `refusals.rs`, by test name.
pub mod refusals {
    use super::*;

    pub fn startxref_off_by_one() -> Vec<u8> {
        corpus("hostile/startxref-off-by-one.pdf")
    }

    pub fn malformed_prev() -> Vec<u8> {
        corpus("hostile/xref-malformed-prev.pdf")
    }

    pub fn xref_entry_pointing_elsewhere() -> Vec<u8> {
        minimal(Xref::Table).shift(1, 3).build()
    }

    pub fn xref_entry_pointing_at_another_object() -> Vec<u8> {
        minimal(Xref::Table).shift_onto(1, 2).build()
    }

    pub fn missing_catalog() -> Vec<u8> {
        minimal(Xref::Table).root(9).build()
    }

    pub fn object_stream_index_past_n() -> Vec<u8> {
        Pdf::new(Xref::Stream { filter: None })
            .object(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>")
            .object(2, PAGES)
            .compressed(3, 5, "<< /Unused true >>")
            .compressed(3, 4, "<< /Fields [] >>")
            .object_stream_n(1)
            .build()
    }

    pub fn encrypted() -> Vec<u8> {
        corpus("hostile/aes256.pdf")
    }

    pub fn other_filter_on_xref_stream() -> Vec<u8> {
        minimal(Xref::Stream {
            filter: Some("/LZWDecode"),
        })
        .build()
    }

    pub fn bytes_after_last_eof() -> Vec<u8> {
        minimal(Xref::Table).after_eof(b"garbage\n").build()
    }

    pub fn all() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("startxref_off_by_one", startxref_off_by_one()),
            ("malformed_prev", malformed_prev()),
            (
                "xref_entry_pointing_elsewhere",
                xref_entry_pointing_elsewhere(),
            ),
            (
                "xref_entry_pointing_at_another_object",
                xref_entry_pointing_at_another_object(),
            ),
            ("missing_catalog", missing_catalog()),
            ("object_stream_index_past_n", object_stream_index_past_n()),
            ("encrypted", encrypted()),
            ("other_filter_on_xref_stream", other_filter_on_xref_stream()),
            ("bytes_after_last_eof", bytes_after_last_eof()),
        ]
    }
}

/// The hostile cases of `hostile.rs`, by test name, except the 50 MB one.
pub mod hostile {
    use super::*;

    pub fn xref_prev_loop() -> Vec<u8> {
        corpus("hostile/circular-xref-chain.pdf")
    }

    pub fn reference_loop() -> Vec<u8> {
        Pdf::new(Xref::Table)
            .root(5)
            .object(5, "6 0 R")
            .object(6, "5 0 R")
            .build()
    }

    pub fn field_kids_loop() -> Vec<u8> {
        Pdf::new(Xref::Table)
            .object(
                1,
                "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [3 0 R] >> >>",
            )
            .object(2, PAGES)
            .object(3, "<< /FT /Sig /T (A) /Kids [4 0 R] >>")
            .object(4, "<< /T (B) /Kids [3 0 R] >>")
            .build()
    }

    fn catalog_in_object_stream(length_delta: i64) -> Vec<u8> {
        Pdf::new(Xref::Stream { filter: None })
            .compressed(3, 1, CATALOG)
            .compressed(3, 2, PAGES)
            .object_stream_length_delta(length_delta)
            .build()
    }

    pub fn stream_length_too_short() -> Vec<u8> {
        catalog_in_object_stream(-10)
    }

    pub fn stream_length_past_end() -> Vec<u8> {
        catalog_in_object_stream(1_000_000)
    }

    pub fn deep_nesting() -> Vec<u8> {
        let mut catalog = "<< /Type /Catalog /Pages 2 0 R /Deep ".to_owned();
        catalog.push_str(&"[".repeat(1_000_000));
        catalog.push_str(" >>");
        Pdf::new(Xref::Table)
            .object(1, catalog)
            .object(2, PAGES)
            .build()
    }

    pub fn huge_declared_counts() -> Vec<u8> {
        let mut pdf = b"%PDF-1.7\n".to_vec();
        let at = pdf.len();
        pdf.extend_from_slice(b"xref\n0 8388607\n0000000000 65535 f \n");
        pdf.extend_from_slice(&[b' '; 900]);
        pdf.extend_from_slice(b"\ntrailer\n<< /Size 1 >>\n");
        pdf.extend_from_slice(format!("startxref\n{at}\n%%EOF\n").as_bytes());
        pdf
    }

    pub fn xref_stream_wrong_decoded_length() -> Vec<u8> {
        minimal(Xref::Stream { filter: None })
            .xref_stream_extra_bytes(1)
            .build()
    }

    pub fn all() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("xref_prev_loop", xref_prev_loop()),
            ("reference_loop", reference_loop()),
            ("field_kids_loop", field_kids_loop()),
            ("stream_length_too_short", stream_length_too_short()),
            ("stream_length_past_end", stream_length_past_end()),
            ("deep_nesting", deep_nesting()),
            ("huge_declared_counts", huge_declared_counts()),
            (
                "xref_stream_wrong_decoded_length",
                xref_stream_wrong_decoded_length(),
            ),
        ]
    }
}

/// The writer cases of `revision.rs`, each with one page (object 3).
pub mod revision {
    use super::*;

    pub const ONE_PAGE: &str = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>";
    pub const PAGE: &str = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>";

    fn one_page(catalog: &str) -> Pdf {
        Pdf::new(Xref::Table)
            .object(1, catalog)
            .object(2, ONE_PAGE)
            .object(3, PAGE)
    }

    pub fn certified_no_changes() -> Vec<u8> {
        one_page("<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>")
            .object(
                5,
                "<< /Type /Sig /Reference [<< /Type /SigRef /TransformMethod /DocMDP /TransformParams 6 0 R >>] >>",
            )
            .object(6, "<< /Type /TransformParams /P 1 /V /1.2 >>")
            .build()
    }

    pub fn direct_acroform() -> Vec<u8> {
        one_page("<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /DA (/Helv 0 Tf) >> >>")
            .build()
    }

    pub fn indirect_fields() -> Vec<u8> {
        one_page("<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>")
            .object(4, "<< /Fields 5 0 R /SigFlags 1 >>")
            .object(5, "[]")
            .build()
    }

    pub fn indirect_annots() -> Vec<u8> {
        Pdf::new(Xref::Table)
            .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(2, ONE_PAGE)
            .object(
                3,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots 6 0 R >>",
            )
            .object(6, "[]")
            .build()
    }

    pub fn page_tree_loop() -> Vec<u8> {
        Pdf::new(Xref::Table)
            .object(1, "<< /Type /Catalog /Pages 2 0 R >>")
            .object(2, "<< /Type /Pages /Kids [2 0 R] /Count 1 >>")
            .build()
    }
}
