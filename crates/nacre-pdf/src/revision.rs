use std::fmt;

use crate::document::Document;
use crate::limits::MAX_INPUT_LEN;
use crate::write;
use crate::{Dictionary, Error, Object, ObjectId, XrefKind};

/// The widest `/ByteRange` the slot holds, so the digits can be filled in place.
const BYTE_RANGE_WIDTH: usize = b"[0 9999999999 9999999999 9999999999]".len();

/// The entries of the signature dictionary the writer sets itself.
const RESERVED: [&[u8]; 4] = [b"Filter", b"SubFilter", b"ByteRange", b"Contents"];

enum Body {
    Object(Object),
    Stream(Dictionary, Vec<u8>),
    /// The signature dictionary without `/ByteRange` and `/Contents`, and the slot size.
    Signature(Dictionary, usize),
}

/// One incremental revision being built over a parsed [`Document`]. Nothing is written
/// until [`finish`](Self::finish) or [`sign`](Self::sign).
pub struct Update<'d, 'a> {
    doc: &'d Document<'a>,
    next: u32,
    objects: Vec<(ObjectId, Body)>,
    catalog: Option<Dictionary>,
}

impl fmt::Debug for Update<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Update")
            .field("next", &self.next)
            .field("objects", &self.objects.len())
            .field("catalog_changed", &self.catalog.is_some())
            .finish_non_exhaustive()
    }
}

/// What [`Update::sign`] adds besides the field: the signature dictionary's content.
#[derive(Debug, Clone)]
pub struct SignatureSpec {
    /// The new field's name, which no signature field may already carry.
    pub field: String,
    /// The `/SubFilter` name, without its slash.
    pub sub_filter: Vec<u8>,
    /// The bytes reserved for the DER signature; `/Contents` takes twice as many hex digits.
    pub contents_len: usize,
    /// Further entries of the signature dictionary (`/M`, `/Reason`, `/Type /DocTimeStamp`…).
    /// `/Filter`, `/SubFilter`, `/ByteRange` and `/Contents` are refused.
    pub entries: Dictionary,
}

/// A laid-out revision whose `/Contents` slot waits for the signature.
pub struct PreparedSignature {
    bytes: Vec<u8>,
    range: [usize; 4],
    capacity: usize,
}

impl fmt::Debug for PreparedSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedSignature")
            .field("len", &self.bytes.len())
            .field("byte_range", &self.range)
            .field("capacity", &self.capacity)
            .finish()
    }
}

struct Slot {
    byte_range_at: usize,
    contents_at: usize,
    len: usize,
}

struct Layout {
    bytes: Vec<u8>,
    slot: Option<Slot>,
}

impl<'d, 'a> Update<'d, 'a> {
    pub(crate) fn new(doc: &'d Document<'a>) -> Self {
        let size = match doc.trailer().get(b"Size") {
            Some(Object::Integer(n)) => u32::try_from(*n).ok(),
            _ => None,
        };
        let after_entries = doc.highest_entry().map_or(0, |n| n.saturating_add(1));
        Self {
            doc,
            next: size.unwrap_or(0).max(after_entries),
            objects: Vec::new(),
            catalog: None,
        }
    }

    /// Adds a direct object as a new indirect object and returns its id.
    pub fn add(&mut self, value: Object) -> Result<ObjectId, Error> {
        if matches!(value, Object::Stream(_)) {
            return Err(Error::Unwritable {
                what: "a direct stream",
            });
        }
        let id = self.allocate()?;
        self.put(id, Body::Object(value));
        Ok(id)
    }

    /// Adds a stream holding `data` unencoded, its `/Length` set by the writer.
    pub fn add_stream(&mut self, mut dict: Dictionary, data: Vec<u8>) -> Result<ObjectId, Error> {
        let length = i64::try_from(data.len()).map_err(|_| Error::TooLarge {
            len: data.len(),
            max: MAX_INPUT_LEN,
        })?;
        dict.insert(b"Length", Object::Integer(length));
        let id = self.allocate()?;
        self.put(id, Body::Stream(dict, data));
        Ok(id)
    }

    /// Sets `key` in the catalog, which the revision then rewrites under its own id.
    pub fn set_catalog(&mut self, key: &[u8], value: Object) {
        let doc = self.doc;
        self.catalog
            .get_or_insert_with(|| doc.catalog().clone())
            .insert(key, value);
    }

    /// Writes the revision after the original bytes.
    pub fn finish(self) -> Result<Vec<u8>, Error> {
        self.layout().map(|layout| layout.bytes)
    }

    /// Adds an invisible signature field and its signature dictionary, with `/Contents`
    /// reserved and `/ByteRange` filled, then writes the revision.
    pub fn sign(mut self, spec: SignatureSpec) -> Result<PreparedSignature, Error> {
        if let Some(key) = RESERVED.iter().find(|k| spec.entries.get(k).is_some()) {
            return Err(Error::ReservedEntry {
                key: String::from_utf8_lossy(key).into_owned(),
            });
        }
        if spec.contents_len == 0 {
            return Err(Error::EmptySignatureSlot);
        }
        let input_len = self.doc.input().len();
        let at_least = spec
            .contents_len
            .checked_mul(2)
            .and_then(|n| n.checked_add(input_len));
        if at_least.is_none_or(|n| n > MAX_INPUT_LEN) {
            return Err(Error::TooLarge {
                len: at_least.unwrap_or(usize::MAX),
                max: MAX_INPUT_LEN,
            });
        }
        if self
            .doc
            .signature_fields()
            .iter()
            .any(|f| f.name == spec.field)
        {
            return Err(Error::DuplicateField { name: spec.field });
        }

        let mut sig = Dictionary::new();
        sig.insert(b"Type", Object::Name(b"Sig".to_vec()));
        for (key, value) in spec.entries.iter() {
            sig.insert(key, value.clone());
        }
        sig.insert(b"Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
        sig.insert(b"SubFilter", Object::Name(spec.sub_filter));
        // ISO 32000-2, Table 257: /P 1 forbids approval signatures, not document timestamps.
        let approval = sig.get(b"Type").is_some_and(|t| t.is_name(b"Sig"));
        if approval && self.doc_mdp_level()? == Some(1) {
            return Err(Error::CertifiedNoChanges);
        }
        let page = self.first_page()?;

        let sig_id = self.allocate()?;
        self.put(sig_id, Body::Signature(sig, spec.contents_len));

        let mut field = Dictionary::new();
        field.insert(b"FT", Object::Name(b"Sig".to_vec()));
        field.insert(b"T", Object::String(text_string(&spec.field)));
        field.insert(b"V", Object::Reference(sig_id));
        field.insert(b"Type", Object::Name(b"Annot".to_vec()));
        field.insert(b"Subtype", Object::Name(b"Widget".to_vec()));
        field.insert(b"Rect", Object::Array(vec![Object::Integer(0); 4]));
        field.insert(b"F", Object::Integer(132));
        if let Some((page_id, _)) = &page {
            field.insert(b"P", Object::Reference(*page_id));
        }
        let field_id = self.add(Object::Dictionary(field))?;

        self.hook_into_acroform(field_id)?;
        if let Some((page_id, mut page)) = page {
            let indirect = matches!(page.get(b"Annots"), Some(Object::Reference(_)));
            let annots = self.append_to_array(page.get(b"Annots"), field_id, page_id)?;
            if !indirect {
                page.insert(b"Annots", annots);
                self.put(page_id, Body::Object(Object::Dictionary(page)));
            }
        }

        let layout = self.layout()?;
        let Some(slot) = layout.slot else {
            return Err(Error::Unwritable {
                what: "a signature slot",
            });
        };
        let mut bytes = layout.bytes;
        let a = slot.contents_at;
        let b = a + 2 * slot.len + 2;
        let range = [0, a, b, bytes.len() - b];
        let text = byte_range_text(range).ok_or(Error::TooLarge {
            len: bytes.len(),
            max: MAX_INPUT_LEN,
        })?;
        if let Some(target) = bytes.get_mut(slot.byte_range_at..slot.byte_range_at + text.len()) {
            target.copy_from_slice(&text);
        }
        Ok(PreparedSignature {
            bytes,
            range,
            capacity: slot.len,
        })
    }

    fn allocate(&mut self) -> Result<ObjectId, Error> {
        if self.next > self.doc.limits().max_object_number {
            return Err(Error::Limit {
                what: "object number",
                offset: 0,
            });
        }
        let id = ObjectId::new(self.next, 0);
        self.next += 1;
        Ok(id)
    }

    fn put(&mut self, id: ObjectId, body: Body) {
        match self
            .objects
            .iter_mut()
            .find(|(existing, _)| *existing == id)
        {
            Some((_, slot)) => *slot = body,
            None => self.objects.push((id, body)),
        }
    }

    fn current_catalog(&self) -> &Dictionary {
        self.catalog.as_ref().unwrap_or(self.doc.catalog())
    }

    /// The DocMDP permission level, following references at each step; `None` when the
    /// document is not certified.
    fn doc_mdp_level(&self) -> Result<Option<i64>, Error> {
        let doc = self.doc;
        let Some(perms) = doc.catalog().get(b"Perms") else {
            return Ok(None);
        };
        let perms = self.dictionary(perms, doc.catalog_id(), "permissions dictionary")?;
        let Some(mdp) = perms.1.get(b"DocMDP") else {
            return Ok(None);
        };
        let mdp = self.dictionary(mdp, perms.0, "signature dictionary")?;
        let Some(references) = mdp.1.get(b"Reference") else {
            return Ok(None);
        };
        let (id, references) = doc.follow(references)?;
        let Object::Array(references) = references else {
            return Err(Error::WrongType {
                object: id.unwrap_or(mdp.0),
                expected: "array of signature references",
            });
        };
        for reference in &references {
            let (owner, reference) = self.dictionary(reference, mdp.0, "signature reference")?;
            if !reference
                .get(b"TransformMethod")
                .is_some_and(|m| m.is_name(b"DocMDP"))
            {
                continue;
            }
            let Some(params) = reference.get(b"TransformParams") else {
                return Ok(Some(2));
            };
            let (owner, params) = self.dictionary(params, owner, "transform parameters")?;
            return match params.get(b"P").map(|p| doc.follow(p)).transpose()? {
                None => Ok(Some(2)),
                Some((_, Object::Integer(p))) => Ok(Some(p)),
                Some((id, _)) => Err(Error::WrongType {
                    object: id.unwrap_or(owner),
                    expected: "DocMDP permission level",
                }),
            };
        }
        Ok(None)
    }

    /// Follows `value` to a dictionary, returning the id it lives under (else `owner`).
    fn dictionary(
        &self,
        value: &Object,
        owner: ObjectId,
        expected: &'static str,
    ) -> Result<(ObjectId, Dictionary), Error> {
        match self.doc.follow(value)? {
            (id, Object::Dictionary(d)) => Ok((id.unwrap_or(owner), d)),
            (id, _) => Err(Error::WrongType {
                object: id.unwrap_or(owner),
                expected,
            }),
        }
    }

    /// The first leaf of the page tree, through `/Kids[0]` at each level.
    fn first_page(&self) -> Result<Option<(ObjectId, Dictionary)>, Error> {
        let Some(mut node) = self.doc.catalog().get(b"Pages").cloned() else {
            return Ok(None);
        };
        let mut owner = self.doc.catalog_id();
        for _ in 0..self.doc.limits().max_depth {
            let (id, dict) = match self.doc.follow(&node)? {
                (id, Object::Dictionary(d)) => (id, d),
                (id, _) => {
                    return Err(Error::WrongType {
                        object: id.unwrap_or(owner),
                        expected: "page tree node",
                    });
                }
            };
            if dict.get(b"Type").is_some_and(|t| t.is_name(b"Page")) {
                let id = id.ok_or(Error::WrongType {
                    object: owner,
                    expected: "page reference",
                })?;
                return Ok(Some((id, dict)));
            }
            let here = id.unwrap_or(owner);
            let Some(kids) = dict.get(b"Kids") else {
                return Ok(None);
            };
            let Object::Array(kids) = self.doc.follow(kids)?.1 else {
                return Err(Error::WrongType {
                    object: here,
                    expected: "array of kids",
                });
            };
            let Some(first) = kids.into_iter().next() else {
                return Ok(None);
            };
            node = first;
            owner = here;
        }
        Err(Error::Limit {
            what: "page tree depth",
            offset: 0,
        })
    }

    fn hook_into_acroform(&mut self, field_id: ObjectId) -> Result<(), Error> {
        let catalog_id = self.doc.catalog_id();
        let Some(acroform) = self.current_catalog().get(b"AcroForm").cloned() else {
            let mut acroform = Dictionary::new();
            acroform.insert(b"Fields", Object::Array(vec![Object::Reference(field_id)]));
            acroform.insert(b"SigFlags", Object::Integer(3));
            let id = self.add(Object::Dictionary(acroform))?;
            self.set_catalog(b"AcroForm", Object::Reference(id));
            return Ok(());
        };
        let (id, mut dict) = match self.doc.follow(&acroform)? {
            (id, Object::Dictionary(d)) => (id, d),
            (id, _) => {
                return Err(Error::WrongType {
                    object: id.unwrap_or(catalog_id),
                    expected: "AcroForm dictionary",
                });
            }
        };
        let fields =
            self.append_to_array(dict.get(b"Fields"), field_id, id.unwrap_or(catalog_id))?;
        dict.insert(b"Fields", fields);
        let flags = match dict
            .get(b"SigFlags")
            .map(|f| self.doc.follow(f))
            .transpose()?
        {
            Some((_, Object::Integer(n))) => n | 3,
            _ => 3,
        };
        dict.insert(b"SigFlags", Object::Integer(flags));
        match id {
            Some(id) => self.put(id, Body::Object(Object::Dictionary(dict))),
            None => self.set_catalog(b"AcroForm", Object::Dictionary(dict)),
        }
        Ok(())
    }

    /// Appends a reference to `item` to the array `value` names. An indirect array is
    /// rewritten under its own id and `value` returned unchanged; otherwise the new direct
    /// array is returned for the caller to store.
    fn append_to_array(
        &mut self,
        value: Option<&Object>,
        item: ObjectId,
        owner: ObjectId,
    ) -> Result<Object, Error> {
        let Some(value) = value else {
            return Ok(Object::Array(vec![Object::Reference(item)]));
        };
        let (id, mut items) = match self.doc.follow(value)? {
            (id, Object::Array(items)) => (id, items),
            (id, _) => {
                return Err(Error::WrongType {
                    object: id.unwrap_or(owner),
                    expected: "array",
                });
            }
        };
        items.push(Object::Reference(item));
        match id {
            Some(id) => {
                self.put(id, Body::Object(Object::Array(items)));
                Ok(value.clone())
            }
            None => Ok(Object::Array(items)),
        }
    }

    /// Lays the revision out once: the original bytes, an end of line if they lack one,
    /// each object, then a cross-reference section of the newest revision's kind.
    fn layout(mut self) -> Result<Layout, Error> {
        let doc = self.doc;
        if let Some(catalog) = self.catalog.take() {
            self.put(doc.catalog_id(), Body::Object(Object::Dictionary(catalog)));
        }
        let newest = doc.revisions().last().ok_or(Error::MissingStartxref)?;
        // A hybrid file takes a classic table: its readers already follow tables.
        let xref_id = match newest.xref {
            XrefKind::Stream => Some(self.allocate()?),
            XrefKind::Table | XrefKind::Hybrid => None,
        };

        let input = doc.input();
        let mut out = Vec::with_capacity(input.len() + 4096);
        out.extend_from_slice(input);
        if !matches!(input.last(), Some(b'\n' | b'\r')) {
            out.push(b'\n');
        }
        let mut offsets = Vec::with_capacity(self.objects.len() + 1);
        let mut slot = None;
        for (id, body) in &self.objects {
            offsets.push((*id, out.len()));
            header(&mut out, *id);
            match body {
                Body::Object(value) => write::object(&mut out, value)?,
                Body::Stream(dict, data) => stream(&mut out, dict, data)?,
                Body::Signature(dict, len) => slot = Some(signature(&mut out, dict, *len)?),
            }
            out.extend_from_slice(b"\nendobj\n");
            check_len(&out)?;
        }

        let mut trailer = Dictionary::new();
        trailer.insert(b"Size", Object::Integer(i64::from(self.next)));
        trailer.insert(b"Prev", offset(newest.startxref)?);
        trailer.insert(b"Root", Object::Reference(doc.catalog_id()));
        for key in [&b"Info"[..], b"ID"] {
            if let Some(value) = newest.trailer.get(key) {
                trailer.insert(key, value.clone());
            }
        }
        let xref_at = out.len();
        match xref_id {
            Some(xref_id) => {
                offsets.push((xref_id, xref_at));
                offsets.sort_by_key(|(id, _)| id.number);
                xref_stream(&mut out, xref_id, trailer, &offsets)?;
            }
            None => {
                offsets.sort_by_key(|(id, _)| id.number);
                xref_table(&mut out, &trailer, &offsets)?;
            }
        }
        out.extend_from_slice(b"startxref\n");
        write::decimal(&mut out, xref_at);
        out.extend_from_slice(b"\n%%EOF\n");
        check_len(&out)?;
        Ok(Layout { bytes: out, slot })
    }
}

impl PreparedSignature {
    /// `[0, a, b, c]`: the signed bytes are `0..a` and `b..b + c`; `a..b` is the
    /// `/Contents` hex string, `<` and `>` included.
    pub fn byte_range(&self) -> [usize; 4] {
        self.range
    }

    /// The two byte ranges the signature covers, in file order.
    pub fn signed_parts(&self) -> [&[u8]; 2] {
        let [_, a, b, _] = self.range;
        [
            self.bytes.get(..a).unwrap_or_default(),
            self.bytes.get(b..).unwrap_or_default(),
        ]
    }

    /// The file with `der` written in hex at the start of the slot, zeros after it.
    pub fn embed(&self, der: &[u8]) -> Result<Vec<u8>, Error> {
        if der.len() > self.capacity {
            return Err(Error::SignatureTooLarge {
                len: der.len(),
                capacity: self.capacity,
            });
        }
        let mut hex = Vec::with_capacity(2 * der.len());
        write::hex(&mut hex, der);
        let mut out = self.bytes.clone();
        let [_, a, _, _] = self.range;
        let start = a + 1;
        if let Some(target) = out.get_mut(start..start + hex.len()) {
            target.copy_from_slice(&hex);
        }
        Ok(out)
    }
}

fn header(out: &mut Vec<u8>, id: ObjectId) {
    write::decimal(out, id.number);
    out.push(b' ');
    write::decimal(out, id.generation);
    out.extend_from_slice(b" obj\n");
}

fn stream(out: &mut Vec<u8>, dict: &Dictionary, data: &[u8]) -> Result<(), Error> {
    write::object(out, &Object::Dictionary(dict.clone()))?;
    out.extend_from_slice(b"\nstream\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\nendstream");
    Ok(())
}

fn signature(out: &mut Vec<u8>, dict: &Dictionary, len: usize) -> Result<Slot, Error> {
    out.extend_from_slice(b"<<");
    for (key, value) in dict.iter() {
        write::entry(out, key, value)?;
    }
    out.extend_from_slice(b" /ByteRange ");
    let byte_range_at = out.len();
    let placeholder = byte_range_text([0; 4]).ok_or(Error::Unwritable {
        what: "a byte range",
    })?;
    out.extend_from_slice(&placeholder);
    out.extend_from_slice(b" /Contents ");
    let contents_at = out.len();
    out.push(b'<');
    out.resize(out.len() + 2 * len, b'0');
    out.extend_from_slice(b"> >>");
    Ok(Slot {
        byte_range_at,
        contents_at,
        len,
    })
}

/// `[0 a b c]` padded with spaces before `]` to [`BYTE_RANGE_WIDTH`]; `None` if wider.
fn byte_range_text(range: [usize; 4]) -> Option<Vec<u8>> {
    let mut text = Vec::with_capacity(BYTE_RANGE_WIDTH);
    text.push(b'[');
    for (i, n) in range.iter().enumerate() {
        if i > 0 {
            text.push(b' ');
        }
        write::decimal(&mut text, n);
    }
    if text.len() + 1 > BYTE_RANGE_WIDTH {
        return None;
    }
    text.resize(BYTE_RANGE_WIDTH - 1, b' ');
    text.push(b']');
    Some(text)
}

/// Contiguous runs of object numbers, as `(first, entries)`.
fn runs(offsets: &[(ObjectId, usize)]) -> Vec<(u32, &[(ObjectId, usize)])> {
    let mut runs = Vec::new();
    let mut start = 0;
    for i in 1..=offsets.len() {
        let breaks = match (offsets.get(i - 1), offsets.get(i)) {
            (Some((prev, _)), Some((id, _))) => prev.number.checked_add(1) != Some(id.number),
            _ => true,
        };
        if breaks {
            if let (Some(run), Some((first, _))) = (offsets.get(start..i), offsets.get(start)) {
                runs.push((first.number, run));
            }
            start = i;
        }
    }
    runs
}

fn xref_table(
    out: &mut Vec<u8>,
    trailer: &Dictionary,
    offsets: &[(ObjectId, usize)],
) -> Result<(), Error> {
    use std::io::Write as _;
    out.extend_from_slice(b"xref\n");
    for (first, run) in runs(offsets) {
        let _ = writeln!(out, "{first} {}", run.len());
        for (id, at) in run {
            let _ = write!(out, "{at:010} {:05} n\r\n", id.generation);
        }
    }
    out.extend_from_slice(b"trailer\n");
    write::object(out, &Object::Dictionary(trailer.clone()))?;
    out.push(b'\n');
    Ok(())
}

fn xref_stream(
    out: &mut Vec<u8>,
    id: ObjectId,
    trailer: Dictionary,
    offsets: &[(ObjectId, usize)],
) -> Result<(), Error> {
    let mut rows = Vec::with_capacity(offsets.len() * 7);
    let mut index = Vec::new();
    for (first, run) in runs(offsets) {
        index.push(Object::Integer(i64::from(first)));
        index.push(Object::Integer(run.len() as i64));
        for (id, at) in run {
            let at = u32::try_from(*at).map_err(|_| Error::TooLarge {
                len: *at,
                max: MAX_INPUT_LEN,
            })?;
            rows.push(1);
            rows.extend_from_slice(&at.to_be_bytes());
            rows.extend_from_slice(&id.generation.to_be_bytes());
        }
    }
    let mut dict = Dictionary::new();
    dict.insert(b"Type", Object::Name(b"XRef".to_vec()));
    dict.insert(
        b"W",
        Object::Array(vec![
            Object::Integer(1),
            Object::Integer(4),
            Object::Integer(2),
        ]),
    );
    dict.insert(b"Index", Object::Array(index));
    for (key, value) in trailer.iter() {
        dict.insert(key, value.clone());
    }
    dict.insert(b"Length", Object::Integer(rows.len() as i64));
    header(out, id);
    stream(out, &dict, &rows)?;
    out.extend_from_slice(b"\nendobj\n");
    Ok(())
}

fn offset(at: usize) -> Result<Object, Error> {
    i64::try_from(at)
        .map(Object::Integer)
        .map_err(|_| Error::TooLarge {
            len: at,
            max: MAX_INPUT_LEN,
        })
}

fn check_len(out: &[u8]) -> Result<(), Error> {
    if out.len() > MAX_INPUT_LEN {
        return Err(Error::TooLarge {
            len: out.len(),
            max: MAX_INPUT_LEN,
        });
    }
    Ok(())
}

/// A field name as a PDF text string: ASCII as is, anything else UTF-16BE with its mark,
/// which the reader decodes back to the same name.
fn text_string(name: &str) -> Vec<u8> {
    if name.is_ascii() {
        return name.as_bytes().to_vec();
    }
    let mut out = vec![0xFE, 0xFF];
    for unit in name.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}
