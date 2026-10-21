use std::collections::{HashMap, HashSet};

use crate::filter;
use crate::limits::Limits;
use crate::parse::{Parser, is_whitespace};
use crate::{Dictionary, Error, Object, ObjectId};

/// How the section that opens a revision is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    /// A classic `xref` table.
    Table,
    /// A cross-reference stream.
    Stream,
    /// A table whose trailer points at a cross-reference stream through `/XRefStm`.
    Hybrid,
}

/// One revision: the original document or one incremental update.
#[derive(Debug, Clone, PartialEq)]
pub struct Revision {
    /// The offset just past this revision's `%%EOF` line and its end of line. The last
    /// revision ends at the input's length.
    pub end: usize,
    /// The offset of the cross-reference section that opens this revision.
    pub startxref: usize,
    /// How that section is written.
    pub xref: XrefKind,
    /// That section's trailer dictionary (the stream dictionary for a stream).
    pub trailer: Dictionary,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Entry {
    Free,
    InUse { offset: usize, generation: u16 },
    Compressed { container: u32, index: u32 },
}

/// The merged cross-reference of a document, newest definitions first.
pub(crate) struct CrossReference {
    pub(crate) revisions: Vec<Revision>,
    pub(crate) entries: HashMap<u32, Entry>,
}

struct Section {
    offset: usize,
    kind: XrefKind,
    trailer: Dictionary,
    end: usize,
    prev: Option<usize>,
}

const TAIL: usize = 1024;

pub(crate) fn read(
    input: &[u8],
    limits: &Limits,
    budget: &mut usize,
) -> Result<CrossReference, Error> {
    if !input.starts_with(b"%PDF-") {
        return Err(Error::MissingHeader);
    }
    let start = find_startxref(input)?;
    let mut entries = HashMap::new();
    let mut visited = HashSet::new();
    let mut sections = Vec::new();
    let mut next = Some(start);
    while let Some(offset) = next {
        if !visited.insert(offset) {
            return Err(Error::XrefLoop { offset });
        }
        if sections.len() >= limits.max_sections {
            return Err(Error::Limit {
                what: "cross-reference sections",
                offset,
            });
        }
        let section = read_section(input, offset, limits, budget, &mut entries)?;
        next = section.prev;
        sections.push(section);
    }
    Ok(CrossReference {
        revisions: group_revisions(input, start, sections, &visited),
        entries,
    })
}

/// The revision rule: a `startxref Y %%EOF` right after a section closes a revision when
/// `Y` is a section of the chain; a section no statement names belongs to the revision
/// whose `/Prev` reached it. The last statement of the file names the newest section.
fn group_revisions(
    input: &[u8],
    start: usize,
    sections: Vec<Section>,
    chain: &HashSet<usize>,
) -> Vec<Revision> {
    let mut named: HashMap<usize, usize> = HashMap::new();
    named.insert(start, input.len());
    for section in &sections {
        let mut p = Parser::new(input, section.end, &Limits::DEFAULT);
        p.skip_whitespace();
        if let Some(y) = statement(&mut p) {
            p.eol();
            if chain.contains(&y) {
                let end = named.entry(y).or_insert(p.pos());
                *end = (*end).max(p.pos());
            }
        }
    }
    let mut revisions: Vec<Revision> = sections
        .into_iter()
        .filter_map(|s| {
            named.get(&s.offset).map(|&end| Revision {
                end,
                startxref: s.offset,
                xref: s.kind,
                trailer: s.trailer,
            })
        })
        .collect();
    revisions.reverse();
    revisions
}

/// Reads `startxref Y %%EOF` at the cursor and returns `Y`, leaving the cursor after `%%EOF`.
fn statement(p: &mut Parser<'_>) -> Option<usize> {
    if !p.keyword(b"startxref") {
        return None;
    }
    p.skip_whitespace();
    let y = usize::try_from(p.digits()?).ok()?;
    p.skip_whitespace();
    if !p.rest().starts_with(b"%%EOF") {
        return None;
    }
    p.set_pos(p.pos() + 5);
    Some(y)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// The only search of the input: the last `startxref N %%EOF` within the final 1,024 bytes.
fn find_startxref(input: &[u8]) -> Result<usize, Error> {
    let tail_start = input.len().saturating_sub(TAIL);
    let tail = input.get(tail_start..).unwrap_or(&[]);
    let mut end = tail.len();
    while let Some(i) = tail.get(..end).and_then(|t| rfind(t, b"startxref")) {
        let mut p = Parser::new(input, tail_start + i, &Limits::DEFAULT);
        if let Some(offset) = statement(&mut p) {
            let after = p.pos();
            let rest = input.get(after..).unwrap_or(&[]);
            if let Some(junk) = rest.iter().position(|b| !is_whitespace(*b)) {
                return Err(Error::TrailingData {
                    offset: after + junk,
                });
            }
            return Ok(offset);
        }
        end = i;
    }
    Err(Error::MissingStartxref)
}

fn read_section(
    input: &[u8],
    offset: usize,
    limits: &Limits,
    budget: &mut usize,
    entries: &mut HashMap<u32, Entry>,
) -> Result<Section, Error> {
    let mut p = Parser::new(input, offset, limits);
    if p.keyword(b"xref") {
        return read_table(input, p, offset, limits, budget, entries);
    }
    let Some(id) = p.object_header() else {
        return Err(Error::NotAnXrefSection { offset });
    };
    let (trailer, end) = read_stream(input, p, id, limits, budget, entries)?;
    let prev = match trailer.get(b"Prev") {
        None => None,
        Some(Object::Integer(n)) => Some(usize::try_from(*n).map_err(|_| Error::XrefStream {
            object: id,
            reason: "/Prev is not an offset",
        })?),
        Some(_) => {
            return Err(Error::XrefStream {
                object: id,
                reason: "/Prev is not an offset",
            });
        }
    };
    Ok(Section {
        offset,
        kind: XrefKind::Stream,
        trailer,
        end,
        prev,
    })
}

fn read_table(
    input: &[u8],
    mut p: Parser<'_>,
    offset: usize,
    limits: &Limits,
    budget: &mut usize,
    entries: &mut HashMap<u32, Entry>,
) -> Result<Section, Error> {
    let table = |reason| Error::XrefTable { offset, reason };
    loop {
        p.skip_whitespace();
        if p.keyword(b"trailer") {
            break;
        }
        let line = p.pos();
        let subsection = |reason| Error::XrefTable {
            offset: line,
            reason,
        };
        let first = p
            .digits()
            .ok_or_else(|| subsection("expected a subsection header or trailer"))?;
        p.skip_whitespace();
        let count = p
            .digits()
            .ok_or_else(|| subsection("expected a subsection count"))?;
        p.skip_whitespace();
        let remaining = p.rest().len() as u64;
        if count.checked_mul(20).is_none_or(|n| n > remaining) {
            return Err(subsection("subsection longer than the file"));
        }
        let max = u64::from(limits.max_object_number);
        if count > 0 && first.checked_add(count - 1).is_none_or(|last| last > max) {
            return Err(Error::Limit {
                what: "object number",
                offset: line,
            });
        }
        for k in 0..count {
            let at = p.pos();
            let entry = p
                .rest()
                .get(..20)
                .and_then(table_entry)
                .ok_or(Error::XrefTable {
                    offset: at,
                    reason: "entry is not 20 bytes `nnnnnnnnnn ggggg n|f` and an end of line",
                })?;
            let number = u32::try_from(first + k).map_err(|_| subsection("object number"))?;
            entries.entry(number).or_insert(entry);
            p.set_pos(at + 20);
        }
    }
    p.skip_ws();
    let trailer = match p.object()? {
        Object::Dictionary(d) => d,
        _ => return Err(table("trailer is not a dictionary")),
    };
    let end = p.pos();
    let prev = match trailer.get(b"Prev") {
        None => None,
        Some(Object::Integer(n)) => {
            Some(usize::try_from(*n).map_err(|_| table("/Prev is not an offset"))?)
        }
        Some(_) => return Err(table("/Prev is not an offset")),
    };
    check_size(&trailer, limits, offset, || {
        table("/Size is not an integer")
    })?;
    let kind = match trailer.get(b"XRefStm") {
        None => XrefKind::Table,
        Some(Object::Integer(n)) => {
            let stm = usize::try_from(*n).map_err(|_| table("/XRefStm is not an offset"))?;
            let mut q = Parser::new(input, stm, limits);
            let id = q
                .object_header()
                .ok_or(Error::NotAnXrefSection { offset: stm })?;
            read_stream(input, q, id, limits, budget, entries)?;
            XrefKind::Hybrid
        }
        Some(_) => return Err(table("/XRefStm is not an offset")),
    };
    Ok(Section {
        offset,
        kind,
        trailer,
        end,
        prev,
    })
}

fn table_entry(raw: &[u8]) -> Option<Entry> {
    let (offset, rest) = raw.split_at_checked(10)?;
    let (sep1, rest) = rest.split_first()?;
    let (generation, rest) = rest.split_at_checked(5)?;
    let [sep2, kind, eol1, eol2] = rest else {
        return None;
    };
    let eol_ok = matches!((eol1, eol2), (b' ', b'\n' | b'\r') | (b'\r', b'\n'));
    if *sep1 != b' ' || *sep2 != b' ' || !eol_ok {
        return None;
    }
    let offset = decimal(offset)?;
    let generation = u16::try_from(decimal(generation)?).ok()?;
    match kind {
        b'n' => Some(Entry::InUse {
            offset: usize::try_from(offset).ok()?,
            generation,
        }),
        b'f' => Some(Entry::Free),
        _ => None,
    }
}

fn decimal(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0u64, |acc, b| {
        b.is_ascii_digit().then(|| acc * 10 + u64::from(b - b'0'))
    })
}

fn check_size(
    trailer: &Dictionary,
    limits: &Limits,
    offset: usize,
    not_integer: impl FnOnce() -> Error,
) -> Result<Option<u64>, Error> {
    match trailer.get(b"Size") {
        None => Ok(None),
        Some(Object::Integer(n)) if *n >= 0 => {
            let size = n.unsigned_abs();
            if size > u64::from(limits.max_object_number) {
                return Err(Error::Limit {
                    what: "/Size",
                    offset,
                });
            }
            Ok(Some(size))
        }
        Some(_) => Err(not_integer()),
    }
}

/// Reads a cross-reference stream whose `N G obj` header the cursor has passed, merges
/// its entries, and returns its dictionary and the offset just past `endobj`.
fn read_stream(
    input: &[u8],
    mut p: Parser<'_>,
    id: ObjectId,
    limits: &Limits,
    budget: &mut usize,
    entries: &mut HashMap<u32, Entry>,
) -> Result<(Dictionary, usize), Error> {
    let bad = |reason| Error::XrefStream { object: id, reason };
    let at = p.pos();
    let object = p.indirect_body(id, &mut |_| Err(bad("indirect /Length")))?;
    let end = p.pos();
    let Object::Stream(stream) = object else {
        return Err(bad("not a stream"));
    };
    let dict = &stream.dict;
    if !dict.get(b"Type").is_some_and(|t| t.is_name(b"XRef")) {
        return Err(bad("not /Type /XRef"));
    }
    let size = check_size(dict, limits, at, || bad("/Size is not an integer"))?
        .ok_or(bad("/Size is missing"))?;
    let widths: Vec<usize> = match dict.get(b"W") {
        Some(Object::Array(w)) if w.len() == 3 => w
            .iter()
            .map(|v| match v {
                Object::Integer(n @ 0..=8) => usize::try_from(*n).ok(),
                _ => None,
            })
            .collect::<Option<_>>()
            .ok_or(bad("/W is not three widths up to 8"))?,
        _ => return Err(bad("/W is not three widths up to 8")),
    };
    let entry_len: usize = widths.iter().sum();
    if entry_len == 0 {
        return Err(bad("/W widths sum to zero"));
    }
    let subsections: Vec<(u64, u64)> = match dict.get(b"Index") {
        None => vec![(0, size)],
        Some(Object::Array(items)) if items.len() % 2 == 0 => {
            let numbers = items
                .iter()
                .map(|v| match v {
                    Object::Integer(n) => u64::try_from(*n).ok(),
                    _ => None,
                })
                .collect::<Option<Vec<u64>>>()
                .ok_or(bad("/Index is not pairs of counts"))?;
            numbers
                .chunks_exact(2)
                .filter_map(|pair| match pair {
                    [a, b] => Some((*a, *b)),
                    _ => None,
                })
                .collect()
        }
        Some(_) => return Err(bad("/Index is not pairs of counts")),
    };
    let max = u64::from(limits.max_object_number);
    let mut total: u64 = 0;
    for &(first, count) in &subsections {
        if count > 0 && first.checked_add(count - 1).is_none_or(|last| last > max) {
            return Err(Error::Limit {
                what: "object number",
                offset: at,
            });
        }
        total = total
            .checked_add(count)
            .ok_or(bad("/Index counts overflow"))?;
    }
    let expected = total
        .checked_mul(entry_len as u64)
        .ok_or(bad("/Index counts overflow"))?;
    let data = filter::decode(input, &stream, id, limits, budget)?;
    if data.len() as u64 != expected {
        return Err(bad(
            "decoded length is not the entry count times the /W widths",
        ));
    }
    let mut rows = data.chunks_exact(entry_len);
    for (first, count) in subsections {
        for k in 0..count {
            let row = rows.next().ok_or(bad("fewer entries than /Index"))?;
            let number = u32::try_from(first + k).map_err(|_| bad("object number"))?;
            let entry = stream_entry(row, &widths).ok_or(bad("entry field out of range"))?;
            entries.entry(number).or_insert(entry);
        }
    }
    Ok((stream.dict, end))
}

fn stream_entry(row: &[u8], widths: &[usize]) -> Option<Entry> {
    let [w1, w2, _] = widths else {
        return None;
    };
    let (f1, rest) = row.split_at_checked(*w1)?;
    let (f2, f3) = rest.split_at_checked(*w2)?;
    let field = |bytes: &[u8]| bytes.iter().fold(0u64, |acc, b| acc << 8 | u64::from(*b));
    // ISO 32000-1, 7.5.8.2: a type field of width 0 means type 1.
    let kind = if *w1 == 0 { 1 } else { field(f1) };
    let (f2, f3) = (field(f2), field(f3));
    Some(match kind {
        0 => Entry::Free,
        1 => Entry::InUse {
            offset: usize::try_from(f2).ok()?,
            generation: u16::try_from(f3).ok()?,
        },
        2 => Entry::Compressed {
            container: u32::try_from(f2).ok()?,
            index: u32::try_from(f3).ok()?,
        },
        // Other types are references to the null object.
        _ => Entry::Free,
    })
}
