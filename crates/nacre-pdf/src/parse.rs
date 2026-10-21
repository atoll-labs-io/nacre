use std::collections::HashSet;

use crate::limits::Limits;
use crate::{Dictionary, Error, Object, ObjectId, Stream};

pub(crate) fn is_whitespace(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

fn is_delimiter(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

fn is_regular(b: u8) -> bool {
    !is_whitespace(b) && !is_delimiter(b)
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Resolves the indirect `/Length` of a stream to its integer value.
pub(crate) type LengthResolver<'r> = dyn FnMut(ObjectId) -> Result<i64, Error> + 'r;

/// A cursor over the input. Every read goes through `get`, so no input can make it panic.
pub(crate) struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    max_depth: usize,
    max_object_number: u32,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(input: &'a [u8], pos: usize, limits: &Limits) -> Self {
        Self {
            input,
            pos,
            max_depth: limits.max_depth,
            max_object_number: limits.max_object_number,
        }
    }

    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    pub(crate) fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.input.get(self.pos..).unwrap_or(&[])
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.input.get(self.pos.checked_add(ahead)?).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    /// Skips PDF whitespace only.
    pub(crate) fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(is_whitespace) {
            self.pos += 1;
        }
    }

    /// Skips whitespace and comments.
    pub(crate) fn skip_ws(&mut self) {
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'%') {
                return;
            }
            while self.peek().is_some_and(|b| b != b'\n' && b != b'\r') {
                self.pos += 1;
            }
        }
    }

    pub(crate) fn at_keyword(&self, keyword: &[u8]) -> bool {
        self.rest().starts_with(keyword)
            && self.peek_at(keyword.len()).is_none_or(|b| !is_regular(b))
    }

    pub(crate) fn keyword(&mut self, keyword: &[u8]) -> bool {
        let found = self.at_keyword(keyword);
        if found {
            self.pos += keyword.len();
        }
        found
    }

    /// Consumes one end of line: CRLF, LF or CR.
    pub(crate) fn eol(&mut self) -> bool {
        match self.peek() {
            Some(b'\r') => {
                self.pos += 1;
                if self.peek() == Some(b'\n') {
                    self.pos += 1;
                }
                true
            }
            Some(b'\n') => {
                self.pos += 1;
                true
            }
            _ => false,
        }
    }

    /// Reads an unsigned decimal; `None`, with the position unchanged, when there is no
    /// digit or the value overflows.
    pub(crate) fn digits(&mut self) -> Option<u64> {
        let start = self.pos;
        let mut value: u64 = 0;
        while let Some(b @ b'0'..=b'9') = self.peek() {
            let Some(next) = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u64::from(b - b'0')))
            else {
                self.pos = start;
                return None;
            };
            value = next;
            self.pos += 1;
        }
        if self.pos == start { None } else { Some(value) }
    }

    /// Reads `N G obj`; `None`, with the position unchanged, when the bytes are not that.
    pub(crate) fn object_header(&mut self) -> Option<ObjectId> {
        let start = self.pos;
        let id = self.object_header_inner();
        if id.is_none() {
            self.pos = start;
        }
        id
    }

    fn object_header_inner(&mut self) -> Option<ObjectId> {
        let number = u32::try_from(self.digits()?).ok()?;
        if !self.peek().is_some_and(is_whitespace) {
            return None;
        }
        self.skip_ws();
        let generation = u16::try_from(self.digits()?).ok()?;
        self.skip_ws();
        self.keyword(b"obj")
            .then_some(ObjectId::new(number, generation))
    }

    /// Reads one direct object.
    pub(crate) fn object(&mut self) -> Result<Object, Error> {
        self.object_at_depth(0)
    }

    /// Reads what follows `N G obj`: an object, its stream data if any, and `endobj`.
    pub(crate) fn indirect_body(
        &mut self,
        id: ObjectId,
        length: &mut LengthResolver<'_>,
    ) -> Result<Object, Error> {
        let value = self.object()?;
        self.skip_ws();
        let at = self.pos;
        if !self.keyword(b"stream") {
            return self.endobj().map(|()| value);
        }
        let Object::Dictionary(dict) = value else {
            return Err(Error::Syntax {
                offset: at,
                expected: "a dictionary before stream",
            });
        };
        let after_keyword = self.pos;
        let lf = match self.peek() {
            Some(b'\n') => 1,
            Some(b'\r') if self.peek_at(1) == Some(b'\n') => 2,
            _ => {
                return Err(Error::Syntax {
                    offset: after_keyword,
                    expected: "CRLF or LF after stream",
                });
            }
        };
        self.pos += lf;
        let declared = match dict.get(b"Length") {
            Some(Object::Integer(n)) => *n,
            Some(Object::Reference(r)) => length(*r)?,
            _ => return Err(Error::StreamLength { object: id }),
        };
        let start = self.pos;
        let end = usize::try_from(declared)
            .ok()
            .and_then(|len| start.checked_add(len))
            .filter(|end| *end <= self.input.len())
            .ok_or(Error::StreamLength { object: id })?;
        self.pos = end;
        self.eol();
        if !self.keyword(b"endstream") {
            return Err(Error::StreamLength { object: id });
        }
        self.skip_ws();
        self.endobj()?;
        Ok(Object::Stream(Stream {
            dict,
            data: start..end,
        }))
    }

    fn endobj(&mut self) -> Result<(), Error> {
        self.skip_ws();
        if self.keyword(b"endobj") {
            Ok(())
        } else {
            Err(Error::Syntax {
                offset: self.pos,
                expected: "endobj",
            })
        }
    }

    fn object_at_depth(&mut self, depth: usize) -> Result<Object, Error> {
        self.skip_ws();
        let start = self.pos;
        match self.peek() {
            Some(b'/') => self.name().map(Object::Name),
            Some(b'(') => self.literal_string().map(Object::String),
            Some(b'<') if self.peek_at(1) == Some(b'<') => {
                self.dictionary(depth).map(Object::Dictionary)
            }
            Some(b'<') => self.hex_string().map(Object::String),
            Some(b'[') => self.array(depth).map(Object::Array),
            Some(b'+' | b'-' | b'.' | b'0'..=b'9') => self.number(),
            _ if self.keyword(b"true") => Ok(Object::Bool(true)),
            _ if self.keyword(b"false") => Ok(Object::Bool(false)),
            _ if self.keyword(b"null") => Ok(Object::Null),
            _ => Err(Error::Syntax {
                offset: start,
                expected: "an object",
            }),
        }
    }

    fn dictionary(&mut self, depth: usize) -> Result<Dictionary, Error> {
        if depth >= self.max_depth {
            return Err(Error::TooDeep { offset: self.pos });
        }
        self.pos += 2;
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        loop {
            self.skip_ws();
            let at = self.pos;
            match self.peek() {
                Some(b'>') if self.peek_at(1) == Some(b'>') => {
                    self.pos += 2;
                    return Ok(Dictionary::from_entries(entries));
                }
                Some(b'/') => {
                    let key = self.name()?;
                    if !seen.insert(key.clone()) {
                        return Err(Error::DuplicateKey { offset: at });
                    }
                    let value = self.object_at_depth(depth + 1)?;
                    entries.push((key, value));
                }
                _ => {
                    return Err(Error::Syntax {
                        offset: at,
                        expected: "a name key or >>",
                    });
                }
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Vec<Object>, Error> {
        if depth >= self.max_depth {
            return Err(Error::TooDeep { offset: self.pos });
        }
        self.pos += 1;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(items);
            }
            if self.peek().is_none() {
                return Err(Error::Syntax {
                    offset: self.pos,
                    expected: "]",
                });
            }
            items.push(self.object_at_depth(depth + 1)?);
        }
    }

    fn name(&mut self) -> Result<Vec<u8>, Error> {
        self.pos += 1;
        let mut out = Vec::new();
        while let Some(b) = self.peek().filter(|b| is_regular(*b)) {
            if b == b'#' {
                let byte = self
                    .peek_at(1)
                    .and_then(hex_value)
                    .zip(self.peek_at(2).and_then(hex_value))
                    .map(|(hi, lo)| hi << 4 | lo)
                    .ok_or(Error::Syntax {
                        offset: self.pos,
                        expected: "two hex digits after # in a name",
                    })?;
                out.push(byte);
                self.pos += 3;
            } else {
                out.push(b);
                self.pos += 1;
            }
        }
        Ok(out)
    }

    fn literal_string(&mut self) -> Result<Vec<u8>, Error> {
        let start = self.pos;
        self.pos += 1;
        let mut out = Vec::new();
        let mut open = 1usize;
        let unterminated = || Error::Syntax {
            offset: start,
            expected: "a closing parenthesis",
        };
        loop {
            match self.bump().ok_or_else(unterminated)? {
                b'(' => {
                    open += 1;
                    out.push(b'(');
                }
                b')' => {
                    open -= 1;
                    if open == 0 {
                        return Ok(out);
                    }
                    out.push(b')');
                }
                b'\r' => {
                    if self.peek() == Some(b'\n') {
                        self.pos += 1;
                    }
                    out.push(b'\n');
                }
                b'\\' => match self.bump().ok_or_else(unterminated)? {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'\r' => {
                        if self.peek() == Some(b'\n') {
                            self.pos += 1;
                        }
                    }
                    b'\n' => {}
                    d @ b'0'..=b'7' => {
                        let mut value = u32::from(d - b'0');
                        for _ in 0..2 {
                            match self.peek() {
                                Some(o @ b'0'..=b'7') => {
                                    value = value * 8 + u32::from(o - b'0');
                                    self.pos += 1;
                                }
                                _ => break,
                            }
                        }
                        // ISO 32000-1, 7.3.4.2: high-order overflow is ignored.
                        out.push((value & 0xFF) as u8);
                    }
                    other => out.push(other),
                },
                b => out.push(b),
            }
        }
    }

    fn hex_string(&mut self) -> Result<Vec<u8>, Error> {
        self.pos += 1;
        let mut out = Vec::new();
        let mut high: Option<u8> = None;
        loop {
            self.skip_whitespace();
            let at = self.pos;
            match self.bump() {
                Some(b'>') => {
                    if let Some(hi) = high {
                        out.push(hi << 4);
                    }
                    return Ok(out);
                }
                Some(b) => {
                    let nibble = hex_value(b).ok_or(Error::Syntax {
                        offset: at,
                        expected: "a hex digit or >",
                    })?;
                    match high.take() {
                        Some(hi) => out.push(hi << 4 | nibble),
                        None => high = Some(nibble),
                    }
                }
                None => {
                    return Err(Error::Syntax {
                        offset: at,
                        expected: "a hex digit or >",
                    });
                }
            }
        }
    }

    fn number(&mut self) -> Result<Object, Error> {
        let start = self.pos;
        let signed = matches!(self.peek(), Some(b'+' | b'-'));
        if signed {
            self.pos += 1;
        }
        let mut digits = 0usize;
        let mut real = false;
        while let Some(b) = self.peek() {
            match b {
                b'0'..=b'9' => digits += 1,
                b'.' if !real => real = true,
                _ => break,
            }
            self.pos += 1;
        }
        let malformed = || Error::Syntax {
            offset: start,
            expected: "a number",
        };
        if digits == 0 || self.peek().is_some_and(is_regular) {
            return Err(malformed());
        }
        let text = self
            .input
            .get(start..self.pos)
            .and_then(|t| std::str::from_utf8(t).ok())
            .ok_or_else(malformed)?;
        if real {
            return text
                .parse::<f64>()
                .map(Object::Real)
                .map_err(|_| malformed());
        }
        let value = text.parse::<i64>().map_err(|_| Error::Syntax {
            offset: start,
            expected: "an integer in range",
        })?;
        if signed {
            return Ok(Object::Integer(value));
        }
        let after = self.pos;
        match self.reference_tail(value, start)? {
            Some(id) => Ok(Object::Reference(id)),
            None => {
                self.pos = after;
                Ok(Object::Integer(value))
            }
        }
    }

    /// After an unsigned integer, reads ` G R` if it is there.
    fn reference_tail(&mut self, number: i64, start: usize) -> Result<Option<ObjectId>, Error> {
        self.skip_ws();
        let Some(generation) = self.digits() else {
            return Ok(None);
        };
        self.skip_ws();
        if !self.keyword(b"R") {
            return Ok(None);
        }
        let number = u32::try_from(number)
            .ok()
            .filter(|n| *n <= self.max_object_number)
            .ok_or(Error::Limit {
                what: "object number",
                offset: start,
            })?;
        let generation = u16::try_from(generation).map_err(|_| Error::Syntax {
            offset: start,
            expected: "a generation number up to 65535",
        })?;
        Ok(Some(ObjectId::new(number, generation)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn parse(input: &[u8]) -> Object {
        Parser::new(input, 0, &Limits::DEFAULT).object().unwrap()
    }

    #[test]
    fn strings_names_and_numbers_decode() {
        let cases: &[(&[u8], Object)] = &[
            (b"(a\\(b\\)c)", Object::String(b"a(b)c".to_vec())),
            (b"(x(nested)y)", Object::String(b"x(nested)y".to_vec())),
            (
                b"(\\n\\r\\t\\b\\f\\\\\\q)",
                Object::String(b"\n\r\t\x08\x0C\\q".to_vec()),
            ),
            (b"(\\101\\7\\0603)", Object::String(b"A\x0703".to_vec())),
            (b"(a\\\r\nb)", Object::String(b"ab".to_vec())),
            (b"(a\r\nb\rc)", Object::String(b"a\nb\nc".to_vec())),
            (b"<48 656C6c6F>", Object::String(b"Hello".to_vec())),
            (b"<901FA>", Object::String(vec![0x90, 0x1F, 0xA0])),
            (b"/A#20B#2Fc", Object::Name(b"A B/c".to_vec())),
            (b"/", Object::Name(Vec::new())),
            (b"-17", Object::Integer(-17)),
            (b"+4", Object::Integer(4)),
            (b"12 0 R", Object::Reference(ObjectId::new(12, 0))),
            (b"12 0 obj", Object::Integer(12)),
            (b"-.5", Object::Real(-0.5)),
            (b"4.", Object::Real(4.0)),
            (
                b"[1 2 0 R]",
                Object::Array(vec![
                    Object::Integer(1),
                    Object::Reference(ObjectId::new(2, 0)),
                ]),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                &parse(input),
                expected,
                "{}",
                String::from_utf8_lossy(input)
            );
        }
        let overflow = Parser::new(b"99999999999999999999", 0, &Limits::DEFAULT).object();
        assert!(matches!(overflow, Err(Error::Syntax { offset: 0, .. })));
    }
}
