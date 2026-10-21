use std::io::Write as _;

use crate::limits::Limits;
use crate::{Error, Object};

/// Appends `value` in PDF syntax. Strings are written in hex, so any byte survives; names
/// escape every byte the reader would not take back as itself.
pub(crate) fn object(out: &mut Vec<u8>, value: &Object) -> Result<(), Error> {
    object_at_depth(out, value, 0)
}

fn object_at_depth(out: &mut Vec<u8>, value: &Object, depth: usize) -> Result<(), Error> {
    match value {
        Object::Null => out.extend_from_slice(b"null"),
        Object::Bool(true) => out.extend_from_slice(b"true"),
        Object::Bool(false) => out.extend_from_slice(b"false"),
        Object::Integer(n) => decimal(out, n),
        Object::Real(r) => real(out, *r)?,
        Object::String(bytes) => hex_string(out, bytes),
        Object::Name(bytes) => name(out, bytes),
        Object::Reference(id) => decimal(out, id),
        Object::Array(items) => {
            enter(out, depth)?;
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b' ');
                }
                object_at_depth(out, item, depth + 1)?;
            }
            out.push(b']');
        }
        Object::Dictionary(dict) => {
            enter(out, depth)?;
            out.extend_from_slice(b"<<");
            for (key, item) in dict.iter() {
                entry_at_depth(out, key, item, depth + 1)?;
            }
            out.extend_from_slice(b" >>");
        }
        Object::Stream(_) => {
            return Err(Error::Unwritable {
                what: "a direct stream",
            });
        }
    }
    Ok(())
}

/// Appends ` /key value`, one entry of a dictionary the caller opened.
pub(crate) fn entry(out: &mut Vec<u8>, key: &[u8], value: &Object) -> Result<(), Error> {
    entry_at_depth(out, key, value, 1)
}

fn entry_at_depth(
    out: &mut Vec<u8>,
    key: &[u8],
    value: &Object,
    depth: usize,
) -> Result<(), Error> {
    out.push(b' ');
    name(out, key);
    out.push(b' ');
    object_at_depth(out, value, depth)
}

fn enter(out: &[u8], depth: usize) -> Result<(), Error> {
    if depth >= Limits::DEFAULT.max_depth {
        return Err(Error::TooDeep { offset: out.len() });
    }
    Ok(())
}

pub(crate) fn decimal(out: &mut Vec<u8>, value: impl std::fmt::Display) {
    // Writing into a Vec cannot fail.
    let _ = write!(out, "{value}");
}

fn real(out: &mut Vec<u8>, value: f64) -> Result<(), Error> {
    if !value.is_finite() {
        return Err(Error::Unwritable {
            what: "a real that is not finite",
        });
    }
    // `Display` never uses an exponent, but prints `1` for 1.0, which reads back as an integer.
    let start = out.len();
    decimal(out, value);
    if !out.get(start..).is_some_and(|text| text.contains(&b'.')) {
        out.extend_from_slice(b".0");
    }
    Ok(())
}

pub(crate) fn hex_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'<');
    hex(out, bytes);
    out.push(b'>');
}

pub(crate) fn hex(out: &mut Vec<u8>, bytes: &[u8]) {
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
}

fn name(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'/');
    for &b in bytes {
        let plain = matches!(b, 0x21..=0x7E)
            && !matches!(
                b,
                b'#' | b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
            );
        if plain {
            out.push(b);
        } else {
            let _ = write!(out, "#{b:02X}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::parse::Parser;
    use crate::{Dictionary, ObjectId};

    #[test]
    fn written_objects_parse_back_identical() {
        let mut inner = Dictionary::new();
        inner.insert(b"Ref", Object::Reference(ObjectId::new(12, 3)));
        inner.insert(b"Nothing", Object::Null);
        let mut dict = Dictionary::new();
        dict.insert(b"A name#with/odd\xE9", Object::Name(b"x y#z/\x80".to_vec()));
        dict.insert(b"S", Object::String(b"a(b)c\\d\x00e".to_vec()));
        dict.insert(b"One", Object::Real(1.0));
        dict.insert(b"Quarter", Object::Real(-0.25));
        dict.insert(b"Int", Object::Integer(-7));
        dict.insert(
            b"Nested",
            Object::Array(vec![
                Object::Array(vec![Object::Integer(1), Object::Bool(true)]),
                Object::Bool(false),
                Object::Dictionary(inner),
            ]),
        );
        let value = Object::Dictionary(dict);
        let mut out = Vec::new();
        object(&mut out, &value).unwrap();
        let back = Parser::new(&out, 0, &Limits::DEFAULT).object().unwrap();
        assert_eq!(back, value, "{}", String::from_utf8_lossy(&out));
    }
}
