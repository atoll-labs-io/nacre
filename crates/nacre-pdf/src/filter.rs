use miniz_oxide::inflate::{TINFLStatus, decompress_to_vec_zlib_with_limit};

use crate::limits::Limits;
use crate::{Dictionary, Error, Object, ObjectId, Stream};

/// Decodes a stream's data. Every byte produced is charged to `budget`, the bytes left
/// for this parse, and one stream may not produce more than the per-stream limit.
pub(crate) fn decode(
    input: &[u8],
    stream: &Stream,
    object: ObjectId,
    limits: &Limits,
    budget: &mut usize,
) -> Result<Vec<u8>, Error> {
    let raw = input
        .get(stream.data.clone())
        .ok_or(Error::StreamLength { object })?;
    let max = limits.max_stream_decoded.min(*budget);
    let flate = match stream.dict.get(b"Filter") {
        None | Some(Object::Null) => false,
        Some(Object::Array(filters)) if filters.is_empty() => false,
        Some(f) if is_flate(f) => true,
        Some(other) => {
            return Err(Error::UnsupportedFilter {
                object,
                filter: describe_filter(other),
            });
        }
    };
    if !flate {
        if raw.len() > max {
            return Err(Error::DecodedTooLarge { object, max });
        }
        *budget -= raw.len();
        return Ok(raw.to_vec());
    }
    let inflated = decompress_to_vec_zlib_with_limit(raw, max).map_err(|e| {
        if e.status == TINFLStatus::HasMoreOutput {
            Error::DecodedTooLarge { object, max }
        } else {
            Error::Decode { object }
        }
    })?;
    *budget -= inflated.len();
    match decode_parms(&stream.dict, object)? {
        Some(parms) => unpredict(inflated, parms, object),
        None => Ok(inflated),
    }
}

fn is_flate(filter: &Object) -> bool {
    match filter {
        Object::Array(filters) => matches!(filters.as_slice(), [f] if f.is_name(b"FlateDecode")),
        f => f.is_name(b"FlateDecode"),
    }
}

fn describe_filter(filter: &Object) -> String {
    match filter {
        Object::Name(name) => format!("/{}", String::from_utf8_lossy(name)),
        Object::Array(filters) => {
            let names: Vec<String> = filters.iter().map(describe_filter).collect();
            format!("[{}]", names.join(" "))
        }
        _ => "a filter that is not a name".to_owned(),
    }
}

fn decode_parms(dict: &Dictionary, object: ObjectId) -> Result<Option<&Dictionary>, Error> {
    match dict.get(b"DecodeParms") {
        None | Some(Object::Null) => Ok(None),
        Some(Object::Dictionary(parms)) => Ok(Some(parms)),
        Some(Object::Array(parms)) => match parms.as_slice() {
            [Object::Dictionary(parms)] => Ok(Some(parms)),
            [Object::Null] => Ok(None),
            _ => Err(Error::Decode { object }),
        },
        Some(_) => Err(Error::Decode { object }),
    }
}

fn unpredict(data: Vec<u8>, parms: &Dictionary, object: ObjectId) -> Result<Vec<u8>, Error> {
    let predictor = match parms.get(b"Predictor") {
        None => 1,
        Some(Object::Integer(p)) => *p,
        Some(_) => return Err(Error::Decode { object }),
    };
    match predictor {
        1 => Ok(data),
        10..=15 => png_reverse(&data, parms, object),
        _ => Err(Error::UnsupportedPredictor { object, predictor }),
    }
}

fn positive(
    parms: &Dictionary,
    key: &[u8],
    default: usize,
    object: ObjectId,
) -> Result<usize, Error> {
    match parms.get(key) {
        None => Ok(default),
        Some(Object::Integer(n)) if *n >= 1 => {
            usize::try_from(*n).map_err(|_| Error::Decode { object })
        }
        Some(_) => Err(Error::Decode { object }),
    }
}

/// Undoes the PNG row filters (ISO 32000-1, 7.4.4.4): each row starts with its type byte.
fn png_reverse(data: &[u8], parms: &Dictionary, object: ObjectId) -> Result<Vec<u8>, Error> {
    let bad = || Error::Decode { object };
    let columns = positive(parms, b"Columns", 1, object)?;
    let colors = positive(parms, b"Colors", 1, object)?;
    let bits = positive(parms, b"BitsPerComponent", 8, object)?;
    if !matches!(bits, 1 | 2 | 4 | 8 | 16) {
        return Err(bad());
    }
    let bits_per_pixel = colors.checked_mul(bits).ok_or_else(bad)?;
    let bpp = bits_per_pixel.div_ceil(8).max(1);
    let row_len = columns
        .checked_mul(bits_per_pixel)
        .ok_or_else(bad)?
        .div_ceil(8);
    let stride = row_len.checked_add(1).ok_or_else(bad)?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    if stride > data.len() || !data.len().is_multiple_of(stride) {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(data.len() / stride * row_len);
    let mut prev = vec![0u8; row_len];
    for row in data.chunks_exact(stride) {
        let Some((&kind, encoded)) = row.split_first() else {
            return Err(bad());
        };
        if kind > 4 {
            return Err(bad());
        }
        let mut cur = encoded.to_vec();
        for i in 0..row_len {
            let left = i.checked_sub(bpp);
            let a = left.and_then(|j| cur.get(j)).copied().unwrap_or(0);
            let b = prev.get(i).copied().unwrap_or(0);
            let c = left.and_then(|j| prev.get(j)).copied().unwrap_or(0);
            if let Some(x) = cur.get_mut(i) {
                let predicted = match kind {
                    1 => a,
                    2 => b,
                    3 => ((u16::from(a) + u16::from(b)) / 2) as u8,
                    4 => paeth(a, b, c),
                    _ => 0,
                };
                *x = x.wrapping_add(predicted);
            }
        }
        out.extend_from_slice(&cur);
        prev = cur;
    }
    Ok(out)
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let p = i16::from(a) + i16::from(b) - i16::from(c);
    let pa = (p - i16::from(a)).abs();
    let pb = (p - i16::from(b)).abs();
    let pc = (p - i16::from(c)).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::parse::Parser;

    const ID: ObjectId = ObjectId::new(7, 0);

    fn stream(dict: &[u8], data_len: usize) -> Stream {
        let Object::Dictionary(dict) = Parser::new(dict, 0, &Limits::DEFAULT).object().unwrap()
        else {
            panic!("not a dictionary")
        };
        Stream {
            dict,
            data: 0..data_len,
        }
    }

    #[test]
    fn png_rows_are_reversed() {
        // Rows of types 0 to 4 (None, Sub, Up, Average, Paeth), Columns 3, Colors 2,
        // encoded by a Python PNG filter and pasted here.
        let encoded: [u8; 35] = [
            0, 10, 20, 30, 40, 50, 60, 1, 200, 100, 50, 161, 13, 4, 2, 57, 158, 9, 255, 254, 253,
            3, 255, 255, 255, 62, 222, 237, 4, 91, 80, 236, 236, 218, 224,
        ];
        let plain: [u8; 30] = [
            10, 20, 30, 40, 50, 60, 200, 100, 250, 5, 7, 9, 1, 2, 3, 4, 5, 6, 255, 0, 128, 64, 32,
            16, 90, 80, 70, 60, 250, 240,
        ];
        let input = miniz_oxide::deflate::compress_to_vec_zlib(&encoded, 6);
        let s = stream(
            b"<< /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 3 /Colors 2 >> >>",
            input.len(),
        );
        let mut budget = usize::MAX;
        let decoded = decode(&input, &s, ID, &Limits::DEFAULT, &mut budget).unwrap();
        assert_eq!(decoded, plain);
    }

    #[test]
    fn stream_and_parse_budgets_hold() {
        let limits = Limits {
            max_stream_decoded: 1024,
            max_total_decoded: 2048,
            ..Limits::DEFAULT
        };
        let flate = |len: usize| {
            let data = miniz_oxide::deflate::compress_to_vec_zlib(&vec![b'x'; len], 6);
            let s = stream(b"<< /Filter /FlateDecode >>", data.len());
            (data, s)
        };

        let mut budget = limits.max_total_decoded;
        let (data, s) = flate(1024);
        assert_eq!(
            decode(&data, &s, ID, &limits, &mut budget).unwrap().len(),
            1024
        );
        let mut budget = limits.max_total_decoded;
        let (data, s) = flate(1025);
        let over = decode(&data, &s, ID, &limits, &mut budget);
        assert!(matches!(
            over,
            Err(Error::DecodedTooLarge { max: 1024, .. })
        ));

        let mut budget = limits.max_total_decoded;
        let (data, s) = flate(900);
        decode(&data, &s, ID, &limits, &mut budget).unwrap();
        decode(&data, &s, ID, &limits, &mut budget).unwrap();
        let third = decode(&data, &s, ID, &limits, &mut budget);
        assert!(matches!(
            third,
            Err(Error::DecodedTooLarge { max: 248, .. })
        ));
    }
}
