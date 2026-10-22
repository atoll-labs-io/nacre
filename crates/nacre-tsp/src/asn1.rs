use der::{Decode, Encode, Header, Length, Reader, SliceReader, Tag};

use crate::Error;

/// Runs `f` over `bytes` and requires it to consume them all.
pub(crate) fn nested<'a, T>(
    bytes: &'a [u8],
    f: impl FnOnce(&mut SliceReader<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut reader = SliceReader::new(bytes)?;
    let value = f(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

/// Reads one TLV with tag `tag` and returns its content octets.
pub(crate) fn expect<'a>(r: &mut SliceReader<'a>, tag: Tag) -> Result<&'a [u8], Error> {
    let header = Header::decode(r)?;
    header.tag().assert_eq(tag)?;
    Ok(r.read_slice(header.length())?)
}

pub(crate) fn peek_tag(r: &SliceReader<'_>) -> Result<Option<Tag>, Error> {
    if r.is_finished() {
        return Ok(None);
    }
    Ok(Some(Tag::peek(r)?))
}

pub(crate) fn tlv(tag: Tag, content: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    Header::new(tag, Length::try_from(content.len())?).encode_to_vec(&mut out)?;
    out.extend_from_slice(content);
    Ok(out)
}
