//! PDF dates (ISO 32000-1, 7.9.4), read only as far as the `/M` rule needs.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The longest date read: `D:YYYYMMDDHHmmSSOHH'mm'` is 23 bytes, padded for leniency.
const MAX_LEN: usize = 32;

/// The instant `D:YYYY[MM[DD[HH[mm[SS[Z|±HH'mm']]]]]]` names, a missing field taking its
/// default (month and day 1, 0 elsewhere) and a missing offset read as UTC. Anything else,
/// or more than 32 bytes, is `None`.
pub(crate) fn pdf_date(bytes: &[u8]) -> Option<SystemTime> {
    if bytes.len() > MAX_LEN {
        return None;
    }
    let rest = bytes.strip_prefix(b"D:")?;
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if !matches!(digits, 4 | 6 | 8 | 10 | 12 | 14) {
        return None;
    }
    let (fields, zone) = rest.split_at_checked(digits)?;
    let year = u16::from(two(fields, 0)?) * 100 + u16::from(two(fields, 2)?);
    let field = |at: usize, default: u8| match fields.get(at..) {
        Some([]) | None => Some(default),
        Some(_) => two(fields, at),
    };
    let local = der::DateTime::new(
        year,
        field(4, 1)?,
        field(6, 1)?,
        field(8, 0)?,
        field(10, 0)?,
        field(12, 0)?,
    )
    .ok()?;
    let local = UNIX_EPOCH + local.unix_duration();
    let (sign, offset) = match zone {
        [] | [b'Z'] => return Some(local),
        [sign @ (b'+' | b'-'), offset @ ..] => (*sign, offset),
        _ => return None,
    };
    let (hours, minutes) = match offset {
        [h1, h2] | [h1, h2, b'\''] => (two(&[*h1, *h2], 0)?, 0),
        [h1, h2, b'\'', m1, m2] | [h1, h2, b'\'', m1, m2, b'\''] => {
            (two(&[*h1, *h2], 0)?, two(&[*m1, *m2], 0)?)
        }
        _ => return None,
    };
    if hours > 23 || minutes > 59 {
        return None;
    }
    let shift = Duration::from_secs(u64::from(hours) * 3600 + u64::from(minutes) * 60);
    // Local time ahead of UTC is later on the clock face than the instant it names.
    match sign {
        b'+' => local.checked_sub(shift),
        _ => local.checked_add(shift),
    }
}

/// The two ASCII digits of `bytes` at `at`, as a number.
fn two(bytes: &[u8], at: usize) -> Option<u8> {
    match bytes.get(at..at.checked_add(2)?)? {
        [high @ b'0'..=b'9', low @ b'0'..=b'9'] => Some((high - b'0') * 10 + (low - b'0')),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn at(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> SystemTime {
        UNIX_EPOCH
            + der::DateTime::new(year, month, day, hour, minute, second)
                .unwrap()
                .unix_duration()
    }

    #[test]
    fn pdf_dates_are_read_or_refused() {
        let rows: [(&[u8], Option<SystemTime>); 6] = [
            (b"D:20261022080000Z", Some(at(2026, 10, 22, 8, 0, 0))),
            (b"D:20261022100000+02'00'", Some(at(2026, 10, 22, 8, 0, 0))),
            (b"D:2026", Some(at(2026, 1, 1, 0, 0, 0))),
            (b"D:20261340", None),
            (b"D:20261022080000Z                       ", None),
            (b"20261022", None),
        ];
        for (input, expected) in rows {
            assert_eq!(pdf_date(input), expected, "{}", input.escape_ascii());
        }
    }
}
