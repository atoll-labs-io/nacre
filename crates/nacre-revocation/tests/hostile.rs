#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::DateTime;
use nacre_revocation::Crl;

const CA: &[u8] = include_bytes!("corpus/openssl/ec-ca.der");
const CRL: &[u8] = include_bytes!("corpus/openssl/ec-ca.crl");
const REVOKED: &[u8] = include_bytes!("corpus/openssl/revoked.der");

fn rejected(input: &[u8]) -> bool {
    let at = DateTime::new(2027, 1, 1, 0, 0, 0).unwrap().to_system_time();
    match Crl::from_der(input) {
        Err(_) => true,
        Ok(crl) => crl.status(REVOKED, CA, at).is_err(),
    }
}

/// Offsets of the length octets of every TLV header in `bytes[start..end]`.
fn length_offsets(bytes: &[u8], start: usize, end: usize, out: &mut Vec<usize>) {
    let mut at = start;
    while at + 1 < end {
        let tag = bytes[at];
        let first = bytes[at + 1];
        let (len, len_octets) = if first < 0x80 {
            (first as usize, 1)
        } else {
            let n = (first & 0x7f) as usize;
            let len = bytes[at + 2..at + 2 + n]
                .iter()
                .fold(0usize, |acc, b| acc << 8 | *b as usize);
            (len, 1 + n)
        };
        out.extend(at + 1..at + 1 + len_octets);
        let content = at + 1 + len_octets;
        if tag & 0x20 != 0 {
            length_offsets(bytes, content, content + len, out);
        }
        at = content + len;
    }
}

#[test]
fn mutated_lengths_and_truncations_are_errors() {
    assert!(!rejected(CRL));
    for end in 0..CRL.len() {
        assert!(rejected(&CRL[..end]), "prefix of {end} bytes accepted");
    }

    let mut offsets = Vec::new();
    length_offsets(CRL, 0, CRL.len(), &mut offsets);
    assert!(offsets.len() > 20);
    for at in offsets {
        for replacement in [0x00, 0x7f, 0x81, 0xff] {
            if CRL[at] == replacement {
                continue;
            }
            let mut corrupted = CRL.to_vec();
            corrupted[at] = replacement;
            assert!(
                rejected(&corrupted),
                "length octet {at} set to {replacement:#04x} accepted"
            );
        }
    }
}

fn sequence(content: Vec<u8>) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![0x30];
    match len {
        0..0x80 => out.push(len as u8),
        0x80..0x100 => out.extend([0x81, len as u8]),
        _ => out.extend([0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend(content);
    out
}

#[test]
fn deep_nesting_is_an_error() {
    // Built from the inside out, each header with the minimal DER length, so that only the
    // depth is wrong.
    let mut nested = vec![0x05, 0x00];
    for _ in 0..200 {
        nested = sequence(nested);
    }
    assert!(Crl::from_der(&nested).is_err());
}
