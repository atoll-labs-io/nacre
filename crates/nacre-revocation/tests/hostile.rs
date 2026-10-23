#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use der::DateTime;
use nacre_revocation::{Crl, OcspResponse};

const CA: &[u8] = include_bytes!("corpus/openssl/ec-ca.der");
const CRL: &[u8] = include_bytes!("corpus/openssl/ec-ca.crl");
const REVOKED: &[u8] = include_bytes!("corpus/openssl/revoked.der");
const OCSP_CA: &[u8] = include_bytes!("corpus/ocsp-openssl/ca.der");
const OCSP_RESPONSE: &[u8] = include_bytes!("corpus/ocsp-openssl/revoked.der");
const OCSP_REVOKED: &[u8] = include_bytes!("corpus/ocsp-openssl/revoked-leaf.der");

fn rejected(input: &[u8]) -> bool {
    let at = DateTime::new(2027, 1, 1, 0, 0, 0).unwrap().to_system_time();
    match Crl::from_der(input) {
        Err(_) => true,
        Ok(crl) => crl.status(REVOKED, CA, at).is_err(),
    }
}

/// Offsets of the length octets of every TLV header in `bytes[start..end]`, descending
/// into constructed values and, when `octets` is set, into the first `OCTET STRING` holding a
/// `SEQUENCE`: the `BasicOCSPResponse` inside an `OCSPResponse`.
fn length_offsets(bytes: &[u8], start: usize, end: usize, mut octets: bool, out: &mut Vec<usize>) {
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
            length_offsets(bytes, content, content + len, octets, out);
        } else if octets && tag == 0x04 && bytes.get(content) == Some(&0x30) {
            length_offsets(bytes, content, content + len, false, out);
            octets = false;
        }
        at = content + len;
    }
}

fn ocsp_rejected(input: &[u8]) -> bool {
    let Ok(response) = OcspResponse::from_der(input) else {
        return true;
    };
    // OpenSSL stamped thisUpdate at generation: judge at the response's own date.
    let Some(at) = response.this_update() else {
        return true;
    };
    response.status(OCSP_REVOKED, OCSP_CA, at).is_err()
}

/// Every prefix of `input`, and every length octet set to four other values, is rejected,
/// while `input` itself is accepted.
fn truncations_and_length_mutations_rejected(
    input: &[u8],
    octets: bool,
    rejected: impl Fn(&[u8]) -> bool,
) {
    assert!(!rejected(input));
    for end in 0..input.len() {
        assert!(rejected(&input[..end]), "prefix of {end} bytes accepted");
    }

    let mut offsets = Vec::new();
    length_offsets(input, 0, input.len(), octets, &mut offsets);
    assert!(offsets.len() > 20);
    for at in offsets {
        for replacement in [0x00, 0x7f, 0x81, 0xff] {
            if input[at] == replacement {
                continue;
            }
            let mut corrupted = input.to_vec();
            corrupted[at] = replacement;
            assert!(
                rejected(&corrupted),
                "length octet {at} set to {replacement:#04x} accepted"
            );
        }
    }
}

#[test]
fn mutated_lengths_and_truncations_are_errors() {
    truncations_and_length_mutations_rejected(CRL, false, rejected);
}

#[test]
fn mutated_ocsp_lengths_and_truncations_are_errors() {
    truncations_and_length_mutations_rejected(OCSP_RESPONSE, true, ocsp_rejected);
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
