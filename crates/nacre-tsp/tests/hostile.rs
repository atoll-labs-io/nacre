#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_core::DigestAlgorithm;
use nacre_tsp::{Request, verify_response, verify_token};
use sha2::{Digest, Sha256};

const DATA: &[u8] = include_bytes!("corpus/recorded/data.bin");
const BENCH: &[u8] = include_bytes!("corpus/recorded/bench.tsr");
const NONCE: [u8; 8] = [0xd4, 0x1c, 0xbf, 0xf4, 0xfd, 0xed, 0x9d, 0x81];

fn request() -> Request {
    Request::new(DigestAlgorithm::Sha256, &Sha256::digest(DATA), &NONCE).unwrap()
}

/// Offsets of the length octets of every TLV header starting in `bytes[..limit]`.
fn length_offsets(bytes: &[u8], start: usize, end: usize, limit: usize, out: &mut Vec<usize>) {
    let mut at = start;
    while at + 1 < end && at < limit {
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
            length_offsets(bytes, content, content + len, limit, out);
        }
        at = content + len;
    }
}

#[test]
fn truncated_and_relengthed_responses_never_panic() {
    let request = request();
    assert!(verify_response(BENCH, &request).is_ok());
    for end in 0..BENCH.len() {
        assert!(
            verify_response(&BENCH[..end], &request).is_err(),
            "prefix of {end} bytes accepted"
        );
    }

    let mut offsets = Vec::new();
    length_offsets(BENCH, 0, BENCH.len(), 64, &mut offsets);
    assert!(offsets.len() > 10);
    for at in offsets.into_iter().filter(|at| *at < 64) {
        for replacement in [0x00, 0x7f, 0x84, 0xff] {
            if BENCH[at] == replacement {
                continue;
            }
            let mut corrupted = BENCH.to_vec();
            corrupted[at] = replacement;
            assert!(
                verify_response(&corrupted, &request).is_err(),
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
        0x100..0x10000 => out.extend([0x82, (len >> 8) as u8, len as u8]),
        _ => out.extend([0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]),
    }
    out.extend(content);
    out
}

#[test]
fn deep_nesting_and_huge_lengths_are_errors() {
    const DEPTH: usize = 10_000;
    let request = request();
    let imprint = Sha256::digest(DATA);

    // Built from the inside out, each SEQUENCE header with the minimal DER length, so
    // that only the depth is wrong.
    let mut nested = vec![0x05, 0x00];
    for _ in 0..DEPTH {
        nested = sequence(nested);
    }
    // The same depth with indefinite lengths, which DER forbids.
    let indefinite: Vec<u8> = std::iter::repeat_n([0x30, 0x80], DEPTH).flatten().collect();
    // A response claiming 2^31 content octets, with almost none behind it.
    let huge = [
        0x30, 0x84, 0x80, 0x00, 0x00, 0x00, 0x30, 0x03, 0x02, 0x01, 0x00,
    ];
    // A granted status followed by the deep nesting where the token belongs.
    let mut granted = vec![0x30, 0x03, 0x02, 0x01, 0x00];
    granted.extend(&nested);
    let deep_token = sequence(granted);

    for hostile in [&nested[..], &indefinite, &huge, &deep_token] {
        assert!(verify_response(hostile, &request).is_err());
        assert!(verify_token(hostile, DigestAlgorithm::Sha256, &imprint).is_err());
    }
}
