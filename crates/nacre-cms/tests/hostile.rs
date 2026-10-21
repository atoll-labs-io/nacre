#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_cms::{Profile, SignedData, sign_detached};
use nacre_core::TestSigner;
use sha2::{Digest, Sha256};

const CONTENT: &[u8] = include_bytes!("corpus/openssl/content.bin");
const EC_DETACHED: &[u8] = include_bytes!("corpus/openssl/ec-detached.der");

fn rejected(input: &[u8]) -> bool {
    match SignedData::from_der(input) {
        Err(_) => true,
        Ok(signed) => signed.verify(Some(CONTENT)).is_err(),
    }
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
fn truncated_or_corrupted_der_is_an_error() {
    let nacre = sign_detached(
        &Sha256::digest(CONTENT),
        &TestSigner::from_secret(&[0x11; 32]).unwrap(),
        &Profile::PADES,
        None,
    )
    .unwrap();

    for valid in [EC_DETACHED, nacre.as_slice()] {
        assert!(!rejected(valid));
        for end in 0..valid.len() {
            assert!(rejected(&valid[..end]), "prefix of {end} bytes accepted");
        }

        let mut offsets = Vec::new();
        length_offsets(valid, 0, valid.len(), 64, &mut offsets);
        assert!(offsets.len() > 10);
        for at in offsets.into_iter().filter(|at| *at < 64) {
            for replacement in [0x00, 0x7f, 0x84, 0xff] {
                if valid[at] == replacement {
                    continue;
                }
                let mut corrupted = valid.to_vec();
                corrupted[at] = replacement;
                assert!(
                    rejected(&corrupted),
                    "length octet {at} set to {replacement:#04x} accepted"
                );
            }
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
fn deep_nesting_is_an_error() {
    const DEPTH: usize = 10_000;
    // Built from the inside out, each SEQUENCE header with the minimal DER length, so
    // that only the depth is wrong.
    let mut nested = vec![0x05, 0x00];
    for _ in 0..DEPTH {
        nested = sequence(nested);
    }
    assert!(SignedData::from_der(&nested).is_err());

    // The same depth as a certificate of a valid SignedData: reading keeps it raw, and
    // verification, which decodes it, must fail without overflowing the stack.
    let signer = TestSigner::from_secret(&[0x11; 32]).unwrap();
    let der = sign_detached(&Sha256::digest(CONTENT), &signer, &Profile::PADES, None).unwrap();
    let mut signed = SignedData::from_der(&der).unwrap();
    signed.certificates.insert(0, nested);
    let reread = SignedData::from_der(&signed.to_der().unwrap()).unwrap();
    assert!(reread.verify(Some(CONTENT)).is_err());
}
