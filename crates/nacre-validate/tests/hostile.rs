#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use nacre_core::TestSigner;
use nacre_pades::{DateTime, sign};
use nacre_validate::validate;

const STRIDE: usize = 97;

#[test]
fn truncated_and_flipped_inputs_never_panic() {
    let signer = TestSigner::from_secret(&[0x11; 32]).unwrap();
    let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();
    let mut files = vec![sign(include_bytes!("corpus/unsigned.pdf"), &signer, time).unwrap()];
    let attacks = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/attacks");
    for entry in std::fs::read_dir(attacks).unwrap() {
        files.push(std::fs::read(entry.unwrap().path()).unwrap());
    }

    for file in &files {
        for at in (0..file.len()).step_by(STRIDE) {
            let _ = validate(&file[..at]);
            let mut flipped = file.clone();
            flipped[at] = 0xFF;
            let _ = validate(&flipped);
        }
    }
}
