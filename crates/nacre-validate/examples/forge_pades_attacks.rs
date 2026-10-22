//! Writes the attack corpus of `tests/corpus/attacks/`: each file is `tests/corpus/unsigned.pdf`
//! signed, or given a signature dictionary, with exactly one defect.
//!
//! `cargo run -p nacre-validate --example forge_pades_attacks -- crates/nacre-validate/tests/corpus/attacks`
//!
//! The output is deterministic: a fixed test key, RFC 6979 ECDSA, a fixed signing time.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};

use der::{Decode, Header, Reader, SliceReader};
use nacre_cms::{Profile, sign_detached};
use nacre_core::TestSigner;
use nacre_pades::{DateTime, sign};
use nacre_pdf::{Dictionary, Document, Object, SignatureSpec};
use sha2::{Digest, Sha256};

const SECRET: [u8; 32] = [0x11; 32];
const UNSIGNED: &[u8] = include_bytes!("../tests/corpus/unsigned.pdf");
/// Room for the CMS in a forged slot; the test signer's CMS takes well under half.
const CAPACITY: usize = 4096;

fn main() {
    let dir = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("usage: forge_pades_attacks <dir>"),
    );
    std::fs::create_dir_all(&dir).unwrap();

    let signer = TestSigner::from_secret(&SECRET).unwrap();
    let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();
    let base = sign(UNSIGNED, &signer, time).unwrap();
    let base_der = signature_der(&base);

    write(&dir, "usf-contents-missing", &hand(&[]));
    write(
        &dir,
        "usf-contents-null",
        &hand(&[(b"Contents", Object::Null)]),
    );
    write(
        &dir,
        "usf-contents-empty",
        &hand(&[(b"Contents", Object::String(Vec::new()))]),
    );
    write(&dir, "usf-contents-zeros", &zero_slot());

    let contents = (&b"Contents"[..], Object::String(base_der));
    write(
        &dir,
        "usf-byterange-missing",
        &hand(std::slice::from_ref(&contents)),
    );
    write(
        &dir,
        "usf-byterange-null",
        &hand(&[contents.clone(), (b"ByteRange", Object::Null)]),
    );
    let three = [0, 100, 200].map(Object::Integer).to_vec();
    write(
        &dir,
        "usf-byterange-short",
        &hand(&[contents, (b"ByteRange", Object::Array(three))]),
    );

    write(
        &dir,
        "byterange-not-from-start",
        &range_forge(&signer, |[_, a, b, c]| [1, a - 1, b, c]),
    );
    write(
        &dir,
        "byterange-overlap",
        &range_forge(&signer, |[_, _, b, c]| [0, b + 1, b, c]),
    );
    write(
        &dir,
        "byterange-outside-file",
        &range_forge(&signer, |[_, a, b, c]| [0, a, b, c + 1]),
    );
    // The last `%%EOF` line, 7 bytes, left unsigned.
    write(
        &dir,
        "byterange-not-whole-file",
        &range_forge(&signer, |[_, a, b, c]| [0, a, b, c - 7]),
    );
    // The gap swallows ` >>`, the end of the signature dictionary, and `\nendobj\n`: bytes
    // left unsigned, which an attacker fills with their own content.
    const K: usize = b" >>\nendobj\n".len();
    write(
        &dir,
        "swa-wrapped",
        &range_forge(&signer, |[_, a, b, c]| [0, a, b + K, c - K]),
    );

    write(&dir, "isa-appended-revision", &appended_revision(&base));
    let mut no_xref = base.clone();
    no_xref.extend_from_slice(b"99 0 obj\n(appended without a cross-reference section)\nendobj\n");
    write(&dir, "isa-no-xref", &no_xref);
}

fn write(dir: &Path, name: &str, pdf: &[u8]) {
    std::fs::write(dir.join(format!("{name}.pdf")), pdf).unwrap();
}

fn name(n: &[u8]) -> Object {
    Object::Name(n.to_vec())
}

/// The DER `SignedData` of the first signature of `pdf`, its zero padding cut.
fn signature_der(pdf: &[u8]) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let field = &doc.signature_fields()[0];
    let Object::Dictionary(sig) = doc.object(field.value.unwrap()).unwrap() else {
        panic!("/V is not a dictionary");
    };
    let Some(Object::String(contents)) = sig.get(b"Contents") else {
        panic!("no /Contents");
    };
    let mut reader = SliceReader::new(contents).unwrap();
    let header = Header::decode(&mut reader).unwrap();
    let len = usize::try_from((reader.position() + header.length()).unwrap()).unwrap();
    contents[..len].to_vec()
}

/// `unsigned.pdf` with a signature field whose `/Sig` dictionary is written by hand: the
/// usual entries, then `extra`.
fn hand(extra: &[(&[u8], Object)]) -> Vec<u8> {
    let doc = Document::parse(UNSIGNED).unwrap();
    let mut update = doc.update();

    let mut sig = Dictionary::new();
    sig.insert(b"Type", name(b"Sig"));
    sig.insert(b"Filter", name(b"Adobe.PPKLite"));
    sig.insert(b"SubFilter", name(b"ETSI.CAdES.detached"));
    sig.insert(b"M", Object::String(b"D:20261022080000Z".to_vec()));
    for (key, value) in extra {
        sig.insert(key, value.clone());
    }
    let sig_id = update.add(Object::Dictionary(sig)).unwrap();

    let mut field = Dictionary::new();
    field.insert(b"FT", name(b"Sig"));
    field.insert(b"T", Object::String(b"Signature1".to_vec()));
    field.insert(b"V", Object::Reference(sig_id));
    field.insert(b"Type", name(b"Annot"));
    field.insert(b"Subtype", name(b"Widget"));
    field.insert(b"Rect", Object::Array(vec![Object::Integer(0); 4]));
    field.insert(b"F", Object::Integer(132));
    let field_id = update.add(Object::Dictionary(field)).unwrap();

    let mut acroform = Dictionary::new();
    acroform.insert(b"Fields", Object::Array(vec![Object::Reference(field_id)]));
    acroform.insert(b"SigFlags", Object::Integer(3));
    update.set_catalog(b"AcroForm", Object::Dictionary(acroform));
    update.finish().unwrap()
}

fn spec() -> SignatureSpec {
    let mut entries = Dictionary::new();
    entries.insert(b"M", Object::String(b"D:20261022080000Z".to_vec()));
    SignatureSpec {
        field: "Signature1".into(),
        sub_filter: b"ETSI.CAdES.detached".to_vec(),
        contents_len: CAPACITY,
        entries,
    }
}

/// A signature slot laid out by the writer and left all zeros.
fn zero_slot() -> Vec<u8> {
    let doc = Document::parse(UNSIGNED).unwrap();
    doc.update().sign(spec()).unwrap().embed(&[]).unwrap()
}

/// A signature whose `/ByteRange` is `forge([0, a, b, c])`, `a..b` being the `/Contents`
/// string, rewritten in place before signing, so the CMS is correct over the forged ranges
/// as they lie in the file (clipped to its end).
fn range_forge(signer: &TestSigner, forge: impl Fn([usize; 4]) -> [usize; 4]) -> Vec<u8> {
    let doc = Document::parse(UNSIGNED).unwrap();
    let prepared = doc.update().sign(spec()).unwrap();
    let [_, a, b, c] = prepared.byte_range();
    let mut pdf = prepared.embed(&[]).unwrap();

    let forged = forge([0, a, b, c]);
    let key = b"/ByteRange ";
    let at = pdf.windows(key.len()).position(|w| w == key).unwrap() + key.len();
    let width = pdf[at..].iter().position(|&byte| byte == b']').unwrap() + 1;
    let mut text = format!("[{} {} {} {}", forged[0], forged[1], forged[2], forged[3]).into_bytes();
    assert!(text.len() < width, "the forged /ByteRange does not fit");
    text.resize(width - 1, b' ');
    text.push(b']');
    pdf[at..at + width].copy_from_slice(&text);

    let len = pdf.len();
    let part = |start: usize, count: usize| &pdf[start.min(len)..(start + count).min(len)];
    let mut hasher = Sha256::new();
    hasher.update(part(forged[0], forged[1]));
    hasher.update(part(forged[2], forged[3]));
    let cms = sign_detached(&hasher.finalize(), signer, &Profile::PADES, None).unwrap();

    let hex: String = cms.iter().map(|byte| format!("{byte:02X}")).collect();
    assert!(hex.len() <= b - a - 2, "the CMS does not fit the slot");
    pdf[a + 1..a + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    pdf
}

/// `base` followed by a revision that replaces the page tree with a page of its own.
fn appended_revision(base: &[u8]) -> Vec<u8> {
    let doc = Document::parse(base).unwrap();
    let mut update = doc.update();
    let content = update
        .add_stream(
            Dictionary::new(),
            b"BT /F1 18 Tf 72 760 Td (Content added after the signature) Tj ET".to_vec(),
        )
        .unwrap();
    // Ids are allocated in sequence, so the page tree added next takes this number.
    let pages_id = nacre_pdf::ObjectId::new(content.number + 2, 0);

    let mut font = Dictionary::new();
    font.insert(b"Type", name(b"Font"));
    font.insert(b"Subtype", name(b"Type1"));
    font.insert(b"BaseFont", name(b"Helvetica"));
    let mut fonts = Dictionary::new();
    fonts.insert(b"F1", Object::Dictionary(font));
    let mut resources = Dictionary::new();
    resources.insert(b"Font", Object::Dictionary(fonts));

    let mut page = Dictionary::new();
    page.insert(b"Type", name(b"Page"));
    page.insert(b"Parent", Object::Reference(pages_id));
    page.insert(
        b"MediaBox",
        Object::Array([0, 0, 595, 842].map(Object::Integer).to_vec()),
    );
    page.insert(b"Resources", Object::Dictionary(resources));
    page.insert(b"Contents", Object::Reference(content));
    let page_id = update.add(Object::Dictionary(page)).unwrap();

    let mut pages = Dictionary::new();
    pages.insert(b"Type", name(b"Pages"));
    pages.insert(b"Kids", Object::Array(vec![Object::Reference(page_id)]));
    pages.insert(b"Count", Object::Integer(1));
    let added = update.add(Object::Dictionary(pages)).unwrap();
    assert_eq!(added, pages_id);

    update.set_catalog(b"Pages", Object::Reference(pages_id));
    update.finish().unwrap()
}
