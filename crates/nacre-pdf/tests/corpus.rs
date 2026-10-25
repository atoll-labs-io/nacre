#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use std::collections::HashMap;

use nacre_pdf::{Document, Object, ObjectId, XrefKind};
use support::{Pdf, Xref};

use XrefKind::{Hybrid as H, Stream as S, Table as T};

/// Each real file with the revision ends and the kind of each revision's opening section,
/// as the spike measured them (docs/research/s04-pdf-read.md).
const FILES: &[(&str, &[usize], &[XrefKind])] = &[
    (
        "word-hybrid.pdf",
        &[81959, 82140, 90822, 94902],
        &[T, H, H, T],
    ),
    ("word-pdfmaker-linearized.pdf", &[57615, 66887], &[S, S]),
    ("libreoffice-pdfa3.pdf", &[206397], &[T]),
    ("chrome-print.pdf", &[18950], &[T]),
    ("firefox-print.pdf", &[25050], &[T]),
    ("ghostscript-pdfa2.pdf", &[15883], &[S]),
    ("form-xfa-irs-w9.pdf", &[126744, 140815], &[S, S]),
    ("signed-twice-pyhanko.pdf", &[26384, 50827], &[S, S]),
    (
        "signed-lta-pyhanko.pdf",
        &[739, 1393, 25853, 46212, 46884],
        &[T, T, T, T, T],
    ),
    ("certified-pyhanko.pdf", &[744, 9700], &[T, T]),
];

fn read(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/corpus/real/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

#[test]
fn revisions_match_the_spike() {
    for (name, ends, kinds) in FILES {
        let bytes = read(name);
        let doc = Document::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let got_ends: Vec<usize> = doc.revisions().iter().map(|r| r.end).collect();
        let got_kinds: Vec<XrefKind> = doc.revisions().iter().map(|r| r.xref).collect();
        assert_eq!(&got_ends, ends, "{name}");
        assert_eq!(&got_kinds, kinds, "{name}");
        assert_eq!(doc.revisions().last().unwrap().end, bytes.len(), "{name}");
    }
}

#[test]
fn signature_fields_match_pdfsig() {
    let expected: &[(&str, &[(&str, bool)])] = &[
        (
            "signed-twice-pyhanko.pdf",
            &[("Sig1", true), ("Sig2", true)],
        ),
        (
            "signed-lta-pyhanko.pdf",
            &[
                ("Sig1", true),
                ("Timestamp-977301ad-bec9-4cae-a0cd-f6a674c6e465", true),
            ],
        ),
        (
            "certified-pyhanko.pdf",
            &[("Certification", true), ("Approval", false)],
        ),
    ];
    for (name, _, _) in FILES {
        let bytes = read(name);
        let doc = Document::parse(&bytes).unwrap();
        let got: Vec<(&str, bool)> = doc
            .signature_fields()
            .iter()
            .map(|f| (f.name.as_str(), f.value.is_some()))
            .collect();
        let want = expected
            .iter()
            .find(|(n, _)| n == name)
            .map_or(&[][..], |(_, fields)| fields);
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn catalog_and_trailer_are_read() {
    for (name, _, _) in FILES {
        let bytes = read(name);
        let doc = Document::parse(&bytes).unwrap();
        assert_eq!(
            doc.trailer().get(b"Root"),
            Some(&Object::Reference(doc.catalog_id())),
            "{name}"
        );
        assert_eq!(
            doc.catalog().get(b"Type"),
            Some(&Object::Name(b"Catalog".to_vec())),
            "{name}"
        );
        let hybrid = doc.revisions().iter().any(|r| r.xref == XrefKind::Hybrid);
        assert_eq!(hybrid, *name == "word-hybrid.pdf", "{name}");
    }
}

fn type_is(object: &Object, name: &[u8]) -> bool {
    let dict = match object {
        Object::Dictionary(d) => d,
        Object::Stream(s) => &s.dict,
        _ => return false,
    };
    dict.get(b"Type") == Some(&Object::Name(name.to_vec()))
}

/// The leaves of the page tree, read from `map` alone.
fn pages_in(map: &HashMap<ObjectId, Object>, node: ObjectId) -> Vec<ObjectId> {
    let Some(Object::Dictionary(dict)) = map.get(&node) else {
        panic!("{node} is not in the map");
    };
    if type_is(&map[&node], b"Page") {
        return vec![node];
    }
    let kids = match dict.get(b"Kids") {
        Some(Object::Array(kids)) => kids.clone(),
        Some(Object::Reference(id)) => match &map[id] {
            Object::Array(kids) => kids.clone(),
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    };
    kids.iter()
        .flat_map(|kid| match kid {
            Object::Reference(id) => pages_in(map, *id),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn reachable_objects_follow_references_once() {
    let bytes = read("word-pdfmaker-linearized.pdf");
    let doc = Document::parse(&bytes).unwrap();
    let map = doc.reachable().unwrap();
    assert!(type_is(&map[&doc.catalog_id()], b"Catalog"));
    let Some(Object::Reference(root)) = doc.catalog().get(b"Pages") else {
        panic!("no /Pages reference");
    };
    let Some(Object::Dictionary(tree)) = map.get(root) else {
        panic!("page tree root missing");
    };
    let Some(Object::Integer(count)) = tree.get(b"Count") else {
        panic!("no /Count");
    };
    assert_eq!(pages_in(&map, *root).len() as i64, *count);
    assert!(!map.values().any(|o| type_is(o, b"XRef")));

    // Every object lives in an object stream; the page points at a free object 9.
    let built = Pdf::new(Xref::Stream { filter: None })
        .compressed(3, 1, "<< /Type /Catalog /Pages 2 0 R >>")
        .compressed(3, 2, "<< /Type /Pages /Kids [4 0 R] /Count 1 >>")
        .compressed(3, 4, "<< /Type /Page /Parent 2 0 R /Contents 9 0 R >>")
        .build();
    let doc = Document::parse(&built).unwrap();
    let mut ids: Vec<u32> = doc
        .reachable()
        .unwrap()
        .keys()
        .map(|id| id.number)
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, [1, 2, 4]);
}
