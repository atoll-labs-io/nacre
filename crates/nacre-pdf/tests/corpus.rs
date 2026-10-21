#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_pdf::{Document, Object, XrefKind};

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
    ("certified-dss.pdf", &[127672, 152955], &[T, T]),
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
            "certified-dss.pdf",
            &[("signature-test", true), ("signature-test2", false)],
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
