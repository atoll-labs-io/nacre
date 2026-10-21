#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use nacre_pdf::{Dictionary, Document, Error, Object, ObjectId, SignatureSpec, XrefKind};

const FILES: [&str; 10] = [
    "word-hybrid.pdf",
    "word-pdfmaker-linearized.pdf",
    "libreoffice-pdfa3.pdf",
    "chrome-print.pdf",
    "firefox-print.pdf",
    "ghostscript-pdfa2.pdf",
    "form-xfa-irs-w9.pdf",
    "signed-twice-pyhanko.pdf",
    "signed-lta-pyhanko.pdf",
    "certified-dss.pdf",
];

fn real(name: &str) -> Vec<u8> {
    support::corpus(&format!("real/{name}"))
}

fn name(n: &str) -> Object {
    Object::Name(n.as_bytes().to_vec())
}

/// The catalog's entries other than `skip`.
fn catalog_without(doc: &Document<'_>, skip: &[u8]) -> Vec<(Vec<u8>, Object)> {
    doc.catalog()
        .iter()
        .filter(|(k, _)| *k != skip)
        .map(|(k, v)| (k.to_vec(), v.clone()))
        .collect()
}

fn plain_revision(original: &[u8]) -> (Vec<u8>, ObjectId, Dictionary, ObjectId) {
    let doc = Document::parse(original).unwrap();
    let mut update = doc.update();
    let mut dict = Dictionary::new();
    dict.insert(b"Nacre", Object::String(b"plain (revision)".to_vec()));
    dict.insert(b"Scale", Object::Real(1.0));
    let dict_id = update.add(Object::Dictionary(dict.clone())).unwrap();
    let mut stream_dict = Dictionary::new();
    stream_dict.insert(b"Type", name("NacreData"));
    let stream_id = update
        .add_stream(stream_dict, b"stream data\nendstream inside\n".to_vec())
        .unwrap();
    update.set_catalog(b"NacreTest", Object::Reference(stream_id));
    (update.finish().unwrap(), dict_id, dict, stream_id)
}

#[test]
fn every_corpus_file_takes_a_plain_revision() {
    for file in FILES {
        let original = real(file);
        let before = Document::parse(&original).unwrap();
        let (out, dict_id, dict, stream_id) = plain_revision(&original);
        assert!(out.starts_with(&original), "{file}");

        let after = Document::parse(&out).unwrap_or_else(|e| panic!("{file}: {e}"));
        let old: Vec<usize> = before.revisions().iter().map(|r| r.end).collect();
        let new: Vec<usize> = after.revisions().iter().map(|r| r.end).collect();
        assert_eq!(new.len(), old.len() + 1, "{file}");
        assert_eq!(new[..old.len()], old[..], "{file}");
        let want = match before.revisions().last().unwrap().xref {
            XrefKind::Stream => XrefKind::Stream,
            XrefKind::Table | XrefKind::Hybrid => XrefKind::Table,
        };
        assert_eq!(after.revisions().last().unwrap().xref, want, "{file}");

        assert_eq!(
            after.catalog().get(b"NacreTest"),
            Some(&Object::Reference(stream_id)),
            "{file}"
        );
        assert_eq!(
            catalog_without(&after, b"NacreTest"),
            catalog_without(&before, b"NacreTest"),
            "{file}"
        );
        assert_eq!(
            after.signature_fields(),
            before.signature_fields(),
            "{file}"
        );
        assert_eq!(
            after.object(dict_id).unwrap(),
            Object::Dictionary(dict.clone()),
            "{file}"
        );
        let Object::Stream(stream) = after.object(stream_id).unwrap() else {
            panic!("{file}: not a stream");
        };
        assert_eq!(stream.dict.get(b"Type"), Some(&name("NacreData")), "{file}");
        assert_eq!(
            &out[stream.data], b"stream data\nendstream inside\n",
            "{file}"
        );
    }
}

fn spec(field: &str, contents_len: usize) -> SignatureSpec {
    SignatureSpec {
        field: field.to_owned(),
        sub_filter: b"ETSI.CAdES.detached".to_vec(),
        contents_len,
        entries: Dictionary::new(),
    }
}

fn dict(value: Object) -> Dictionary {
    match value {
        Object::Dictionary(d) => d,
        other => panic!("not a dictionary: {other:?}"),
    }
}

/// Follows one level of reference, as the writer's hooks may leave one.
fn resolve(doc: &Document<'_>, value: &Object) -> Object {
    match value {
        Object::Reference(id) => doc.object(*id).unwrap(),
        other => other.clone(),
    }
}

#[test]
fn every_corpus_file_takes_a_signature_slot() {
    const LEN: usize = 8192;
    for file in FILES {
        let original = real(file);
        let before = Document::parse(&original).unwrap();
        let prepared = before.update().sign(spec("Nacre1", LEN)).unwrap();
        let out = prepared.embed(&[]).unwrap();
        assert!(out.starts_with(&original), "{file}");

        let after = Document::parse(&out).unwrap_or_else(|e| panic!("{file}: {e}"));
        let fields = after.signature_fields();
        assert_eq!(fields.len(), before.signature_fields().len() + 1, "{file}");
        assert_eq!(
            &fields[..fields.len() - 1],
            before.signature_fields(),
            "{file}"
        );
        let field = fields.last().unwrap();
        assert_eq!(field.name, "Nacre1", "{file}");
        assert_eq!(
            catalog_without(&after, b"AcroForm"),
            catalog_without(&before, b"AcroForm"),
            "{file}"
        );

        let sig = dict(after.object(field.value.unwrap()).unwrap());
        assert_eq!(sig.get(b"Type"), Some(&name("Sig")), "{file}");
        assert_eq!(sig.get(b"Filter"), Some(&name("Adobe.PPKLite")), "{file}");
        assert_eq!(
            sig.get(b"SubFilter"),
            Some(&name("ETSI.CAdES.detached")),
            "{file}"
        );
        assert_eq!(
            sig.get(b"Contents"),
            Some(&Object::String(vec![0; LEN])),
            "{file}"
        );
        let Some(Object::Array(range)) = sig.get(b"ByteRange") else {
            panic!("{file}: no /ByteRange");
        };
        let range: Vec<usize> = range
            .iter()
            .map(|n| match n {
                Object::Integer(n) => usize::try_from(*n).unwrap(),
                other => panic!("{file}: {other:?}"),
            })
            .collect();
        let [zero, a, b, c] = range[..] else {
            panic!("{file}: {range:?}");
        };
        assert_eq!([zero, a, b, c], prepared.byte_range(), "{file}");
        assert_eq!((zero, c), (0, out.len() - b), "{file}");
        assert_eq!(b - a, 2 * LEN + 2, "{file}");
        assert_eq!(out[a], b'<', "{file}");
        assert_eq!(out[b - 1], b'>', "{file}");
        assert!(out[a + 1..b - 1].iter().all(|d| *d == b'0'), "{file}");

        let widget = dict(after.object(field.id).unwrap());
        let Some(Object::Reference(page_id)) = widget.get(b"P") else {
            panic!("{file}: no /P");
        };
        let page = dict(after.object(*page_id).unwrap());
        assert_eq!(page.get(b"Type"), Some(&name("Page")), "{file}");
        let Object::Array(annots) = resolve(&after, page.get(b"Annots").unwrap()) else {
            panic!("{file}: /Annots is not an array");
        };
        assert!(annots.contains(&Object::Reference(field.id)), "{file}");
    }
}

fn without(bytes: &[u8], a: usize, b: usize) -> Vec<u8> {
    [&bytes[..a], &bytes[b..]].concat()
}

#[test]
fn signed_parts_are_the_file_minus_contents() {
    for file in ["chrome-print.pdf", "ghostscript-pdfa2.pdf"] {
        let original = real(file);
        let doc = Document::parse(&original).unwrap();
        let prepared = doc.update().sign(spec("Nacre1", 512)).unwrap();
        let [_, a, b, _] = prepared.byte_range();
        let parts = prepared.signed_parts().concat();

        let blank = prepared.embed(&[]).unwrap();
        assert_eq!(parts, without(&blank, a, b), "{file}");

        let der = vec![0xAB; 300];
        let signed = prepared.embed(&der).unwrap();
        assert_eq!(signed.len(), blank.len(), "{file}");
        assert_eq!(parts, without(&signed, a, b), "{file}");
        let mut slot = b"<".to_vec();
        slot.extend(b"AB".repeat(300));
        slot.extend(vec![b'0'; 2 * (512 - 300)]);
        slot.push(b'>');
        assert_eq!(&signed[a..b], &slot[..], "{file}");
        Document::parse(&signed).unwrap_or_else(|e| panic!("{file}: {e}"));
    }
}

#[test]
fn oversized_signature_is_refused_whole() {
    let original = real("chrome-print.pdf");
    let doc = Document::parse(&original).unwrap();
    let prepared = doc.update().sign(spec("Nacre1", 64)).unwrap();
    let range = prepared.byte_range();
    let parts = prepared.signed_parts().concat();

    let err = prepared.embed(&[0x01; 65]).unwrap_err();
    assert!(
        matches!(
            err,
            Error::SignatureTooLarge {
                len: 65,
                capacity: 64
            }
        ),
        "{err:?}"
    );
    assert_eq!(prepared.byte_range(), range);
    assert_eq!(prepared.signed_parts().concat(), parts);

    let full = prepared.embed(&[0xCD; 64]).unwrap();
    let [_, a, b, _] = range;
    assert_eq!(&full[a + 1..b - 1], "CD".repeat(64).as_bytes());
}

#[test]
fn no_change_certification_refuses_a_signature() {
    let original = support::revision::certified_no_changes();
    let doc = Document::parse(&original).unwrap();

    let err = doc.update().sign(spec("Nacre1", 64)).unwrap_err();
    assert!(matches!(err, Error::CertifiedNoChanges), "{err:?}");

    let plain = doc.update().finish().unwrap();
    Document::parse(&plain).unwrap();

    let mut timestamp = spec("Nacre1", 64);
    timestamp.entries.insert(b"Type", name("DocTimeStamp"));
    let out = doc.update().sign(timestamp).unwrap().embed(&[]).unwrap();
    let after = Document::parse(&out).unwrap();
    assert_eq!(after.signature_fields().last().unwrap().name, "Nacre1");
}

#[test]
fn taken_field_name_is_refused() {
    let original = real("certified-dss.pdf");
    let doc = Document::parse(&original).unwrap();
    let err = doc.update().sign(spec("signature-test2", 64)).unwrap_err();
    assert!(
        matches!(&err, Error::DuplicateField { name } if name == "signature-test2"),
        "{err:?}"
    );
}

#[test]
fn reserved_entry_is_refused() {
    let original = real("chrome-print.pdf");
    let doc = Document::parse(&original).unwrap();
    let mut with_contents = spec("Nacre1", 64);
    with_contents
        .entries
        .insert(b"Contents", Object::String(vec![1, 2, 3]));
    let err = doc.update().sign(with_contents).unwrap_err();
    assert!(
        matches!(&err, Error::ReservedEntry { key } if key == "Contents"),
        "{err:?}"
    );
}

#[test]
fn page_tree_loop_is_refused() {
    let original = support::revision::page_tree_loop();
    let doc = Document::parse(&original).unwrap();
    let err = doc.update().sign(spec("Nacre1", 64)).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Limit {
                what: "page tree depth",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn field_joins_every_acroform_shape() {
    use support::revision::{direct_acroform, indirect_annots, indirect_fields};
    // Each case: the file, and the indirect array (if any) that must now list the field.
    let cases: [(&str, Vec<u8>, Option<ObjectId>); 3] = [
        ("direct_acroform", direct_acroform(), None),
        (
            "indirect_fields",
            indirect_fields(),
            Some(ObjectId::new(5, 0)),
        ),
        (
            "indirect_annots",
            indirect_annots(),
            Some(ObjectId::new(6, 0)),
        ),
    ];
    for (case, original, array) in cases {
        let before = Document::parse(&original).unwrap();
        let out = before
            .update()
            .sign(spec("Nacre1", 64))
            .unwrap()
            .embed(&[])
            .unwrap();
        let after = Document::parse(&out).unwrap_or_else(|e| panic!("{case}: {e}"));
        let field = after.signature_fields().last().unwrap();
        assert_eq!(field.name, "Nacre1", "{case}");
        if let Some(array) = array {
            let Object::Array(items) = after.object(array).unwrap() else {
                panic!("{case}: {array} is not an array");
            };
            assert_eq!(items, vec![Object::Reference(field.id)], "{case}");
        }
        let page = dict(after.object(ObjectId::new(3, 0)).unwrap());
        let Object::Array(annots) = resolve(&after, page.get(b"Annots").unwrap()) else {
            panic!("{case}: /Annots is not an array");
        };
        assert_eq!(annots, vec![Object::Reference(field.id)], "{case}");
    }
}

/// Writes `bytes` under the target's temporary folder and runs `qpdf --check` on it.
fn qpdf_check(label: &str, bytes: &[u8]) {
    let path = format!("{}/s05-{label}.pdf", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&path, bytes).unwrap();
    let output = std::process::Command::new("qpdf")
        .arg("--check")
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("qpdf could not run: {e}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && !stdout.contains("WARNING") && !stderr.contains("WARNING"),
        "{label}: {}\n{stdout}\n{stderr}",
        output.status
    );
}

#[test]
#[ignore = "conformance"]
fn qpdf_check_is_clean() {
    // A fictitious DER: a SEQUENCE header and filler, never parsed by qpdf.
    let mut der = vec![0x30, 0x82, 0x01, 0x28];
    der.resize(300, 0x5A);
    for file in FILES {
        let original = real(file);
        let (plain, ..) = plain_revision(&original);
        qpdf_check(&format!("plain-{file}"), &plain);
        let doc = Document::parse(&original).unwrap();
        let prepared = doc.update().sign(spec("Nacre1", 8192)).unwrap();
        qpdf_check(&format!("signed-{file}"), &prepared.embed(&der).unwrap());
    }
}
