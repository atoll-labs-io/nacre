//! Writes the attack corpus of `tests/corpus/attacks/`: each file is `tests/corpus/unsigned.pdf`
//! signed, or given a signature dictionary, with exactly one defect, or signed and then
//! given one revision that is not allowed. It also writes the legitimate later-revision
//! files of `tests/corpus/`, next to that folder.
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
use nacre_pdf::{Dictionary, Document, Object, ObjectId, SignatureSpec};
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

    later_revisions(&dir, &signer);
}

/// The shadow, EAA and SSA cases in `dir`, and the legitimate fills next to it.
fn later_revisions(dir: &Path, signer: &TestSigner) {
    let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();

    // Shadow hide: an empty body of object 6, then the overlay drawn over the text under the
    // same id; after the signature, the xref points 6 back at the empty body.
    let page = with(&object(UNSIGNED, 3), b"Contents", refs(&[4, 6]));
    let (first, at) = append(
        UNSIGNED,
        &[(3, ser(&page)), (6, stream("", b""))],
        &[],
        None,
    );
    let overlay = stream("", b"1 1 1 rg 0 0 595 842 re f");
    let (hidden, _) = append(&first, &[(6, overlay)], &[], None);
    let signed = sign(&hidden, signer, time).unwrap();
    write(
        dir,
        "shadow-hide",
        &append(&signed, &[], &[(6, offset_of(&at, 6))], None).0,
    );

    // Shadow replace: the font of the signed page swapped.
    let signed = sign(UNSIGNED, signer, time).unwrap();
    let font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_vec();
    write(
        dir,
        "shadow-replace",
        &append(&signed, &[(5, font)], &[], None).0,
    );

    // Shadow hide-and-replace: a second catalog and page tree written before signing, both
    // sharing the AcroForm 6, then a trailer whose /Root names that catalog.
    let catalog = with(&object(UNSIGNED, 1), b"AcroForm", Object::Reference(id(6)));
    let shadow = [
        (1, ser(&catalog)),
        (6, b"<< /Fields [] >>".to_vec()),
        (
            7,
            b"<< /Type /Catalog /Pages 8 0 R /AcroForm 6 0 R >>".to_vec(),
        ),
        (8, b"<< /Type /Pages /Kids [9 0 R] /Count 1 >>".to_vec()),
        (
            9,
            b"<< /Type /Page /Parent 8 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 10 0 R >>".to_vec(),
        ),
        (
            10,
            stream("", b"BT /F1 18 Tf 72 760 Td (Shadow document) Tj ET"),
        ),
    ];
    let (prepared, _) = append(UNSIGNED, &shadow, &[], None);
    let signed = sign(&prepared, signer, time).unwrap();
    write(
        dir,
        "shadow-hide-and-replace",
        &append(&signed, &[], &[], Some(7)).0,
    );

    // A page that refers to object 50 while it is free, then 50 defined after signing.
    let page = with(&object(UNSIGNED, 3), b"Contents", refs(&[4, 50]));
    let (prepared, _) = append(UNSIGNED, &[(3, ser(&page))], &[], None);
    let signed = sign(&prepared, signer, time).unwrap();
    let late = stream("", b"BT /F1 18 Tf 72 700 Td (Defined after signing) Tj ET");
    write(
        dir,
        "shadow-late-definition",
        &append(&signed, &[(50, late)], &[], None).0,
    );

    // A stream both in the /DSS and drawn by the page, redefined after signing as if it
    // were a DSS update.
    let catalog = with(&object(UNSIGNED, 1), b"DSS", Object::Reference(id(6)));
    let page = with(&object(UNSIGNED, 3), b"Contents", refs(&[4, 7]));
    let (prepared, _) = append(
        UNSIGNED,
        &[
            (1, ser(&catalog)),
            (3, ser(&page)),
            (6, b"<< /Certs [7 0 R] >>".to_vec()),
            (7, stream("", b"q Q")),
        ],
        &[],
        None,
    );
    let signed = sign(&prepared, signer, time).unwrap();
    let overlay = stream("", b"1 1 1 rg 0 0 595 842 re f");
    write(
        dir,
        "shadow-dss-page",
        &append(&signed, &[(7, overlay)], &[], None).0,
    );

    let form = with_text_field(UNSIGNED);
    let signed = sign(&form, signer, time).unwrap();
    write(dir, "shadow-form-field", &fill(&signed, b"Mallory"));

    // A certified form whose page refers to object 50 while it is free; the fill then
    // defines 50 as the field's appearance, so the page draws it too.
    let page = with(&object(&form, 3), b"Contents", refs(&[4, 50]));
    let (prepared, _) = append(&form, &[(3, ser(&page))], &[], None);
    let certified = certify(&prepared, 2, signer);
    write(
        dir,
        "shadow-fill-late-definition",
        &fill_at(&certified, b"Bob", 50),
    );

    let certified = certify(UNSIGNED, 2, signer);
    write(dir, "eaa-freetext", &free_text(&certified));
    write(dir, "ssa-visible-signature", &sneaky(&certified, signer));
    write(dir, "ssa-split-widget", &sneaky_split(&certified, signer));
    write(
        dir,
        "ssa-empty-field-signed",
        &sneaky_two_steps(&certified, signer),
    );
    ssa_by_effect(dir, &form, signer);
    ssa_by_page(dir, &form, signer);

    let corpus = dir.parent().unwrap();
    write(
        corpus,
        "certified-form-fill",
        &fill(&certify(&form, 2, signer), b"Bob"),
    );
    write(
        corpus,
        "certified-p1-form-fill",
        &fill(&certify(&form, 1, signer), b"Bob"),
    );
    let lock = reference(
        b"FieldMDP",
        &[
            (b"Action", name(b"Include")),
            (
                b"Fields",
                Object::Array(vec![Object::String(b"Name".to_vec())]),
            ),
        ],
    );
    let approved = sign_with(&certify(&form, 2, signer), "Approval", lock, signer);
    write(corpus, "fieldmdp-locked-fill", &fill(&approved, b"Bob"));

    // Not certified: one revision fills the field and adds Bob's invisible signature, as an
    // ordinary signing tool saves it. The fill is refused for Alice, not Bob's signature.
    let alice = sign(&form, signer, time).unwrap();
    let ap = next_free(&alice) + 2;
    write(
        corpus,
        "fill-and-second-signature",
        &add_signature(&alice, signer, "Bob", false, &filled(&alice, b"Bob", ap)),
    );

    // An invisible signature added after a certification that forbids any change.
    write(
        corpus,
        "certified-p1-second-signature",
        &add_signature(&certify(&form, 1, signer), signer, "Late", false, &[]),
    );

    // The certified fill, then a catalog naming a DocMDP signature whose /Reference array is
    // over the reader's cap, then an invisible signature, which only `/P 1` refuses.
    let certified = fill(&certify(&form, 2, signer), b"Bob");
    let doc = Document::parse(&certified).unwrap();
    let root = doc.catalog_id().number;
    let hostile = next_free(&certified);
    let mut perms = Dictionary::new();
    perms.insert(b"DocMDP", Object::Reference(id(hostile)));
    let catalog = with(doc.catalog(), b"Perms", Object::Dictionary(perms));
    let Object::Array(one) = reference(b"DocMDP", &[(b"P", Object::Integer(2))]) else {
        unreachable!()
    };
    let mut sig = Dictionary::new();
    sig.insert(b"Type", name(b"Sig"));
    sig.insert(b"Reference", Object::Array(vec![one[0].clone(); 40]));
    let (capped, _) = append(
        &certified,
        &[(root, ser(&catalog)), (hostile, ser(&sig))],
        &[],
        None,
    );
    write(
        corpus,
        "docmdp-reference-cap",
        &add_signature(&capped, signer, "Late", false, &[]),
    );
}

fn id(number: u32) -> ObjectId {
    ObjectId::new(number, 0)
}

fn refs(numbers: &[u32]) -> Object {
    Object::Array(numbers.iter().map(|n| Object::Reference(id(*n))).collect())
}

/// The dictionary stored under `number` in `pdf`.
fn object(pdf: &[u8], number: u32) -> Dictionary {
    match Document::parse(pdf).unwrap().object(id(number)).unwrap() {
        Object::Dictionary(dict) => dict,
        other => panic!("{number} is {other:?}"),
    }
}

fn with(dict: &Dictionary, key: &[u8], value: Object) -> Dictionary {
    let mut dict = dict.clone();
    dict.insert(key, value);
    dict
}

/// `value` written as PDF syntax; strings in hex. No stream is ever written this way.
fn ser(value: &Dictionary) -> Vec<u8> {
    fn object(out: &mut Vec<u8>, value: &Object) {
        match value {
            Object::Null => out.extend_from_slice(b"null"),
            Object::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            Object::Integer(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Object::Real(r) => out.extend_from_slice(format!("{r:?}").as_bytes()),
            Object::String(bytes) => {
                out.push(b'<');
                for byte in bytes {
                    out.extend_from_slice(format!("{byte:02X}").as_bytes());
                }
                out.push(b'>');
            }
            Object::Name(n) => {
                out.push(b'/');
                out.extend_from_slice(n);
            }
            Object::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b' ');
                    }
                    object(out, item);
                }
                out.push(b']');
            }
            Object::Dictionary(dict) => {
                out.extend_from_slice(b"<<");
                for (key, value) in dict.iter() {
                    out.extend_from_slice(b" /");
                    out.extend_from_slice(key);
                    out.push(b' ');
                    object(out, value);
                }
                out.extend_from_slice(b" >>");
            }
            Object::Reference(id) => {
                out.extend_from_slice(format!("{} {} R", id.number, id.generation).as_bytes())
            }
            Object::Stream(_) => panic!("a stream is not serialized"),
        }
    }
    let mut out = Vec::new();
    object(&mut out, &Object::Dictionary(value.clone()));
    out
}

/// A stream body with `entries` (raw, may be empty) and a correct `/Length`.
fn stream(entries: &str, data: &[u8]) -> Vec<u8> {
    let mut body = format!("<< {entries} /Length {} >>\nstream\n", data.len()).into_bytes();
    body.extend_from_slice(data);
    body.extend_from_slice(b"\nendstream");
    body
}

fn offset_of(offsets: &[(u32, usize)], number: u32) -> usize {
    offsets.iter().find(|(n, _)| *n == number).unwrap().1
}

/// The next object number free in `pdf`, from its trailer's `/Size`.
fn next_free(pdf: &[u8]) -> u32 {
    match Document::parse(pdf).unwrap().trailer().get(b"Size") {
        Some(Object::Integer(n)) => u32::try_from(*n).unwrap(),
        other => panic!("/Size is {other:?}"),
    }
}

/// `base` followed by one revision written by hand: `objects` (number and body, which may
/// redefine an existing object), `redirects` (an entry pointing a number at an offset
/// already in `base`), a classic table and a trailer whose `/Root` is `root` or unchanged.
/// Returns the file and the offset of each object written.
fn append(
    base: &[u8],
    objects: &[(u32, Vec<u8>)],
    redirects: &[(u32, usize)],
    root: Option<u32>,
) -> (Vec<u8>, Vec<(u32, usize)>) {
    let doc = Document::parse(base).unwrap();
    let prev = doc.revisions().last().unwrap().startxref;
    let root = root.unwrap_or(doc.catalog_id().number);
    let mut out = base.to_vec();
    if !matches!(out.last(), Some(b'\n' | b'\r')) {
        out.push(b'\n');
    }
    let mut written = Vec::new();
    for (number, body) in objects {
        written.push((*number, out.len()));
        out.extend_from_slice(format!("{number} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let mut entries: Vec<(u32, usize)> = written.iter().chain(redirects).copied().collect();
    entries.sort_unstable();
    let size = entries
        .iter()
        .map(|(n, _)| n + 1)
        .chain([next_free(base)])
        .max()
        .unwrap();
    let xref_at = out.len();
    out.extend_from_slice(b"xref\n");
    for (number, at) in &entries {
        out.extend_from_slice(format!("{number} 1\n{at:010} 00000 n\r\n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {size} /Prev {prev} /Root {root} 0 R >>\nstartxref\n{xref_at}\n%%EOF\n")
            .as_bytes(),
    );
    (out, written)
}

/// `base` with a filled text field `Name` (object 7, value `Alice`) on page 3, in the
/// AcroForm 6, its appearance in 8.
fn with_text_field(base: &[u8]) -> Vec<u8> {
    let catalog = with(&object(base, 1), b"AcroForm", Object::Reference(id(6)));
    let page = with(&object(base, 3), b"Annots", refs(&[7]));
    let objects = [
        (1, ser(&catalog)),
        (3, ser(&page)),
        (6, b"<< /Fields [7 0 R] >>".to_vec()),
        (
            7,
            b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /V (Alice) /Rect [72 600 300 620] /F 4 /P 3 0 R /AP << /N 8 0 R >> >>".to_vec(),
        ),
        (8, appearance(b"Alice")),
    ];
    append(base, &objects, &[], None).0
}

fn appearance(text: &[u8]) -> Vec<u8> {
    let mut data = b"BT /F1 12 Tf 2 6 Td (".to_vec();
    data.extend_from_slice(text);
    data.extend_from_slice(b") Tj ET");
    stream(
        "/Type /XObject /Subtype /Form /BBox [0 0 228 20] /Resources << /Font << /F1 5 0 R >> >>",
        &data,
    )
}

/// The text field 7 of `pdf` given `value` and a new appearance.
fn fill(pdf: &[u8], value: &[u8]) -> Vec<u8> {
    fill_at(pdf, value, next_free(pdf))
}

/// The same fill, its appearance written as object `ap`.
fn fill_at(pdf: &[u8], value: &[u8], ap: u32) -> Vec<u8> {
    append(pdf, &filled(pdf, value, ap), &[], None).0
}

/// The objects of that fill: the appearance `ap` and the field 7.
fn filled(pdf: &[u8], value: &[u8], ap: u32) -> [(u32, Vec<u8>); 2] {
    let mut n = Dictionary::new();
    n.insert(b"N", Object::Reference(id(ap)));
    let field = with(
        &with(&object(pdf, 7), b"V", Object::String(value.to_vec())),
        b"AP",
        Object::Dictionary(n),
    );
    [(ap, appearance(value)), (7, ser(&field))]
}

/// A signature reference dictionary of `method` with these transform parameters.
fn reference(method: &[u8], params: &[(&[u8], Object)]) -> Object {
    let mut transform = Dictionary::new();
    transform.insert(b"Type", name(b"TransformParams"));
    for (key, value) in params {
        transform.insert(key, value.clone());
    }
    transform.insert(b"V", name(b"1.2"));
    let mut reference = Dictionary::new();
    reference.insert(b"Type", name(b"SigRef"));
    reference.insert(b"TransformMethod", name(method));
    reference.insert(b"TransformParams", Object::Dictionary(transform));
    Object::Array(vec![Object::Dictionary(reference)])
}

/// `pdf` certified at DocMDP level `p`: the catalog's `/Perms` names the signature
/// dictionary the writer allocates first.
fn certify(pdf: &[u8], p: i64, signer: &TestSigner) -> Vec<u8> {
    let mdp = reference(b"DocMDP", &[(b"P", Object::Integer(p))]);
    let sig = next_free(pdf);
    let mut perms = Dictionary::new();
    perms.insert(b"DocMDP", Object::Reference(id(sig)));
    let out = sign_inner(pdf, "Certification", mdp, Some(perms), signer);
    let doc = Document::parse(&out).unwrap();
    assert_eq!(doc.signature_fields().last().unwrap().value, Some(id(sig)));
    assert_eq!(doc.doc_mdp_level().unwrap(), Some(p));
    out
}

/// `pdf` with an approval signature `field` whose dictionary carries `/Reference`.
fn sign_with(pdf: &[u8], field: &str, reference: Object, signer: &TestSigner) -> Vec<u8> {
    sign_inner(pdf, field, reference, None, signer)
}

fn sign_inner(
    pdf: &[u8],
    field: &str,
    reference: Object,
    perms: Option<Dictionary>,
    signer: &TestSigner,
) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let mut update = doc.update();
    if let Some(perms) = perms {
        update.set_catalog(b"Perms", Object::Dictionary(perms));
    }
    let mut spec = spec();
    spec.field = field.into();
    spec.entries.insert(b"Reference", reference);
    let prepared = update.sign(spec).unwrap();
    let mut hasher = Sha256::new();
    for part in prepared.signed_parts() {
        hasher.update(part);
    }
    let cms = sign_detached(&hasher.finalize(), signer, &Profile::PADES, None).unwrap();
    prepared.embed(&cms).unwrap()
}

/// `pdf` with a `/FreeText` annotation added to page 3.
fn free_text(pdf: &[u8]) -> Vec<u8> {
    let annot = next_free(pdf);
    let page = object(pdf, 3);
    let Some(Object::Array(mut annots)) = page.get(b"Annots").cloned() else {
        panic!("page 3 has no direct /Annots");
    };
    annots.push(Object::Reference(id(annot)));
    let body = b"<< /Type /Annot /Subtype /FreeText /Rect [72 650 400 700] /Contents (Approved: 1,000,000 EUR) /DA (/Helv 14 Tf 0 g) /P 3 0 R >>".to_vec();
    let page = with(&page, b"Annots", Object::Array(annots));
    append(pdf, &[(annot, body), (3, ser(&page))], &[], None).0
}

/// `pdf` with a new approval signature whose widget is visible, its appearance drawing
/// over the page, its CMS correct over its own `/ByteRange`.
fn sneaky(pdf: &[u8], signer: &TestSigner) -> Vec<u8> {
    add_signature(pdf, signer, "Sneaky", true, &[])
}

/// `pdf` with a new approval signature `title` in a revision that also writes `extra`. A
/// visible widget takes the next three numbers and draws over the page; an invisible one,
/// the next two. Its CMS is correct over its own `/ByteRange`.
fn add_signature(
    pdf: &[u8],
    signer: &TestSigner,
    title: &str,
    visible: bool,
    extra: &[(u32, Vec<u8>)],
) -> Vec<u8> {
    let sig = next_free(pdf);
    let (ap, field) = if visible {
        (sig + 1, sig + 2)
    } else {
        (0, sig + 1)
    };
    let mut objects = vec![(sig, sig_placeholder())];
    let widget = if visible {
        objects.push((ap, overlay_appearance()));
        format!(
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T ({title}) /V {sig} 0 R /Rect [72 650 400 700] /F 4 /P 3 0 R /AP << /N {ap} 0 R >> >>"
        )
    } else {
        format!(
            "<< /Type /Annot /Subtype /Widget /FT /Sig /T ({title}) /V {sig} 0 R /Rect [0 0 0 0] /F 132 /P 3 0 R >>"
        )
    };
    objects.push((field, widget.into_bytes()));
    objects.extend(register(pdf, field, field));
    objects.extend_from_slice(extra);
    let (out, _) = append(pdf, &objects, &[], None);
    seal(out, signer)
}

/// `pdf` with a new approval signature `Sneaky` whose field and visible widget are separate
/// objects: the field, in `/Fields`, has the widget as its only kid, which the page lists.
fn sneaky_split(pdf: &[u8], signer: &TestSigner) -> Vec<u8> {
    let sig = next_free(pdf);
    let (ap, widget, field) = (sig + 1, sig + 2, sig + 3);
    let mut objects = vec![
        (sig, sig_placeholder()),
        (ap, overlay_appearance()),
        (
            widget,
            format!(
                "<< /Type /Annot /Subtype /Widget /Parent {field} 0 R /Rect [72 650 400 700] /F 4 /P 3 0 R /AP << /N {ap} 0 R >> >>"
            )
            .into_bytes(),
        ),
        (
            field,
            format!("<< /FT /Sig /T (Sneaky) /V {sig} 0 R /Kids [{widget} 0 R] >>").into_bytes(),
        ),
    ];
    objects.extend(register(pdf, field, widget));
    let (out, _) = append(pdf, &objects, &[], None);
    seal(out, signer)
}

/// `pdf` given an empty visible signature field `Sneaky` in one revision, then signed in it
/// by the next.
fn sneaky_two_steps(pdf: &[u8], signer: &TestSigner) -> Vec<u8> {
    let ap = next_free(pdf);
    let field = ap + 1;
    let mut objects = vec![
        (ap, overlay_appearance()),
        (
            field,
            format!(
                "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Sneaky) /Rect [72 650 400 700] /F 4 /P 3 0 R /AP << /N {ap} 0 R >> >>"
            )
            .into_bytes(),
        ),
    ];
    objects.extend(register(pdf, field, field));
    let (prepared, _) = append(pdf, &objects, &[], None);

    let sig = next_free(&prepared);
    let signed = with(&object(&prepared, field), b"V", Object::Reference(id(sig)));
    let (out, _) = append(
        &prepared,
        &[(sig, sig_placeholder()), (field, ser(&signed))],
        &[],
        None,
    );
    seal(out, signer)
}

/// The sneaky signature shapes in which a signature field present in the certified state
/// is made to show only while being signed, and the honest signing of a field the
/// certified state already placed on the page.
fn ssa_by_effect(dir: &Path, form: &[u8], signer: &TestSigner) {
    let n = next_free(form);

    let base = prepared(
        form,
        &[(n, merged_sig("Sneaky", "/Rect [0 0 0 0] /F 4"))],
        n,
        n,
    );
    let certified = certify(&base, 2, signer);
    let sig = next_free(&certified);
    let field = edited(
        &certified,
        n,
        &[
            (b"V", Object::Reference(id(sig))),
            (b"Rect", rect()),
            (b"AP", ap(sig + 1)),
        ],
    );
    write(
        dir,
        "ssa-zero-rect-shown",
        &sign_prepared(
            &certified,
            signer,
            &[(sig + 1, overlay_appearance()), (n, field)],
            sig,
        ),
    );

    let hidden = format!("/Rect [72 650 400 700] /F 6 /AP << /N {} 0 R >>", n + 1);
    let base = prepared(
        form,
        &[
            (n + 1, overlay_appearance()),
            (n, merged_sig("Sneaky", &hidden)),
        ],
        n,
        n,
    );
    let certified = certify(&base, 3, signer);
    let sig = next_free(&certified);
    let field = edited(
        &certified,
        n,
        &[
            (b"V", Object::Reference(id(sig))),
            (b"F", Object::Integer(4)),
        ],
    );
    write(
        dir,
        "ssa-hidden-widget-shown",
        &sign_prepared(&certified, signer, &[(n, field)], sig),
    );

    let (r, f) = (n, n + 1);
    let indirect = format!("/Rect {r} 0 R /F 4");
    let base = prepared(
        form,
        &[
            (r, b"[0 0 0 0]".to_vec()),
            (f, merged_sig("Sneaky", &indirect)),
        ],
        f,
        f,
    );
    let certified = certify(&base, 2, signer);
    let sig = next_free(&certified);
    let field = edited(
        &certified,
        f,
        &[(b"V", Object::Reference(id(sig))), (b"AP", ap(sig + 1))],
    );
    write(
        dir,
        "ssa-indirect-rect",
        &sign_prepared(
            &certified,
            signer,
            &[
                (sig + 1, overlay_appearance()),
                (r, b"[72 650 400 700]".to_vec()),
                (f, field),
            ],
            sig,
        ),
    );

    let (w, f) = (n, n + 1);
    let base = prepared(
        form,
        &[
            (
                w,
                format!(
                    "<< /Type /Annot /Subtype /Widget /Parent {f} 0 R /Rect [0 0 0 0] /F 4 /P 3 0 R >>"
                )
                .into_bytes(),
            ),
            (
                f,
                format!("<< /FT /Sig /T (Sneaky) /Kids [{w} 0 R] >>").into_bytes(),
            ),
        ],
        f,
        w,
    );
    let certified = certify(&base, 2, signer);
    let sig = next_free(&certified);
    let widget = edited(&certified, w, &[(b"Rect", rect()), (b"AP", ap(sig + 1))]);
    let field = edited(&certified, f, &[(b"V", Object::Reference(id(sig)))]);
    write(
        dir,
        "ssa-kid-widget-shown",
        &sign_prepared(
            &certified,
            signer,
            &[(sig + 1, overlay_appearance()), (w, widget), (f, field)],
            sig,
        ),
    );

    let base = prepared(
        form,
        &[(n, merged_sig("Approver", "/Rect [72 650 400 700] /F 4"))],
        n,
        n,
    );
    let certified = certify(&base, 2, signer);
    let sig = next_free(&certified);
    let field = edited(
        &certified,
        n,
        &[
            (b"V", Object::Reference(id(sig))),
            (b"AP", ap(sig + 1)),
            (b"F", Object::Integer(132)),
        ],
    );
    write(
        dir.parent().unwrap(),
        "certified-visible-field-signed",
        &sign_prepared(
            &certified,
            signer,
            &[(sig + 1, overlay_appearance()), (n, field)],
            sig,
        ),
    );
}

/// The sneaky signature shapes in which what the page draws, not the field's own entries,
/// makes a signature show, a signature whose rectangle cannot be read, and a placed field
/// whose rectangle moves while it is signed.
fn ssa_by_page(dir: &Path, form: &[u8], signer: &TestSigner) {
    let certified = certify(form, 2, signer);

    // A widget whose `/Parent` is the invisible merged field, listed by the page only.
    let sig = next_free(&certified);
    let (look, widget, field) = (sig + 1, sig + 2, sig + 3);
    let mut objects = vec![
        (sig, sig_placeholder()),
        (look, overlay_appearance()),
        (
            widget,
            format!(
                "<< /Type /Annot /Subtype /Widget /Parent {field} 0 R /Rect [72 650 400 700] /F 4 /P 3 0 R /AP << /N {look} 0 R >> >>"
            )
            .into_bytes(),
        ),
        (
            field,
            merged_sig("Sneaky", &format!("/V {sig} 0 R /Rect [0 0 0 0] /F 132")),
        ),
    ];
    objects.extend(register_all(&certified, field, &[field, widget]));
    write(
        dir,
        "ssa-orphan-widget",
        &seal(append(&certified, &objects, &[], None).0, signer),
    );

    // A visible merged signature that only the page lists, outside `/Fields`.
    let sig = next_free(&certified);
    let (look, field) = (sig + 1, sig + 2);
    let page = object(&certified, 3);
    let Some(Object::Array(mut annots)) = page.get(b"Annots").cloned() else {
        panic!("page 3 has no direct /Annots");
    };
    annots.push(Object::Reference(id(field)));
    let objects = [
        (sig, sig_placeholder()),
        (look, overlay_appearance()),
        (
            field,
            merged_sig(
                "Sneaky",
                &format!("/V {sig} 0 R /Rect [72 650 400 700] /F 4 /AP << /N {look} 0 R >>"),
            ),
        ),
        (3, ser(&with(&page, b"Annots", Object::Array(annots)))),
    ];
    write(
        dir,
        "ssa-outside-fields",
        &seal(append(&certified, &objects, &[], None).0, signer),
    );

    // A visible merged signature whose `/Rect` cannot be read: one item refers to an
    // object the file never defines.
    let sig = next_free(&certified);
    let (look, field) = (sig + 1, sig + 2);
    let missing = sig + 3;
    let mut objects = vec![
        (sig, sig_placeholder()),
        (look, overlay_appearance()),
        (
            field,
            merged_sig(
                "Sneaky",
                &format!(
                    "/V {sig} 0 R /Rect [72 650 400 {missing} 0 R] /F 4 /AP << /N {look} 0 R >>"
                ),
            ),
        ),
    ];
    objects.extend(register(&certified, field, field));
    write(
        dir,
        "ssa-unreadable-rect",
        &seal(append(&certified, &objects, &[], None).0, signer),
    );

    // A visible merged signature flagged NoView and ToggleNoView, so it shows on hover.
    let sig = next_free(&certified);
    let (look, field) = (sig + 1, sig + 2);
    let mut objects = vec![
        (sig, sig_placeholder()),
        (look, overlay_appearance()),
        (
            field,
            merged_sig(
                "Sneaky",
                &format!("/V {sig} 0 R /Rect [72 650 400 700] /F 292 /AP << /N {look} 0 R >>"),
            ),
        ),
    ];
    objects.extend(register(&certified, field, field));
    write(
        dir,
        "ssa-toggle-noview-shown",
        &seal(append(&certified, &objects, &[], None).0, signer),
    );

    let n = next_free(form);

    // A placed field the page does not list in the certified state, listed while signed.
    let mut objects = vec![(n, merged_sig("Sneaky", "/Rect [72 650 400 700] /F 4"))];
    objects.extend(register_all(form, n, &[]));
    let certified = certify(&append(form, &objects, &[], None).0, 2, signer);
    let sig = next_free(&certified);
    let field = edited(
        &certified,
        n,
        &[(b"V", Object::Reference(id(sig))), (b"AP", ap(sig + 1))],
    );
    let page = object(&certified, 3);
    let Some(Object::Array(mut annots)) = page.get(b"Annots").cloned() else {
        panic!("page 3 has no direct /Annots");
    };
    annots.push(Object::Reference(id(n)));
    write(
        dir,
        "ssa-unlisted-widget-shown",
        &sign_prepared(
            &certified,
            signer,
            &[
                (sig + 1, overlay_appearance()),
                (3, ser(&with(&page, b"Annots", Object::Array(annots)))),
                (n, field),
            ],
            sig,
        ),
    );

    // A placed field with its appearance, in an optional content group the document's
    // default configuration turns off; signing takes it out of the group.
    let (g, ap_n, f) = (n, n + 1, n + 2);
    let mut layers = Dictionary::new();
    layers.insert(b"OCGs", refs(&[g]));
    let mut off = Dictionary::new();
    off.insert(b"OFF", refs(&[g]));
    layers.insert(b"D", Object::Dictionary(off));
    let catalog = with(
        &object(form, 1),
        b"OCProperties",
        Object::Dictionary(layers),
    );
    let entries = format!("/Rect [72 650 400 700] /F 4 /AP << /N {ap_n} 0 R >>");
    let base = prepared(
        form,
        &[
            (1, ser(&catalog)),
            (g, b"<< /Type /OCG /Name (Layer) >>".to_vec()),
            (ap_n, overlay_appearance()),
            (f, merged_sig("Sneaky", &format!("{entries} /OC {g} 0 R"))),
        ],
        f,
        f,
    );
    let certified = certify(&base, 2, signer);
    let sig = next_free(&certified);
    write(
        dir,
        "ssa-layer-widget-shown",
        &sign_prepared(
            &certified,
            signer,
            &[(f, merged_sig("Sneaky", &format!("{entries} /V {sig} 0 R")))],
            sig,
        ),
    );

    // A field placed in the certified state, signed with its rectangle moved.
    let base = prepared(
        form,
        &[(n, merged_sig("Sneaky", "/Rect [72 650 400 700] /F 4"))],
        n,
        n,
    );
    let certified = certify(&base, 2, signer);
    let sig = next_free(&certified);
    let field = edited(
        &certified,
        n,
        &[
            (b"V", Object::Reference(id(sig))),
            (b"AP", ap(sig + 1)),
            (
                b"Rect",
                Object::Array([72, 100, 400, 150].map(Object::Integer).to_vec()),
            ),
        ],
    );
    write(
        dir,
        "ssa-moved-rect",
        &sign_prepared(
            &certified,
            signer,
            &[(sig + 1, overlay_appearance()), (n, field)],
            sig,
        ),
    );
}

/// An empty signature field `title` merged with its widget on page 3, with `entries`.
fn merged_sig(title: &str, entries: &str) -> Vec<u8> {
    format!("<< /Type /Annot /Subtype /Widget /FT /Sig /T ({title}) {entries} /P 3 0 R >>")
        .into_bytes()
}

/// `base` given `objects` and `field` registered, its widget `widget` on page 3, in one
/// revision.
fn prepared(base: &[u8], objects: &[(u32, Vec<u8>)], field: u32, widget: u32) -> Vec<u8> {
    let mut objects = objects.to_vec();
    objects.extend(register(base, field, widget));
    append(base, &objects, &[], None).0
}

/// `pdf` signed in a field it already has: one revision writing the signature dictionary
/// `sig` and `edits`, then sealed.
fn sign_prepared(pdf: &[u8], signer: &TestSigner, edits: &[(u32, Vec<u8>)], sig: u32) -> Vec<u8> {
    let mut objects = vec![(sig, sig_placeholder())];
    objects.extend_from_slice(edits);
    seal(append(pdf, &objects, &[], None).0, signer)
}

/// The dictionary `number` of `pdf` with `entries` set, serialized.
fn edited(pdf: &[u8], number: u32, entries: &[(&[u8], Object)]) -> Vec<u8> {
    let mut dict = object(pdf, number);
    for (key, value) in entries {
        dict.insert(key, value.clone());
    }
    ser(&dict)
}

fn rect() -> Object {
    Object::Array([72, 650, 400, 700].map(Object::Integer).to_vec())
}

/// An appearance dictionary whose normal appearance is `number`.
fn ap(number: u32) -> Object {
    let mut n = Dictionary::new();
    n.insert(b"N", Object::Reference(id(number)));
    Object::Dictionary(n)
}

/// The AcroForm of `pdf` with `field` added to its `/Fields`, and page 3 with `widget` added
/// to its `/Annots`.
fn register(pdf: &[u8], field: u32, widget: u32) -> [(u32, Vec<u8>); 2] {
    register_all(pdf, field, &[widget])
}

/// The AcroForm of `pdf` with `field` added to its `/Fields`, and page 3 with `widgets`
/// added to its `/Annots`.
fn register_all(pdf: &[u8], field: u32, widgets: &[u32]) -> [(u32, Vec<u8>); 2] {
    let doc = Document::parse(pdf).unwrap();
    let Some(Object::Reference(form_id)) = doc.catalog().get(b"AcroForm").cloned() else {
        panic!("no indirect AcroForm");
    };
    let form = object(pdf, form_id.number);
    let Some(Object::Array(mut fields)) = form.get(b"Fields").cloned() else {
        panic!("no direct /Fields");
    };
    fields.push(Object::Reference(id(field)));
    let form = with(&form, b"Fields", Object::Array(fields));
    let page = object(pdf, 3);
    let Some(Object::Array(mut annots)) = page.get(b"Annots").cloned() else {
        panic!("page 3 has no direct /Annots");
    };
    annots.extend(widgets.iter().map(|w| Object::Reference(id(*w))));
    let page = with(&page, b"Annots", Object::Array(annots));
    [(form_id.number, ser(&form)), (3, ser(&page))]
}

/// A signature dictionary whose `/ByteRange` and `/Contents` `seal` fills.
fn sig_placeholder() -> Vec<u8> {
    let mut body = b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M (D:20261022080000Z) /ByteRange [0 0000000000 0000000000 0000000000] /Contents <".to_vec();
    body.resize(body.len() + 2 * CAPACITY, b'0');
    body.extend_from_slice(b"> >>");
    body
}

/// An appearance that whites out part of the page and writes over it.
fn overlay_appearance() -> Vec<u8> {
    stream(
        "/Type /XObject /Subtype /Form /BBox [0 0 328 50] /Resources << /Font << /F1 5 0 R >> >>",
        b"1 1 1 rg 0 0 328 50 re f 0 g BT /F1 14 Tf 4 20 Td (Approved: 1,000,000 EUR) Tj ET",
    )
}

/// Fills the last `/ByteRange` placeholder of `pdf` and the `/Contents` after it.
fn seal(mut pdf: Vec<u8>, signer: &TestSigner) -> Vec<u8> {
    let key = b"/ByteRange [0 0000000000 0000000000 0000000000]";
    let at = pdf.windows(key.len()).rposition(|w| w == key).unwrap();
    let open = at + pdf[at..].iter().position(|&b| b == b'<').unwrap();
    let after = open + 2 * CAPACITY + 2;
    let range = format!(
        "/ByteRange [0 {open:010} {after:010} {:010}]",
        pdf.len() - after
    );
    assert_eq!(range.len(), key.len());
    pdf[at..at + key.len()].copy_from_slice(range.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(&pdf[..open]);
    hasher.update(&pdf[after..]);
    let cms = sign_detached(&hasher.finalize(), signer, &Profile::PADES, None).unwrap();
    let hex: String = cms.iter().map(|byte| format!("{byte:02X}")).collect();
    pdf[open + 1..open + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    pdf
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
    let pages_id = ObjectId::new(content.number + 2, 0);

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
