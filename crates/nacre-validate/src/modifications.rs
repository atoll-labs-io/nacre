//! DSS 6.5.1's two format checks on a signature followed by later revisions, read in its
//! bytecode: the signed and the last revision hold the same root `/Pages` `/Count`
//! (`PdfPageDifference`), and the signature field holds the same `/V`, `/Rect`, `/AP` and
//! `/F` in both, compared deeply with DSS's exclusions (`PdfSignatureDictionary`). Both
//! apply under every policy (ADR-0026).

use std::collections::{HashMap, HashSet};

use nacre_pdf::{Dictionary, Document, Object, ObjectId, ReadOptions};

use crate::Defect;

/// DSS's own depth bound on the comparison.
const MAX_DEPTH: usize = 500;
/// Bounds the pairs one comparison walks, for the cost of a hostile file only; reaching it
/// counts as a change. A pair identical on both sides and holding no reference counts once,
/// however large (a font's `/Widths`), so only the references a field reaches and the
/// direct objects around them add up: no field of the repository's PDF files walks more than
/// 20, and a Type 3 font in an appearance adds two per glyph.
const MAX_PAIRS: usize = 65_536;
/// The keys of the signed-revision field DSS compares.
const FIELD_KEYS: [&[u8]; 4] = [b"V", b"Rect", b"AP", b"F"];
/// A modification whose last key is one of these is tolerated.
const TOLERATED_KEYS: [&[u8]; 3] = [b"F", b"Type", b"ITXT"];

pub(crate) type Objects = HashMap<ObjectId, Object>;

const NULL: Object = Object::Null;

/// The defect DSS's checks give the signature `value` of the field named `field`, whose
/// signed bytes end at `end`, `last` being the document as of its last revision and
/// `last_objects` what [`Document::reachable`] read of it, `None` when that read failed.
/// `None` when the signed bytes end the file or their revision cannot be read. An object
/// of the last revision that cannot be read is never a reason to skip the checks: it reads
/// as `null` in the page count, as PDFBox's lenient reading does, and the field comparison
/// counts it as a change.
pub(crate) fn changed_since(
    last: &Document<'_>,
    last_objects: Option<&Objects>,
    pdf: &[u8],
    end: usize,
    field: &str,
    value: ObjectId,
    options: &ReadOptions,
) -> Option<Defect> {
    if end >= pdf.len() {
        return None;
    }
    let signed = Document::parse_with_options(pdf.get(..end)?, options).ok()?;
    let signed_objects = signed.reachable().ok()?;

    let before = page_count(signed.catalog(), |id| signed_objects.get(&id).cloned());
    let after = page_count(last.catalog(), |id| last.object(id).ok());
    if before != after {
        return Some(Defect::PageCountChanged {
            signed: before,
            last: after,
        });
    }

    let last_field = last
        .signature_fields()
        .iter()
        .find(|f| f.name == field && f.value == Some(value))?;
    let Some(last_objects) = last_objects else {
        return Some(Defect::SignatureDictionaryChanged);
    };
    let last_field = field_dict(last_objects, last_field.id)?;
    let changed = match signed.signature_fields().iter().find(|f| f.name == field) {
        Some(signed_field) => match field_dict(&signed_objects, signed_field.id) {
            Some(signed_field) => {
                field_changed(&signed_objects, last_objects, pdf, signed_field, last_field)
            }
            None => true,
        },
        None => true,
    };
    changed.then_some(Defect::SignatureDictionaryChanged)
}

/// The root `/Pages` `/Count` as PDFBox reads it: an integer as is, a real truncated,
/// anything else or nothing as 0. `object` gives the object stored under an id, `None`
/// standing for `null`.
fn page_count(catalog: &Dictionary, object: impl Fn(ObjectId) -> Option<Object>) -> i64 {
    let resolve = |value: Option<&Object>| -> Option<Object> {
        let mut value = value?.clone();
        for _ in 0..MAX_DEPTH {
            match value {
                Object::Reference(id) => value = object(id)?,
                direct => return Some(direct),
            }
        }
        None
    };
    let Some(Object::Dictionary(pages)) = resolve(catalog.get(b"Pages")) else {
        return 0;
    };
    match resolve(pages.get(b"Count")) {
        Some(Object::Integer(n)) => n,
        // `as` saturates, as Java's narrowing of a double does.
        #[allow(clippy::cast_possible_truncation)]
        Some(Object::Real(r)) => r.trunc() as i64,
        _ => 0,
    }
}

fn field_dict(objects: &Objects, id: ObjectId) -> Option<&Dictionary> {
    match objects.get(&id)? {
        Object::Dictionary(dict) => Some(dict),
        _ => None,
    }
}

/// Whether `object` holds a reference, at any depth of its direct structure.
fn holds_reference(object: &Object) -> bool {
    let mut pending = vec![object];
    while let Some(object) = pending.pop() {
        match object {
            Object::Reference(_) => return true,
            Object::Array(items) => pending.extend(items),
            Object::Dictionary(dict) => pending.extend(dict.iter().map(|(_, value)| value)),
            Object::Stream(stream) => pending.extend(stream.dict.iter().map(|(_, value)| value)),
            _ => {}
        }
    }
    false
}

/// What DSS's filter needs to know of the keys leading to a pair.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Chain {
    /// The last key is one whose modification is tolerated.
    tolerated: bool,
    /// A `/Reference` key lies on the chain.
    reference: bool,
    /// An `/AP` key lies on the chain.
    appearance: bool,
    /// A `/Resources` key lies below that `/AP`.
    resources: bool,
}

impl Chain {
    const ROOT: Self = Self {
        tolerated: false,
        reference: false,
        appearance: false,
        resources: false,
    };

    /// The chain once `key` is entered, `None` when DSS drops whatever lies below it:
    /// a `/Data` reached through a `/Reference` (the DocMDP reference to the catalog), a
    /// second `/Resources` inside an `/AP`.
    fn enter(self, key: &[u8]) -> Option<Self> {
        if self.reference && key == b"Data" {
            return None;
        }
        let resources = key == b"Resources" && self.appearance;
        if resources && self.resources {
            return None;
        }
        Some(Self {
            tolerated: TOLERATED_KEYS.contains(&key),
            reference: self.reference || key == b"Reference",
            appearance: self.appearance || key == b"AP",
            resources: self.resources || resources,
        })
    }
}

/// Whether the signed-revision field `signed` and the last revision's `last` differ beyond
/// DSS's exclusions on a key of [`FIELD_KEYS`] the signed field holds. Reaching a bound
/// counts as a difference: never laxer than DSS.
fn field_changed(
    signed: &Objects,
    last: &Objects,
    pdf: &[u8],
    signed_field: &Dictionary,
    last_field: &Dictionary,
) -> bool {
    let mut stack: Vec<(&Object, &Object, Chain, usize)> = Vec::new();
    for key in FIELD_KEYS {
        let Some(before) = signed_field.get(key) else {
            continue;
        };
        let Some(chain) = Chain::ROOT.enter(key) else {
            continue;
        };
        match last_field.get(key) {
            Some(after) => stack.push((before, after, chain, 1)),
            None if key == b"AP" => {}
            None => return true,
        }
    }
    let mut visited: HashSet<(ObjectId, ObjectId, Chain)> = HashSet::new();
    let mut pairs = 0;
    while let Some((before, after, chain, depth)) = stack.pop() {
        pairs += 1;
        if pairs > MAX_PAIRS || depth > MAX_DEPTH {
            return true;
        }
        if before == after && !holds_reference(before) {
            continue;
        }
        let modified = match (before, after) {
            (Object::Reference(x), Object::Reference(y)) => {
                if visited.insert((*x, *y, chain)) {
                    stack.push((
                        signed.get(x).unwrap_or(&NULL),
                        last.get(y).unwrap_or(&NULL),
                        chain,
                        depth + 1,
                    ));
                }
                false
            }
            (Object::Reference(x), _) => {
                stack.push((signed.get(x).unwrap_or(&NULL), after, chain, depth + 1));
                false
            }
            (_, Object::Reference(y)) => {
                stack.push((before, last.get(y).unwrap_or(&NULL), chain, depth + 1));
                false
            }
            (Object::Dictionary(x), Object::Dictionary(y)) => {
                if entries(x, y, chain, depth, &mut stack) {
                    return true;
                }
                false
            }
            (Object::Stream(x), Object::Stream(y)) => {
                let raw = |range: &std::ops::Range<usize>| pdf.get(range.clone());
                let same_data =
                    matches!((raw(&x.data), raw(&y.data)), (Some(p), Some(q)) if p == q);
                if entries(&x.dict, &y.dict, chain, depth, &mut stack) {
                    return true;
                }
                !same_data
            }
            (Object::Array(x), Object::Array(y)) => {
                if x.len() == y.len() {
                    stack.extend(x.iter().zip(y).map(|(p, q)| (p, q, chain, depth + 1)));
                    false
                } else {
                    true
                }
            }
            (Object::Integer(_) | Object::Real(_), Object::Integer(_) | Object::Real(_)) => {
                number(before) != number(after)
            }
            _ => before != after,
        };
        if modified && !chain.tolerated {
            return true;
        }
    }
    false
}

/// Pushes the pairs of the entries `before` and `after` share, and tells whether an entry
/// was removed or added in a way DSS does not tolerate: only a removed `/AP` is.
fn entries<'o>(
    before: &'o Dictionary,
    after: &'o Dictionary,
    chain: Chain,
    depth: usize,
    stack: &mut Vec<(&'o Object, &'o Object, Chain, usize)>,
) -> bool {
    for (key, value) in before.iter() {
        let Some(inner) = chain.enter(key) else {
            continue;
        };
        match after.get(key) {
            Some(other) => stack.push((value, other, inner, depth + 1)),
            None if key == b"AP" => {}
            None => return true,
        }
    }
    after
        .iter()
        .any(|(key, _)| before.get(key).is_none() && chain.enter(key).is_some())
}

#[allow(clippy::cast_precision_loss)]
fn number(object: &Object) -> Option<f64> {
    match object {
        Object::Integer(n) => Some(*n as f64),
        Object::Real(r) => Some(*r),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dict(entries: &[(&[u8], Object)]) -> Object {
        let mut dict = Dictionary::new();
        for (key, value) in entries {
            dict.insert(key, value.clone());
        }
        Object::Dictionary(dict)
    }

    fn id(number: u32) -> ObjectId {
        ObjectId::new(number, 0)
    }

    fn name(n: &[u8]) -> Object {
        Object::Name(n.to_vec())
    }

    /// The catalog `1 0 R`, the signature dictionary `2 0 R` with its `/Type`, an indirect
    /// `/Reason 3 0 R`, a DocMDP `/Reference` whose `/Data` names the catalog, and a
    /// `/Prop_Build` whose `/Data` is reached without `/Reference`; the appearance `5 0 R`.
    fn state(catalog: &[(&[u8], Object)], kind: &[u8], reason: &[u8], built_by: &[u8]) -> Objects {
        let signature = dict(&[
            (b"Type", name(kind)),
            (b"Reason", Object::Reference(id(3))),
            (
                b"Reference",
                Object::Array(vec![dict(&[
                    (b"TransformMethod", name(b"DocMDP")),
                    (b"Data", Object::Reference(id(1))),
                ])]),
            ),
            (
                b"Prop_Build",
                dict(&[(b"Data", dict(&[(b"Name", name(built_by))]))]),
            ),
        ]);
        HashMap::from([
            (id(1), dict(catalog)),
            (id(2), signature),
            (id(3), Object::String(reason.to_vec())),
            (id(5), dict(&[(b"Type", name(b"XObject"))])),
        ])
    }

    fn signed() -> Objects {
        state(
            &[(b"Type", name(b"Catalog"))],
            b"Sig",
            b"Approved",
            b"Nacre",
        )
    }

    /// The signature field, without the key `skip`, `/F` and the `/Rect` corner given.
    fn field(skip: &[u8], flags: i64, corner: Object) -> Dictionary {
        let mut field = Dictionary::new();
        let entries: [(&[u8], Object); 5] = [
            (b"FT", name(b"Sig")),
            (b"V", Object::Reference(id(2))),
            (
                b"Rect",
                Object::Array(vec![
                    Object::Integer(0),
                    Object::Integer(0),
                    corner,
                    Object::Integer(50),
                ]),
            ),
            (b"F", Object::Integer(flags)),
            (b"AP", dict(&[(b"N", Object::Reference(id(5)))])),
        ];
        for (key, value) in entries {
            if key != skip {
                field.insert(key, value);
            }
        }
        field
    }

    fn signed_field() -> Dictionary {
        field(b"", 4, Object::Integer(100))
    }

    fn changed(last: &Objects, last_field: &Dictionary) -> bool {
        field_changed(&signed(), last, b"", &signed_field(), last_field)
    }

    #[test]
    fn dss_exclusions_and_nothing_else() {
        assert!(!changed(&signed(), &signed_field()));
        assert!(
            !changed(&signed(), &field(b"", 4, Object::Real(100.0))),
            "an integer equals the same real"
        );
        assert!(
            !changed(&signed(), &field(b"", 132, Object::Integer(100))),
            "/F modified"
        );
        let retyped = state(
            &[(b"Type", name(b"Catalog"))],
            b"Other",
            b"Approved",
            b"Nacre",
        );
        assert!(!changed(&retyped, &signed_field()), "/Type modified");
        assert!(
            !changed(&signed(), &field(b"AP", 4, Object::Integer(100))),
            "/AP removed"
        );
        let catalog = state(
            &[
                (b"Type", name(b"Catalog")),
                (b"DSS", Object::Reference(id(9))),
            ],
            b"Sig",
            b"Approved",
            b"Nacre",
        );
        assert!(
            !changed(&catalog, &signed_field()),
            "catalog changed behind /Reference /Data"
        );

        assert!(
            changed(&signed(), &field(b"F", 4, Object::Integer(100))),
            "/F removed"
        );
        assert!(
            changed(&signed(), &field(b"", 4, Object::Integer(120))),
            "/Rect moved"
        );
        let reason = state(&[(b"Type", name(b"Catalog"))], b"Sig", b"Forged", b"Nacre");
        assert!(
            changed(&reason, &signed_field()),
            "indirect /Reason redefined"
        );
        let built = state(
            &[(b"Type", name(b"Catalog"))],
            b"Sig",
            b"Approved",
            b"Other",
        );
        assert!(
            changed(&built, &signed_field()),
            "/Data reached without /Reference"
        );
    }
}
