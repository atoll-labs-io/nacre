//! Qualifies each revision appended after a signature by comparing the objects reachable
//! from the catalog before and after it. Nothing is rendered: two states differ when an
//! object they reach differs.

use std::collections::{HashMap, HashSet};

use nacre_pdf::{Dictionary, Document, Object, ObjectId};

use crate::Error;
use crate::report::{AllowedChange, LaterRevision, RevisionVerdict};
use crate::validate::byte_range;

/// Bounds the states parsed and walked in one call, as `MAX_SIGNATURES` bounds the hashing.
pub(crate) const MAX_REVISIONS: usize = 64;

const MAX_FIELD_DEPTH: usize = 32;
const MAX_HOPS: usize = 32;

/// Catalog entries whose subtree is never displayed: what only they reach is inert.
const INERT_KEYS: [&[u8]; 2] = [b"DSS", b"Metadata"];
const CATALOG_KEYS: [&[u8]; 4] = [b"DSS", b"Metadata", b"Extensions", b"AcroForm"];
const FILL_KEYS: [&[u8]; 3] = [b"V", b"AS", b"AP"];
/// pyHanko also sets the Locked flag of the field it signs.
const SIGN_KEYS: [&[u8]; 4] = [b"V", b"AS", b"AP", b"F"];
/// The annotation flag Locked (ISO 32000-1, Table 165, bit 8).
const LOCKED: i64 = 128;
/// The annotation flags Hidden, NoView and ToggleNoView (ISO 32000-1, Table 165).
const HIDDEN: i64 = 2;
const NO_VIEW: i64 = 32;
const TOGGLE_NO_VIEW: i64 = 256;

type Objects = HashMap<ObjectId, Object>;

/// One revision's verdict, with the signatures it adds that a signature rule refuses.
pub(crate) struct Qualified {
    pub(crate) revision: LaterRevision,
    /// The signature dictionaries of a signature added under DocMDP 1, and of one whose
    /// field shows on the page a widget that was not placed at the same rectangle in the
    /// certified state. A signature this revision adds and refuses for another reason is not
    /// here: it is judged on its own signed bytes.
    pub(crate) refused_signatures: Vec<ObjectId>,
}

/// The verdict on every revision after `first`, the index of the oldest signed revision.
pub(crate) fn qualify(
    pdf: &[u8],
    doc: &Document<'_>,
    first: usize,
) -> Result<Vec<Qualified>, Error> {
    let ends: Vec<usize> = doc.revisions().iter().skip(first).map(|r| r.end).collect();
    let count = ends.len().saturating_sub(1);
    if count > MAX_REVISIONS {
        return Err(Error::TooManyRevisions {
            count,
            max: MAX_REVISIONS,
        });
    }
    let Some((&signed, later)) = ends.split_first() else {
        return Ok(Vec::new());
    };
    if later.is_empty() {
        return Ok(Vec::new());
    }
    let mut previous = State::read(pdf, signed);
    // Where the signature widgets of the first certified state lie: a signature shown
    // anywhere else appeared after the certification.
    let mut certified: Option<Placed> = None;
    let mut out = Vec::with_capacity(later.len());
    for &end in later {
        let current = State::read(pdf, end);
        if let Some(before) = previous.as_ref().filter(|s| s.doc_mdp.is_some()) {
            certified.get_or_insert_with(|| before.placed_signature_widgets());
        }
        // Without both states nothing can be compared, so the revision is unreadable.
        out.push(match (&previous, &current) {
            (Some(before), Some(after)) => diff(pdf, before, after, certified.as_ref()),
            _ => Qualified {
                revision: LaterRevision {
                    end,
                    changed: Vec::new(),
                    verdict: RevisionVerdict::Unreadable,
                },
                refused_signatures: Vec::new(),
            },
        });
        previous = current;
    }
    Ok(out)
}

/// A form node of the state before a revision.
struct FormNode {
    /// The full name, raw `/T` bytes joined by `.`.
    name: Vec<u8>,
    signature: bool,
    /// A widget kid of a terminal field rather than the field itself.
    widget_only: bool,
    has_value: bool,
}

/// Where a widget lies on its page.
#[derive(Clone, Copy)]
enum Placement {
    /// Hidden, NoView, no `/Rect`, or a `/Rect` of zero area.
    Off,
    /// The rectangle, corners normalised to min x, min y, max x, max y.
    At([f64; 4]),
    /// A `/Rect` present but unreadable: visible, and equal to nothing.
    Unknown,
}

/// Signature field id → its widgets placed on a page, with their rectangles.
type Placed = HashMap<ObjectId, Vec<(ObjectId, [f64; 4])>>;

enum Lock {
    All,
    Include(Vec<Vec<u8>>),
    Exclude(Vec<Vec<u8>>),
}

/// The document as of one revision.
struct State<'a> {
    doc: Document<'a>,
    end: usize,
    objects: Objects,
    live: HashSet<ObjectId>,
    /// Objects only the catalog's `/DSS` reaches.
    dss: HashSet<ObjectId>,
    /// Read as `/P 1` when the permission cannot be read.
    doc_mdp: Option<i64>,
    doc_mdp_readable: bool,
    form: HashMap<ObjectId, FormNode>,
    locks: Vec<Lock>,
    /// The annotations the pages list in their `/Annots`.
    drawn: HashSet<ObjectId>,
    /// Object id → the drawn annotations whose `/Parent` chain reaches it.
    drawn_under: HashMap<ObjectId, Vec<ObjectId>>,
}

impl<'a> State<'a> {
    fn read(pdf: &'a [u8], end: usize) -> Option<Self> {
        let doc = Document::parse(pdf.get(..end)?).ok()?;
        let objects = doc.reachable().ok()?;
        // An unreadable permission is the strictest one for the revision after this state.
        let (doc_mdp, doc_mdp_readable) = match doc.doc_mdp_level() {
            Ok(level) => (level, true),
            Err(_) => (Some(1), false),
        };
        let root = doc.catalog_id();
        let catalog = doc.catalog();

        let mut live = HashSet::from([root]);
        let mut seeds = Vec::new();
        for (key, value) in catalog.iter() {
            if !INERT_KEYS.contains(&key) {
                references(value, &mut seeds);
            }
        }
        closure(&objects, seeds, &mut live);
        let mut dss = HashSet::new();
        if let Some(value) = catalog.get(b"DSS") {
            let mut seeds = Vec::new();
            references(value, &mut seeds);
            closure(&objects, seeds, &mut dss);
        }
        dss.retain(|id| !live.contains(id));

        let form = form_nodes(&objects, catalog);
        let locks = field_locks(&objects, &form);
        let (drawn, drawn_under) = drawn_annotations(&objects, &live);
        Some(Self {
            doc,
            end,
            objects,
            live,
            dss,
            doc_mdp,
            doc_mdp_readable,
            form,
            locks,
            drawn,
            drawn_under,
        })
    }

    fn dict(&self, id: ObjectId) -> Option<&Dictionary> {
        match self.objects.get(&id)? {
            Object::Dictionary(d) => Some(d),
            _ => None,
        }
    }

    /// The widgets of the signature field `id`: its kids without `/T`, the field itself when
    /// merged with its widget or when it has no widget kid, and every annotation a page
    /// lists whose `/Parent` chain reaches it.
    fn widgets(&self, id: ObjectId, field: &Dictionary) -> Vec<ObjectId> {
        let (_, kids) = split_kids(&self.objects, field);
        let mut widgets = with_self(id, field, kids);
        let mut seen: HashSet<ObjectId> = widgets.iter().copied().collect();
        for widget in self.drawn_under.get(&id).into_iter().flatten() {
            if seen.insert(*widget) {
                widgets.push(*widget);
            }
        }
        widgets
    }

    /// Only a widget a page lists, outside any optional content group, counts as placed:
    /// one the page does not draw, or draws depending on a viewer's layer state, may show
    /// once signed without a change of its own.
    fn placed_signature_widgets(&self) -> Placed {
        self.form
            .iter()
            .filter(|(_, n)| n.signature && !n.widget_only)
            .filter_map(|(id, _)| {
                let field = self.dict(*id)?;
                let placed = self
                    .widgets(*id, field)
                    .into_iter()
                    .filter(|w| self.drawn.contains(w))
                    .filter_map(|w| {
                        let widget = self.dict(w).filter(|d| d.get(b"OC").is_none())?;
                        match placement(&self.objects, widget, false) {
                            Placement::At(rect) => Some((w, rect)),
                            Placement::Off | Placement::Unknown => None,
                        }
                    })
                    .collect();
                Some((*id, placed))
            })
            .collect()
    }

    fn locked(&self, name: &[u8]) -> bool {
        self.locks.iter().any(|lock| match lock {
            Lock::All => true,
            Lock::Include(names) => names.iter().any(|n| n == name),
            Lock::Exclude(names) => !names.iter().any(|n| n == name),
        })
    }
}

fn diff(
    pdf: &[u8],
    before: &State<'_>,
    after: &State<'_>,
    certified: Option<&Placed>,
) -> Qualified {
    let mut changed = Vec::new();
    let mut changed_live = HashSet::new();
    let mut new_live = HashSet::new();
    for (id, object) in &after.objects {
        let differs = before
            .objects
            .get(id)
            .is_none_or(|old| !same(pdf, old, object));
        if after.live.contains(id) && !before.live.contains(id) {
            new_live.insert(*id);
        } else if after.live.contains(id) && differs {
            changed_live.insert(*id);
        } else if !differs {
            continue;
        }
        changed.push(*id);
    }
    changed.sort_unstable();

    let root = after.doc.catalog_id();
    // The revision that makes the permission unreadable is; the ones after it are judged
    // under the strictest permission.
    let (verdict, refused_signatures) = if before.doc_mdp_readable && !after.doc_mdp_readable {
        (RevisionVerdict::Unreadable, Vec::new())
    } else if root != before.doc.catalog_id() {
        (
            RevisionVerdict::NotAllowed {
                refused: vec![root],
            },
            Vec::new(),
        )
    } else {
        let dss = changed.iter().any(|id| after.dss.contains(id))
            || before.doc.catalog().get(b"DSS") != after.doc.catalog().get(b"DSS");
        Judge {
            before,
            after,
            changed: &changed_live,
            new: &new_live,
            certified,
            accepted: HashSet::new(),
            forced: HashSet::new(),
            new_signature_fields: HashSet::new(),
            roots: Vec::new(),
            kinds: Vec::new(),
            refused_signatures: Vec::new(),
        }
        .verdict(dss)
    };
    Qualified {
        revision: LaterRevision {
            end: after.end,
            changed,
            verdict,
        },
        refused_signatures,
    }
}

struct Judge<'s, 'a> {
    before: &'s State<'a>,
    after: &'s State<'a>,
    changed: &'s HashSet<ObjectId>,
    new: &'s HashSet<ObjectId>,
    certified: Option<&'s Placed>,
    accepted: HashSet<ObjectId>,
    /// The fields, widgets and signature dictionaries of a refused sneaky signature, which
    /// no accept rule may let through.
    forced: HashSet<ObjectId>,
    new_signature_fields: HashSet<ObjectId>,
    /// Where the new objects an accepted field brings (`/V`, `/AP`) are reached from.
    roots: Vec<ObjectId>,
    kinds: Vec<AllowedChange>,
    refused_signatures: Vec<ObjectId>,
}

impl Judge<'_, '_> {
    fn verdict(mut self, dss: bool) -> (RevisionVerdict, Vec<ObjectId>) {
        if dss {
            self.kinds.push(AllowedChange::Dss);
        }
        self.sneaky();
        self.signatures();
        self.form_fills();
        self.catalog();
        self.pages();
        self.subordinates();
        for id in &self.forced {
            self.accepted.remove(id);
        }

        let mut refused: Vec<ObjectId> = self
            .changed
            .iter()
            .chain(self.new)
            .filter(|id| !self.accepted.contains(id))
            .copied()
            .collect();
        let verdict = if refused.is_empty() {
            RevisionVerdict::Allowed(self.kinds)
        } else {
            refused.sort_unstable();
            RevisionVerdict::NotAllowed { refused }
        };
        (verdict, self.refused_signatures)
    }

    fn kind(&mut self, kind: AllowedChange) {
        if !self.kinds.contains(&kind) {
            self.kinds.push(kind);
        }
    }

    fn sorted(set: &HashSet<ObjectId>) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = set.iter().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// The sneaky signature attack, judged by its effect: once the document has a certified
    /// state, a signature this revision adds is refused when one widget of its field shows
    /// on the page and was not placed at that same rectangle in the certified state,
    /// whatever the shape of the field and whatever changed to show it.
    fn sneaky(&mut self) {
        let Some(certified) = self.certified else {
            return;
        };
        let mut fields: Vec<ObjectId> = self
            .after
            .form
            .iter()
            .filter(|(_, n)| n.signature && !n.widget_only)
            .map(|(id, _)| *id)
            .collect();
        // A signature field outside `/Fields` still draws its widgets on the page.
        fields.extend(self.new.iter().chain(self.changed).filter(|id| {
            !self.after.form.contains_key(id)
                && self
                    .after
                    .dict(**id)
                    .is_some_and(|f| is_name(f.get(b"FT"), b"Sig"))
        }));
        fields.sort_unstable();
        for id in fields {
            let Some(field) = self.after.dict(id) else {
                continue;
            };
            let Some(value) = self.added_here(field) else {
                continue;
            };
            let widgets = self.after.widgets(id, field);
            let placed = certified.get(&id).map_or(&[][..], Vec::as_slice);
            let sneaky = widgets.iter().any(|w| {
                let Some(widget) = self.after.dict(*w) else {
                    return false;
                };
                match placement(&self.after.objects, widget, true) {
                    Placement::Off => false,
                    Placement::Unknown => true,
                    Placement::At(rect) => !placed.iter().any(|(p, r)| p == w && *r == rect),
                }
            });
            if sneaky {
                self.refuse_signature(field);
                self.forced.insert(id);
                self.forced.insert(value);
                self.forced.extend(widgets);
            }
        }
    }

    /// New merged signature widgets, and existing empty signature fields gaining `/V`.
    fn signatures(&mut self) {
        for id in Self::sorted(self.new) {
            if self.forced.contains(&id) {
                continue;
            }
            let Some(field) = self.after.dict(id) else {
                continue;
            };
            if !is_name(field.get(b"FT"), b"Sig") {
                continue;
            }
            let Some(kind) = self.signature_value(field) else {
                continue;
            };
            if !is_name(field.get(b"Subtype"), b"Widget") {
                continue;
            }
            self.accept_field(id, field, kind);
            self.new_signature_fields.insert(id);
        }
        for id in Self::sorted(self.changed) {
            if self.forced.contains(&id) {
                continue;
            }
            let empty = self
                .before
                .form
                .get(&id)
                .is_some_and(|n| n.signature && !n.widget_only && !n.has_value);
            let (Some(old), Some(field)) = (self.before.dict(id), self.after.dict(id)) else {
                continue;
            };
            if !empty {
                continue;
            }
            let Some(kind) = self.signature_value(field) else {
                continue;
            };
            if only_keys_differ(old, field, &SIGN_KEYS) && locks_only(old, field) {
                self.accept_field(id, field, kind);
            }
        }
    }

    /// The kind of the signature dictionary `/V` names, when its signed bytes end with
    /// this revision and the DocMDP permission allows it. A signature the permission
    /// forbids is recorded as refused.
    fn signature_value(&mut self, field: &Dictionary) -> Option<AllowedChange> {
        let sig = self.after.dict(self.added_here(field)?)?;
        if is_name(sig.get(b"Type"), b"DocTimeStamp")
            && is_name(sig.get(b"SubFilter"), b"ETSI.RFC3161")
        {
            return Some(AllowedChange::DocumentTimestamp);
        }
        // ISO 32000-2, Table 257: /P 1 forbids any approval signature.
        if self.before.doc_mdp == Some(1) {
            self.refuse_signature(field);
            return None;
        }
        Some(AllowedChange::Signature)
    }

    /// The signature dictionary `field`'s `/V` names, when its signed bytes end with this
    /// revision: the signature this revision adds.
    fn added_here(&self, field: &Dictionary) -> Option<ObjectId> {
        let Some(Object::Reference(value)) = field.get(b"V") else {
            return None;
        };
        let sig = self.after.dict(*value)?;
        let [_, _, c, d] = byte_range(&self.after.doc, sig)?;
        (c.checked_add(d) == Some(self.after.end)).then_some(*value)
    }

    fn refuse_signature(&mut self, field: &Dictionary) {
        if let Some(Object::Reference(value)) = field.get(b"V")
            && !self.refused_signatures.contains(value)
        {
            self.refused_signatures.push(*value);
        }
    }

    fn accept_field(&mut self, id: ObjectId, field: &Dictionary, kind: AllowedChange) {
        self.accepted.insert(id);
        for key in [&b"V"[..], b"AP"] {
            if let Some(value) = field.get(key) {
                references(value, &mut self.roots);
            }
        }
        self.kind(kind);
    }

    /// Changed non-signature fields and widgets: only `/V`, `/AS` and `/AP`, under a DocMDP
    /// level that permits form filling, on a field no FieldMDP lock covers.
    fn form_fills(&mut self) {
        if !matches!(self.before.doc_mdp, Some(2 | 3)) {
            return;
        }
        for id in Self::sorted(self.changed) {
            let Some(node) = self.before.form.get(&id) else {
                continue;
            };
            let (Some(old), Some(new)) = (self.before.dict(id), self.after.dict(id)) else {
                continue;
            };
            if node.signature
                || self.before.locked(&node.name)
                || !only_keys_differ(old, new, &FILL_KEYS)
            {
                continue;
            }
            self.accepted.insert(id);
            for key in FILL_KEYS {
                if let Some(value) = new.get(key) {
                    references(value, &mut self.roots);
                }
            }
            self.kind(AllowedChange::FormFill);
        }
    }

    /// The catalog, its AcroForm and the AcroForm's `/Fields` array: only the entries
    /// `CATALOG_KEYS` names change, and `/Fields` only gains new signature fields.
    fn catalog(&mut self) {
        let root = self.after.doc.catalog_id();
        let old_catalog = self.before.doc.catalog();
        let new_catalog = self.after.doc.catalog();
        let old_form = dict_at(&self.before.objects, old_catalog.get(b"AcroForm"));
        let new_form_value = new_catalog.get(b"AcroForm");
        let new_form = dict_at(&self.after.objects, new_form_value);

        let form_ok = match (old_form, new_form) {
            (_, None) => old_catalog.get(b"AcroForm") == new_form_value,
            (old, Some(new)) => {
                let empty = Dictionary::new();
                let old = old.unwrap_or(&empty);
                let fields_value = new.get(b"Fields");
                let ok = only_keys_differ(old, new, &[b"Fields", b"SigFlags"])
                    && self.items_ok(
                        array_at(&self.before.objects, old.get(b"Fields")),
                        array_at(&self.after.objects, fields_value),
                    );
                if ok {
                    for value in [new_form_value, fields_value].into_iter().flatten() {
                        if let Object::Reference(id) = value {
                            self.accepted.insert(*id);
                        }
                    }
                }
                ok
            }
        };
        if form_ok && only_keys_differ(old_catalog, new_catalog, &CATALOG_KEYS) {
            self.accepted.insert(root);
        }
    }

    /// Pages that existed before: only `/Annots` changes, and it only gains new signature
    /// widgets.
    fn pages(&mut self) {
        for id in Self::sorted(&self.after.live) {
            let Some(page) = self.after.dict(id) else {
                continue;
            };
            if !is_name(page.get(b"Type"), b"Page") {
                continue;
            }
            let annots = match page.get(b"Annots") {
                Some(Object::Reference(annots)) => Some(*annots),
                _ => None,
            };
            let touched = |id: &ObjectId| self.changed.contains(id) || self.new.contains(id);
            if !touched(&id) && !annots.as_ref().is_some_and(touched) {
                continue;
            }
            let Some(old) = self
                .before
                .dict(id)
                .filter(|_| self.before.live.contains(&id))
            else {
                continue;
            };
            if only_keys_differ(old, page, &[b"Annots"])
                && self.items_ok(
                    array_at(&self.before.objects, old.get(b"Annots")),
                    array_at(&self.after.objects, page.get(b"Annots")),
                )
            {
                self.accepted.insert(id);
                self.accepted.extend(annots);
            }
        }
    }

    /// Whether `new` keeps every item of `old` and adds only new signature fields.
    fn items_ok(&self, old: Option<&Vec<Object>>, new: Option<&Vec<Object>>) -> bool {
        let old = old.map_or(&[][..], Vec::as_slice);
        let Some(new) = new else {
            return old.is_empty();
        };
        let mut added: Vec<&Object> = new.iter().collect();
        for item in old {
            match added.iter().position(|a| *a == item) {
                Some(at) => {
                    added.remove(at);
                }
                None => return false,
            }
        }
        added.iter().all(|item| match item {
            Object::Reference(id) => self.new_signature_fields.contains(id),
            _ => false,
        })
    }

    /// New objects reached from the `/V` and `/AP` of accepted fields through new objects
    /// only; then every accepted new object must be referred to by accepted objects alone.
    fn subordinates(&mut self) {
        let mut pending = std::mem::take(&mut self.roots);
        let mut reached = HashSet::new();
        while let Some(id) = pending.pop() {
            if !self.new.contains(&id) || !reached.insert(id) {
                continue;
            }
            if let Some(object) = self.after.objects.get(&id) {
                references(object, &mut pending);
            }
        }
        self.accepted.extend(reached);

        let mut referrers: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
        for id in &self.after.live {
            if let Some(object) = self.after.objects.get(id) {
                let mut held = Vec::new();
                references(object, &mut held);
                for target in held {
                    if self.new.contains(&target) {
                        referrers.entry(target).or_default().push(*id);
                    }
                }
            }
        }
        let orphaned: Vec<ObjectId> = self
            .new
            .iter()
            .filter(|id| self.accepted.contains(id))
            .filter(|id| {
                referrers
                    .get(id)
                    .is_some_and(|from| from.iter().any(|r| !self.accepted.contains(r)))
            })
            .copied()
            .collect();
        for id in orphaned {
            self.accepted.remove(&id);
        }
    }
}

/// Whether the annotation flags of `new` are those of `old`, the Locked flag possibly added.
fn locks_only(old: &Dictionary, new: &Dictionary) -> bool {
    let flags = |d: &Dictionary| match d.get(b"F") {
        None => Some(0),
        Some(Object::Integer(n)) => Some(*n),
        Some(_) => None,
    };
    match (flags(old), flags(new)) {
        (Some(old), Some(new)) => new == old | LOCKED || new == old,
        _ => old.get(b"F") == new.get(b"F"),
    }
}

/// Where a widget lies: off the page when the Hidden or NoView flag is set, when it has no
/// `/Rect` or one of zero area. ToggleNoView makes a NoView widget show on hover, so `after`
/// reads it as shown while the certified state reads it as off: both fail closed.
fn placement(objects: &Objects, widget: &Dictionary, after: bool) -> Placement {
    let flags = match resolve(objects, widget.get(b"F")) {
        Some(Object::Integer(n)) => *n,
        _ => 0,
    };
    let off = if after && flags & TOGGLE_NO_VIEW != 0 {
        HIDDEN
    } else {
        HIDDEN | NO_VIEW
    };
    if flags & off != 0 {
        return Placement::Off;
    }
    let Some(rect) = array_at(objects, widget.get(b"Rect")) else {
        return if widget.get(b"Rect").is_some() {
            Placement::Unknown
        } else {
            Placement::Off
        };
    };
    let numbers: Vec<f64> = rect
        .iter()
        .filter_map(|n| match resolve(objects, Some(n)) {
            Some(Object::Integer(i)) => Some(*i as f64),
            Some(Object::Real(r)) => Some(*r),
            _ => None,
        })
        .collect();
    let [x1, y1, x2, y2] = numbers.as_slice() else {
        return Placement::Unknown;
    };
    let rect = [x1.min(*x2), y1.min(*y2), x1.max(*x2), y1.max(*y2)];
    // A NaN area is not zero, so such a rectangle stays visible and matches nothing.
    if (rect[2] - rect[0]) * (rect[3] - rect[1]) == 0.0 {
        Placement::Off
    } else {
        Placement::At(rect)
    }
}

/// The kids of `field`, split into field kids (with `/T`) and widget kids.
fn split_kids(objects: &Objects, field: &Dictionary) -> (Vec<ObjectId>, Vec<ObjectId>) {
    let kids: Vec<ObjectId> = array_at(objects, field.get(b"Kids"))
        .map(|kids| {
            kids.iter()
                .filter_map(|k| match k {
                    Object::Reference(id) => Some(*id),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    kids.into_iter().partition(
        |kid| matches!(objects.get(kid), Some(Object::Dictionary(d)) if d.get(b"T").is_some()),
    )
}

/// The annotations listed in the `/Annots` of the live pages, and for each object the
/// listed annotations whose `/Parent` chain reaches it.
fn drawn_annotations(
    objects: &Objects,
    live: &HashSet<ObjectId>,
) -> (HashSet<ObjectId>, HashMap<ObjectId, Vec<ObjectId>>) {
    let mut drawn = HashSet::new();
    for id in live {
        let Some(Object::Dictionary(page)) = objects.get(id) else {
            continue;
        };
        if !is_name(page.get(b"Type"), b"Page") {
            continue;
        }
        for item in array_at(objects, page.get(b"Annots")).into_iter().flatten() {
            if let Object::Reference(annot) = item {
                drawn.insert(*annot);
            }
        }
    }
    let mut under: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    for annot in &drawn {
        let mut current = *annot;
        let mut visited = HashSet::from([current]);
        for _ in 0..MAX_FIELD_DEPTH {
            let Some(Object::Dictionary(node)) = objects.get(&current) else {
                break;
            };
            let Some(Object::Reference(parent)) = node.get(b"Parent") else {
                break;
            };
            if !visited.insert(*parent) {
                break;
            }
            under.entry(*parent).or_default().push(*annot);
            current = *parent;
        }
    }
    (drawn, under)
}

fn with_self(id: ObjectId, field: &Dictionary, mut widgets: Vec<ObjectId>) -> Vec<ObjectId> {
    if widgets.is_empty() || is_name(field.get(b"Subtype"), b"Widget") {
        widgets.insert(0, id);
    }
    widgets
}

/// The form nodes of a state: every terminal field and every widget kid of one.
fn form_nodes(objects: &Objects, catalog: &Dictionary) -> HashMap<ObjectId, FormNode> {
    let mut nodes = HashMap::new();
    let Some(form) = dict_at(objects, catalog.get(b"AcroForm")) else {
        return nodes;
    };
    let Some(fields) = array_at(objects, form.get(b"Fields")) else {
        return nodes;
    };
    let mut pending: Vec<(ObjectId, Vec<u8>, bool, usize)> = fields
        .iter()
        .rev()
        .filter_map(|f| match f {
            Object::Reference(id) => Some((*id, Vec::new(), false, 1)),
            _ => None,
        })
        .collect();
    let mut visited = HashSet::new();
    while let Some((id, parent, inherited_sig, depth)) = pending.pop() {
        if depth > MAX_FIELD_DEPTH || !visited.insert(id) {
            continue;
        }
        let Some(Object::Dictionary(field)) = objects.get(&id) else {
            continue;
        };
        let mut name = parent;
        if let Some(Object::String(part)) = field.get(b"T") {
            if !name.is_empty() {
                name.push(b'.');
            }
            name.extend_from_slice(part);
        }
        let signature = match field.get(b"FT") {
            Some(Object::Name(ft)) => ft == b"Sig",
            _ => inherited_sig,
        };
        let (field_kids, widgets) = split_kids(objects, field);
        if field_kids.is_empty() {
            let has_value = !matches!(field.get(b"V"), None | Some(Object::Null));
            for widget in &widgets {
                nodes.insert(
                    *widget,
                    FormNode {
                        name: name.clone(),
                        signature,
                        widget_only: true,
                        has_value,
                    },
                );
            }
            nodes.insert(
                id,
                FormNode {
                    name,
                    signature,
                    widget_only: false,
                    has_value,
                },
            );
        } else {
            for kid in field_kids.into_iter().rev() {
                pending.push((kid, name.clone(), signature, depth + 1));
            }
        }
    }
    nodes
}

/// The FieldMDP locks of the signed signature fields. A lock that cannot be read locks
/// every field.
fn field_locks(objects: &Objects, form: &HashMap<ObjectId, FormNode>) -> Vec<Lock> {
    let mut locks = Vec::new();
    let mut ids: Vec<&ObjectId> = form
        .iter()
        .filter(|(_, n)| n.signature && !n.widget_only && n.has_value)
        .map(|(id, _)| id)
        .collect();
    ids.sort_unstable();
    for id in ids {
        let Some(Object::Dictionary(field)) = objects.get(id) else {
            continue;
        };
        let Some(sig) = dict_at(objects, field.get(b"V")) else {
            continue;
        };
        let Some(references) = array_at(objects, sig.get(b"Reference")) else {
            continue;
        };
        for reference in references {
            let Some(reference) = dict_at(objects, Some(reference)) else {
                continue;
            };
            if !is_name(
                resolve(objects, reference.get(b"TransformMethod")),
                b"FieldMDP",
            ) {
                continue;
            }
            locks.push(field_lock(objects, reference).unwrap_or(Lock::All));
        }
    }
    locks
}

fn field_lock(objects: &Objects, reference: &Dictionary) -> Option<Lock> {
    let params = dict_at(objects, reference.get(b"TransformParams"))?;
    let names = || -> Option<Vec<Vec<u8>>> {
        array_at(objects, params.get(b"Fields"))?
            .iter()
            .map(|n| match resolve(objects, Some(n)) {
                Some(Object::String(s)) => Some(s.clone()),
                _ => None,
            })
            .collect()
    };
    match resolve(objects, params.get(b"Action")) {
        Some(Object::Name(a)) if a == b"All" => Some(Lock::All),
        Some(Object::Name(a)) if a == b"Include" => Some(Lock::Include(names()?)),
        Some(Object::Name(a)) if a == b"Exclude" => Some(Lock::Exclude(names()?)),
        _ => None,
    }
}

/// Whether two objects are equal, streams compared by dictionary and raw bytes since equal
/// streams may lie at different offsets.
fn same(pdf: &[u8], a: &Object, b: &Object) -> bool {
    match (a, b) {
        (Object::Stream(x), Object::Stream(y)) => {
            x.dict == y.dict
                && pdf
                    .get(x.data.clone())
                    .zip(pdf.get(y.data.clone()))
                    .is_some_and(|(p, q)| p == q)
        }
        _ => a == b,
    }
}

/// Whether every entry of `old` and `new` outside `allowed` is present in both with the
/// same value, or absent from both.
fn only_keys_differ(old: &Dictionary, new: &Dictionary, allowed: &[&[u8]]) -> bool {
    old.iter()
        .chain(new.iter())
        .map(|(key, _)| key)
        .filter(|key| !allowed.contains(key))
        .all(|key| old.get(key) == new.get(key))
}

fn is_name(value: Option<&Object>, name: &[u8]) -> bool {
    matches!(value, Some(Object::Name(n)) if n == name)
}

/// Follows `value` through `objects` while it is a reference.
fn resolve<'o>(objects: &'o Objects, value: Option<&'o Object>) -> Option<&'o Object> {
    let mut current = value?;
    for _ in 0..MAX_HOPS {
        match current {
            Object::Reference(id) => current = objects.get(id)?,
            direct => return Some(direct),
        }
    }
    None
}

fn dict_at<'o>(objects: &'o Objects, value: Option<&'o Object>) -> Option<&'o Dictionary> {
    match resolve(objects, value)? {
        Object::Dictionary(d) => Some(d),
        _ => None,
    }
}

fn array_at<'o>(objects: &'o Objects, value: Option<&'o Object>) -> Option<&'o Vec<Object>> {
    match resolve(objects, value)? {
        Object::Array(items) => Some(items),
        _ => None,
    }
}

/// Every reference `object` holds, at any depth.
fn references(object: &Object, out: &mut Vec<ObjectId>) {
    let mut stack = vec![object];
    while let Some(current) = stack.pop() {
        match current {
            Object::Reference(id) => out.push(*id),
            Object::Array(items) => stack.extend(items),
            Object::Dictionary(dict) => stack.extend(dict.iter().map(|(_, v)| v)),
            Object::Stream(stream) => stack.extend(stream.dict.iter().map(|(_, v)| v)),
            _ => {}
        }
    }
}

/// Adds to `into` every object of `objects` reached from `seeds`.
fn closure(objects: &Objects, mut seeds: Vec<ObjectId>, into: &mut HashSet<ObjectId>) {
    while let Some(id) = seeds.pop() {
        if into.contains(&id) {
            continue;
        }
        let Some(object) = objects.get(&id) else {
            continue;
        };
        into.insert(id);
        references(object, &mut seeds);
    }
}
