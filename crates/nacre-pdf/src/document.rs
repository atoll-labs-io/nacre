use std::collections::{HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use crate::acroform::{self, SignatureField};
use crate::filter;
use crate::limits::{Limits, MAX_INPUT_LEN};
use crate::parse::Parser;
use crate::revision::Update;
use crate::xref::{self, Entry, Revision};
use crate::{Dictionary, Error, Object, ObjectId};

/// A parsed PDF. It borrows the input and never modifies it.
pub struct Document<'a> {
    input: &'a [u8],
    limits: Limits,
    revisions: Vec<Revision>,
    entries: HashMap<u32, Entry>,
    catalog_id: ObjectId,
    catalog: Dictionary,
    fields: Vec<SignatureField>,
}

impl fmt::Debug for Document<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Document")
            .field("len", &self.input.len())
            .field("revisions", &self.revisions.len())
            .field("catalog_id", &self.catalog_id)
            .field("signature_fields", &self.fields)
            .finish_non_exhaustive()
    }
}

impl<'a> Document<'a> {
    /// Parses `bytes`, refusing any defect on the paths it follows.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_with(bytes, Limits::DEFAULT)
    }

    pub(crate) fn parse_with(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if input.len() > MAX_INPUT_LEN {
            return Err(Error::TooLarge {
                len: input.len(),
                max: MAX_INPUT_LEN,
            });
        }
        let mut budget = limits.max_total_decoded;
        let xref = xref::read(input, &limits, &mut budget)?;
        let newest = xref.revisions.last().ok_or(Error::MissingStartxref)?;
        if newest.trailer.get(b"Encrypt").is_some() {
            return Err(Error::Encrypted);
        }
        let Some(Object::Reference(catalog_id)) = newest.trailer.get(b"Root") else {
            return Err(Error::Syntax {
                offset: newest.startxref,
                expected: "a /Root reference in the trailer",
            });
        };
        let catalog_id = *catalog_id;
        let mut resolver = Resolver::new(input, &xref.entries, limits, budget);
        let catalog = match resolver.follow(&Object::Reference(catalog_id))? {
            (_, Object::Dictionary(d)) if d.get(b"Type").is_some_and(|t| t.is_name(b"Catalog")) => {
                d
            }
            (id, _) => {
                return Err(Error::WrongType {
                    object: id.unwrap_or(catalog_id),
                    expected: "catalog dictionary",
                });
            }
        };
        let fields = acroform::signature_fields(&mut resolver, catalog_id, &catalog, &limits)?;
        Ok(Self {
            input,
            limits,
            revisions: xref.revisions,
            entries: xref.entries,
            catalog_id,
            catalog,
            fields,
        })
    }

    /// The revisions, oldest first.
    pub fn revisions(&self) -> &[Revision] {
        &self.revisions
    }

    /// The newest trailer.
    pub fn trailer(&self) -> &Dictionary {
        // `parse` refuses a document without a revision, so the fallback is never taken.
        static EMPTY: Dictionary = Dictionary::EMPTY;
        self.revisions.last().map_or(&EMPTY, |r| &r.trailer)
    }

    /// The object the newest trailer's `/Root` names.
    pub fn catalog_id(&self) -> ObjectId {
        self.catalog_id
    }

    pub fn catalog(&self) -> &Dictionary {
        &self.catalog
    }

    /// The AcroForm signature fields, in tree order. A field whose `/V` is neither absent,
    /// `null` nor a reference is listed with
    /// [`value_unreadable`](SignatureField::value_unreadable) set rather than refusing the
    /// file.
    pub fn signature_fields(&self) -> &[SignatureField] {
        &self.fields
    }

    /// The object stored under `id`, a reference it holds left unfollowed.
    pub fn object(&self, id: ObjectId) -> Result<Object, Error> {
        Resolver::new(
            self.input,
            &self.entries,
            self.limits,
            self.limits.max_total_decoded,
        )
        .object(id)
    }

    /// Every indirect object reachable from the newest trailer's `/Root`, through the
    /// references held in dictionaries, arrays and stream dictionaries, each read once. The
    /// trailer's `/Info` is not followed. A reference to a free or absent object stands for
    /// `null` (ISO 32000-1, 7.3.10) and is left out. Only object streams are decoded, each
    /// once, so the whole walk stays within the decoding budget of one parse.
    pub fn reachable(&self) -> Result<HashMap<ObjectId, Object>, Error> {
        let mut resolver = Resolver::new(
            self.input,
            &self.entries,
            self.limits,
            self.limits.max_total_decoded,
        );
        let mut found = HashMap::new();
        let mut pending = vec![self.catalog_id];
        while let Some(id) = pending.pop() {
            if found.contains_key(&id) {
                continue;
            }
            let object = match resolver.object(id) {
                Ok(object) => object,
                Err(Error::ObjectNotFound { .. }) => continue,
                Err(error) => return Err(error),
            };
            references(&object, &mut pending);
            found.insert(id, object);
            if found.len() > self.limits.max_reachable {
                return Err(Error::Limit {
                    what: "reachable objects",
                    offset: 0,
                });
            }
        }
        Ok(found)
    }

    /// The DocMDP permission level of a certified document, following references at each
    /// step: `None` when the catalog's `/Perms` names no DocMDP signature, 2 when its
    /// transform parameters give no `/P`. A `/Reference` array longer than 32 entries is an
    /// [`Error::Limit`].
    pub fn doc_mdp_level(&self) -> Result<Option<i64>, Error> {
        let Some(perms) = self.catalog.get(b"Perms") else {
            return Ok(None);
        };
        // One resolver for the whole reading: each entry looked up through a fresh one would
        // decode its object stream again.
        let mut resolver = Resolver::new(
            self.input,
            &self.entries,
            self.limits,
            self.limits.max_total_decoded,
        );
        let perms = dictionary(
            &mut resolver,
            perms,
            self.catalog_id,
            "permissions dictionary",
        )?;
        let Some(mdp) = perms.1.get(b"DocMDP") else {
            return Ok(None);
        };
        let mdp = dictionary(&mut resolver, mdp, perms.0, "signature dictionary")?;
        let Some(references) = mdp.1.get(b"Reference") else {
            return Ok(None);
        };
        let (id, references) = resolver.follow(references)?;
        let Object::Array(references) = references else {
            return Err(Error::WrongType {
                object: id.unwrap_or(mdp.0),
                expected: "array of signature references",
            });
        };
        if references.len() > self.limits.max_signature_references {
            return Err(Error::Limit {
                what: "signature references",
                offset: 0,
            });
        }
        for reference in &references {
            let (owner, reference) =
                dictionary(&mut resolver, reference, mdp.0, "signature reference")?;
            if !reference
                .get(b"TransformMethod")
                .is_some_and(|m| m.is_name(b"DocMDP"))
            {
                continue;
            }
            let Some(params) = reference.get(b"TransformParams") else {
                return Ok(Some(2));
            };
            let (owner, params) = dictionary(&mut resolver, params, owner, "transform parameters")?;
            return match params.get(b"P").map(|p| resolver.follow(p)).transpose()? {
                None => Ok(Some(2)),
                Some((_, Object::Integer(p))) => Ok(Some(p)),
                Some((id, _)) => Err(Error::WrongType {
                    object: id.unwrap_or(owner),
                    expected: "DocMDP permission level",
                }),
            };
        }
        Ok(None)
    }

    /// Starts one incremental revision appended to this document.
    pub fn update(&self) -> Update<'_, 'a> {
        Update::new(self)
    }

    pub(crate) fn input(&self) -> &'a [u8] {
        self.input
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The highest object number any cross-reference section lists.
    pub(crate) fn highest_entry(&self) -> Option<u32> {
        self.entries.keys().max().copied()
    }

    /// Follows `value` while it is a reference, as [`Resolver::follow`] does.
    pub(crate) fn follow(&self, value: &Object) -> Result<(Option<ObjectId>, Object), Error> {
        Resolver::new(
            self.input,
            &self.entries,
            self.limits,
            self.limits.max_total_decoded,
        )
        .follow(value)
    }
}

/// Follows `value` to a dictionary, returning the id it lives under (else `owner`).
fn dictionary(
    resolver: &mut Resolver<'_, '_>,
    value: &Object,
    owner: ObjectId,
    expected: &'static str,
) -> Result<(ObjectId, Dictionary), Error> {
    match resolver.follow(value)? {
        (id, Object::Dictionary(d)) => Ok((id.unwrap_or(owner), d)),
        (id, _) => Err(Error::WrongType {
            object: id.unwrap_or(owner),
            expected,
        }),
    }
}

/// Pushes every reference `object` holds, at any depth, onto `out`.
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

struct ObjectStream {
    data: Vec<u8>,
    first: usize,
    /// The header pairs: object number and offset from `/First`.
    pairs: Vec<(u64, u64)>,
}

/// Looks objects up for one parse. Decoded object streams are cached, so each is decoded
/// and charged to the budget once.
pub(crate) struct Resolver<'a, 'e> {
    input: &'a [u8],
    entries: &'e HashMap<u32, Entry>,
    limits: Limits,
    budget: usize,
    object_streams: HashMap<u32, Rc<ObjectStream>>,
    in_progress: Vec<ObjectId>,
}

impl<'a, 'e> Resolver<'a, 'e> {
    fn new(
        input: &'a [u8],
        entries: &'e HashMap<u32, Entry>,
        limits: Limits,
        budget: usize,
    ) -> Self {
        Self {
            input,
            entries,
            limits,
            budget,
            object_streams: HashMap::new(),
            in_progress: Vec::new(),
        }
    }

    /// Follows `value` while it is a reference. Returns the last object id followed, if any,
    /// and the direct object reached.
    pub(crate) fn follow(&mut self, value: &Object) -> Result<(Option<ObjectId>, Object), Error> {
        let mut current = value.clone();
        let mut last = None;
        let mut seen = HashSet::new();
        while let Object::Reference(id) = current {
            if !seen.insert(id) || seen.len() > self.limits.max_hops {
                return Err(Error::ReferenceLoop { object: id });
            }
            current = self.object(id)?;
            last = Some(id);
        }
        Ok((last, current))
    }

    /// The object stored under `id`. Reading one object may need others (an indirect
    /// `/Length`, an object stream); an id already being read means a loop.
    pub(crate) fn object(&mut self, id: ObjectId) -> Result<Object, Error> {
        if self.in_progress.contains(&id) || self.in_progress.len() >= self.limits.max_hops {
            return Err(Error::ReferenceLoop { object: id });
        }
        self.in_progress.push(id);
        let result = self.lookup(id);
        self.in_progress.pop();
        result
    }

    fn lookup(&mut self, id: ObjectId) -> Result<Object, Error> {
        match self.entries.get(&id.number).copied() {
            Some(Entry::InUse { offset, generation }) if generation == id.generation => {
                self.parse_at(id, offset)
            }
            Some(Entry::Compressed { container, index }) if id.generation == 0 => {
                self.compressed_object(id, container, index)
            }
            _ => Err(Error::ObjectNotFound { object: id }),
        }
    }

    fn parse_at(&mut self, id: ObjectId, offset: usize) -> Result<Object, Error> {
        let input = self.input;
        let mut p = Parser::new(input, offset, &self.limits);
        if p.object_header() != Some(id) {
            return Err(Error::ObjectMismatch { object: id, offset });
        }
        p.indirect_body(
            id,
            &mut |length_id| match self.follow(&Object::Reference(length_id))? {
                (_, Object::Integer(n)) => Ok(n),
                _ => Err(Error::StreamLength { object: id }),
            },
        )
    }

    fn compressed_object(
        &mut self,
        id: ObjectId,
        container: u32,
        index: u32,
    ) -> Result<Object, Error> {
        let bad = |reason| Error::ObjectStream { object: id, reason };
        let stream = self.object_stream(id, container)?;
        let &(number, offset) = usize::try_from(index)
            .ok()
            .and_then(|i| stream.pairs.get(i))
            .ok_or(bad("index past /N"))?;
        if number != u64::from(id.number) {
            return Err(bad("the header pair names another object"));
        }
        let pos = usize::try_from(offset)
            .ok()
            .and_then(|o| stream.first.checked_add(o))
            .filter(|pos| *pos < stream.data.len())
            .ok_or(bad("object offset past the decoded data"))?;
        Parser::new(&stream.data, pos, &self.limits).object()
    }

    fn object_stream(&mut self, id: ObjectId, container: u32) -> Result<Rc<ObjectStream>, Error> {
        if let Some(stream) = self.object_streams.get(&container) {
            return Ok(Rc::clone(stream));
        }
        let bad = |reason| Error::ObjectStream { object: id, reason };
        let Some(Entry::InUse { generation, .. }) = self.entries.get(&container).copied() else {
            return Err(bad("the container is not a type-1 entry"));
        };
        let container_id = ObjectId::new(container, generation);
        let Object::Stream(stream) = self.object(container_id)? else {
            return Err(bad("the container is not a stream"));
        };
        if !stream
            .dict
            .get(b"Type")
            .is_some_and(|t| t.is_name(b"ObjStm"))
        {
            return Err(bad("the container is not /Type /ObjStm"));
        }
        let non_negative = |key: &[u8]| match stream.dict.get(key) {
            Some(Object::Integer(n)) => usize::try_from(*n).ok(),
            _ => None,
        };
        let n = non_negative(b"N").ok_or(bad("/N is not a count"))?;
        let first = non_negative(b"First").ok_or(bad("/First is not an offset"))?;
        let data = filter::decode(
            self.input,
            &stream,
            container_id,
            &self.limits,
            &mut self.budget,
        )?;
        let header = data
            .get(..first)
            .ok_or(bad("/First past the decoded data"))?;
        let mut p = Parser::new(header, 0, &self.limits);
        let mut pairs = Vec::new();
        // Bounded by the header bytes: a pair that is not there ends the loop.
        for _ in 0..n {
            p.skip_ws();
            let number = p.digits().ok_or(bad("malformed header"))?;
            p.skip_ws();
            let offset = p.digits().ok_or(bad("malformed header"))?;
            pairs.push((number, offset));
        }
        let stream = Rc::new(ObjectStream { data, first, pairs });
        self.object_streams.insert(container, Rc::clone(&stream));
        Ok(stream)
    }
}
