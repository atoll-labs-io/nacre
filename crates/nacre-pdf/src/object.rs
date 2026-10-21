use std::fmt;
use std::ops::Range;

/// The number and generation of an indirect object, displayed as `N G R`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId {
    pub number: u32,
    pub generation: u16,
}

impl ObjectId {
    pub const fn new(number: u32, generation: u16) -> Self {
        Self { number, generation }
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} R", self.number, self.generation)
    }
}

/// A PDF object. Strings and names hold their decoded bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum Object {
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    String(Vec<u8>),
    Name(Vec<u8>),
    Array(Vec<Object>),
    Dictionary(Dictionary),
    Reference(ObjectId),
    Stream(Stream),
}

impl Object {
    pub(crate) fn is_name(&self, name: &[u8]) -> bool {
        matches!(self, Object::Name(n) if n == name)
    }
}

/// A dictionary, its entries kept in the order of the input. Keys are unique.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dictionary {
    entries: Vec<(Vec<u8>, Object)>,
}

impl Dictionary {
    pub(crate) const EMPTY: Self = Self {
        entries: Vec::new(),
    };

    pub(crate) fn from_entries(entries: Vec<(Vec<u8>, Object)>) -> Self {
        Self { entries }
    }

    /// The value of `key`, a name given without its slash.
    pub fn get(&self, key: &[u8]) -> Option<&Object> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, value)| value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &Object)> {
        self.entries.iter().map(|(k, v)| (k.as_slice(), v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A stream: its dictionary, and the range of its raw data in the input.
#[derive(Debug, Clone, PartialEq)]
pub struct Stream {
    pub dict: Dictionary,
    pub data: Range<usize>,
}
