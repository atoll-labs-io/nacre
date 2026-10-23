/// The largest input [`Document::parse`](crate::Document::parse) accepts, in bytes; it is
/// checked before any parsing.
pub const MAX_INPUT_LEN: usize = 50_000_000;

/// The bounds every parse runs under. Tests build smaller ones to reach a guard cheaply.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) max_depth: usize,
    pub(crate) max_object_number: u32,
    pub(crate) max_sections: usize,
    pub(crate) max_hops: usize,
    pub(crate) max_stream_decoded: usize,
    pub(crate) max_total_decoded: usize,
    pub(crate) max_field_depth: usize,
    pub(crate) max_fields: usize,
    pub(crate) max_reachable: usize,
    pub(crate) max_signature_references: usize,
}

impl Limits {
    pub(crate) const DEFAULT: Self = Self {
        max_depth: 64,
        // ISO 32000-1, Annex C: the largest number of indirect objects.
        max_object_number: 8_388_607,
        max_sections: 1_024,
        max_hops: 32,
        max_stream_decoded: 32 * 1024 * 1024,
        max_total_decoded: 256 * 1024 * 1024,
        max_field_depth: 32,
        max_fields: 65_536,
        max_reachable: 1_000_000,
        max_signature_references: 32,
    };
}
