#![forbid(unsafe_code)]
//! **Experimental**: not yet fuzzed at length nor cross-checked against a reference reader.
//!
//! `nacre-pdf` opens a PDF and returns what signing and validating need from it: its
//! revisions (where each one ends), its newest trailer, its catalog and its AcroForm
//! signature fields. It reads classic cross-reference tables, cross-reference streams
//! (FlateDecode with PNG predictors), object streams and hybrid files.
//!
//! The reader is strict: an input it cannot read exactly as written is refused with an
//! [`Error`] naming the defect, never repaired. One tolerance exists, opt-in through
//! [`ReadOptions::misplaced_xref`] and off in [`Document::parse`]: a cross-reference
//! section whose stated offset lands on whitespace before it. Every count, length and depth read from
//! the input is bounded, so hostile input fails in bounded time and memory.
//!
//! It also appends one incremental revision through [`Document::update`]: new objects and
//! catalog entries, and optionally an invisible signature field whose `/Contents` slot is
//! filled once the signature over [`PreparedSignature::signed_parts`] is made. The original
//! bytes are always kept as an exact prefix.
//!
//! Out of scope: rendering, text, content streams, any other editing (removing or
//! compacting objects, rewriting earlier revisions), and repair of any kind beyond that one
//! opt-in tolerance.

mod acroform;
mod document;
mod error;
mod filter;
mod limits;
mod object;
mod parse;
mod revision;
mod write;
mod xref;

pub use acroform::SignatureField;
pub use document::{Document, ReadOptions};
pub use error::Error;
pub use limits::MAX_INPUT_LEN;
pub use object::{Dictionary, Object, ObjectId, Stream};
pub use revision::{PreparedSignature, SignatureSpec, Update};
pub use xref::{Revision, XrefKind};
