#![forbid(unsafe_code)]
//! **Experimental**: not yet fuzzed at length nor cross-checked against a reference reader.
//!
//! `nacre-pdf` opens a PDF and returns what signing and validating need from it: its
//! revisions (where each one ends), its newest trailer, its catalog and its AcroForm
//! signature fields. It reads classic cross-reference tables, cross-reference streams
//! (FlateDecode with PNG predictors), object streams and hybrid files.
//!
//! The reader is strict: an input it cannot read exactly as written is refused with an
//! [`Error`] naming the defect, never repaired. Every count, length and depth read from
//! the input is bounded, so hostile input fails in bounded time and memory.
//!
//! Out of scope: rendering, text, pages, content streams, editing, and repair of any kind.

mod acroform;
mod document;
mod error;
mod filter;
mod limits;
mod object;
mod parse;
mod xref;

pub use acroform::SignatureField;
pub use document::Document;
pub use error::Error;
pub use limits::MAX_INPUT_LEN;
pub use object::{Dictionary, Object, ObjectId, Stream};
pub use xref::{Revision, XrefKind};
