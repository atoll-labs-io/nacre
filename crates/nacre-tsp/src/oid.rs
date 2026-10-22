//! The object identifiers this crate reads and writes, beyond those of [`nacre_cms::oid`].

use der::oid::ObjectIdentifier;

pub use nacre_cms::oid::{SHA256, SIGNING_CERTIFICATE_V2};

/// `id-ct-TSTInfo` (RFC 3161 §2.4.2).
pub const TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// `id-kp-timeStamping` (RFC 5280 §4.2.1.12).
pub const TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
/// `id-sha384` (RFC 5754).
pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// `id-sha512` (RFC 5754).
pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
