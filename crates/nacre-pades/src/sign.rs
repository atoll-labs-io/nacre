use der::DateTime;
use nacre_cms::Profile;
use nacre_core::{Signer, TimestampAuthority};
use nacre_pdf::{Dictionary, Document, Object, SignatureSpec};
use sha2::{Digest, Sha256};

use crate::Error;
use crate::reserve::contents_capacity;
use crate::timestamp::timestamp_signature;

/// The level a signature is made at.
#[non_exhaustive]
pub enum Level<'a> {
    /// PAdES-BASELINE-B: no timestamp.
    B,
    /// PAdES-BASELINE-T: a signature timestamp from `tsa`, which may verify its own
    /// answer (`HttpTsa` does).
    T {
        /// The authority asked once, after the signer has signed.
        tsa: &'a dyn TimestampAuthority,
    },
}

/// Signs `pdf` at PAdES-BASELINE-B and returns the signed file.
///
/// The original bytes are kept as an exact prefix: one incremental revision is appended,
/// holding an invisible signature field named `Signature<N>` (the smallest `N` no signature
/// field carries yet) and its `/Sig` dictionary, with `/Filter /Adobe.PPKLite`,
/// `/SubFilter /ETSI.CAdES.detached`, `/M` set to `signing_time` and a `/Contents` holding
/// a detached CMS over the `/ByteRange`. The CMS carries `signingCertificateV2` and the
/// whole certificate chain, never `signingTime` nor revocation data.
///
/// The caller supplies the time, for now with `DateTime::from_system_time`; it is written in
/// UTC. `signer` signs exactly once. See [`sign_at_level`] for higher levels.
pub fn sign(pdf: &[u8], signer: &dyn Signer, signing_time: DateTime) -> Result<Vec<u8>, Error> {
    sign_at_level(pdf, signer, signing_time, Level::B)
}

/// Signs `pdf` at `level`, as [`sign`] does for `Level::B`.
///
/// At `Level::T` the authority time-stamps the signature value and the token goes into the
/// unsigned attribute `id-aa-signatureTimeStampToken` of the `SignerInfo`. The `/Contents`
/// reserves room for a token of up to [`TIMESTAMP_TOKEN_MAX`](crate::TIMESTAMP_TOKEN_MAX)
/// DER bytes; a larger one is refused. A failure of the authority returns
/// [`Error::Timestamp`] and no PDF. `signer` signs once and the authority is asked once.
pub fn sign_at_level(
    pdf: &[u8],
    signer: &dyn Signer,
    signing_time: DateTime,
    level: Level<'_>,
) -> Result<Vec<u8>, Error> {
    let doc = Document::parse(pdf)?;
    let capacity = contents_capacity(signer, matches!(level, Level::T { .. }))?;

    let fields = doc.signature_fields();
    let field = (1u64..)
        .map(|n| format!("Signature{n}"))
        .find(|name| fields.iter().all(|f| &f.name != name))
        .unwrap_or_default();

    let mut entries = Dictionary::new();
    entries.insert(b"M", Object::String(pdf_date(&signing_time).into_bytes()));

    let prepared = doc.update().sign(SignatureSpec {
        field,
        sub_filter: b"ETSI.CAdES.detached".to_vec(),
        contents_len: capacity,
        entries,
    })?;

    let mut hasher = Sha256::new();
    for part in prepared.signed_parts() {
        hasher.update(part);
    }
    let mut cms = nacre_cms::sign_detached(&hasher.finalize(), signer, &Profile::PADES, None)?;
    if let Level::T { tsa } = level {
        cms = timestamp_signature(&cms, tsa)?;
    }
    Ok(prepared.embed(&cms)?)
}

/// ISO 32000 date `D:YYYYMMDDHHmmSSZ`.
fn pdf_date(time: &DateTime) -> String {
    format!(
        "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minutes(),
        time.seconds()
    )
}
