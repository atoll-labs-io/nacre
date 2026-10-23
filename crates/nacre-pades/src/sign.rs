use der::DateTime;
use nacre_cms::Profile;
use nacre_cms::SignedData;
use nacre_core::{RevocationSource, Signer, TimestampAuthority};
use nacre_pdf::{Dictionary, Document, Object, PreparedSignature, SignatureSpec};
use sha2::{Digest, Sha256};

use crate::error::SignedPdf;
use crate::reserve::contents_capacity;
use crate::timestamp::timestamp_signature;
use crate::{Error, archive, dss, ltv};

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
    /// PAdES-BASELINE-LT: B-T, then a revision holding `/DSS` with the certificates of the
    /// signer's chain and of the token, and their revocation data. Nothing goes into the CMS.
    LT {
        /// The authority asked once, after the signer has signed.
        tsa: &'a dyn TimestampAuthority,
        /// Asked once per distinct certificate that is not self-signed, after the authority
        /// has answered.
        revocation: &'a dyn RevocationSource,
        /// The certificates the chains lead to that neither `signer.certificate_chain()`
        /// nor the token carries, typically the trust anchor.
        issuers: &'a [Vec<u8>],
    },
    /// PAdES-BASELINE-LTA: B-LT, then a revision holding a document timestamp over every
    /// byte before it, `/DSS` included. `tsa` time-stamps the signature and `document_tsa`
    /// the document; the two may be distinct authorities. Renew it with
    /// [`extend`](crate::extend).
    LTA {
        /// The authority asked once for the signature timestamp, after the signer has signed.
        tsa: &'a dyn TimestampAuthority,
        /// Asked once per distinct certificate that is not self-signed, after `tsa` has
        /// answered.
        revocation: &'a dyn RevocationSource,
        /// The certificates the chains lead to that neither `signer.certificate_chain()`
        /// nor the token carries, typically the trust anchor.
        issuers: &'a [Vec<u8>],
        /// The authority asked once for the document timestamp, after `/DSS` is written.
        document_tsa: &'a dyn TimestampAuthority,
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
///
/// At `Level::LT` the B-T file gets one more revision whose catalog points at a `/DSS`
/// holding, as raw DER streams, every certificate reached by walking issuers by name from
/// the signer's chain and the token's certificates (with `issuers` as the only other
/// source), the CRLs and OCSP responses the `RevocationSource` gave for them, and one
/// `/VRI` entry for this signature. A self-signed certificate is not asked about. An
/// existing `/DSS` keeps its entries. Nothing is added to the CMS. Once the B-T file is
/// made, any failure returns [`Error::LongTerm`], which carries that file.
///
/// At `Level::LTA` the B-LT file gets one more revision: a `/Type /DocTimeStamp` signature
/// dictionary with `/SubFilter /ETSI.RFC3161`, no `/M`, and a `/Contents` holding the token
/// `document_tsa` returns for the SHA-256 of its `/ByteRange`, which covers the `/DSS`
/// revision. The slot reserves [`TIMESTAMP_TOKEN_MAX`](crate::TIMESTAMP_TOKEN_MAX) bytes.
/// A failure of the B-LT step returns [`Error::LongTerm`] as above; once the B-LT file is
/// made, any failure returns [`Error::Archive`], which carries that file.
pub fn sign_at_level(
    pdf: &[u8],
    signer: &dyn Signer,
    signing_time: DateTime,
    level: Level<'_>,
) -> Result<Vec<u8>, Error> {
    let doc = Document::parse(pdf)?;
    let capacity = contents_capacity(signer, !matches!(level, Level::B))?;

    let field = field_name(&doc);

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
    match level {
        Level::B => Ok(prepared.embed(&cms)?),
        Level::T { tsa } => {
            cms = timestamp_signature(&cms, tsa)?.0;
            Ok(prepared.embed(&cms)?)
        }
        Level::LT {
            tsa,
            revocation,
            issuers,
        } => to_long_term(&prepared, &cms, capacity, signer, tsa, revocation, issuers),
        Level::LTA {
            tsa,
            revocation,
            issuers,
            document_tsa,
        } => {
            let lt = to_long_term(&prepared, &cms, capacity, signer, tsa, revocation, issuers)?;
            archive::document_timestamp(&lt, document_tsa).map_err(|error| Error::Archive {
                signed: SignedPdf(lt),
                source: Box::new(error),
            })
        }
    }
}

/// The smallest `Signature<N>` no signature field of `doc` carries yet.
pub(crate) fn field_name(doc: &Document<'_>) -> String {
    let fields = doc.signature_fields();
    (1u64..)
        .map(|n| format!("Signature{n}"))
        .find(|name| fields.iter().all(|f| &f.name != name))
        .unwrap_or_default()
}

/// Time-stamps `cms`, embeds it in `prepared`, then raises that B-T file to B-LT. A failure
/// after the embedding returns [`Error::LongTerm`] carrying the B-T file.
fn to_long_term(
    prepared: &PreparedSignature,
    cms: &[u8],
    capacity: usize,
    signer: &dyn Signer,
    tsa: &dyn TimestampAuthority,
    revocation: &dyn RevocationSource,
    issuers: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let (cms, token) = timestamp_signature(cms, tsa)?;
    let signed = prepared.embed(&cms)?;
    long_term(&signed, &cms, capacity, &token, signer, revocation, issuers).map_err(|error| {
        Error::LongTerm {
            signed: SignedPdf(signed),
            source: Box::new(error),
        }
    })
}

/// The B-LT step on `signed`, the finished B-T file.
fn long_term(
    signed: &[u8],
    cms: &[u8],
    capacity: usize,
    token: &[u8],
    signer: &dyn Signer,
    revocation: &dyn RevocationSource,
    issuers: &[Vec<u8>],
) -> Result<Vec<u8>, Error> {
    let token_certificates = SignedData::from_der(token)?.certificates;
    let material = ltv::material(
        signer.certificate_chain(),
        &token_certificates,
        issuers,
        revocation,
    )?;
    dss::append(signed, &dss::vri_key(cms, capacity), &material)
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
