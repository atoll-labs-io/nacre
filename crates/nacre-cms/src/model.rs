//! The ASN.1 model of RFC 5652 `SignedData`, decoded and encoded by hand on top of `der`.
//!
//! Signed attributes, certificates and CRLs keep the bytes they arrived with: `der`
//! re-sorts a `SET OF` when it decodes one, so a derived model would verify and write
//! back bytes the signer never produced.

use der::asn1::{OctetString, SetOfVec};
use der::oid::ObjectIdentifier;
use der::{Any, Decode, Encode, Header, Length, Reader, SliceReader, Tag, TagNumber};
use spki::AlgorithmIdentifierOwned;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;

use crate::{Error, oid};

const CONTEXT_0: Tag = context(0);
const CONTEXT_1: Tag = context(1);
const CONTEXT_0_PRIMITIVE: Tag = Tag::ContextSpecific {
    constructed: false,
    number: TagNumber(0),
};

const fn context(number: u32) -> Tag {
    Tag::ContextSpecific {
        constructed: true,
        number: TagNumber(number),
    }
}

/// A `ContentInfo` (RFC 5652 §3): a content type and its content, kept as the DER of
/// the value inside `[0] EXPLICIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentInfo {
    pub content_type: ObjectIdentifier,
    pub content: Vec<u8>,
}

impl ContentInfo {
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        nested(bytes, |r| {
            let value = expect(r, Tag::Sequence)?;
            nested(value, |r| {
                let content_type = ObjectIdentifier::decode(r)?;
                let explicit = expect(r, CONTEXT_0)?;
                let content = nested(explicit, |r| Ok(r.tlv_bytes()?.to_vec()))?;
                Ok(Self {
                    content_type,
                    content,
                })
            })
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let mut body = self.content_type.to_der()?;
        body.extend(tlv(CONTEXT_0, &self.content)?);
        Ok(tlv(Tag::Sequence, &body)?)
    }
}

/// An `EncapsulatedContentInfo`: `econtent` is the content octets, absent when detached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncapsulatedContentInfo {
    pub econtent_type: ObjectIdentifier,
    pub econtent: Option<Vec<u8>>,
}

/// A `SignedData` (RFC 5652 §5.1).
///
/// `certificates` and `crls` hold each `CertificateChoices` and
/// `RevocationInfoChoice` as its received DER, in received order; empty means absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData {
    pub version: u8,
    pub digest_algorithms: Vec<AlgorithmIdentifierOwned>,
    pub encap_content_info: EncapsulatedContentInfo,
    pub certificates: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
    pub signer_infos: Vec<SignerInfo>,
}

impl SignedData {
    /// Reads a DER `ContentInfo` holding a `SignedData`.
    pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
        let info = ContentInfo::from_der(bytes)?;
        if info.content_type != oid::SIGNED_DATA {
            return Err(Error::NotSignedData);
        }
        nested(&info.content, |r| {
            let value = expect(r, Tag::Sequence)?;
            nested(value, Self::decode_fields)
        })
    }

    fn decode_fields(r: &mut SliceReader<'_>) -> Result<Self, Error> {
        let version = u8::decode(r)?;
        let digest_algorithms = nested(expect(r, Tag::Set)?, |r| {
            let mut algorithms = Vec::new();
            while !r.is_finished() {
                algorithms.push(AlgorithmIdentifierOwned::decode(r)?);
            }
            Ok(algorithms)
        })?;
        let encap_content_info = nested(expect(r, Tag::Sequence)?, |r| {
            let econtent_type = ObjectIdentifier::decode(r)?;
            let econtent = match peek_tag(r)? {
                Some(CONTEXT_0) => Some(nested(expect(r, CONTEXT_0)?, |r| {
                    Ok(OctetString::decode(r)?.into_bytes().into_vec())
                })?),
                _ => None,
            };
            Ok(EncapsulatedContentInfo {
                econtent_type,
                econtent,
            })
        })?;
        let certificates = match peek_tag(r)? {
            Some(CONTEXT_0) => raw_elements(expect(r, CONTEXT_0)?)?,
            _ => Vec::new(),
        };
        let crls = match peek_tag(r)? {
            Some(CONTEXT_1) => raw_elements(expect(r, CONTEXT_1)?)?,
            _ => Vec::new(),
        };
        let signer_infos = nested(expect(r, Tag::Set)?, |r| {
            let mut infos = Vec::new();
            while !r.is_finished() {
                infos.push(SignerInfo::decode(r)?);
            }
            Ok(infos)
        })?;
        Ok(Self {
            version,
            digest_algorithms,
            encap_content_info,
            certificates,
            crls,
            signer_infos,
        })
    }

    /// Writes the `ContentInfo`. A decoded value is written back byte for byte, unsigned
    /// attributes apart, which are always DER-sorted.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let mut body = self.version.to_der()?;
        let mut algorithms = Vec::new();
        for algorithm in &self.digest_algorithms {
            algorithms.extend(algorithm.to_der()?);
        }
        body.extend(tlv(Tag::Set, &algorithms)?);

        let mut encap = self.encap_content_info.econtent_type.to_der()?;
        if let Some(econtent) = &self.encap_content_info.econtent {
            let octets = OctetString::new(econtent.as_slice())?.to_der()?;
            encap.extend(tlv(CONTEXT_0, &octets)?);
        }
        body.extend(tlv(Tag::Sequence, &encap)?);

        if !self.certificates.is_empty() {
            body.extend(tlv(CONTEXT_0, &self.certificates.concat())?);
        }
        if !self.crls.is_empty() {
            body.extend(tlv(CONTEXT_1, &self.crls.concat())?);
        }

        let mut infos = Vec::new();
        for info in &self.signer_infos {
            infos.extend(info.to_der()?);
        }
        body.extend(tlv(Tag::Set, &infos)?);

        ContentInfo {
            content_type: oid::SIGNED_DATA,
            content: tlv(Tag::Sequence, &body)?,
        }
        .to_der()
    }

    /// The encapsulated content octets, absent when the signature is detached.
    pub fn econtent(&self) -> Option<&[u8]> {
        self.encap_content_info.econtent.as_deref()
    }
}

/// The `SignerIdentifier` of a `SignerInfo`. `issuer` is the DER of the `Name` as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber {
        issuer: Vec<u8>,
        serial_number: SerialNumber,
    },
    SubjectKeyIdentifier(Vec<u8>),
}

/// A `SignerInfo` (RFC 5652 §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    pub version: u8,
    pub sid: SignerIdentifier,
    pub digest_algorithm: AlgorithmIdentifierOwned,
    pub signed_attrs: Option<SignedAttributes>,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: Vec<u8>,
    pub unsigned_attrs: Vec<Attribute>,
}

impl SignerInfo {
    fn decode(r: &mut SliceReader<'_>) -> Result<Self, Error> {
        nested(expect(r, Tag::Sequence)?, |r| {
            let version = u8::decode(r)?;
            let sid = match peek_tag(r)? {
                Some(CONTEXT_0_PRIMITIVE) => {
                    SignerIdentifier::SubjectKeyIdentifier(expect(r, CONTEXT_0_PRIMITIVE)?.to_vec())
                }
                _ => nested(expect(r, Tag::Sequence)?, |r| {
                    let issuer = r.tlv_bytes()?;
                    Name::from_der(issuer)?;
                    Ok(SignerIdentifier::IssuerAndSerialNumber {
                        issuer: issuer.to_vec(),
                        serial_number: SerialNumber::decode(r)?,
                    })
                })?,
            };
            let digest_algorithm = AlgorithmIdentifierOwned::decode(r)?;
            let signed_attrs = match peek_tag(r)? {
                Some(CONTEXT_0) => {
                    let attrs = SignedAttributes {
                        octets: expect(r, CONTEXT_0)?.to_vec(),
                    };
                    attrs.attributes()?;
                    Some(attrs)
                }
                _ => None,
            };
            let signature_algorithm = AlgorithmIdentifierOwned::decode(r)?;
            let signature = OctetString::decode(r)?.into_bytes().into_vec();
            let unsigned_attrs = match peek_tag(r)? {
                Some(CONTEXT_1) => decode_attributes(expect(r, CONTEXT_1)?)?,
                _ => Vec::new(),
            };
            Ok(Self {
                version,
                sid,
                digest_algorithm,
                signed_attrs,
                signature_algorithm,
                signature,
                unsigned_attrs,
            })
        })
    }

    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let mut body = self.version.to_der()?;
        match &self.sid {
            SignerIdentifier::IssuerAndSerialNumber {
                issuer,
                serial_number,
            } => {
                let mut sid = issuer.clone();
                sid.extend(serial_number.to_der()?);
                body.extend(tlv(Tag::Sequence, &sid)?);
            }
            SignerIdentifier::SubjectKeyIdentifier(ski) => {
                body.extend(tlv(CONTEXT_0_PRIMITIVE, ski)?);
            }
        }
        body.extend(self.digest_algorithm.to_der()?);
        if let Some(attrs) = &self.signed_attrs {
            body.extend(tlv(CONTEXT_0, &attrs.octets)?);
        }
        body.extend(self.signature_algorithm.to_der()?);
        body.extend(OctetString::new(self.signature.as_slice())?.to_der()?);
        if !self.unsigned_attrs.is_empty() {
            body.extend(tlv(CONTEXT_1, &sorted_set_content(&self.unsigned_attrs)?)?);
        }
        Ok(tlv(Tag::Sequence, &body)?)
    }

    /// Adds an unsigned attribute. The signed attributes and the signature are left
    /// untouched, so the signature still verifies.
    pub fn push_unsigned_attribute(&mut self, attribute: Attribute) {
        self.unsigned_attrs.push(attribute);
    }
}

/// An `Attribute` (RFC 5652 §5.3): a type and its values, each kept as its DER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub oid: ObjectIdentifier,
    pub values: Vec<Any>,
}

impl Attribute {
    /// An attribute holding the single value `value`.
    pub fn new(oid: ObjectIdentifier, value: &impl Encode) -> Result<Self, Error> {
        Ok(Self {
            oid,
            values: vec![Any::from_der(&value.to_der()?)?],
        })
    }

    fn decode(r: &mut SliceReader<'_>) -> Result<Self, Error> {
        nested(expect(r, Tag::Sequence)?, |r| {
            let oid = ObjectIdentifier::decode(r)?;
            let values = nested(expect(r, Tag::Set)?, |r| {
                let mut values = Vec::new();
                while !r.is_finished() {
                    values.push(Any::decode(r)?);
                }
                Ok(values)
            })?;
            Ok(Self { oid, values })
        })
    }

    /// The DER `SEQUENCE`, values DER-sorted.
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let mut body = self.oid.to_der()?;
        body.extend(SetOfVec::try_from(self.values.clone())?.to_der()?);
        Ok(tlv(Tag::Sequence, &body)?)
    }
}

/// The signed attributes of a `SignerInfo`, held as the content octets of `[0]` exactly
/// as received or built, never re-encoded from a decoded set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttributes {
    octets: Vec<u8>,
}

impl SignedAttributes {
    /// Builds signed attributes DER-sorted. Duplicates are kept, not merged.
    pub fn from_attributes(attributes: Vec<Attribute>) -> Result<Self, Error> {
        Ok(Self {
            octets: sorted_set_content(&attributes)?,
        })
    }

    /// The bytes the signature covers: the octets under a `SET OF` tag (RFC 5652 §5.4).
    pub fn to_be_signed(&self) -> Result<Vec<u8>, Error> {
        Ok(tlv(Tag::Set, &self.octets)?)
    }

    /// The content octets of `[0]`, as held.
    pub fn octets(&self) -> &[u8] {
        &self.octets
    }

    /// The attributes, decoded in the held order.
    pub fn attributes(&self) -> Result<Vec<Attribute>, Error> {
        decode_attributes(&self.octets)
    }
}

fn decode_attributes(octets: &[u8]) -> Result<Vec<Attribute>, Error> {
    nested(octets, |r| {
        let mut attributes = Vec::new();
        while !r.is_finished() {
            attributes.push(Attribute::decode(r)?);
        }
        Ok(attributes)
    })
}

fn sorted_set_content(attributes: &[Attribute]) -> Result<Vec<u8>, Error> {
    let mut elements = Vec::with_capacity(attributes.len());
    for attribute in attributes {
        elements.push(Any::from_der(&attribute.to_der()?)?);
    }
    let set = SetOfVec::try_from(elements)?;
    let mut octets = Vec::new();
    for element in set.iter() {
        element.encode_to_vec(&mut octets)?;
    }
    Ok(octets)
}

fn raw_elements(value: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    nested(value, |r| {
        let mut elements = Vec::new();
        while !r.is_finished() {
            elements.push(r.tlv_bytes()?.to_vec());
        }
        Ok(elements)
    })
}

/// Runs `f` over `bytes` and requires it to consume them all.
pub(crate) fn nested<'a, T>(
    bytes: &'a [u8],
    f: impl FnOnce(&mut SliceReader<'a>) -> Result<T, Error>,
) -> Result<T, Error> {
    let mut reader = SliceReader::new(bytes)?;
    let value = f(&mut reader)?;
    reader.finish()?;
    Ok(value)
}

/// Reads one TLV with tag `tag` and returns its content octets.
pub(crate) fn expect<'a>(r: &mut SliceReader<'a>, tag: Tag) -> Result<&'a [u8], Error> {
    let header = Header::decode(r)?;
    header.tag().assert_eq(tag)?;
    Ok(r.read_slice(header.length())?)
}

pub(crate) fn peek_tag(r: &SliceReader<'_>) -> Result<Option<Tag>, Error> {
    if r.is_finished() {
        return Ok(None);
    }
    Ok(Some(Tag::peek(r)?))
}

pub(crate) fn tlv(tag: Tag, content: &[u8]) -> Result<Vec<u8>, der::Error> {
    let mut out = Vec::new();
    Header::new(tag, Length::try_from(content.len())?).encode_to_vec(&mut out)?;
    out.extend_from_slice(content);
    Ok(out)
}
