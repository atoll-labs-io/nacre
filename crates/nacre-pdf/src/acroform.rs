use std::collections::HashSet;

use crate::document::Resolver;
use crate::limits::Limits;
use crate::{Dictionary, Error, Object, ObjectId};

/// A terminal AcroForm field of type `/Sig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureField {
    /// The dotted full name. A UTF-16BE `/T` (with its byte order mark) is decoded; any
    /// other is read byte by byte as Latin-1, which is exact for ASCII names.
    pub name: String,
    pub id: ObjectId,
    /// The signature dictionary `/V` names, `None` for an empty field.
    pub value: Option<ObjectId>,
}

pub(crate) fn signature_fields(
    resolver: &mut Resolver<'_, '_>,
    catalog_id: ObjectId,
    catalog: &Dictionary,
    limits: &Limits,
) -> Result<Vec<SignatureField>, Error> {
    let Some(acroform) = catalog.get(b"AcroForm") else {
        return Ok(Vec::new());
    };
    let (id, acroform) = resolver.follow(acroform)?;
    let owner = id.unwrap_or(catalog_id);
    let Object::Dictionary(acroform) = acroform else {
        return Err(Error::WrongType {
            object: owner,
            expected: "AcroForm dictionary",
        });
    };
    let Some(fields) = acroform.get(b"Fields") else {
        return Ok(Vec::new());
    };
    let (id, fields) = resolver.follow(fields)?;
    let Object::Array(fields) = fields else {
        return Err(Error::WrongType {
            object: id.unwrap_or(owner),
            expected: "array of fields",
        });
    };
    let mut walk = Walk {
        resolver,
        limits,
        visited: HashSet::new(),
        nodes: 0,
        names: Vec::new(),
        out: Vec::new(),
    };
    for field in &fields {
        let id = reference(field, owner)?;
        let dict = walk.node(id)?;
        walk.field(id, &dict, None, 1)?;
    }
    Ok(walk.out)
}

fn reference(value: &Object, owner: ObjectId) -> Result<ObjectId, Error> {
    match value {
        Object::Reference(id) => Ok(*id),
        _ => Err(Error::WrongType {
            object: owner,
            expected: "field reference",
        }),
    }
}

struct Walk<'r, 'a, 'e> {
    resolver: &'r mut Resolver<'a, 'e>,
    limits: &'r Limits,
    visited: HashSet<ObjectId>,
    nodes: usize,
    names: Vec<String>,
    out: Vec<SignatureField>,
}

impl Walk<'_, '_, '_> {
    /// Resolves a field or widget dictionary; every node resolved counts toward the cap.
    fn node(&mut self, id: ObjectId) -> Result<Dictionary, Error> {
        self.nodes += 1;
        if self.nodes > self.limits.max_fields {
            return Err(Error::Limit {
                what: "form field nodes",
                offset: 0,
            });
        }
        match self.resolver.follow(&Object::Reference(id))? {
            (_, Object::Dictionary(d)) => Ok(d),
            _ => Err(Error::WrongType {
                object: id,
                expected: "field dictionary",
            }),
        }
    }

    fn field(
        &mut self,
        id: ObjectId,
        dict: &Dictionary,
        inherited_type: Option<&[u8]>,
        depth: usize,
    ) -> Result<(), Error> {
        if depth > self.limits.max_field_depth {
            return Err(Error::Limit {
                what: "form field depth",
                offset: 0,
            });
        }
        if !self.visited.insert(id) {
            return Err(Error::FieldLoop { object: id });
        }
        let field_type = match dict.get(b"FT") {
            Some(Object::Name(name)) => Some(name.as_slice()),
            _ => inherited_type,
        };
        let named = match dict.get(b"T") {
            None => false,
            Some(Object::String(bytes)) => {
                self.names.push(text(bytes));
                true
            }
            Some(_) => {
                return Err(Error::WrongType {
                    object: id,
                    expected: "text string /T",
                });
            }
        };
        let kids = match dict.get(b"Kids") {
            None => Vec::new(),
            Some(kids) => match self.resolver.follow(kids)? {
                (_, Object::Array(kids)) => kids,
                (kids_id, _) => {
                    return Err(Error::WrongType {
                        object: kids_id.unwrap_or(id),
                        expected: "array of kids",
                    });
                }
            },
        };
        let mut field_kids = Vec::new();
        for kid in &kids {
            let kid = reference(kid, id)?;
            let kid_dict = self.node(kid)?;
            // A kid without /T is a widget annotation of this field, not a field.
            if kid_dict.get(b"T").is_some() {
                field_kids.push((kid, kid_dict));
            }
        }
        if field_kids.is_empty() {
            if field_type == Some(b"Sig".as_slice()) {
                let value = match dict.get(b"V") {
                    None | Some(Object::Null) => None,
                    Some(Object::Reference(v)) => Some(*v),
                    Some(_) => {
                        return Err(Error::WrongType {
                            object: id,
                            expected: "signature value reference",
                        });
                    }
                };
                self.out.push(SignatureField {
                    name: self.names.join("."),
                    id,
                    value,
                });
            }
        } else {
            for (kid, kid_dict) in &field_kids {
                self.field(*kid, kid_dict, field_type, depth + 1)?;
            }
        }
        if named {
            self.names.pop();
        }
        Ok(())
    }
}

fn text(bytes: &[u8]) -> String {
    match bytes.strip_prefix(&[0xFE, 0xFF]) {
        Some(utf16) => {
            let units = utf16
                .chunks_exact(2)
                .map(|pair| pair.iter().fold(0u16, |acc, b| acc << 8 | u16::from(*b)));
            char::decode_utf16(units)
                .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
        None => bytes.iter().copied().map(char::from).collect(),
    }
}
