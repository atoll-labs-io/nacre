use std::fmt::Write as _;

use nacre_pdf::{Dictionary, Document, Object, ObjectId};
use sha1::{Digest, Sha1};

use crate::Error;
use crate::ltv::Material;

/// The `/VRI` key of a signature: the upper-case hex SHA-1 of its decoded `/Contents`, the
/// zero padding after the CMS included, as pyHanko writes it.
pub(crate) fn vri_key(cms: &[u8], capacity: usize) -> String {
    let mut hasher = Sha1::new();
    hasher.update(cms);
    hasher.update(vec![0; capacity.saturating_sub(cms.len())]);
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(40), |mut hex, byte| {
            let _ = write!(hex, "{byte:02X}");
            hex
        })
}

/// `value`, followed through one reference when it is one, with `owner` named when it is not
/// of the type `expected`.
fn resolve(
    doc: &Document<'_>,
    value: &Object,
    owner: ObjectId,
    expected: &'static str,
) -> Result<(ObjectId, Object), Error> {
    let (id, object) = match value {
        Object::Reference(id) => (*id, doc.object(*id)?),
        other => (owner, other.clone()),
    };
    match object {
        Object::Dictionary(_) | Object::Array(_) => Ok((id, object)),
        _ => Err(Error::Pdf(nacre_pdf::Error::WrongType {
            object: id,
            expected,
        })),
    }
}

fn array(
    doc: &Document<'_>,
    value: Option<&Object>,
    owner: ObjectId,
) -> Result<Vec<Object>, Error> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match resolve(doc, value, owner, "DSS array")? {
        (_, Object::Array(items)) => Ok(items),
        (id, _) => Err(Error::Pdf(nacre_pdf::Error::WrongType {
            object: id,
            expected: "DSS array",
        })),
    }
}

fn dictionary(
    doc: &Document<'_>,
    value: &Object,
    owner: ObjectId,
    expected: &'static str,
) -> Result<(ObjectId, Dictionary), Error> {
    match resolve(doc, value, owner, expected)? {
        (id, Object::Dictionary(dict)) => Ok((id, dict)),
        (id, _) => Err(Error::Pdf(nacre_pdf::Error::WrongType {
            object: id,
            expected,
        })),
    }
}

type ListSpec<'m> = (&'static [u8], &'static [u8], &'m [Vec<u8>]);

/// Appends to `pdf` one revision whose catalog points at a `/DSS` holding `material` and a
/// `/VRI` entry under `vri_key`. An existing `/DSS` keeps its entries, before the new ones.
pub(crate) fn append(pdf: &[u8], vri_key: &str, material: &Material) -> Result<Vec<u8>, Error> {
    let doc = Document::parse(pdf)?;
    let mut update = doc.update();

    let (mut dss, dss_id) = match doc.catalog().get(b"DSS") {
        Some(value) => {
            let (id, dict) = dictionary(&doc, value, doc.catalog_id(), "DSS dictionary")?;
            (dict, id)
        }
        None => (Dictionary::new(), doc.catalog_id()),
    };
    let mut vri = match dss.get(b"VRI") {
        Some(value) => dictionary(&doc, value, dss_id, "VRI dictionary")?.1,
        None => Dictionary::new(),
    };

    let mut entry = Dictionary::new();
    entry.insert(b"Type", Object::Name(b"VRI".to_vec()));
    // Each `/DSS` array, the `/VRI` entry key that lists this signature's part of it, the items.
    let lists: [ListSpec<'_>; 3] = [
        (b"Certs", b"Cert", &material.certificates),
        (b"CRLs", b"CRL", &material.crls),
        (b"OCSPs", b"OCSP", &material.ocsps),
    ];
    for (dss_key, entry_key, items) in lists {
        let mut all = array(&doc, dss.get(dss_key), dss_id)?;
        let mut own = Vec::with_capacity(items.len());
        for item in items {
            own.push(Object::Reference(
                update.add_stream(Dictionary::new(), item.clone())?,
            ));
        }
        all.extend(own.iter().cloned());
        if !own.is_empty() {
            entry.insert(entry_key, Object::Array(own));
        }
        if !all.is_empty() {
            dss.insert(dss_key, Object::Array(all));
        }
    }

    vri.insert(
        vri_key.as_bytes(),
        Object::Reference(update.add(Object::Dictionary(entry))?),
    );
    dss.insert(b"VRI", Object::Dictionary(vri));
    let id = update.add(Object::Dictionary(dss))?;
    update.set_catalog(b"DSS", Object::Reference(id));
    Ok(update.finish()?)
}
