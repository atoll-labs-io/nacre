//! Writes the chain corpus: a fictitious PKI (root, intermediate, leaf, and an impostor
//! root of the same name as the root) and the signed PDFs of `tests/corpus/chain/`, then
//! one PDF per chain attack into `tests/corpus/attacks/`. Each attack PDF is
//! `tests/corpus/unsigned.pdf` correctly signed by a leaf whose path to `root.der` breaks
//! exactly one rule, but `xref-misplaced-startxref.pdf`: `chain-cms.pdf` given an empty
//! update whose `startxref` lands on the end of line before its `xref`.
//!
//! `cargo run -p nacre-validate --example forge_chain_attacks -- crates/nacre-validate/tests/corpus`
//!
//! The output is deterministic: fixed test keys, RFC 6979 ECDSA, fixed dates.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::str::FromStr;

use der::asn1::{Null, OctetString};
use der::flagset::FlagSet;
use der::oid::ObjectIdentifier;
use der::{DateTime as DerDateTime, Encode};
use nacre_core::{SignatureAlgorithm, Signer};
use nacre_pades::{DateTime, sign};
use nacre_pdf::{Dictionary, Document, Object};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{DerSignature, SigningKey};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;
use x509_cert::Certificate;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectKeyIdentifier,
};
use x509_cert::ext::{Extension, ToExtension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

const UNSIGNED: &[u8] = include_bytes!("../tests/corpus/unsigned.pdf");
const ROOT_SECRET: [u8; 32] = [0x31; 32];
const INTERMEDIATE_SECRET: [u8; 32] = [0x32; 32];
const LEAF_SECRET: [u8; 32] = [0x33; 32];
const IMPOSTOR_SECRET: [u8; 32] = [0x34; 32];
const SECOND_CA_SECRET: [u8; 32] = [0x35; 32];
const ROOT: &str = "CN=Nacre chain root,O=Nacre tests,C=FR";
const INTERMEDIATE: &str = "CN=Nacre chain intermediate,O=Nacre tests,C=FR";
const CONSTRAINED: &str = "CN=Nacre chain constrained CA,O=Nacre tests,C=FR";
const SECOND_CA: &str = "CN=Nacre chain second CA,O=Nacre tests,C=FR";
const LEAF: &str = "CN=Nacre chain signer,O=Nacre tests,C=FR";
/// Under the arc RFC 5612 reserves for documentation (enterprise number 32473).
const UNKNOWN_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1");
const EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");

fn main() {
    let corpus = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("usage: forge_chain_attacks <corpus dir>"),
    );
    let chain = corpus.join("chain");
    let attacks = corpus.join("attacks");
    std::fs::create_dir_all(&chain).unwrap();
    std::fs::create_dir_all(&attacks).unwrap();

    let root_key = key(&ROOT_SECRET);
    let intermediate_key = key(&INTERMEDIATE_SECRET);
    let leaf_key = key(&LEAF_SECRET);
    let impostor_key = key(&IMPOSTOR_SECRET);
    let second_key = key(&SECOND_CA_SECRET);

    let root = issue(Profile::ca(ROOT, ROOT), 1, &root_key, &root_key);
    let intermediate = issue(
        Profile::ca(INTERMEDIATE, ROOT),
        2,
        &intermediate_key,
        &root_key,
    );
    let leaf = issue(Profile::leaf(INTERMEDIATE), 3, &leaf_key, &intermediate_key);
    let impostor = issue(Profile::ca(ROOT, ROOT), 1, &impostor_key, &impostor_key);
    write_der(&chain, "root", &root);
    write_der(&chain, "intermediate", &intermediate);
    write_der(&chain, "leaf", &leaf);
    write_der(&chain, "impostor-root", &impostor);

    let chain_cms = signed(&leaf_key, &[&leaf, &intermediate]);
    write_pdf(&chain, "chain-cms", &chain_cms);
    write_pdf(
        &chain,
        "chain-dss",
        &with_dss(
            &signed(&leaf_key, &[&leaf]),
            &[intermediate.to_der().unwrap()],
        ),
    );
    write_pdf(
        &chain,
        "chain-cms-refused-revision",
        &refused_revision(&chain_cms),
    );

    let impostor_leaf = issue(Profile::leaf(ROOT), 4, &leaf_key, &impostor_key);
    write_pdf(
        &attacks,
        "chain-impostor-root",
        &signed(&leaf_key, &[&impostor_leaf, &impostor]),
    );

    let mut not_a_ca = Profile::ca(INTERMEDIATE, ROOT);
    not_a_ca.ca = false;
    let not_a_ca = issue(not_a_ca, 5, &intermediate_key, &root_key);
    write_pdf(
        &attacks,
        "chain-leaf-as-ca",
        &signed(&leaf_key, &[&leaf, &not_a_ca]),
    );

    let mut constrained = Profile::ca(CONSTRAINED, ROOT);
    constrained.path_len = Some(0);
    let constrained = issue(constrained, 6, &intermediate_key, &root_key);
    let second = issue(
        Profile::ca(SECOND_CA, CONSTRAINED),
        7,
        &second_key,
        &intermediate_key,
    );
    let below_second = issue(Profile::leaf(SECOND_CA), 8, &leaf_key, &second_key);
    write_pdf(
        &attacks,
        "chain-path-length",
        &signed(&leaf_key, &[&below_second, &second, &constrained]),
    );

    let mut expired = Profile::leaf(INTERMEDIATE);
    expired.not_after = (2026, 6, 1);
    let expired = issue(expired, 9, &leaf_key, &intermediate_key);
    write_pdf(
        &attacks,
        "chain-expired",
        &signed(&leaf_key, &[&expired, &intermediate]),
    );

    let mut wrong_usage = Profile::leaf(INTERMEDIATE);
    wrong_usage.key_usage = KeyUsages::KeyCertSign.into();
    let wrong_usage = issue(wrong_usage, 10, &leaf_key, &intermediate_key);
    write_pdf(
        &attacks,
        "chain-key-usage",
        &signed(&leaf_key, &[&wrong_usage, &intermediate]),
    );

    let mut critical = Profile::ca(INTERMEDIATE, ROOT);
    critical.extra = Some(Extension {
        extn_id: UNKNOWN_EXTENSION,
        critical: true,
        extn_value: OctetString::new(Null.to_der().unwrap()).unwrap(),
    });
    let critical = issue(critical, 11, &intermediate_key, &root_key);
    write_pdf(
        &attacks,
        "chain-critical-extension",
        &signed(&leaf_key, &[&leaf, &critical]),
    );

    let mut not_yet_valid = Profile::leaf(INTERMEDIATE);
    not_yet_valid.not_before = (2027, 1, 1);
    let not_yet_valid = issue(not_yet_valid, 12, &leaf_key, &intermediate_key);
    write_pdf(
        &attacks,
        "chain-not-yet-valid",
        &signed(&leaf_key, &[&not_yet_valid, &intermediate]),
    );

    let mut signing_ca = Profile::ca(INTERMEDIATE, ROOT);
    signing_ca.key_usage = KeyUsages::DigitalSignature.into();
    let signing_ca = issue(signing_ca, 13, &intermediate_key, &root_key);
    write_pdf(
        &attacks,
        "chain-ca-key-usage",
        &signed(&leaf_key, &[&leaf, &signing_ca]),
    );

    let mut server_only = Profile::leaf(INTERMEDIATE);
    server_only.extra = Some(Extension {
        extn_id: EXTENDED_KEY_USAGE,
        critical: false,
        extn_value: OctetString::new(ExtendedKeyUsage(vec![SERVER_AUTH]).to_der().unwrap())
            .unwrap(),
    });
    let server_only = issue(server_only, 14, &leaf_key, &intermediate_key);
    write_pdf(
        &attacks,
        "chain-extended-key-usage",
        &signed(&leaf_key, &[&server_only, &intermediate]),
    );

    let mut twice = Profile::leaf(INTERMEDIATE);
    twice.extra = Some(Extension {
        extn_id: KEY_USAGE,
        critical: true,
        extn_value: OctetString::new(
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_der()
                .unwrap(),
        )
        .unwrap(),
    });
    let twice = issue(twice, 15, &leaf_key, &intermediate_key);
    write_pdf(
        &attacks,
        "chain-malformed-extension",
        &signed(&leaf_key, &[&twice, &intermediate]),
    );

    let junk: Vec<Vec<u8>> = (0..300u16)
        .map(|i| {
            let [hi, lo] = i.to_be_bytes();
            vec![0x30, 0x04, 0x02, 0x02, hi, lo]
        })
        .collect();
    write_pdf(&attacks, "chain-dss-junk", &with_dss(&chain_cms, &junk));
    write_pdf(
        &attacks,
        "xref-misplaced-startxref",
        &misplaced_startxref(&chain_cms),
    );
}

/// `pdf` given an empty update, an `xref` table with no entry and a trailer whose `/Prev`
/// names the newest section, whose `startxref` names the end of line just before that
/// `xref`.
fn misplaced_startxref(pdf: &[u8]) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let newest = doc.revisions().last().unwrap();
    let size = match newest.trailer.get(b"Size") {
        Some(Object::Integer(size)) => *size,
        other => panic!("/Size {other:?}"),
    };
    let root = doc.catalog_id();
    let mut out = pdf.to_vec();
    let misplaced = out.len();
    out.extend_from_slice(
        format!(
            "\nxref\ntrailer\n<< /Size {size} /Root {} {} R /Prev {} >>\nstartxref\n{misplaced}\n%%EOF\n",
            root.number, root.generation, newest.startxref
        )
        .as_bytes(),
    );
    out
}

/// A certificate profile reduced to what the corpus needs: a subject and an issuer,
/// `basicConstraints`, a critical `keyUsage`, a `subjectKeyIdentifier` for a CA, a
/// validity and one optional extra extension.
struct Profile {
    subject: Name,
    issuer: Name,
    ca: bool,
    path_len: Option<u8>,
    key_usage: FlagSet<KeyUsages>,
    not_before: (u16, u8, u8),
    not_after: (u16, u8, u8),
    extra: Option<Extension>,
}

impl Profile {
    fn ca(subject: &str, issuer: &str) -> Self {
        Self {
            subject: name(subject),
            issuer: name(issuer),
            ca: true,
            path_len: None,
            key_usage: KeyUsages::KeyCertSign | KeyUsages::CRLSign,
            not_before: (2026, 1, 1),
            not_after: (2036, 1, 1),
            extra: None,
        }
    }

    fn leaf(issuer: &str) -> Self {
        Self {
            subject: name(LEAF),
            issuer: name(issuer),
            ca: false,
            path_len: None,
            key_usage: KeyUsages::DigitalSignature | KeyUsages::NonRepudiation,
            not_before: (2026, 1, 1),
            not_after: (2036, 1, 1),
            extra: None,
        }
    }
}

impl BuilderProfile for Profile {
    fn get_issuer(&self, _subject: &Name) -> Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> Name {
        self.subject.clone()
    }

    fn build_extensions(
        &self,
        spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        let basic_constraints = BasicConstraints {
            ca: self.ca,
            path_len_constraint: self.path_len,
        }
        .to_extension(tbs.subject(), &[])?;
        let key_usage = KeyUsage(self.key_usage)
            .to_extension(tbs.subject(), std::slice::from_ref(&basic_constraints))?;
        let mut extensions = vec![basic_constraints, key_usage];
        if self.ca {
            let digest = Sha256::digest(spk.subject_public_key.raw_bytes());
            extensions.push(
                SubjectKeyIdentifier(OctetString::new(&digest[..20])?)
                    .to_extension(tbs.subject(), &extensions)?,
            );
        }
        extensions.extend(self.extra.clone());
        Ok(extensions)
    }
}

/// A P-256 signer holding `chain`, signer first, for the corpus only.
struct ChainSigner {
    key: SigningKey,
    chain: Vec<Vec<u8>>,
}

impl Signer for ChainSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256Sha256
    }

    fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, nacre_core::Error> {
        let signature: DerSignature = self
            .key
            .sign_prehash(digest)
            .map_err(|error| nacre_core::Error::Signer(Box::new(error)))?;
        Ok(signature.as_bytes().to_vec())
    }
}

/// `unsigned.pdf` signed by `key`, its CMS carrying `chain`.
fn signed(key: &SigningKey, chain: &[&Certificate]) -> Vec<u8> {
    let signer = ChainSigner {
        key: key.clone(),
        chain: chain.iter().map(|c| c.to_der().unwrap()).collect(),
    };
    let time = DateTime::new(2026, 10, 22, 8, 0, 0).unwrap();
    sign(UNSIGNED, &signer, time).unwrap()
}

/// `pdf` given one revision whose catalog points at a `/DSS` whose `/Certs` lists one
/// unfiltered stream per entry of `streams`.
fn with_dss(pdf: &[u8], streams: &[Vec<u8>]) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let mut update = doc.update();
    let certs = streams
        .iter()
        .map(|data| Object::Reference(update.add_stream(Dictionary::new(), data.clone()).unwrap()))
        .collect();
    let mut dss = Dictionary::new();
    dss.insert(b"Certs", Object::Array(certs));
    let dss = update.add(Object::Dictionary(dss)).unwrap();
    update.set_catalog(b"DSS", Object::Reference(dss));
    update.finish().unwrap()
}

/// `pdf` given one revision that sets a catalog `/OpenAction`, which no rule allows.
fn refused_revision(pdf: &[u8]) -> Vec<u8> {
    let doc = Document::parse(pdf).unwrap();
    let mut update = doc.update();
    let mut action = Dictionary::new();
    action.insert(b"S", Object::Name(b"JavaScript".to_vec()));
    action.insert(
        b"JS",
        Object::String(b"app.alert('added after signing')".to_vec()),
    );
    update.set_catalog(b"OpenAction", Object::Dictionary(action));
    update.finish().unwrap()
}

fn issue(profile: Profile, serial: u32, key: &SigningKey, signer: &SigningKey) -> Certificate {
    let validity = Validity::new(time(profile.not_before), time(profile.not_after));
    let spki = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).unwrap();
    CertificateBuilder::new(profile, SerialNumber::from(serial), validity, spki)
        .unwrap()
        .build::<_, DerSignature>(signer)
        .unwrap()
}

fn key(secret: &[u8; 32]) -> SigningKey {
    SigningKey::from_slice(secret).unwrap()
}

fn name(dn: &str) -> Name {
    Name::from_str(dn).unwrap()
}

fn time((year, month, day): (u16, u8, u8)) -> Time {
    Time::from(DerDateTime::new(year, month, day, 0, 0, 0).unwrap())
}

fn write_der(dir: &Path, stem: &str, certificate: &Certificate) {
    std::fs::write(
        dir.join(format!("{stem}.der")),
        certificate.to_der().unwrap(),
    )
    .unwrap();
}

fn write_pdf(dir: &Path, stem: &str, pdf: &[u8]) {
    std::fs::write(dir.join(format!("{stem}.pdf")), pdf).unwrap();
}
