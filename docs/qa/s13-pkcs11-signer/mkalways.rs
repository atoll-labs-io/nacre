// QA setup: stores an EC P-256 private key with CKA_ALWAYS_AUTHENTICATE and its certificate
// on a SoftHSM token, since softhsm2-util cannot set that attribute.
// usage: mkalways <module> <token-label> <secret-hex> <cert.der> <id-hex>   PIN from $QA_PIN
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let p = Pkcs11::new(&a[1]).unwrap();
    p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let slot = p.get_slots_with_token().unwrap().into_iter()
        .find(|s| p.get_token_info(*s).unwrap().label() == a[2]).unwrap();
    let s = p.open_rw_session(slot).unwrap();
    s.login(UserType::User, Some(&AuthPin::from(std::env::var("QA_PIN").unwrap().as_str()))).unwrap();
    let id = hex(&a[5]);
    let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    s.create_object(&[
        Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(p256), Attribute::Value(hex(&a[3])), Attribute::Token(true),
        Attribute::Private(true), Attribute::Sensitive(true), Attribute::Sign(true),
        Attribute::AlwaysAuthenticate(true), Attribute::Label(b"qa-always".to_vec()), Attribute::Id(id.clone()),
    ]).unwrap();
    let cert = std::fs::read(&a[4]).unwrap();
    s.create_object(&[
        Attribute::Class(ObjectClass::CERTIFICATE), Attribute::CertificateType(CertificateType::X_509),
        Attribute::Value(cert), Attribute::Token(true), Attribute::Id(id), Attribute::Label(b"qa-always-cert".to_vec()),
        Attribute::Subject(vec![0x30, 0x00]),
    ]).unwrap();
    s.logout().unwrap();
    println!("always-authenticate key stored");
}
