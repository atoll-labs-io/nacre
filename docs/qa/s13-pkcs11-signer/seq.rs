// QA probe: signers opened one after the other in one process, the first dropped before the second.
// usage: seq <module> <digest-hex>   right PIN from $QA_PIN, second PIN from $QA_PIN2
use nacre_core::Signer;
use nacre_pkcs11::{Config, KeySelector, Pin, Pkcs11Signer};
fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn cfg(m: &str, k: KeySelector) -> Config { Config { module: m.into(), token_label: Some("qa-token".into()), key: k, issuers: vec![] } }
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let d = hex(&a[2]);
    let first = Pkcs11Signer::open(&cfg(&a[1], KeySelector::Id(vec![1])), Pin::new(std::env::var("QA_PIN").unwrap())).unwrap();
    println!("signer A (id 01, right PIN) sign: {:?}", first.sign_digest(&d).map(|s| s.len()).map_err(|e| e.to_string()));
    drop(first);
    println!("signer A dropped");
    let second = Pkcs11Signer::open(&cfg(&a[1], KeySelector::Id(vec![2])), Pin::new(std::env::var("QA_PIN2").unwrap()));
    println!("signer B (id 02, PIN from QA_PIN2) open after A dropped: {:?}", second.as_ref().map(|_| "ok").map_err(|e| format!("{e} / {e:?}")));
    if let Ok(b) = &second { println!("signer B sign: {:?}", b.sign_digest(&d).map(|s| s.len()).map_err(|e| e.to_string())); }
}
