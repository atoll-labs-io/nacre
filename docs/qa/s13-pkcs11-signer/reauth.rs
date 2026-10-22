// QA probe: an always-authenticate key whose PIN changes after open; signs N times.
// usage: reauth <module> <id-hex> <digest-hex> <n>   PIN from $QA_PIN, new PIN from $QA_NEWPIN
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::types::AuthPin;
use nacre_core::Signer;
use nacre_pkcs11::{Config, KeySelector, Pin, Pkcs11Signer};
fn hex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let config = Config { module: a[1].clone().into(), token_label: Some("qa-token".into()), key: KeySelector::Id(hex(&a[2])), issuers: vec![] };
    let signer = Pkcs11Signer::open(&config, Pin::new(std::env::var("QA_PIN").unwrap())).unwrap();
    println!("open: ok");
    let d = hex(&a[3]);
    println!("sign before PIN change: {:?}", signer.sign_digest(&d).map(|s| s.len()).map_err(|e| e.to_string()));
    // Change the user PIN from another, non-logged-in session of the same process.
    let p = Pkcs11::new(&a[1]).unwrap();
    let _ = p.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK));
    let slot = p.get_slots_with_token().unwrap().into_iter().find(|s| p.get_token_info(*s).unwrap().label() == "qa-token").unwrap();
    let s = p.open_rw_session(slot).unwrap();
    s.set_pin(&AuthPin::from(std::env::var("QA_PIN").unwrap().as_str()), &AuthPin::from(std::env::var("QA_NEWPIN").unwrap().as_str())).unwrap();
    s.close().unwrap();
    println!("user PIN changed by another session");
    let n: usize = a[4].parse().unwrap();
    for i in 0..n {
        match signer.sign_digest(&d) {
            Ok(sig) => println!("sign {i} after change: ok, {} bytes", sig.len()),
            Err(e) => {
                println!("sign {i} after change: kind {:?}", e.kind());
                println!("  Display: {e}");
                println!("  Debug:   {e:?}");
                let mut src = std::error::Error::source(&e);
                while let Some(x) = src { println!("  source:  {x} | {x:?}"); src = x.source(); }
            }
        }
    }
}
