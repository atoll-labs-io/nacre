// QA probe: drives nacre_pkcs11's public interface as a developer would.
// usage: probe <module> <token-label|-> <label:NAME|id:HEX> <digest-hex> <out-sig> [signs]
// PIN from $QA_PIN; if $QA_PIN_FIRST is set, open is tried with it first, in the same process.
use nacre_core::Signer;
use nacre_pkcs11::{Config, KeySelector, Pin, Pkcs11Signer};
use std::error::Error as _;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn show(what: &str, e: &dyn std::error::Error) {
    println!("{what} Display: {e}");
    println!("{what} Debug:   {e:?}");
    let mut src = e.source();
    while let Some(s) = src {
        println!("{what} source:  {s} | {s:?}");
        src = s.source();
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let key = match a[3].split_once(':').unwrap() {
        ("label", l) => KeySelector::Label(l.to_string()),
        (_, h) => KeySelector::Id(hex(h)),
    };
    let config = Config {
        module: a[1].clone().into(),
        token_label: if a[2] == "-" { None } else { Some(a[2].clone()) },
        key,
        issuers: vec![],
    };
    if let Ok(first) = std::env::var("QA_PIN_FIRST") {
        match Pkcs11Signer::open(&config, Pin::new(first)) {
            Ok(_) => println!("first open: ok"),
            Err(e) => { println!("first open: kind {:?}", e.kind()); show("first open", &e); }
        }
    }
    let signer = match Pkcs11Signer::open(&config, Pin::new(std::env::var("QA_PIN").unwrap())) {
        Ok(s) => s,
        Err(e) => { println!("open: kind {:?}", e.kind()); show("open", &e); std::process::exit(2); }
    };
    println!("open: ok; algorithm {:?}; chain length {}", signer.algorithm(), signer.certificate_chain().len());
    std::fs::write(format!("{}.chain0.der", a[5]), &signer.certificate_chain()[0]).unwrap();
    let n: usize = a.get(6).map(|s| s.parse().unwrap()).unwrap_or(1);
    for i in 0..n {
        match signer.sign_digest(&hex(&a[4])) {
            Ok(sig) => {
                let out = if i == 0 { a[5].clone() } else { format!("{}.{i}", a[5]) };
                std::fs::write(&out, &sig).unwrap();
                println!("sign {i}: ok, {} bytes -> {out}", sig.len());
            }
            Err(e) => { println!("sign {i}: kind {:?}", e.kind()); show("sign", &e); std::process::exit(3); }
        }
    }
}
