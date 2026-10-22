//! Signs a PDF at PAdES-BASELINE-B with a key on a PKCS#11 token, then asks the local DSS
//! of the conformance bench for its verdict. The manual YubiKey run of `MANUAL.md`.
//!
//! ```sh
//! sign_pdf <module> <key-id-hex> <issuer.pem|-> <in.pdf> <out.pdf>
//! ```
//!
//! The PIN is read from the first line of standard input. `-` as the issuer sends the
//! token's certificate alone.

use std::error::Error;
use std::io::BufRead;
use std::path::PathBuf;
use std::time::SystemTime;

use nacre_conformance::Dss;
use nacre_pades::{DateTime, sign};
use nacre_pkcs11::{Config, KeySelector, Pin, Pkcs11Signer};

const USAGE: &str = "usage: sign_pdf <module> <key-id-hex> <issuer.pem|-> <in.pdf> <out.pdf>";

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mut next = || args.next().ok_or(USAGE);
    let module = PathBuf::from(next()?);
    let key_id = hex(&next()?)?;
    let issuer = next()?;
    let input = next()?;
    let output = next()?;

    let issuers = if issuer == "-" {
        Vec::new()
    } else {
        let pem = std::fs::read_to_string(&issuer)?;
        let (label, der) = der::pem::decode_vec(pem.as_bytes())?;
        if label != "CERTIFICATE" {
            return Err(format!("{issuer} holds no certificate").into());
        }
        vec![der]
    };

    // Room enough that reading does not reallocate, and truncating keeps the buffer `Pin`
    // zeroizes; stdin's own buffer is not ours to clear.
    let mut pin = String::with_capacity(256);
    std::io::stdin().lock().read_line(&mut pin)?;
    let length = pin.trim_end_matches(['\r', '\n']).len();
    pin.truncate(length);

    let config = Config {
        module,
        token_label: None,
        key: KeySelector::Id(key_id),
        issuers,
    };
    let signer = Pkcs11Signer::open(&config, Pin::new(pin))?;
    let pdf = std::fs::read(&input)?;
    let signed = sign(
        &pdf,
        &signer,
        DateTime::from_system_time(SystemTime::now())?,
    )?;
    std::fs::write(&output, &signed)?;
    println!("signed: {output}");

    let reports = Dss::from_env()?.validate("s13-yubikey-b", &signed)?;
    for verdict in &reports.signatures {
        println!(
            "indication: {:?}, sub-indication: {:?}, format: {}",
            verdict.report.indication(),
            verdict.report.sub_indication(),
            verdict.format
        );
    }
    println!(
        "report: {}",
        nacre_conformance::reports_dir()
            .join("s13-yubikey-b.xml")
            .display()
    );
    Ok(())
}

fn hex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(format!("key id {text:?}: an even number of hex digits").into());
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}
