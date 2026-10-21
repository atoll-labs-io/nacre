#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use nacre_pdf::{Dictionary, Document, SignatureSpec};

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = Document::parse(data) {
        let spec = SignatureSpec {
            field: "Fuzz".to_owned(),
            sub_filter: b"ETSI.CAdES.detached".to_vec(),
            contents_len: 64,
            entries: Dictionary::new(),
        };
        if let Ok(prepared) = doc.update().sign(spec) {
            let _ = prepared.signed_parts();
            let _ = prepared.embed(&[0xA5; 16]);
        }
    }
});
