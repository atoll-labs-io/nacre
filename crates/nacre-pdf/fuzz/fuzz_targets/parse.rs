#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = nacre_pdf::Document::parse(data) {
        let _ = doc.revisions();
        let _ = doc.trailer();
        let _ = doc.signature_fields();
        let _ = doc.object(doc.catalog_id());
    }
});
