#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fn read(doc: &nacre_pdf::Document<'_>) {
    let _ = doc.revisions();
    let _ = doc.trailer();
    let _ = doc.signature_fields();
    let _ = doc.object(doc.catalog_id());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = nacre_pdf::Document::parse(data) {
        read(&doc);
    }
    let mut options = nacre_pdf::ReadOptions::default();
    options.misplaced_xref = true;
    if let Ok(doc) = nacre_pdf::Document::parse_with_options(data, &options) {
        read(&doc);
    }
});
