#![no_main]

use libfuzzer_sys::fuzz_target;
use nacre_cms::SignedData;

fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = SignedData::from_der(data) {
        let _ = signed.to_der();
        let _ = signed.verify(Some(data));
        let _ = signed.verify(None);
    }
});
