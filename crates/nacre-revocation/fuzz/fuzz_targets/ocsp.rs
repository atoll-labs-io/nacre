#![no_main]

use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use nacre_revocation::{OcspRequest, OcspResponse};

const CA: &[u8] = include_bytes!("../../tests/corpus/ocsp-openssl/ca.der");
const LEAF: &[u8] = include_bytes!("../../tests/corpus/ocsp-openssl/revoked-leaf.der");
// 2027-01-01T00:00:00Z: the target never reads the clock.
const AT: Duration = Duration::from_secs(1_798_761_600);

fuzz_target!(|data: &[u8]| {
    if let Ok(response) = OcspResponse::from_der(data) {
        let at = SystemTime::UNIX_EPOCH + AT;
        let _ = response.produced_at();
        let _ = response.this_update();
        let _ = response.nonce();
        if let Ok(request) = OcspRequest::new(LEAF, CA, &[0x4e; 32]) {
            let _ = response.check_nonce(&request);
        }
        let _ = response.check_this_update(LEAF, CA, at, Duration::from_secs(300));
        let _ = response.status(LEAF, CA, at);
    }
});
