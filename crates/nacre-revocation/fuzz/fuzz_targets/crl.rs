#![no_main]

use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use nacre_revocation::Crl;

const CA: &[u8] = include_bytes!("../../tests/corpus/openssl/ec-ca.der");
const LEAF: &[u8] = include_bytes!("../../tests/corpus/openssl/revoked.der");
// 2027-01-01T00:00:00Z: the target never reads the clock.
const AT: Duration = Duration::from_secs(1_798_761_600);

fuzz_target!(|data: &[u8]| {
    if let Ok(crl) = Crl::from_der(data) {
        let _ = crl.issuer();
        let _ = crl.this_update();
        let _ = crl.next_update();
        let _ = crl.revoked();
        let _ = crl.verify_signature(CA);
        let _ = crl.status(LEAF, CA, SystemTime::UNIX_EPOCH + AT);
    }
});
