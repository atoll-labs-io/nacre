#![no_main]

use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use nacre_validate::TrustAnchors;

const ROOT: &[u8] = include_bytes!("../../tests/corpus/chain/root.der");
/// 2026-10-22T00:00:00Z, a date the corpus chain is valid at.
const AT_SECONDS: u64 = 1_792_627_200;

fn anchors() -> &'static TrustAnchors {
    static ANCHORS: OnceLock<TrustAnchors> = OnceLock::new();
    ANCHORS.get_or_init(|| TrustAnchors::from_certificates([ROOT]).expect("corpus root"))
}

fuzz_target!(|data: &[u8]| {
    let _ = nacre_validate::validate(data);
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(AT_SECONDS);
    let _ = nacre_validate::validate_with_anchors(data, anchors(), at);
});
