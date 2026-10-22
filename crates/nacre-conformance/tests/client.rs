#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use nacre_conformance::{Dss, Error};

#[test]
fn only_a_dss_on_this_machine_is_accepted() {
    assert!(matches!(
        Dss::new("https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo"),
        Err(Error::Url(_))
    ));
    assert!(matches!(
        Dss::new("http://10.0.0.1:8080"),
        Err(Error::Url(_))
    ));
    assert!(Dss::new("http://127.0.0.1:18080").is_ok());
}

#[test]
fn a_report_name_that_leaves_the_report_folder_is_refused_before_any_request() {
    // Port 9 (discard) has no DSS: a request would fail with Error::Http, not Error::Url.
    let dss = Dss::new("http://127.0.0.1:9").unwrap();

    assert!(matches!(
        dss.validate("../escape", b"%PDF-1.7"),
        Err(Error::Url(_))
    ));
}
