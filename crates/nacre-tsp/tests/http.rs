#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::net::TcpListener;

use nacre_core::{DigestAlgorithm, ErrorKind, TimestampAuthority};
use nacre_tsp::HttpTsa;

/// Reads one HTTP request, answers 500, and returns its lowercased head and its body.
fn serve_once(listener: TcpListener) -> (String, Vec<u8>) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut buffer).unwrap();
        assert!(n > 0, "connection closed before the request head");
        received.extend_from_slice(&buffer[..n]);
        if let Some(at) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&received[..head_end]).to_lowercase();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    while received.len() < head_end + length {
        let n = stream.read(&mut buffer).unwrap();
        assert!(n > 0, "connection closed before the request body");
        received.extend_from_slice(&buffer[..n]);
    }
    stream
        .write_all(
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    (head, received[head_end..head_end + length].to_vec())
}

#[test]
fn http_tsa_sends_only_the_request_and_reports_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/tsa", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || serve_once(listener));

    let imprint = [0x5au8; 32];
    let error = HttpTsa::new(&url)
        .timestamp(DigestAlgorithm::Sha256, &imprint)
        .unwrap_err();
    let (head, body) = server.join().unwrap();

    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert!(head.starts_with("post /tsa "), "{head}");
    assert!(
        head.lines()
            .any(|line| line == "content-type: application/timestamp-query"),
        "{head}"
    );
    // SEQUENCE { INTEGER 1, MessageImprint { sha256 NULL, OCTET STRING imprint }, nonce,
    // certReq TRUE }: only the imprint, the nonce being the request's own.
    let mut imprint_part = vec![0x02, 0x01, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09];
    imprint_part.extend([
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ]);
    imprint_part.extend([0x04, 0x20]);
    imprint_part.extend(imprint);
    assert_eq!(body[0], 0x30);
    assert_eq!(body[1] as usize, body.len() - 2);
    assert_eq!(&body[2..2 + imprint_part.len()], &imprint_part[..]);
    assert_eq!(body[2 + imprint_part.len()], 0x02, "a nonce follows");
    assert_eq!(
        &body[body.len() - 3..],
        &[0x01, 0x01, 0xff],
        "certReq TRUE ends it"
    );

    let short = HttpTsa::new(&url)
        .timestamp(DigestAlgorithm::Sha256, &imprint[..31])
        .unwrap_err();
    assert_eq!(short.kind(), ErrorKind::InvalidInput);
}
