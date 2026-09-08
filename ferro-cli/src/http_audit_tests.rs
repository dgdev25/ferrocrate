use super::read_http_request;
use std::{io::Write, os::unix::net::UnixStream};

fn parse(request: Vec<u8>) -> Result<super::HttpRequest, String> {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || {
        // A rejected request may close the reader before all bytes are sent.
        let _ = sender.write_all(&request);
    });
    let result = read_http_request(&mut receiver);
    drop(receiver);
    writer.join().unwrap();
    result
}

#[test]
fn chunk_extension_line_cannot_exceed_header_budget() {
    let request = format!(
        "POST /build HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1;{}\r\nx\r\n0\r\n\r\n",
        "x".repeat(65 * 1024)
    );
    assert!(parse(request.into_bytes()).is_err());
}

#[test]
fn chunk_trailer_headers_have_an_aggregate_budget() {
    let trailers = format!("X-Trailer: {}\r\n", "x".repeat(1000)).repeat(70);
    let request = format!(
        "POST /build HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n{trailers}\r\n"
    );
    assert!(parse(request.into_bytes()).is_err());
}

#[test]
fn valid_chunk_extensions_and_trailers_preserve_body() {
    let request = b"POST /build HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3;foo=bar\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: value\r\n\r\n";
    let parsed = parse(request.to_vec()).unwrap();
    assert_eq!(parsed.body, b"abcde");
}
