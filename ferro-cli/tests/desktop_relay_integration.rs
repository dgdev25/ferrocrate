#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

#[test]
fn desktop_relay_copies_bytes_in_both_directions() {
    let directory = tempfile::tempdir().expect("relay tempdir");
    let socket = directory.path().join("engine.sock");
    let listener = UnixListener::bind(&socket).expect("bind relay fixture");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept relay");
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).expect("read relay request");
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").expect("write relay response");
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .args(["__ferrocrate_desktop_relay", socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn desktop relay");
    child
        .stdin
        .take()
        .expect("relay stdin")
        .write_all(b"ping")
        .expect("write relay stdin");
    let output = child.wait_with_output().expect("wait for relay");
    assert!(
        output.status.success(),
        "relay failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"pong");
    server.join().expect("relay fixture thread");
}
