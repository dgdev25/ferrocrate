use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct DaemonHarness {
    child: Child,
    _runtime_dir: tempfile::TempDir,
    socket_path: PathBuf,
}

impl Drop for DaemonHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DaemonHarness {
    fn spawn() -> Self {
        let runtime_dir = tempfile::tempdir().expect("runtime tempdir");
        let socket_path = runtime_dir.path().join("docker.sock");

        let child = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "daemon",
                "--docker-compat",
                "--socket",
                socket_path.to_str().expect("socket path utf8"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon");

        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if socket_path.exists() && UnixStream::connect(&socket_path).is_ok() {
                return Self {
                    child,
                    _runtime_dir: runtime_dir,
                    socket_path,
                };
            }
            thread::sleep(Duration::from_millis(25));
        }

        panic!("daemon socket did not become ready: {}", socket_path.display());
    }

    fn request(&self, method: &str, path: &str) -> (u16, String) {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
        );
        self.request_raw(&request)
    }

    fn request_raw(&self, raw: &str) -> (u16, String) {
        let mut stream = UnixStream::connect(&self.socket_path).expect("connect daemon socket");
        stream
            .write_all(raw.as_bytes())
            .expect("write request to daemon");
        let _ = stream.shutdown(std::net::Shutdown::Write);

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("read daemon response");
        let text = String::from_utf8_lossy(&response).to_string();

        let mut parts = text.splitn(2, "\r\n\r\n");
        let headers = parts.next().unwrap_or_default();
        let body = parts.next().unwrap_or_default().to_string();
        let status_line = headers.lines().next().unwrap_or_default();
        let code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|val| val.parse::<u16>().ok())
            .expect("parse status code");

        (code, body)
    }
}

#[test]
fn docker_compat_routes_support_version_prefix() {
    let harness = DaemonHarness::spawn();

    let routes = [
        "/_ping",
        "/version",
        "/info",
        "/containers/json",
        "/images/json",
        "/v1.45/_ping",
        "/v1.45/version",
        "/v1.45/info",
        "/v1.45/containers/json",
        "/v1.45/images/json",
    ];

    for route in routes {
        let (status, body) = harness.request("GET", route);
        assert_eq!(status, 200, "route {route} should return 200");
        if route.ends_with("/_ping") || route == "/_ping" {
            assert_eq!(body, "OK\n", "route {route} should return ping body");
        }
    }
}

#[test]
fn docker_compat_unknown_route_returns_docker_json_error() {
    let harness = DaemonHarness::spawn();
    let (status, body) = harness.request("GET", "/v1.45/does-not-exist");
    assert_eq!(status, 404);
    assert!(body.contains("\"message\":\"not found\""), "body={body}");
}

#[test]
fn docker_compat_malformed_content_length_returns_400_json_error() {
    let harness = DaemonHarness::spawn();
    let raw = "POST /v1.45/containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: nope\r\n\r\n";
    let (status, body) = harness.request_raw(raw);
    assert_eq!(status, 400);
    assert!(
        body.contains("\"message\":\"docker: invalid content-length\""),
        "body={body}"
    );
}

#[test]
fn docker_compat_network_create_list_delete_routes_work() {
    let harness = DaemonHarness::spawn();
    let create_body = r#"{
        "Name":"compat-net",
        "Driver":"bridge",
        "IPAM":{"Config":[{"Subnet":"172.44.0.0/16","Gateway":"172.44.0.1"}]}
    }"#;
    let create_request = format!(
        "POST /v1.45/networks/create HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (create_status, create_resp) = harness.request_raw(&create_request);
    assert_eq!(create_status, 201, "create body={create_resp}");
    assert!(create_resp.contains("\"Id\":\"compat-net\""), "body={create_resp}");

    let (list_status, list_resp) = harness.request("GET", "/v1.45/networks");
    assert_eq!(list_status, 200, "list body={list_resp}");
    assert!(list_resp.contains("\"Name\":\"compat-net\""), "body={list_resp}");

    let (delete_status, delete_resp) = harness.request("DELETE", "/v1.45/networks/compat-net");
    assert_eq!(delete_status, 204, "delete body={delete_resp}");
}
