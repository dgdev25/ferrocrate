use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
enum Coverage {
    Implemented,
    Partial,
    Unsupported,
}

#[derive(Debug, Clone, Copy)]
struct ApiCase {
    method: &'static str,
    path: &'static str,
    coverage: Coverage,
    expected_status: u16,
    body: &'static str,
}

const API_MATRIX: &[ApiCase] = &[
    ApiCase {
        method: "GET",
        path: "/_ping",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/version",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/info",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/json",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/images/json",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/create",
        coverage: Coverage::Partial,
        expected_status: 400,
        body: "{}",
    },
    ApiCase {
        method: "GET",
        path: "/networks",
        coverage: Coverage::Unsupported,
        expected_status: 404,
        body: "",
    },
];

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

    fn request(&self, method: &str, path: &str, body: &str) -> (u16, String) {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
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
fn docker_api_compatibility_matrix() {
    let harness = DaemonHarness::spawn();

    for case in API_MATRIX {
        let (status, body) = harness.request(case.method, case.path, case.body);
        assert_eq!(
            status, case.expected_status,
            "coverage={:?} {} {} unexpected status, body={}",
            case.coverage, case.method, case.path, body
        );
    }
}
