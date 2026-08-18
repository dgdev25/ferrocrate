#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[allow(dead_code)]
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
        path: "/system/df",
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
        method: "GET",
        path: "/images/missing/json",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/build",
        // The route has a dedicated valid tar-context probe below; this matrix
        // row preserves its fail-closed empty-body validation behavior.
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/create",
        // Valid creation is exercised by the named-container row below; this
        // row verifies the route's fail-closed missing-image validation.
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "{}",
    },
    ApiCase {
        method: "POST",
        path: "/containers/create?name=matrix-container",
        coverage: Coverage::Implemented,
        expected_status: 201,
        body: r#"{"Image":"busybox","Cmd":["true"]}"#,
    },
    ApiCase {
        method: "POST",
        path: "/containers/prune",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/networks",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/json",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/logs",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/stats",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/changes",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/start",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/stop",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/stop?t=invalid",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/kill?signal=not-a-signal",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/wait",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/pause",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/unpause",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/events",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/images/prune",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/images/missing/tag?repo=example/tag&tag=v1",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/images/missing/history",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/volumes",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/volumes/prune",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/volumes/missing",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/networks/missing",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/networks/prune",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/plugins/pull",
        coverage: Coverage::Unsupported,
        expected_status: 404,
        body: "{}",
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

        let mut child = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
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

        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "daemon socket did not become ready: {}",
            socket_path.display()
        );
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

    fn request_bytes(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> (u16, String) {
        let header = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = UnixStream::connect(&self.socket_path).expect("connect daemon socket");
        stream.write_all(header.as_bytes()).expect("write headers");
        stream.write_all(body).expect("write body");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        let text = String::from_utf8_lossy(&response);
        let (headers, body) = text.split_once("\r\n\r\n").expect("response headers");
        let code = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .expect("parse status code");
        (code, body.to_owned())
    }

    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
            .env("FERROCRATE_RUNTIME_DIR", self._runtime_dir.path())
            .args([
                "daemon",
                "--docker-compat",
                "--socket",
                self.socket_path.to_str().expect("socket path utf8"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("restart daemon");
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if self.socket_path.exists() && UnixStream::connect(&self.socket_path).is_ok() {
                self.child = child;
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("daemon socket did not become ready after restart");
    }
}

#[test]
fn docker_api_compatibility_matrix() {
    let harness = DaemonHarness::spawn();
    let mut pending_id = None;

    for case in API_MATRIX {
        let (status, body) = harness.request(case.method, case.path, case.body);
        assert_eq!(
            status, case.expected_status,
            "coverage={:?} {} {} unexpected status, body={}",
            case.coverage, case.method, case.path, body
        );
        if case.path.starts_with("/containers/create?name=") && status == 201 {
            pending_id = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("Id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
        }
        if case.path == "/containers/prune" {
            assert!(
                body.contains("ContainersDeleted")
                    && pending_id.as_deref().is_some_and(|id| body.contains(id)),
                "pending create must be removed by prune: {body}"
            );
        }
    }
}

#[test]
fn docker_api_build_accepts_a_valid_tar_context() {
    let harness = DaemonHarness::spawn();
    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        let dockerfile = b"FROM scratch\nCOPY app /app\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("Dockerfile").expect("dockerfile path");
        header.set_size(dockerfile.len() as u64);
        header.set_cksum();
        builder
            .append(&header, &dockerfile[..])
            .expect("append dockerfile");
        let app = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_path("app").expect("app path");
        header.set_size(app.len() as u64);
        header.set_cksum();
        builder.append(&header, &app[..]).expect("append app");
        builder.finish().expect("finish tar archive");
    }

    let (status, body) = harness.request_bytes(
        "POST",
        "/build?dockerfile=Dockerfile&t=matrix%2Fbuild%3Alatest",
        "application/x-tar",
        &archive,
    );
    assert_eq!(status, 200, "build response: {body}");
    assert!(
        body.contains("Successfully built"),
        "build response: {body}"
    );
    let (status, body) = harness.request("GET", "/images/matrix%2Fbuild%3Alatest/json", "");
    assert_eq!(status, 200, "image inspect response: {body}");
    let inspect = serde_json::from_str::<serde_json::Value>(&body).expect("image inspect JSON");
    assert!(inspect["Created"].as_str().is_some(), "Created={inspect}");
    assert!(
        inspect["Size"].as_u64().is_some_and(|size| size > 0),
        "Size={inspect}"
    );
    let (status, body) = harness.request("GET", "/images/matrix%2Fbuild%3Alatest/history", "");
    assert_eq!(status, 200, "image history response: {body}");
    let history = serde_json::from_str::<serde_json::Value>(&body).expect("image history JSON");
    assert!(
        history.as_array().is_some_and(|layers| !layers.is_empty()),
        "history={history}"
    );
}

#[test]
fn unsupported_plugin_pull_reports_an_explicit_boundary() {
    let harness = DaemonHarness::spawn();
    let (status, body) = harness.request("POST", "/plugins/pull", "{}");
    assert_eq!(status, 404);
    assert!(
        body.contains("plugin pull is unsupported")
            && body.contains("signed local plugin manifest"),
        "body={body}"
    );
}

#[test]
fn docker_events_are_durable_and_filterable_over_the_socket() {
    let harness = DaemonHarness::spawn();
    let (status, _) = harness.request("POST", "/volumes/create", r#"{"Name":"events-volume"}"#);
    assert_eq!(status, 201);

    let (status, body) = harness.request("GET", "/events?type=volume&event=create", "");
    assert_eq!(status, 200, "events response: {body}");
    assert!(body.contains("\"Type\":\"volume\""), "{body}");
    assert!(body.contains("\"Action\":\"create\""), "{body}");
    assert!(body.contains("\"Actor\":"), "{body}");
    assert!(body.contains("\"timeNano\":"), "{body}");
}

#[test]
fn docker_create_identity_is_inspectable_before_start() {
    let mut harness = DaemonHarness::spawn();
    let (status, body) = harness.request(
        "POST",
        "/containers/create?name=created-before-start",
        r#"{"Image":"busybox","Cmd":["true"]}"#,
    );
    assert_eq!(status, 201, "create response: {body}");
    let id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("create id")
        .to_string();

    let (status, body) = harness.request("GET", &format!("/containers/{id}/json"), "");
    assert_eq!(status, 200, "inspect response: {body}");
    let inspect = serde_json::from_str::<serde_json::Value>(&body).expect("inspect JSON");
    assert_eq!(inspect["Id"], id);
    assert_eq!(inspect["Name"], "/created-before-start");
    assert_eq!(inspect["State"]["Status"], "created");

    let (status, body) = harness.request("GET", "/containers/json?all=1", "");
    assert_eq!(status, 200, "list response: {body}");
    let listed = serde_json::from_str::<serde_json::Value>(&body).expect("list JSON");
    assert!(listed
        .as_array()
        .is_some_and(|items| items.iter().any(|item| item["Id"] == id)));

    harness.restart();
    let (status, body) = harness.request("GET", &format!("/containers/{id}/json"), "");
    assert_eq!(status, 200, "post-restart inspect response: {body}");
    let inspect = serde_json::from_str::<serde_json::Value>(&body).expect("post-restart JSON");
    assert_eq!(inspect["Id"], id);
    assert_eq!(inspect["State"]["Status"], "created");

    let (status, body) = harness.request(
        "POST",
        "/containers/create?name=remove-before-start",
        r#"{"Image":"busybox","Cmd":["true"]}"#,
    );
    assert_eq!(status, 201, "second create response: {body}");
    let remove_id = serde_json::from_str::<serde_json::Value>(&body).expect("second create JSON")
        ["Id"]
        .as_str()
        .expect("second create id")
        .to_string();
    let (status, body) = harness.request("DELETE", &format!("/containers/{remove_id}"), "");
    assert_eq!(status, 204, "pending remove response: {body}");
    let (status, body) = harness.request("GET", &format!("/containers/{remove_id}/json"), "");
    assert_eq!(status, 404, "removed inspect response: {body}");
    harness.restart();
    let (status, body) = harness.request("GET", &format!("/containers/{remove_id}/json"), "");
    assert_eq!(status, 404, "removed post-restart inspect response: {body}");
}
