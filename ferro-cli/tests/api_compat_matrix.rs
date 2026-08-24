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
        path: "/build/prune?max_entries=64",
        coverage: Coverage::Implemented,
        expected_status: 200,
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
        path: "/containers/create?name=matrix-restart-policy",
        coverage: Coverage::Implemented,
        expected_status: 201,
        body: r#"{"Image":"busybox","Cmd":["true"],"HostConfig":{"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0}}}"#,
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/exec",
        coverage: Coverage::Implemented,
        expected_status: 201,
        body: r#"{"Cmd":["true"]}"#,
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/exec",
        coverage: Coverage::Implemented,
        expected_status: 201,
        body: r#"{"Cmd":["true"],"Tty":true}"#,
    },
    ApiCase {
        method: "POST",
        path: "/containers/create?name=matrix-tty",
        coverage: Coverage::Implemented,
        expected_status: 201,
        body: r#"{"Image":"busybox","Cmd":["sh"],"Tty":true}"#,
    },
    ApiCase {
        method: "POST",
        path: "/exec/missing/start",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: r#"{"Tty":true}"#,
    },
    ApiCase {
        method: "POST",
        path: "/exec/missing/start",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: r#"{"Tty":false}"#,
    },
    ApiCase {
        method: "GET",
        path: "/containers/matrix-container/logs?stdout=1&stderr=1",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/matrix-container/logs?follow=maybe",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "GET",
        // Docker rejects a logs request that selects no stream; validation
        // precedes container resolution.
        path: "/containers/missing/logs?stdout=0&stderr=0",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "GET",
        // timestamps=1 is now honored for journaled non-TTY containers; for a
        // missing container, resolution runs after query validation, so the
        // response is Docker's 404 not-found.
        path: "/containers/missing/logs?timestamps=1",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/logs?since=not-a-number",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "GET",
        // The Docker client always sends since/until; zero is the no-op bound
        // and must stay accepted (nonzero bounds select per-line filtering).
        path: "/containers/missing/logs?since=0",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/matrix-container/changes",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/matrix-container/top",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/matrix-container/stats?stream=0",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/matrix-container/stats?stream=maybe",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/update",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: r#"{"RestartPolicy":{"Name":"always","MaximumRetryCount":0}}"#,
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/update",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: r#"{"NanoCpus":1000000}"#,
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/resize?w=80&h=24",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/resize?w=80",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/resize?w=wide&h=24",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/resize?w=65536&h=24",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/matrix-container/rename?name=matrix-renamed",
        coverage: Coverage::Implemented,
        expected_status: 204,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/matrix-renamed/json?size=1",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/v1.45/containers/matrix-renamed/json?size=1",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
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
        path: "/images/search?term=alpine",
        coverage: Coverage::Implemented,
        expected_status: 200,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/images/create?fromImage=busybox&lazy=maybe",
        coverage: Coverage::Implemented,
        expected_status: 400,
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
        path: "/containers/missing/logs?tail=invalid",
        coverage: Coverage::Implemented,
        expected_status: 400,
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
        path: "/containers/missing/stats?stream=maybe",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/resize?w=80&h=24",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/resize?w=wide&h=24",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/top",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        // The local process listing is synthetic; an explicit ps argument
        // set cannot be honored and fails closed.
        path: "/containers/missing/top?ps_args=-ef",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "GET",
        // Recognized Docker route without a local websocket implementation.
        path: "/containers/missing/attach/ws",
        coverage: Coverage::Unsupported,
        expected_status: 501,
        body: "",
    },
    ApiCase {
        method: "PUT",
        // noOverwriteDirNonDir is validated before the container resolves.
        path: "/containers/missing/archive?path=%2F&noOverwriteDirNonDir=maybe",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "archive",
    },
    ApiCase {
        method: "POST",
        // The implemented route validates its required local request fields
        // before attempting registry credential verification.
        path: "/auth",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/attach",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/attach?logs=maybe",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/rename?name=renamed-container",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/update",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: r#"{"Memory":0,"PidsLimit":-1}"#,
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/changes",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/export",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/containers/missing/archive?path=%2Fetc%2Fhosts",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "HEAD",
        path: "/containers/missing/archive?path=%2F",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "PUT",
        path: "/containers/missing/archive?path=%2F",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "archive",
    },
    ApiCase {
        method: "GET",
        path: "/exec/missing/json",
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
        path: "/containers/missing/restart?t=invalid",
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
        path: "/containers/missing/wait?condition=unsupported",
        coverage: Coverage::Implemented,
        expected_status: 400,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/wait?timeout=invalid",
        coverage: Coverage::Implemented,
        expected_status: 400,
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
        method: "DELETE",
        path: "/containers/missing",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/containers/missing/restart",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/commit?container=missing&repo=example%2Fmissing",
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
        method: "GET",
        path: "/events?follow=maybe",
        coverage: Coverage::Implemented,
        expected_status: 400,
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
        path: "/images/get?names=missing",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "GET",
        path: "/images/missing/get",
        coverage: Coverage::Implemented,
        expected_status: 404,
        body: "",
    },
    ApiCase {
        method: "POST",
        path: "/images/load",
        coverage: Coverage::Implemented,
        expected_status: 400,
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
        Self::spawn_env(&[])
    }

    /// Spawn with extra daemon environment variables. Network creation needs
    /// the emulated kernel-adapter state file to run without root, matching
    /// the Docker compat integration harness.
    fn spawn_env(extra_env: &[(&str, std::path::PathBuf)]) -> Self {
        let runtime_dir = tempfile::tempdir().expect("runtime tempdir");
        let socket_path = runtime_dir.path().join("docker.sock");

        let mut command = Command::new(env!("CARGO_BIN_EXE_ferro-cli"));
        command
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "daemon",
                "--docker-compat",
                "--socket",
                socket_path.to_str().expect("socket path utf8"),
            ]);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let mut child = command
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

    fn request_binary(&self, method: &str, path: &str) -> (u16, Vec<u8>) {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let mut stream = UnixStream::connect(&self.socket_path).expect("connect daemon socket");
        stream.write_all(request.as_bytes()).expect("write request");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        let separator = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("response headers");
        let status = String::from_utf8_lossy(&response[..separator])
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .expect("parse status code");
        (status, response[separator + 4..].to_vec())
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
        if case.path == "/system/df" {
            let payload: serde_json::Value =
                serde_json::from_str(&body).expect("system df response is JSON");
            assert!(
                payload
                    .get("BuildCache")
                    .is_some_and(serde_json::Value::is_array),
                "system df must project BuildCache: {body}"
            );
        }
        if case.path.starts_with("/build/prune") {
            let payload: serde_json::Value =
                serde_json::from_str(&body).expect("build prune response is JSON");
            assert!(payload.get("Removed").is_some());
            assert_eq!(payload["MaxEntries"], 64);
        }
        if case.path.ends_with("/json?size=1") {
            let payload: serde_json::Value =
                serde_json::from_str(&body).expect("size inspect response is JSON");
            assert!(payload.get("SizeRw").is_some_and(serde_json::Value::is_u64));
            assert!(payload
                .get("SizeRootFs")
                .is_some_and(serde_json::Value::is_u64));
        }
        if case.path.ends_with("/matrix-container/resize?w=80&h=24") {
            assert!(
                body.trim().is_empty(),
                "resize success must have an empty body: {body:?}"
            );
        }
        if case.path.contains("/logs?stdout=1&stderr=1") {
            assert!(
                body.trim().is_empty(),
                "created-container logs should be empty: {body:?}"
            );
        }
        if case.path.ends_with("/stats?stream=0") {
            let stats: serde_json::Value = serde_json::from_str(&body).expect("stats JSON");
            assert_eq!(stats["memory_stats"]["usage"], 0);
            assert_eq!(stats["memory_stats"]["limit"], 0);
            assert_eq!(stats["cpu_stats"]["cpu_usage"]["total_usage"], 0);
            assert_eq!(stats["pids_stats"]["current"], 0);
            assert_eq!(stats["pids_stats"]["limit_reached"], 0);
        }
        if case.path.ends_with("/matrix-container/top") {
            let top: serde_json::Value = serde_json::from_str(&body).expect("top JSON");
            assert_eq!(top["Titles"][0], "PID");
            assert!(top["Processes"]
                .as_array()
                .is_some_and(|rows| rows.is_empty()));
        }
        if case.path.ends_with("/changes") && case.path.contains("matrix-container") {
            let changes: serde_json::Value = serde_json::from_str(&body).expect("changes JSON");
            assert!(changes.as_array().is_some_and(|entries| entries.is_empty()));
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
    assert_eq!(inspect["Architecture"], "amd64", "inspect={inspect}");
    assert_eq!(inspect["Os"], "linux", "inspect={inspect}");
    assert!(inspect["Config"].is_object(), "inspect={inspect}");
    assert_eq!(inspect["RootFS"]["Type"], "layers", "inspect={inspect}");
    assert!(
        inspect["RootFS"]["Layers"]
            .as_array()
            .is_some_and(|layers| !layers.is_empty()),
        "inspect={inspect}"
    );

    let (status, body) = harness.request("GET", "/images/json", "");
    assert_eq!(status, 200, "image list response: {body}");
    let images = serde_json::from_str::<Vec<serde_json::Value>>(&body).expect("image list JSON");
    let listed = images
        .iter()
        .find(|image| {
            image["RepoTags"] == serde_json::json!(["registry-1.docker.io/matrix/build:latest"])
        })
        .expect("built image appears in image list");
    assert!(
        listed["Size"].as_u64().is_some_and(|size| size > 0),
        "image={listed}"
    );
    assert_eq!(listed["Labels"], serde_json::json!({}), "image={listed}");
    assert_eq!(listed["ParentId"], "", "image={listed}");
    let (status, body) = harness.request("GET", "/images/matrix%2Fbuild%3Alatest/history", "");
    assert_eq!(status, 200, "image history response: {body}");
    let history = serde_json::from_str::<serde_json::Value>(&body).expect("image history JSON");
    assert!(
        history.as_array().is_some_and(|layers| !layers.is_empty()),
        "history={history}"
    );

    let (status, archive) =
        harness.request_binary("GET", "/images/get?names=matrix%2Fbuild%3Alatest");
    assert_eq!(status, 200, "image get response status");
    let mut archive = tar::Archive::new(std::io::Cursor::new(archive));
    let entries = archive
        .entries()
        .expect("image export entries")
        .map(|entry| {
            entry
                .expect("image export entry")
                .path()
                .expect("entry path")
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert!(entries
        .iter()
        .any(|path| path == std::path::Path::new("manifest.json")));
    assert!(entries
        .iter()
        .any(|path| path == std::path::Path::new("repositories")));
    assert!(entries
        .iter()
        .any(|path| path.to_string_lossy().ends_with(".tar")));
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
fn plugin_management_family_reports_explicit_boundaries() {
    let harness = DaemonHarness::spawn();
    let (status, body) = harness.request("GET", "/plugins", "");
    assert_eq!(status, 404, "list status: {body}");
    assert!(
        body.contains("plugin listing is unsupported") && body.contains("signed local manifests"),
        "list body={body}"
    );

    let cases = [
        ("GET", "/plugins/audit-log", "{}"),
        ("POST", "/plugins/audit-log/enable", "{}"),
        ("POST", "/plugins/audit-log/disable", "{}"),
        ("POST", "/plugins/audit-log/upgrade", "{}"),
        ("POST", "/plugins/audit-log/set", "{}"),
        ("DELETE", "/plugins/audit-log", ""),
    ];
    for (method, path, body) in cases {
        let (status, response) = harness.request(method, path, body);
        assert_eq!(status, 404, "{method} {path}: {response}");
        assert!(
            response.contains("remote plugin management is unsupported")
                && response.contains("signed local plugin manifest"),
            "{method} {path} body={response}"
        );
    }
}

#[test]
fn unsupported_network_attachment_mutations_report_an_explicit_boundary() {
    let harness = DaemonHarness::spawn();
    for operation in ["connect", "disconnect"] {
        let path = format!("/networks/matrix-network/{operation}");
        let (status, body) = harness.request("POST", &path, "{}");
        assert_eq!(status, 404, "{operation} status: {body}");
        assert!(
            body.contains(&format!("network {operation} is unsupported"))
                && body.contains("one durable network attachment"),
            "{operation} body={body}"
        );
    }
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
    assert!(body.contains("\"ID\":\"events-volume\""), "{body}");
    assert!(body.contains("\"Name\":\"events-volume\""), "{body}");
    assert!(body.contains("\"Actor\":"), "{body}");
    assert!(body.contains("\"timeNano\":"), "{body}");
}

/// Docker clients read `/events` as newline-delimited JSON where each frame
/// carries the documented scalar fields with fixed JSON types, and the actor
/// attributes use Docker's canonical lowercase keys (`name`, `image`,
/// `driver`, `type`). Consume the response the way the Docker CLI does:
/// frame-by-frame, validating types rather than substrings.
#[test]
fn docker_events_frames_carry_docker_canonical_attribute_types() {
    let runtime_dir = tempfile::tempdir().expect("runtime tempdir");
    let kernel_state = runtime_dir.path().join("network-kernel-state.json");
    let harness = DaemonHarness::spawn_env(&[("FERROCRATE_NETWORK_KERNEL_STATE", kernel_state)]);
    let (status, _) = harness.request(
        "POST",
        "/containers/create?name=attr-container",
        r#"{"Image":"busybox","Cmd":["true"]}"#,
    );
    assert_eq!(status, 201);
    let create_body = r#"{"Name":"attr-network","Driver":"bridge","IPAM":{"Config":[]}}"#;
    let create_request = format!(
        "POST /networks/create HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, body) = harness.request_raw(&create_request);
    assert_eq!(status, 201, "network create: {body}");
    let (status, _) = harness.request("POST", "/volumes/create", r#"{"Name":"attr-volume"}"#);
    assert_eq!(status, 201);

    let (status, body) = harness.request("GET", "/events", "");
    assert_eq!(status, 200, "events response: {body}");
    let frames: Vec<serde_json::Value> = body
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("event frame must be one JSON object: {error}: {line}")
            })
        })
        .collect();
    assert!(frames.len() >= 3, "expected three create events: {body}");

    for frame in &frames {
        assert!(frame["status"].is_string(), "status: {frame}");
        assert!(frame["id"].is_string(), "id: {frame}");
        assert!(frame["from"].is_string(), "from: {frame}");
        assert!(frame["Type"].is_string(), "Type: {frame}");
        assert!(frame["Action"].is_string(), "Action: {frame}");
        assert!(frame["scope"].is_string(), "scope: {frame}");
        assert!(frame["time"].is_u64(), "time: {frame}");
        assert!(frame["timeNano"].is_u64(), "timeNano: {frame}");
        assert!(
            frame["timeNano"].as_u64().unwrap() >= frame["time"].as_u64().unwrap() * 1_000_000_000
        );
        let actor = &frame["Actor"];
        assert!(actor.is_object(), "Actor: {frame}");
        assert!(actor["ID"].is_string(), "Actor.ID: {frame}");
        let attributes = &actor["Attributes"];
        assert!(attributes.is_object(), "Actor.Attributes: {frame}");
        for (key, value) in attributes.as_object().expect("attributes object") {
            assert!(
                key.len() <= 256 && value.as_str().is_some_and(|text| text.len() <= 256),
                "attribute {key} must stay bounded and scalar: {frame}"
            );
        }
    }

    let container = frames
        .iter()
        .find(|frame| frame["Type"] == "container" && frame["Action"] == "create")
        .expect("container create event");
    assert_eq!(container["Actor"]["Attributes"]["name"], "attr-container");
    assert_eq!(container["Actor"]["Attributes"]["image"], "busybox");
    assert_eq!(container["from"], "busybox");

    let network = frames
        .iter()
        .find(|frame| frame["Type"] == "network" && frame["Action"] == "create")
        .expect("network create event");
    assert_eq!(network["Actor"]["Attributes"]["name"], "attr-network");
    assert_eq!(network["Actor"]["Attributes"]["type"], "bridge");

    let volume = frames
        .iter()
        .find(|frame| frame["Type"] == "volume" && frame["Action"] == "create")
        .expect("volume create event");
    assert_eq!(volume["Actor"]["Attributes"]["name"], "attr-volume");
    assert_eq!(volume["Actor"]["Attributes"]["driver"], "local");
}

/// The Docker CLI subscribes with `Accept: application/x-ndjson` and reads
/// chunked-transfer frames. Read one chunk like a streaming client, verify
/// the hex-size framing and the JSON payload, then drop the connection.
#[test]
fn docker_events_follow_stream_uses_chunked_jsonl_framing() {
    let harness = DaemonHarness::spawn();
    let (status, _) = harness.request("POST", "/volumes/create", r#"{"Name":"stream-volume"}"#);
    assert_eq!(status, 201);

    let mut stream = UnixStream::connect(&harness.socket_path).expect("connect daemon socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout");
    let request =
        "GET /events?follow=1 HTTP/1.1\r\nHost: docker\r\nAccept: application/x-ndjson\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .expect("write events request");

    let mut buffered = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(10);
    // Accumulate until the first chunked frame is complete: a hex length
    // line, the JSON body it announces, and the trailing CRLF.
    let frame = loop {
        if Instant::now() > deadline {
            panic!("no event chunk arrived before timeout");
        }
        if let Some(text) = parse_first_chunk(&buffered) {
            break text;
        }
        match stream.read(&mut chunk) {
            Ok(0) => panic!("stream closed before a chunk arrived: {buffered:?}"),
            Ok(read) => buffered.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                panic!("read timed out before a chunk arrived: {error}")
            }
            Err(error) => panic!("stream read failed: {error}"),
        }
    };
    let payload: serde_json::Value = serde_json::from_str(&frame)
        .unwrap_or_else(|error| panic!("chunk payload must be one JSON object: {error}: {frame}"));
    assert_eq!(payload["Type"], "volume");
    assert_eq!(payload["Action"], "create");
    assert_eq!(payload["Actor"]["ID"], "stream-volume");
    assert_eq!(payload["Actor"]["Attributes"]["name"], "stream-volume");
}

/// Extract the payload of the first complete chunked-transfer frame from a
/// buffered HTTP response, or `None` while the frame is still partial.
fn parse_first_chunk(buffered: &[u8]) -> Option<String> {
    let header_end = buffered
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let body = &buffered[header_end + 4..];
    let line_end = body.windows(2).position(|window| window == b"\r\n")?;
    let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
    let size = usize::from_str_radix(size_text, 16).ok()?;
    let frame_end = line_end + 2 + size;
    if body.len() < frame_end + 2 {
        return None;
    }
    Some(String::from_utf8_lossy(&body[line_end + 2..frame_end]).into_owned())
}

#[test]
fn docker_events_replay_since_until_bounds_and_reject_malformed_bounds() {
    let harness = DaemonHarness::spawn();
    let (status, _) = harness.request("POST", "/volumes/create", r#"{"Name":"replay-volume"}"#);
    assert_eq!(status, 201);

    let (status, body) = harness.request(
        "GET",
        "/events?type=volume&event=create&since=0&until=9999999999",
        "",
    );
    assert_eq!(status, 200, "bounded events response: {body}");
    assert!(body.contains("\"Action\":\"create\""), "{body}");

    let (status, body) = harness.request("GET", "/events?since=not-a-timestamp", "");
    assert_eq!(status, 400, "malformed since must fail closed: {body}");
    let (status, body) = harness.request("GET", "/events?until=1.1234567890", "");
    assert_eq!(status, 400, "over-precise until must fail closed: {body}");
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
    assert_eq!(inspect["NetworkSettings"]["IPAddress"], "");
    assert_eq!(
        inspect["NetworkSettings"]["Networks"]["bridge"]["NetworkID"],
        "bridge"
    );
    assert!(inspect["NetworkSettings"]["Networks"]["bridge"]["DNSNames"]
        .as_array()
        .is_some_and(|names| names.is_empty()));

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
    assert_eq!(
        inspect["NetworkSettings"]["Networks"]["bridge"]["NetworkID"],
        "bridge"
    );

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
