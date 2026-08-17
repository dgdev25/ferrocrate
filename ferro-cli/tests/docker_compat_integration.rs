#![cfg(target_os = "linux")]

#[path = "cli_integration.rs"]
mod cli_fixture;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Snapshot of the file-backed emulated network kernel used by the daemon
/// under `FERROCRATE_NETWORK_KERNEL_STATE`. Mirrors the production state file
/// shape so tests can prove create/delete effects without CAP_NET_ADMIN.
#[derive(Debug, Clone, serde::Deserialize, Default)]
struct KernelStateFile {
    #[serde(default)]
    effect_count: u32,
    #[serde(default)]
    bridges: std::collections::BTreeMap<String, KernelBridgeIdentity>,
}

#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
struct KernelBridgeIdentity {
    name: String,
    ifindex: Option<u32>,
    cidr: Option<String>,
    ipv6_cidr: Option<String>,
}

fn load_kernel_state(path: &Path) -> KernelStateFile {
    if !path.exists() {
        return KernelStateFile::default();
    }
    let raw = std::fs::read_to_string(path).expect("read kernel state file");
    if raw.trim().is_empty() {
        return KernelStateFile::default();
    }
    serde_json::from_str(&raw).expect("parse kernel state file")
}

struct DaemonHarness {
    child: Child,
    _runtime_dir: tempfile::TempDir,
    socket_path: PathBuf,
    kernel_state_path: PathBuf,
}

impl Drop for DaemonHarness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DaemonHarness {
    fn spawn() -> Self {
        Self::spawn_mode("disabled")
    }

    fn spawn_mode(mode: &str) -> Self {
        let runtime_dir = cli_fixture::configured_runtime(mode);
        let socket_path = runtime_dir.path().join("docker.sock");
        // Private per-daemon state file: only active because the env var is set.
        let kernel_state_path = runtime_dir.path().join("network-kernel-state.json");

        let mut child = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .env(
                "FERROCRATE_NETWORK_KERNEL_STATE",
                kernel_state_path.as_os_str(),
            )
            .env(
                "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
                format!("docker-{mode}"),
            )
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
                    kernel_state_path,
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

    fn kernel_state(&self) -> KernelStateFile {
        load_kernel_state(&self.kernel_state_path)
    }

    fn request(&self, method: &str, path: &str) -> (u16, String) {
        let request =
            format!("{method} {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n");
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
fn docker_compat_rename_uses_docker_name_query_parameter() {
    let harness = DaemonHarness::spawn();

    let (status, body) = harness.request(
        "POST",
        "/v1.45/containers/missing/rename?name=renamed-container",
    );
    assert_eq!(
        status, 404,
        "a valid rename request should reach lookup: {body}"
    );

    let (status, body) = harness.request("POST", "/v1.45/containers/missing/rename");
    assert_eq!(status, 400);
    assert!(body.contains("name query parameter"), "body={body}");

    let raw = "POST /v1.45/containers/missing/rename HTTP/1.1\r\nHost: docker\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{\"name\":\"legacy-body\"}";
    let (status, body) = harness.request_raw(raw);
    assert_eq!(status, 400);
    assert!(body.contains("name query parameter"), "body={body}");
}

#[test]
fn docker_compat_events_accepts_docker_cli_scalar_filter_values() {
    let harness = DaemonHarness::spawn();
    let (status, body) = harness.request(
        "GET",
        "/v1.45/events?filters=%7B%22type%22%3A%7B%22network%22%3Atrue%7D%7D",
    );
    assert_eq!(status, 200, "body={body}");
}

#[test]
fn docker_compat_create_persists_host_resource_limits_before_start() {
    let harness = DaemonHarness::spawn();
    let create_body = r#"{"Image":"busybox","Cmd":["true"],"HostConfig":{"Memory":67108864,"CpuQuota":50000,"CpuPeriod":100000,"PidsLimit":32}}"#;
    let create_request = format!(
        "POST /v1.45/containers/create?name=limited-compat HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create_request);
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create response JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("created id")
        .to_string();

    let (status, inspect) = harness.request("GET", &format!("/v1.45/containers/{id}/json"));
    assert_eq!(status, 200, "inspect response={inspect}");
    let inspect = serde_json::from_str::<serde_json::Value>(&inspect).expect("inspect JSON");
    assert_eq!(inspect["HostConfig"]["Memory"], 67_108_864u64);
    assert_eq!(inspect["HostConfig"]["CpuQuota"], 50_000u64);
    assert_eq!(inspect["HostConfig"]["CpuPeriod"], 100_000u64);
    assert_eq!(inspect["HostConfig"]["PidsLimit"], 32u64);
}

#[test]
fn docker_compat_events_uses_chunked_stream_for_docker_cli_accept_header() {
    let harness = DaemonHarness::spawn();
    let mut stream = UnixStream::connect(&harness.socket_path).expect("connect event stream");
    stream
        .write_all(
            b"GET /v1.45/events?filters=%7B%22type%22%3A%7B%22network%22%3Atrue%7D%7D HTTP/1.1\r\nHost: docker\r\nAccept: application/jsonl\r\nConnection: close\r\n\r\n",
        )
        .expect("write event stream request");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set event stream read timeout");
    let mut response = [0u8; 512];
    let read = stream.read(&mut response).expect("read event stream headers");
    let headers = String::from_utf8_lossy(&response[..read]);
    assert!(headers.contains("Transfer-Encoding: chunked"), "headers={headers}");
}

#[test]
fn docker_compat_attach_accepts_pre_start_hijack_handshake() {
    let harness = DaemonHarness::spawn();
    let body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=attach-before-start HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response: {response}");
    let id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();

    let attach = format!(
        "POST /v1.45/containers/{id}/attach?logs=1&stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n"
    );
    let (status, response) = harness.request_raw(&attach);
    assert_eq!(status, 101, "attach handshake response: {response}");
}

#[test]
fn docker_compat_attach_logs_zero_does_not_emit_history() {
    let harness = DaemonHarness::spawn();
    let body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=attach-quiet HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response: {response}");
    let id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();
    let (status, body) = harness.request(
        "POST",
        &format!("/v1.45/containers/{id}/attach?logs=0&stream=0"),
    );
    assert_eq!(status, 200, "attach response: {body}");
    assert!(body.is_empty(), "logs=0 must not emit history: {body:?}");
}

#[test]
fn docker_compat_listing_accepts_docker_cli_boolean_keyed_filters() {
    let harness = DaemonHarness::spawn();
    for path in [
        "/v1.45/networks?filters=%7B%22name%22%3A%7B%22foo%22%3Atrue%7D%7D",
        "/v1.45/containers/json?filters=%7B%22status%22%3A%7B%22running%22%3Atrue%7D%7D",
        "/v1.45/images/json?filters=%7B%22reference%22%3A%7B%22foo%22%3Atrue%7D%7D",
    ] {
        let (status, body) = harness.request("GET", path);
        assert_eq!(status, 200, "path={path} body={body}");
    }
}

#[test]
fn docker_compat_commit_requires_container_and_repository() {
    let harness = DaemonHarness::spawn();
    let (status, body) = harness.request("POST", "/v1.45/commit");
    assert_eq!(status, 400, "body={body}");
    assert!(body.contains("commit requires container"), "body={body}");

    let (status, body) = harness.request("POST", "/v1.45/commit?container=missing");
    assert_eq!(status, 400, "body={body}");
    assert!(body.contains("commit requires repo"), "body={body}");
}

#[test]
fn docker_compat_malformed_content_length_returns_400_json_error() {
    let harness = DaemonHarness::spawn();
    let raw =
        "POST /v1.45/containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: nope\r\n\r\n";
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
    assert!(
        create_resp.contains("\"Id\":\"compat-net\""),
        "body={create_resp}"
    );

    let (list_status, list_resp) = harness.request("GET", "/v1.45/networks");
    assert_eq!(list_status, 200, "list body={list_resp}");
    assert!(
        list_resp.contains("\"Name\":\"compat-net\""),
        "body={list_resp}"
    );

    let (delete_status, delete_resp) = harness.request("DELETE", "/v1.45/networks/compat-net");
    assert_eq!(delete_status, 204, "delete body={delete_resp}");
}

#[test]
fn docker_compat_dual_stack_network_preserves_ipv6_ipam_on_list_and_inspect() {
    let harness = DaemonHarness::spawn();
    let create_body = r#"{
        "Name":"dual-stack-compat",
        "Driver":"bridge",
        "EnableIPv6":true,
        "IPAM":{"Config":[
            {"Subnet":"10.99.0.0/24","Gateway":"10.99.0.1"},
            {"Subnet":"fd42:99::/64","Gateway":"fd42:99::1"}
        ]}
    }"#;
    let create_request = format!(
        "POST /v1.45/networks/create HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, body) = harness.request_raw(&create_request);
    assert_eq!(status, 201, "create body={body}");

    for path in ["/v1.45/networks", "/v1.45/networks/dual-stack-compat"] {
        let (status, body) = harness.request("GET", path);
        assert_eq!(status, 200, "path={path} body={body}");
        assert!(body.contains("fd42:99::/64"), "path={path} body={body}");
        assert!(body.contains("fd42:99::1"), "path={path} body={body}");
    }
}

/// Docker create/delete must drive the shared lifecycle kernel adapter and leave
/// durable exact-identity effects in the emulated state file.
#[test]
fn docker_compat_network_create_delete_cause_kernel_effects() {
    let harness = DaemonHarness::spawn();
    let before = harness.kernel_state();
    assert_eq!(before.effect_count, 0, "no effects before create");
    assert!(before.bridges.is_empty(), "no bridges before create");

    let create_body = r#"{
        "Name":"kernel-effect-net",
        "Driver":"bridge",
        "IPAM":{"Config":[{"Subnet":"172.45.0.0/16","Gateway":"172.45.0.1"}]}
    }"#;
    let create_request = format!(
        "POST /v1.45/networks/create HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (create_status, create_resp) = harness.request_raw(&create_request);
    assert_eq!(create_status, 201, "create body={create_resp}");

    let after_create = harness.kernel_state();
    assert!(
        after_create.effect_count >= 1,
        "create must record at least one kernel effect, state={after_create:?}"
    );
    assert_eq!(
        after_create.bridges.len(),
        1,
        "create must persist one bridge identity, state={after_create:?}"
    );
    let (bridge_name, identity) = after_create
        .bridges
        .iter()
        .next()
        .expect("created bridge identity");
    assert!(
        bridge_name.starts_with("fc-") && bridge_name.len() == 15,
        "canonical bridge name, got {bridge_name}"
    );
    assert_eq!(identity.name, *bridge_name);
    assert!(
        identity.ifindex.is_some_and(|idx| idx != 0),
        "exact observed ifindex required, got {identity:?}"
    );
    // Kernel bridge identity carries bridge_cidr (gateway/prefix), not the
    // logical subnet alone.
    assert_eq!(
        identity.cidr.as_deref(),
        Some("172.45.0.1/16"),
        "exact bridge cidr persisted, got {identity:?}"
    );
    let create_effects = after_create.effect_count;
    let created_identity = identity.clone();

    let (delete_status, delete_resp) =
        harness.request("DELETE", "/v1.45/networks/kernel-effect-net");
    assert_eq!(delete_status, 204, "delete body={delete_resp}");

    let after_delete = harness.kernel_state();
    assert!(
        after_delete.effect_count > create_effects,
        "delete must record an additional kernel effect ({create_effects} -> {})",
        after_delete.effect_count
    );
    assert!(
        after_delete.bridges.is_empty(),
        "delete must remove exact identity {:?}, remaining={:?}",
        created_identity,
        after_delete.bridges
    );
}

/// Enforce-mode denial must reject Docker network create before any kernel
/// mutation, leaving the emulated state file empty of effects.
#[test]
fn docker_compat_network_enforce_denial_causes_zero_kernel_effects() {
    let harness = DaemonHarness::spawn_mode("enforce");
    let before = harness.kernel_state();
    assert_eq!(before.effect_count, 0);
    assert!(before.bridges.is_empty());

    let create_body = r#"{
        "Name":"enforce-kernel-net",
        "Driver":"bridge",
        "IPAM":{"Config":[{"Subnet":"172.46.0.0/16","Gateway":"172.46.0.1"}]}
    }"#;
    let create_request = format!(
        "POST /v1.45/networks/create HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create_request);
    assert_eq!(status, 500, "stable enforce response: {response}");
    assert!(
        response.contains("PolicyDenied"),
        "stable enforce response: {response}"
    );

    let after = harness.kernel_state();
    assert_eq!(
        after.effect_count, 0,
        "enforce denial must leave zero kernel effects, state={after:?}"
    );
    assert!(
        after.bridges.is_empty(),
        "enforce denial must leave no bridge identities, state={after:?}"
    );
    assert!(
        !harness.kernel_state_path.exists() || after.effect_count == 0,
        "no mutation path may create effects under enforce denial"
    );
}

#[test]
fn docker_compat_volume_create_delete_routes_are_mediated() {
    let harness = DaemonHarness::spawn();
    let body = r#"{"Name":"compat-volume","Driver":"local","DriverOpts":{}}"#;
    let request = format!(
        "POST /v1.45/volumes/create HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    let (status, response) = harness.request_raw(&request);
    assert_eq!(status, 201, "create body={response}");
    assert!(response.contains("compat-volume"), "body={response}");

    let (status, response) = harness.request("DELETE", "/v1.45/volumes/compat-volume");
    assert_eq!(status, 204, "delete body={response}");
}

#[test]
fn docker_compat_volume_mutation_preserves_disabled_shadow_and_enforce_contracts() {
    for mode in ["disabled", "shadow"] {
        let harness = DaemonHarness::spawn_mode(mode);
        let body =
            format!(r#"{{"Name":"{mode}-compat-volume","Driver":"local","DriverOpts":{{}}}}"#);
        let request = format!(
            "POST /v1.45/volumes/create HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(), body
        );
        let (status, response) = harness.request_raw(&request);
        assert_eq!(status, 201, "{mode}: {response}");
    }
    let harness = DaemonHarness::spawn_mode("enforce");
    let body = r#"{"Name":"enforce-compat-volume","Driver":"local","DriverOpts":{}}"#;
    let request = format!(
        "POST /v1.45/volumes/create HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    let (status, response) = harness.request_raw(&request);
    assert_eq!(status, 500, "stable enforce response: {response}");
    assert!(
        response.contains("PolicyDenied"),
        "stable enforce response: {response}"
    );
}
