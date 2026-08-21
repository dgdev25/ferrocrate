#![cfg(target_os = "linux")]

#[path = "cli_integration.rs"]
mod cli_fixture;

use base64::Engine;
use std::fs;
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

fn build_local_busybox_image(harness: &DaemonHarness, tag: &str) {
    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        let dockerfile = b"FROM scratch\nCOPY --chmod=755 busybox /bin/busybox\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("Dockerfile").expect("dockerfile path");
        header.set_size(dockerfile.len() as u64);
        header.set_cksum();
        builder
            .append(&header, &dockerfile[..])
            .expect("append dockerfile");
        let busybox = fs::read("/bin/busybox").expect("host busybox fixture");
        let mut header = tar::Header::new_gnu();
        header.set_path("busybox").expect("busybox path");
        header.set_size(busybox.len() as u64);
        header.set_mode(0o755);
        header.set_uid(nix::unistd::geteuid().as_raw() as u64);
        header.set_gid(nix::unistd::getegid().as_raw() as u64);
        header.set_cksum();
        builder
            .append(&header, &busybox[..])
            .expect("append busybox");
        builder.finish().expect("finish image context");
    }
    let encoded_tag = tag
        .replace('%', "%25")
        .replace('/', "%2F")
        .replace(':', "%3A");
    let path = format!("/v1.45/build?dockerfile=Dockerfile&t={encoded_tag}");
    let (status, body) = harness.request_bytes("POST", &path, "application/x-tar", &archive);
    assert_eq!(status, 200, "local image build response={body}");
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
            .env("FERROCRATE_NETWORK_BACKEND", "iptables")
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
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        (code, body.to_string())
    }

    fn request_bytes_raw(
        &self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
    ) -> Vec<u8> {
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
        response
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
fn docker_compat_build_accepts_secure_tar_context() {
    let harness = DaemonHarness::spawn();
    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        let dockerfile = b"FROM scratch\nCOPY app /app\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("Dockerfile").unwrap();
        header.set_size(dockerfile.len() as u64);
        header.set_cksum();
        builder.append(&header, &dockerfile[..]).unwrap();
        let app = b"hello";
        let mut header = tar::Header::new_gnu();
        header.set_path("app").unwrap();
        header.set_size(app.len() as u64);
        header.set_cksum();
        builder.append(&header, &app[..]).unwrap();
        builder.finish().unwrap();
    }
    let (status, body) = harness.request_bytes(
        "POST",
        "/v1.45/build?dockerfile=Dockerfile&t=compat%2Fbuild%3Alatest",
        "application/x-tar",
        &archive,
    );
    assert_eq!(status, 200, "body={body}");
    assert!(body.contains("Successfully built"), "body={body}");
}

#[test]
fn docker_compat_image_resource_form_export_matches_query_form() {
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/export:latest");

    let raw = harness.request_bytes_raw(
        "GET",
        "/v1.45/images/compat%2Fexport%3Alatest/get",
        "application/json",
        &[],
    );
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("image export response headers");
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    assert!(headers.starts_with("HTTP/1.1 200 OK"), "headers={headers}");
    let mut archive = tar::Archive::new(&raw[header_end + 4..]);
    let entries = archive
        .entries()
        .expect("image export archive entries")
        .map(|entry| {
            entry
                .expect("image export archive entry")
                .path()
                .expect("entry path")
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert!(entries
        .iter()
        .any(|path| path == Path::new("manifest.json")));
    assert!(entries.iter().any(|path| path == Path::new("repositories")));
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
fn docker_compat_image_search_returns_local_catalog_matches() {
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "search:fixture");
    let (status, response) = harness.request("GET", "/v1.45/images/search?term=SEARCH&limit=5");
    assert_eq!(status, 200, "search response={response}");
    let results = serde_json::from_str::<Vec<serde_json::Value>>(&response).expect("search JSON");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["Index"], "local");
    assert_eq!(
        results[0]["Name"],
        "registry-1.docker.io/library/search:fixture"
    );
}

#[test]
fn docker_compat_update_changes_pending_resource_limits() {
    let harness = DaemonHarness::spawn();
    let create_body =
        r#"{"Image":"busybox","Cmd":["true"],"HostConfig":{"Memory":67108864,"PidsLimit":32}}"#;
    let (status, response) = harness.request_bytes(
        "POST",
        "/v1.45/containers/create?name=update-compat",
        "application/json",
        create_body.as_bytes(),
    );
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response).expect("create response JSON")
        ["Id"]
        .as_str()
        .expect("created id")
        .to_string();
    let (status, response) = harness.request_bytes(
        "POST",
        &format!("/v1.45/containers/{id}/update"),
        "application/json",
        br#"{"Memory":134217728,"PidsLimit":64}"#,
    );
    assert_eq!(status, 200, "update response={response}");
    assert!(response.contains("Warnings"), "update response={response}");
    let (status, response) = harness.request("GET", &format!("/v1.45/containers/{id}/json"));
    assert_eq!(status, 200, "inspect response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("inspect JSON");
    assert_eq!(inspect["HostConfig"]["Memory"], 134_217_728u64);
    assert_eq!(inspect["HostConfig"]["PidsLimit"], 64u64);
}

#[test]
fn docker_compat_update_changes_pending_restart_policy() {
    let harness = DaemonHarness::spawn();
    let create_body =
        r#"{"Image":"busybox","Cmd":["true"],"HostConfig":{"RestartPolicy":{"Name":"no"}}}"#;
    let (status, response) = harness.request_bytes(
        "POST",
        "/v1.45/containers/create?name=restart-update-compat",
        "application/json",
        create_body.as_bytes(),
    );
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response).expect("create response JSON")
        ["Id"]
        .as_str()
        .expect("created id")
        .to_string();
    let (status, response) = harness.request_bytes(
        "POST",
        &format!("/v1.45/containers/{id}/update"),
        "application/json",
        br#"{"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0}}"#,
    );
    assert_eq!(status, 200, "update response={response}");
    let (status, response) = harness.request("GET", &format!("/v1.45/containers/{id}/json"));
    assert_eq!(status, 200, "inspect response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("inspect JSON");
    assert_eq!(
        inspect["HostConfig"]["RestartPolicy"]["Name"],
        "unless-stopped"
    );
    assert_eq!(
        inspect["HostConfig"]["RestartPolicy"]["MaximumRetryCount"],
        0
    );
}

#[test]
fn docker_compat_update_combines_limits_and_restart_policy() {
    let harness = DaemonHarness::spawn();
    let create_body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let (status, response) = harness.request_bytes(
        "POST",
        "/v1.45/containers/create?name=combined-update-compat",
        "application/json",
        create_body.as_bytes(),
    );
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response).expect("create response JSON")
        ["Id"]
        .as_str()
        .expect("created id")
        .to_string();
    let (status, response) = harness.request_bytes(
        "POST",
        &format!("/v1.45/containers/{id}/update"),
        "application/json",
        br#"{"Memory":67108864,"PidsLimit":32,"RestartPolicy":{"Name":"always","MaximumRetryCount":0}}"#,
    );
    assert_eq!(status, 200, "update response={response}");
    let (status, response) = harness.request("GET", &format!("/v1.45/containers/{id}/json"));
    assert_eq!(status, 200, "inspect response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("inspect JSON");
    assert_eq!(inspect["HostConfig"]["Memory"], 67_108_864u64);
    assert_eq!(inspect["HostConfig"]["PidsLimit"], 32u64);
    assert_eq!(inspect["HostConfig"]["RestartPolicy"]["Name"], "always");
}

#[test]
fn docker_compat_inspect_uses_rfc3339_started_at() {
    let harness = DaemonHarness::spawn();
    let body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=inspect-time HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();
    let (status, response) = harness.request("GET", &format!("/v1.45/containers/{id}/json"));
    assert_eq!(status, 200, "inspect response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("inspect JSON");
    let started_at = inspect["State"]["StartedAt"]
        .as_str()
        .expect("StartedAt must be an RFC3339 string");
    assert!(started_at.contains('T'), "StartedAt={started_at}");
    assert!(started_at.ends_with('Z'), "StartedAt={started_at}");
}

#[test]
fn docker_compat_logs_for_created_container_returns_empty_success() {
    let harness = DaemonHarness::spawn();
    let body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=logs-created HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();
    let (status, response) = harness.request("GET", &format!("/v1.45/containers/{id}/logs"));
    assert_eq!(status, 200, "logs response={response}");
    assert!(
        response.is_empty(),
        "created container logs should be empty"
    );
}

#[test]
fn docker_compat_changes_for_created_container_returns_empty_success() {
    let harness = DaemonHarness::spawn();
    let body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=changes-created HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();
    let (status, response) = harness.request("GET", &format!("/v1.45/containers/{id}/changes"));
    assert_eq!(status, 200, "changes response={response}");
    assert_eq!(response, "[]");
}

#[test]
fn docker_compat_changes_reports_added_rootfs_entries() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping rootfs diff fixture: rootful image materialization is covered by the dedicated OCI lifecycle gate");
        return;
    }
    let harness = DaemonHarness::spawn();
    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        let dockerfile = b"FROM scratch\nCOPY busybox /bin/busybox\nCOPY app /app\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("Dockerfile").expect("dockerfile path");
        header.set_size(dockerfile.len() as u64);
        header.set_cksum();
        builder
            .append(&header, &dockerfile[..])
            .expect("append dockerfile");
        let busybox = fs::read("/bin/busybox").expect("host busybox fixture");
        let mut header = tar::Header::new_gnu();
        header.set_path("busybox").expect("busybox path");
        header.set_size(busybox.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append(&header, &busybox[..])
            .expect("append busybox");
        let app = b"baseline";
        let mut header = tar::Header::new_gnu();
        header.set_path("app").expect("app path");
        header.set_size(app.len() as u64);
        header.set_cksum();
        builder.append(&header, &app[..]).expect("append app");
        builder.finish().expect("finish context");
    }
    let (status, body) = harness.request_bytes(
        "POST",
        "/v1.45/build?dockerfile=Dockerfile&t=compat%2Fchanges%3Alatest",
        "application/x-tar",
        &archive,
    );
    assert_eq!(status, 200, "build response={body}");

    let create_body = r#"{"Image":"compat/changes:latest","Cmd":["/bin/busybox","true"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=changes-added HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, body) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response={body}");
    let id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();

    // The runtime materializes an image rootfs at the first lifecycle
    // transition; this scratch fixture intentionally has no executable, so
    // the start result itself is not part of this diff contract.
    let start = harness.request("POST", &format!("/v1.45/containers/{id}/start"));
    assert_eq!(start.0, 204, "start response={}", start.1);

    let rootfs = harness
        ._runtime_dir
        .path()
        .join("containers")
        .join(&id)
        .join("rootfs");
    assert!(
        rootfs.is_dir(),
        "created rootfs missing: {}",
        rootfs.display()
    );
    let mut put_archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut put_archive);
        let payload = b"written through the Docker archive API";
        let mut header = tar::Header::new_gnu();
        header.set_path("added").expect("archive path");
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder
            .append(&header, &payload[..])
            .expect("append archive payload");
        builder.finish().expect("finish put archive");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        &format!("/v1.45/containers/{id}/archive?path=%2F"),
        "application/x-tar",
        &put_archive,
    );
    assert_eq!(status, 200, "put archive response={body}");
    assert_eq!(
        fs::read(rootfs.join("added")).expect("archive output"),
        b"written through the Docker archive API"
    );
    let raw = harness.request_bytes_raw(
        "GET",
        &format!("/v1.45/containers/{id}/archive?path=%2Fadded"),
        "application/x-tar",
        &[],
    );
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("archive response headers");
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let stat = headers
        .lines()
        .find_map(|line| line.strip_prefix("X-Docker-Container-Path-Stat: "))
        .expect("Docker archive path-stat header");
    let stat = base64::engine::general_purpose::STANDARD
        .decode(stat)
        .expect("decode path-stat header");
    let stat: serde_json::Value = serde_json::from_slice(&stat).expect("path-stat JSON");
    assert_eq!(stat["name"], "added");
    let mut archive = tar::Archive::new(&raw[header_end + 4..]);
    let mut entries = archive.entries().expect("archive entries");
    let entry = entries
        .next()
        .expect("file archive entry")
        .expect("file archive entry decode");
    assert_eq!(entry.path().expect("file archive path"), Path::new("added"));
    let root_raw = harness.request_bytes_raw(
        "GET",
        &format!("/v1.45/containers/{id}/archive?path=%2F"),
        "application/x-tar",
        &[],
    );
    let root_header_end = root_raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("root archive response headers");
    let root_headers = String::from_utf8_lossy(&root_raw[..root_header_end]);
    assert!(root_headers.starts_with("HTTP/1.1 200 OK"));
    let root_stat = root_headers
        .lines()
        .find_map(|line| line.strip_prefix("X-Docker-Container-Path-Stat: "))
        .expect("root path-stat header");
    let root_stat = base64::engine::general_purpose::STANDARD
        .decode(root_stat)
        .expect("decode root path-stat header");
    let root_stat: serde_json::Value =
        serde_json::from_slice(&root_stat).expect("root path-stat JSON");
    assert_eq!(root_stat["name"], "/");
    assert!(root_stat["mode"].as_u64().unwrap_or_default() & (1u64 << 31) != 0);
    let head_raw = harness.request_bytes_raw(
        "HEAD",
        &format!("/v1.45/containers/{id}/archive?path=%2F"),
        "application/x-tar",
        &[],
    );
    let head_end = head_raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HEAD archive response headers");
    let head_headers = String::from_utf8_lossy(&head_raw[..head_end]);
    assert!(head_headers.starts_with("HTTP/1.1 200 OK"));
    assert!(head_headers
        .lines()
        .any(|line| line.starts_with("X-Docker-Container-Path-Stat: ")));

    let (status, body) = harness.request("GET", &format!("/v1.45/containers/{id}/changes"));
    assert_eq!(status, 200, "changes response={body}");
    let changes = serde_json::from_str::<Vec<serde_json::Value>>(&body).expect("changes JSON");
    assert!(
        changes
            .iter()
            .any(|change| change["Path"] == "/added" && change["Kind"] == 1),
        "added entry missing from changes: {changes:?}"
    );
}

#[test]
fn docker_compat_removes_created_container_by_name_before_start() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping rootful pending-container name fixture");
        return;
    }
    let harness = DaemonHarness::spawn();
    let create_body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=pending-name HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response={response}");
    let id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create response JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("created id")
        .to_string();

    let (status, response) = harness.request("GET", "/v1.45/containers/pending-name/json");
    assert_eq!(status, 200, "name inspect response={response}");
    let inspected = serde_json::from_str::<serde_json::Value>(&response).expect("inspect JSON");
    assert_eq!(inspected["Id"], id, "inspect must preserve provisional ID");

    let (status, response) = harness.request("GET", "/v1.45/containers/pending-name/changes");
    assert_eq!(status, 200, "name changes response={response}");
    assert_eq!(response, "[]", "pending changes should be empty");
    let (status, response) = harness.request("GET", "/v1.45/containers/pending-name/logs");
    assert_eq!(status, 200, "name logs response={response}");
    assert!(response.is_empty(), "pending logs should be empty");
    let (status, response) = harness.request(
        "POST",
        "/v1.45/containers/pending-name/wait?condition=removed",
    );
    assert_eq!(status, 200, "name wait response={response}");

    let (status, response) = harness.request("DELETE", "/v1.45/containers/pending-name");
    assert_eq!(status, 204, "name removal response={response}");
    let (status, response) = harness.request("DELETE", &format!("/v1.45/containers/{id}"));
    assert_eq!(status, 404, "removed id response={response}");
}

#[test]
fn docker_compat_exec_inspect_reports_created_exec_state() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping rootful exec-inspect fixture: rootful image materialization is covered by the dedicated OCI lifecycle gate");
        return;
    }
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/exec:latest");
    let create_body = r#"{"Image":"compat/exec:latest","Cmd":["/bin/busybox","true"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create_request = format!(
        "POST /v1.45/containers/create?name=exec-inspect HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create_request);
    assert_eq!(status, 201, "create response={response}");
    let container_id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("create response JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("created id")
        .to_string();

    let (status, response) = harness.request("POST", "/v1.45/containers/exec-inspect/start");
    assert_eq!(status, 204, "container start response={response}");

    let (status, response) = harness.request("GET", "/v1.45/containers/exec-inspect/json");
    assert_eq!(status, 200, "post-start name inspect response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("name inspect JSON");
    assert_eq!(inspect["Id"], container_id);
    let (status, response) = harness.request("GET", "/v1.45/containers/exec-inspect/logs");
    assert_eq!(status, 200, "post-start name logs response={response}");
    let (status, response) = harness.request("GET", "/v1.45/containers/exec-inspect/changes");
    assert_eq!(status, 200, "post-start name changes response={response}");
    assert!(response.starts_with('['), "changes response={response}");
    let (status, response) = harness.request(
        "POST",
        "/v1.45/containers/exec-inspect/wait?condition=not-running",
    );
    assert_eq!(status, 200, "post-start name wait response={response}");
    let wait = serde_json::from_str::<serde_json::Value>(&response).expect("wait JSON");
    assert!(wait.get("StatusCode").is_some(), "wait response={response}");
    let (status, response) = harness.request(
        "POST",
        "/v1.45/containers/exec-inspect/attach?logs=0&stream=0",
    );
    assert_eq!(status, 200, "post-start name attach response={response}");
    assert!(
        response.is_empty(),
        "logs=0 attach should be empty: {response:?}"
    );

    let exec_body = r#"{"Cmd":["/bin/busybox","true"]}"#;
    let exec_request = format!(
        "POST /v1.45/containers/exec-inspect/exec HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        exec_body.len(),
        exec_body
    );
    let (status, response) = harness.request_raw(&exec_request);
    assert_eq!(status, 201, "exec create response={response}");
    let exec_id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("exec create response JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("exec id")
        .to_string();

    let (status, response) = harness.request("GET", &format!("/v1.45/exec/{exec_id}/json"));
    assert_eq!(status, 200, "exec inspect response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("exec inspect JSON");
    assert_eq!(inspect["ID"], exec_id);
    assert_eq!(inspect["ContainerID"], container_id);
    assert_eq!(inspect["Running"], false);
    assert_eq!(inspect["ExitCode"], serde_json::Value::Null);

    let (status, response) = harness.request("POST", &format!("/v1.45/exec/{exec_id}/start"));
    assert_eq!(status, 200, "exec start response={response}");
    let (status, response) = harness.request("GET", &format!("/v1.45/exec/{exec_id}/json"));
    assert_eq!(status, 200, "exec inspect after start response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("exec inspect JSON");
    assert_eq!(inspect["Running"], false);
    assert!(
        inspect["ExitCode"].is_i64(),
        "exit code={}",
        inspect["ExitCode"]
    );

    // Detached exec must acknowledge immediately and publish completion through
    // exec inspect rather than holding the HTTP request until the workload exits.
    let detached_body = r#"{"Cmd":["/bin/busybox","sleep","1"]}"#;
    let detached_request = format!(
        "POST /v1.45/containers/exec-inspect/exec HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        detached_body.len(),
        detached_body
    );
    let (status, response) = harness.request_raw(&detached_request);
    assert_eq!(status, 201, "detached exec create response={response}");
    let detached_id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("detached exec create response JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("detached exec id")
        .to_string();
    let started = std::time::Instant::now();
    let detached_start_body = r#"{"Detach":true}"#;
    let detached_start_request = format!(
        "POST /v1.45/exec/{detached_id}/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        detached_start_body.len(),
        detached_start_body
    );
    let (status, response) = harness.request_raw(&detached_start_request);
    assert_eq!(status, 200, "detached exec start response={response}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "detached exec request waited for workload: {:?}",
        started.elapsed()
    );
    let mut completed = false;
    while started.elapsed() < std::time::Duration::from_secs(3) {
        let (status, response) = harness.request("GET", &format!("/v1.45/exec/{detached_id}/json"));
        assert_eq!(status, 200, "detached exec inspect response={response}");
        let inspect = serde_json::from_str::<serde_json::Value>(&response)
            .expect("detached exec inspect JSON");
        if inspect["Running"] == serde_json::Value::Bool(false) && inspect["ExitCode"].is_i64() {
            completed = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(completed, "detached exec did not publish completion");

    let (status, response) = harness.request("DELETE", "/v1.45/containers/exec-inspect");
    assert_eq!(status, 204, "post-start name removal response={response}");
}

#[test]
fn docker_compat_rootful_exec_tty_uses_public_socket() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipping rootful TTY exec fixture: requires root");
        return;
    }
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/tty-exec:latest");
    let create_body = r#"{"Image":"compat/tty-exec:latest","Cmd":["/bin/busybox","sleep","5"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create_request = format!(
        "POST /v1.45/containers/create?name=tty-exec HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create_request);
    assert_eq!(status, 201, "TTY container create response={response}");
    let (status, response) = harness.request("POST", "/v1.45/containers/tty-exec/start");
    assert_eq!(status, 204, "TTY container start response={response}");

    let exec_body = r#"{"Cmd":["/bin/busybox","sh","-c","test -t 1 && printf tty"],"Tty":true}"#;
    let exec_request = format!(
        "POST /v1.45/containers/tty-exec/exec HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        exec_body.len(),
        exec_body
    );
    let (status, response) = harness.request_raw(&exec_request);
    assert_eq!(status, 201, "TTY exec create response={response}");
    let exec_id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("TTY exec create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("TTY exec id")
        .to_string();
    let start_body = r#"{"Tty":true}"#;
    let start_request = format!(
        "POST /v1.45/exec/{exec_id}/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        start_body.len(),
        start_body
    );
    let (status, response) = harness.request_raw(&start_request);
    assert_eq!(status, 200, "TTY exec start response={response}");
    assert!(response.contains("tty"), "TTY exec output={response:?}");

    let (status, response) = harness.request("DELETE", "/v1.45/containers/tty-exec?force=true");
    assert_eq!(status, 204, "TTY container cleanup response={response}");
}

#[test]
fn docker_compat_rootful_tty_container_create_start_and_logs() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipping rootful TTY container fixture: requires root");
        return;
    }
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/tty-container:latest");
    let create_body = r#"{"Image":"compat/tty-container:latest","Cmd":["/bin/busybox","sh","-c","printf tty-container; sleep 1"],"Tty":true,"HostConfig":{"NetworkMode":"none"}}"#;
    let create_request = format!(
        "POST /v1.45/containers/create?name=tty-container HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create_request);
    assert_eq!(status, 201, "TTY container create response={response}");

    let (status, response) = harness.request("GET", "/v1.45/containers/tty-container/json");
    assert_eq!(status, 200, "TTY container inspect response={response}");
    let inspect: serde_json::Value = serde_json::from_str(&response).expect("TTY inspect JSON");
    assert_eq!(inspect["Config"]["Tty"], true, "inspect={inspect}");

    let (status, response) = harness.request("POST", "/v1.45/containers/tty-container/start");
    assert_eq!(status, 204, "TTY container start response={response}");

    let (status, response) =
        harness.request("POST", "/v1.45/containers/tty-container/resize?w=100&h=40");
    assert_eq!(status, 200, "TTY container resize response={response}");

    let mut logs = String::new();
    for _ in 0..40 {
        let (status, response) = harness.request(
            "GET",
            "/v1.45/containers/tty-container/logs?stdout=1&stderr=1",
        );
        assert_eq!(status, 200, "TTY container logs response={response}");
        if response.contains("tty-container") {
            logs = response;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(logs.contains("tty-container"), "TTY logs={logs:?}");

    let (status, response) =
        harness.request("DELETE", "/v1.45/containers/tty-container?force=true");
    assert_eq!(status, 204, "TTY container cleanup response={response}");
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
    let read = stream
        .read(&mut response)
        .expect("read event stream headers");
    let headers = String::from_utf8_lossy(&response[..read]);
    assert!(
        headers.contains("Transfer-Encoding: chunked"),
        "headers={headers}"
    );
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
fn docker_compat_attach_validates_stdin_flag() {
    let harness = DaemonHarness::spawn();
    let body = r#"{"Image":"busybox","Cmd":["true"]}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=attach-stdin-validation HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

    let (status, response) = harness.request(
        "POST",
        &format!("/v1.45/containers/{id}/attach?stdin=maybe"),
    );
    assert_eq!(status, 400, "invalid stdin must fail closed: {response}");
    assert!(
        response.contains("stdin must be a boolean"),
        "body={response}"
    );
}

#[test]
fn docker_compat_attach_forwards_stdin_over_hijacked_socket() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping rootful attach-stdin fixture: rootful image materialization is covered by the dedicated OCI lifecycle gate");
        return;
    }
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/attach-stdin:latest");
    let create_body = r#"{"Image":"compat/attach-stdin:latest","Cmd":["/bin/busybox","sh","-c","read line; echo received:$line; sleep 2"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=attach-stdin-wire HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "create response: {response}");

    let start = harness.request("POST", "/v1.45/containers/attach-stdin-wire/start");
    assert_eq!(start.0, 204, "start response: {}", start.1);
    let inspect = harness.request("GET", "/v1.45/containers/attach-stdin-wire/json");
    assert_eq!(inspect.0, 200, "inspect response: {}", inspect.1);
    let _ = serde_json::from_str::<serde_json::Value>(&inspect.1).expect("inspect JSON");

    let mut stream = UnixStream::connect(&harness.socket_path).expect("connect attach socket");
    stream
        .write_all(
            "POST /v1.45/containers/attach-stdin-wire/attach?logs=0&stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n".as_bytes(),
        )
        .expect("write attach handshake");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set attach timeout");
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read attach headers");
        headers.push(byte[0]);
        assert!(headers.len() < 4096, "attach headers are unbounded");
    }
    let header_text = String::from_utf8_lossy(&headers);
    assert!(
        header_text.starts_with("HTTP/1.1 101"),
        "headers={header_text}"
    );

    stream
        .write_all(b"ferrocrate-fifo\n")
        .expect("write attach stdin");
    stream.flush().expect("flush attach stdin");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut output = Vec::new();
    while Instant::now() < deadline
        && !output
            .windows(b"received:ferrocrate-fifo".len())
            .any(|window| window == b"received:ferrocrate-fifo")
    {
        let mut chunk = [0_u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => output.extend_from_slice(&chunk[..size]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("read attach output: {error}"),
        }
    }
    assert!(
        output
            .windows(b"received:ferrocrate-fifo".len())
            .any(|window| window == b"received:ferrocrate-fifo"),
        "attach output did not include stdin payload: {:?}",
        String::from_utf8_lossy(&output)
    );

    let (status, body) =
        harness.request("DELETE", "/v1.45/containers/attach-stdin-wire?force=true");
    assert_eq!(status, 204, "remove response: {body}");
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
    if nix::unistd::geteuid().is_root() {
        assert_eq!(
            status, 201,
            "root administrator must be allowed: {response}"
        );
        let after = harness.kernel_state();
        assert_eq!(after.effect_count, 1);
        assert_eq!(after.bridges.len(), 1);
        return;
    }
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
    if nix::unistd::geteuid().is_root() {
        assert_eq!(
            status, 201,
            "root administrator must be allowed: {response}"
        );
        assert!(response.contains("enforce-compat-volume"));
        return;
    }
    assert_eq!(status, 500, "stable enforce response: {response}");
    assert!(
        response.contains("PolicyDenied"),
        "stable enforce response: {response}"
    );
}
