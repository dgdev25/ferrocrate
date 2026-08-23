#![cfg(target_os = "linux")]

#[path = "cli_integration.rs"]
mod cli_fixture;

use base64::Engine;
use sha2::Digest;
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
fn docker_container_list_projects_identity_labels_ports_networks_and_mounts() {
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/list-wire:latest");

    let (images_status, images_body) = harness.request("GET", "/v1.45/images/json");
    assert_eq!(images_status, 200, "images response: {images_body}");
    let images: serde_json::Value = serde_json::from_str(&images_body).expect("images JSON");
    let image_id = images
        .as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry["Id"].as_str())
        .expect("built image ID");

    let create_body = r#"{
        "Image":"compat/list-wire:latest",
        "Cmd":["true"],
        "Labels":{"com.docker.compose.project":"wire-test"},
        "HostConfig":{
            "Binds":["/tmp:/workspace:ro"],
            "PortBindings":{"8080/tcp":[{"HostPort":"18080"}]},
            "NetworkMode":"bridge"
        }
    }"#;
    let create_request = format!(
        "POST /v1.45/containers/create?name=wire-list HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (create_status, create_response) = harness.request_raw(&create_request);
    assert_eq!(create_status, 201, "create response: {create_response}");

    let (list_status, list_body) = harness.request("GET", "/v1.45/containers/json?all=1");
    assert_eq!(list_status, 200, "list response: {list_body}");
    let entries: serde_json::Value = serde_json::from_str(&list_body).expect("list JSON");
    let entry = entries
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["Names"][0] == "/wire-list")
        })
        .expect("created container in list");

    assert_eq!(entry["ImageID"], image_id);
    assert_eq!(entry["Labels"]["com.docker.compose.project"], "wire-test");
    assert_eq!(entry["Ports"][0]["PrivatePort"], 8080);
    assert_eq!(entry["Ports"][0]["PublicPort"], 18080);
    assert_eq!(entry["Ports"][0]["Type"], "tcp");
    assert!(entry["NetworkSettings"]["Networks"]["bridge"].is_object());
    assert_eq!(entry["Mounts"][0]["Type"], "bind");
    assert_eq!(entry["Mounts"][0]["Source"], "/tmp");
    assert_eq!(entry["Mounts"][0]["Destination"], "/workspace");
    assert_eq!(entry["Mounts"][0]["RW"], false);
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
fn docker_compat_exec_hijack_forwards_stdin() {
    if nix::unistd::geteuid().is_root() {
        eprintln!("skipping rootful exec-stdin fixture: rootful image materialization is covered by the dedicated OCI lifecycle gate");
        return;
    }
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/exec-stdin:latest");
    let create_body = r#"{"Image":"compat/exec-stdin:latest","Cmd":["/bin/busybox","sleep","5"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create_request = format!(
        "POST /v1.45/containers/create?name=exec-stdin HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    assert_eq!(harness.request_raw(&create_request).0, 201);
    assert_eq!(
        harness
            .request("POST", "/v1.45/containers/exec-stdin/start")
            .0,
        204
    );

    let exec_body = r#"{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Cmd":["/bin/busybox","cat"]}"#;
    let exec_request = format!(
        "POST /v1.45/containers/exec-stdin/exec HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        exec_body.len(),
        exec_body
    );
    let (status, response) = harness.request_raw(&exec_request);
    assert_eq!(status, 201, "exec create response={response}");
    let exec_id = serde_json::from_str::<serde_json::Value>(&response)
        .expect("exec create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("exec id")
        .to_string();

    let (status, response) = harness.request("GET", &format!("/v1.45/exec/{exec_id}/json"));
    assert_eq!(status, 200, "exec inspect response={response}");
    let inspect = serde_json::from_str::<serde_json::Value>(&response).expect("exec inspect JSON");
    assert_eq!(inspect["OpenStdin"], true);

    let start_body = r#"{"Detach":false,"Tty":false}"#;
    let mut stream = UnixStream::connect(&harness.socket_path).expect("connect exec stdin socket");
    stream
        .write_all(
            format!(
                "POST /v1.45/exec/{exec_id}/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: {}\r\n\r\n{}",
                start_body.len(),
                start_body
            )
            .as_bytes(),
        )
        .expect("write exec start request");
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("read exec start headers");
        headers.push(byte[0]);
    }
    assert!(
        String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 101"),
        "headers={}",
        String::from_utf8_lossy(&headers)
    );
    stream
        .write_all(b"stdin-through-exec\n")
        .expect("write exec stdin");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("close exec stdin");
    let mut output = Vec::new();
    stream.read_to_end(&mut output).expect("read exec output");
    assert!(
        output
            .windows(b"stdin-through-exec\n".len())
            .any(|window| window == b"stdin-through-exec\n"),
        "exec output={output:?}"
    );

    assert_eq!(
        harness
            .request("DELETE", "/v1.45/containers/exec-stdin?force=true")
            .0,
        204
    );
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
    let create_body = r#"{"Image":"compat/tty-container:latest","Cmd":["/bin/busybox","sh","-c","read line; printf tty-container:$line; sleep 1"],"Tty":true,"HostConfig":{"NetworkMode":"none"}}"#;
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

    let mut stream = UnixStream::connect(&harness.socket_path).expect("connect TTY attach socket");
    stream
        .write_all(
            b"POST /v1.45/containers/tty-container/attach?logs=0&stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("write TTY attach handshake");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set TTY attach timeout");
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("read TTY attach headers");
        headers.push(byte[0]);
        assert!(headers.len() < 4096, "TTY attach headers are unbounded");
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 101"));
    stream
        .write_all(b"ferrocrate-tty\n")
        .expect("write TTY stdin");
    stream.flush().expect("flush TTY stdin");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut attach_output = Vec::new();
    while Instant::now() < deadline
        && !attach_output
            .windows(b"tty-container:ferrocrate-tty".len())
            .any(|window| window == b"tty-container:ferrocrate-tty")
    {
        let mut chunk = [0_u8; 4096];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => attach_output.extend_from_slice(&chunk[..size]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("read TTY attach output: {error}"),
        }
    }
    assert!(
        attach_output
            .windows(b"tty-container:ferrocrate-tty".len())
            .any(|window| window == b"tty-container:ferrocrate-tty"),
        "TTY attach output did not include stdin payload: {:?}",
        String::from_utf8_lossy(&attach_output)
    );

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

    let (status, response) = harness.request("POST", "/v1.45/containers/tty-container/restart");
    assert_eq!(status, 204, "TTY container restart response={response}");
    let (status, response) = harness.request("GET", "/v1.45/containers/tty-container/json");
    assert_eq!(status, 200, "TTY inspect after restart response={response}");
    let restarted: serde_json::Value =
        serde_json::from_str(&response).expect("TTY inspect after restart JSON");
    assert_eq!(restarted["Config"]["Tty"], true, "inspect={restarted}");
    // Restart launches the original command again, so feed the restarted PTY
    // the same line before asserting its natural terminal state.
    let mut restarted_stream =
        UnixStream::connect(&harness.socket_path).expect("connect restarted TTY attach socket");
    restarted_stream
        .write_all(
            b"POST /v1.45/containers/tty-container/attach?logs=0&stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1\r\nHost: docker\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
        )
        .expect("write restarted TTY attach handshake");
    restarted_stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set restarted TTY attach timeout");
    let mut restarted_headers = Vec::new();
    let mut restarted_byte = [0_u8; 1];
    while !restarted_headers.ends_with(b"\r\n\r\n") {
        restarted_stream
            .read_exact(&mut restarted_byte)
            .expect("read restarted TTY attach headers");
        restarted_headers.push(restarted_byte[0]);
        assert!(
            restarted_headers.len() < 4096,
            "restarted TTY headers are unbounded"
        );
    }
    assert!(String::from_utf8_lossy(&restarted_headers).starts_with("HTTP/1.1 101"));
    restarted_stream
        .write_all(b"ferrocrate-tty-restart\n")
        .expect("write restarted TTY stdin");
    restarted_stream.flush().expect("flush restarted TTY stdin");
    let (status, response) = harness.request(
        "POST",
        "/v1.45/containers/tty-container/kill?signal=SIGTERM",
    );
    assert_eq!(status, 204, "TTY kill response={response}");
    let mut attach_closed = false;
    let close_deadline = Instant::now() + Duration::from_secs(5);
    let mut close_buffer = [0_u8; 4096];
    while Instant::now() < close_deadline {
        match restarted_stream.read(&mut close_buffer) {
            Ok(0) => {
                attach_closed = true;
                break;
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("read closed TTY attach: {error}"),
        }
    }
    assert!(attach_closed, "TTY attach stream did not close after kill");
    let mut stopped = false;
    for _ in 0..80 {
        let (status, response) = harness.request("GET", "/v1.45/containers/tty-container/json");
        assert_eq!(status, 200, "TTY inspect while waiting response={response}");
        let state: serde_json::Value = serde_json::from_str(&response).expect("TTY state JSON");
        if state["State"]["Status"] != serde_json::Value::String("running".to_string()) {
            stopped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(stopped, "TTY container did not finish after restart");

    let (status, response) =
        harness.request("DELETE", "/v1.45/containers/tty-container?force=true");
    assert_eq!(status, 204, "TTY container cleanup response={response}");
}

/// Docker signal semantics: `stop` delivers SIGTERM and escalates to SIGKILL
/// only after the grace period when TERM is trapped; a delivered `kill`
/// signal reaches the workload's handler. Exit codes follow Docker's 128+n.
#[test]
#[ignore = "environment-sensitive: opt in with FERROCRATE_SIGNAL_E2E=1 (see item-8 evidence open-flake note)"]
fn docker_compat_stop_timeout_and_signal_delivery_semantics() {
    if std::env::var("FERROCRATE_SIGNAL_E2E").as_deref() != Ok("1") {
        return;
    }
    // The two stop-escalation scenarios are gated behind
    // FERROCRATE_SIGNAL_E2E_STRICT=1: under the in-process harness they are
    // intermittently preempted by the workload self-exiting (busybox `wait`
    // returning cleanly when its background child dies — see the item-8
    // evidence open-flake note). The same scenarios pass deterministically
    // through the public socket (manual loop 16/16). USR1 delivery is
    // deterministic and always runs.
    let strict = std::env::var("FERROCRATE_SIGNAL_E2E_STRICT").as_deref() == Ok("1");
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/signals:latest");

    let create = |name: &str, cmd: &str| {
        let create_body = format!(
            r#"{{"Image":"compat/signals:latest","Cmd":["/bin/busybox","sh","-c",{cmd}],"HostConfig":{{"NetworkMode":"none"}}}}"#
        );
        let request = format!(
            "POST /v1.45/containers/create?name={name} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            create_body.len(),
            create_body
        );
        let (status, response) = harness.request_raw(&request);
        assert_eq!(status, 201, "{name} create response={response}");
    };

    // 1) TERM-trapped container: stop?t=2 must escalate to SIGKILL (137).
    if strict {
        create(
            "term-trapper",
            "\"sleep 300 & trap '' TERM; echo trapped-ready; wait\"",
        );
        let (status, response) = harness.request("POST", "/v1.45/containers/term-trapper/start");
        assert_eq!(status, 204, "start term-trapper response={response}");
        let mut ready = false;
        for _ in 0..200 {
            let response = harness.request_bytes_raw(
                "GET",
                "/v1.45/containers/term-trapper/logs?stdout=1&stderr=1",
                "text/plain",
                b"",
            );
            if String::from_utf8_lossy(http_body(&response)).contains("trapped-ready") {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            ready,
            "term-trapper never reported readiness; last logs: {}",
            {
                let response = harness.request_bytes_raw(
                    "GET",
                    "/v1.45/containers/term-trapper/logs?stdout=1&stderr=1",
                    "text/plain",
                    b"",
                );
                String::from_utf8_lossy(http_body(&response)).to_string()
            }
        );
        let started = std::time::Instant::now();
        let (status, response) = harness.request("POST", "/v1.45/containers/term-trapper/stop?t=2");
        assert_eq!(status, 204, "stop response={response}");
        let elapsed = started.elapsed();
        let (_status, response) = harness.request("POST", "/v1.45/containers/term-trapper/wait");
        let exit_code: i64 = serde_json::from_str::<serde_json::Value>(&response)
            .expect("wait json")
            .get("StatusCode")
            .and_then(|code| code.as_i64())
            .unwrap_or(-1);
        assert_eq!(
            exit_code, 137,
            "trapped TERM must escalate to SIGKILL: {response}"
        );
        assert!(
            elapsed.as_secs() >= 2,
            "stop returned before the grace period elapsed: {elapsed:?}"
        );
    }

    // 2) Default container: stop delivers SIGTERM; exit code 143.
    if strict {
        create("plain-stopper", "\"echo plain-ready; sleep 300 & wait\"");
        let (status, response) = harness.request("POST", "/v1.45/containers/plain-stopper/start");
        assert_eq!(status, 204, "start plain-stopper response={response}");
        let (status, response) =
            harness.request("POST", "/v1.45/containers/plain-stopper/stop?t=10");
        assert_eq!(status, 204, "plain stop response={response}");
        let (_status, response) = harness.request("POST", "/v1.45/containers/plain-stopper/wait");
        let exit_code: i64 = serde_json::from_str::<serde_json::Value>(&response)
            .expect("wait json")
            .get("StatusCode")
            .and_then(|code| code.as_i64())
            .unwrap_or(-1);
        assert_eq!(
            exit_code, 143,
            "untrapped TERM exit must be 128+15: {response}"
        );
    }

    // 3) kill?signal=USR1 reaches the workload handler.
    create(
        "usr1-handler",
        "\"sleep 300 & trap 'echo usr1-delivered; exit 42' USR1; echo usr1-ready; wait\"",
    );
    let (status, response) = harness.request("POST", "/v1.45/containers/usr1-handler/start");
    assert_eq!(status, 204, "start usr1-handler response={response}");
    let mut ready = false;
    for _ in 0..200 {
        let response = harness.request_bytes_raw(
            "GET",
            "/v1.45/containers/usr1-handler/logs?stdout=1&stderr=1",
            "text/plain",
            b"",
        );
        if http_body(&response).windows(10).any(|w| w == b"usr1-ready") {
            ready = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "usr1-handler never reported readiness");
    let (status, response) =
        harness.request("POST", "/v1.45/containers/usr1-handler/kill?signal=SIGUSR1");
    assert_eq!(status, 204, "kill USR1 response={response}");
    let mut delivered = false;
    for _ in 0..200 {
        let response = harness.request_bytes_raw(
            "GET",
            "/v1.45/containers/usr1-handler/logs?stdout=1&stderr=1",
            "text/plain",
            b"",
        );
        if http_body(&response)
            .windows(14)
            .any(|w| w == b"usr1-delivered")
        {
            delivered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(delivered, "USR1 handler marker missing in logs");
    let (_status, response) = harness.request("POST", "/v1.45/containers/usr1-handler/wait");
    let exit_code: i64 = serde_json::from_str::<serde_json::Value>(&response)
        .expect("wait json")
        .get("StatusCode")
        .and_then(|code| code.as_i64())
        .unwrap_or(-1);
    assert_eq!(exit_code, 42, "handler exit code must surface: {response}");

    for name in ["term-trapper", "plain-stopper", "usr1-handler"] {
        let _ = harness.request("POST", &format!("/v1.45/containers/{name}/kill"));
        let (status, response) = harness.request("DELETE", &format!("/v1.45/containers/{name}"));
        // Gated-off scenarios never create their containers.
        assert!(
            status == 204 || (!strict && status == 404),
            "{name} cleanup response={response}"
        );
    }
}

/// Docker returns `/containers/{id}/logs` for a non-TTY container as a
/// multiplexed raw stream: each frame carries a stream id (1=stdout,
/// 2=stderr) and a big-endian length. The stdout/stderr query selectors
/// must filter which frames are emitted, `timestamps=1` prefixes each line
/// with its RFC3339Nano capture time, and `since`/`until` select lines by
/// that capture time; `follow` plus time filtering stays fail-closed.
#[test]
fn docker_compat_non_tty_logs_are_framed_and_stream_selectable() {
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/framed-logs:latest");
    let create_body = r#"{"Image":"compat/framed-logs:latest","Cmd":["/bin/busybox","sh","-c","printf out-line; printf err-line 1>&2"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=framed-logs HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, response) = harness.request_raw(&create);
    assert_eq!(status, 201, "framed-logs create response={response}");

    let (status, response) = harness.request("POST", "/v1.45/containers/framed-logs/start");
    assert_eq!(status, 204, "framed-logs start response={response}");
    let (status, response) = harness.request(
        "POST",
        "/v1.45/containers/framed-logs/wait?condition=not-running",
    );
    assert_eq!(status, 200, "framed-logs wait response={response}");

    // Poll until both log streams are durable; bounded like the TTY fixture.
    let mut frames = Vec::new();
    for _ in 0..40 {
        let response = harness.request_bytes_raw(
            "GET",
            "/v1.45/containers/framed-logs/logs?stdout=1&stderr=1",
            "text/plain",
            b"",
        );
        frames = http_body(&response).to_vec();
        let text = String::from_utf8_lossy(&frames).to_string();
        if text.contains("out-line") && text.contains("err-line") {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    let decoded = decode_raw_frames(&frames).expect("combined logs must be framed");
    assert!(
        decoded
            .iter()
            .any(|(stream, payload)| *stream == 1 && payload == b"out-line"),
        "stdout frame missing: {decoded:?}"
    );
    assert!(
        decoded
            .iter()
            .any(|(stream, payload)| *stream == 2 && payload == b"err-line"),
        "stderr frame missing: {decoded:?}"
    );

    let response = harness.request_bytes_raw(
        "GET",
        "/v1.45/containers/framed-logs/logs?stdout=1&stderr=0",
        "text/plain",
        b"",
    );
    let decoded = decode_raw_frames(http_body(&response)).expect("stdout-only logs are framed");
    assert!(
        decoded.iter().all(|(stream, _)| *stream == 1),
        "stdout-only response leaked other streams: {decoded:?}"
    );
    assert!(
        decoded.iter().any(|(_, payload)| payload == b"out-line"),
        "stdout payload missing: {decoded:?}"
    );

    let response = harness.request_bytes_raw(
        "GET",
        "/v1.45/containers/framed-logs/logs?stdout=0&stderr=1",
        "text/plain",
        b"",
    );
    let decoded = decode_raw_frames(http_body(&response)).expect("stderr-only logs are framed");
    assert!(
        decoded.iter().all(|(stream, _)| *stream == 2),
        "stderr-only response leaked other streams: {decoded:?}"
    );
    assert!(
        decoded.iter().any(|(_, payload)| payload == b"err-line"),
        "stderr payload missing: {decoded:?}"
    );

    let (status, _response) = harness.request(
        "GET",
        "/v1.45/containers/framed-logs/logs?stdout=0&stderr=0",
    );
    assert_eq!(status, 400, "both streams disabled must fail");
    // timestamps=1 prefixes every line with Docker's RFC3339Nano capture time.
    let response = harness.request_bytes_raw(
        "GET",
        "/v1.45/containers/framed-logs/logs?stdout=1&stderr=1&timestamps=1",
        "text/plain",
        b"",
    );
    let decoded =
        decode_raw_frames(http_body(&response)).expect("timestamped logs must stay framed");
    assert!(
        decoded.iter().any(|(stream, payload)| *stream == 1
            && payload.starts_with(b"20")
            && payload.contains(&b' ')
            && payload.ends_with(b"out-line")),
        "timestamped stdout frame missing RFC3339 prefix: {decoded:?}"
    );
    assert!(
        decoded.iter().any(|(stream, payload)| *stream == 2
            && payload.starts_with(b"20")
            && payload.ends_with(b"err-line")),
        "timestamped stderr frame missing RFC3339 prefix: {decoded:?}"
    );
    // since/until select lines by capture time: a past since keeps everything,
    // a past until drops everything.
    let past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(60);
    let response = harness.request_bytes_raw(
        "GET",
        &format!("/v1.45/containers/framed-logs/logs?stdout=1&stderr=1&since={past}"),
        "text/plain",
        b"",
    );
    let decoded =
        decode_raw_frames(http_body(&response)).expect("since-filtered logs must stay framed");
    assert!(
        decoded.iter().any(|(_, payload)| payload == b"out-line"),
        "past since must keep lines: {decoded:?}"
    );
    let response = harness.request_bytes_raw(
        "GET",
        &format!("/v1.45/containers/framed-logs/logs?stdout=1&stderr=1&until={past}"),
        "text/plain",
        b"",
    );
    let decoded =
        decode_raw_frames(http_body(&response)).expect("until-filtered logs must stay framed");
    assert!(
        decoded.is_empty(),
        "past until must drop all lines: {decoded:?}"
    );
    let (status, response) = harness.request(
        "GET",
        "/v1.45/containers/framed-logs/logs?since=not-a-number",
    );
    assert_eq!(status, 400, "malformed since must fail closed: {response}");
    let (status, response) = harness.request(
        "GET",
        "/v1.45/containers/framed-logs/logs?stdout=1&stderr=1&since=0&until=0&timestamps=0",
    );
    assert_eq!(
        status, 200,
        "client-default no-op bounds must pass: {response}"
    );
    // Combining time filtering with follow remains an explicit boundary.
    let (status, response) = harness.request(
        "GET",
        "/v1.45/containers/framed-logs/logs?stdout=1&stderr=1&follow=1&timestamps=1",
    );
    assert_eq!(
        status, 400,
        "timestamps with follow must fail closed: {response}"
    );
    assert!(response.contains("follow"), "body={response}");

    let (status, response) = harness.request("DELETE", "/v1.45/containers/framed-logs");
    assert_eq!(status, 204, "framed-logs cleanup response={response}");
}

/// Docker's `noOverwriteDirNonDir=1` upload contract: an archive entry that
/// is a directory must not replace an existing non-directory (and vice
/// versa), and the rejection must happen before any bytes are written.
#[test]
fn docker_compat_put_archive_enforces_no_overwrite_dir_non_dir() {
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/archive-conflict:latest");
    let create_body = r#"{"Image":"compat/archive-conflict:latest","Cmd":["/bin/busybox","true"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=archive-conflict HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, body) = harness.request_raw(&create);
    assert_eq!(status, 201, "archive-conflict create response={body}");
    let id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();
    let (status, body) = harness.request("POST", "/v1.45/containers/archive-conflict/start");
    assert_eq!(status, 204, "archive-conflict start response={body}");
    let rootfs = harness
        ._runtime_dir
        .path()
        .join("containers")
        .join(&id)
        .join("rootfs");
    assert!(rootfs.is_dir(), "rootfs missing: {}", rootfs.display());

    // Seed a plain file, then attempt a directory entry over it.
    let mut file_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut file_tar);
        let payload = b"seed";
        let mut header = tar::Header::new_gnu();
        header.set_path("conflict").expect("file path");
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder.append(&header, &payload[..]).expect("append file");
        builder.finish().expect("finish file tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-conflict/archive?path=%2F",
        "application/x-tar",
        &file_tar,
    );
    assert_eq!(status, 200, "seed put archive response={body}");

    let mut dir_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut dir_tar);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_path("conflict").expect("dir path");
        header.set_cksum();
        builder
            .append(&header, std::io::empty())
            .expect("append dir");
        builder.finish().expect("finish dir tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-conflict/archive?path=%2F&noOverwriteDirNonDir=1",
        "application/x-tar",
        &dir_tar,
    );
    assert_eq!(status, 400, "dir-over-file must fail closed: {body}");
    assert!(
        body.contains("cannot overwrite non-directory"),
        "body={body}"
    );
    assert!(
        rootfs.join("conflict").is_file(),
        "rejected upload must not modify the existing entry"
    );

    // Seed an existing directory under a fresh name, then attempt a file
    // entry over it in the opposite direction.
    let mut dir_fresh_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut dir_fresh_tar);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_path("dir-target").expect("dir path");
        header.set_cksum();
        builder
            .append(&header, std::io::empty())
            .expect("append dir");
        builder.finish().expect("finish dir tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-conflict/archive?path=%2F",
        "application/x-tar",
        &dir_fresh_tar,
    );
    assert_eq!(status, 200, "seed dir upload response={body}");
    assert!(rootfs.join("dir-target").is_dir(), "seed dir applies");

    let mut file_over_dir_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut file_over_dir_tar);
        let payload = b"payload";
        let mut header = tar::Header::new_gnu();
        header.set_path("dir-target").expect("file path");
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder.append(&header, &payload[..]).expect("append file");
        builder.finish().expect("finish file tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-conflict/archive?path=%2F&noOverwriteDirNonDir=1",
        "application/x-tar",
        &file_over_dir_tar,
    );
    assert_eq!(status, 400, "file-over-dir must fail closed: {body}");
    assert!(body.contains("cannot overwrite directory"), "body={body}");

    // A flagged upload without type conflicts applies normally.
    let mut fresh_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut fresh_tar);
        let payload = b"fresh";
        let mut header = tar::Header::new_gnu();
        header.set_path("fresh-file").expect("fresh path");
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder.append(&header, &payload[..]).expect("append fresh");
        builder.finish().expect("finish fresh tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-conflict/archive?path=%2F&noOverwriteDirNonDir=1",
        "application/x-tar",
        &fresh_tar,
    );
    assert_eq!(status, 200, "flagged compatible upload response={body}");
    assert!(
        rootfs.join("fresh-file").is_file(),
        "flagged compatible upload applies"
    );

    // A malformed flag value is rejected before the container is resolved.
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/missing/archive?path=%2F&noOverwriteDirNonDir=maybe",
        "application/x-tar",
        &file_tar,
    );
    assert_eq!(status, 400, "malformed flag response={body}");

    let (status, body) = harness.request("DELETE", "/v1.45/containers/archive-conflict");
    assert_eq!(status, 204, "archive-conflict cleanup response={body}");
}

/// Without `noOverwriteDirNonDir`, Docker replaces a file with a directory
/// (and vice versa) instead of returning EEXIST.
#[test]
fn docker_compat_put_archive_replaces_type_changing_entries() {
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/archive-replace:latest");
    let create_body = r#"{"Image":"compat/archive-replace:latest","Cmd":["/bin/busybox","true"],"HostConfig":{"NetworkMode":"none"}}"#;
    let create = format!(
        "POST /v1.45/containers/create?name=archive-replace HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, body) = harness.request_raw(&create);
    assert_eq!(status, 201, "archive-replace create response={body}");
    let id = serde_json::from_str::<serde_json::Value>(&body)
        .expect("create JSON")
        .get("Id")
        .and_then(serde_json::Value::as_str)
        .expect("container id")
        .to_string();
    let (status, body) = harness.request("POST", "/v1.45/containers/archive-replace/start");
    assert_eq!(status, 204, "archive-replace start response={body}");
    let rootfs = harness
        ._runtime_dir
        .path()
        .join("containers")
        .join(&id)
        .join("rootfs");

    let mut file_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut file_tar);
        let payload = b"seed";
        let mut header = tar::Header::new_gnu();
        header.set_path("conflict").expect("file path");
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder.append(&header, &payload[..]).expect("append file");
        builder.finish().expect("finish file tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-replace/archive?path=%2F",
        "application/x-tar",
        &file_tar,
    );
    assert_eq!(status, 200, "seed put archive response={body}");
    assert!(rootfs.join("conflict").is_file(), "seed file applies");

    let mut dir_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut dir_tar);
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_path("conflict").expect("dir path");
        header.set_cksum();
        builder
            .append(&header, std::io::empty())
            .expect("append dir");
        builder.finish().expect("finish dir tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-replace/archive?path=%2F",
        "application/x-tar",
        &dir_tar,
    );
    assert_eq!(status, 200, "dir-over-file replace response={body}");
    assert!(
        rootfs.join("conflict").is_dir(),
        "unflagged upload must replace the file with a directory"
    );

    let mut file_over_dir_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut file_over_dir_tar);
        let payload = b"payload";
        let mut header = tar::Header::new_gnu();
        header.set_path("conflict").expect("file path");
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder.append(&header, &payload[..]).expect("append file");
        builder.finish().expect("finish file tar");
    }
    let (status, body) = harness.request_bytes(
        "PUT",
        "/v1.45/containers/archive-replace/archive?path=%2F",
        "application/x-tar",
        &file_over_dir_tar,
    );
    assert_eq!(status, 200, "file-over-dir replace response={body}");
    assert!(
        rootfs.join("conflict").is_file(),
        "unflagged upload must replace the directory with a file"
    );
    assert_eq!(
        std::fs::read(rootfs.join("conflict")).expect("replaced file"),
        b"payload"
    );

    let (status, body) = harness.request("DELETE", "/v1.45/containers/archive-replace");
    assert_eq!(status, 204, "archive-replace cleanup response={body}");
}

/// Recognized Docker routes without a local implementation report an explicit
/// 501 boundary instead of a generic unknown-route 404.
#[test]
fn docker_compat_unimplemented_routes_report_explicit_boundaries() {
    let harness = DaemonHarness::spawn();

    let auth_request = "POST /auth HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"username\":\"u\",\"password\":\"p\"}";
    let (status, body) = harness.request_raw(auth_request);
    assert_eq!(status, 501, "auth response={body}");
    assert!(
        body.contains("auth is unsupported") && body.contains("registry credential backend"),
        "body={body}"
    );

    let (status, body) = harness.request("GET", "/v1.45/containers/missing/attach/ws");
    assert_eq!(status, 501, "attach/ws response={body}");
    assert!(
        body.contains("websocket attach is unsupported") && body.contains("TCP hijack attach"),
        "body={body}"
    );

    // The synthetic top listing cannot honor a client ps argument set.
    let (status, body) = harness.request("GET", "/v1.45/containers/missing/top?ps_args=-ef");
    assert_eq!(status, 400, "top ps_args response={body}");
    assert!(
        body.contains("ps_args is unsupported") && body.contains("synthetic"),
        "body={body}"
    );
    // An empty ps_args stays a no-op and preserves the missing-container 404.
    let (status, body) = harness.request("GET", "/v1.45/containers/missing/top?ps_args=");
    assert_eq!(status, 404, "empty ps_args response={body}");
}

/// Decode a complete Docker multiplexed raw stream into (stream id, payload)
/// frames; any truncated or invalid header is an error.
fn decode_raw_frames(raw: &[u8]) -> Result<Vec<(u8, &[u8])>, String> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < raw.len() {
        if raw.len() - offset < 8 {
            return Err("truncated frame header".to_string());
        }
        let stream = raw[offset];
        if stream != 1 && stream != 2 {
            return Err(format!("invalid stream id {stream}"));
        }
        let size = u32::from_be_bytes([
            raw[offset + 4],
            raw[offset + 5],
            raw[offset + 6],
            raw[offset + 7],
        ]) as usize;
        offset += 8;
        let end = offset + size;
        if end > raw.len() {
            return Err("truncated frame payload".to_string());
        }
        frames.push((stream, &raw[offset..end]));
        offset = end;
    }
    Ok(frames)
}

#[test]
fn docker_compat_healthcheck_reaches_healthy_and_reports_streak() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("SKIP: healthcheck lifecycle requires CAP_SYS_ADMIN for nsenter");
        return;
    }
    let harness = DaemonHarness::spawn();
    build_local_busybox_image(&harness, "compat/health:latest");

    let create_body = serde_json::json!({
        "Image": "compat/health:latest",
        "Cmd": ["/bin/busybox", "sleep", "5"],
        "Healthcheck": {
            "Test": ["CMD-SHELL", "/bin/busybox true"],
            "Interval": 100_000_000,
            "Timeout": 1_000_000_000,
            "Retries": 2,
            "StartPeriod": 0
        },
        "HostConfig": {"NetworkMode": "none"}
    })
    .to_string();
    let request = format!(
        "POST /v1.45/containers/create?name=health-container HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        create_body.len(),
        create_body
    );
    let (status, body) = harness.request_raw(&request);
    assert_eq!(status, 201, "health create response={body}");

    let (status, body) = harness.request("POST", "/v1.45/containers/health-container/start");
    assert_eq!(status, 204, "health start response={body}");

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut inspect = serde_json::Value::Null;
    while Instant::now() < deadline {
        let (status, response) = harness.request("GET", "/v1.45/containers/health-container/json");
        assert_eq!(status, 200, "health inspect response={response}");
        inspect = serde_json::from_str(&response).expect("health inspect JSON");
        if inspect["State"]["Health"]["Status"] == "healthy" {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        inspect["State"]["Health"]["Status"], "healthy",
        "inspect={inspect}"
    );
    assert_eq!(
        inspect["State"]["Health"]["FailingStreak"], 0,
        "inspect={inspect}"
    );
    assert!(
        inspect["Config"]["Healthcheck"].is_object(),
        "inspect={inspect}"
    );

    let (status, body) = harness.request("DELETE", "/v1.45/containers/health-container?force=true");
    assert_eq!(status, 204, "health cleanup response={body}");
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

// ── OCI archive (docker save/load) conformance ────────────────────────────────

fn build_tar_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut archive);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).expect("archive entry path");
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &bytes[..]).expect("append entry");
        }
        builder.finish().expect("finish archive");
    }
    archive
}

fn parse_tar_archive(archive: &[u8]) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut entries = std::collections::BTreeMap::new();
    let mut tar = tar::Archive::new(archive);
    for entry in tar.entries().expect("archive entries") {
        let mut entry = entry.expect("archive entry");
        let path = entry.path().expect("entry path").to_path_buf();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).expect("entry bytes");
        entries.insert(path.to_string_lossy().to_string(), bytes);
    }
    entries
}

fn http_body(archive_response: &[u8]) -> &[u8] {
    let header_end = archive_response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers");
    &archive_response[header_end + 4..]
}

fn export_image_archive(harness: &DaemonHarness, encoded_tag: &str) -> Vec<u8> {
    let raw = harness.request_bytes_raw(
        "GET",
        &format!("/v1.45/images/{encoded_tag}/get"),
        "application/json",
        &[],
    );
    let headers_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("export response headers");
    let headers = String::from_utf8_lossy(&raw[..headers_end]).to_string();
    assert!(headers.starts_with("HTTP/1.1 200 OK"), "export: {headers}");
    raw[headers_end + 4..].to_vec()
}

fn octal_field(value: u64, width: usize) -> Vec<u8> {
    let digits = format!("{:0width$o}", value, width = width - 2);
    let mut field = digits.into_bytes();
    field.push(0);
    field.push(b' ');
    field
}

/// Append a tar entry whose raw name may contain `..`. The high-level builder
/// refuses such names, so the header is written byte-for-byte to prove the
/// loader rejects the archive instead of the test tooling.
fn append_raw_tar_entry(out: &mut Vec<u8>, name: &str, data: &[u8]) {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(&octal_field(0o644, 8));
    header[108..116].copy_from_slice(&octal_field(0, 8));
    header[116..124].copy_from_slice(&octal_field(0, 8));
    header[124..136].copy_from_slice(&octal_field(data.len() as u64, 12));
    header[136..148].copy_from_slice(&octal_field(0, 12));
    for byte in &mut header[148..156] {
        *byte = b' ';
    }
    header[156] = b'0';
    header[257..262].copy_from_slice(b"ustar");
    header[262..264].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| *byte as u32).sum();
    let mut cksum = format!("{:06o}", checksum).into_bytes();
    cksum.push(0);
    cksum.push(b' ');
    header[148..156].copy_from_slice(&cksum);
    out.extend_from_slice(&header);
    out.extend_from_slice(data);
    let padding = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, padding));
}

fn finish_raw_tar(out: &mut Vec<u8>) {
    out.extend(std::iter::repeat_n(0u8, 1024));
}

#[test]
fn docker_compat_image_archive_round_trip_preserves_layers_and_config() {
    let source = DaemonHarness::spawn();
    build_local_busybox_image(&source, "round/trip:latest");
    let archive_a = export_image_archive(&source, "round%2Ftrip%3Alatest");
    let entries_a = parse_tar_archive(&archive_a);

    let manifest_a: Vec<serde_json::Value> =
        serde_json::from_slice(&entries_a["manifest.json"]).expect("source manifest.json");
    assert_eq!(manifest_a.len(), 1, "one image per archive");
    let config_name_a = manifest_a[0]["Config"]
        .as_str()
        .expect("config name")
        .to_string();
    let config_a: serde_json::Value =
        serde_json::from_slice(&entries_a[&config_name_a]).expect("source config JSON");
    let layers_a = manifest_a[0]["Layers"]
        .as_array()
        .expect("layer list")
        .clone();
    assert!(
        !layers_a.is_empty(),
        "built image must have at least one layer"
    );

    let target = DaemonHarness::spawn();
    let (status, body) = target.request_bytes(
        "POST",
        "/v1.45/images/load",
        "application/x-tar",
        &archive_a,
    );
    assert_eq!(status, 200, "load response={body}");
    assert!(body.contains("Loaded image"), "load stream={body}");

    let archive_b = export_image_archive(&target, "round%2Ftrip%3Alatest");
    let entries_b = parse_tar_archive(&archive_b);
    let manifest_b: Vec<serde_json::Value> =
        serde_json::from_slice(&entries_b["manifest.json"]).expect("loaded manifest.json");
    assert_eq!(manifest_b.len(), 1);
    assert_eq!(
        manifest_b[0]["RepoTags"], manifest_a[0]["RepoTags"],
        "RepoTags must survive the round trip"
    );

    let layers_b = manifest_b[0]["Layers"]
        .as_array()
        .expect("loaded layer list");
    assert_eq!(layers_b.len(), layers_a.len(), "layer count must survive");
    for (layer_a, layer_b) in layers_a.iter().zip(layers_b.iter()) {
        let name_a = layer_a.as_str().expect("layer name");
        let name_b = layer_b.as_str().expect("loaded layer name");
        assert_eq!(
            entries_a[name_a], entries_b[name_b],
            "layer bytes must be identical after export/load/export"
        );
    }

    let config_name_b = manifest_b[0]["Config"]
        .as_str()
        .expect("loaded config name");
    let config_b: serde_json::Value =
        serde_json::from_slice(&entries_b[config_name_b]).expect("loaded config JSON");
    assert_eq!(
        config_a["architecture"], config_b["architecture"],
        "architecture label must survive the round trip"
    );
    assert_eq!(
        config_a["os"], config_b["os"],
        "os label must survive the round trip"
    );
    let diff_ids = config_b["rootfs"]["diff_ids"]
        .as_array()
        .expect("loaded diff_ids");
    assert_eq!(
        diff_ids.len(),
        layers_b.len(),
        "loaded config diff_ids must match the layer count"
    );
}

#[test]
fn docker_compat_image_load_rejects_malformed_archives() {
    let harness = DaemonHarness::spawn();

    let config_bytes = br#"{"architecture":"amd64","os":"linux"}"#;
    let config_name = format!("{:x}.json", sha2::Sha256::digest(config_bytes));
    let missing_layer_manifest = format!(
        r#"[{{"Config":"{config_name}","RepoTags":["malformed/layer:latest"],"Layers":["layer-0/layer.tar"]}}]"#
    );
    let digest_mismatch_manifest =
        r#"[{"Config":"deadbeef.json","RepoTags":["malformed/cfg:latest"],"Layers":[]}]"#;

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("not a tar at all", b"definitely not a tar archive".to_vec()),
        (
            "missing manifest.json",
            build_tar_archive(&[("README", b"no manifest here")]),
        ),
        (
            "two images in one archive",
            build_tar_archive(&[
                (
                    "manifest.json",
                    br#"[{"Config":"a.json","RepoTags":["x/a:1"],"Layers":[]},{"Config":"b.json","RepoTags":["x/b:1"],"Layers":[]}]"#,
                ),
                ("a.json", b"{}"),
                ("b.json", b"{}"),
            ]),
        ),
        (
            "unsafe entry path",
            {
                let mut archive = Vec::new();
                append_raw_tar_entry(&mut archive, "../escape", b"payload");
                append_raw_tar_entry(&mut archive, "manifest.json", b"[]");
                finish_raw_tar(&mut archive);
                archive
            },
        ),
        (
            "repeated entry name",
            build_tar_archive(&[("manifest.json", b"[]"), ("manifest.json", b"[]")]),
        ),
        (
            "config digest does not match filename",
            build_tar_archive(&[
                ("manifest.json", digest_mismatch_manifest.as_bytes()),
                ("deadbeef.json", config_bytes),
            ]),
        ),
        (
            "manifest references missing layer",
            build_tar_archive(&[
                ("manifest.json", missing_layer_manifest.as_bytes()),
                (&config_name, config_bytes),
            ]),
        ),
    ];

    for (name, archive) in cases {
        let (status, body) =
            harness.request_bytes("POST", "/v1.45/images/load", "application/x-tar", &archive);
        assert!(
            status >= 400,
            "malformed archive ({name}) must fail closed: status={status} body={body}"
        );
    }

    for tag in ["malformed%2Flayer%3Alatest", "malformed%2Fcfg%3Alatest"] {
        let (status, body) = harness.request("GET", &format!("/v1.45/images/{tag}/json"));
        assert_eq!(
            status, 404,
            "no image may be published from a malformed archive: {body}"
        );
    }
}

#[test]
fn docker_compat_foreign_architecture_archive_keeps_label_without_execution_claim() {
    let harness = DaemonHarness::spawn();

    let mut layer_tar = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut layer_tar);
        let payload = b"#!/bin/sh\n";
        let mut header = tar::Header::new_gnu();
        header.set_path("bin/true").expect("layer entry path");
        header.set_size(payload.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append(&header, &payload[..])
            .expect("append layer entry");
        builder.finish().expect("finish layer tar");
    }
    let diff_id = format!("sha256:{:x}", sha2::Sha256::digest(&layer_tar));
    let config_json = format!(
        r#"{{"architecture":"arm64","os":"linux","config":{{}},"rootfs":{{"type":"layers","diff_ids":["{diff_id}"]}}}}"#
    );
    let config_bytes = config_json.as_bytes();
    let config_name = format!("{:x}.json", sha2::Sha256::digest(config_bytes));
    let manifest = format!(
        r#"[{{"Config":"{config_name}","RepoTags":["foreign/arch:latest"],"Layers":["layer-0/layer.tar"]}}]"#
    );
    let archive = build_tar_archive(&[
        (&config_name, config_bytes),
        ("manifest.json", manifest.as_bytes()),
        ("layer-0/layer.tar", &layer_tar),
    ]);

    let (status, body) =
        harness.request_bytes("POST", "/v1.45/images/load", "application/x-tar", &archive);
    assert_eq!(status, 200, "foreign-arch load response={body}");

    // The artifact stays inspectable and correctly labeled.
    let (status, body) = harness.request("GET", "/v1.45/images/foreign%2Farch%3Alatest/json");
    assert_eq!(status, 200, "foreign-arch inspect={body}");
    assert!(body.contains("foreign/arch:latest"), "inspect={body}");

    // Re-exporting must preserve the foreign platform label verbatim: the
    // export is a data artifact and must not relabel it as host-runnable.
    let exported = export_image_archive(&harness, "foreign%2Farch%3Alatest");
    let entries = parse_tar_archive(&exported);
    let manifest: Vec<serde_json::Value> =
        serde_json::from_slice(&entries["manifest.json"]).expect("exported manifest.json");
    let exported_config = manifest[0]["Config"].as_str().expect("config name");
    let config: serde_json::Value =
        serde_json::from_slice(&entries[exported_config]).expect("exported config JSON");
    assert_eq!(config["architecture"], "arm64", "exported config={config}");
    assert_eq!(config["os"], "linux", "exported config={config}");
}
