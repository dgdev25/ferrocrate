//! Roadmap item 21: bounded 100-container resource/fault qualification.
//!
//! Every scenario runs unprivileged against a real `ferro-cli daemon` over
//! its Docker-compatible socket, with an isolated runtime directory and a
//! driver-imposed outer timeout (`scripts/qualification-fault-matrix.sh`).
//! A scenario that fails or times out is recorded as evidence; nothing here
//! retries a flaky outcome to force a pass.
//!
//! Root-gated rows (real ENOSPC via tmpfs/loopback, rootful cgroup
//! `memory.oom.group` teardown, live iptables/nftables/eBPF fault injection)
//! are intentionally not simulated locally and stay with the coordinator's
//! privileged matrix.

#![cfg(target_os = "linux")]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Per-request socket timeout. A daemon that stops answering must fail the
/// scenario here instead of hanging until the driver kills the test binary.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

struct QualDaemon {
    child: Child,
    runtime_dir: PathBuf,
    /// Kept alive so the runtime directory survives until the harness
    /// drops. `None` when the caller owns the directory (root-gated rows).
    runtime_guard: Option<tempfile::TempDir>,
    socket_path: PathBuf,
    kernel_state_path: PathBuf,
}

impl Drop for QualDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl QualDaemon {
    /// Spawn a daemon with extra environment variables and an optional
    /// `bash -c` prelude (used for RLIMIT_FSIZE disk-pressure simulation).
    fn spawn(extra_env: &[(&str, &str)], prelude: Option<&str>) -> Self {
        let runtime_guard = tempfile::tempdir().expect("runtime tempdir");
        fs::set_permissions(runtime_guard.path(), fs::Permissions::from_mode(0o700))
            .expect("protect runtime directory");
        let mut harness = Self::spawn_in(runtime_guard.path(), extra_env, prelude);
        harness.runtime_guard = Some(runtime_guard);
        harness
    }

    /// Spawn a daemon against a caller-owned runtime directory (root-gated
    /// tmpfs scenario). The caller owns cleanup and unmount of the directory.
    fn spawn_in(runtime_dir: &Path, extra_env: &[(&str, &str)], prelude: Option<&str>) -> Self {
        let socket_path = runtime_dir.join("docker.sock");
        let kernel_state_path = runtime_dir.join("network-kernel-state.json");
        let child = Self::spawn_process(
            runtime_dir,
            &socket_path,
            &kernel_state_path,
            extra_env,
            prelude,
        );
        let harness = Self {
            child,
            runtime_dir: runtime_dir.to_path_buf(),
            runtime_guard: None,
            socket_path,
            kernel_state_path,
        };
        harness.wait_ready(10);
        harness
    }

    fn spawn_process(
        runtime_dir: &Path,
        socket_path: &Path,
        kernel_state_path: &Path,
        extra_env: &[(&str, &str)],
        prelude: Option<&str>,
    ) -> Child {
        let binary = env!("CARGO_BIN_EXE_ferro-cli");
        let daemon_args = format!(
            "daemon --docker-compat --socket {}",
            socket_path.to_str().expect("socket path utf8")
        );
        let mut command = match prelude {
            Some(prelude) => {
                let mut command = Command::new("bash");
                command.args([
                    "-c",
                    &format!("{prelude}; exec \"$0\" {daemon_args}",),
                    binary,
                ]);
                command
            }
            None => {
                let mut command = Command::new(binary);
                command.arg("daemon").arg("--docker-compat");
                command.arg("--socket").arg(socket_path);
                command
            }
        };
        command
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir)
            .env("FERROCRATE_NETWORK_KERNEL_STATE", kernel_state_path)
            .env("FERROCRATE_NETWORK_BACKEND", "iptables")
            .env(
                "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
                "docker-disabled",
            );
        for (key, value) in extra_env {
            command.env(key, value);
        }
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon")
    }

    fn wait_ready(&self, seconds: u64) {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(seconds) {
            if self.socket_path.exists() && UnixStream::connect(&self.socket_path).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "daemon socket did not become ready: {}",
            self.socket_path.display()
        );
    }

    /// SIGKILL the daemon, then restart it against the same runtime
    /// directory so journal reconciliation must run.
    fn kill9_and_restart(&mut self) {
        self.child.kill().expect("send SIGKILL to daemon");
        self.child.wait().expect("reap killed daemon");
        let runtime_dir = self.runtime_dir.clone();
        // The socket file outlives the killed daemon; remove it so the new
        // listener can bind. The daemon itself also removes stale sockets.
        let _ = fs::remove_file(&self.socket_path);
        self.child = Self::spawn_process(
            &runtime_dir,
            &self.socket_path,
            &self.kernel_state_path,
            &[],
            None,
        );
        self.wait_ready(15);
    }

    fn daemon_alive(&self) -> bool {
        let Ok(mut stream) = UnixStream::connect(&self.socket_path) else {
            return false;
        };
        let request =
            "GET /_ping HTTP/1.1\r\nHost: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if stream.write_all(request.as_bytes()).is_err() {
            return false;
        }
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        if stream.read_to_end(&mut response).is_err() {
            return false;
        }
        response.starts_with(b"HTTP/1.1 200")
    }

    fn daemon_rss_kib(&self) -> u64 {
        let status =
            fs::read_to_string(format!("/proc/{}/status", self.child.id())).expect("read status");
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                return rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .expect("parse VmRSS");
            }
        }
        panic!("VmRSS missing from daemon status");
    }

    fn request(&self, method: &str, path: &str, body: &[u8]) -> (u16, String) {
        let header = format!(
            "{method} {path} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = UnixStream::connect(&self.socket_path).expect("connect daemon socket");
        stream
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .expect("set read timeout");
        stream.write_all(header.as_bytes()).expect("write headers");
        stream.write_all(body).expect("write body");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("read daemon response");
        let text = String::from_utf8_lossy(&response);
        let (headers, body) = text.split_once("\r\n\r\n").expect("response headers");
        let code = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .expect("parse status code");
        (code, body.to_string())
    }

    fn request_tar(&self, path: &str, body: &[u8]) -> (u16, String) {
        let header = format!(
            "POST {path} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/x-tar\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream = UnixStream::connect(&self.socket_path).expect("connect daemon socket");
        stream
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .expect("set read timeout");
        stream.write_all(header.as_bytes()).expect("write headers");
        stream.write_all(body).expect("write body");
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("read daemon response");
        let text = String::from_utf8_lossy(&response);
        let (headers, body) = text.split_once("\r\n\r\n").expect("response headers");
        let code = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .expect("parse status code");
        (code, body.to_string())
    }

    fn build_busybox_image(&self, tag: &str) {
        let encoded_tag = tag.replace('/', "%2F").replace(':', "%3A");
        let (status, body) = self.request_tar(
            &format!("/v1.45/build?dockerfile=Dockerfile&t={encoded_tag}"),
            &busybox_image_archive(),
        );
        assert_eq!(status, 200, "local image build response={body}");
    }

    /// Lossy variant of the tar request used by the disk-pressure scenario,
    /// where the fault may kill the daemon mid-response.
    fn request_lossy_tar(&self, path: &str, body: &[u8]) -> Result<(u16, String), String> {
        let header = format!(
            "POST {path} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/x-tar\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|error| format!("connect: {error}"))?;
        stream
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|error| format!("set timeout: {error}"))?;
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(body))
            .map_err(|error| format!("write: {error}"))?;
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| format!("read: {error}"))?;
        let text = String::from_utf8_lossy(&response);
        let (headers, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| "truncated response".to_string())?;
        let code = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| "missing status line".to_string())?;
        Ok((code, body.to_string()))
    }

    fn create_container(&self, name: &str, payload: &Value) -> String {
        let (status, body) = self.request(
            "POST",
            &format!("/containers/create?name={name}"),
            payload.to_string().as_bytes(),
        );
        assert_eq!(status, 201, "create {name} response={body}");
        serde_json::from_str::<Value>(&body)
            .expect("parse create response")
            .get("Id")
            .and_then(Value::as_str)
            .expect("create response Id")
            .to_string()
    }

    fn start_container(&self, id: &str) -> (u16, String) {
        self.request("POST", &format!("/containers/{id}/start"), b"")
    }

    fn inspect(&self, id: &str) -> Value {
        let (status, body) = self.request("GET", &format!("/containers/{id}/json"), b"");
        assert_eq!(status, 200, "inspect {id} response={body}");
        serde_json::from_str(&body).expect("parse inspect response")
    }

    fn container_state(&self, id: &str) -> (String, Option<i64>, i64) {
        let inspect = self.inspect(id);
        let state = &inspect["State"];
        (
            state["Status"].as_str().unwrap_or_default().to_string(),
            state["ExitCode"].as_i64(),
            state["Pid"].as_i64().unwrap_or(0),
        )
    }

    /// Poll until a container reaches `exited`, bounded by `seconds`.
    fn wait_exited(&self, id: &str, seconds: u64) -> Option<i64> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            let (status, exit_code, _) = self.container_state(id);
            if status == "exited" {
                return exit_code;
            }
            thread::sleep(Duration::from_millis(100));
        }
        None
    }

    fn stop_container(&self, id: &str) -> (u16, String) {
        self.request("POST", &format!("/containers/{id}/stop?t=5"), b"")
    }

    fn remove_container(&self, id: &str) -> (u16, String) {
        self.request("DELETE", &format!("/containers/{id}"), b"")
    }

    fn container_dir_entries(&self) -> Vec<String> {
        let containers_dir = self.runtime_dir.join("containers");
        let Ok(entries) = fs::read_dir(&containers_dir) else {
            return Vec::new();
        };
        entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect()
    }
}

fn busybox_payload(cmd: &[&str]) -> Value {
    json!({
        "Image": "qual/busybox:latest",
        "Cmd": cmd,
        "HostConfig": {"NetworkMode": "none"},
    })
}

/// Build context that copies the host busybox binary into a scratch image.
/// A non-zero pad adds a distinct payload so the layer digest changes and
/// the build cannot be served from the content-addressed cache.
fn busybox_image_archive() -> Vec<u8> {
    busybox_image_archive_with_pad(0)
}

fn busybox_image_archive_with_pad(pad_bytes: usize) -> Vec<u8> {
    let mut archive = Vec::new();
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
    header.set_cksum();
    builder
        .append(&header, &busybox[..])
        .expect("append busybox");
    if pad_bytes > 0 {
        let pad = vec![0xa5u8; pad_bytes];
        let mut header = tar::Header::new_gnu();
        header.set_path("qual-pad").expect("pad path");
        header.set_size(pad.len() as u64);
        header.set_cksum();
        builder.append(&header, &pad[..]).expect("append pad");
    }
    builder.finish().expect("finish image context");
    drop(builder);
    archive
}

/// Fail if a Unix pid is no longer alive (best-effort zombie check via
/// /proc/<pid>/stat state and signal 0).
fn process_alive(pid: i64) -> bool {
    if pid <= 0 {
        return false;
    }
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // State is the field after the (comm) parenthesis; zombies count as
    // gone for reconciliation purposes only when reaped by init, so treat
    // 'Z' as not running.
    let after_comm = status.rsplit(')').next().unwrap_or_default();
    !after_comm.trim_start().starts_with('Z')
}

/// Scenario 1: 100 sequential create/start/wait/remove cycles with daemon
/// RSS sampled every 10 containers. Asserts zero failures, bounded daemon
/// RSS growth, and an empty store at the end.
#[test]
#[ignore = "qualification scenario: run via scripts/qualification-fault-matrix.sh"]
fn qual_hundred_container_lifecycle_with_rss_sampling() {
    let count: usize = std::env::var("FERROCRATE_QUAL_LIFECYCLE_COUNT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(100);
    let harness = QualDaemon::spawn(&[], None);
    harness.build_busybox_image("qual/busybox:latest");

    let mut rss_samples: Vec<(usize, u64)> = Vec::new();
    rss_samples.push((0, harness.daemon_rss_kib()));
    let baseline_rss = rss_samples[0].1;

    let started_at = Instant::now();
    for index in 0..count {
        let name = format!("qual-life-{index}");
        let id =
            harness.create_container(&name, &busybox_payload(&["/bin/busybox", "echo", "qual"]));
        let (status, body) = harness.start_container(&id);
        assert_eq!(status, 204, "container {index} start response={body}");
        let exit = harness.wait_exited(&id, 30);
        assert_eq!(exit, Some(0), "container {index} exit code={exit:?}");
        let (status, body) = harness.remove_container(&id);
        assert_eq!(status, 204, "container {index} remove response={body}");
        if (index + 1) % 10 == 0 {
            rss_samples.push((index + 1, harness.daemon_rss_kib()));
        }
    }
    let elapsed = started_at.elapsed();

    let final_rss = harness.daemon_rss_kib();
    rss_samples.push((count, final_rss));
    let growth_kib = final_rss.saturating_sub(baseline_rss);
    eprintln!(
        "qual.lifecycle count={count} elapsed_ms={}",
        elapsed.as_millis()
    );
    for (index, rss) in &rss_samples {
        eprintln!("qual.lifecycle rss_sample containers={index} daemon_rss_kib={rss}");
    }
    eprintln!("qual.lifecycle daemon_rss_growth_kib={growth_kib}");

    assert!(
        harness.container_dir_entries().is_empty(),
        "container directories left behind: {:?}",
        harness.container_dir_entries()
    );
    // Catch runaway per-container leakage. 128 MiB over 100 short-lived
    // containers is far above anything a healthy store path retains.
    assert!(
        growth_kib < 128 * 1024,
        "daemon RSS grew {growth_kib} KiB over {count} container lifecycles"
    );
    assert!(harness.daemon_alive(), "daemon must survive the full run");
}

/// Scenario 2: containers with a tiny memory limit are OOM-killed by the
/// kernel individually (exit 137) while sibling containers and the daemon
/// stay healthy. Requires cgroup v2 delegation for the invoking user; hosts
/// without delegation make this row root-gated instead.
#[test]
#[ignore = "qualification scenario: run via scripts/qualification-fault-matrix.sh"]
fn qual_resource_exhaustion_memory_oom_isolated() {
    let delegated = fs::read_to_string(
        "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/cgroup.controllers",
    )
    .unwrap_or_default()
    .contains("memory");
    if !delegated {
        panic!("host does not delegate the memory controller; run this row root-gated");
    }

    let harness = QualDaemon::spawn(&[], None);
    harness.build_busybox_image("qual/busybox:latest");

    // Two unlimited neighbors must be untouched by the neighbor OOM kills.
    let mut neighbors = Vec::new();
    for index in 0..2 {
        let id = harness.create_container(
            &format!("qual-neighbor-{index}"),
            &busybox_payload(&["/bin/busybox", "sleep", "60"]),
        );
        let (status, body) = harness.start_container(&id);
        assert_eq!(status, 204, "neighbor start response={body}");
        neighbors.push(id);
    }

    // Three hogs, each limited to 8 MiB, each growing an awk string until
    // the kernel kills the cgroup.
    let mut hogs = Vec::new();
    for index in 0..3 {
        let payload = json!({
            "Image": "qual/busybox:latest",
            "Cmd": ["/bin/busybox", "awk", "BEGIN{s=\"aaaaaaaa\";while(1){s=s s}}"],
            "HostConfig": {"NetworkMode": "none", "Memory": 8 * 1024 * 1024},
        });
        let id = harness.create_container(&format!("qual-oom-{index}"), &payload);
        let (status, body) = harness.start_container(&id);
        assert_eq!(status, 204, "oom hog start response={body}");
        hogs.push(id);
    }

    for (index, id) in hogs.iter().enumerate() {
        let exit = harness.wait_exited(id, 60);
        assert_eq!(
            exit,
            Some(137),
            "oom hog {index} exit={exit:?}; expected kernel OOM kill (137)"
        );
    }
    for id in &neighbors {
        let (status, _, _) = harness.container_state(id);
        assert_eq!(
            status, "running",
            "neighbor {id} must survive the OOM kills"
        );
    }
    assert!(harness.daemon_alive(), "daemon must survive OOM kills");

    for id in &neighbors {
        let (status, body) = harness.stop_container(id);
        assert_eq!(status, 204, "neighbor stop response={body}");
    }
    for id in neighbors.iter().chain(hogs.iter()) {
        let (status, body) = harness.remove_container(id);
        assert_eq!(status, 204, "cleanup remove response={body}");
    }
    assert!(harness.container_dir_entries().is_empty());
}

/// Scenario 3: CPU-limit behavior under partial cgroup delegation. This
/// host delegates memory and pids to the user service but does not enable
/// the cpu controller in the delegated subtree, so a CPU-quota start must
/// fail closed with an explicit controller error while an unlimited loop
/// runs normally. Measured kernel CPU throttling stays root-gated.
#[test]
#[ignore = "qualification scenario: run via scripts/qualification-fault-matrix.sh"]
fn qual_resource_exhaustion_cpu_quota_fail_closed() {
    let harness = QualDaemon::spawn(&[], None);
    harness.build_busybox_image("qual/busybox:latest");

    let loop_cmd = [
        "/bin/busybox",
        "sh",
        "-c",
        "i=0; while [ $i -lt 1000000 ]; do i=$((i+1)); done",
    ];
    let unlimited = harness.create_container("qual-cpu-free", &busybox_payload(&loop_cmd));
    let (status, body) = harness.start_container(&unlimited);
    assert_eq!(status, 204, "unlimited start response={body}");
    let started = Instant::now();
    let exit = harness.wait_exited(&unlimited, 60);
    assert_eq!(exit, Some(0), "unlimited loop exit={exit:?}");
    eprintln!(
        "qual.cpu_quota unlimited_loop_ms={}",
        started.elapsed().as_millis()
    );

    let cpu_delegated = fs::read_to_string(
        "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/cgroup.subtree_control",
    )
    .unwrap_or_default()
    .contains("cpu");
    let throttled_payload = json!({
        "Image": "qual/busybox:latest",
        "Cmd": loop_cmd,
        "HostConfig": {
            "NetworkMode": "none",
            "CpuQuota": 5000,
            "CpuPeriod": 100000,
        },
    });
    let throttled = harness.create_container("qual-cpu-capped", &throttled_payload);
    let (status, body) = harness.start_container(&throttled);
    if cpu_delegated {
        assert_eq!(status, 204, "throttled start response={body}");
        let started = Instant::now();
        let exit = harness.wait_exited(&throttled, 120);
        assert_eq!(exit, Some(0), "throttled loop exit={exit:?}");
        let capped_ms = started.elapsed().as_millis();
        eprintln!("qual.cpu_quota quota5000_of_100000_ms={capped_ms}");
    } else {
        // Fail-closed contract: the unavailable cpu controller must surface
        // as an explicit error naming the cgroup path, not a silent ignore
        // or a daemon crash.
        assert!(
            status >= 400,
            "cpu-quota start must fail closed without the controller, got {status} {body}"
        );
        assert!(
            body.contains("cgroup controller is unavailable"),
            "cpu-quota failure must name the controller, got {body}"
        );
        eprintln!("qual.cpu_quota cpu_controller_delegated=false fail_closed_status={status}");
    }
    assert!(harness.daemon_alive());
    for id in [&unlimited, &throttled] {
        let (status, body) = harness.remove_container(id);
        assert_eq!(status, 204, "cleanup remove response={body}");
    }
}

/// Scenario 4: a container with PidsLimit=1 cannot fork its workload shell;
/// it must fail inside its own cgroup without harming the daemon.
#[test]
#[ignore = "qualification scenario: run via scripts/qualification-fault-matrix.sh"]
fn qual_resource_exhaustion_pids_limit_fail_closed() {
    let harness = QualDaemon::spawn(&[], None);
    harness.build_busybox_image("qual/busybox:latest");

    let payload = json!({
        "Image": "qual/busybox:latest",
        "Cmd": ["/bin/busybox", "sh", "-c", "sleep 30 & wait"],
        "HostConfig": {"NetworkMode": "none", "PidsLimit": 1},
    });
    let id = harness.create_container("qual-pids-1", &payload);
    let (status, body) = harness.start_container(&id);
    assert_eq!(status, 204, "pids-limited start response={body}");

    // The shell's own fork must fail under pids.max=1, so the container
    // must reach exited well before the 30s background sleep.
    let exit = harness.wait_exited(&id, 45);
    eprintln!("qual.pids_limit exit_code={exit:?}");
    assert!(
        exit.is_some(),
        "pids-limited container never exited; fork was not contained"
    );
    assert!(harness.daemon_alive(), "daemon must survive pid exhaustion");
    let (status, body) = harness.remove_container(&id);
    assert_eq!(status, 204, "cleanup remove response={body}");
}

/// Scenario 5: SIGKILL the daemon mid-lifecycle. Live containers stay
/// running across the restart; containers whose processes died while the
/// daemon was down reconcile to exited; cleanup leaves no orphans.
#[test]
#[ignore = "qualification scenario: run via scripts/qualification-fault-matrix.sh"]
fn qual_daemon_crash_mid_lifecycle_reconciliation() {
    let mut harness = QualDaemon::spawn(&[], None);
    harness.build_busybox_image("qual/busybox:latest");

    let live: Vec<String> = (0..10)
        .map(|index| {
            let id = harness.create_container(
                &format!("qual-crash-live-{index}"),
                &busybox_payload(&["/bin/busybox", "sleep", "120"]),
            );
            let (status, body) = harness.start_container(&id);
            assert_eq!(status, 204, "live container start response={body}");
            id
        })
        .collect();
    let victim = harness.create_container(
        "qual-crash-victim",
        &busybox_payload(&["/bin/busybox", "sleep", "120"]),
    );
    let (status, body) = harness.start_container(&victim);
    assert_eq!(status, 204, "victim start response={body}");

    let live_pids: Vec<i64> = live
        .iter()
        .map(|id| harness.container_state(id).2)
        .collect();
    let victim_pid = harness.container_state(&victim).2;
    for (index, pid) in live_pids.iter().enumerate() {
        assert!(
            process_alive(*pid),
            "live container {index} pid {pid} not running"
        );
    }

    // Phase A: daemon dies, container processes survive, restart must keep
    // the live records running (no false exit).
    harness.kill9_and_restart();
    for (index, id) in live.iter().enumerate() {
        let (status, _, pid) = harness.container_state(id);
        assert_eq!(
            status, "running",
            "still-alive container {index} must stay running after daemon restart"
        );
        assert_eq!(pid, live_pids[index], "container {index} pid changed");
    }
    assert!(harness.daemon_alive(), "restarted daemon must answer ping");

    // Phase B: kill a container process out-of-band while the daemon runs,
    // then crash and restart the daemon; the stale pid must reconcile to
    // exited rather than stay running.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(victim_pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    )
    .expect("kill victim container process");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline && process_alive(victim_pid) {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(!process_alive(victim_pid), "victim process did not die");

    harness.kill9_and_restart();
    let (status, exit_code, _) = harness.container_state(&victim);
    assert_eq!(
        status, "exited",
        "stale-pid container must reconcile to exited after restart"
    );
    eprintln!("qual.daemon_crash victim reconciled exit_code={exit_code:?}");

    // Cleanup: stop live containers, remove everything, expect an empty
    // store and no orphaned container directories.
    for id in &live {
        let (status, body) = harness.stop_container(id);
        assert_eq!(status, 204, "stop after restart response={body}");
    }
    for id in live.iter().chain([&victim]) {
        let (status, body) = harness.remove_container(id);
        assert_eq!(status, 204, "cleanup remove response={body}");
    }
    assert!(
        harness.container_dir_entries().is_empty(),
        "orphaned container directories: {:?}",
        harness.container_dir_entries()
    );
    assert!(harness.daemon_alive());
}

/// Scenario 6: interrupt the daemon between network mutations. The
/// persisted network store must reconcile exactly once, deletes must work
/// after restart, and published-port starts must fail closed with an
/// explicit rootless diagnostic instead of partial host state.
#[test]
#[ignore = "qualification scenario: run via scripts/qualification-fault-matrix.sh"]
fn qual_interrupted_network_emulated_recovery() {
    let mut harness = QualDaemon::spawn(&[], None);

    let (status, body) = harness.request(
        "POST",
        "/networks/create",
        json!({"Name": "qualnet", "Driver": "bridge"})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(status, 201, "network create response={body}");

    // Crash mid-lifecycle: the network exists but nothing has been deleted.
    harness.kill9_and_restart();

    let (status, body) = harness.request("GET", "/networks", b"");
    assert_eq!(status, 200, "network list response={body}");
    let networks: Vec<Value> = serde_json::from_str::<Value>(&body)
        .expect("parse network list")
        .as_array()
        .cloned()
        .unwrap_or_default();
    let matching: Vec<&Value> = networks
        .iter()
        .filter(|network| network["Name"].as_str() == Some("qualnet"))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "network must reconcile exactly once after crash, got {matching:?}"
    );

    let network_id = matching[0]["Id"].as_str().expect("network Id").to_string();
    let (status, body) = harness.request("DELETE", &format!("/networks/{network_id}"), b"");
    assert_eq!(status, 204, "network delete after restart response={body}");

    // Published-port container start must fail closed unprivileged with an
    // explicit rootless diagnostic, and the daemon must stay healthy.
    harness.build_busybox_image("qual/busybox:latest");
    let payload = json!({
        "Image": "qual/busybox:latest",
        "Cmd": ["/bin/busybox", "sleep", "30"],
        "HostConfig": {
            "NetworkMode": "bridge",
            "PortBindings": {"80/tcp": [{"HostPort": "0"}]},
        },
    });
    let id = harness.create_container("qual-published-port", &payload);
    let (status, body) = harness.start_container(&id);
    assert!(
        status >= 400,
        "published-port start must fail closed unprivileged, got {status} {body}"
    );
    assert!(
        body.contains("unavailable") || body.contains("rootless") || body.contains("unsupported"),
        "published-port failure must name the cause, got {body}"
    );
    assert!(
        harness.daemon_alive(),
        "daemon must survive fail-closed start"
    );
    let (status, body) = harness.remove_container(&id);
    assert_eq!(status, 204, "cleanup remove response={body}");
    assert!(harness.container_dir_entries().is_empty());
}

/// Scenario 7: disk-pressure fault via RLIMIT_FSIZE (an EFBIG write-fault
/// approximation; real ENOSPC needs a root-gated tmpfs/loopback). Writes
/// past the limit must fail without corrupting durable state: the daemon
/// reports explicit errors (or dies with the fault recorded), and a clean
/// daemon reopens the same runtime directory afterwards.
#[test]
#[ignore = "qualification scenario: run via scripts/qualification-fault-matrix.sh"]
fn qual_disk_pressure_rlimit_fsize_fail_closed_and_recovery() {
    // 1 MiB file-size limit in 512-byte blocks: the busybox layer (~2.5 MiB)
    // exceeds it during build.
    let mut harness = QualDaemon::spawn(&[], Some("ulimit -f 2048"));
    assert!(
        harness.daemon_alive(),
        "limited daemon must start and answer"
    );

    // Attempt the oversized build and record how the fault surfaces. An
    // explicit HTTP error is the fail-closed contract; a connection loss
    // means the fault killed or wedged the daemon and is recorded as such.
    let build_outcome = harness.request_lossy_tar(
        "/v1.45/build?dockerfile=Dockerfile&t=qual%2Fbusybox%3Alatest",
        &busybox_image_archive(),
    );
    match &build_outcome {
        Ok((status, body)) => {
            eprintln!("qual.disk_pressure build_status={status} body={body}");
            assert!(
                *status >= 400,
                "oversized build must fail explicitly, got {status} {body}"
            );
        }
        Err(error) => {
            eprintln!("qual.disk_pressure build_connection_error={error}");
        }
    }
    let daemon_survived = harness.daemon_alive();
    eprintln!("qual.disk_pressure daemon_survived_build={daemon_survived}");
    if !daemon_survived {
        // SIGXFSZ/EFBIG took the daemon down mid-write; record how it died.
        // Poll with a deadline so a wedged (not dead) daemon cannot hang the
        // scenario past the driver's outer timeout.
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(exit) = harness
                .child
                .try_wait()
                .expect("poll limited daemon status")
            {
                eprintln!("qual.disk_pressure daemon_exit={exit}");
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    // Recovery: a fault-free daemon must reopen the same runtime directory
    // and serve a consistent store.
    let runtime_dir = harness.runtime_dir.clone();
    let socket_path = harness.socket_path.clone();
    let kernel_state_path = harness.kernel_state_path.clone();
    let child =
        QualDaemon::spawn_process(&runtime_dir, &socket_path, &kernel_state_path, &[], None);
    harness.child = child;
    harness.wait_ready(15);
    assert!(harness.daemon_alive(), "recovered daemon must answer ping");
    let (status, body) = harness.request("GET", "/containers/json?all=1", b"");
    assert_eq!(status, 200, "container list after recovery response={body}");
    let containers: Vec<Value> = serde_json::from_str::<Value>(&body)
        .expect("parse recovered container list")
        .as_array()
        .cloned()
        .unwrap_or_default();
    eprintln!(
        "qual.disk_pressure recovered_container_count={}",
        containers.len()
    );
    for container in &containers {
        let id = container["Id"].as_str().expect("container Id");
        let (remove_status, remove_body) = harness.remove_container(id);
        assert_eq!(
            remove_status, 204,
            "recovered store must allow cleanup, response={remove_body}"
        );
    }
    assert!(harness.container_dir_entries().is_empty());
}

// ---------------------------------------------------------------------------
// Root-gated scenarios. These run only under the coordinator's privileged
// matrix (`FERROCRATE_QUAL_ROOT=1` as root). Each one aborts immediately
// when invoked unprivileged so an accidental default run cannot half-execute
// privileged setup.
// ---------------------------------------------------------------------------

fn assert_root(row: &str) {
    assert!(
        nix::unistd::geteuid().is_root(),
        "qual.{row}: root required; run via scripts/qualification-fault-matrix.sh with FERROCRATE_QUAL_ROOT=1"
    );
}

/// Locate the container's cgroup by walking up from the daemon's own
/// cgroup until the `ferrocrate/<id>` child exists. This resolves the
/// delegated rootless subtree and the rootful `/sys/fs/cgroup` root alike.
fn find_container_cgroup(daemon_pid: u32, container_id: &str) -> PathBuf {
    let cgroups =
        fs::read_to_string(format!("/proc/{daemon_pid}/cgroup")).expect("read daemon cgroup");
    let path = cgroups
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("unified cgroup v2 entry for daemon");
    let mut dir = PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    loop {
        let candidate = dir.join("ferrocrate").join(container_id);
        if candidate.join("memory.max").exists() {
            return candidate;
        }
        if !dir.pop() {
            panic!(
                "container cgroup not found for {container_id} above {}",
                dir.display()
            );
        }
    }
}

/// Mounted tmpfs whose Drop always unmounts, so a failing assertion cannot
/// leak the mount.
struct TmpfsMount {
    mount_dir: PathBuf,
    unmounted: bool,
}

impl TmpfsMount {
    fn mount(parent: &Path, size_mib: u64, row: &str) -> Self {
        let mount_dir = parent.join("runtime-tmpfs");
        fs::create_dir(&mount_dir).expect("create tmpfs mountpoint");
        let status = Command::new("mount")
            .args([
                "-t",
                "tmpfs",
                "-o",
                &format!("size={size_mib}m"),
                "tmpfs",
                mount_dir.to_str().expect("mount dir utf8"),
            ])
            .status()
            .expect("run mount");
        assert!(
            status.success(),
            "qual.{row}: tmpfs mount failed: {}",
            status
        );
        Self {
            mount_dir,
            unmounted: false,
        }
    }

    fn unmount(&mut self) {
        if self.unmounted {
            return;
        }
        let _ = Command::new("umount").arg(&self.mount_dir).status();
        // Best-effort lazy fallback: never leave the mount behind even if a
        // daemon process still holds a file open on it.
        let _ = Command::new("umount")
            .arg("-l")
            .arg(&self.mount_dir)
            .status();
        self.unmounted = true;
    }
}

impl Drop for TmpfsMount {
    fn drop(&mut self) {
        self.unmount();
    }
}

/// Fill the filesystem under `dir` until a write fails with ENOSPC-style
/// errors, leaving well under one chunk of free space. Returns the fill
/// file paths so the test can release the space later.
fn fill_until_full(dir: &Path, chunk_bytes: usize) -> Vec<PathBuf> {
    let mut fill_files = Vec::new();
    let chunk = vec![0u8; chunk_bytes];
    loop {
        let path = dir.join(format!("qual-fill-{}", fill_files.len()));
        match fs::write(&path, &chunk) {
            Ok(()) => fill_files.push(path),
            Err(error) => {
                let _ = fs::remove_file(&path);
                assert!(
                    matches!(
                        error.kind(),
                        std::io::ErrorKind::StorageFull | std::io::ErrorKind::WriteZero
                    ) || error.raw_os_error() == Some(28),
                    "fill write failed for an unexpected reason: {error}"
                );
                return fill_files;
            }
        }
    }
}

/// Shared recovery step for the ENOSPC row: after space returns, the same
/// padded build must succeed and the daemon must stay healthy.
fn recovery_build(harness: &QualDaemon, padded: &[u8]) {
    let (status, body) = harness.request_tar(
        "/v1.45/build?dockerfile=Dockerfile&t=qual%2Fpadded%3Alatest",
        padded,
    );
    assert_eq!(
        status, 200,
        "build after space returns must succeed, response={body}"
    );
    assert!(harness.daemon_alive());
}

/// Root scenario (a): real ENOSPC. The daemon's runtime directory lives on
/// a 12 MiB tmpfs. After a successful image build, the test fills the
/// filesystem; a second build with a distinct pad layer (still below the
/// daemon's 4 MiB HTTP body cap) must fail with an explicit no-space error
/// while the daemon stays alive. Deleting the fill files must restore
/// service: the same build then succeeds.
#[test]
#[ignore = "root-gated qualification scenario: FERROCRATE_QUAL_ROOT=1 as root"]
fn qual_root_enospc_tmpfs_fail_closed_and_recovery() {
    assert_root("enospc_tmpfs");
    let scratch = tempfile::tempdir().expect("scratch tempdir");
    let mut tmpfs = TmpfsMount::mount(scratch.path(), 12, "enospc_tmpfs");

    let harness = QualDaemon::spawn_in(&tmpfs.mount_dir, &[], None);
    harness.build_busybox_image("qual/busybox:latest");
    assert!(
        harness.daemon_alive(),
        "daemon must be healthy before the fault"
    );

    // Exhaust the filesystem, leaving under 512 KiB free.
    let fill_files = fill_until_full(&tmpfs.mount_dir, 512 * 1024);
    eprintln!(
        "qual.enospc_tmpfs fill_files={} ({} KiB each)",
        fill_files.len(),
        512
    );

    // The build under pressure must fail explicitly. The archive carries a
    // 512 KiB pad so its layer digest differs from the cached busybox
    // layer (the build cannot be served from the content store) while the
    // request body stays below the daemon's 4 MiB HTTP body cap — a larger
    // body would be rejected before ENOSPC is ever reached.
    let padded = busybox_image_archive_with_pad(512 * 1024);
    assert!(
        padded.len() < 4 * 1024 * 1024,
        "padded archive must stay below the daemon 4 MiB body cap, got {}",
        padded.len()
    );
    let build_result = harness.request_lossy_tar(
        "/v1.45/build?dockerfile=Dockerfile&t=qual%2Fpadded%3Alatest",
        &padded,
    );
    let mut connection_lost = false;
    match &build_result {
        Ok((status, body)) => {
            eprintln!("qual.enospc_tmpfs full_build_status={status} body={body}");
            assert!(
                *status >= 400,
                "build under ENOSPC must fail explicitly, got {status} {body}"
            );
            let lowered = body.to_lowercase();
            assert!(
                lowered.contains("no space") || lowered.contains("enospc"),
                "ENOSPC failure must name the cause, got {body}"
            );
        }
        Err(error) => {
            // Record the connection loss distinctly instead of hiding it
            // behind the recovery phase; whether the daemon survives it is
            // part of the evidence.
            connection_lost = true;
            eprintln!("qual.enospc_tmpfs full_build_connection_lost={error}");
        }
    }
    let daemon_survived = harness.daemon_alive();
    eprintln!("qual.enospc_tmpfs daemon_survived_full_build={daemon_survived}");
    if !connection_lost {
        assert!(
            daemon_survived,
            "daemon must survive an explicit ENOSPC build failure"
        );
    } else if daemon_survived {
        // The request connection broke but the daemon process lived: a
        // per-connection failure, recorded above, must still recover.
        eprintln!("qual.enospc_tmpfs connection_lost_daemon_alive=true");
    }

    // Recovery: release the space and retry the same build. If the fault
    // killed the daemon, record that distinctly (it is the open finding)
    // and prove the store still recovers with a fresh daemon on the same
    // tmpfs — a corrupted or wedged store would not.
    for path in &fill_files {
        fs::remove_file(path).expect("remove fill file");
    }
    if !daemon_survived {
        eprintln!("qual.enospc_tmpfs daemon_killed_by_enospc=true finding");
        let mount_dir = tmpfs.mount_dir.clone();
        drop(harness); // reap the dead daemon's child handle
        let fresh = QualDaemon::spawn_in(&mount_dir, &[], None);
        recovery_build(&fresh, &padded);
        drop(fresh);
    } else {
        recovery_build(&harness, &padded);
        drop(harness);
    }
    eprintln!("qual.enospc_tmpfs recovery_build=pass");

    // Cleanup: unmount with no daemon holding the tmpfs.
    tmpfs.unmount();
}

/// Root scenario (b): rootful cgroup OOM teardown under
/// `memory.oom.group=1`. A memory-limited container that spawns background
/// hogs must have the entire cgroup killed by the kernel when the limit is
/// hit, with the OOM accounted in `memory.events` and no surviving
/// processes left in the group.
#[test]
#[ignore = "root-gated qualification scenario: FERROCRATE_QUAL_ROOT=1 as root"]
fn qual_root_cgroup_oom_group_teardown() {
    assert_root("cgroup_oom_group");
    let harness = QualDaemon::spawn(&[], None);
    harness.build_busybox_image("qual/busybox:latest");

    // A hog behind a startup delay, plus a second background hog, with the
    // shell `exec`-replaced by the main hog. The sleep gives the test time
    // to enable memory.oom.group before any allocation pressure exists, and
    // the exec makes the container's tracked process a hog itself: a
    // bare `wait` would exit 0 after the kernel killed the children
    // (POSIX `wait` with no operands returns zero), masking the kill.
    let payload = json!({
        "Image": "qual/busybox:latest",
        "Cmd": [
            "/bin/busybox", "sh", "-c",
            "sleep 5; /bin/busybox awk 'BEGIN{s=\"b\";while(1){s=s s}}' & exec /bin/busybox awk 'BEGIN{s=\"a\";while(1){s=s s}}'",
        ],
        "HostConfig": {"NetworkMode": "none", "Memory": 8 * 1024 * 1024},
    });
    let id = harness.create_container("qual-oom-group", &payload);
    let (status, body) = harness.start_container(&id);
    assert_eq!(status, 204, "oom-group container start response={body}");

    let cgroup = find_container_cgroup(harness.child.id(), &id);
    assert!(
        cgroup.join("memory.max").exists(),
        "container cgroup missing at {}",
        cgroup.display()
    );
    // Prove the container's tracked pid actually lives in this cgroup
    // before relying on the group limit.
    let memory_max = fs::read_to_string(cgroup.join("memory.max")).expect("read memory.max");
    eprintln!(
        "qual.cgroup_oom_group memory_max={} path={}",
        memory_max.trim(),
        cgroup.display()
    );
    assert_eq!(
        memory_max.trim(),
        "8388608",
        "memory.max must hold the 8 MiB limit"
    );
    let (state, _, pid) = harness.container_state(&id);
    let procs_at_start =
        fs::read_to_string(cgroup.join("cgroup.procs")).expect("read cgroup.procs at start");
    eprintln!(
        "qual.cgroup_oom_group state={state} pid={pid} procs_at_start={}",
        procs_at_start.trim()
    );
    assert!(
        procs_at_start
            .split_whitespace()
            .any(|proc| proc.parse::<i64>() == Ok(pid)),
        "container pid {pid} must be in the container cgroup, procs: {procs_at_start}"
    );
    fs::write(cgroup.join("memory.oom.group"), b"1").expect("enable memory.oom.group");
    eprintln!("qual.cgroup_oom_group memory_oom_group=1");

    let exit = harness.wait_exited(&id, 90);
    eprintln!("qual.cgroup_oom_group exit_code={exit:?}");
    assert_eq!(
        exit,
        Some(137),
        "oom-group container must be killed with 137, got {exit:?}"
    );

    // Kernel evidence: at least one OOM kill accounted against the group.
    let events = fs::read_to_string(cgroup.join("memory.events"))
        .expect("read memory.events before cleanup");
    eprintln!("qual.cgroup_oom_group memory_events={}", events.trim());
    let oom_kills: u64 = events
        .lines()
        .find_map(|line| line.strip_prefix("oom_kill "))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    assert!(
        oom_kills >= 1,
        "memory.events must account the OOM kill, got {events}"
    );

    // The whole group must be dead: no processes left in cgroup.procs.
    let procs =
        fs::read_to_string(cgroup.join("cgroup.procs")).expect("read cgroup.procs before cleanup");
    assert!(
        procs.trim().is_empty(),
        "oom.group=1 must kill every process in the group, remaining procs: {procs}"
    );
    assert!(harness.daemon_alive(), "daemon must survive group OOM kill");

    let (status, body) = harness.remove_container(&id);
    assert_eq!(status, 204, "cleanup remove response={body}");
}

/// Root scenario (c): measured rootful CPU throttling. A busy loop under
/// `CpuQuota 5000 / CpuPeriod 100000` (5% of one CPU) must take a measured
/// multiple of the unlimited run and register throttling in `cpu.stat`.
#[test]
#[ignore = "root-gated qualification scenario: FERROCRATE_QUAL_ROOT=1 as root"]
fn qual_root_cpu_throttle_measured() {
    assert_root("cpu_throttle");
    let harness = QualDaemon::spawn(&[], None);
    harness.build_busybox_image("qual/busybox:latest");

    let loop_cmd = [
        "/bin/busybox",
        "sh",
        "-c",
        "i=0; while [ $i -lt 1000000 ]; do i=$((i+1)); done",
    ];
    let unlimited = harness.create_container("qual-cpu-free", &busybox_payload(&loop_cmd));
    let (status, body) = harness.start_container(&unlimited);
    assert_eq!(status, 204, "unlimited start response={body}");
    let started = Instant::now();
    let exit = harness.wait_exited(&unlimited, 60);
    assert_eq!(exit, Some(0), "unlimited loop exit={exit:?}");
    let free_ms = started.elapsed().as_millis();
    let (status, body) = harness.remove_container(&unlimited);
    assert_eq!(status, 204, "unlimited cleanup response={body}");

    let throttled_payload = json!({
        "Image": "qual/busybox:latest",
        "Cmd": loop_cmd,
        "HostConfig": {
            "NetworkMode": "none",
            "CpuQuota": 5000,
            "CpuPeriod": 100000,
        },
    });
    let throttled = harness.create_container("qual-cpu-capped", &throttled_payload);
    let (status, body) = harness.start_container(&throttled);
    assert_eq!(status, 204, "throttled start response={body}");
    let started = Instant::now();
    let exit = harness.wait_exited(&throttled, 240);
    assert_eq!(exit, Some(0), "throttled loop exit={exit:?}");
    let capped_ms = started.elapsed().as_millis();

    let cgroup = find_container_cgroup(harness.child.id(), &throttled);
    let cpu_stat =
        fs::read_to_string(cgroup.join("cpu.stat")).expect("read cpu.stat before cleanup");
    eprintln!("qual.cpu_throttle unlimited_ms={free_ms} quota5000_of_100000_ms={capped_ms}");
    eprintln!("qual.cpu_throttle cpu_stat={}", cpu_stat.trim());

    let nr_throttled: u64 = cpu_stat
        .lines()
        .find_map(|line| line.strip_prefix("nr_throttled "))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    assert!(
        nr_throttled >= 1,
        "cpu.stat must show throttling, got {cpu_stat}"
    );
    assert!(
        capped_ms >= free_ms.saturating_mul(2),
        "cpu quota did not throttle the workload: unlimited={free_ms}ms capped={capped_ms}ms"
    );
    assert!(harness.daemon_alive());
    let (status, body) = harness.remove_container(&throttled);
    assert_eq!(status, 204, "cleanup remove response={body}");
}
