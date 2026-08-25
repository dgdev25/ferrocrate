use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ferro_core::docker_auth::resolve_auth_for_registry;
use ferro_desktop::backend::{
    select_backend, Backend, DuplexStream, TerminalRequest, TransportRequest,
};
use ferro_web::{CommandDispatcher, CommandRequest, EventHub, Server, StaticAssets};
use rust_embed::RustEmbed;
use serde_json::{json, Value};

const LOG_TRUNCATION_MARKER: &str = "[Earlier log output truncated]\n";
const MAX_LOG_LINES: usize = 2_000;
const MAX_LOG_BYTES: usize = 512 * 1024;
const LOG_CHANNEL_CAPACITY: usize = 128;
const LOG_READ_CHUNK_BYTES: usize = 8 * 1024;
const PLACEHOLDER_MARKER: &str = "<!-- ferrocrate-dashboard-placeholder -->";
const PLACEHOLDER_MESSAGE: &str = "The dashboard UI was not bundled in this build. Run `npm ci && npm run build` in apps/ferro-desktop-ui, then rebuild ferro-cli.";

#[derive(RustEmbed)]
#[folder = "$OUT_DIR/ferrocrate-dashboard-dist"]
struct DashboardAssets;

fn dashboard_placeholder_message(index: Option<&[u8]>) -> Option<String> {
    std::str::from_utf8(index?)
        .ok()?
        .contains(PLACEHOLDER_MARKER)
        .then(|| PLACEHOLDER_MESSAGE.to_string())
}

pub(crate) fn unavailable_message() -> Option<String> {
    <DashboardAssets as RustEmbed>::get("index.html")
        .and_then(|asset| dashboard_placeholder_message(Some(asset.data.as_ref())))
}

impl StaticAssets for DashboardAssets {
    fn get(&self, path: &str) -> Option<(Vec<u8>, &'static str)> {
        let path = Path::new(path);
        if path
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return None;
        }
        let path = path.to_str()?;
        let mut bytes = <Self as RustEmbed>::get(path)?.data.into_owned();
        if path == "index.html" {
            let html = String::from_utf8(bytes).ok()?;
            bytes = html
                .replace(
                    "</head>",
                    "<script>window.__FERROCRATE_DASHBOARD__=true</script></head>",
                )
                .into_bytes();
        }
        let mime = match mime_guess::from_path(path)
            .first_or_octet_stream()
            .essence_str()
        {
            "text/html" => "text/html; charset=utf-8",
            "text/css" => "text/css; charset=utf-8",
            "text/javascript" | "application/javascript" => "text/javascript; charset=utf-8",
            "image/svg+xml" => "image/svg+xml",
            "image/png" => "image/png",
            "font/woff2" => "font/woff2",
            _ => "application/octet-stream",
        };
        Some((bytes, mime))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub listen: SocketAddr,
    pub token_file: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub operator_gate: bool,
}

impl Options {
    fn validate(&self) -> Result<(), String> {
        if self.listen.ip().is_loopback() {
            return Ok(());
        }
        if self.tls_cert.is_none() || self.tls_key.is_none() || !self.operator_gate {
            return Err(format!(
                "refusing non-loopback dashboard bind {}; --tls-cert, --tls-key, and --operator-gate are all required",
                self.listen
            ));
        }
        for (label, path) in [
            ("TLS certificate", self.tls_cert.as_deref()),
            ("TLS private key", self.tls_key.as_deref()),
        ] {
            let path = path.expect("validated option");
            if !path.is_file() {
                return Err(format!("{label} does not exist: {}", path.display()));
            }
        }
        Ok(())
    }
}

struct OwnedDaemon {
    child: Option<Child>,
}

impl Drop for OwnedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn runtime_socket() -> Option<PathBuf> {
    std::env::var_os("FERROCRATE_RUNTIME_DIR")
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR"))
        .map(PathBuf::from)
        .map(|path| path.join("ferrocrate.sock"))
}

fn sibling_binary(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join(name)))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

fn ensure_daemon() -> Result<OwnedDaemon, String> {
    let socket = runtime_socket().ok_or_else(|| {
        "FERROCRATE_RUNTIME_DIR or XDG_RUNTIME_DIR is required for the dashboard".to_string()
    })?;
    if socket.exists() {
        return Ok(OwnedDaemon { child: None });
    }
    let mut child = Command::new(sibling_binary("ferro-cli"))
        .arg("daemon")
        .arg("--docker-compat")
        .arg("--socket")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("failed to start desktop supervisor: {error}"))?;
    for _ in 0..100 {
        if runtime_socket().is_some_and(|path| path.exists()) {
            return Ok(OwnedDaemon { child: Some(child) });
        }
        if child
            .try_wait()
            .map_err(|error| format!("failed to inspect desktop supervisor: {error}"))?
            .is_some()
        {
            return Err("desktop supervisor exited before its socket became ready".to_string());
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err("desktop supervisor did not make its socket ready".to_string())
}

fn write_token(path: &Path, token: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".ferrocrate-dashboard-token-")
        .tempfile_in(parent)
        .map_err(|error| format!("failed to create token file {}: {error}", path.display()))?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .and_then(|()| writeln!(temporary, "{token}"))
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| format!("failed to persist token file {}: {error}", path.display()))?;
    temporary.persist(path).map_err(|error| {
        format!(
            "failed to install token file {}: {}",
            path.display(),
            error.error
        )
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "failed to sync token directory {}: {error}",
                parent.display()
            )
        })
}

struct LogBuffer {
    entries: VecDeque<String>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    truncated: bool,
}

impl LogBuffer {
    fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_lines,
            max_bytes,
            truncated: false,
        }
    }

    fn push(&mut self, mut entry: String) {
        if entry.len() > self.max_bytes {
            let mut start = entry.len() - self.max_bytes;
            while !entry.is_char_boundary(start) {
                start += 1;
            }
            entry = entry[start..].to_string();
            self.truncated = true;
        }
        self.bytes += entry.len();
        self.entries.push_back(entry);
        while self.entries.len() > self.max_lines || self.bytes > self.max_bytes {
            if let Some(removed) = self.entries.pop_front() {
                self.bytes -= removed.len();
                self.truncated = true;
            } else {
                break;
            }
        }
    }

    fn text(&self) -> String {
        let mut text = String::new();
        if self.truncated {
            text.push_str(LOG_TRUNCATION_MARKER);
        }
        for entry in &self.entries {
            text.push_str(entry);
        }
        text
    }
}

fn log_channel(capacity: usize) -> (SyncSender<String>, Receiver<String>) {
    mpsc::sync_channel(capacity)
}

fn queue_log_chunks<R: Read>(mut reader: R, sender: SyncSender<String>) {
    let mut chunk = [0_u8; LOG_READ_CHUNK_BYTES];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(bytes) => {
                if sender
                    .send(String::from_utf8_lossy(&chunk[..bytes]).into_owned())
                    .is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn publish_log_batches(events: EventHub, receiver: Receiver<String>) {
    let mut buffer = LogBuffer::new(MAX_LOG_LINES, MAX_LOG_BYTES);
    let mut changed = false;
    let mut last_publish = Instant::now();
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(entry) => {
                buffer.push(entry);
                changed = true;
                while let Ok(entry) = receiver.try_recv() {
                    buffer.push(entry);
                }
                if last_publish.elapsed() >= Duration::from_millis(100) {
                    events.emit(
                        "container-log-batch",
                        json!({ "text": buffer.text(), "truncated": buffer.truncated }),
                    );
                    changed = false;
                    last_publish = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) if changed => {
                events.emit(
                    "container-log-batch",
                    json!({ "text": buffer.text(), "truncated": buffer.truncated }),
                );
                changed = false;
                last_publish = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if changed {
                    events.emit(
                        "container-log-batch",
                        json!({ "text": buffer.text(), "truncated": buffer.truncated }),
                    );
                }
                events.emit("container-log-ended", true);
                return;
            }
        }
    }
}

fn command_result(output: Output) -> Value {
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    json!({
        "ok": output.status.success(),
        "code": output.status.code().unwrap_or(1),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": stderr,
        "message": stderr.lines().find(|line| !line.trim().is_empty()).unwrap_or("").trim(),
    })
}

fn desktop_command(args: &[String], stdin: Option<&[u8]>) -> Result<Output, String> {
    let mut command = Command::new(sibling_binary("ferro-cli"));
    command.args(args);
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to run desktop command: {error}"))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| "desktop command stdin unavailable".to_string())?
            .write_all(input)
            .map_err(|error| format!("failed to write desktop command input: {error}"))?;
    }
    child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for desktop command: {error}"))
}

fn run_command_result(args: &[&str]) -> Result<Value, String> {
    let args = args
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    desktop_command(&args, None).map(command_result)
}

fn run_json(args: &[&str]) -> Result<Value, String> {
    let result = run_command_result(args)?;
    if !result["ok"].as_bool().unwrap_or(false) {
        return Err(result["message"]
            .as_str()
            .unwrap_or("dashboard command failed")
            .to_string());
    }
    serde_json::from_str(result["stdout"].as_str().unwrap_or(""))
        .map_err(|error| format!("dashboard command returned invalid JSON: {error}"))
}

fn volume_summaries(value: &Value) -> Vec<Value> {
    value
        .get("Volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|volume| {
            json!({
                "name": volume["Name"],
                "driver": volume["Driver"],
                "mountpoint": volume["Mountpoint"],
                "created_at": volume["CreatedAt"],
                "mounts": volume.get("FerrocrateMounts").and_then(Value::as_array).cloned().unwrap_or_default(),
            })
        })
        .collect()
}

fn network_summaries(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|network| {
            let subnets = network
                .pointer("/IPAM/Config")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|config| config.get("Subnet").and_then(Value::as_str))
                .collect::<Vec<_>>();
            json!({
                "name": network["Name"],
                "driver": network["Driver"],
                "subnets": subnets,
                "containers": [],
            })
        })
        .collect()
}

fn container_detail(value: &Value) -> Value {
    if value.get("id").is_some() {
        return value.clone();
    }
    let mounts = value
        .get("Mounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|mount| {
            json!({
                "kind": mount.get("Type").and_then(Value::as_str).unwrap_or("bind"),
                "source": mount.get("Source").and_then(Value::as_str).unwrap_or(""),
                "destination": mount.get("Destination").and_then(Value::as_str).unwrap_or(""),
                "access": if mount.get("RW").and_then(Value::as_bool).unwrap_or(true) { "rw" } else { "ro" },
            })
        })
        .collect::<Vec<_>>();
    json!({
        "id": value["Id"],
        "name": value["Name"].as_str().unwrap_or("").trim_start_matches('/'),
        "image": value.pointer("/Config/Image").cloned().unwrap_or(Value::Null),
        "status": value.pointer("/State/Status").cloned().unwrap_or(Value::Null),
        "command": value.pointer("/Config/Cmd").cloned().unwrap_or_else(|| json!([])),
        "environment": value.pointer("/Config/Env").cloned().unwrap_or_else(|| json!([])),
        "working_dir": value.pointer("/Config/WorkingDir").cloned().unwrap_or_else(|| json!("")),
        "user": value.pointer("/Config/User").cloned().unwrap_or_else(|| json!("")),
        "mounts": mounts,
        "health": value.pointer("/State/Health").cloned().unwrap_or(Value::Null),
        "resources": {
            "memory": value.pointer("/HostConfig/Memory").and_then(Value::as_u64).unwrap_or(0),
            "cpu_quota": value.pointer("/HostConfig/CpuQuota").and_then(Value::as_u64).unwrap_or(0),
            "cpu_period": value.pointer("/HostConfig/CpuPeriod").and_then(Value::as_u64).unwrap_or(0),
        },
        "restart_policy": {
            "name": value.pointer("/HostConfig/RestartPolicy/Name").and_then(Value::as_str).unwrap_or("no"),
            "maximum_retry_count": value.pointer("/HostConfig/RestartPolicy/MaximumRetryCount").and_then(Value::as_u64).unwrap_or(0),
        },
    })
}

struct TerminalState {
    stream: Box<dyn DuplexStream>,
    exec_id: String,
}

#[derive(Clone)]
struct ProcessDispatcher {
    log_process: Arc<Mutex<Option<Child>>>,
    terminal: Arc<Mutex<Option<TerminalState>>>,
    backend: Arc<dyn Backend>,
    stopped_container_ids: Arc<Mutex<HashMap<String, String>>>,
}

impl ProcessDispatcher {
    fn new() -> Result<Self, String> {
        Ok(Self {
            log_process: Arc::new(Mutex::new(None)),
            terminal: Arc::new(Mutex::new(None)),
            backend: Arc::from(select_backend().map_err(|error| error.to_string())?),
            stopped_container_ids: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    fn snapshot(&self) -> Result<Value, String> {
        let socket = runtime_socket()
            .map(|path| path.display().to_string())
            .unwrap_or_default();
        let containers = run_command_result(&["containers", "--all", "--format", "json"])?;
        let images = run_command_result(&["images", "--format", "json"])?;
        Ok(json!({
            "daemon": {
                "state": "running", "healthy": true, "socket_path": socket,
                "reason": null, "platform": "linux-native", "custom_networks": false
            },
            "runtime": { "ok": true, "code": 0, "stdout": socket, "stderr": "", "message": "" },
            "containers": containers,
            "images": images
        }))
    }

    fn start_log_follow(&self, target: String, events: EventHub) -> Result<Value, String> {
        if target.trim().is_empty() {
            return Err("target container is required".to_string());
        }
        let mut slot = self
            .log_process
            .lock()
            .map_err(|_| "log follow state is unavailable".to_string())?;
        if slot.is_some() {
            return Err("a container log stream is already active".to_string());
        }
        let mut child = Command::new(sibling_binary("ferro-cli"))
            .arg("logs")
            .arg(target)
            .args(["--follow", "--format", "text"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("failed to start container log stream: {error}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "container log stream stdout unavailable".to_string())?;
        let (log_sender, log_receiver) = log_channel(LOG_CHANNEL_CAPACITY);
        let publish_events = events.clone();
        thread::spawn(move || publish_log_batches(publish_events, log_receiver));
        thread::spawn(move || queue_log_chunks(stdout, log_sender));
        *slot = Some(child);
        Ok(Value::Null)
    }

    fn stop_log_follow(&self) -> Result<Value, String> {
        if let Some(mut child) = self
            .log_process
            .lock()
            .map_err(|_| "log follow state is unavailable".to_string())?
            .take()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(Value::Null)
    }

    fn start_terminal(
        &self,
        args: ferro_web::TerminalArgs,
        events: EventHub,
    ) -> Result<Value, String> {
        if args.target.trim().is_empty() {
            return Err("target container is required".to_string());
        }
        if args.shell.trim().is_empty() {
            return Err("shell command is required".to_string());
        }
        let mut slot = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?;
        if slot.is_some() {
            return Err("an exec terminal is already active".to_string());
        }
        let session = self
            .backend
            .open_terminal(TerminalRequest {
                container: args.target,
                command: vec![args.shell],
                env: args.env,
                user: args.user,
                workdir: args.workdir,
            })
            .map_err(|error| error.to_string())?;
        let mut output = session
            .stream
            .try_clone_stream()
            .map_err(|error| error.to_string())?;
        *slot = Some(TerminalState {
            stream: session.stream,
            exec_id: session.exec_id,
        });
        thread::spawn(move || {
            let mut buffer = [0_u8; 8192];
            loop {
                match output.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes) => events.emit(
                        "terminal-output",
                        json!({ "data": &buffer[..bytes], "stderr": false }),
                    ),
                    Err(error) => {
                        events.emit("terminal-error", error.to_string());
                        break;
                    }
                }
            }
            events.emit("terminal-ended", true);
        });
        Ok(Value::Null)
    }

    fn write_terminal(&self, data: Vec<u8>) -> Result<Value, String> {
        if data.len() > 64 * 1024 {
            return Err("terminal input exceeds 64 KiB".to_string());
        }
        let mut slot = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?;
        let terminal = slot
            .as_mut()
            .ok_or_else(|| "no exec terminal is active".to_string())?;
        terminal
            .stream
            .write_all(&data)
            .and_then(|()| terminal.stream.flush())
            .map_err(|error| format!("failed to write terminal input: {error}"))?;
        Ok(Value::Null)
    }

    fn resize_terminal(&self, columns: u16, rows: u16) -> Result<Value, String> {
        if columns == 0 || rows == 0 {
            return Err("terminal dimensions must be non-zero".to_string());
        }
        let exec_id = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?
            .as_ref()
            .map(|terminal| terminal.exec_id.clone())
            .ok_or_else(|| "no exec terminal is active".to_string())?;
        self.backend
            .resize_terminal(&exec_id, columns, rows)
            .map_err(|error| error.to_string())?;
        Ok(Value::Null)
    }

    fn close_terminal(&self) -> Result<Value, String> {
        if let Some(terminal) = self
            .terminal
            .lock()
            .map_err(|_| "terminal state is unavailable".to_string())?
            .take()
        {
            terminal
                .stream
                .shutdown_write()
                .map_err(|error| error.to_string())?;
        }
        Ok(Value::Null)
    }
}

fn value_string(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .ok_or_else(|| "invalid command action".to_string())
}

impl CommandDispatcher for ProcessDispatcher {
    fn dispatch(&self, request: CommandRequest, events: EventHub) -> Result<Value, String> {
        match request {
            CommandRequest::GetDesktopSnapshot => self.snapshot(),
            CommandRequest::GetContainerStats(args) => {
                let started = Instant::now();
                let first = args
                    .ids
                    .iter()
                    .map(|id| {
                        (
                            id.clone(),
                            run_json(&["stats", id, "--format", "json"]).ok(),
                        )
                    })
                    .collect::<HashMap<_, _>>();
                thread::sleep(Duration::from_millis(100));
                let elapsed = started.elapsed().as_micros() as f64;
                let mut samples = Vec::new();
                for id in args.ids {
                    let value = run_json(&["stats", &id, "--format", "json"]).ok();
                    let before = first
                        .get(&id)
                        .and_then(Option::as_ref)
                        .and_then(|item| item.pointer("/cpu_stats/cpu_usage/total_usage"))
                        .and_then(Value::as_u64);
                    let after = value
                        .as_ref()
                        .and_then(|item| item.pointer("/cpu_stats/cpu_usage/total_usage"))
                        .and_then(Value::as_u64);
                    let cpu_percent =
                        before
                            .zip(after)
                            .filter(|_| elapsed > 0.0)
                            .map(|(before, after)| {
                                after.saturating_sub(before) as f64 / 1_000.0 / elapsed * 100.0
                            });
                    let memory_usage = value.as_ref().and_then(|item| {
                        item.pointer("/memory_stats/usage").and_then(Value::as_u64)
                    });
                    samples.push(json!({
                        "id": id,
                        "available": cpu_percent.is_some() && memory_usage.is_some(),
                        "memory_usage": memory_usage,
                        "memory_limit": value.as_ref().and_then(|item| item.pointer("/memory_stats/limit")).and_then(Value::as_u64),
                        "cpu_percent": cpu_percent
                    }));
                }
                Ok(json!({ "samples": samples }))
            }
            CommandRequest::GetVolumes => Ok(Value::Array(volume_summaries(&run_json(&[
                "volume", "ls", "--format", "json",
            ])?))),
            CommandRequest::GetNetworks => Ok(Value::Array(network_summaries(&run_json(&[
                "network", "ls", "--format", "json",
            ])?))),
            CommandRequest::GetContainerDetail(args) => Ok(container_detail(&run_json(&[
                "inspect",
                &args.target,
                "--format",
                "json",
            ])?)),
            CommandRequest::GetComposeSnapshot(args) => {
                let config = run_command_result(&["compose", "-f", &args.file, "config"])?;
                if !config["ok"].as_bool().unwrap_or(false) {
                    return Err(config["message"]
                        .as_str()
                        .unwrap_or("compose config failed")
                        .to_string());
                }
                let yaml = config["stdout"].as_str().unwrap_or("");
                let parsed: serde_yaml::Value = serde_yaml::from_str(yaml)
                    .map_err(|error| format!("compose config returned invalid YAML: {error}"))?;
                let services = parsed
                    .get("services")
                    .and_then(serde_yaml::Value::as_mapping)
                    .into_iter()
                    .flat_map(|mapping| mapping.keys())
                    .filter_map(serde_yaml::Value::as_str)
                    .map(|name| json!({ "name": name, "status": "not_created", "container_id": null }))
                    .collect::<Vec<_>>();
                Ok(json!({ "config": yaml, "services": services }))
            }
            CommandRequest::BuildImage(args) => {
                let values = ["build", &args.context, "--tag", &args.tag]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
                let output = desktop_command(&values, None)?;
                for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
                    for line in String::from_utf8_lossy(bytes).lines() {
                        events.emit(
                            "image-build-progress",
                            json!({ "build_id": args.build_id, "stream": stream, "text": line }),
                        );
                    }
                }
                Ok(command_result(output))
            }
            CommandRequest::RunDesktopAction(args) => {
                let target = args.target.unwrap_or_default();
                if value_string(&args.action)? == "stop_container" {
                    if let Ok(detail) = run_json(&["inspect", &target, "--format", "json"]) {
                        let id = detail
                            .get("Id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        if !id.is_empty() {
                            self.stopped_container_ids
                                .lock()
                                .map_err(|_| "stopped-container state is unavailable".to_string())?
                                .insert(target.clone(), id);
                        }
                    }
                }
                let resolved_target = if value_string(&args.action)? == "start_container" {
                    self.stopped_container_ids
                        .lock()
                        .map_err(|_| "stopped-container state is unavailable".to_string())?
                        .get(&target)
                        .cloned()
                        .unwrap_or_else(|| target.clone())
                } else {
                    target.clone()
                };
                let command = match value_string(&args.action)? {
                    "pull_image" => vec!["pull", &target],
                    "remove_image" => vec!["rmi", &target],
                    "start_container" => vec!["start", &resolved_target],
                    "stop_container" => vec!["stop", &target],
                    "remove_container" => vec!["rm", &target],
                    "container_prune" => vec!["container-prune"],
                    "image_prune" => vec!["image-prune"],
                    "vm_start" => {
                        return Ok(
                            json!({ "ok": true, "code": 0, "stdout": "", "stderr": "", "message": "" }),
                        )
                    }
                    "vm_stop" => {
                        return Err(
                            "the dashboard cannot stop the daemon that serves it".to_string()
                        )
                    }
                    action => return Err(format!("unsupported desktop action: {action}")),
                };
                let result = run_command_result(&command)?;
                if value_string(&args.action)? == "start_container"
                    && result["ok"].as_bool().unwrap_or(false)
                {
                    self.stopped_container_ids
                        .lock()
                        .map_err(|_| "stopped-container state is unavailable".to_string())?
                        .remove(&target);
                }
                Ok(result)
            }
            CommandRequest::RunComposeAction(args) => {
                let action = value_string(&args.action)?;
                run_command_result(&["compose", "-f", &args.file, action])
            }
            CommandRequest::RunVolumeAction(args) => {
                let target = args.target.unwrap_or_default();
                let action = value_string(&args.action)?;
                let command = match action {
                    "create" => vec!["volume", "create", &target],
                    "remove" => vec!["volume", "rm", &target],
                    "prune" => vec!["volume", "prune"],
                    _ => return Err(format!("unsupported volume action: {action}")),
                };
                run_command_result(&command)
            }
            CommandRequest::RunNetworkAction(args) => {
                let target = args.target.unwrap_or_default();
                let action = value_string(&args.action)?;
                let public_action = if action == "remove" { "rm" } else { action };
                let mut values = vec!["network", public_action, &target];
                let subnet = args.subnet.unwrap_or_default();
                if action == "create" && !subnet.is_empty() {
                    values.extend(["--subnet", &subnet]);
                }
                run_command_result(&values)
            }
            CommandRequest::UpdateContainerResources(args) => {
                let body = serde_json::to_vec(&json!({
                    "Memory": args.memory,
                    "CpuQuota": args.cpu_quota,
                    "CpuPeriod": args.cpu_period,
                }))
                .map_err(|error| format!("failed to encode resource update: {error}"))?;
                let response = self
                    .backend
                    .request(
                        TransportRequest::new(
                            "POST",
                            format!("/containers/{}/update", args.target),
                        )
                        .header("Content-Type", "application/json")
                        .body(body),
                    )
                    .map_err(|error| error.to_string())?;
                let ok = (200..300).contains(&response.status);
                let output = String::from_utf8_lossy(&response.body).to_string();
                Ok(json!({
                    "ok": ok,
                    "code": if ok { 0 } else { 1 },
                    "stdout": if ok { output.clone() } else { String::new() },
                    "stderr": if ok { String::new() } else { output.clone() },
                    "message": if ok { String::new() } else { output },
                }))
            }
            CommandRequest::RunNewContainer(args) => {
                let mut values = vec!["run".to_string(), "--detach".to_string()];
                if let Some(name) = args.name {
                    values.extend(["--name".to_string(), name]);
                }
                for port in args.ports {
                    values.extend(["--publish".to_string(), port]);
                }
                for volume in args.volumes {
                    values.extend(["--volume".to_string(), volume]);
                }
                for env in args.environment {
                    values.extend(["--env".to_string(), env]);
                }
                if let Some(memory) = args.memory {
                    values.extend(["--memory-max".to_string(), memory.to_string()]);
                }
                if let Some(quota) = args.cpu_quota {
                    values.extend(["--cpu-quota".to_string(), quota.to_string()]);
                }
                if let Some(period) = args.cpu_period {
                    values.extend(["--cpu-period".to_string(), period.to_string()]);
                }
                values.push(args.image);
                values.extend(args.command);
                desktop_command(&values, None).map(command_result)
            }
            CommandRequest::GetRegistryAuthStatus(args) => {
                let credential =
                    resolve_auth_for_registry(&args.registry).map_err(|error| error.to_string())?;
                Ok(json!({
                    "registry": args.registry,
                    "logged_in": credential.is_some(),
                    "username": credential.map(|auth| auth.username),
                }))
            }
            CommandRequest::LoginRegistry(args) => {
                let values = vec![
                    "login".to_string(),
                    args.registry,
                    "--username".to_string(),
                    args.username,
                    "--password-stdin".to_string(),
                ];
                desktop_command(&values, Some(args.password.as_bytes())).map(command_result)
            }
            CommandRequest::LogoutRegistry(args) => run_command_result(&["logout", &args.registry]),
            CommandRequest::StartLogFollow { target } => self.start_log_follow(target, events),
            CommandRequest::StopLogFollow => self.stop_log_follow(),
            CommandRequest::StartTerminal(args) => self.start_terminal(args, events),
            CommandRequest::WriteTerminal(args) => self.write_terminal(args.data),
            CommandRequest::ResizeTerminal(args) => self.resize_terminal(args.columns, args.rows),
            CommandRequest::CloseTerminal => self.close_terminal(),
            CommandRequest::GetPaidAuthState => Ok(
                json!({ "config": null, "session": { "token_present": false, "subject": null, "plan": null, "expires_at": null, "expired": null }, "entitlement": null }),
            ),
            CommandRequest::SavePaidBackendConfig(_)
            | CommandRequest::SetPaidSessionToken(_)
            | CommandRequest::AcquirePaidSession(_)
            | CommandRequest::ClearPaidSession
            | CommandRequest::RunPaidFullStackInstall(_) => {
                Err("paid account settings are managed by the native desktop".to_string())
            }
            CommandRequest::RunDoctorAction(args) => {
                let mut values = vec!["doctor".to_string(), "--json".to_string()];
                if args.fix {
                    values.push("--fix".to_string());
                }
                if args.bootstrap {
                    values.push("--bootstrap".to_string());
                }
                if args.dry_run {
                    values.push("--dry-run".to_string());
                }
                if args.confirm {
                    values.push("--confirm".to_string());
                }
                let output = desktop_command(&values, None)?;
                let ok = output.status.success();
                let mut raw: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(
                    |error| json!({ "healthy": false, "checks": [], "error": error.to_string() }),
                );
                if let Some(object) = raw.as_object_mut() {
                    object.insert("surface".to_string(), json!("dashboard"));
                    if let Some(checks) = object
                        .entry("checks".to_string())
                        .or_insert_with(|| json!([]))
                        .as_array_mut()
                    {
                        checks.push(json!({ "id": "dashboard_surface", "ok": true, "message": "dashboard browser surface is active", "hint": "Bearer-authenticated loopback session", "remediated": false, "action": null }));
                    }
                }
                Ok(json!({ "ok": ok && raw["healthy"].as_bool().unwrap_or(false), "raw": raw }))
            }
        }
    }
}

pub(crate) fn run(options: Options) -> Result<(), String> {
    if let Some(message) = unavailable_message() {
        return Err(message);
    }
    options.validate()?;
    let _daemon = ensure_daemon()?;
    let token = ferro_web::generate_session_token()?;
    if let Some(path) = options.token_file.as_deref() {
        write_token(path, &token)?;
    }
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|error| format!("failed to create dashboard runtime: {error}"))?;
    runtime.block_on(async move {
        let assets = Arc::new(DashboardAssets);
        let dispatcher = Arc::new(ProcessDispatcher::new()?);
        if options.listen.ip().is_loopback() {
            let server =
                Server::spawn_loopback(options.listen, token.clone(), assets, dispatcher).await?;
            println!("dashboard ready at http://{}/#token={token}", server.addr());
            server.wait().await
        } else {
            let cert = options.tls_cert.as_deref().expect("validated TLS cert");
            let key = options.tls_key.as_deref().expect("validated TLS key");
            println!(
                "dashboard ready at https://{}/#token={token}",
                options.listen
            );
            ferro_web::serve_tls(options.listen, token, cert, key, assets, dispatcher).await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    struct TestDispatcher;

    impl CommandDispatcher for TestDispatcher {
        fn dispatch(&self, _request: CommandRequest, _events: EventHub) -> Result<Value, String> {
            Ok(json!({}))
        }
    }

    #[test]
    fn non_loopback_requires_tls_and_operator_gate() {
        let options = Options {
            listen: "0.0.0.0:4190".parse().unwrap(),
            token_file: None,
            tls_cert: None,
            tls_key: None,
            operator_gate: false,
        };
        let error = options.validate().expect_err("unsafe bind rejected");
        assert!(error.contains("--tls-cert"));
        assert!(error.contains("--operator-gate"));
    }

    #[test]
    fn embedded_dashboard_contains_the_forge_shell() {
        let (_, mime) = DashboardAssets.get("index.html").expect("embedded index");
        assert!(mime.starts_with("text/html"));
        assert!(<DashboardAssets as RustEmbed>::iter()
            .any(|path| path.starts_with("assets/index-") && path.ends_with(".js")));
    }

    #[test]
    fn placeholder_dashboard_assets_are_refused_before_starting_a_daemon() {
        let placeholder = format!("{PLACEHOLDER_MARKER}{PLACEHOLDER_MESSAGE}");
        let message = dashboard_placeholder_message(Some(placeholder.as_bytes()))
            .expect("placeholder marker");

        assert!(message.contains("dashboard UI was not bundled"));
        assert!(message.contains("npm ci && npm run build"));
    }

    #[tokio::test]
    async fn built_dashboard_assets_are_served() {
        assert!(unavailable_message().is_none(), "test requires built dashboard assets");
        let server = Server::spawn_loopback(
            "127.0.0.1:0".parse().unwrap(),
            "test-token".to_string(),
            Arc::new(DashboardAssets),
            Arc::new(TestDispatcher),
        )
        .await
        .expect("start dashboard server");
        let response = reqwest::get(format!("http://{}/", server.addr()))
            .await
            .expect("request dashboard");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert!(response.text().await.expect("dashboard body").contains("<html"));
        server.shutdown().await;
    }

    #[test]
    fn docker_resource_payloads_are_normalized_for_the_shared_frontend() {
        let volumes = volume_summaries(&json!({ "Volumes": [{
            "Name": "data", "Driver": "local", "Mountpoint": "/data",
            "CreatedAt": "1", "FerrocrateMounts": []
        }] }));
        assert_eq!(volumes[0]["name"], "data");
        let networks = network_summaries(&json!([{ "Name": "bridge", "Driver": "bridge" }]));
        assert_eq!(networks[0]["containers"], json!([]));
        let detail = container_detail(&json!({
            "Id": "abc", "Name": "/worker", "Config": { "Image": "alpine", "Cmd": ["sh"] },
            "State": { "Status": "running" }, "HostConfig": {}, "Mounts": []
        }));
        assert_eq!(detail["name"], "worker");
        assert_eq!(detail["command"], json!(["sh"]));
    }

    #[test]
    fn token_file_permissions_are_tightened_when_file_exists() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dashboard.token");
        std::fs::write(&path, "old-token\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_token(&path, "new-token").unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new-token\n");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn token_file_replaces_symlink_without_overwriting_target() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("dashboard.token");
        std::fs::write(&target, "preserve-me\n").unwrap();
        symlink(&target, &link).unwrap();

        write_token(&link, "new-token").unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "preserve-me\n");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "new-token\n");
        assert!(!std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn token_file_atomic_replace_does_not_update_existing_open_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dashboard.token");
        std::fs::write(&path, "old-token\n").unwrap();
        let mut existing_reader = File::open(&path).unwrap();

        write_token(&path, "new-token").unwrap();

        let mut old_contents = String::new();
        existing_reader.read_to_string(&mut old_contents).unwrap();
        assert_eq!(old_contents, "old-token\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new-token\n");
    }

    #[test]
    fn log_buffer_bounds_retained_text_and_marks_truncation() {
        let mut buffer = LogBuffer::new(2, 8);
        buffer.push("first\n".to_string());
        buffer.push("second\n".to_string());
        buffer.push("third\n".to_string());

        assert!(buffer.truncated);
        assert!(buffer.bytes <= 8);
        assert!(buffer.entries.len() <= 2);
        assert!(buffer.text().starts_with(LOG_TRUNCATION_MARKER));
    }

    #[test]
    fn log_reader_splits_streams_without_newlines_into_bounded_chunks() {
        let input = vec![b'x'; LOG_READ_CHUNK_BYTES * 3 + 7];
        let (sender, receiver) = log_channel(8);
        queue_log_chunks(input.as_slice(), sender);
        let chunks = receiver.into_iter().collect::<Vec<_>>();

        assert_eq!(chunks.iter().map(String::len).sum::<usize>(), input.len());
        assert!(chunks
            .iter()
            .all(|chunk| chunk.len() <= LOG_READ_CHUNK_BYTES));
    }
}
