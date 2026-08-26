#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

mod web_bridge;
#[cfg(target_os = "linux")]
mod webkit_rendering;

use base64::Engine as _;
use ferro_desktop::backend::{
    select_backend, Backend, BackendState, BackendStatus, DuplexStream, ExecStream,
    ExecRequest as BackendExecRequest, TerminalRequest,
};
#[cfg(target_os = "macos")]
use ferro_desktop::backend::{LinuxNativeBackend, LinuxNativeConfig};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::Emitter;

#[derive(Clone)]
enum EventSink {
    Tauri(tauri::AppHandle),
    Web(web_bridge::WebEventHub),
}

impl EventSink {
    fn emit<T: Serialize + Clone>(&self, event: &str, payload: T) {
        match self {
            Self::Tauri(app) => {
                let _ = app.emit(event, payload);
            }
            Self::Web(events) => events.emit(event, payload),
        }
    }
}

const KEYRING_SERVICE: &str = "ferrocrate-desktop-ui";
const KEYRING_ACCOUNT: &str = "paid_session_token";
const LOG_TRUNCATION_MARKER: &str = "[Earlier log output truncated]\n";
const MAX_LOG_LINES: usize = 2_000;
const MAX_LOG_BYTES: usize = 512 * 1024;
const LOG_CHANNEL_CAPACITY: usize = 128;
static LOG_FOLLOW_PROCESS: Mutex<Option<Box<dyn ExecStream>>> = Mutex::new(None);
static TERMINAL_PROCESS: Mutex<Option<TerminalProcess>> = Mutex::new(None);
static DESKTOP_DAEMON_PROCESS: Mutex<Option<Child>> = Mutex::new(None);
static DESKTOP_DAEMON_STARTING: AtomicBool = AtomicBool::new(false);
static DESKTOP_DAEMON_FAILURE: Mutex<Option<String>> = Mutex::new(None);

struct TerminalProcess {
    stream: Box<dyn DuplexStream>,
    exec_id: String,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
    message: String,
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn parse_nullable_json_list<T: DeserializeOwned>(
    stdout: &str,
) -> Result<Vec<T>, serde_json::Error> {
    serde_json::from_str::<Option<Vec<T>>>(stdout).map(Option::unwrap_or_default)
}

fn normalize_nullable_list_output(result: &mut CommandResult) {
    if result.ok
        && matches!(parse_nullable_json_list::<JsonValue>(&result.stdout), Ok(records) if records.is_empty() && result.stdout.trim() == "null")
    {
        result.stdout = "[]".to_string();
    }
}

fn strip_ansi(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            output.push(ch);
            continue;
        }
        if chars.next_if_eq(&'[').is_none() {
            continue;
        }
        for code in chars.by_ref() {
            if ('@'..='~').contains(&code) {
                break;
            }
        }
    }
    output
}

fn is_tracing_line(line: &str) -> bool {
    const LEVELS: &[&str] = &["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let level_index = if fields
        .first()
        .is_some_and(|field| field.contains('T') && (field.ends_with('Z') || field.contains('+')))
    {
        1
    } else {
        0
    };
    fields
        .get(level_index)
        .is_some_and(|field| LEVELS.contains(field))
        && fields
            .get(level_index + 1)
            .is_some_and(|field| field.ends_with(':'))
}

fn actionable_error(stderr: &str) -> String {
    strip_ansi(stderr)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !is_tracing_line(line))
        .filter(|line| !line.contains("container operation(s) failed"))
        .filter(|line| !line.contains("remote command exited with status"))
        .map(|line| line.strip_prefix("error: ").unwrap_or(line))
        .next()
        .unwrap_or_default()
        .to_string()
}

fn command_result_from_output(output: std::process::Output) -> CommandResult {
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    CommandResult {
        ok: output.status.success(),
        code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        message: actionable_error(&stderr),
        stderr,
    }
}

fn command_spawn_failure(binary: &str, err: impl std::fmt::Display) -> CommandResult {
    let stderr = format!("failed to run `{binary}`: {err}");
    CommandResult {
        ok: false,
        code: 127,
        stdout: String::new(),
        message: stderr.clone(),
        stderr,
    }
}

fn command_input_failure(message: &str) -> CommandResult {
    CommandResult {
        ok: false,
        code: 2,
        stdout: String::new(),
        stderr: message.to_string(),
        message: message.to_string(),
    }
}

fn ferrocrate_proxy_command(args: &[&str]) -> Vec<String> {
    ["exec", "--", "ferrocrate"]
        .into_iter()
        .chain(args.iter().copied())
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Serialize)]
struct DesktopSnapshot {
    daemon: DaemonStatus,
    runtime: CommandResult,
    containers: CommandResult,
    images: CommandResult,
}

#[derive(Debug, Serialize)]
struct DaemonStatus {
    state: String,
    healthy: bool,
    socket_path: String,
    reason: Option<String>,
    platform: String,
    custom_networks: bool,
}

#[derive(Debug, Serialize)]
struct DaemonCapabilities {
    custom_networks: bool,
}

#[cfg(target_os = "linux")]
fn desktop_socket_path() -> Result<PathBuf, String> {
    std::env::var_os("FERROCRATE_RUNTIME_DIR")
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR"))
        .map(PathBuf::from)
        .map(|path| path.join("ferrocrate.sock"))
        .ok_or_else(|| "FERROCRATE_RUNTIME_DIR or XDG_RUNTIME_DIR is not set".to_string())
}

#[cfg(target_os = "linux")]
fn daemon_health_response_ok(response: &str) -> bool {
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    headers.starts_with("HTTP/1.1 200") && body.trim() == "OK"
}

#[cfg(target_os = "linux")]
fn daemon_capabilities_from_info_response(response: &str) -> Result<DaemonCapabilities, String> {
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return Err("Ferrocrate API info response is malformed".to_string());
    };
    if !headers.starts_with("HTTP/1.1 200") {
        return Err("Ferrocrate API info request failed".to_string());
    }
    let info: JsonValue = serde_json::from_str(body.trim())
        .map_err(|error| format!("Ferrocrate API info response is invalid: {error}"))?;
    let explicit = info
        .get("FerrocrateCapabilities")
        .and_then(|value| value.get("CustomNetworks"))
        .and_then(JsonValue::as_bool);
    Ok(DaemonCapabilities {
        custom_networks: explicit.unwrap_or(false),
    })
}

#[cfg(target_os = "linux")]
fn daemon_capabilities(socket: &std::path::Path) -> Result<DaemonCapabilities, String> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| format!("cannot connect to {}: {error}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(b"GET /info HTTP/1.1\r\nHost: ferrocrate-desktop\r\nConnection: close\r\n\r\n")
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    daemon_capabilities_from_info_response(&response)
}

#[cfg(target_os = "linux")]
fn running_daemon_status(socket_path: &str, capabilities: DaemonCapabilities) -> DaemonStatus {
    DaemonStatus {
        state: "running".to_string(),
        healthy: true,
        socket_path: socket_path.to_string(),
        reason: None,
        platform: "linux-native".to_string(),
        custom_networks: capabilities.custom_networks,
    }
}

#[cfg(target_os = "linux")]
fn ping_daemon(socket: &std::path::Path) -> Result<(), String> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| format!("cannot connect to {}: {error}", socket.display()))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(b"GET /_ping HTTP/1.1\r\nHost: ferrocrate-desktop\r\nConnection: close\r\n\r\n")
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    if daemon_health_response_ok(&response) {
        Ok(())
    } else {
        Err("Ferrocrate API health check returned an unexpected response".to_string())
    }
}

#[cfg(target_os = "linux")]
fn unavailable_daemon_state(
    starting: bool,
    supervisor_running: bool,
    supervisor_failure: Option<&str>,
) -> (&'static str, Option<String>) {
    if starting || supervisor_running {
        return ("starting", supervisor_failure.map(str::to_string));
    }
    match supervisor_failure {
        Some(reason) => ("failed", Some(reason.to_string())),
        None => ("stopped", None),
    }
}

#[cfg(target_os = "linux")]
fn supervisor_process_state() -> (bool, Option<String>) {
    let Ok(mut slot) = DESKTOP_DAEMON_PROCESS.lock() else {
        return (
            false,
            Some("desktop daemon supervisor state is unavailable".to_string()),
        );
    };
    let Some(child) = slot.as_mut() else {
        drop(slot);
        return (
            false,
            DESKTOP_DAEMON_FAILURE
                .lock()
                .ok()
                .and_then(|value| value.clone()),
        );
    };
    match child.try_wait() {
        Ok(None) => (true, None),
        Ok(Some(status)) => (
            false,
            Some(format!("desktop daemon supervisor exited with {status}")),
        ),
        Err(error) => (
            false,
            Some(format!(
                "failed to inspect desktop daemon supervisor: {error}"
            )),
        ),
    }
}

#[allow(dead_code)]
fn legacy_daemon_status() -> DaemonStatus {
    #[cfg(target_os = "linux")]
    {
        match desktop_socket_path() {
            Ok(socket) => match ping_daemon(&socket) {
                Ok(()) => {
                    let capabilities = daemon_capabilities(&socket).unwrap_or(DaemonCapabilities {
                        custom_networks: false,
                    });
                    running_daemon_status(&socket.display().to_string(), capabilities)
                }
                Err(reason) => {
                    let (supervisor_running, supervisor_failure) = supervisor_process_state();
                    let (state, lifecycle_reason) = unavailable_daemon_state(
                        DESKTOP_DAEMON_STARTING.load(Ordering::SeqCst),
                        supervisor_running,
                        supervisor_failure.as_deref(),
                    );
                    DaemonStatus {
                        state: state.to_string(),
                        healthy: false,
                        socket_path: socket.display().to_string(),
                        reason: lifecycle_reason.or(Some(reason)),
                        platform: "linux-native".to_string(),
                        custom_networks: false,
                    }
                }
            },
            Err(reason) => DaemonStatus {
                state: "failed".to_string(),
                healthy: false,
                socket_path: String::new(),
                reason: Some(reason),
                platform: "linux-native".to_string(),
                custom_networks: false,
            },
        }
    }
    #[cfg(not(target_os = "linux"))]
    DaemonStatus {
        state: "running".to_string(),
        healthy: true,
        socket_path: "desktop bridge".to_string(),
        reason: None,
        platform: "desktop-vm".to_string(),
        custom_networks: true,
    }
}

#[cfg(target_os = "linux")]
fn desktop_daemon_transport_ready(_tcp_ready: bool, socket_ready: bool) -> bool {
    socket_ready
}

#[cfg(not(target_os = "linux"))]
fn desktop_daemon_transport_ready(tcp_ready: bool, _socket_ready: bool) -> bool {
    tcp_ready
}

#[cfg(target_os = "linux")]
fn desktop_daemon_ready() -> bool {
    desktop_daemon_transport_ready(
        false,
        desktop_socket_path()
            .and_then(|socket| ping_daemon(&socket))
            .is_ok(),
    )
}

#[cfg(not(target_os = "linux"))]
fn desktop_daemon_ready() -> bool {
    desktop_daemon_transport_ready(
        std::net::TcpStream::connect("127.0.0.1:4288").is_ok(),
        false,
    )
}

#[allow(dead_code)]
fn legacy_start_desktop_daemon() -> Result<(), String> {
    if desktop_daemon_ready() {
        DESKTOP_DAEMON_STARTING.store(false, Ordering::SeqCst);
        if let Ok(mut failure) = DESKTOP_DAEMON_FAILURE.lock() {
            *failure = None;
        }
        return Ok(());
    }
    DESKTOP_DAEMON_STARTING.store(true, Ordering::SeqCst);
    if let Ok(mut failure) = DESKTOP_DAEMON_FAILURE.lock() {
        *failure = None;
    }
    let mut slot = match DESKTOP_DAEMON_PROCESS.lock() {
        Ok(slot) => slot,
        Err(_) => {
            let reason = "desktop daemon state is unavailable".to_string();
            DESKTOP_DAEMON_STARTING.store(false, Ordering::SeqCst);
            if let Ok(mut failure) = DESKTOP_DAEMON_FAILURE.lock() {
                *failure = Some(reason.clone());
            }
            return Err(reason);
        }
    };
    let supervisor_running = slot
        .as_mut()
        .is_some_and(|child| child.try_wait().ok().flatten().is_none());
    if !supervisor_running {
        let child = match Command::new("ferro-desktop")
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                let reason = format!("failed to start desktop daemon supervisor: {error}");
                DESKTOP_DAEMON_STARTING.store(false, Ordering::SeqCst);
                if let Ok(mut failure) = DESKTOP_DAEMON_FAILURE.lock() {
                    *failure = Some(reason.clone());
                }
                return Err(reason);
            }
        };
        *slot = Some(child);
    }
    drop(slot);
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        if desktop_daemon_ready() {
            DESKTOP_DAEMON_STARTING.store(false, Ordering::SeqCst);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    let reason = "desktop daemon supervisor did not become ready".to_string();
    DESKTOP_DAEMON_STARTING.store(false, Ordering::SeqCst);
    if let Ok(mut failure) = DESKTOP_DAEMON_FAILURE.lock() {
        *failure = Some(reason.clone());
    }
    if let Ok(mut slot) = DESKTOP_DAEMON_PROCESS.lock() {
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    Err(reason)
}

#[allow(dead_code)]
fn legacy_stop_desktop_daemon() {
    DESKTOP_DAEMON_STARTING.store(false, Ordering::SeqCst);
    if let Ok(mut failure) = DESKTOP_DAEMON_FAILURE.lock() {
        *failure = None;
    }
    if let Ok(mut slot) = DESKTOP_DAEMON_PROCESS.lock() {
        if let Some(mut child) = slot.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

static DESKTOP_BACKEND: OnceLock<Result<Box<dyn Backend>, String>> = OnceLock::new();

fn desktop_backend() -> Result<&'static dyn Backend, String> {
    DESKTOP_BACKEND
        .get_or_init(|| select_backend().map_err(|error| error.to_string()))
        .as_ref()
        .map(|backend| backend.as_ref())
        .map_err(Clone::clone)
}

fn daemon_status() -> DaemonStatus {
    let status = match desktop_backend() {
        Ok(backend) => backend.status(),
        Err(reason) => {
            return DaemonStatus {
                state: "failed".to_string(),
                healthy: false,
                socket_path: String::new(),
                reason: Some(reason),
                platform: "unsupported".to_string(),
                custom_networks: false,
            };
        }
    };
    daemon_status_from_backend(status)
}

fn daemon_status_from_backend(status: BackendStatus) -> DaemonStatus {
    DaemonStatus {
        state: match status.state {
            BackendState::Stopped => "stopped",
            BackendState::Starting => "starting",
            BackendState::Running => "running",
            BackendState::Stopping => "stopping",
            BackendState::Failed => "failed",
            BackendState::Unavailable => "unavailable",
        }
        .to_string(),
        healthy: status.healthy,
        socket_path: status.endpoint,
        reason: status.reason,
        platform: status.backend,
        custom_networks: status.capabilities.custom_networks,
    }
}

fn start_desktop_daemon() -> Result<(), String> {
    desktop_backend()?
        .start()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn stop_desktop_daemon() {
    if let Ok(backend) = desktop_backend() {
        let _ = backend.stop();
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NativeContainerStats {
    memory_current: Option<u64>,
    memory_max: Option<u64>,
    cpu_usage_usec: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NativeStatsOutput {
    stats: NativeContainerStats,
}

fn parse_container_stats_json(stdout: &str) -> Result<NativeContainerStats, serde_json::Error> {
    let value: JsonValue = serde_json::from_str(stdout)?;
    if value.get("stats").is_some() {
        return serde_json::from_value::<NativeStatsOutput>(value).map(|output| output.stats);
    }
    let nonzero = |path: &str| {
        value
            .pointer(path)
            .and_then(JsonValue::as_u64)
            .filter(|value| *value > 0)
    };
    Ok(NativeContainerStats {
        memory_current: value
            .pointer("/memory_stats/usage")
            .and_then(JsonValue::as_u64),
        memory_max: nonzero("/memory_stats/limit"),
        cpu_usage_usec: value
            .pointer("/cpu_stats/cpu_usage/total_usage")
            .and_then(JsonValue::as_u64)
            .map(|nanoseconds| nanoseconds / 1_000),
    })
}

#[derive(Debug, Clone)]
struct TimedNativeContainerStats {
    sampled_at: Instant,
    stats: NativeContainerStats,
}

#[derive(Debug, Clone, Serialize)]
struct ContainerStatsSample {
    id: String,
    available: bool,
    memory_usage: Option<u64>,
    memory_limit: Option<u64>,
    cpu_percent: Option<f64>,
}

#[derive(Debug, Serialize)]
struct ContainerStatsResponse {
    samples: Vec<ContainerStatsSample>,
}

fn container_stats_command(target: &str) -> Vec<String> {
    ferrocrate_proxy_command(&["stats", target, "--format", "json"])
}

fn read_container_stats(target: &str) -> Option<NativeContainerStats> {
    let result = run_owned_command("ferro-desktop", &container_stats_command(target));
    result
        .ok
        .then(|| parse_container_stats_json(&result.stdout).ok())
        .flatten()
}

fn aggregate_container_stats(
    ids: &[String],
    first: &BTreeMap<String, TimedNativeContainerStats>,
    second: &BTreeMap<String, TimedNativeContainerStats>,
) -> Vec<ContainerStatsSample> {
    ids.iter()
        .map(|id| {
            let pair = first.get(id).zip(second.get(id));
            let cpu_percent = pair
                .as_ref()
                .and_then(|(previous, current)| {
                    previous
                        .stats
                        .cpu_usage_usec
                        .zip(current.stats.cpu_usage_usec)
                })
                .map(|(before, after)| {
                    let elapsed_usec = pair
                        .as_ref()
                        .map(|(previous, current)| {
                            current
                                .sampled_at
                                .saturating_duration_since(previous.sampled_at)
                                .as_micros() as f64
                        })
                        .unwrap_or(0.0);
                    (before, after, elapsed_usec)
                })
                .filter(|(_, _, elapsed_usec)| *elapsed_usec > 0.0)
                .map(|(before, after, elapsed_usec)| {
                    after.saturating_sub(before) as f64 / elapsed_usec * 100.0
                });
            let memory_usage = pair
                .as_ref()
                .and_then(|(_, current)| current.stats.memory_current);
            ContainerStatsSample {
                id: id.clone(),
                available: cpu_percent.is_some() && memory_usage.is_some(),
                memory_usage,
                memory_limit: pair
                    .as_ref()
                    .and_then(|(_, current)| current.stats.memory_max),
                cpu_percent,
            }
        })
        .collect()
}

fn collect_container_stats(ids: &[String]) -> Vec<ContainerStatsSample> {
    let first = ids
        .iter()
        .filter_map(|id| {
            read_container_stats(id).map(|stats| {
                (
                    id.clone(),
                    TimedNativeContainerStats {
                        sampled_at: Instant::now(),
                        stats,
                    },
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    if first.is_empty() {
        return aggregate_container_stats(ids, &first, &BTreeMap::new());
    }
    thread::sleep(Duration::from_millis(100));
    let second = ids
        .iter()
        .filter_map(|id| {
            read_container_stats(id).map(|stats| {
                (
                    id.clone(),
                    TimedNativeContainerStats {
                        sampled_at: Instant::now(),
                        stats,
                    },
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    aggregate_container_stats(ids, &first, &second)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PaidBackendConfig {
    release_base_url: String,
    token_endpoint: String,
    #[serde(default)]
    issuance_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionSummary {
    token_present: bool,
    subject: Option<String>,
    plan: Option<String>,
    expires_at: Option<u64>,
    expired: Option<bool>,
}

#[derive(Debug, Serialize)]
struct EntitlementSummary {
    status: String,
    plan: Option<String>,
    subject: Option<String>,
    expires_at: Option<u64>,
    features: Vec<String>,
    message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DoctorSummary {
    ok: bool,
    raw: JsonValue,
}

#[derive(Debug, Serialize)]
struct PaidAuthState {
    config: Option<PaidBackendConfig>,
    session: SessionSummary,
    entitlement: Option<EntitlementSummary>,
}

#[derive(Debug, Serialize)]
struct InstallerRunSummary {
    dry_run: bool,
    ok: bool,
    command: String,
    result: Option<CommandResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DesktopAction {
    VmStart,
    VmStop,
    PullImage,
    RemoveImage,
    StartContainer,
    StopContainer,
    RemoveContainer,
    ContainerPrune,
    ImagePrune,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VolumeAction {
    List,
    Create,
    Remove,
    Prune,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NetworkAction {
    List,
    Inspect,
    Create,
    Remove,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ComposeAction {
    Config,
    Up,
    Down,
    Stop,
    Start,
}

#[derive(Debug, Deserialize)]
struct ComposeConfigProjection {
    services: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct ComposeContainerRecord {
    #[serde(alias = "Id")]
    id: String,
    #[serde(
        rename = "Names",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    names: Vec<String>,
    #[serde(rename = "Labels", default)]
    labels: BTreeMap<String, String>,
    #[serde(alias = "State")]
    status: String,
}

#[derive(Debug, Serialize)]
struct ComposeServiceSummary {
    name: String,
    status: String,
    container_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ComposeSnapshot {
    config: String,
    services: Vec<ComposeServiceSummary>,
}

#[derive(Clone, Serialize)]
struct BuildProgressFrame {
    build_id: String,
    stream: String,
    text: String,
}

fn build_bridge_command(context: &str, tag: &str) -> Result<Vec<String>, String> {
    let context = context.trim();
    let tag = tag.trim();
    if context.is_empty() {
        return Err("build context directory is required".to_string());
    }
    if tag.is_empty() {
        return Err("image tag is required".to_string());
    }
    let dockerfile = PathBuf::from(context).join("Dockerfile");
    Ok(vec![
        "exec".to_string(),
        "--".to_string(),
        "ferrocrate".to_string(),
        "build".to_string(),
        "--dockerfile".to_string(),
        dockerfile.to_string_lossy().to_string(),
        "--tag".to_string(),
        tag.to_string(),
    ])
}

fn compose_bridge_command(file: &str, action: ComposeAction) -> Result<Vec<String>, String> {
    let file = file.trim();
    if file.is_empty() {
        return Err("compose file is required".to_string());
    }
    let mut args = vec![
        "exec".to_string(),
        "--".to_string(),
        "ferrocrate".to_string(),
        "compose".to_string(),
        "--file".to_string(),
        file.to_string(),
        match action {
            ComposeAction::Config => "config",
            ComposeAction::Up => "up",
            ComposeAction::Down => "down",
            ComposeAction::Stop => "stop",
            ComposeAction::Start => "start",
        }
        .to_string(),
    ];
    if matches!(action, ComposeAction::Up) {
        args.push("--detach".to_string());
    }
    Ok(args)
}

fn compose_container_list_command() -> Vec<String> {
    [
        "exec",
        "--",
        "ferrocrate",
        "containers",
        "--all",
        "--format",
        "json",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn compose_service_rows(
    mut services: Vec<String>,
    containers: &[ComposeContainerRecord],
) -> Vec<ComposeServiceSummary> {
    services.sort();
    services
        .into_iter()
        .map(|name| {
            let replica_prefix = format!("{name}-");
            let container = containers.iter().find(|container| {
                container.labels.get("com.docker.compose.service") == Some(&name)
                    || container.names.iter().any(|container_name| {
                        let container_name = container_name.trim_start_matches('/');
                        container_name == name || container_name.starts_with(&replica_prefix)
                    })
            });
            ComposeServiceSummary {
                name,
                status: container
                    .map(|container| container.status.clone())
                    .unwrap_or_else(|| "not_created".to_string()),
                container_id: container.map(|container| container.id.clone()),
            }
        })
        .collect()
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "PascalCase", serialize = "snake_case"))]
struct VolumeMountUsage {
    container_id: String,
    container_name: String,
    destination: String,
    #[serde(rename(deserialize = "RW", serialize = "read_write"))]
    read_write: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "PascalCase", serialize = "snake_case"))]
struct VolumeSummary {
    name: String,
    driver: String,
    mountpoint: String,
    created_at: String,
    #[serde(
        rename(deserialize = "FerrocrateMounts", serialize = "mounts"),
        default,
        deserialize_with = "deserialize_null_default"
    )]
    mounts: Vec<VolumeMountUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VolumeListResponse {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    volumes: Vec<VolumeSummary>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkIpamConfig {
    subnet: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkIpam {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    config: Vec<NetworkIpamConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkListRecord {
    name: String,
    driver: String,
    #[serde(rename = "IPAM", default)]
    ipam: NetworkIpam,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkInspectContainer {
    name: String,
    #[serde(rename = "IPv4Address", default)]
    ipv4_address: String,
    #[serde(rename = "IPv6Address", default)]
    ipv6_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NetworkInspectRecord {
    #[serde(default)]
    containers: BTreeMap<String, NetworkInspectContainer>,
    #[serde(rename = "IPAM", default)]
    ipam: NetworkIpam,
}

#[derive(Debug, Deserialize)]
struct ContainerPortRecord {
    #[serde(alias = "PublicPort")]
    host_port: u16,
    #[serde(alias = "PrivatePort")]
    container_port: u16,
    #[serde(alias = "Type")]
    protocol: String,
}

#[derive(Debug, Deserialize)]
struct ContainerNetworkRecord {
    #[serde(alias = "Id")]
    id: String,
    #[serde(
        rename = "Names",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    names: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    #[serde(alias = "Ports")]
    ports: Vec<ContainerPortRecord>,
}

impl ContainerNetworkRecord {
    fn name(&self) -> Option<String> {
        self.names
            .first()
            .map(|name| name.trim_start_matches('/').to_string())
            .filter(|name| !name.is_empty())
    }
}

#[derive(Debug, Serialize)]
struct NetworkContainerSummary {
    container_id: String,
    name: String,
    ipv4_address: String,
    ipv6_address: String,
    ports: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NetworkSummary {
    name: String,
    driver: String,
    subnets: Vec<String>,
    containers: Vec<NetworkContainerSummary>,
}

#[derive(Debug, Serialize)]
struct ContainerMountSummary {
    kind: String,
    source: String,
    destination: String,
    access: String,
}

#[derive(Debug, Serialize)]
struct ContainerHealthLogSummary {
    start: String,
    end: String,
    exit_code: i64,
    output: String,
}

#[derive(Debug, Serialize)]
struct ContainerHealthSummary {
    status: String,
    failing_streak: u64,
    log: Vec<ContainerHealthLogSummary>,
}

#[derive(Debug, Serialize)]
struct ContainerResourceSummary {
    memory: u64,
    cpu_quota: u64,
    cpu_period: u64,
}

#[derive(Debug, Serialize)]
struct ContainerRestartPolicySummary {
    name: String,
    maximum_retry_count: u64,
}

#[derive(Debug, Serialize)]
struct ContainerDetailSummary {
    id: String,
    name: String,
    image: String,
    status: String,
    command: Vec<String>,
    environment: Vec<String>,
    working_dir: String,
    user: String,
    mounts: Vec<ContainerMountSummary>,
    health: Option<ContainerHealthSummary>,
    resources: ContainerResourceSummary,
    restart_policy: ContainerRestartPolicySummary,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRegistryCredential {
    registry: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct RegistryAuthStatus {
    registry: String,
    logged_in: bool,
    username: Option<String>,
}

fn container_detail_from_json(value: JsonValue) -> Result<ContainerDetailSummary, String> {
    if value.get("id").is_some() {
        return container_detail_from_native_json(&value);
    }
    let string = |path: &[&str]| {
        path.iter()
            .try_fold(&value, |current, key| current.get(*key))
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let number = |path: &[&str]| {
        path.iter()
            .try_fold(&value, |current, key| current.get(*key))
            .and_then(JsonValue::as_u64)
            .unwrap_or_default()
    };
    let array_strings = |path: &[&str]| {
        path.iter()
            .try_fold(&value, |current, key| current.get(*key))
            .and_then(JsonValue::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    let mounts = value
        .get("Mounts")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .map(|mount| ContainerMountSummary {
            kind: mount
                .get("Type")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            source: mount
                .get("Source")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            destination: mount
                .get("Destination")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            access: if mount
                .get("RW")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false)
            {
                "rw".to_string()
            } else {
                "ro".to_string()
            },
        })
        .collect();
    let health = value
        .pointer("/State/Health")
        .filter(|health| !health.is_null())
        .map(|health| ContainerHealthSummary {
            status: health
                .get("Status")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            failing_streak: health
                .get("FailingStreak")
                .and_then(JsonValue::as_u64)
                .unwrap_or_default(),
            log: health
                .get("Log")
                .and_then(JsonValue::as_array)
                .into_iter()
                .flatten()
                .map(|entry| ContainerHealthLogSummary {
                    start: entry
                        .get("Start")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    end: entry
                        .get("End")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    exit_code: entry
                        .get("ExitCode")
                        .and_then(JsonValue::as_i64)
                        .unwrap_or_default(),
                    output: entry
                        .get("Output")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .to_string(),
                })
                .collect(),
        });
    let id = string(&["Id"]);
    if id.is_empty() {
        return Err("container inspect response omitted Id".to_string());
    }
    Ok(ContainerDetailSummary {
        id,
        name: string(&["Name"]).trim_start_matches('/').to_string(),
        image: string(&["Config", "Image"]),
        status: string(&["State", "Status"]),
        command: array_strings(&["Config", "Cmd"]),
        environment: array_strings(&["Config", "Env"]),
        working_dir: string(&["Config", "WorkingDir"]),
        user: string(&["Config", "User"]),
        mounts,
        health,
        resources: ContainerResourceSummary {
            memory: number(&["HostConfig", "Memory"]),
            cpu_quota: number(&["HostConfig", "CpuQuota"]),
            cpu_period: number(&["HostConfig", "CpuPeriod"]),
        },
        restart_policy: ContainerRestartPolicySummary {
            name: string(&["HostConfig", "RestartPolicy", "Name"]),
            maximum_retry_count: number(&["HostConfig", "RestartPolicy", "MaximumRetryCount"]),
        },
    })
}

fn container_detail_from_native_json(value: &JsonValue) -> Result<ContainerDetailSummary, String> {
    let string = |key: &str| {
        value
            .get(key)
            .and_then(JsonValue::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let id = string("id");
    if id.is_empty() {
        return Err("container inspect response omitted id".to_string());
    }
    let mut mounts = value
        .get("mounts")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .map(|mount| ContainerMountSummary {
            kind: "bind".to_string(),
            source: mount
                .get("source")
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            destination: format!(
                "/{}",
                mount
                    .get("target")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .trim_start_matches('/')
            ),
            access: if mount
                .get("read_only")
                .and_then(JsonValue::as_bool)
                .unwrap_or(false)
            {
                "ro".to_string()
            } else {
                "rw".to_string()
            },
        })
        .collect::<Vec<_>>();
    mounts.extend(
        value
            .get("tmpfs_mounts")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .map(|mount| ContainerMountSummary {
                kind: "tmpfs".to_string(),
                source: String::new(),
                destination: format!(
                    "/{}",
                    mount
                        .get("target")
                        .and_then(JsonValue::as_str)
                        .unwrap_or_default()
                        .trim_start_matches('/')
                ),
                access: "rw".to_string(),
            }),
    );
    let limits = value
        .get("resource_limits")
        .filter(|limits| !limits.is_null());
    let restart_value = value.get("restart_policy");
    let (restart_name, maximum_retry_count) = match restart_value {
        Some(JsonValue::String(policy)) => policy
            .split_once(':')
            .map(|(name, count)| (name.to_string(), count.parse::<u64>().unwrap_or_default()))
            .unwrap_or_else(|| (policy.clone(), 0)),
        Some(JsonValue::Object(policy)) => policy
            .get("on-failure-with-retries")
            .and_then(JsonValue::as_u64)
            .map(|count| ("on-failure".to_string(), count))
            .unwrap_or_else(|| ("no".to_string(), 0)),
        _ => ("no".to_string(), 0),
    };
    let health_status = string("health_status");
    let health = (health_status != "none").then(|| ContainerHealthSummary {
        status: health_status,
        failing_streak: value
            .get("health_failures")
            .and_then(JsonValue::as_u64)
            .unwrap_or_default(),
        log: value
            .get("health_log")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .map(|entry| ContainerHealthLogSummary {
                start: entry
                    .get("start_unix")
                    .and_then(JsonValue::as_u64)
                    .unwrap_or_default()
                    .to_string(),
                end: entry
                    .get("end_unix")
                    .and_then(JsonValue::as_u64)
                    .unwrap_or_default()
                    .to_string(),
                exit_code: entry
                    .get("exit_code")
                    .and_then(JsonValue::as_i64)
                    .unwrap_or_default(),
                output: entry
                    .get("output")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect(),
    });
    Ok(ContainerDetailSummary {
        id: id.clone(),
        name: value
            .get("name")
            .and_then(JsonValue::as_str)
            .unwrap_or(&id)
            .to_string(),
        image: string("image"),
        status: string("status"),
        command: value
            .get("command")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .filter_map(JsonValue::as_str)
            .map(str::to_string)
            .collect(),
        environment: value
            .get("env")
            .and_then(JsonValue::as_array)
            .into_iter()
            .flatten()
            .filter_map(JsonValue::as_str)
            .map(str::to_string)
            .collect(),
        working_dir: string("workdir"),
        user: string("user"),
        mounts,
        health,
        resources: ContainerResourceSummary {
            memory: limits
                .and_then(|limits| limits.get("memory_max"))
                .and_then(JsonValue::as_u64)
                .unwrap_or_default(),
            cpu_quota: limits
                .and_then(|limits| limits.get("cpu_quota"))
                .and_then(JsonValue::as_u64)
                .unwrap_or_default(),
            cpu_period: limits
                .and_then(|limits| limits.get("cpu_period"))
                .and_then(JsonValue::as_u64)
                .unwrap_or_default(),
        },
        restart_policy: ContainerRestartPolicySummary {
            name: restart_name,
            maximum_retry_count,
        },
    })
}

fn container_inspect_command(target: &str) -> Result<Vec<String>, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("container name or id is required".to_string());
    }
    Ok([
        "exec",
        "--",
        "ferrocrate",
        "inspect",
        target,
        "--format",
        "json",
    ]
    .into_iter()
    .map(str::to_string)
    .collect())
}

fn container_update_command(
    target: &str,
    memory: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
) -> Result<Vec<String>, String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("container name or id is required".to_string());
    }
    if memory.is_none() && cpu_quota.is_none() && cpu_period.is_none() {
        return Err("at least one resource limit is required".to_string());
    }
    let mut command = vec![
        "container-proxy".to_string(),
        "update".to_string(),
        target.to_string(),
    ];
    for (flag, value) in [
        ("--memory", memory),
        ("--cpu-quota", cpu_quota),
        ("--cpu-period", cpu_period),
    ] {
        if let Some(value) = value {
            command.push(flag.to_string());
            command.push(value.to_string());
        }
    }
    Ok(command)
}

// Each argument maps directly to an independent container-create protocol field.
#[allow(clippy::too_many_arguments)]
fn run_container_bridge_command(
    image: &str,
    name: Option<&str>,
    command_args: &[String],
    ports: &[String],
    volumes: &[String],
    environment: &[String],
    memory: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
) -> Result<Vec<String>, String> {
    let image = image.trim();
    if image.is_empty() {
        return Err("container image is required".to_string());
    }
    let mut command = ["exec", "--", "ferrocrate", "run", "--detach"]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if let Some(name) = name.map(str::trim).filter(|value| !value.is_empty()) {
        command.extend(["--name".to_string(), name.to_string()]);
    }
    for port in ports
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        if !port.contains(':') {
            return Err(format!("port mapping must use host:container: {port}"));
        }
        command.extend(["--publish".to_string(), port.to_string()]);
    }
    for volume in volumes
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        if !volume.contains(':') {
            return Err(format!(
                "volume mapping must use source:container: {volume}"
            ));
        }
        command.extend(["--volume".to_string(), volume.to_string()]);
    }
    for value in environment
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        if !value.contains('=') {
            return Err(format!("environment entry must use KEY=value: {value}"));
        }
        command.extend(["--env".to_string(), value.to_string()]);
    }
    for (flag, value) in [
        ("--memory-max", memory),
        ("--cpu-quota", cpu_quota),
        ("--cpu-period", cpu_period),
    ] {
        if let Some(value) = value {
            command.extend([flag.to_string(), value.to_string()]);
        }
    }
    command.push(image.to_string());
    command.extend(command_args.iter().cloned());
    Ok(command)
}

fn image_list_contains(stdout: &str, image: &str) -> bool {
    parse_nullable_json_list::<JsonValue>(stdout).is_ok_and(|records| {
        records.iter().any(|record| {
            record
                .get("RepoTags")
                .and_then(JsonValue::as_array)
                .is_some_and(|tags| tags.iter().any(|tag| tag.as_str() == Some(image)))
                || record.get("reference").and_then(JsonValue::as_str) == Some(image)
        })
    })
}

fn registry_login_command(registry: &str, username: &str) -> Result<Vec<String>, String> {
    let registry = registry.trim();
    let username = username.trim();
    if registry.is_empty() || username.is_empty() {
        return Err("registry and username are required".to_string());
    }
    Ok(ferrocrate_proxy_command(&[
        "login",
        registry,
        "--username",
        username,
        "--password-stdin",
    ]))
}

fn registry_logout_command(registry: &str) -> Result<Vec<String>, String> {
    let registry = registry.trim();
    if registry.is_empty() {
        return Err("registry is required".to_string());
    }
    Ok(["exec", "--", "ferrocrate", "logout", registry]
        .into_iter()
        .map(str::to_string)
        .collect())
}

fn network_summaries(
    mut networks: Vec<NetworkListRecord>,
    inspections: &BTreeMap<String, NetworkInspectRecord>,
    containers: &[ContainerNetworkRecord],
) -> Vec<NetworkSummary> {
    networks.sort_by(|left, right| left.name.cmp(&right.name));
    networks
        .into_iter()
        .map(|network| {
            let ipam = if network.ipam.config.is_empty() {
                inspections
                    .get(&network.name)
                    .map(|inspection| &inspection.ipam)
                    .unwrap_or(&network.ipam)
            } else {
                &network.ipam
            };
            let mut attachments = inspections
                .get(&network.name)
                .into_iter()
                .flat_map(|inspection| inspection.containers.iter())
                .map(|(container_id, attachment)| {
                    let container = containers.iter().find(|row| row.id == *container_id);
                    let name = attachment.name.trim_start_matches('/').to_string();
                    NetworkContainerSummary {
                        container_id: container_id.clone(),
                        name: if name.is_empty() {
                            container
                                .and_then(ContainerNetworkRecord::name)
                                .unwrap_or_else(|| container_id.clone())
                        } else {
                            name
                        },
                        ipv4_address: attachment.ipv4_address.clone(),
                        ipv6_address: attachment.ipv6_address.clone(),
                        ports: container
                            .map(|row| {
                                row.ports
                                    .iter()
                                    .map(|port| {
                                        format!(
                                            "0.0.0.0:{}→{}/{}",
                                            port.host_port, port.container_port, port.protocol
                                        )
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    }
                })
                .collect::<Vec<_>>();
            attachments.sort_by(|left, right| left.name.cmp(&right.name));
            NetworkSummary {
                name: network.name,
                driver: network.driver,
                subnets: ipam
                    .config
                    .iter()
                    .filter_map(|config| config.subnet.clone())
                    .collect(),
                containers: attachments,
            }
        })
        .collect()
}

fn volume_proxy_command(action: VolumeAction, target: Option<&str>) -> Result<Vec<String>, String> {
    let command = match action {
        VolumeAction::List => ferrocrate_proxy_command(&["volume", "ls", "--format", "json"]),
        VolumeAction::Prune => ferrocrate_proxy_command(&["volume", "prune"]),
        VolumeAction::Create | VolumeAction::Remove => {
            let target = target
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "volume name is required".to_string())?;
            ferrocrate_proxy_command(&[
                "volume",
                match action {
                    VolumeAction::Create => "create",
                    VolumeAction::Remove => "rm",
                    _ => unreachable!(),
                },
                target,
            ])
        }
    };
    Ok(command)
}

fn network_proxy_command(
    action: NetworkAction,
    target: Option<&str>,
    subnet: Option<&str>,
) -> Result<Vec<String>, String> {
    let command = match action {
        NetworkAction::List => ferrocrate_proxy_command(&["network", "ls", "--format", "json"]),
        NetworkAction::Inspect | NetworkAction::Create | NetworkAction::Remove => {
            let target = target
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "network name is required".to_string())?;
            if matches!(action, NetworkAction::Inspect) {
                return Ok(ferrocrate_proxy_command(&[
                    "network", "inspect", target, "--format", "json",
                ]));
            }
            let operation = match action {
                NetworkAction::Inspect => "inspect",
                NetworkAction::Create => "create",
                NetworkAction::Remove => "rm",
                NetworkAction::List => unreachable!(),
            };
            let mut command = ferrocrate_proxy_command(&["network", operation, target]);
            if matches!(action, NetworkAction::Create) {
                if let Some(subnet) = subnet.map(str::trim).filter(|value| !value.is_empty()) {
                    command.push("--subnet".to_string());
                    command.push(subnet.to_string());
                }
            }
            command
        }
    };
    Ok(command)
}

fn execute_volume_proxy(
    action: VolumeAction,
    target: Option<&str>,
) -> Result<CommandResult, String> {
    let args = volume_proxy_command(action, target)?;
    Ok(run_owned_command("ferro-desktop", &args))
}

fn execute_network_proxy(
    action: NetworkAction,
    target: Option<&str>,
    subnet: Option<&str>,
) -> Result<CommandResult, String> {
    let args = network_proxy_command(action, target, subnet)?;
    Ok(run_owned_command("ferro-desktop", &args))
}

fn run_command(binary: &str, args: &[&str]) -> CommandResult {
    if matches!(binary, "ferro-desktop" | "ferrocrate" | "ferro-cli") {
        return run_backend_command(
            binary,
            &args
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
            &[],
        );
    }
    match Command::new(binary).args(args).output() {
        Ok(output) => command_result_from_output(output),
        Err(err) => command_spawn_failure(binary, err),
    }
}

fn run_owned_command(binary: &str, args: &[String]) -> CommandResult {
    if matches!(binary, "ferro-desktop" | "ferrocrate" | "ferro-cli") {
        return run_backend_command(binary, args, &[]);
    }
    match Command::new(binary).args(args).output() {
        Ok(output) => command_result_from_output(output),
        Err(err) => command_spawn_failure(binary, err),
    }
}

fn run_command_env(binary: &str, args: &[&str], envs: &[(&str, String)]) -> CommandResult {
    if matches!(binary, "ferro-desktop" | "ferrocrate" | "ferro-cli") {
        return run_backend_command(
            binary,
            &args
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
            envs,
        );
    }
    let mut command = Command::new(binary);
    command.args(args);
    for (k, v) in envs {
        command.env(k, v);
    }
    match command.output() {
        Ok(output) => command_result_from_output(output),
        Err(err) => command_spawn_failure(binary, err),
    }
}

fn backend_command_request(
    binary: &str,
    args: &[String],
    envs: &[(&str, String)],
    stdin: Vec<u8>,
) -> Result<BackendExecRequest, String> {
    let (program, routed_args) =
        if binary == "ferro-desktop" && args.first().is_some_and(|arg| arg == "exec") {
            let split = args
                .iter()
                .position(|arg| arg == "--")
                .map(|index| index + 1)
                .unwrap_or(1);
            match args.get(split) {
                Some(program) => (program.clone(), args[split + 1..].to_vec()),
                None => return Err("desktop exec command is required".to_string()),
            }
        } else {
            (binary.to_string(), args.to_vec())
        };
    let mut request = BackendExecRequest::new(program).args(routed_args).stdin(stdin);
    for (name, value) in envs {
        request = request.env(*name, value.clone());
    }
    Ok(request)
}

fn command_result_from_backend(output: ferro_desktop::backend::ExecResponse) -> CommandResult {
    CommandResult {
        ok: output.code == 0,
        code: output.code,
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        message: actionable_error(&String::from_utf8_lossy(&output.stderr)),
    }
}

fn run_backend_command_with(
    backend: &dyn Backend,
    binary: &str,
    args: &[String],
    envs: &[(&str, String)],
    stdin: Vec<u8>,
) -> CommandResult {
    let request = match backend_command_request(binary, args, envs, stdin) {
        Ok(request) => request,
        Err(error) => return command_input_failure(&error),
    };
    match backend.exec(request) {
        Ok(output) => command_result_from_backend(output),
        Err(error) => command_spawn_failure(binary, error),
    }
}

fn run_backend_command(binary: &str, args: &[String], envs: &[(&str, String)]) -> CommandResult {
    #[cfg(target_os = "macos")]
    {
        let request = match backend_command_request(binary, args, envs, Vec::new()) {
            Ok(request) => request,
            Err(error) => return command_input_failure(&error),
        };
        let program = Path::new(&request.program)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&request.program);
        if !matches!(program, "ferrocrate" | "ferro-cli") {
            let backend = LinuxNativeBackend::new(LinuxNativeConfig::default());
            return match backend.exec(request) {
                Ok(output) => command_result_from_backend(output),
                Err(error) => command_spawn_failure(binary, error),
            };
        }
    }
    match desktop_backend() {
        Ok(backend) => run_backend_command_with(backend, binary, args, envs, Vec::new()),
        Err(error) => command_spawn_failure(binary, error),
    }
}

fn backend_stream_with(
    backend: &dyn Backend,
    binary: &str,
    args: &[String],
) -> Result<Box<dyn ExecStream>, String> {
    let request = backend_command_request(binary, args, &[], Vec::new())?;
    backend.exec_stream(request).map_err(|error| error.to_string())
}

fn start_log_follow_stream_with(
    backend: &dyn Backend,
    target: &str,
) -> Result<Box<dyn ExecStream>, String> {
    backend_stream_with(backend, "ferro-desktop", &log_follow_command(target))
}

fn start_image_build_stream_with(
    backend: &dyn Backend,
    context: &str,
    tag: &str,
) -> Result<Box<dyn ExecStream>, String> {
    backend_stream_with(backend, "ferro-desktop", &build_bridge_command(context, tag)?)
}

fn log_follow_command(target: &str) -> Vec<String> {
    vec![
        "exec".to_string(),
        "--follow".to_string(),
        "--".to_string(),
        "ferrocrate".to_string(),
        "logs".to_string(),
        "--follow".to_string(),
        target.to_string(),
    ]
}

#[cfg(test)]
fn terminal_exec_command(
    target: &str,
    shell: &str,
    env: &[String],
    user: Option<&str>,
    workdir: Option<&str>,
) -> Vec<String> {
    let mut command = vec![
        "terminal-proxy".to_string(),
        "--container".to_string(),
        target.to_string(),
    ];
    for value in env {
        command.push("--env".to_string());
        command.push(value.clone());
    }
    if let Some(user) = user.filter(|value| !value.trim().is_empty()) {
        command.push("--user".to_string());
        command.push(user.to_string());
    }
    if let Some(workdir) = workdir.filter(|value| !value.trim().is_empty()) {
        command.push("--workdir".to_string());
        command.push(workdir.to_string());
    }
    command.extend(["--".to_string(), shell.to_string()]);
    command
}

#[cfg(test)]
fn terminal_resize_command(exec_id: &str, columns: u16, rows: u16) -> Vec<String> {
    vec![
        "terminal-resize".to_string(),
        "--exec-id".to_string(),
        exec_id.to_string(),
        "--columns".to_string(),
        columns.to_string(),
        "--rows".to_string(),
        rows.to_string(),
    ]
}

#[derive(Clone, Serialize)]
struct TerminalOutput {
    data: Vec<u8>,
    stderr: bool,
}

#[cfg(test)]
fn parse_terminal_exec_id(line: &str) -> Result<String, String> {
    const PREFIX: &str = "FERROCRATE_EXEC_ID=";
    let trimmed = line.trim();
    let Some(exec_id) = trimmed.strip_prefix(PREFIX) else {
        return Err(if trimmed.is_empty() {
            "terminal proxy closed before the daemon exec was allocated".to_string()
        } else {
            trimmed.to_string()
        });
    };
    if exec_id.is_empty() {
        return Err("terminal proxy returned an empty exec id".to_string());
    }
    Ok(exec_id.to_string())
}

fn emit_terminal_output<R: Read>(mut reader: R, events: EventSink, stderr: bool) {
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes = match reader.read(&mut buffer) {
            Ok(0) => return,
            Ok(bytes) => bytes,
            Err(err) => {
                events.emit("terminal-error", err.to_string());
                return;
            }
        };
        events.emit(
            "terminal-output",
            TerminalOutput {
                data: buffer[..bytes].to_vec(),
                stderr,
            },
        );
    }
}

fn clear_terminal_slot_if_matches(
    slot: &Mutex<Option<TerminalProcess>>,
    exec_id: &str,
) -> bool {
    let Ok(mut current) = slot.lock() else {
        return false;
    };
    if current
        .as_ref()
        .is_some_and(|process| process.exec_id == exec_id)
    {
        *current = None;
        true
    } else {
        false
    }
}

fn start_terminal_impl(
    events: EventSink,
    target: String,
    shell: String,
    env: Vec<String>,
    user: Option<String>,
    workdir: Option<String>,
) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target container is required".to_string());
    }
    let shell = shell.trim();
    if shell.is_empty() {
        return Err("shell command is required".to_string());
    }

    let mut current = TERMINAL_PROCESS
        .lock()
        .map_err(|_| "terminal state is unavailable".to_string())?;
    if current.is_some() {
        return Err("an exec terminal is already active".to_string());
    }
    let session = desktop_backend()?
        .open_terminal(TerminalRequest {
            container: target.to_string(),
            command: vec![shell.to_string()],
            env,
            user,
            workdir,
        })
        .map_err(|error| error.to_string())?;
    let output = session
        .stream
        .try_clone_stream()
        .map_err(|error| error.to_string())?;
    let output_exec_id = session.exec_id.clone();
    *current = Some(TerminalProcess {
        stream: session.stream,
        exec_id: session.exec_id,
    });
    drop(current);
    let output_events = events.clone();
    thread::spawn(move || {
        emit_terminal_output(output, output_events.clone(), false);
        if clear_terminal_slot_if_matches(&TERMINAL_PROCESS, &output_exec_id) {
            output_events.emit("terminal-ended", true);
        }
    });
    Ok(())
}

#[tauri::command]
fn start_terminal(
    app: tauri::AppHandle,
    target: String,
    shell: String,
    env: Vec<String>,
    user: Option<String>,
    workdir: Option<String>,
) -> Result<(), String> {
    start_terminal_impl(EventSink::Tauri(app), target, shell, env, user, workdir)
}

#[tauri::command]
fn write_terminal(data: Vec<u8>) -> Result<(), String> {
    if data.len() > 64 * 1024 {
        return Err("terminal input exceeds 64 KiB".to_string());
    }
    let mut current = TERMINAL_PROCESS
        .lock()
        .map_err(|_| "terminal state is unavailable".to_string())?;
    let process = current
        .as_mut()
        .ok_or_else(|| "no exec terminal is active".to_string())?;
    process
        .stream
        .write_all(&data)
        .and_then(|_| process.stream.flush())
        .map_err(|err| format!("failed to write terminal input: {err}"))
}

#[tauri::command]
fn resize_terminal(columns: u16, rows: u16) -> Result<(), String> {
    if columns == 0 || rows == 0 {
        return Err("terminal dimensions must be non-zero".to_string());
    }
    let exec_id = TERMINAL_PROCESS
        .lock()
        .map_err(|_| "terminal state is unavailable".to_string())?
        .as_ref()
        .map(|process| process.exec_id.clone())
        .ok_or_else(|| "no exec terminal is active".to_string())?;
    desktop_backend()?
        .resize_terminal(&exec_id, columns, rows)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn close_terminal() -> Result<(), String> {
    let mut current = TERMINAL_PROCESS
        .lock()
        .map_err(|_| "terminal state is unavailable".to_string())?;
    if let Some(process) = current.take() {
        process
            .stream
            .shutdown_write()
            .map_err(|error| error.to_string())?;
    }
    Ok(())
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

#[derive(Clone, Serialize)]
struct LogBatch {
    text: String,
    truncated: bool,
}

fn emit_log_batch(events: &EventSink, buffer: &LogBuffer) {
    events.emit(
        "container-log-batch",
        LogBatch {
            text: buffer.text(),
            truncated: buffer.truncated,
        },
    );
}

fn log_channel(capacity: usize) -> (SyncSender<String>, Receiver<String>) {
    mpsc::sync_channel(capacity)
}

fn publish_log_batches(events: EventSink, receiver: Receiver<String>) {
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
                    emit_log_batch(&events, &buffer);
                    changed = false;
                    last_publish = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) if changed => {
                emit_log_batch(&events, &buffer);
                changed = false;
                last_publish = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if changed {
                    emit_log_batch(&events, &buffer);
                }
                return;
            }
        }
    }
}

fn queue_log_lines<R: std::io::Read>(reader: R, sender: SyncSender<String>) {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                if sender.send(line.clone()).is_err() {
                    break;
                }
                line.clear();
            }
            Err(_) => break,
        }
    }
}

fn emit_log_errors<R: std::io::Read>(reader: R, events: EventSink) {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    while let Ok(bytes) = reader.read_line(&mut line) {
        if bytes == 0 {
            break;
        }
        events.emit("container-log-error", line.clone());
        line.clear();
    }
}

fn start_log_follow_impl(events: EventSink, target: String) -> Result<(), String> {
    let target = target.trim();
    if target.is_empty() {
        return Err("target container is required".to_string());
    }

    let mut current = LOG_FOLLOW_PROCESS
        .lock()
        .map_err(|_| "log follow state is unavailable".to_string())?;
    if let Some(child) = current.as_mut() {
        if child
            .try_wait()
            .map_err(|err| format!("failed to inspect log follow process: {err}"))?
            .is_none()
        {
            return Err("a container log stream is already active".to_string());
        }
    }
    *current = None;

    let mut child = start_log_follow_stream_with(desktop_backend()?, target)
        .map_err(|err| format!("failed to start container log stream: {err}"))?;
    let stdout = child
        .take_stdout()
        .map_err(|err| format!("container log stream stdout missing: {err}"))?;
    let stderr = child
        .take_stderr()
        .map_err(|err| format!("container log stream stderr missing: {err}"))?;
    let (log_sender, log_receiver) = log_channel(LOG_CHANNEL_CAPACITY);
    let stdout_events = events.clone();
    thread::spawn(move || publish_log_batches(stdout_events, log_receiver));
    thread::spawn(move || queue_log_lines(stdout, log_sender));
    let stderr_events = events.clone();
    thread::spawn(move || emit_log_errors(stderr, stderr_events));
    *current = Some(child);
    drop(current);

    thread::spawn(move || loop {
        let status = {
            let mut process = match LOG_FOLLOW_PROCESS.lock() {
                Ok(process) => process,
                Err(_) => return,
            };
            let Some(child) = process.as_mut() else {
                return;
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    *process = None;
                    Some(status)
                }
                Ok(None) => None,
                Err(err) => {
                    events.emit("container-log-error", err.to_string());
                    *process = None;
                    return;
                }
            }
        };
        if let Some(status) = status {
            events.emit("container-log-ended", status == 0);
            return;
        }
        thread::sleep(Duration::from_millis(250));
    });
    Ok(())
}

#[tauri::command]
fn start_log_follow(app: tauri::AppHandle, target: String) -> Result<(), String> {
    start_log_follow_impl(EventSink::Tauri(app), target)
}

#[tauri::command]
fn stop_log_follow() -> Result<(), String> {
    let mut current = LOG_FOLLOW_PROCESS
        .lock()
        .map_err(|_| "log follow state is unavailable".to_string())?;
    if let Some(mut child) = current.take() {
        child
            .kill()
            .map_err(|err| format!("failed to stop container log stream: {err}"))?;
        child
            .wait()
            .map_err(|err| format!("failed to reap container log stream: {err}"))?;
    }
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn config_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let dir = PathBuf::from(home).join(".ferrocrate");
    fs::create_dir_all(&dir).map_err(|err| format!("failed to create config dir: {err}"))?;
    Ok(dir.join("desktop-ui-auth.json"))
}

fn read_paid_backend_config() -> Result<Option<PaidBackendConfig>, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).map_err(|err| format!("failed to read config: {err}"))?;
    let parsed = serde_json::from_str::<PaidBackendConfig>(&raw)
        .map_err(|err| format!("invalid config JSON: {err}"))?;
    Ok(Some(parsed))
}

fn write_paid_backend_config(cfg: &PaidBackendConfig) -> Result<(), String> {
    let path = config_path()?;
    let raw = serde_json::to_string_pretty(cfg)
        .map_err(|err| format!("failed to encode config: {err}"))?;
    fs::write(&path, raw).map_err(|err| format!("failed to write config: {err}"))
}

fn keyring_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|err| format!("keyring init failed: {err}"))
}

fn get_session_token() -> Result<Option<String>, String> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(value) => {
            if value.trim().is_empty() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(format!("failed to read session token from keyring: {err}")),
    }
}

fn set_session_token(token: &str) -> Result<(), String> {
    let entry = keyring_entry()?;
    entry
        .set_password(token)
        .map_err(|err| format!("failed to write session token to keyring: {err}"))
}

fn clear_session_token() -> Result<(), String> {
    let entry = keyring_entry()?;
    match entry.delete_credential() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(format!("failed to clear session token from keyring: {err}")),
    }
}

fn registry_keyring_entry(registry: &str) -> Result<keyring::Entry, String> {
    let registry = registry.trim().to_ascii_lowercase();
    if registry.is_empty() {
        return Err("registry is required".to_string());
    }
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(registry.as_bytes());
    keyring::Entry::new(KEYRING_SERVICE, &format!("registry_auth:{encoded}"))
        .map_err(|err| format!("registry keyring init failed: {err}"))
}

fn get_registry_credential(registry: &str) -> Result<Option<StoredRegistryCredential>, String> {
    let entry = registry_keyring_entry(registry)?;
    match entry.get_password() {
        Ok(value) => serde_json::from_str(&value)
            .map(Some)
            .map_err(|err| format!("invalid registry credential in keyring: {err}")),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(format!(
            "failed to read registry credential from keyring: {err}"
        )),
    }
}

fn set_registry_credential(credential: &StoredRegistryCredential) -> Result<(), String> {
    let entry = registry_keyring_entry(&credential.registry)?;
    let value = serde_json::to_string(credential)
        .map_err(|err| format!("failed to encode registry credential: {err}"))?;
    entry
        .set_password(&value)
        .map_err(|err| format!("failed to write registry credential to keyring: {err}"))
}

fn clear_registry_credential(registry: &str) -> Result<(), String> {
    let entry = registry_keyring_entry(registry)?;
    match entry.delete_credential() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(format!(
            "failed to clear registry credential from keyring: {err}"
        )),
    }
}

fn parse_jwt_claims(token: &str) -> Option<JsonValue> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    serde_json::from_slice::<JsonValue>(&payload).ok()
}

fn session_summary_from_token(token: Option<String>) -> SessionSummary {
    let Some(token) = token else {
        return SessionSummary {
            token_present: false,
            subject: None,
            plan: None,
            expires_at: None,
            expired: None,
        };
    };
    let claims = parse_jwt_claims(&token);
    let expires_at = claims
        .as_ref()
        .and_then(|v| v.get("exp"))
        .and_then(|v| v.as_u64());
    let expired = expires_at.map(|exp| now_unix() >= exp);
    SessionSummary {
        token_present: true,
        subject: claims
            .as_ref()
            .and_then(|v| v.get("sub"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        plan: claims
            .as_ref()
            .and_then(|v| v.get("plan"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        expires_at,
        expired,
    }
}

fn query_entitlement_from_session(
    config: &PaidBackendConfig,
    session_token: &str,
) -> Result<EntitlementSummary, String> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&config.token_endpoint)
        .header("Authorization", format!("Bearer {session_token}"))
        .header("X-Ferrocrate-Tag", "latest")
        .send()
        .map_err(|err| format!("token endpoint request failed: {err}"))?;

    let status = resp.status();
    let body = resp
        .text()
        .map_err(|err| format!("token endpoint read failed: {err}"))?;
    if !status.is_success() {
        return Err(format!("token endpoint rejected session: {body}"));
    }
    let parsed = serde_json::from_str::<JsonValue>(&body)
        .map_err(|err| format!("token endpoint invalid JSON: {err}"))?;
    let plan = parsed
        .get("plan")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let message = parsed
        .get("error")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    Ok(EntitlementSummary {
        status: "ok".to_string(),
        plan,
        subject: None,
        expires_at: parsed.get("expires_at").and_then(|v| v.as_u64()),
        features: Vec::new(),
        message,
    })
}

#[tauri::command]
fn get_desktop_snapshot() -> DesktopSnapshot {
    let daemon = daemon_status();
    let runtime = if daemon.state == "running" {
        CommandResult {
            ok: true,
            code: 0,
            stdout: daemon.socket_path.clone(),
            stderr: String::new(),
            message: String::new(),
        }
    } else {
        command_input_failure(
            daemon
                .reason
                .as_deref()
                .unwrap_or("Ferrocrate daemon is stopped"),
        )
    };
    let mut containers = run_owned_command(
        "ferro-desktop",
        &ferrocrate_proxy_command(&["containers", "--all", "--format", "json"]),
    );
    normalize_nullable_list_output(&mut containers);
    let mut images = run_owned_command(
        "ferro-desktop",
        &ferrocrate_proxy_command(&["images", "--format", "json"]),
    );
    normalize_nullable_list_output(&mut images);

    DesktopSnapshot {
        daemon,
        runtime,
        containers,
        images,
    }
}

#[tauri::command]
fn get_container_stats(ids: Vec<String>) -> ContainerStatsResponse {
    ContainerStatsResponse {
        samples: collect_container_stats(&ids),
    }
}

#[tauri::command]
fn get_volumes() -> Result<Vec<VolumeSummary>, String> {
    let result = execute_volume_proxy(VolumeAction::List, None)?;
    if !result.ok {
        return Err(if result.stderr.trim().is_empty() {
            format!("volume list failed with status {}", result.code)
        } else {
            result.stderr.trim().to_string()
        });
    }
    serde_json::from_str::<VolumeListResponse>(&result.stdout)
        .map(|response| response.volumes)
        .map_err(|error| format!("volume proxy returned invalid JSON: {error}"))
}

#[tauri::command]
fn get_networks() -> Result<Vec<NetworkSummary>, String> {
    let list_result = execute_network_proxy(NetworkAction::List, None, None)?;
    if !list_result.ok {
        return Err(command_failure("network list", &list_result));
    }
    let networks = parse_nullable_json_list::<NetworkListRecord>(&list_result.stdout)
        .map_err(|error| format!("network proxy returned invalid JSON: {error}"))?;
    let mut inspections = BTreeMap::new();
    for network in &networks {
        let result = execute_network_proxy(NetworkAction::Inspect, Some(&network.name), None)?;
        if !result.ok {
            return Err(command_failure("network inspect", &result));
        }
        inspections.insert(
            network.name.clone(),
            serde_json::from_str::<NetworkInspectRecord>(&result.stdout)
                .map_err(|error| format!("network inspect returned invalid JSON: {error}"))?,
        );
    }
    let containers_result = run_owned_command("ferro-desktop", &compose_container_list_command());
    if !containers_result.ok {
        return Err(command_failure("container port list", &containers_result));
    }
    let containers = parse_nullable_json_list::<ContainerNetworkRecord>(&containers_result.stdout)
        .map_err(|error| format!("container port list returned invalid JSON: {error}"))?;
    Ok(network_summaries(networks, &inspections, &containers))
}

#[tauri::command]
fn get_container_detail(target: String) -> Result<ContainerDetailSummary, String> {
    let result = run_owned_command("ferro-desktop", &container_inspect_command(&target)?);
    if !result.ok {
        return Err(command_failure("container inspect", &result));
    }
    let value = serde_json::from_str::<JsonValue>(&result.stdout)
        .map_err(|error| format!("container inspect returned invalid JSON: {error}"))?;
    container_detail_from_json(value)
}

fn command_failure(label: &str, result: &CommandResult) -> String {
    if result.message.is_empty() {
        format!("{label} failed with status {}", result.code)
    } else {
        result.message.clone()
    }
}

#[tauri::command]
fn get_compose_snapshot(file: String) -> Result<ComposeSnapshot, String> {
    let config_result = run_owned_command(
        "ferro-desktop",
        &compose_bridge_command(&file, ComposeAction::Config)?,
    );
    if !config_result.ok {
        return Err(command_failure("compose config", &config_result));
    }
    let config = serde_yaml::from_str::<ComposeConfigProjection>(&config_result.stdout)
        .map_err(|error| format!("compose config returned invalid YAML: {error}"))?;
    let containers_result = run_owned_command("ferro-desktop", &compose_container_list_command());
    if !containers_result.ok {
        return Err(command_failure("container status", &containers_result));
    }
    let containers = parse_nullable_json_list::<ComposeContainerRecord>(&containers_result.stdout)
        .map_err(|error| format!("container status returned invalid JSON: {error}"))?;
    Ok(ComposeSnapshot {
        config: config_result.stdout,
        services: compose_service_rows(config.services.into_keys().collect(), &containers),
    })
}

#[tauri::command]
fn run_compose_action(file: String, action: ComposeAction) -> Result<CommandResult, String> {
    if matches!(action, ComposeAction::Config) {
        return Err("use the compose snapshot command to validate config".to_string());
    }
    Ok(run_owned_command(
        "ferro-desktop",
        &compose_bridge_command(&file, action)?,
    ))
}

fn build_image_impl(
    events: EventSink,
    context: String,
    tag: String,
    build_id: String,
) -> Result<CommandResult, String> {
    let build_id = build_id.trim().to_string();
    if build_id.is_empty() {
        return Err("build identifier is required".to_string());
    }
    let mut child = start_image_build_stream_with(desktop_backend()?, &context, &tag)
        .map_err(|error| format!("failed to start image build: {error}"))?;
    let stdout = child
        .take_stdout()
        .map_err(|error| format!("image build stdout unavailable: {error}"))?;
    let stderr = child
        .take_stderr()
        .map_err(|error| format!("image build stderr unavailable: {error}"))?;
    let (sender, receiver) = mpsc::channel::<BuildProgressFrame>();
    for (stream, reader) in [
        ("stdout", Box::new(stdout) as Box<dyn Read + Send>),
        ("stderr", Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let sender = sender.clone();
        let build_id = build_id.clone();
        thread::spawn(move || {
            for line in BufReader::new(reader).lines() {
                match line {
                    Ok(text) => {
                        let _ = sender.send(BuildProgressFrame {
                            build_id: build_id.clone(),
                            stream: stream.to_string(),
                            text,
                        });
                    }
                    Err(error) => {
                        let _ = sender.send(BuildProgressFrame {
                            build_id: build_id.clone(),
                            stream: "stderr".to_string(),
                            text: format!("failed to read build output: {error}"),
                        });
                    }
                }
            }
        });
    }
    drop(sender);
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();
    for frame in receiver {
        let destination = if frame.stream == "stderr" {
            &mut stderr_text
        } else {
            &mut stdout_text
        };
        destination.push_str(&frame.text);
        destination.push('\n');
        events.emit("image-build-progress", frame);
    }
    let code = child
        .wait()
        .map_err(|error| format!("failed to wait for image build: {error}"))?;
    Ok(CommandResult {
        ok: code == 0,
        code,
        stdout: stdout_text,
        message: actionable_error(&stderr_text),
        stderr: stderr_text,
    })
}

#[tauri::command]
fn build_image(
    app: tauri::AppHandle,
    context: String,
    tag: String,
    build_id: String,
) -> Result<CommandResult, String> {
    build_image_impl(EventSink::Tauri(app), context, tag, build_id)
}

#[tauri::command]
fn run_volume_action(
    action: VolumeAction,
    target: Option<String>,
) -> Result<CommandResult, String> {
    if matches!(action, VolumeAction::List) {
        return Err("list is a read-only snapshot action".to_string());
    }
    execute_volume_proxy(action, target.as_deref())
}

#[tauri::command]
fn run_network_action(
    action: NetworkAction,
    target: Option<String>,
    subnet: Option<String>,
) -> Result<CommandResult, String> {
    if matches!(action, NetworkAction::List | NetworkAction::Inspect) {
        return Err("list is a read-only snapshot action".to_string());
    }
    if matches!(action, NetworkAction::Create) && !daemon_status().custom_networks {
        return Err(
            "Custom networks need a privileged (rootful) daemon, or a host configured with the Ferrocrate AppArmor profile. Open Doctor for guided setup."
                .to_string(),
        );
    }
    execute_network_proxy(action, target.as_deref(), subnet.as_deref())
}

#[tauri::command]
fn update_container_resources(
    target: String,
    memory: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
) -> Result<CommandResult, String> {
    Ok(run_owned_command(
        "ferro-desktop",
        &container_update_command(&target, memory, cpu_quota, cpu_period)?,
    ))
}

#[tauri::command]
// Tauri IPC requires the command signature to expose each frontend field by name.
#[allow(clippy::too_many_arguments)]
fn run_new_container(
    image: String,
    name: Option<String>,
    command: Vec<String>,
    ports: Vec<String>,
    volumes: Vec<String>,
    pull_if_missing: bool,
    environment: Vec<String>,
    memory: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
) -> Result<CommandResult, String> {
    if pull_if_missing {
        let images = run_owned_command(
            "ferro-desktop",
            &ferrocrate_proxy_command(&["images", "--format", "json"]),
        );
        if !images.ok {
            return Ok(images);
        }
        if !image_list_contains(&images.stdout, image.trim()) {
            let pull = run_owned_command(
                "ferro-desktop",
                &ferrocrate_proxy_command(&["pull", image.trim()]),
            );
            if !pull.ok {
                return Ok(pull);
            }
        }
    }
    Ok(run_owned_command(
        "ferro-desktop",
        &run_container_bridge_command(
            &image,
            name.as_deref(),
            &command,
            &ports,
            &volumes,
            &environment,
            memory,
            cpu_quota,
            cpu_period,
        )?,
    ))
}

#[tauri::command]
fn get_registry_auth_status(registry: String) -> Result<RegistryAuthStatus, String> {
    let registry = registry.trim().to_string();
    let credential = get_registry_credential(&registry)?;
    Ok(RegistryAuthStatus {
        registry,
        logged_in: credential.is_some(),
        username: credential.map(|value| value.username),
    })
}

#[tauri::command]
fn login_registry(
    registry: String,
    username: String,
    password: String,
) -> Result<CommandResult, String> {
    let registry = registry.trim().to_string();
    let username = username.trim().to_string();
    if password.is_empty() {
        return Err("registry password is required".to_string());
    }
    let args = registry_login_command(&registry, &username)?;
    let mut stdin = password.as_bytes().to_vec();
    stdin.push(b'\n');
    let result = run_backend_command_with(desktop_backend()?, "ferro-desktop", &args, &[], stdin);
    if result.ok {
        set_registry_credential(&StoredRegistryCredential {
            registry,
            username,
            password,
        })?;
    }
    Ok(result)
}

#[tauri::command]
fn logout_registry(registry: String) -> Result<CommandResult, String> {
    let registry = registry.trim().to_string();
    let result = run_owned_command("ferro-desktop", &registry_logout_command(&registry)?);
    if result.ok {
        clear_registry_credential(&registry)?;
    }
    Ok(result)
}

#[tauri::command]
fn get_paid_auth_state() -> Result<PaidAuthState, String> {
    let config = read_paid_backend_config()?;
    let token = get_session_token()?;
    let session = session_summary_from_token(token.clone());
    let entitlement = match (&config, token) {
        (Some(cfg), Some(token_value)) => query_entitlement_from_session(cfg, &token_value).ok(),
        _ => None,
    };
    Ok(PaidAuthState {
        config,
        session,
        entitlement,
    })
}

#[tauri::command]
fn save_paid_backend_config(
    release_base_url: String,
    token_endpoint: String,
    issuance_endpoint: Option<String>,
) -> Result<(), String> {
    if release_base_url.trim().is_empty() || token_endpoint.trim().is_empty() {
        return Err("release_base_url and token_endpoint are required".to_string());
    }
    write_paid_backend_config(&PaidBackendConfig {
        release_base_url,
        token_endpoint,
        issuance_endpoint,
    })
}

#[tauri::command]
fn set_paid_session_token(token: String) -> Result<SessionSummary, String> {
    if token.trim().is_empty() {
        return Err("session token is required".to_string());
    }
    set_session_token(token.trim())?;
    Ok(session_summary_from_token(Some(token)))
}

#[tauri::command]
fn acquire_paid_session(
    customer_id: String,
    access_token: Option<String>,
) -> Result<SessionSummary, String> {
    if customer_id.trim().is_empty() {
        return Err("customer_id is required".to_string());
    }
    let cfg =
        read_paid_backend_config()?.ok_or_else(|| "paid backend config missing".to_string())?;
    let issuance = cfg
        .issuance_endpoint
        .ok_or_else(|| "issuance_endpoint is not configured".to_string())?;

    let client = reqwest::blocking::Client::new();
    let mut req = client
        .post(issuance)
        .json(&serde_json::json!({ "customer_id": customer_id.trim() }));
    if let Some(token) = access_token {
        if !token.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", token.trim()));
        }
    }
    let resp = req
        .send()
        .map_err(|err| format!("session issuance request failed: {err}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .map_err(|err| format!("session issuance response read failed: {err}"))?;
    if !status.is_success() {
        return Err(format!("session issuance failed: {body}"));
    }
    let parsed = serde_json::from_str::<JsonValue>(&body)
        .map_err(|err| format!("session issuance invalid JSON: {err}"))?;
    let token = parsed
        .get("session_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "session issuance response missing session_token".to_string())?;
    set_session_token(token)?;
    Ok(session_summary_from_token(Some(token.to_string())))
}

#[tauri::command]
fn clear_paid_session() -> Result<(), String> {
    clear_session_token()
}

#[tauri::command]
fn run_paid_full_stack_install(
    confirm: bool,
    dry_run: bool,
) -> Result<InstallerRunSummary, String> {
    let cfg =
        read_paid_backend_config()?.ok_or_else(|| "paid backend config missing".to_string())?;
    let token = get_session_token()?
        .ok_or_else(|| "paid session token missing (login required)".to_string())?;
    let command = "scripts/install-macos.sh --channel paid --full-stack".to_string();
    if dry_run {
        return Ok(InstallerRunSummary {
            dry_run: true,
            ok: true,
            command,
            result: None,
        });
    }
    if !confirm {
        return Err("install requires explicit confirmation (set confirm=true)".to_string());
    }
    let result = run_command_env(
        "bash",
        &[
            "scripts/install-macos.sh",
            "--channel",
            "paid",
            "--full-stack",
        ],
        &[
            ("PAID_RELEASE_BASE_URL", cfg.release_base_url),
            ("PAID_RELEASE_TOKEN_ENDPOINT", cfg.token_endpoint),
            ("PAID_SESSION_TOKEN", token),
        ],
    );
    Ok(InstallerRunSummary {
        dry_run: false,
        ok: result.ok,
        command,
        result: Some(result),
    })
}

#[tauri::command]
fn run_doctor_action(
    fix: bool,
    bootstrap: bool,
    dry_run: bool,
    confirm: bool,
) -> Result<DoctorSummary, String> {
    let args = doctor_command(fix, bootstrap, dry_run, confirm);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let result = run_command("ferrocrate", &args);
    let payload = serde_json::from_str::<JsonValue>(&result.stdout).unwrap_or_else(|_| {
        serde_json::json!({
            "healthy": false,
            "error": "invalid doctor json output",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "checks": []
        })
    });
    let payload = match desktop_backend() {
        Ok(backend) => doctor_with_backend_status(payload, backend.status()),
        Err(error) => doctor_with_backend_error(payload, &error),
    };
    Ok(DoctorSummary {
        ok: result.ok && payload["healthy"].as_bool().unwrap_or(false),
        raw: payload,
    })
}

fn doctor_with_backend_status(payload: JsonValue, status: BackendStatus) -> JsonValue {
    let backend = serde_json::to_value(status).unwrap_or_else(|error| {
        serde_json::json!({
            "backend": "unavailable",
            "state": "failed",
            "healthy": false,
            "reason": error.to_string(),
            "capabilities": {},
        })
    });
    doctor_with_backend_payload(payload, backend)
}

fn doctor_with_backend_error(payload: JsonValue, error: &str) -> JsonValue {
    doctor_with_backend_payload(
        payload,
        serde_json::json!({
            "backend": "unavailable",
            "platform": "unsupported",
            "state": "unavailable",
            "healthy": false,
            "endpoint": "",
            "reason": error,
            "capabilities": {
                "terminal": false,
                "registry": false,
                "containers": false,
                "networks": false,
                "volumes": false,
                "custom_networks": false,
                "streaming_exec": false,
            },
        }),
    )
}

fn doctor_with_backend_payload(mut payload: JsonValue, backend: JsonValue) -> JsonValue {
    let Some(object) = payload.as_object_mut() else {
        return payload;
    };

    let state = backend["state"].as_str().unwrap_or("unavailable");
    let reported_healthy = backend["healthy"].as_bool().unwrap_or(false);
    let backend_healthy = reported_healthy
        && !matches!(state, "failed" | "unavailable");
    let backend_name = backend["backend"].as_str().unwrap_or("desktop");
    let reason = backend["reason"]
        .as_str()
        .filter(|reason| !reason.trim().is_empty());
    let message = match reason {
        Some(reason) => format!("{backend_name} backend is {state}: {reason}"),
        None => format!("{backend_name} backend is {state}"),
    };
    let capabilities = backend["capabilities"].as_object().map_or_else(
        || "none reported".to_string(),
        |capabilities| {
            let enabled = capabilities
                .iter()
                .filter_map(|(name, enabled)| enabled.as_bool().filter(|enabled| *enabled).map(|_| name.replace('_', " ")))
                .collect::<Vec<_>>();
            if enabled.is_empty() {
                "none".to_string()
            } else {
                enabled.join(", ")
            }
        },
    );
    let checks = object
        .entry("checks".to_string())
        .or_insert_with(|| JsonValue::Array(Vec::new()));
    if let Some(checks) = checks.as_array_mut() {
        checks.retain(|check| check["id"] != "desktop_backend");
        checks.push(serde_json::json!({
            "id": "desktop_backend",
            "ok": backend_healthy,
            "message": message,
            "hint": format!("Capabilities: {capabilities}."),
            "remediated": false,
            "action": null,
        }));
    }
    let doctor_healthy = object["healthy"].as_bool().unwrap_or(false);
    object.insert("healthy".to_string(), JsonValue::Bool(doctor_healthy && backend_healthy));
    object.insert("desktop_backend".to_string(), backend);
    payload
}

fn doctor_command(fix: bool, bootstrap: bool, dry_run: bool, confirm: bool) -> Vec<String> {
    let mut args = vec!["doctor", "--json"];
    if fix {
        args.push("--fix");
    }
    if bootstrap {
        args.push("--bootstrap");
    }
    if dry_run {
        args.push("--dry-run");
    }
    if confirm {
        args.push("--confirm");
    }
    args.into_iter().map(str::to_string).collect()
}

#[tauri::command]
fn run_desktop_action(action: DesktopAction, target: Option<String>) -> CommandResult {
    let target = target.unwrap_or_default().trim().to_string();
    match action {
        DesktopAction::VmStart => match start_desktop_daemon() {
            Ok(()) => CommandResult {
                ok: true,
                code: 0,
                stdout: daemon_status().socket_path,
                stderr: String::new(),
                message: String::new(),
            },
            Err(error) => command_input_failure(&error),
        },
        DesktopAction::VmStop => {
            stop_desktop_daemon();
            CommandResult {
                ok: true,
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
                message: String::new(),
            }
        }
        DesktopAction::PullImage => {
            if target.is_empty() {
                return command_input_failure("target image is required");
            }
            run_owned_command(
                "ferro-desktop",
                &ferrocrate_proxy_command(&["pull", &target]),
            )
        }
        DesktopAction::RemoveImage => {
            if target.is_empty() {
                return command_input_failure("target image is required");
            }
            run_owned_command(
                "ferro-desktop",
                &ferrocrate_proxy_command(&["rmi", &target]),
            )
        }
        DesktopAction::StartContainer => {
            if target.is_empty() {
                return command_input_failure("target container is required");
            }
            run_owned_command(
                "ferro-desktop",
                &ferrocrate_proxy_command(&["start", &target]),
            )
        }
        DesktopAction::StopContainer => {
            if target.is_empty() {
                return command_input_failure("target container is required");
            }
            run_owned_command(
                "ferro-desktop",
                &ferrocrate_proxy_command(&["stop", &target]),
            )
        }
        DesktopAction::RemoveContainer => {
            if target.is_empty() {
                return command_input_failure("target container is required");
            }
            run_owned_command("ferro-desktop", &ferrocrate_proxy_command(&["rm", &target]))
        }
        DesktopAction::ContainerPrune => run_owned_command(
            "ferro-desktop",
            &ferrocrate_proxy_command(&["container-prune"]),
        ),
        DesktopAction::ImagePrune => {
            run_owned_command("ferro-desktop", &ferrocrate_proxy_command(&["image-prune"]))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct WebModeOptions {
    listen: SocketAddr,
    insecure_bind: bool,
}

fn parse_web_mode<I, S>(args: I) -> Result<Option<WebModeOptions>, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let _program = args.next();
    let mut web = false;
    let mut insecure_bind = false;
    let mut listen = "127.0.0.1:4190"
        .parse::<SocketAddr>()
        .expect("default bind");
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--web" => web = true,
            "--insecure-bind" => insecure_bind = true,
            "--listen" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--listen requires an IP:PORT value".to_string())?;
                listen = value
                    .parse()
                    .map_err(|error| format!("invalid --listen address {value:?}: {error}"))?;
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if !web {
        if insecure_bind || listen != "127.0.0.1:4190".parse().expect("default bind") {
            return Err("--listen and --insecure-bind require --web".to_string());
        }
        return Ok(None);
    }
    if !listen.ip().is_loopback() && !insecure_bind {
        return Err(format!(
            "refusing non-loopback web bridge bind {listen}; pass --insecure-bind to override"
        ));
    }
    Ok(Some(WebModeOptions {
        listen,
        insecure_bind,
    }))
}

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = webkit_rendering::apply() {
        eprintln!("ferro-desktop-ui: {error}");
        std::process::exit(2);
    }
    let web_mode = match parse_web_mode(std::env::args()) {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("ferro-desktop-ui: {error}");
            std::process::exit(2);
        }
    };
    if let Some(options) = web_mode {
        let dist = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist");
        if !dist.join("index.html").is_file() {
            eprintln!(
                "ferro-desktop-ui: frontend build missing at {}; run npm run build first",
                dist.display()
            );
            std::process::exit(2);
        }
        if options.insecure_bind {
            eprintln!("WARNING: --insecure-bind exposes container control to the network");
        }
        if let Err(error) = start_desktop_daemon() {
            eprintln!("ferro-desktop-ui: {error}");
            std::process::exit(1);
        }
        let runtime = tokio::runtime::Runtime::new().expect("create web bridge runtime");
        let result = runtime.block_on(web_bridge::run_web_bridge(options.listen, dist));
        stop_desktop_daemon();
        if let Err(error) = result {
            eprintln!("ferro-desktop-ui: {error}");
            std::process::exit(1);
        }
        return;
    }
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|_| {
            start_desktop_daemon().map_err(std::io::Error::other)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_desktop_snapshot,
            get_container_stats,
            get_volumes,
            get_networks,
            get_container_detail,
            get_compose_snapshot,
            build_image,
            run_desktop_action,
            run_compose_action,
            run_volume_action,
            run_network_action,
            update_container_resources,
            run_new_container,
            get_registry_auth_status,
            login_registry,
            logout_registry,
            start_log_follow,
            stop_log_follow,
            start_terminal,
            write_terminal,
            resize_terminal,
            close_terminal,
            get_paid_auth_state,
            save_paid_backend_config,
            set_paid_session_token,
            acquire_paid_session,
            clear_paid_session,
            run_paid_full_stack_install,
            run_doctor_action
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");
    app.run(|_, event| {
        if matches!(
            event,
            tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }
        ) {
            stop_desktop_daemon();
        }
    });
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read, Write};
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::{
        actionable_error, aggregate_container_stats, backend_command_request, build_bridge_command,
        clear_terminal_slot_if_matches, command_failure, compose_bridge_command,
        compose_service_rows, container_detail_from_json, container_inspect_command,
        container_update_command, doctor_command, doctor_with_backend_status,
        ferrocrate_proxy_command, log_channel, log_follow_command, network_proxy_command,
        network_summaries, normalize_nullable_list_output, parse_container_stats_json,
        parse_nullable_json_list, parse_terminal_exec_id, parse_web_mode, registry_login_command,
        registry_logout_command, run_backend_command, run_backend_command_with,
        run_container_bridge_command, start_image_build_stream_with, start_log_follow_stream_with,
        terminal_exec_command, terminal_resize_command, volume_proxy_command, BuildProgressFrame,
        CommandResult, ComposeAction, ComposeContainerRecord, ContainerNetworkRecord,
        ContainerPortRecord, JsonValue, LogBuffer, NativeContainerStats, NetworkAction,
        NetworkInspectRecord, NetworkIpam, NetworkIpamConfig, NetworkListRecord, TerminalProcess,
        TimedNativeContainerStats, VolumeAction, VolumeListResponse,
    };
    use ferro_desktop::backend::{
        Backend, BackendCapabilities, BackendError, BackendState, BackendStatus, DuplexStream,
        ExecRequest, ExecResponse, ExecStream, Platform, TerminalRequest, TerminalSession,
        TransportRequest, TransportResponse,
    };

    #[derive(Default)]
    struct RecordingBackend {
        requests: Mutex<Vec<(bool, ExecRequest)>>,
    }

    impl RecordingBackend {
        fn requests(&self) -> Vec<(bool, ExecRequest)> {
            self.requests.lock().expect("requests").clone()
        }
    }

    struct TestExecStream {
        stdout: Option<Cursor<Vec<u8>>>,
        stderr: Option<Cursor<Vec<u8>>>,
        stdin: Cursor<Vec<u8>>,
    }

    impl Default for TestExecStream {
        fn default() -> Self {
            Self {
                stdout: Some(Cursor::new(Vec::new())),
                stderr: Some(Cursor::new(Vec::new())),
                stdin: Cursor::new(Vec::new()),
            }
        }
    }

    impl Read for TestExecStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.stdout.as_mut().expect("stdout").read(buffer)
        }
    }

    impl Write for TestExecStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.stdin.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl ExecStream for TestExecStream {
        fn take_stdin(&mut self) -> Result<Box<dyn Write + Send>, BackendError> {
            Ok(Box::new(Cursor::new(Vec::new())))
        }

        fn take_stdout(&mut self) -> Result<Box<dyn Read + Send>, BackendError> {
            Ok(Box::new(self.stdout.take().expect("stdout")))
        }

        fn take_stderr(&mut self) -> Result<Box<dyn Read + Send>, BackendError> {
            Ok(Box::new(self.stderr.take().expect("stderr")))
        }

        fn close_stdin(&mut self) -> Result<(), BackendError> {
            Ok(())
        }

        fn kill(&mut self) -> Result<(), BackendError> {
            Ok(())
        }

        fn try_wait(&mut self) -> Result<Option<i32>, BackendError> {
            Ok(Some(0))
        }

        fn wait(&mut self) -> Result<i32, BackendError> {
            Ok(0)
        }
    }

    #[derive(Default)]
    struct TestDuplex(Cursor<Vec<u8>>);

    impl Read for TestDuplex {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl Write for TestDuplex {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }

    impl DuplexStream for TestDuplex {
        fn try_clone_stream(&self) -> Result<Box<dyn DuplexStream>, BackendError> {
            Ok(Box::new(Self::default()))
        }

        fn shutdown_write(&self) -> Result<(), BackendError> { Ok(()) }
    }

    impl Backend for RecordingBackend {
        fn name(&self) -> &'static str { "recording" }
        fn platform(&self) -> Platform { Platform::Linux }
        fn capabilities(&self) -> BackendCapabilities { BackendCapabilities::native() }
        fn start(&self) -> Result<BackendStatus, BackendError> { unimplemented!() }
        fn stop(&self) -> Result<BackendStatus, BackendError> { unimplemented!() }
        fn status(&self) -> BackendStatus { unimplemented!() }
        fn health(&self) -> Result<bool, BackendError> { Ok(true) }
        fn exec(&self, request: ExecRequest) -> Result<ExecResponse, BackendError> {
            self.requests.lock().expect("requests").push((false, request));
            Ok(ExecResponse { code: 0, stdout: Vec::new(), stderr: Vec::new() })
        }
        fn exec_stream(&self, request: ExecRequest) -> Result<Box<dyn ExecStream>, BackendError> {
            self.requests.lock().expect("requests").push((true, request));
            Ok(Box::new(TestExecStream::default()))
        }
        fn request(&self, _request: TransportRequest) -> Result<TransportResponse, BackendError> { unimplemented!() }
        fn open_terminal(&self, _request: TerminalRequest) -> Result<TerminalSession, BackendError> { unimplemented!() }
        fn resize_terminal(&self, _exec_id: &str, _columns: u16, _rows: u16) -> Result<(), BackendError> { unimplemented!() }
        fn socket_path(&self) -> Option<PathBuf> { None }
    }

    // On Windows this exec runs through the WSL2 backend, which is unavailable to the
    // CI runner service account. The WSL2 path is covered by the VM acceptance report.
    #[test]
    #[cfg(not(target_os = "windows"))]
    fn tauri_cli_consumer_routes_exec_through_backend() {
        let result = run_backend_command(
            "ferro-desktop",
            &[
                "exec".into(),
                "--".into(),
                "sh".into(),
                "-c".into(),
                "printf routed".into(),
            ],
            &[],
        );
        assert!(result.ok, "{}", result.stderr);
        assert_eq!(result.stdout, "routed");
    }

    #[test]
    fn tauri_streaming_and_registry_consumers_route_through_injected_backend() {
        let backend = RecordingBackend::default();
        let mut logs = start_log_follow_stream_with(&backend, "container-1").expect("logs");
        assert_eq!(logs.wait().expect("logs exit"), 0);
        let mut build = start_image_build_stream_with(&backend, ".", "demo:latest").expect("build");
        assert_eq!(build.wait().expect("build exit"), 0);
        let login = run_backend_command_with(
            &backend,
            "ferro-desktop",
            &registry_login_command("registry.example", "alice").expect("login args"),
            &[],
            b"secret\n".to_vec(),
        );
        assert!(login.ok);

        let requests = backend.requests();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].0);
        assert_eq!(requests[0].1.program, "ferrocrate");
        assert_eq!(requests[0].1.args, ["logs", "--follow", "container-1"]);
        assert!(requests[1].0);
        assert_eq!(requests[1].1.program, "ferrocrate");
        assert_eq!(requests[1].1.args.first().map(String::as_str), Some("build"));
        assert!(!requests[2].0);
        assert_eq!(requests[2].1.stdin, b"secret\n");
    }

    #[test]
    fn guest_proxy_builders_only_invoke_the_installed_ferrocrate_binary() {
        let commands = [
            registry_login_command("registry.example", "alice").expect("registry command"),
            volume_proxy_command(VolumeAction::Create, Some("data")).expect("volume command"),
            network_proxy_command(NetworkAction::Create, Some("frontend"), None)
                .expect("network command"),
        ];

        for args in commands {
            let request = backend_command_request("ferro-desktop", &args, &[], Vec::new())
                .expect("backend request");
            assert_eq!(request.program, "ferrocrate", "args={args:?}");
        }
    }

    #[test]
    fn terminal_eof_clears_only_the_matching_active_slot() {
        let slot = Mutex::new(Some(TerminalProcess {
            stream: Box::new(TestDuplex::default()),
            exec_id: "exec-1".to_string(),
        }));
        assert!(!clear_terminal_slot_if_matches(&slot, "different"));
        assert!(slot.lock().expect("slot").is_some());
        assert!(clear_terminal_slot_if_matches(&slot, "exec-1"));
        assert!(slot.lock().expect("slot").is_none());
    }

    #[test]
    fn daemon_status_preserves_backend_health_and_state() {
        let status = super::daemon_status_from_backend(BackendStatus {
            backend: "wsl2".into(),
            platform: Platform::Windows,
            state: BackendState::Failed,
            healthy: false,
            endpoint: "http://127.0.0.1:4288".into(),
            reason: Some("backend health check failed".into()),
            capabilities: BackendCapabilities::native(),
        });

        assert_eq!(status.state, "failed");
        assert!(!status.healthy);
        assert_eq!(status.platform, "wsl2");
    }

    #[test]
    fn doctor_backend_failure_is_a_visible_unhealthy_check() {
        let payload = doctor_with_backend_status(
            serde_json::json!({ "healthy": true, "checks": [] }),
            BackendStatus {
                backend: "wsl2".into(),
                platform: Platform::Windows,
                state: BackendState::Failed,
                healthy: false,
                endpoint: "127.0.0.1:4288".into(),
                reason: Some("relay unavailable".into()),
                capabilities: BackendCapabilities::native(),
            },
        );
        assert_eq!(payload["healthy"], false);
        assert_eq!(payload["desktop_backend"]["backend"], "wsl2");
        assert_eq!(payload["desktop_backend"]["healthy"], false);
        assert_eq!(payload["desktop_backend"]["reason"], "relay unavailable");
        assert_eq!(payload["desktop_backend"]["capabilities"]["networks"], true);
        assert_eq!(payload["checks"].as_array().expect("checks").len(), 1);
        assert_eq!(payload["checks"][0]["id"], "desktop_backend");
        assert_eq!(payload["checks"][0]["ok"], false);
        assert!(payload["checks"][0]["message"]
            .as_str()
            .expect("backend message")
            .contains("relay unavailable"));
    }

    #[test]
    fn container_stats_aggregate_usage_limit_and_unavailable_samples() {
        let base = std::time::Instant::now();
        let stats = |memory_current, cpu_usage_usec| NativeContainerStats {
            memory_current: Some(memory_current),
            memory_max: Some(256),
            cpu_usage_usec: Some(cpu_usage_usec),
        };
        let first = BTreeMap::from([
            (
                "demo".to_string(),
                TimedNativeContainerStats {
                    sampled_at: base,
                    stats: stats(64, 1_000),
                },
            ),
            (
                "slow".to_string(),
                TimedNativeContainerStats {
                    sampled_at: base,
                    stats: stats(64, 1_000),
                },
            ),
        ]);
        let second = BTreeMap::from([
            (
                "demo".to_string(),
                TimedNativeContainerStats {
                    sampled_at: base + std::time::Duration::from_micros(1_000),
                    stats: stats(96, 1_250),
                },
            ),
            (
                "slow".to_string(),
                TimedNativeContainerStats {
                    sampled_at: base + std::time::Duration::from_micros(2_000),
                    stats: stats(96, 1_250),
                },
            ),
        ]);
        let samples = aggregate_container_stats(
            &[
                "demo".to_string(),
                "slow".to_string(),
                "missing".to_string(),
            ],
            &first,
            &second,
        );

        assert_eq!(samples[0].id, "demo");
        assert!(samples[0].available);
        assert_eq!(samples[0].memory_usage, Some(96));
        assert_eq!(samples[0].memory_limit, Some(256));
        assert_eq!(samples[0].cpu_percent, Some(25.0));
        assert_eq!(samples[1].cpu_percent, Some(12.5));
        assert_eq!(samples[2].id, "missing");
        assert!(!samples[2].available);

        let empty_stats = NativeContainerStats::default();
        let empty_first = BTreeMap::from([(
            "no-cgroup".to_string(),
            TimedNativeContainerStats {
                sampled_at: base,
                stats: empty_stats.clone(),
            },
        )]);
        let empty_second = BTreeMap::from([(
            "no-cgroup".to_string(),
            TimedNativeContainerStats {
                sampled_at: base + std::time::Duration::from_millis(100),
                stats: empty_stats,
            },
        )]);
        let empty_samples =
            aggregate_container_stats(&["no-cgroup".to_string()], &empty_first, &empty_second);
        assert!(!empty_samples[0].available);
    }

    #[test]
    fn delegated_docker_stats_decode_to_native_counter_units() {
        let stats = parse_container_stats_json(
            r#"{
            "memory_stats":{"usage":67108864,"limit":134217728},
            "cpu_stats":{"cpu_usage":{"total_usage":1250000}}
        }"#,
        )
        .expect("Docker stats payload");
        assert_eq!(stats.memory_current, Some(67_108_864));
        assert_eq!(stats.memory_max, Some(134_217_728));
        assert_eq!(stats.cpu_usage_usec, Some(1_250));

        let unlimited = parse_container_stats_json(
            r#"{
            "memory_stats":{"usage":1,"limit":0},
            "cpu_stats":{"cpu_usage":{"total_usage":1000}}
        }"#,
        )
        .expect("Docker unlimited stats payload");
        assert_eq!(unlimited.memory_max, None);
    }

    #[cfg(target_os = "linux")]
    use super::{
        daemon_capabilities_from_info_response, daemon_health_response_ok,
        desktop_daemon_transport_ready, running_daemon_status, unavailable_daemon_state,
    };

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_health_accepts_the_real_newline_terminated_ping_body() {
        assert!(daemon_health_response_ok(
            "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nOK\n"
        ));
        assert!(!daemon_health_response_ok(
            "HTTP/1.1 500 Internal Server Error\r\n\r\nOK\n"
        ));
        assert_eq!(
            unavailable_daemon_state(true, false, None),
            ("starting", None)
        );
        assert_eq!(
            unavailable_daemon_state(false, false, Some("exit status 1")),
            ("failed", Some("exit status 1".to_string()))
        );
        assert_eq!(
            unavailable_daemon_state(false, false, None),
            ("stopped", None)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn daemon_info_propagates_custom_network_capability() {
        let rootless = daemon_capabilities_from_info_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"SecurityOptions\":[\"name=rootless\"],\"FerrocrateCapabilities\":{\"CustomNetworks\":false}}",
        )
        .expect("rootless info");
        assert!(!rootless.custom_networks);
        let status = running_daemon_status("/run/user/1000/ferrocrate.sock", rootless);
        assert_eq!(
            serde_json::to_value(status).expect("daemon status")["custom_networks"],
            false
        );

        let rootful = daemon_capabilities_from_info_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"SecurityOptions\":[],\"FerrocrateCapabilities\":{\"CustomNetworks\":true}}",
        )
        .expect("rootful info");
        assert!(rootful.custom_networks);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_daemon_info_without_capability_evidence_fails_closed() {
        let legacy = daemon_capabilities_from_info_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
        )
        .expect("legacy info response");

        assert!(!legacy.custom_networks);

        let standard_rootless = daemon_capabilities_from_info_response(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"SecurityOptions\":[\"name=rootless\"]}",
        )
        .expect("standard rootless info response");
        assert!(!standard_rootless.custom_networks);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_daemon_readiness_depends_on_the_unix_socket_not_legacy_tcp() {
        assert!(desktop_daemon_transport_ready(false, true));
        assert!(!desktop_daemon_transport_ready(true, false));
    }

    #[test]
    fn web_mode_defaults_to_loopback_and_rejects_remote_bind_without_override() {
        let options = parse_web_mode(["ferro-desktop-ui", "--web"]).expect("web mode");
        assert_eq!(
            options.expect("web options").listen.to_string(),
            "127.0.0.1:4190"
        );

        let error = parse_web_mode(["ferro-desktop-ui", "--web", "--listen", "0.0.0.0:4190"])
            .expect_err("remote bind must be refused");
        assert!(error.contains("--insecure-bind"));

        let options = parse_web_mode([
            "ferro-desktop-ui",
            "--web",
            "--listen",
            "0.0.0.0:4190",
            "--insecure-bind",
        ])
        .expect("explicit remote bind")
        .expect("web options");
        assert_eq!(options.listen.to_string(), "0.0.0.0:4190");
    }

    #[test]
    fn image_build_uses_selected_context_through_desktop_bridge() {
        let dockerfile = PathBuf::from("/tmp/build context")
            .join("Dockerfile")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            build_bridge_command("/tmp/build context", "demo/app:dev").expect("build command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "build",
                "--dockerfile",
                dockerfile.as_str(),
                "--tag",
                "demo/app:dev",
            ]
        );
        assert!(build_bridge_command(" ", "demo:latest").is_err());
        assert!(build_bridge_command("/tmp/context", " ").is_err());
    }

    #[test]
    fn build_progress_payload_identifies_its_originating_build() {
        let payload = serde_json::to_value(BuildProgressFrame {
            build_id: "build-27".to_string(),
            stream: "stdout".to_string(),
            text: "Step 1/2 : FROM alpine".to_string(),
        })
        .expect("build progress serializes");

        assert_eq!(payload["build_id"], "build-27");
        assert_eq!(payload["stream"], "stdout");
    }

    #[test]
    fn compose_actions_use_the_desktop_exec_bridge() {
        assert_eq!(
            compose_bridge_command("/tmp/real app/compose.yml", ComposeAction::Config)
                .expect("config command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "compose",
                "--file",
                "/tmp/real app/compose.yml",
                "config",
            ]
        );
        assert_eq!(
            compose_bridge_command("/tmp/compose.yml", ComposeAction::Up).expect("up command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "compose",
                "--file",
                "/tmp/compose.yml",
                "up",
                "--detach",
            ]
        );
        assert!(compose_bridge_command("  ", ComposeAction::Down).is_err());
    }

    #[test]
    fn compose_service_rows_reflect_matching_container_state() {
        let containers: Vec<ComposeContainerRecord> = serde_json::from_str(concat!(
            "[{\"Id\":\"api-id\",\"Names\":[\"/shop-api-1\"],\"State\":\"running\",",
            "\"Labels\":{\"com.docker.compose.project\":\"shop\",\"com.docker.compose.service\":\"api\"}},",
            "{\"Id\":\"worker-id\",\"Names\":[\"/worker-1\"],\"State\":\"exited\",\"Labels\":{}}]"
        ))
        .expect("Docker container list records");
        let rows = compose_service_rows(
            vec!["worker".to_string(), "db".to_string(), "api".to_string()],
            &containers,
        );
        assert_eq!(rows[0].name, "api");
        assert_eq!(rows[0].status, "running");
        assert_eq!(rows[1].name, "db");
        assert_eq!(rows[1].status, "not_created");
        assert_eq!(rows[2].name, "worker");
        assert_eq!(rows[2].container_id.as_deref(), Some("worker-id"));
    }

    #[test]
    fn log_follow_uses_the_desktop_exec_bridge() {
        assert_eq!(
            log_follow_command("web"),
            vec![
                "exec",
                "--follow",
                "--",
                "ferrocrate",
                "logs",
                "--follow",
                "web",
            ]
        );
    }

    #[test]
    fn log_buffer_keeps_recent_entries_with_a_truncation_marker() {
        let mut buffer = LogBuffer::new(2, 1024);
        buffer.push("first\n".to_string());
        buffer.push("second\n".to_string());
        buffer.push("third\n".to_string());

        assert_eq!(
            buffer.text(),
            "[Earlier log output truncated]\nsecond\nthird\n"
        );
    }

    #[test]
    fn log_channel_applies_backpressure_at_its_capacity() {
        let (sender, receiver) = log_channel(1);
        sender
            .send("first\n".to_string())
            .expect("first entry fits");
        assert!(sender.try_send("second\n".to_string()).is_err());
        assert_eq!(receiver.recv().expect("first entry"), "first\n");
        sender.send("second\n".to_string()).expect("capacity freed");
    }

    #[test]
    fn terminal_exec_uses_typed_daemon_proxy_and_exec_options() {
        assert_eq!(
            terminal_exec_command(
                "web",
                "sh",
                &["TERM=xterm-256color".to_string()],
                Some("1000:1000"),
                Some("/workspace"),
            ),
            vec![
                "terminal-proxy",
                "--container",
                "web",
                "--env",
                "TERM=xterm-256color",
                "--user",
                "1000:1000",
                "--workdir",
                "/workspace",
                "--",
                "sh",
            ]
        );
    }

    #[test]
    fn terminal_exec_id_requires_proxy_handshake_prefix() {
        assert_eq!(
            parse_terminal_exec_id("FERROCRATE_EXEC_ID=exec-123\n").expect("exec id"),
            "exec-123"
        );
        assert!(parse_terminal_exec_id("error: daemon unavailable\n")
            .expect_err("missing handshake")
            .contains("daemon unavailable"));
        assert!(parse_terminal_exec_id("FERROCRATE_EXEC_ID=\n").is_err());
    }

    #[test]
    fn terminal_resize_uses_typed_daemon_proxy() {
        assert_eq!(
            terminal_resize_command("exec/123", 100, 40),
            vec![
                "terminal-resize",
                "--exec-id",
                "exec/123",
                "--columns",
                "100",
                "--rows",
                "40",
            ]
        );
    }

    #[test]
    fn command_failure_surfaces_only_actionable_restart_error() {
        let stderr = concat!(
            "\x1b[2m2026-08-24T17:09:02Z\x1b[0m ",
            "\x1b[33m WARN\x1b[0m ferro_core::runtime: pending cleanup journal ",
            "/run/ferrocrate/containers/demo/network-cleanup-pending.json retained in quarantine\n",
            "restart: demo: io error: Permission denied\n",
            "\x1b[31mERROR\x1b[0m ferro_cli: restart: 1 container operation(s) failed\n",
            "error: restart: 1 container operation(s) failed\n",
            "Error: Invalid(\"remote command exited with status 1\")\n",
        );
        let result = CommandResult {
            ok: false,
            code: 1,
            stdout: String::new(),
            stderr: stderr.to_string(),
            message: actionable_error(stderr),
        };

        assert_eq!(
            command_failure("container restart", &result),
            "restart: demo: io error: Permission denied"
        );
    }

    #[test]
    fn doctor_options_use_the_real_cli_flags() {
        assert_eq!(
            doctor_command(true, true, false, true),
            vec!["doctor", "--json", "--fix", "--bootstrap", "--confirm"]
        );
    }

    #[test]
    fn stopped_container_start_runs_through_the_daemon_bridge() {
        assert_eq!(
            ferrocrate_proxy_command(&["start", "demo"]),
            vec!["exec", "--", "ferrocrate", "start", "demo"]
        );
    }

    #[test]
    fn volume_operations_use_the_installed_cli_exec_bridge() {
        assert_eq!(
            volume_proxy_command(VolumeAction::List, None).expect("list command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "volume",
                "ls",
                "--format",
                "json",
            ]
        );
        assert_eq!(
            volume_proxy_command(VolumeAction::Create, Some("data")).expect("create command"),
            vec!["exec", "--", "ferrocrate", "volume", "create", "data"]
        );
        assert_eq!(
            volume_proxy_command(VolumeAction::Remove, Some("data")).expect("remove command"),
            vec!["exec", "--", "ferrocrate", "volume", "rm", "data"]
        );
        assert_eq!(
            volume_proxy_command(VolumeAction::Prune, None).expect("prune command"),
            vec!["exec", "--", "ferrocrate", "volume", "prune"]
        );
        assert!(volume_proxy_command(VolumeAction::Create, Some("  ")).is_err());
    }

    #[test]
    fn volume_list_accepts_exact_legacy_null_payload_as_empty() {
        let response: VolumeListResponse =
            serde_json::from_str(r#"{"Volumes":null,"Warnings":[]}"#)
                .expect("legacy daemon null volume list");

        assert!(response.volumes.is_empty());
    }

    #[test]
    fn top_level_legacy_null_lists_decode_and_normalize_as_empty_arrays() {
        let records = parse_nullable_json_list::<JsonValue>("null")
            .expect("legacy daemon null top-level list");
        assert!(records.is_empty());

        let mut result = CommandResult {
            ok: true,
            code: 0,
            stdout: "null\n".to_string(),
            stderr: String::new(),
            message: String::new(),
        };
        normalize_nullable_list_output(&mut result);

        assert_eq!(result.stdout, "[]");
    }

    #[test]
    fn network_operations_use_the_installed_cli_exec_bridge() {
        assert_eq!(
            network_proxy_command(NetworkAction::List, None, None).expect("list command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "network",
                "ls",
                "--format",
                "json",
            ]
        );
        assert_eq!(
            network_proxy_command(NetworkAction::Inspect, Some("frontend"), None)
                .expect("inspect command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "network",
                "inspect",
                "frontend",
                "--format",
                "json",
            ]
        );
        assert_eq!(
            network_proxy_command(
                NetworkAction::Create,
                Some("frontend"),
                Some("172.30.0.0/16")
            )
            .expect("create command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "network",
                "create",
                "frontend",
                "--subnet",
                "172.30.0.0/16",
            ]
        );
        assert_eq!(
            network_proxy_command(NetworkAction::Remove, Some("frontend"), None)
                .expect("remove command"),
            vec!["exec", "--", "ferrocrate", "network", "rm", "frontend"]
        );
        assert!(network_proxy_command(NetworkAction::Create, Some(" "), None).is_err());
    }

    #[test]
    fn container_detail_uses_native_json_through_exec_bridge() {
        assert_eq!(
            container_inspect_command("web").expect("inspect command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "inspect",
                "web",
                "--format",
                "json",
            ]
        );

        let detail = container_detail_from_json(serde_json::json!({
            "id": "container-1",
            "name": "web",
            "image": "alpine:latest",
            "status": "running",
            "command": ["sleep", "60"],
            "env": ["MODE=test"],
            "workdir": "/workspace",
            "user": "1000:1000",
            "mounts": [{
                "source": "/var/lib/data",
                "target": "data",
                "read_only": true
            }],
            "health": null,
            "health_status": "none",
            "health_failures": 0,
            "health_log": [],
            "resource_limits": {
                "memory_max": 1024,
                "cpu_quota": 50000,
                "cpu_period": 100000,
                "pids_max": null
            },
            "restart_policy": "on-failure:3"
        }))
        .expect("native inspect projection");

        assert_eq!(detail.id, "container-1");
        assert_eq!(detail.name, "web");
        assert_eq!(detail.mounts[0].destination, "/data");
        assert_eq!(detail.mounts[0].access, "ro");
        assert_eq!(detail.resources.memory, 1024);
        assert_eq!(detail.restart_policy.name, "on-failure");
        assert_eq!(detail.restart_policy.maximum_retry_count, 3);
    }

    #[test]
    fn network_projection_includes_addresses_and_container_ports() {
        let list = vec![NetworkListRecord {
            name: "frontend".to_string(),
            driver: "bridge".to_string(),
            ipam: NetworkIpam {
                config: vec![NetworkIpamConfig {
                    subnet: Some("172.30.0.0/16".to_string()),
                }],
            },
        }];
        let inspection: NetworkInspectRecord = serde_json::from_str(
            r#"{"Containers":{"container-1":{"Name":"/web","IPv4Address":"172.30.0.2","IPv6Address":""}}}"#,
        )
        .expect("daemon network inspect fixture");
        let inspections = BTreeMap::from([("frontend".to_string(), inspection)]);
        let containers = vec![ContainerNetworkRecord {
            id: "container-1".to_string(),
            names: vec!["/web".to_string()],
            ports: vec![ContainerPortRecord {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            }],
        }];

        let rows = network_summaries(list, &inspections, &containers);
        assert_eq!(rows[0].subnets, vec!["172.30.0.0/16"]);
        assert_eq!(rows[0].containers[0].name, "web");
        assert_eq!(rows[0].containers[0].ipv4_address, "172.30.0.2");
        assert_eq!(rows[0].containers[0].ports, vec!["0.0.0.0:8080→80/tcp"]);
    }

    #[test]
    fn network_projection_uses_inspect_ipam_when_docker_list_omits_it() {
        let list: Vec<NetworkListRecord> = serde_json::from_str(
            r#"[{"Id":"bridge","Name":"bridge","Driver":"bridge","Scope":"local"}]"#,
        )
        .expect("Docker network list");
        let inspection: NetworkInspectRecord = serde_json::from_str(
            r#"{"Name":"bridge","Driver":"bridge","IPAM":{"Config":[{"Subnet":"10.0.0.0/24","Gateway":"10.0.0.1"}]},"Containers":{}}"#,
        )
        .expect("Docker network inspect");
        let rows = network_summaries(
            list,
            &BTreeMap::from([("bridge".to_string(), inspection)]),
            &[],
        );
        assert_eq!(rows[0].subnets, vec!["10.0.0.0/24"]);
    }

    #[test]
    fn docker_container_list_fixture_decodes_for_compose_and_network_projections() {
        let fixture = include_str!("../../src/fixtures/ferrocrate-containers.json");
        let compose = parse_nullable_json_list::<ComposeContainerRecord>(fixture)
            .expect("compose Docker list fixture");
        let rows = compose_service_rows(vec!["web".to_string()], &compose);
        assert_eq!(rows[0].container_id.as_deref(), Some("abc123"));
        assert_eq!(rows[0].status, "running");

        let containers = parse_nullable_json_list::<ContainerNetworkRecord>(fixture)
            .expect("network Docker list fixture");
        assert_eq!(containers[0].id, "abc123");
        assert_eq!(containers[0].name().as_deref(), Some("web-frontend"));
        assert_eq!(containers[0].ports[0].host_port, 8080);
        assert_eq!(containers[0].ports[0].container_port, 80);
        assert_eq!(containers[0].ports[0].protocol, "tcp");
    }

    #[test]
    fn container_detail_projects_inspect_configuration_and_health_history() {
        let detail = container_detail_from_json(serde_json::json!({
            "Id": "container-1",
            "Name": "/web",
            "Image": "alpine:latest",
            "Config": {"Env": ["TOKEN=secret", "MODE=dev"], "Cmd": ["sh"], "WorkingDir": "/app", "User": "1000"},
            "Mounts": [{"Type": "volume", "Source": "/data", "Destination": "/app/data", "RW": false}],
            "HostConfig": {
                "Memory": 134217728,
                "CpuQuota": 50000,
                "CpuPeriod": 100000,
                "RestartPolicy": {"Name": "always", "MaximumRetryCount": 0}
            },
            "State": {"Status": "running", "Health": {"Status": "healthy", "FailingStreak": 0, "Log": [
                {"Start": "start", "End": "end", "ExitCode": 0, "Output": "ok"}
            ]}}
        }))
        .expect("detail projection");
        assert_eq!(detail.name, "web");
        assert_eq!(detail.environment, vec!["TOKEN=secret", "MODE=dev"]);
        assert_eq!(detail.mounts[0].access, "ro");
        assert_eq!(detail.health.expect("health").log[0].output, "ok");
        assert_eq!(detail.resources.memory, 134_217_728);
        assert_eq!(detail.restart_policy.name, "always");
    }

    #[test]
    fn container_detail_commands_preserve_resource_and_new_container_options() {
        assert_eq!(
            container_inspect_command("web").expect("inspect command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "inspect",
                "web",
                "--format",
                "json",
            ]
        );
        assert_eq!(
            container_update_command("web", Some(134_217_728), Some(50_000), Some(100_000))
                .expect("update command"),
            vec![
                "container-proxy",
                "update",
                "web",
                "--memory",
                "134217728",
                "--cpu-quota",
                "50000",
                "--cpu-period",
                "100000",
            ]
        );
        assert_eq!(
            run_container_bridge_command(
                "alpine:latest",
                Some("sentinel-worker"),
                &["printf".to_string(), "sentinel-command".to_string()],
                &["8080:80".to_string()],
                &["data:/data".to_string()],
                &["MODE=dev".to_string(), "TOKEN=secret".to_string()],
                Some(67_108_864),
                Some(25_000),
                Some(100_000),
            )
            .expect("run command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "run",
                "--detach",
                "--name",
                "sentinel-worker",
                "--publish",
                "8080:80",
                "--volume",
                "data:/data",
                "--env",
                "MODE=dev",
                "--env",
                "TOKEN=secret",
                "--memory-max",
                "67108864",
                "--cpu-quota",
                "25000",
                "--cpu-period",
                "100000",
                "alpine:latest",
                "printf",
                "sentinel-command",
            ]
        );
    }

    #[test]
    fn registry_auth_commands_keep_password_out_of_process_arguments() {
        assert_eq!(
            registry_login_command("registry.example.com", "alice").expect("login command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "login",
                "registry.example.com",
                "--username",
                "alice",
                "--password-stdin",
            ]
        );
        assert_eq!(
            registry_logout_command("registry.example.com").expect("logout command"),
            vec!["exec", "--", "ferrocrate", "logout", "registry.example.com",]
        );
        assert!(registry_login_command("registry.example.com", " ").is_err());
        assert!(registry_logout_command(" ").is_err());
    }
}
