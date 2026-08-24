#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::Emitter;

const KEYRING_SERVICE: &str = "ferrocrate-desktop-ui";
const KEYRING_ACCOUNT: &str = "paid_session_token";
const LOG_TRUNCATION_MARKER: &str = "[Earlier log output truncated]\n";
const MAX_LOG_LINES: usize = 2_000;
const MAX_LOG_BYTES: usize = 512 * 1024;
const LOG_CHANNEL_CAPACITY: usize = 128;
static LOG_FOLLOW_PROCESS: Mutex<Option<Child>> = Mutex::new(None);
static TERMINAL_PROCESS: Mutex<Option<TerminalProcess>> = Mutex::new(None);

struct TerminalProcess {
    child: Child,
    stdin: ChildStdin,
    exec_id: String,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct DesktopSnapshot {
    runtime: CommandResult,
    containers: CommandResult,
    images: CommandResult,
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

#[derive(Debug, Serialize)]
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
    #[serde(rename(deserialize = "FerrocrateMounts", serialize = "mounts"), default)]
    mounts: Vec<VolumeMountUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct VolumeListResponse {
    volumes: Vec<VolumeSummary>,
}

fn volume_proxy_command(
    action: VolumeAction,
    target: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut command = vec!["volume-proxy".to_string()];
    match action {
        VolumeAction::List => command.push("list".to_string()),
        VolumeAction::Prune => command.push("prune".to_string()),
        VolumeAction::Create | VolumeAction::Remove => {
            let target = target
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "volume name is required".to_string())?;
            command.push(match action {
                VolumeAction::Create => "create".to_string(),
                VolumeAction::Remove => "remove".to_string(),
                _ => unreachable!(),
            });
            command.push(target.to_string());
        }
    }
    Ok(command)
}

fn execute_volume_proxy(action: VolumeAction, target: Option<&str>) -> Result<CommandResult, String> {
    let args = volume_proxy_command(action, target)?;
    let output = Command::new("ferro-desktop")
        .args(&args)
        .output()
        .map_err(|error| format!("failed to run volume proxy: {error}"))?;
    Ok(CommandResult {
        ok: output.status.success(),
        code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn run_command(binary: &str, args: &[&str]) -> CommandResult {
    match Command::new(binary).args(args).output() {
        Ok(output) => CommandResult {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Err(err) => CommandResult {
            ok: false,
            code: 127,
            stdout: String::new(),
            stderr: format!("failed to run `{binary}`: {err}"),
        },
    }
}

fn run_command_env(binary: &str, args: &[&str], envs: &[(&str, String)]) -> CommandResult {
    let mut command = Command::new(binary);
    command.args(args);
    for (k, v) in envs {
        command.env(k, v);
    }
    match command.output() {
        Ok(output) => CommandResult {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Err(err) => CommandResult {
            ok: false,
            code: 127,
            stdout: String::new(),
            stderr: format!("failed to run `{binary}`: {err}"),
        },
    }
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

fn emit_terminal_output<R: Read>(mut reader: R, app: tauri::AppHandle, stderr: bool) {
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes = match reader.read(&mut buffer) {
            Ok(0) => return,
            Ok(bytes) => bytes,
            Err(err) => {
                let _ = app.emit("terminal-error", err.to_string());
                return;
            }
        };
        let _ = app.emit(
            "terminal-output",
            TerminalOutput {
                data: buffer[..bytes].to_vec(),
                stderr,
            },
        );
    }
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
    if let Some(process) = current.as_mut() {
        if process
            .child
            .try_wait()
            .map_err(|err| format!("failed to inspect terminal process: {err}"))?
            .is_none()
        {
            return Err("an exec terminal is already active".to_string());
        }
    }
    *current = None;

    let mut child = Command::new("ferro-desktop")
        .args(terminal_exec_command(
            target,
            shell,
            &env,
            user.as_deref(),
            workdir.as_deref(),
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to start exec terminal: {err}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "exec terminal stdin missing".to_string())?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "exec terminal stdout missing".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "exec terminal stderr missing".to_string())?;
    let mut stderr = BufReader::new(stderr);
    let mut handshake = String::new();
    stderr
        .read_line(&mut handshake)
        .map_err(|err| format!("failed to read terminal proxy handshake: {err}"))?;
    let exec_id = match parse_terminal_exec_id(&handshake) {
        Ok(exec_id) => exec_id,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("failed to start exec terminal: {err}"));
        }
    };
    let stdout_app = app.clone();
    thread::spawn(move || emit_terminal_output(stdout, stdout_app, false));
    let stderr_app = app.clone();
    thread::spawn(move || emit_terminal_output(stderr, stderr_app, true));
    *current = Some(TerminalProcess {
        child,
        stdin,
        exec_id,
    });
    drop(current);

    thread::spawn(move || loop {
        let status = {
            let mut process = match TERMINAL_PROCESS.lock() {
                Ok(process) => process,
                Err(_) => return,
            };
            let Some(terminal) = process.as_mut() else {
                return;
            };
            match terminal.child.try_wait() {
                Ok(Some(status)) => {
                    *process = None;
                    Some(status)
                }
                Ok(None) => None,
                Err(err) => {
                    let _ = app.emit("terminal-error", err.to_string());
                    *process = None;
                    return;
                }
            }
        };
        if let Some(status) = status {
            let _ = app.emit("terminal-ended", status.success());
            return;
        }
        thread::sleep(Duration::from_millis(50));
    });
    Ok(())
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
        .stdin
        .write_all(&data)
        .and_then(|_| process.stdin.flush())
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
    let output = Command::new("ferro-desktop")
        .args(terminal_resize_command(&exec_id, columns, rows))
        .output()
        .map_err(|err| format!("failed to resize exec terminal: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if message.is_empty() {
        format!(
            "failed to resize exec terminal: status {}",
            output.status.code().unwrap_or(-1)
        )
    } else {
        message
    })
}

#[tauri::command]
fn close_terminal() -> Result<(), String> {
    let mut current = TERMINAL_PROCESS
        .lock()
        .map_err(|_| "terminal state is unavailable".to_string())?;
    if let Some(mut process) = current.take() {
        process
            .child
            .kill()
            .map_err(|err| format!("failed to detach exec terminal: {err}"))?;
        process
            .child
            .wait()
            .map_err(|err| format!("failed to reap exec terminal: {err}"))?;
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

fn emit_log_batch(app: &tauri::AppHandle, buffer: &LogBuffer) {
    let _ = app.emit(
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

fn publish_log_batches(app: tauri::AppHandle, receiver: Receiver<String>) {
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
                    emit_log_batch(&app, &buffer);
                    changed = false;
                    last_publish = Instant::now();
                }
            }
            Err(RecvTimeoutError::Timeout) if changed => {
                emit_log_batch(&app, &buffer);
                changed = false;
                last_publish = Instant::now();
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if changed {
                    emit_log_batch(&app, &buffer);
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

fn emit_log_errors<R: std::io::Read>(reader: R, app: tauri::AppHandle) {
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    while let Ok(bytes) = reader.read_line(&mut line) {
        if bytes == 0 {
            break;
        }
        let _ = app.emit("container-log-error", line.clone());
        line.clear();
    }
}

#[tauri::command]
fn start_log_follow(app: tauri::AppHandle, target: String) -> Result<(), String> {
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

    let mut child = Command::new("ferro-desktop")
        .args(log_follow_command(target))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to start container log stream: {err}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "container log stream stdout missing".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "container log stream stderr missing".to_string())?;
    let (log_sender, log_receiver) = log_channel(LOG_CHANNEL_CAPACITY);
    let stdout_app = app.clone();
    thread::spawn(move || publish_log_batches(stdout_app, log_receiver));
    thread::spawn(move || queue_log_lines(stdout, log_sender));
    let stderr_app = app.clone();
    thread::spawn(move || emit_log_errors(stderr, stderr_app));
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
                    let _ = app.emit("container-log-error", err.to_string());
                    *process = None;
                    return;
                }
            }
        };
        if let Some(status) = status {
            let _ = app.emit("container-log-ended", status.success());
            return;
        }
        thread::sleep(Duration::from_millis(250));
    });
    Ok(())
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
    let runtime = run_command("ferro-desktop", &["vm", "status", "--json"]);
    let containers = run_command("ferrocrate", &["ps"]);
    let images = run_command("ferrocrate", &["images"]);

    DesktopSnapshot {
        runtime,
        containers,
        images,
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
fn run_volume_action(action: VolumeAction, target: Option<String>) -> Result<CommandResult, String> {
    if matches!(action, VolumeAction::List) {
        return Err("list is a read-only snapshot action".to_string());
    }
    execute_volume_proxy(action, target.as_deref())
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
        args.push("--yes");
    }
    let result = run_command("ferrocrate", &args);
    let payload = serde_json::from_str::<JsonValue>(&result.stdout).unwrap_or_else(|_| {
        serde_json::json!({
            "healthy": false,
            "error": "invalid doctor json output",
            "stdout": result.stdout,
            "stderr": result.stderr
        })
    });
    Ok(DoctorSummary {
        ok: result.ok,
        raw: payload,
    })
}

#[tauri::command]
fn run_desktop_action(action: DesktopAction, target: Option<String>) -> CommandResult {
    let target = target.unwrap_or_default().trim().to_string();
    match action {
        DesktopAction::VmStart => run_command("ferro-desktop", &["vm", "start"]),
        DesktopAction::VmStop => run_command("ferro-desktop", &["vm", "stop"]),
        DesktopAction::PullImage => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target image is required".to_string(),
                };
            }
            run_command("ferrocrate", &["pull", &target])
        }
        DesktopAction::RemoveImage => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target image is required".to_string(),
                };
            }
            run_command("ferrocrate", &["rmi", &target])
        }
        DesktopAction::StartContainer => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target container is required".to_string(),
                };
            }
            run_command("ferrocrate", &["restart", &target])
        }
        DesktopAction::StopContainer => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target container is required".to_string(),
                };
            }
            run_command("ferrocrate", &["stop", &target])
        }
        DesktopAction::RemoveContainer => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target container is required".to_string(),
                };
            }
            run_command("ferrocrate", &["rm", &target])
        }
        DesktopAction::ImagePrune => run_command("ferrocrate", &["image-prune"]),
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_desktop_snapshot,
            get_volumes,
            run_desktop_action,
            run_volume_action,
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::{
        log_channel, log_follow_command, parse_terminal_exec_id, terminal_exec_command,
        terminal_resize_command, volume_proxy_command, LogBuffer, VolumeAction,
    };

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
    fn volume_actions_use_typed_desktop_proxy_commands() {
        assert_eq!(
            volume_proxy_command(VolumeAction::List, None).expect("list command"),
            vec!["volume-proxy", "list"]
        );
        assert_eq!(
            volume_proxy_command(VolumeAction::Create, Some("data")).expect("create command"),
            vec!["volume-proxy", "create", "data"]
        );
        assert_eq!(
            volume_proxy_command(VolumeAction::Remove, Some("data")).expect("remove command"),
            vec!["volume-proxy", "remove", "data"]
        );
        assert_eq!(
            volume_proxy_command(VolumeAction::Prune, None).expect("prune command"),
            vec!["volume-proxy", "prune"]
        );
        assert!(volume_proxy_command(VolumeAction::Create, Some("  ")).is_err());
    }
}
