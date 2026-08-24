#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{BTreeMap, VecDeque};
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
    runtime: CommandResult,
    containers: CommandResult,
    images: CommandResult,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct NativeContainerStats {
    memory_current: Option<u64>,
    cpu_usage_usec: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct NativeStatsOutput {
    stats: NativeContainerStats,
}

#[derive(Debug, Clone, Default)]
struct ContainerResourceUsage {
    memory_usage: Option<u64>,
    cpu_percent: Option<f64>,
}

fn container_stats_command(target: &str) -> Vec<String> {
    ferrocrate_proxy_command(&["stats", target, "--format", "json"])
}

fn read_container_stats(target: &str) -> Option<NativeContainerStats> {
    let result = run_owned_command("ferro-desktop", &container_stats_command(target));
    result
        .ok
        .then(|| serde_json::from_str::<NativeStatsOutput>(&result.stdout).ok())
        .flatten()
        .map(|output| output.stats)
}

fn collect_container_resource_usage(ids: &[String]) -> BTreeMap<String, ContainerResourceUsage> {
    let first = ids
        .iter()
        .filter_map(|id| {
            read_container_stats(id).map(|stats| (id.clone(), (Instant::now(), stats)))
        })
        .collect::<BTreeMap<_, _>>();
    if first.is_empty() {
        return BTreeMap::new();
    }
    thread::sleep(Duration::from_millis(100));
    ids.iter()
        .filter_map(|id| {
            let (started, previous) = first.get(id)?;
            let current = read_container_stats(id)?;
            let elapsed_usec = started.elapsed().as_micros() as f64;
            let cpu_percent = previous
                .cpu_usage_usec
                .zip(current.cpu_usage_usec)
                .filter(|_| elapsed_usec > 0.0)
                .map(|(before, after)| after.saturating_sub(before) as f64 / elapsed_usec * 100.0);
            Some((
                id.clone(),
                ContainerResourceUsage {
                    memory_usage: current.memory_current,
                    cpu_percent,
                },
            ))
        })
        .collect()
}

fn attach_container_resource_usage(
    stdout: &str,
    usage: &BTreeMap<String, ContainerResourceUsage>,
) -> Result<String, serde_json::Error> {
    let mut records = parse_nullable_json_list::<JsonValue>(stdout)?;
    for record in &mut records {
        let Some(id) = record.get("id").and_then(JsonValue::as_str) else {
            continue;
        };
        let Some(stats) = usage.get(id) else {
            continue;
        };
        let Some(object) = record.as_object_mut() else {
            continue;
        };
        if let Some(memory) = stats.memory_usage {
            object.insert("memory_usage".to_string(), JsonValue::from(memory));
        }
        if let Some(cpu) = stats.cpu_percent.and_then(serde_json::Number::from_f64) {
            object.insert("cpu_percent".to_string(), JsonValue::Number(cpu));
        }
    }
    serde_json::to_string(&records)
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
    id: String,
    name: Option<String>,
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
                container.name.as_deref().is_some_and(|container_name| {
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
    #[serde(default)]
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
}

#[derive(Debug, Deserialize)]
struct ContainerPortRecord {
    host_port: u16,
    container_port: u16,
    protocol: String,
}

#[derive(Debug, Deserialize)]
struct ContainerNetworkRecord {
    id: String,
    name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    ports: Vec<ContainerPortRecord>,
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
            .map(|(name, count)| {
                (
                    name.to_string(),
                    count.parse::<u64>().unwrap_or_default(),
                )
            })
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

fn run_container_bridge_command(
    image: &str,
    name: Option<&str>,
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
    Ok(command)
}

fn registry_login_command(registry: &str, username: &str) -> Result<Vec<String>, String> {
    let registry = registry.trim();
    let username = username.trim();
    if registry.is_empty() || username.is_empty() {
        return Err("registry and username are required".to_string());
    }
    Ok(vec![
        "registry-proxy".to_string(),
        "login".to_string(),
        "--registry".to_string(),
        registry.to_string(),
        "--username".to_string(),
        username.to_string(),
    ])
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
                                .and_then(|row| row.name.clone())
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
                subnets: network
                    .ipam
                    .config
                    .into_iter()
                    .filter_map(|config| config.subnet)
                    .collect(),
                containers: attachments,
            }
        })
        .collect()
}

fn volume_proxy_command(action: VolumeAction, target: Option<&str>) -> Result<Vec<String>, String> {
    let mut command = Vec::new();
    match action {
        VolumeAction::List => {
            command = [
                "exec",
                "--",
                "ferrocrate",
                "volume",
                "ls",
                "--format",
                "json",
            ]
            .into_iter()
            .map(str::to_string)
            .collect();
        }
        VolumeAction::Prune => {
            command.extend(["volume-proxy".to_string(), "prune".to_string()]);
        }
        VolumeAction::Create | VolumeAction::Remove => {
            let target = target
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "volume name is required".to_string())?;
            command.push("volume-proxy".to_string());
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

fn network_proxy_command(
    action: NetworkAction,
    target: Option<&str>,
    subnet: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut command = Vec::new();
    match action {
        NetworkAction::List => {
            command = [
                "exec",
                "--",
                "ferrocrate",
                "network",
                "ls",
                "--format",
                "json",
            ]
            .into_iter()
            .map(str::to_string)
            .collect();
        }
        NetworkAction::Inspect | NetworkAction::Create | NetworkAction::Remove => {
            let target = target
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "network name is required".to_string())?;
            if matches!(action, NetworkAction::Inspect) {
                return Ok([
                    "exec",
                    "--",
                    "ferrocrate",
                    "network",
                    "inspect",
                    target,
                    "--format",
                    "json",
                ]
                .into_iter()
                .map(str::to_string)
                .collect());
            }
            command.push("network-proxy".to_string());
            command.push(
                match action {
                    NetworkAction::Inspect => "inspect",
                    NetworkAction::Create => "create",
                    NetworkAction::Remove => "remove",
                    NetworkAction::List => unreachable!(),
                }
                .to_string(),
            );
            command.push(target.to_string());
            if matches!(action, NetworkAction::Create) {
                if let Some(subnet) = subnet.map(str::trim).filter(|value| !value.is_empty()) {
                    command.push("--subnet".to_string());
                    command.push(subnet.to_string());
                }
            }
        }
    }
    Ok(command)
}

fn execute_volume_proxy(
    action: VolumeAction,
    target: Option<&str>,
) -> Result<CommandResult, String> {
    let args = volume_proxy_command(action, target)?;
    let output = Command::new("ferro-desktop")
        .args(&args)
        .output()
        .map_err(|error| format!("failed to run volume proxy: {error}"))?;
    Ok(command_result_from_output(output))
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
    match Command::new(binary).args(args).output() {
        Ok(output) => command_result_from_output(output),
        Err(err) => command_spawn_failure(binary, err),
    }
}

fn run_owned_command(binary: &str, args: &[String]) -> CommandResult {
    match Command::new(binary).args(args).output() {
        Ok(output) => command_result_from_output(output),
        Err(err) => command_spawn_failure(binary, err),
    }
}

fn run_command_env(binary: &str, args: &[&str], envs: &[(&str, String)]) -> CommandResult {
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
    let runtime = run_command("ferro-desktop", &["vm", "status", "--json"]);
    let mut containers = run_owned_command(
        "ferro-desktop",
        &ferrocrate_proxy_command(&["containers", "--all", "--format", "json"]),
    );
    normalize_nullable_list_output(&mut containers);
    if containers.ok {
        if let Ok(records) = parse_nullable_json_list::<JsonValue>(&containers.stdout) {
            let running_ids = records
                .iter()
                .filter(|record| {
                    record.get("status").and_then(JsonValue::as_str) == Some("running")
                })
                .filter_map(|record| {
                    record
                        .get("id")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string)
                })
                .collect::<Vec<_>>();
            let usage = collect_container_resource_usage(&running_ids);
            if let Ok(enriched) = attach_container_resource_usage(&containers.stdout, &usage) {
                containers.stdout = enriched;
            }
        }
    }
    let mut images = run_owned_command(
        "ferro-desktop",
        &ferrocrate_proxy_command(&["images", "--format", "json"]),
    );
    normalize_nullable_list_output(&mut images);

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

#[tauri::command]
fn build_image(
    app: tauri::AppHandle,
    context: String,
    tag: String,
    build_id: String,
) -> Result<CommandResult, String> {
    let build_id = build_id.trim().to_string();
    if build_id.is_empty() {
        return Err("build identifier is required".to_string());
    }
    let args = build_bridge_command(&context, &tag)?;
    let mut child = Command::new("ferro-desktop")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start image build: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "image build stdout unavailable".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "image build stderr unavailable".to_string())?;
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
        let _ = app.emit("image-build-progress", frame);
    }
    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for image build: {error}"))?;
    Ok(CommandResult {
        ok: status.success(),
        code: status.code().unwrap_or(1),
        stdout: stdout_text,
        message: actionable_error(&stderr_text),
        stderr: stderr_text,
    })
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
fn run_new_container(
    image: String,
    name: Option<String>,
    environment: Vec<String>,
    memory: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
) -> Result<CommandResult, String> {
    Ok(run_owned_command(
        "ferro-desktop",
        &run_container_bridge_command(
            &image,
            name.as_deref(),
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
    let mut child = Command::new("ferro-desktop")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to start registry login proxy: {error}"))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "registry login stdin unavailable".to_string())?;
    stdin
        .write_all(password.as_bytes())
        .and_then(|_| stdin.write_all(b"\n"))
        .map_err(|error| format!("failed to send registry password: {error}"))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for registry login: {error}"))?;
    let result = command_result_from_output(output);
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

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            get_desktop_snapshot,
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        actionable_error, attach_container_resource_usage, build_bridge_command, command_failure,
        compose_bridge_command, compose_service_rows, container_detail_from_json,
        container_inspect_command, container_update_command, ferrocrate_proxy_command, log_channel,
        log_follow_command, network_proxy_command, network_summaries,
        normalize_nullable_list_output, parse_nullable_json_list, parse_terminal_exec_id,
        registry_login_command, registry_logout_command, run_container_bridge_command,
        terminal_exec_command, terminal_resize_command, volume_proxy_command, BuildProgressFrame,
        CommandResult, ComposeAction, ComposeContainerRecord, ContainerNetworkRecord,
        ContainerPortRecord, ContainerResourceUsage, JsonValue, LogBuffer, NetworkAction,
        NetworkInspectRecord, NetworkIpam, NetworkIpamConfig, NetworkListRecord, VolumeAction,
        VolumeListResponse,
    };

    #[test]
    fn image_build_uses_selected_context_through_desktop_bridge() {
        assert_eq!(
            build_bridge_command("/tmp/build context", "demo/app:dev").expect("build command"),
            vec![
                "exec",
                "--",
                "ferrocrate",
                "build",
                "--dockerfile",
                "/tmp/build context/Dockerfile",
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
        let containers = vec![
            ComposeContainerRecord {
                id: "api-id".to_string(),
                name: Some("api".to_string()),
                status: "running".to_string(),
            },
            ComposeContainerRecord {
                id: "worker-id".to_string(),
                name: Some("worker-1".to_string()),
                status: "exited".to_string(),
            },
        ];
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
    fn container_snapshot_includes_live_cpu_and_memory_usage() {
        let usage = BTreeMap::from([(
            "demo".to_string(),
            ContainerResourceUsage {
                memory_usage: Some(67_108_864),
                cpu_percent: Some(12.5),
            },
        )]);
        let output = attach_container_resource_usage(
            r#"[{"id":"demo","status":"running"},{"id":"stopped","status":"exited"}]"#,
            &usage,
        )
        .expect("enriched container JSON");
        let records: Vec<JsonValue> = serde_json::from_str(&output).expect("container JSON");

        assert_eq!(records[0]["memory_usage"], 67_108_864);
        assert_eq!(records[0]["cpu_percent"], 12.5);
        assert!(records[1].get("memory_usage").is_none());
    }

    #[test]
    fn stopped_container_start_runs_through_the_daemon_bridge() {
        assert_eq!(
            ferrocrate_proxy_command(&["start", "demo"]),
            vec!["exec", "--", "ferrocrate", "start", "demo"]
        );
    }

    #[test]
    fn volume_list_uses_json_exec_bridge_and_mutations_stay_typed() {
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
    fn network_list_uses_json_exec_bridge_and_mutations_stay_typed() {
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
                "network-proxy",
                "create",
                "frontend",
                "--subnet",
                "172.30.0.0/16",
            ]
        );
        assert_eq!(
            network_proxy_command(NetworkAction::Remove, Some("frontend"), None)
                .expect("remove command"),
            vec!["network-proxy", "remove", "frontend"]
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
            name: Some("web".to_string()),
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
                Some("web"),
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
                "web",
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
            ]
        );
    }

    #[test]
    fn registry_auth_commands_keep_password_out_of_process_arguments() {
        assert_eq!(
            registry_login_command("registry.example.com", "alice").expect("login command"),
            vec![
                "registry-proxy",
                "login",
                "--registry",
                "registry.example.com",
                "--username",
                "alice",
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
