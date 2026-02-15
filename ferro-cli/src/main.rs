#![allow(clippy::items_after_test_module)]
#![allow(missing_docs)]

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use ferro_compose::compose::{
    compose_down, compose_logs, compose_ps, compose_up, find_compose_file, ComposeProject,
};
use ferro_compose::{
    Command as ComposeCommandSpec, DependsOn as ComposeDependsOn,
    Environment as ComposeEnvironment, Service as ComposeService,
};
use ferro_core::docker_auth::resolve_registry_auth;
use ferro_core::entitlements::{self, Entitlement, Feature};
use ferro_core::image_fetch::resolve_layer_paths_with_store;
use ferro_core::image_manifest::parse_image_manifest;
use ferro_core::image_store::LocalImageStore;
use ferro_core::image_tagging::{canonicalize_reference, resolve_reference};
use ferro_core::layer_compression::CompressionFormat;
use ferro_core::registry::{parse_image_reference, RegistryClient};
#[cfg(target_os = "linux")]
use ferro_core::rootfs::construct_rootfs_with_dedup;
#[cfg(target_os = "linux")]
use ferro_core::runtime::ContainerRuntime;
use ferro_core::volume_store::LocalVolumeStore;
use ferro_mind::ai::agents::{orchestrate_task, OrchestrateRequest};
use ferro_mind::ai::audit::AuditLogger;
use ferro_mind::ai::explain::DecisionTrace;
use ferro_mind::ai::training::{
    handle_community_download_command, handle_community_list_command,
    handle_community_publish_command, handle_export_command, handle_import_command,
    handle_stats_command, handle_train_command,
};
#[cfg(target_os = "linux")]
use ferro_mind::ai::training::{
    handle_export_rvf_command, handle_rvf_branch_command, handle_rvf_lineage_command,
    handle_rvf_stats_command, handle_rvf_verify_command,
};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::time::{Duration, Instant};

#[derive(Debug, Parser)]
#[command(name = "ferrocrate", version, about = "FerroCrate CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Commands {
    #[cfg(target_os = "linux")]
    Run {
        image: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "bridge")]
        network: String,
        #[arg(long, default_value = "ebpf")]
        network_backend: String,
        #[arg(long = "bind")]
        bind_mounts: Vec<String>,
        #[arg(long = "tmpfs")]
        tmpfs_mounts: Vec<String>,
        #[arg(long = "read-only")]
        read_only_rootfs: bool,
        #[arg(long = "read-write")]
        read_write_rootfs: bool,
        #[arg(long = "no-new-privileges")]
        no_new_privs: bool,
        #[arg(long, default_value = "dev")]
        profile: String,
        #[arg(short = 'e', long = "env")]
        env: Vec<String>,
        #[arg(short = 'l', long = "label")]
        labels: Vec<String>,
        #[arg(long = "annotation")]
        annotations: Vec<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        workdir: Option<String>,
        #[arg(long)]
        entrypoint: Option<String>,
        #[arg(short = 'p', long = "publish")]
        publish: Vec<String>,
        #[arg(short = 'v', long = "volume")]
        volumes: Vec<String>,
        #[arg(long = "cap-add")]
        cap_add: Vec<String>,
        #[arg(long = "health-cmd")]
        health_cmd: Option<String>,
        #[arg(long = "health-interval")]
        health_interval: Option<u64>,
        #[arg(long = "health-timeout")]
        health_timeout: Option<u64>,
        #[arg(long = "health-retries")]
        health_retries: Option<u32>,
        #[arg(long = "health-start-period")]
        health_start_period: Option<u64>,
        #[arg(long = "restart", default_value = "no")]
        restart_policy: String,
        #[arg(long)]
        rm: bool,
        #[arg(long)]
        bridge_cidr: Option<String>,
        #[arg(long)]
        bridge_name: Option<String>,
        #[arg(long = "net-limit")]
        net_limit: Option<String>,
        #[arg(long)]
        memory_max: Option<u64>,
        #[arg(long)]
        cpu_quota: Option<u64>,
        #[arg(long)]
        cpu_period: Option<u64>,
        #[arg(long)]
        pids_max: Option<u64>,
        #[arg(long = "ai-model")]
        ai_model: Option<String>,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    #[cfg(target_os = "linux")]
    Build {
        dockerfile: Option<String>,
        #[arg(long)]
        ferrofile: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        #[arg(long, default_value = "gzip", value_parser = validate_compression)]
        compress: String,
    },
    Images {
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Rmi {
        image: String,
    },
    ImagePrune,
    #[cfg(target_os = "linux")]
    Volume {
        #[command(subcommand)]
        command: VolumeCommands,
    },
    #[cfg(target_os = "linux")]
    Network {
        #[command(subcommand)]
        command: NetworkCommands,
    },
    #[cfg(target_os = "linux")]
    #[command(alias = "ps")]
    Containers {
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    Logs {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    Stats {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    Inspect {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    Pause {
        container: String,
    },
    #[cfg(target_os = "linux")]
    Unpause {
        container: String,
    },
    #[cfg(target_os = "linux")]
    Stop {
        container: String,
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
    #[cfg(target_os = "linux")]
    Kill {
        container: String,
    },
    #[cfg(target_os = "linux")]
    Rm {
        container: String,
    },
    #[cfg(target_os = "linux")]
    Restart {
        container: String,
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
    #[cfg(target_os = "linux")]
    Exec {
        container: String,
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    Pull {
        image: String,
        #[arg(long)]
        lazy: bool,
    },
    Push {
        image: String,
    },
    #[cfg(target_os = "linux")]
    Scan {
        image: String,
        #[arg(long, default_value = "auto")]
        scanner: String,
    },
    #[cfg(target_os = "linux")]
    Compose {
        #[arg(short, long)]
        file: Option<String>,
        #[command(subcommand)]
        command: ComposeCommands,
    },
    #[cfg(target_os = "linux")]
    Daemon {
        #[arg(long, default_value = "/var/run/ferrocrate.sock")]
        socket: String,
        #[arg(long)]
        docker_compat: bool,
        #[arg(long)]
        metrics_addr: Option<String>,
    },
    Completion {
        shell: String,
    },
    #[cfg(target_os = "linux")]
    Tui,
    Ai {
        #[command(subcommand)]
        command: AiCommands,
    },
    AiTrain {
        #[arg(long = "model-type")]
        model_type: String,
        #[arg(long = "data-dir")]
        data_dir: Option<String>,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    AiExport {
        #[arg(long = "model-type")]
        model_type: String,
        #[arg(long)]
        output: String,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    AiImport {
        #[arg(long = "model-type")]
        model_type: String,
        #[arg(long)]
        input: String,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    AiStats {
        path: Option<String>,
        #[arg(long = "model-type")]
        model_type: Option<String>,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    AiBranch {
        source: String,
        target: String,
        #[arg(long)]
        force: bool,
    },
    #[cfg(target_os = "linux")]
    AiLineage {
        path: String,
        #[arg(long = "parent-file")]
        parent_file: Option<String>,
        #[arg(long)]
        verify: bool,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    Doctor {
        #[arg(long, default_value_t = false)]
        fix: bool,
        #[arg(long, default_value_t = false)]
        bootstrap: bool,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Entitlement {
        #[command(subcommand)]
        command: EntitlementCommands,
    },
    AiAudit {
        #[arg(long)]
        action: String,
        #[arg(long)]
        summary: String,
        #[arg(long = "evidence")]
        evidence: Vec<String>,
    },
    Migrate {
        #[command(subcommand)]
        target: MigrateCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum MigrateCommands {
    DockerAuth {
        #[arg(long)]
        output: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ComposeCommands {
    Up {
        #[arg(long)]
        profile: Vec<String>,
    },
    Watch {
        #[arg(long)]
        profile: Vec<String>,
        #[arg(long, default_value = "2")]
        interval: u64,
    },
    Down,
    Ps,
    Logs,
}

#[derive(Debug, Subcommand)]
pub enum VolumeCommands {
    Create {
        name: String,
        #[arg(long, default_value = "local")]
        driver: String,
        #[arg(long = "opt")]
        opts: Vec<String>,
    },
    Backup {
        name: String,
        path: String,
    },
    Restore {
        name: String,
        path: String,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum NetworkCommands {
    Create {
        name: String,
        #[arg(long)]
        subnet: Option<String>,
        #[arg(long)]
        gateway: Option<String>,
    },
    Ls,
    Rm {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum AiCommands {
    Orchestrate {
        #[arg(long)]
        task: String,
        #[arg(long)]
        context: Option<String>,
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Train {
        #[arg(long = "model-type")]
        model_type: String,
        #[arg(long = "data-dir")]
        data_dir: Option<String>,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long)]
        output: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Export {
        #[arg(long = "model-type")]
        model_type: String,
        #[arg(long)]
        output: String,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Import {
        #[arg(long = "model-type")]
        model_type: String,
        #[arg(long)]
        input: String,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Stats {
        /// Path to a .rvf model file (optional)
        path: Option<String>,
        #[arg(long = "model-type")]
        model_type: Option<String>,
        #[arg(long = "models-dir")]
        models_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    Branch {
        source: String,
        target: String,
        #[arg(long)]
        force: bool,
    },
    #[cfg(target_os = "linux")]
    Lineage {
        path: String,
        #[arg(long = "parent-file")]
        parent_file: Option<String>,
        #[arg(long)]
        verify: bool,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    Migrate {
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        force: bool,
    },
    Community {
        #[command(subcommand)]
        command: AiCommunityCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum AiCommunityCommands {
    List {
        #[arg(long = "marketplace-dir")]
        marketplace_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Publish {
        #[arg(long)]
        input: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        tags: Vec<String>,
        #[arg(long = "marketplace-dir")]
        marketplace_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Download {
        #[arg(long)]
        name: String,
        #[arg(long)]
        output: String,
        #[arg(long = "marketplace-dir")]
        marketplace_dir: Option<String>,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommands {
    Set { key: String, value: String },
    Get { key: String },
}

#[derive(Debug, Subcommand)]
pub enum EntitlementCommands {
    Status {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn main() {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    match maybe_host_desktop_forward(&raw_args) {
        Ok(true) => return,
        Ok(false) => {}
        Err(err) => {
            eprintln!("error: {err}");
            process::exit(1);
        }
    }
    let cli = Cli::parse();
    if let Err(err) = dispatch(cli.command) {
        eprintln!("error: {}", normalize_cli_error(err));
        process::exit(1);
    }
}

#[cfg(any(test, not(target_os = "linux")))]
fn desktop_forward_enabled() -> bool {
    if let Ok(value) = std::env::var("FERROCRATE_DESKTOP_FORWARD") {
        return value == "1" || value.eq_ignore_ascii_case("true");
    }
    #[cfg(target_os = "macos")]
    {
        return true;
    }
    false
}

#[cfg(any(test, not(target_os = "linux")))]
fn is_runtime_command_name(command: &str) -> bool {
    matches!(
        command,
        "run"
            | "build"
            | "containers"
            | "ps"
            | "logs"
            | "inspect"
            | "stats"
            | "pause"
            | "unpause"
            | "stop"
            | "kill"
            | "rm"
            | "restart"
            | "exec"
            | "scan"
            | "compose"
            | "daemon"
            | "tui"
            | "volume"
            | "network"
            | "migrate"
    )
}

#[cfg(any(test, not(target_os = "linux")))]
fn top_level_command_name(raw_args: &[String]) -> Option<&str> {
    raw_args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str)
}

#[cfg(any(test, not(target_os = "linux")))]
fn should_desktop_forward(raw_args: &[String]) -> bool {
    top_level_command_name(raw_args)
        .map(is_runtime_command_name)
        .unwrap_or(false)
}

#[cfg(windows)]
fn maybe_host_desktop_forward(raw_args: &[String]) -> Result<bool, String> {
    if !desktop_forward_enabled() {
        return Ok(false);
    }
    if raw_args.is_empty() {
        return Ok(false);
    }
    // Avoid recursive loops if invoking ferro-desktop subcommands through ferrocrate.
    if raw_args[0] == "desktop" {
        return Ok(false);
    }
    require_cli_feature(Feature::Desktop)?;
    forward_to_desktop(raw_args, true)
}

#[cfg(target_os = "macos")]
fn maybe_host_desktop_forward(raw_args: &[String]) -> Result<bool, String> {
    if !desktop_forward_enabled() || !should_desktop_forward(raw_args) {
        return Ok(false);
    }
    if raw_args.is_empty() {
        return Ok(false);
    }
    require_cli_feature(Feature::Desktop)?;
    ensure_macos_vm_running()?;
    forward_to_desktop(raw_args, false)
}

#[cfg(all(
    not(test),
    not(any(target_os = "linux", target_os = "windows", target_os = "macos"))
))]
fn maybe_host_desktop_forward(_raw_args: &[String]) -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn maybe_host_desktop_forward(_raw_args: &[String]) -> Result<bool, String> {
    Ok(false)
}

#[cfg(any(test, not(target_os = "linux")))]
fn desktop_error_json_enabled() -> bool {
    std::env::var("FERROCRATE_ERROR_FORMAT")
        .map(|value| value.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
        || std::env::var("FERROCRATE_ERROR_JSON")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

#[cfg(any(test, not(target_os = "linux")))]
fn desktop_binary_path() -> PathBuf {
    if let Ok(path) = std::env::var("FERROCRATE_DESKTOP_BIN") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join(if cfg!(windows) {
                "ferro-desktop.exe"
            } else {
                "ferro-desktop"
            });
            if candidate.exists() {
                return candidate;
            }
        }
    }

    PathBuf::from(if cfg!(windows) {
        "ferro-desktop.exe"
    } else {
        "ferro-desktop"
    })
}

#[cfg(any(test, not(target_os = "linux")))]
fn structured_desktop_error(category: &str, message: &str, hint: &str, retryable: bool) -> String {
    if desktop_error_json_enabled() {
        return serde_json::json!({
            "category": category,
            "message": message,
            "hint": hint,
            "retryable": retryable
        })
        .to_string();
    }
    format!("{message} [category={category} retryable={retryable}] hint: {hint}")
}

#[cfg(any(test, not(target_os = "linux")))]
#[cfg_attr(test, allow(dead_code))]
fn forward_to_desktop(raw_args: &[String], use_wsl_default: bool) -> Result<bool, String> {
    let addr =
        std::env::var("FERROCRATE_DESKTOP_ADDR").unwrap_or_else(|_| "127.0.0.1:4288".to_string());
    let wsl_distro = std::env::var("FERROCRATE_DESKTOP_WSL_DISTRO").ok();
    let use_wsl = std::env::var("FERROCRATE_DESKTOP_USE_WSL")
        .map(|value| !(value == "0" || value.eq_ignore_ascii_case("false")))
        .unwrap_or(use_wsl_default);

    let desktop_bin = desktop_binary_path();
    let mut command = std::process::Command::new(&desktop_bin);
    command.arg("exec").arg("--addr").arg(addr);
    #[cfg(windows)]
    {
        if use_wsl {
            command.arg("--wsl");
        }
        if let Some(distro) = wsl_distro {
            if !distro.trim().is_empty() {
                command.arg("--wsl-distro").arg(distro);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = use_wsl;
        let _ = wsl_distro;
    }
    command.arg("--").arg("ferrocrate");
    for arg in raw_args {
        command.arg(arg);
    }

    let status = command.status().map_err(|err| {
        structured_desktop_error(
            "desktop_bridge_unavailable",
            &format!(
                "desktop forward failed to launch {}: {err}",
                desktop_bin.display()
            ),
            "set FERROCRATE_DESKTOP_BIN or ensure `ferro-desktop` is installed and on PATH",
            true,
        )
    })?;
    let code = status.code().unwrap_or(1);
    if code != 0 {
        return Err(structured_desktop_error(
            "desktop_command_failed",
            &format!("desktop forward command exited with status {code}"),
            "run `ferro-desktop vm status --json` and retry",
            true,
        ));
    }
    Ok(true)
}

#[cfg(target_os = "macos")]
fn vm_status_is_running(output: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(output) {
        return value
            .get("status")
            .and_then(|status| status.as_str())
            .map(|status| status == "running")
            .unwrap_or(false);
    }
    output.contains("vm: status=running")
}

#[cfg(target_os = "macos")]
fn ensure_macos_vm_running() -> Result<(), String> {
    let desktop_bin = desktop_binary_path();
    let status_output = std::process::Command::new(&desktop_bin)
        .args(["vm", "status", "--json"])
        .output()
        .map_err(|err| {
            structured_desktop_error(
                "vm_status_check_failed",
                &format!(
                    "failed to query desktop VM status via {}: {err}",
                    desktop_bin.display()
                ),
                "initialize the VM with `ferro-desktop vm init` and/or set FERROCRATE_DESKTOP_BIN",
                false,
            )
        })?;
    if !status_output.status.success() {
        return Err(structured_desktop_error(
            "vm_status_check_failed",
            "desktop VM status check failed",
            "initialize the VM with `ferro-desktop vm init`, then retry",
            false,
        ));
    }
    let status_stdout = String::from_utf8_lossy(&status_output.stdout);
    if vm_status_is_running(&status_stdout) {
        return Ok(());
    }

    let start_status = std::process::Command::new(&desktop_bin)
        .args(["vm", "start"])
        .status()
        .map_err(|err| {
            structured_desktop_error(
                "vm_start_failed",
                &format!(
                    "failed to start desktop VM via {}: {err}",
                    desktop_bin.display()
                ),
                "run `ferro-desktop vm start` manually or set FERROCRATE_DESKTOP_BIN",
                true,
            )
        })?;
    if !start_status.success() {
        return Err(structured_desktop_error(
            "vm_start_failed",
            "desktop VM start command failed",
            "run `ferro-desktop vm status --json` and check VM backend configuration",
            true,
        ));
    }
    Ok(())
}

fn normalize_cli_error(err: String) -> String {
    #[cfg(not(target_os = "linux"))]
    if err.contains("not supported on this platform") {
        return structured_desktop_error(
            "unsupported_on_host",
            "command is not available on host kernel for this platform",
            "for runtime operations, use desktop VM mode (`ferro-desktop vm start`) and retry",
            false,
        );
    }
    err
}

fn require_cli_feature(feature: Feature) -> Result<Entitlement, String> {
    entitlements::require_feature(feature).map_err(|err| {
        format!(
            "entitlement check failed: {err}. set FERROCRATE_ENTITLEMENT_FILE and FERROCRATE_ENTITLEMENT_PUBKEY"
        )
    })
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    id: String,
    ok: bool,
    message: String,
    hint: Option<String>,
    remediated: bool,
}

fn run_command_status(mut cmd: std::process::Command) -> bool {
    cmd.status().map(|status| status.success()).unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn doctor_ensure_brew_formula(bin: &str, formula: &str) -> bool {
    if command_exists(bin) {
        return true;
    }
    if !command_exists("brew") {
        return false;
    }
    run_command_status({
        let mut command = std::process::Command::new("brew");
        command.arg("install").arg(formula);
        command
    }) && command_exists(bin)
}

#[cfg(target_os = "macos")]
fn doctor_default_vm_state_file() -> PathBuf {
    if let Ok(path) = std::env::var("VM_STATE_FILE") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".ferrocrate")
            .join("desktop-vm.json");
    }
    PathBuf::from(".ferrocrate").join("desktop-vm.json")
}

#[cfg(target_os = "macos")]
fn parse_vm_status(output: &str) -> Option<(bool, u16, Option<String>, Option<String>)> {
    let value = serde_json::from_str::<serde_json::Value>(output).ok()?;
    let running = value
        .get("status")
        .and_then(|v| v.as_str())
        .map(|v| v == "running")
        .unwrap_or(false);
    let ssh_port = value
        .get("config")
        .and_then(|config| config.get("ssh_port"))
        .and_then(|v| v.as_u64())
        .unwrap_or(2222) as u16;
    let guest_user = value
        .get("config")
        .and_then(|config| config.get("guest_user"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    let ssh_key = value
        .get("config")
        .and_then(|config| config.get("ssh_private_key_path"))
        .and_then(|v| v.as_str())
        .map(|v| v.to_string());
    Some((running, ssh_port, guest_user, ssh_key))
}

#[cfg(target_os = "macos")]
fn doctor_guest_ferrocrate_installed(
    ssh_port: u16,
    guest_user: Option<String>,
    ssh_key: Option<String>,
) -> bool {
    let mut command = std::process::Command::new("ssh");
    command
        .arg("-p")
        .arg(ssh_port.to_string())
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=5");
    if let Some(path) = ssh_key {
        command.arg("-i").arg(path);
    }
    let user = guest_user.unwrap_or_else(|| "ferro".to_string());
    command
        .arg(format!("{user}@127.0.0.1"))
        .arg("--")
        .arg("bash")
        .arg("-lc")
        .arg("command -v ferrocrate >/dev/null");
    run_command_status(command)
}

fn handle_doctor(fix: bool, bootstrap: bool, json: bool) -> Result<(), String> {
    let mut checks = Vec::<DoctorCheck>::new();

    #[cfg(target_os = "macos")]
    {
        let desktop_bin = desktop_binary_path();
        let desktop_present = desktop_bin.exists() || command_exists("ferro-desktop");
        checks.push(DoctorCheck {
            id: "desktop_binary".to_string(),
            ok: desktop_present,
            message: if desktop_present {
                format!("desktop binary available ({})", desktop_bin.display())
            } else {
                "desktop binary missing".to_string()
            },
            hint: (!desktop_present).then_some(
                "install paid desktop artifacts (`scripts/install-macos.sh --channel paid --full-stack`)".to_string(),
            ),
            remediated: false,
        });

        let arch_bin = if cfg!(target_arch = "aarch64") {
            "qemu-system-aarch64"
        } else {
            "qemu-system-x86_64"
        };
        for (id, bin, formula) in [
            ("qemu_img", "qemu-img", "qemu"),
            ("qemu_system", arch_bin, "qemu"),
            ("virtiofsd", "virtiofsd", "qemu"),
            ("ssh", "ssh", "openssh"),
        ] {
            let mut ok = command_exists(bin);
            let mut remediated = false;
            if !ok && fix {
                ok = doctor_ensure_brew_formula(bin, formula);
                remediated = ok;
            }
            checks.push(DoctorCheck {
                id: id.to_string(),
                ok,
                message: if ok {
                    format!("{bin} available")
                } else {
                    format!("{bin} missing")
                },
                hint: (!ok).then_some(format!("install dependency: brew install {formula}")),
                remediated,
            });
        }

        let mut vm_running = false;
        let mut vm_ssh_port = 2222u16;
        let mut vm_guest_user = None;
        let mut vm_ssh_key = None;
        let status_output = std::process::Command::new(&desktop_bin)
            .args(["vm", "status", "--json"])
            .output();
        match status_output {
            Ok(output) if output.status.success() => {
                let raw = String::from_utf8_lossy(&output.stdout);
                if let Some((running, ssh_port, guest_user, ssh_key)) = parse_vm_status(&raw) {
                    vm_running = running;
                    vm_ssh_port = ssh_port;
                    vm_guest_user = guest_user;
                    vm_ssh_key = ssh_key;
                }
            }
            _ => {}
        }

        let mut vm_remediated = false;
        if !vm_running && fix && desktop_present {
            vm_remediated = run_command_status({
                let mut command = std::process::Command::new(&desktop_bin);
                command.args(["vm", "start"]);
                command
            });
            if vm_remediated {
                if let Ok(output) = std::process::Command::new(&desktop_bin)
                    .args(["vm", "status", "--json"])
                    .output()
                {
                    if output.status.success() {
                        let raw = String::from_utf8_lossy(&output.stdout);
                        if let Some((running, ssh_port, guest_user, ssh_key)) =
                            parse_vm_status(&raw)
                        {
                            vm_running = running;
                            vm_ssh_port = ssh_port;
                            vm_guest_user = guest_user;
                            vm_ssh_key = ssh_key;
                        }
                    }
                }
            }
        }

        checks.push(DoctorCheck {
            id: "vm_running".to_string(),
            ok: vm_running,
            message: if vm_running {
                "desktop VM is running".to_string()
            } else {
                format!(
                    "desktop VM is not running (state file: {})",
                    doctor_default_vm_state_file().display()
                )
            },
            hint: (!vm_running).then_some(
                "initialize/start VM with `ferro-desktop vm init ...` then `ferro-desktop vm start`".to_string(),
            ),
            remediated: vm_remediated,
        });

        let mut ssh_ok = false;
        if vm_running {
            ssh_ok = TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], vm_ssh_port)),
                Duration::from_secs(2),
            )
            .is_ok();
        }
        checks.push(DoctorCheck {
            id: "guest_ssh".to_string(),
            ok: ssh_ok,
            message: if ssh_ok {
                format!("guest SSH reachable on 127.0.0.1:{vm_ssh_port}")
            } else {
                format!("guest SSH not reachable on 127.0.0.1:{vm_ssh_port}")
            },
            hint: (!ssh_ok).then_some(
                "ensure VM networking/port-forward is healthy (`ferro-desktop vm status --json`)"
                    .to_string(),
            ),
            remediated: false,
        });

        let guest_ferro_ok = if ssh_ok {
            doctor_guest_ferrocrate_installed(vm_ssh_port, vm_guest_user, vm_ssh_key)
        } else {
            false
        };
        checks.push(DoctorCheck {
            id: "guest_ferrocrate".to_string(),
            ok: guest_ferro_ok,
            message: if guest_ferro_ok {
                "guest ferrocrate runtime is installed".to_string()
            } else {
                "guest ferrocrate runtime missing".to_string()
            },
            hint: (!guest_ferro_ok).then_some(
                "run installer with `--channel paid --full-stack` to bootstrap guest runtime"
                    .to_string(),
            ),
            remediated: false,
        });
    }

    #[cfg(not(target_os = "macos"))]
    {
        checks.push(DoctorCheck {
            id: "platform_scope".to_string(),
            ok: true,
            message: "doctor currently performs full compatibility checks on macOS hosts"
                .to_string(),
            hint: None,
            remediated: false,
        });
    }

    let healthy = checks.iter().all(|check| check.ok);
    #[cfg(target_os = "macos")]
    let mut healthy = healthy;

    #[cfg(target_os = "macos")]
    if fix && bootstrap && !healthy {
        let mut bootstrap_ok = false;
        let mut bootstrap_msg = "bootstrap script not found".to_string();
        let mut bootstrap_hint = Some(
            "set paid installer env (`PAID_RELEASE_BASE_URL`, token/session vars) then re-run `ferrocrate doctor --fix --bootstrap`"
                .to_string(),
        );

        let candidate_paths = vec![
            PathBuf::from("scripts/install-macos.sh"),
            PathBuf::from("../scripts/install-macos.sh"),
            PathBuf::from("../../scripts/install-macos.sh"),
        ];
        for path in candidate_paths {
            if !path.exists() {
                continue;
            }
            let status = std::process::Command::new("bash")
                .arg(path.as_os_str())
                .arg("--channel")
                .arg("paid")
                .arg("--full-stack")
                .status();
            match status {
                Ok(exit) if exit.success() => {
                    bootstrap_ok = true;
                    bootstrap_msg = format!("bootstrap succeeded via {}", path.display());
                    bootstrap_hint = None;
                    break;
                }
                Ok(exit) => {
                    bootstrap_msg = format!(
                        "bootstrap command failed via {} (status={})",
                        path.display(),
                        exit
                    );
                }
                Err(err) => {
                    bootstrap_msg =
                        format!("bootstrap launch failed via {}: {err}", path.display());
                }
            }
        }

        checks.push(DoctorCheck {
            id: "bootstrap".to_string(),
            ok: bootstrap_ok,
            message: bootstrap_msg,
            hint: bootstrap_hint,
            remediated: bootstrap_ok,
        });
        healthy = checks.iter().all(|check| check.ok);
    }

    if json {
        let payload = serde_json::json!({
            "healthy": healthy,
            "fix": fix,
            "bootstrap": bootstrap,
            "checks": checks,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "doctor: {}",
            if healthy { "healthy" } else { "issues found" }
        );
        for check in &checks {
            let status = if check.ok { "ok" } else { "fail" };
            let remediated = if check.remediated {
                " (remediated)"
            } else {
                ""
            };
            println!(
                "  [{}] {}: {}{}",
                status, check.id, check.message, remediated
            );
            if !check.ok {
                if let Some(hint) = &check.hint {
                    println!("      hint: {hint}");
                }
            }
        }
    }

    if healthy {
        Ok(())
    } else {
        Err("doctor detected compatibility issues".to_string())
    }
}

fn dispatch(command: Commands) -> Result<(), String> {
    // Handle platform-agnostic commands that don't need runtime
    if let Commands::AiAudit {
        ref action,
        ref summary,
        ref evidence,
    } = command
    {
        return handle_ai_audit(action, summary, evidence);
    }

    #[cfg(target_os = "linux")]
    {
        let runtime_dir = runtime_dir();

        // Handle Daemon command
        if let Commands::Daemon {
            ref socket,
            docker_compat,
            ref metrics_addr,
        } = command
        {
            let image_store =
                LocalImageStore::open(runtime_dir.join("images")).map_err(|err| err.to_string())?;
            return run_daemon(&image_store, socket, docker_compat, metrics_addr.as_deref());
        }

        let runtime = ContainerRuntime::new(&runtime_dir).map_err(|err| err.to_string())?;
        let image_store =
            LocalImageStore::open(runtime_dir.join("images")).map_err(|err| err.to_string())?;

        match command {
            #[cfg(target_os = "linux")]
            Commands::Run {
                image,
                cmd,
                network_backend,
                network,
                bind_mounts,
                tmpfs_mounts,
                volumes,
                read_only_rootfs,
                read_write_rootfs,
                no_new_privs,
                env,
                labels,
                annotations,
                cap_add,
                profile,
                user,
                workdir,
                entrypoint,
                publish,
                name,
                health_cmd,
                health_interval,
                health_timeout,
                health_retries,
                health_start_period,
                restart_policy,
                rm,
                bridge_cidr,
                bridge_name,
                net_limit,
                memory_max,
                cpu_quota,
                cpu_period,
                pids_max,
                ai_model,
            } => {
                let volume_store = LocalVolumeStore::open(runtime_dir.join("volumes"))
                    .map_err(|err| err.to_string())?;
                handle_run(
                    &runtime_dir,
                    &runtime,
                    &image_store,
                    &volume_store,
                    &image,
                    &cmd,
                    &network,
                    &network_backend,
                    &bind_mounts,
                    &tmpfs_mounts,
                    &volumes,
                    effective_readonly(&profile, read_only_rootfs, read_write_rootfs)?,
                    no_new_privs,
                    &env,
                    &labels,
                    &annotations,
                    &cap_add,
                    entrypoint.as_deref(),
                    workdir.as_deref(),
                    user.as_deref(),
                    name.as_deref(),
                    &publish,
                    health_cmd.as_deref(),
                    health_interval,
                    health_timeout,
                    health_retries,
                    health_start_period,
                    &restart_policy,
                    rm,
                    bridge_cidr.as_deref(),
                    bridge_name.as_deref(),
                    net_limit.as_deref(),
                    memory_max,
                    cpu_quota,
                    cpu_period,
                    pids_max,
                    ai_model.as_deref(),
                )
            }
            #[cfg(target_os = "linux")]
            Commands::Build {
                dockerfile,
                ferrofile,
                tag,
                compress,
            } => handle_build(
                &image_store,
                dockerfile.as_deref(),
                ferrofile.as_deref(),
                tag.as_deref(),
                compress.as_str(),
            ),
            Commands::Images { format } => handle_images(&image_store, &format),
            Commands::Rmi { image } => handle_rmi(&image_store, &image),
            Commands::ImagePrune => handle_image_prune(&image_store),
            Commands::Volume { command } => handle_volume(&runtime_dir, command),
            #[cfg(target_os = "linux")]
            Commands::Network { command } => handle_network(&runtime_dir, &runtime, command),
            #[cfg(target_os = "linux")]
            Commands::Containers { format } => handle_containers(&runtime, &format),
            #[cfg(target_os = "linux")]
            Commands::Logs { container, format } => handle_logs(&runtime, &container, &format),
            #[cfg(target_os = "linux")]
            Commands::Inspect { container, format } => {
                handle_inspect(&runtime, &container, &format)
            }
            #[cfg(target_os = "linux")]
            Commands::Stats { container, format } => handle_stats(&runtime, &container, &format),
            #[cfg(target_os = "linux")]
            Commands::Pause { container } => handle_pause(&runtime, &container),
            #[cfg(target_os = "linux")]
            Commands::Unpause { container } => handle_unpause(&runtime, &container),
            #[cfg(target_os = "linux")]
            Commands::Stop { container, timeout } => handle_stop(&runtime, &container, timeout),
            #[cfg(target_os = "linux")]
            Commands::Kill { container } => handle_kill(&runtime, &container),
            #[cfg(target_os = "linux")]
            Commands::Rm { container } => handle_rm(&runtime, &container),
            #[cfg(target_os = "linux")]
            Commands::Restart { container, timeout } => {
                handle_restart(&runtime, &container, timeout)
            }
            #[cfg(target_os = "linux")]
            Commands::Exec { container, cmd } => handle_exec(&runtime, &container, &cmd),
            Commands::Pull { image, lazy } => handle_pull(&image_store, &image, lazy),
            Commands::Push { image } => handle_push(&image_store, &image),
            #[cfg(target_os = "linux")]
            Commands::Scan { image, scanner } => handle_scan(&image_store, &image, &scanner),
            #[cfg(target_os = "linux")]
            Commands::Compose { file, command } => {
                let volume_store = LocalVolumeStore::open(runtime_dir.join("volumes"))
                    .map_err(|err| err.to_string())?;
                handle_compose(
                    &runtime,
                    &image_store,
                    &volume_store,
                    file.as_deref(),
                    command,
                )
            }
            Commands::Daemon { .. } => {
                unreachable!("daemon command handled before runtime initialization")
            }
            #[cfg(target_os = "linux")]
            Commands::Completion { shell } => handle_completion(&shell),
            Commands::Tui => handle_tui(&runtime),
            Commands::Ai { command } => handle_ai(command),
            Commands::AiTrain {
                model_type,
                data_dir,
                models_dir,
                output,
                format,
            } => handle_ai(AiCommands::Train {
                model_type,
                data_dir,
                models_dir,
                output,
                format,
            }),
            Commands::AiExport {
                model_type,
                output,
                models_dir,
                format,
            } => handle_ai(AiCommands::Export {
                model_type,
                output,
                models_dir,
                format,
            }),
            Commands::AiImport {
                model_type,
                input,
                models_dir,
                format,
            } => handle_ai(AiCommands::Import {
                model_type,
                input,
                models_dir,
                format,
            }),
            Commands::AiStats {
                path,
                model_type,
                models_dir,
                format,
            } => handle_ai(AiCommands::Stats {
                path,
                model_type,
                models_dir,
                format,
            }),
            Commands::AiBranch {
                source,
                target,
                force,
            } => handle_ai(AiCommands::Branch {
                source,
                target,
                force,
            }),
            Commands::AiLineage {
                path,
                parent_file,
                verify,
                format,
            } => handle_ai(AiCommands::Lineage {
                path,
                parent_file,
                verify,
                format,
            }),
            Commands::Entitlement { command } => handle_entitlement(command),
            Commands::Doctor {
                fix,
                bootstrap,
                json,
            } => handle_doctor(fix, bootstrap, json),
            Commands::Config { command } => handle_config(command),
            Commands::AiAudit {
                action,
                summary,
                evidence,
            } => handle_ai_audit(&action, &summary, &evidence),
            Commands::Migrate { target } => handle_migrate(target),
        }
    }

    // Non-Linux: only handle platform-agnostic commands
    #[cfg(not(target_os = "linux"))]
    {
        let image_store_path = std::env::var("FERROCRATE_IMAGE_STORE").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/.ferrocrate/images", home)
        });
        let image_store = LocalImageStore::open(image_store_path).map_err(|err| err.to_string())?;

        match command {
            Commands::Images { format } => handle_images(&image_store, &format),
            Commands::Rmi { image } => handle_rmi(&image_store, &image),
            Commands::ImagePrune => handle_image_prune(&image_store),
            Commands::Pull { image, lazy } => handle_pull(&image_store, &image, lazy),
            Commands::Push { image } => handle_push(&image_store, &image),
            Commands::Ai { command } => handle_ai(command),
            Commands::AiTrain {
                model_type,
                data_dir,
                models_dir,
                output,
                format,
            } => handle_ai(AiCommands::Train {
                model_type,
                data_dir,
                models_dir,
                output,
                format,
            }),
            Commands::AiExport {
                model_type,
                output,
                models_dir,
                format,
            } => handle_ai(AiCommands::Export {
                model_type,
                output,
                models_dir,
                format,
            }),
            Commands::AiImport {
                model_type,
                input,
                models_dir,
                format,
            } => handle_ai(AiCommands::Import {
                model_type,
                input,
                models_dir,
                format,
            }),
            Commands::AiStats {
                path,
                model_type,
                models_dir,
                format,
            } => handle_ai(AiCommands::Stats {
                path,
                model_type,
                models_dir,
                format,
            }),
            Commands::Entitlement { command } => handle_entitlement(command),
            Commands::Doctor {
                fix,
                bootstrap,
                json,
            } => handle_doctor(fix, bootstrap, json),
            Commands::Config { command } => handle_config(command),
            Commands::AiAudit {
                action,
                summary,
                evidence,
            } => handle_ai_audit(&action, &summary, &evidence),
            _ => Err("This command is not supported on this platform".to_string()),
        }
    }
}

fn handle_ai(command: AiCommands) -> Result<(), String> {
    let configured_backend = configured_ai_backend();
    let _backend_guard = ScopedEnv::set("FERROCRATE_AI_BACKEND", configured_backend.as_deref());
    match command {
        AiCommands::Orchestrate {
            task,
            context,
            timeout_secs,
            format,
        } => {
            require_cli_feature(Feature::AiAdvanced)?;
            let response = orchestrate_task(
                &OrchestrateRequest {
                    task: task.clone(),
                    context: context.clone(),
                },
                Some(Duration::from_secs(timeout_secs)),
            );
            let degrade = std::env::var("FERROCRATE_AI_DEGRADE")
                .map(|value| !(value == "0" || value.eq_ignore_ascii_case("false")))
                .unwrap_or(true);
            let response = match response {
                Ok(response) => response,
                Err(err) if degrade => {
                    if format == "json" {
                        let payload = serde_json::json!({
                            "task": task,
                            "context": context,
                            "degraded": true,
                            "error": err.to_string(),
                            "fallback": "local-ai-only",
                            "message": "claude-flow unavailable, continuing without external orchestration",
                        });
                        let text = serde_json::to_string_pretty(&payload)
                            .map_err(|json_err| format!("ai orchestrate: {json_err}"))?;
                        println!("{text}");
                    } else {
                        println!("ai orchestrate: degraded mode enabled");
                        println!("  reason: {}", err);
                        println!("  fallback: local-ai-only");
                        println!("  message: claude-flow unavailable, continuing without external orchestration");
                    }
                    return Ok(());
                }
                Err(err) => return Err(format!("ai orchestrate: {err}")),
            };
            if format == "json" {
                let payload = serde_json::json!({
                    "task": task,
                    "context": context,
                    "raw_response": response.raw_response,
                    "result": response.parsed_result,
                });
                let text = serde_json::to_string_pretty(&payload)
                    .map_err(|err| format!("ai orchestrate: {err}"))?;
                println!("{text}");
                return Ok(());
            }
            if let Some(result) = response.parsed_result {
                println!("ai orchestrate: {}", result);
            } else {
                println!("ai orchestrate: {}", response.raw_response);
            }
            Ok(())
        }
        AiCommands::Train {
            model_type,
            data_dir,
            models_dir,
            output,
            format,
        } => {
            let data_dir_path = data_dir.as_deref().map(Path::new);
            let models_dir_path = models_dir.as_deref().map(Path::new);
            let result = handle_train_command(&model_type, data_dir_path, models_dir_path)
                .map_err(|err| format!("ai train: {err}"))?;
            if let Some(output) = output {
                let output_path = PathBuf::from(output);
                #[cfg(target_os = "linux")]
                {
                    let is_rvf = output_path
                        .extension()
                        .map(|ext| ext.eq_ignore_ascii_case("rvf"))
                        .unwrap_or(false);
                    if is_rvf {
                        handle_export_rvf_command(
                            &model_type,
                            &output_path,
                            data_dir_path,
                            models_dir_path,
                        )
                        .map_err(|err| format!("ai train: {err}"))?;
                    } else {
                        if let Some(parent) = output_path.parent() {
                            std::fs::create_dir_all(parent)
                                .map_err(|err| format!("ai train: {err}"))?;
                        }
                        std::fs::copy(&result.model_path, &output_path)
                            .map_err(|err| format!("ai train: {err}"))?;
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    if let Some(parent) = output_path.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|err| format!("ai train: {err}"))?;
                    }
                    std::fs::copy(&result.model_path, &output_path)
                        .map_err(|err| format!("ai train: {err}"))?;
                }
            }
            if format == "json" {
                let out = serde_json::json!({
                    "model_type": result.model_type.to_string(),
                    "version": result.version,
                    "samples_used": result.samples_used,
                    "duration_ms": result.duration.as_millis(),
                    "loss": result.loss,
                    "model_path": result.model_path,
                });
                let text =
                    serde_json::to_string_pretty(&out).map_err(|err| format!("ai train: {err}"))?;
                println!("{text}");
                return Ok(());
            }
            println!(
                "ai train: model_type={} version={} samples={} loss={:?} path={}",
                result.model_type,
                result.version,
                result.samples_used,
                result.loss,
                result.model_path.display()
            );
            Ok(())
        }
        AiCommands::Export {
            model_type,
            output,
            models_dir,
            format,
        } => {
            let output_path = PathBuf::from(output);
            let models_dir_path = models_dir.as_deref().map(Path::new);
            let is_rvf = output_path
                .extension()
                .map(|ext| ext.eq_ignore_ascii_case("rvf"))
                .unwrap_or(false);
            #[cfg(target_os = "linux")]
            let exported = {
                if is_rvf {
                    handle_export_rvf_command(&model_type, &output_path, None, models_dir_path)
                        .map_err(|err| format!("ai export: {err}"))?
                } else {
                    handle_export_command(&model_type, &output_path, models_dir_path)
                        .map_err(|err| format!("ai export: {err}"))?
                }
            };
            #[cfg(not(target_os = "linux"))]
            let exported = {
                handle_export_command(&model_type, &output_path, models_dir_path)
                    .map_err(|err| format!("ai export: {err}"))?
            };
            if format == "json" {
                let out = serde_json::json!({
                    "model_type": model_type,
                    "output": exported,
                    "format": if is_rvf { "rvf" } else { "native" },
                });
                let text = serde_json::to_string_pretty(&out)
                    .map_err(|err| format!("ai export: {err}"))?;
                println!("{text}");
                return Ok(());
            }
            println!("ai export: wrote {}", exported.display());
            Ok(())
        }
        AiCommands::Import {
            model_type,
            input,
            models_dir,
            format,
        } => {
            let input_path = PathBuf::from(input);
            let models_dir_path = models_dir.as_deref().map(Path::new);
            let version = handle_import_command(&model_type, &input_path, models_dir_path)
                .map_err(|err| format!("ai import: {err}"))?;
            if format == "json" {
                let text = serde_json::to_string_pretty(&version)
                    .map_err(|err| format!("ai import: {err}"))?;
                println!("{text}");
                return Ok(());
            }
            println!(
                "ai import: model_type={} version={} path={}",
                version.model_type,
                version.version,
                version.path.display()
            );
            Ok(())
        }
        AiCommands::Stats {
            path,
            model_type,
            models_dir,
            format,
        } => {
            let models_dir_path = models_dir.as_deref().map(Path::new);
            #[cfg(target_os = "linux")]
            if let Some(path) = path {
                let rvf = handle_rvf_stats_command(Path::new(&path))
                    .map_err(|err| format!("ai stats: {err}"))?;
                if format == "json" {
                    let out = serde_json::to_string_pretty(&rvf)
                        .map_err(|err| format!("ai stats: {err}"))?;
                    println!("{out}");
                    return Ok(());
                }
                println!("ai stats: rvf={}", rvf.path.display());
                println!("  dimensions={}", rvf.dimensions);
                println!("  total_vectors={}", rvf.total_vectors);
                println!("  total_segments={}", rvf.total_segments);
                println!("  file_size={}", rvf.file_size);
                println!("  epoch={}", rvf.epoch);
                println!("  profile_id={}", rvf.profile_id);
                println!("  compaction_state={}", rvf.compaction_state);
                println!("  dead_space_ratio={:.4}", rvf.dead_space_ratio);
                println!("  read_only={}", rvf.read_only);
                println!("  file_id={}", rvf.file_id_hex);
                println!("  parent_id={}", rvf.parent_id_hex);
                println!("  lineage_depth={}", rvf.lineage_depth);
                return Ok(());
            }

            let model_type = model_type.ok_or_else(|| {
                "ai stats: provide --model-type <type> or ai stats <file.rvf>".to_string()
            })?;
            let stats = handle_stats_command(&model_type, models_dir_path)
                .map_err(|err| format!("ai stats: {err}"))?;
            if format == "json" {
                let out = serde_json::to_string_pretty(&stats)
                    .map_err(|err| format!("ai stats: {err}"))?;
                println!("{out}");
                return Ok(());
            }
            println!("ai stats: model_type={}", stats.model_type);
            println!("  versions={}", stats.versions);
            println!("  total_samples={}", stats.total_samples);
            println!("  active_version={:?}", stats.active_version);
            println!(
                "  active_path={}",
                stats
                    .active_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<none>".to_string())
            );
            println!(
                "  last_trained_at={}",
                stats
                    .last_trained_at
                    .unwrap_or_else(|| "<none>".to_string())
            );
            Ok(())
        }
        #[cfg(target_os = "linux")]
        AiCommands::Branch {
            source,
            target,
            force,
        } => {
            let source = PathBuf::from(source);
            let target = PathBuf::from(target);
            if force && target.exists() {
                std::fs::remove_file(&target).map_err(|err| format!("ai branch: {err}"))?;
            }
            let out = handle_rvf_branch_command(&source, &target)
                .map_err(|err| format!("ai branch: {err}"))?;
            println!("ai branch: wrote {}", out.display());
            Ok(())
        }
        #[cfg(target_os = "linux")]
        AiCommands::Lineage {
            path,
            parent_file,
            verify,
            format,
        } => {
            let lineage = handle_rvf_lineage_command(Path::new(&path))
                .map_err(|err| format!("ai lineage: {err}"))?;
            let verification = if verify {
                let report = handle_rvf_verify_command(
                    Path::new(&path),
                    parent_file.as_deref().map(Path::new),
                )
                .map_err(|err| format!("ai lineage: {err}"))?;
                if !report.verified {
                    return Err("ai lineage: verification failed".to_string());
                }
                Some(report)
            } else {
                None
            };
            if format == "json" {
                let payload = if let Some(report) = verification {
                    serde_json::json!({
                        "lineage": lineage,
                        "verification": report,
                    })
                } else {
                    serde_json::json!({
                        "lineage": lineage,
                    })
                };
                let out = serde_json::to_string_pretty(&payload)
                    .map_err(|err| format!("ai lineage: {err}"))?;
                println!("{out}");
                return Ok(());
            }
            println!("ai lineage: rvf={}", lineage.path.display());
            println!("  file_id={}", lineage.file_id_hex);
            println!("  parent_id={}", lineage.parent_id_hex);
            println!("  lineage_depth={}", lineage.lineage_depth);
            println!("  is_root={}", lineage.is_root);
            if verify {
                println!("  verified=true");
                if let Some(report) = verification {
                    if let Some(parent_match) = report.parent_match {
                        println!("  parent_match={parent_match}");
                    }
                }
            }
            Ok(())
        }
        #[cfg(target_os = "linux")]
        AiCommands::Migrate {
            source,
            target,
            force,
        } => {
            let source = source
                .map(PathBuf::from)
                .unwrap_or_else(|| runtime_dir().join("models"));
            let target = target
                .map(PathBuf::from)
                .unwrap_or_else(|| runtime_dir().join("models-rvf"));
            std::fs::create_dir_all(&target).map_err(|err| format!("ai migrate: {err}"))?;
            for model_type in ["resource-predictor", "anomaly-detector", "restart-policy"] {
                let out = target.join(format!("{model_type}.rvf"));
                if out.exists() {
                    if force {
                        std::fs::remove_file(&out).map_err(|err| format!("ai migrate: {err}"))?;
                    } else {
                        return Err(format!(
                            "ai migrate: target exists (use --force): {}",
                            out.display()
                        ));
                    }
                }
                match handle_export_rvf_command(model_type, &out, None, Some(&source)) {
                    Ok(_) => {
                        println!("ai migrate: exported {model_type} -> {}", out.display());
                    }
                    Err(err) => {
                        eprintln!("ai migrate: skipped {model_type}: {err}");
                    }
                }
            }
            Ok(())
        }
        AiCommands::Community { command } => {
            let default_marketplace = PathBuf::from(".ferrocrate").join("community");
            match command {
                AiCommunityCommands::List {
                    marketplace_dir,
                    format,
                } => {
                    let marketplace = marketplace_dir
                        .map(PathBuf::from)
                        .unwrap_or(default_marketplace);
                    let entries = handle_community_list_command(&marketplace)
                        .map_err(|err| format!("ai community list: {err}"))?;
                    if format == "json" {
                        let out = serde_json::to_string_pretty(&entries)
                            .map_err(|err| format!("ai community list: {err}"))?;
                        println!("{out}");
                        return Ok(());
                    }
                    println!("ai community list: {}", marketplace.display());
                    if entries.is_empty() {
                        println!("  <no models>");
                    } else {
                        for entry in entries {
                            println!(
                                "  {} size={}B lineage_depth={} tags={}",
                                entry.name,
                                entry.size_bytes,
                                entry.lineage_depth,
                                if entry.tags.is_empty() {
                                    "<none>".to_string()
                                } else {
                                    entry.tags.join(",")
                                }
                            );
                        }
                    }
                    Ok(())
                }
                AiCommunityCommands::Publish {
                    input,
                    name,
                    description,
                    tags,
                    marketplace_dir,
                    format,
                } => {
                    let marketplace = marketplace_dir
                        .map(PathBuf::from)
                        .unwrap_or(default_marketplace);
                    let description =
                        description.unwrap_or_else(|| "Community shared model".to_string());
                    let out = handle_community_publish_command(
                        Path::new(&input),
                        &name,
                        &description,
                        &tags,
                        &marketplace,
                    )
                    .map_err(|err| format!("ai community publish: {err}"))?;
                    if format == "json" {
                        let payload = serde_json::json!({
                            "name": name,
                            "artifact": out,
                            "marketplace_dir": marketplace,
                        });
                        let text = serde_json::to_string_pretty(&payload)
                            .map_err(|err| format!("ai community publish: {err}"))?;
                        println!("{text}");
                        return Ok(());
                    }
                    println!("ai community publish: {} -> {}", name, out.display());
                    Ok(())
                }
                AiCommunityCommands::Download {
                    name,
                    output,
                    marketplace_dir,
                    format,
                } => {
                    let marketplace = marketplace_dir
                        .map(PathBuf::from)
                        .unwrap_or(default_marketplace);
                    let out =
                        handle_community_download_command(&name, Path::new(&output), &marketplace)
                            .map_err(|err| format!("ai community download: {err}"))?;
                    if format == "json" {
                        let payload = serde_json::json!({
                            "name": name,
                            "output": out,
                            "marketplace_dir": marketplace,
                        });
                        let text = serde_json::to_string_pretty(&payload)
                            .map_err(|err| format!("ai community download: {err}"))?;
                        println!("{text}");
                        return Ok(());
                    }
                    println!("ai community download: {} -> {}", name, out.display());
                    Ok(())
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(target_os = "linux")]
fn handle_run(
    runtime_dir: &Path,
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    volume_store: &LocalVolumeStore,
    image: &str,
    cmd: &[String],
    network: &str,
    network_backend: &str,
    bind_mounts: &[String],
    tmpfs_mounts: &[String],
    volumes: &[String],
    read_only_rootfs: bool,
    no_new_privs: bool,
    env: &[String],
    labels: &[String],
    annotations: &[String],
    cap_add: &[String],
    entrypoint: Option<&str>,
    workdir: Option<&str>,
    user: Option<&str>,
    name: Option<&str>,
    publish: &[String],
    health_cmd: Option<&str>,
    health_interval: Option<u64>,
    health_timeout: Option<u64>,
    health_retries: Option<u32>,
    health_start_period: Option<u64>,
    restart_policy: &str,
    rm: bool,
    bridge_cidr: Option<&str>,
    bridge_name: Option<&str>,
    net_limit: Option<&str>,
    memory_max: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
    pids_max: Option<u64>,
    ai_model: Option<&str>,
) -> Result<(), String> {
    let mut effective_network = network.to_string();
    if effective_network == "encrypted" {
        effective_network = "wireguard".to_string();
    }
    let mut resolved_bridge_cidr = bridge_cidr.map(|val| val.to_string());
    let mut resolved_bridge_name = bridge_name.map(|val| val.to_string());
    let selected_network_name = if is_builtin_network_mode(&effective_network) {
        validate_network_mode(&effective_network)?;
        if effective_network == "bridge" {
            Some("bridge".to_string())
        } else {
            Some(effective_network.clone())
        }
    } else {
        let named = resolve_named_network(runtime_dir, network)?;
        effective_network = "bridge".to_string();
        if resolved_bridge_cidr.is_none() {
            resolved_bridge_cidr = Some(named.bridge_cidr.clone());
        }
        if resolved_bridge_name.is_none() {
            resolved_bridge_name = Some(named.bridge_name.clone());
        }
        Some(named.name)
    };
    let _bridge_cidr_guard =
        ScopedEnv::set("FERROCRATE_BRIDGE_CIDR", resolved_bridge_cidr.as_deref());
    let _bridge_name_guard =
        ScopedEnv::set("FERROCRATE_BRIDGE_NAME", resolved_bridge_name.as_deref());
    let _network_name_guard =
        ScopedEnv::set("FERROCRATE_NETWORK_NAME", selected_network_name.as_deref());
    let _net_limit_guard = ScopedEnv::set("FERROCRATE_BANDWIDTH_LIMIT", net_limit);
    let configured_backend = configured_ai_backend();
    let _backend_guard = ScopedEnv::set("FERROCRATE_AI_BACKEND", configured_backend.as_deref());
    let _model_guard = ScopedEnv::set("FERROCRATE_AI_MODEL", ai_model);
    let mut effective_backend = network_backend.to_string();
    if !publish.is_empty() && effective_network != "bridge" {
        return Err("run: publish requires --network bridge".to_string());
    }
    if !publish.is_empty() && effective_backend == "ebpf" {
        effective_backend = "iptables".to_string();
    }
    validate_network_backend(&effective_backend)?;
    ensure_image_present(store, image)?;
    let limits = build_limits(memory_max, cpu_quota, cpu_period, pids_max)?;
    let mounts = parse_bind_mounts(bind_mounts)?;
    let volume_mounts = parse_volume_mounts(volume_store, volumes)?;
    let mut mounts = mounts;
    mounts.extend(volume_mounts);
    let tmpfs = parse_tmpfs_mounts(tmpfs_mounts)?;
    let env = parse_env_entries(env)?;
    let labels = parse_key_values("label", labels)?;
    let annotations = parse_key_values("annotation", annotations)?;
    let caps = parse_capabilities(cap_add)?;
    let port_mappings = parse_publish(publish)?;
    let health = build_health_config(
        health_cmd,
        health_interval,
        health_timeout,
        health_retries,
        health_start_period,
    )?;
    let restart_policy = parse_restart_policy(restart_policy)?;
    let effective_cmd = if let Some(entry) = entrypoint {
        let mut out = parse_entrypoint(entry)?;
        out.extend_from_slice(cmd);
        out
    } else {
        cmd.to_vec()
    };

    let record = runtime
        .run_with_store(
            store,
            image,
            &effective_cmd,
            &env,
            &labels,
            &annotations,
            health,
            restart_policy,
            &caps,
            limits.as_ref(),
            &mounts,
            &tmpfs,
            read_only_rootfs,
            no_new_privs,
            workdir,
            user,
            name,
            &port_mappings,
            &effective_network,
            &effective_backend,
        )
        .map_err(|err| err.to_string())?;
    println!(
        "run: container_id={} pid={} network_backend={}",
        record.id, record.pid, effective_backend
    );
    if rm {
        wait_for_container_exit(runtime, &record.id)?;
        runtime.remove(&record.id).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn handle_completion(shell: &str) -> Result<(), String> {
    let shell = parse_shell(shell)?;
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "ferrocrate", &mut std::io::stdout());
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_tui(runtime: &ContainerRuntime) -> Result<(), String> {
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut input = String::new();
        loop {
            input.clear();
            if std::io::stdin().read_line(&mut input).is_err() {
                break;
            }
            if tx.send(input.trim().to_string()).is_err() {
                break;
            }
        }
    });

    loop {
        print!("\x1b[2J\x1b[H");
        println!("FerroCrate TUI (press q + Enter to quit)");
        println!(
            "{:<20} {:<12} {:<20} COMMAND",
            "CONTAINER", "STATUS", "IMAGE"
        );
        let containers = runtime.list().map_err(|err| err.to_string())?;
        for record in containers {
            let name = record.name.unwrap_or(record.id);
            let cmd = record.command.join(" ");
            println!(
                "{:<20} {:<12} {:<20} {}",
                name, record.status, record.image, cmd
            );
        }
        if let Ok(msg) = rx.try_recv() {
            if msg.eq_ignore_ascii_case("q") {
                break;
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

fn handle_ai_audit(action: &str, summary: &str, evidence: &[String]) -> Result<(), String> {
    let logger = AuditLogger::from_env()
        .ok_or_else(|| "ai-audit: FERROCRATE_AI_AUDIT_LOG not set or AI disabled".to_string())?;
    let trace_id = format!(
        "manual-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let mut trace = DecisionTrace::new(trace_id.clone(), summary);
    for entry in evidence {
        if let Some((key, value)) = entry.split_once('=') {
            trace = trace.with_evidence(key, value);
        }
    }
    logger
        .log(action, &trace)
        .map_err(|err| format!("ai-audit: {err}"))?;
    println!("ai-audit: logged action='{action}' trace_id='{trace_id}'");
    Ok(())
}

fn parse_shell(value: &str) -> Result<Shell, String> {
    match value.to_lowercase().as_str() {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        "powershell" | "pwsh" => Ok(Shell::PowerShell),
        "elvish" => Ok(Shell::Elvish),
        other => Err(format!("completion: unsupported shell {other}")),
    }
}

fn handle_migrate(target: MigrateCommands) -> Result<(), String> {
    match target {
        MigrateCommands::DockerAuth { output } => handle_migrate_docker_auth(output.as_deref()),
    }
}

fn handle_config(command: ConfigCommands) -> Result<(), String> {
    match command {
        ConfigCommands::Set { key, value } => {
            let mut config = load_cli_config()?;
            match key.as_str() {
                "ai.backend" => {
                    let normalized = value.to_lowercase();
                    if normalized != "rvf" && normalized != "legacy" {
                        return Err("config set: ai.backend must be 'rvf' or 'legacy'".to_string());
                    }
                    config.ai_backend = Some(normalized);
                }
                _ => {
                    return Err(format!(
                        "config set: unsupported key '{}'. supported: ai.backend",
                        key
                    ))
                }
            }
            save_cli_config(&config)?;
            Ok(())
        }
        ConfigCommands::Get { key } => {
            let config = load_cli_config()?;
            match key.as_str() {
                "ai.backend" => {
                    if let Some(value) = config.ai_backend {
                        println!("{value}");
                    } else {
                        println!("<unset>");
                    }
                    Ok(())
                }
                _ => Err(format!(
                    "config get: unsupported key '{}'. supported: ai.backend",
                    key
                )),
            }
        }
    }
}

fn handle_entitlement(command: EntitlementCommands) -> Result<(), String> {
    match command {
        EntitlementCommands::Status { json } => {
            let path = entitlements::default_entitlement_path();
            let loaded = entitlements::load_entitlement_from_env();
            match loaded {
                Ok(Some(entitlement)) => {
                    if json {
                        let out = serde_json::json!({
                            "status": "ok",
                            "path": path,
                            "plan": entitlement.plan.as_str(),
                            "subject": entitlement.subject,
                            "issued_at": entitlement.issued_at,
                            "expires_at": entitlement.expires_at,
                            "features": entitlement
                                .features
                                .iter()
                                .map(|feature| feature.as_str())
                                .collect::<Vec<_>>(),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&out)
                                .map_err(|err| format!("entitlement status: {err}"))?
                        );
                    } else {
                        println!("entitlement: valid");
                        println!("  plan={}", entitlement.plan.as_str());
                        println!(
                            "  subject={}",
                            entitlement.subject.unwrap_or_else(|| "<none>".to_string())
                        );
                        println!(
                            "  expires_at={}",
                            entitlement
                                .expires_at
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "<none>".to_string())
                        );
                        println!("  path={}", path.display());
                    }
                    Ok(())
                }
                Ok(None) => {
                    if json {
                        let out = serde_json::json!({
                            "status": "none",
                            "path": path,
                            "plan": "free",
                            "message": "no entitlement file found; paid features unavailable",
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&out)
                                .map_err(|err| format!("entitlement status: {err}"))?
                        );
                    } else {
                        println!("entitlement: none (plan=free)");
                        println!("  path={}", path.display());
                        println!("  message=no entitlement file found; paid features unavailable");
                    }
                    Ok(())
                }
                Err(err) => Err(format!("entitlement status: {err}")),
            }
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CliConfig {
    ai_backend: Option<String>,
}

fn config_path() -> PathBuf {
    runtime_dir().join("config.json")
}

fn load_cli_config() -> Result<CliConfig, String> {
    let path = config_path();
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let raw = std::fs::read_to_string(&path).map_err(|err| format!("config: {err}"))?;
    serde_json::from_str(&raw).map_err(|err| format!("config: {err}"))
}

fn save_cli_config(config: &CliConfig) -> Result<(), String> {
    let path = config_path();
    let raw = serde_json::to_string_pretty(config).map_err(|err| format!("config: {err}"))?;
    ferro_core::fs_atomic::write_atomic(&path, raw.as_bytes())
        .map_err(|err| format!("config: {err}"))
}

fn configured_ai_backend() -> Option<String> {
    if std::env::var("FERROCRATE_AI_BACKEND").is_ok() {
        return None;
    }
    load_cli_config().ok().and_then(|cfg| cfg.ai_backend)
}

fn handle_migrate_docker_auth(output: Option<&str>) -> Result<(), String> {
    let auths = ferro_core::docker_auth::export_docker_auths()
        .map_err(|err| format!("migrate docker-auth: {err}"))?;
    if auths.is_empty() {
        return Err("migrate docker-auth: no entries found".to_string());
    }
    let path = if let Some(output) = output {
        PathBuf::from(output)
    } else {
        ferro_core::docker_auth::ferrocrate_auth_path()
            .ok_or_else(|| "migrate docker-auth: HOME not set".to_string())?
    };
    ferro_core::docker_auth::write_ferrocrate_auth_file(&path, &auths)
        .map_err(|err| format!("migrate docker-auth: {err}"))?;
    Ok(())
}

struct ScopedEnv {
    key: String,
    original: Option<String>,
}

impl ScopedEnv {
    fn set(key: &str, value: Option<&str>) -> Self {
        let original = std::env::var(key).ok();
        if let Some(value) = value {
            unsafe {
                std::env::set_var(key, value);
            }
        }
        Self {
            key: key.to_string(),
            original,
        }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            unsafe {
                std::env::set_var(&self.key, value);
            }
        } else {
            unsafe {
                std::env::remove_var(&self.key);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_container_exit(runtime: &ContainerRuntime, id: &str) -> Result<(), String> {
    loop {
        let record = runtime.inspect(id).map_err(|err| err.to_string())?;
        match record.status.as_str() {
            "running" | "paused" => {
                std::thread::sleep(Duration::from_millis(200));
            }
            _ => return Ok(()),
        }
    }
}

fn latest_mtime(root: &Path) -> Result<SystemTime, String> {
    let mut latest = SystemTime::UNIX_EPOCH;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = std::fs::read_dir(&path).map_err(|err| format!("watch: {err}"))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("watch: {err}"))?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == ".git" || name == "target" || name == ".ferrocrate" {
                continue;
            }
            let meta = entry.metadata().map_err(|err| format!("watch: {err}"))?;
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                if let Ok(mtime) = meta.modified() {
                    if mtime > latest {
                        latest = mtime;
                    }
                }
            }
        }
    }
    Ok(latest)
}

#[cfg(target_os = "linux")]
fn parse_bind_mounts(bind_mounts: &[String]) -> Result<Vec<ferro_core::mounts::BindMount>, String> {
    let mut out = Vec::new();
    for entry in bind_mounts {
        let parts = entry.split(':').collect::<Vec<_>>();
        if parts.len() < 2 {
            return Err("run: bind mount must be source:target[:ro]".to_string());
        }
        let read_only = parts.len() >= 3 && parts[2] == "ro";
        let source = parts[0];
        let target = parts[1];
        out.push(ferro_core::mounts::BindMount {
            source: source.into(),
            target: target.trim_start_matches('/').into(),
            read_only,
        });
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn parse_volume_mounts(
    volume_store: &LocalVolumeStore,
    volumes: &[String],
) -> Result<Vec<ferro_core::mounts::BindMount>, String> {
    let mut out = Vec::new();
    for entry in volumes {
        let parts = entry.split(':').collect::<Vec<_>>();
        if parts.len() < 2 {
            return Err("run: volume must be source:target[:ro]".to_string());
        }
        let read_only = parts.len() >= 3 && parts[2] == "ro";
        let source = parts[0];
        let target = parts[1];

        let source_path = if source.starts_with('/') {
            source.to_string()
        } else {
            let record = match volume_store.get(source).map_err(|err| err.to_string())? {
                Some(record) => record,
                None => volume_store.create(source).map_err(|err| err.to_string())?,
            };
            record.path
        };

        out.push(ferro_core::mounts::BindMount {
            source: source_path.into(),
            target: target.trim_start_matches('/').into(),
            read_only,
        });
    }
    Ok(out)
}

fn parse_publish(
    entries: &[String],
) -> Result<Vec<ferro_core::container_store::PortMappingRecord>, String> {
    let mut out = Vec::new();
    for entry in entries {
        let mut parts = entry.splitn(2, '/');
        let ports = parts.next().unwrap_or("");
        let proto = parts.next().unwrap_or("tcp");
        let proto = proto.to_ascii_lowercase();
        if proto != "tcp" && proto != "udp" {
            return Err("run: publish protocol must be tcp or udp".to_string());
        }

        let port_parts = ports.split(':').collect::<Vec<_>>();
        if port_parts.len() != 2 {
            return Err("run: publish must be host:container[/proto]".to_string());
        }
        let host_port = port_parts[0]
            .parse::<u16>()
            .map_err(|_| "run: invalid host port".to_string())?;
        let container_port = port_parts[1]
            .parse::<u16>()
            .map_err(|_| "run: invalid container port".to_string())?;
        out.push(ferro_core::container_store::PortMappingRecord {
            host_port,
            container_port,
            protocol: proto,
        });
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn parse_tmpfs_mounts(
    tmpfs_mounts: &[String],
) -> Result<Vec<ferro_core::mounts::TmpfsMount>, String> {
    let mut out = Vec::new();
    for entry in tmpfs_mounts {
        let parts = entry.split(':').collect::<Vec<_>>();
        if parts.is_empty() || parts[0].is_empty() {
            return Err("run: tmpfs must be target[:size=...]".to_string());
        }
        let size = parts
            .get(1)
            .map(|val| val.trim_start_matches("size=").to_string());
        out.push(ferro_core::mounts::TmpfsMount {
            target: parts[0].trim_start_matches('/').into(),
            size,
        });
    }
    Ok(out)
}

fn ensure_image_present(store: &LocalImageStore, image: &str) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    let canonical = canonicalize_reference(image).map_err(|err| err.to_string())?;
    let existing = resolve_reference(store, &canonical).map_err(|err| err.to_string())?;
    if existing.is_some() {
        return Ok(());
    }
    let runtime_dir = runtime_dir();
    ferro_core::image_fetch::pull_image_with_store(&runtime_dir, &canonical, store)
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn build_limits(
    memory_max: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
    pids_max: Option<u64>,
) -> Result<Option<ferro_core::cgroups::ResourceLimits>, String> {
    if memory_max.is_none() && cpu_quota.is_none() && cpu_period.is_none() && pids_max.is_none() {
        return Ok(None);
    }

    if cpu_quota.is_some() && cpu_period.is_none() {
        return Err("run: cpu-period is required when cpu-quota is set".to_string());
    }

    let cpu_max = match (cpu_quota, cpu_period) {
        (Some(quota), Some(period)) => Some(ferro_core::cgroups::CpuMax { quota, period }),
        _ => None,
    };

    Ok(Some(ferro_core::cgroups::ResourceLimits {
        memory_max,
        cpu_max,
        pids_max,
    }))
}

#[cfg(target_os = "linux")]
fn handle_build(
    store: &LocalImageStore,
    dockerfile: Option<&str>,
    ferrofile: Option<&str>,
    tag: Option<&str>,
    compression: &str,
) -> Result<(), String> {
    let runtime_dir = runtime_dir();
    let compression = parse_compression(compression)?;
    if let Some(ferrofile_path) = ferrofile {
        let result = ferro_core::ferrofile_build::build_from_ferrofile_with_store(
            Path::new(ferrofile_path),
            &runtime_dir,
            compression,
            Some(store),
        )
        .map_err(|err| err.to_string())?;
        println!(
            "build: ferrofile={} tag={} layer_digest={} config_digest={}",
            ferrofile_path, result.reference, result.layer_digest, result.config_digest
        );
        return Ok(());
    }

    let dockerfile = dockerfile.ok_or_else(|| "build: dockerfile path is required".to_string())?;
    let tag = tag.unwrap_or("local/build:latest");
    parse_image_reference(tag).map_err(|err| err.to_string())?;

    let result = ferro_core::dockerfile_build::build_from_dockerfile_with_store_and_compression(
        Path::new(dockerfile),
        Some(tag),
        &runtime_dir,
        compression,
        store,
    )
    .map_err(|err| err.to_string())?;

    println!(
        "build: dockerfile={} tag={} layer_digest={} config_digest={}",
        dockerfile, result.reference, result.layer_digest, result.config_digest
    );
    Ok(())
}

fn validate_network_backend(value: &str) -> Result<(), String> {
    match value {
        "ebpf" | "iptables" | "nftables" => Ok(()),
        _ => Err("network-backend must be one of: ebpf, iptables, nftables".to_string()),
    }
}

fn validate_network_mode(value: &str) -> Result<(), String> {
    match value {
        "bridge" | "host" | "none" | "wireguard" | "encrypted" => Ok(()),
        _ => Err("network must be one of: bridge, host, none, wireguard, encrypted".to_string()),
    }
}

fn validate_output_format(value: &str) -> Result<String, String> {
    match value {
        "text" | "json" => Ok(value.to_string()),
        _ => Err("format must be one of: text, json".to_string()),
    }
}

fn parse_entrypoint(value: &str) -> Result<Vec<String>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("run: entrypoint must not be empty".to_string());
    }
    Ok(trimmed.split_whitespace().map(|s| s.to_string()).collect())
}

fn command_exists(bin: &str) -> bool {
    process::Command::new(bin).arg("--version").output().is_ok()
}

fn validate_compression(value: &str) -> Result<String, String> {
    match value {
        "gzip" | "zstd" => Ok(value.to_string()),
        _ => Err("compress must be one of: gzip, zstd".to_string()),
    }
}

fn parse_compression(value: &str) -> Result<CompressionFormat, String> {
    match value {
        "gzip" => Ok(CompressionFormat::Gzip),
        "zstd" => Ok(CompressionFormat::Zstd),
        _ => Err("compress must be one of: gzip, zstd".to_string()),
    }
}

fn color_status(status: &str) -> String {
    match status {
        "running" => status.green().to_string(),
        "paused" => status.yellow().to_string(),
        "stopped" | "exited" | "killed" => status.red().to_string(),
        other => other.blue().to_string(),
    }
}

fn handle_images(store: &LocalImageStore, format: &str) -> Result<(), String> {
    let records = store.list_references().map_err(|err| err.to_string())?;
    if format == "json" {
        let json = serde_json::to_string_pretty(&records).map_err(|err| err.to_string())?;
        println!("{json}");
        return Ok(());
    }
    if records.is_empty() {
        println!("images: no entries");
        return Ok(());
    }
    for record in records {
        println!("{} {}", record.reference.cyan(), record.digest);
    }
    Ok(())
}

fn handle_rmi(store: &LocalImageStore, image: &str) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    let removed = store
        .remove_reference(image)
        .map_err(|err| err.to_string())?;
    if removed {
        println!("rmi: removed {image}");
    } else {
        println!("rmi: not found {image}");
    }
    Ok(())
}

fn handle_image_prune(store: &LocalImageStore) -> Result<(), String> {
    let removed = store.prune_references().map_err(|err| err.to_string())?;
    println!("image prune: removed={removed}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_containers(runtime: &ContainerRuntime, format: &str) -> Result<(), String> {
    let records = runtime.list().map_err(|err| err.to_string())?;
    if format == "json" {
        let json = serde_json::to_string_pretty(&records).map_err(|err| err.to_string())?;
        println!("{json}");
        return Ok(());
    }
    if records.is_empty() {
        println!("containers: no entries");
        return Ok(());
    }
    for record in records {
        let name = record.name.clone().unwrap_or_else(|| "-".to_string());
        println!(
            "{} {} {} {}",
            record.id.bold(),
            record.image.cyan(),
            color_status(&record.status),
            name
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_logs(runtime: &ContainerRuntime, container: &str, format: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("logs: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let logs = runtime.logs(&resolved).map_err(|err| err.to_string())?;
    if format == "json" {
        let output = serde_json::json!({
            "container": resolved,
            "logs": logs,
        });
        let json = serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?;
        println!("{json}");
        return Ok(());
    }
    print!("{logs}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_inspect(runtime: &ContainerRuntime, container: &str, format: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("inspect: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let record = runtime.inspect(&resolved).map_err(|err| err.to_string())?;
    if format == "json" {
        let json = serde_json::to_string_pretty(&record).map_err(|err| err.to_string())?;
        println!("{json}");
    } else {
        println!(
            "id={} image={} status={} pid={} name={}",
            record.id.bold(),
            record.image.cyan(),
            color_status(&record.status),
            record.pid,
            record.name.clone().unwrap_or_else(|| "-".to_string()),
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct StatsOutput {
    container: String,
    stats: ferro_core::cgroups::CgroupStats,
}

#[cfg(target_os = "linux")]
fn handle_stats(runtime: &ContainerRuntime, container: &str, format: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("stats: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let stats = runtime.stats(&resolved).map_err(|err| err.to_string())?;
    if format == "json" {
        let output = StatsOutput {
            container: resolved.clone(),
            stats,
        };
        let json = serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?;
        println!("{json}");
    } else {
        println!(
            "container={} mem_current={} mem_max={} pids_current={} cpu_usage_usec={} cpu_user_usec={} cpu_system_usec={}",
            resolved,
            stats.memory_current.map(|v| v.to_string()).unwrap_or_else(|| "n/a".to_string()),
            stats.memory_max.map(|v| v.to_string()).unwrap_or_else(|| "max".to_string()),
            stats.pids_current.map(|v| v.to_string()).unwrap_or_else(|| "n/a".to_string()),
            stats.cpu_usage_usec.map(|v| v.to_string()).unwrap_or_else(|| "n/a".to_string()),
            stats.cpu_user_usec.map(|v| v.to_string()).unwrap_or_else(|| "n/a".to_string()),
            stats.cpu_system_usec.map(|v| v.to_string()).unwrap_or_else(|| "n/a".to_string()),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_pause(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("pause: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.pause(&resolved).map_err(|err| err.to_string())?;
    println!("pause: {resolved}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_unpause(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("unpause: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.resume(&resolved).map_err(|err| err.to_string())?;
    println!("unpause: {resolved}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_stop(runtime: &ContainerRuntime, container: &str, timeout: u64) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("stop: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime
        .stop(&resolved, std::time::Duration::from_secs(timeout))
        .map_err(|err| err.to_string())?;
    println!("stop: {resolved}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_kill(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("kill: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.kill(&resolved).map_err(|err| err.to_string())?;
    println!("kill: {resolved}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_rm(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("rm: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.remove(&resolved).map_err(|err| err.to_string())?;
    println!("rm: {resolved}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_restart(runtime: &ContainerRuntime, container: &str, timeout: u64) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("restart: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime
        .restart(&resolved, std::time::Duration::from_secs(timeout))
        .map_err(|err| err.to_string())?;
    println!("restart: {resolved}");
    Ok(())
}

fn handle_volume(runtime_dir: &Path, command: VolumeCommands) -> Result<(), String> {
    let store = ferro_core::volume_store::LocalVolumeStore::open(runtime_dir.join("volumes"))
        .map_err(|err| err.to_string())?;
    match command {
        VolumeCommands::Create { name, driver, opts } => {
            let driver_opts = parse_driver_opts(&opts)?;
            let record = store
                .create_with_driver(&name, &driver, driver_opts)
                .map_err(|err| err.to_string())?;
            println!("volume create: {} {}", record.name, record.path);
        }
        VolumeCommands::Backup { name, path } => {
            store.backup(&name, &path).map_err(|err| err.to_string())?;
            println!("volume backup: {name} -> {path}");
        }
        VolumeCommands::Restore { name, path } => {
            if store.get(&name).map_err(|err| err.to_string())?.is_none() {
                store.create(&name).map_err(|err| err.to_string())?;
            }
            store.restore(&name, &path).map_err(|err| err.to_string())?;
            println!("volume restore: {name} <- {path}");
        }
        VolumeCommands::Ls => {
            let records = store.list().map_err(|err| err.to_string())?;
            if records.is_empty() {
                println!("volumes: no entries");
            } else {
                for record in records {
                    println!("{} {}", record.name, record.path);
                }
            }
        }
        VolumeCommands::Rm { name } => {
            let removed = store.remove(&name).map_err(|err| err.to_string())?;
            if removed {
                println!("volume rm: {name}");
            } else {
                println!("volume rm: not found {name}");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkRecord {
    name: String,
    driver: String,
    subnet: String,
    gateway: String,
    bridge_name: String,
    bridge_cidr: String,
    created_at_unix: u64,
}

fn is_builtin_network_mode(value: &str) -> bool {
    matches!(value, "bridge" | "host" | "none" | "wireguard")
}

fn network_store_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("networks").join("networks.json")
}

fn load_networks(runtime_dir: &Path) -> Result<Vec<NetworkRecord>, String> {
    let path = network_store_path(runtime_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("network: failed to read {}: {err}", path.display()))?;
    serde_json::from_str::<Vec<NetworkRecord>>(&content)
        .map_err(|err| format!("network: failed to parse {}: {err}", path.display()))
}

fn save_networks(runtime_dir: &Path, records: &[NetworkRecord]) -> Result<(), String> {
    let path = network_store_path(runtime_dir);
    let payload = serde_json::to_string_pretty(records)
        .map_err(|err| format!("network: failed to encode store: {err}"))?;
    ferro_core::fs_atomic::write_atomic(&path, payload.as_bytes())
        .map_err(|err| format!("network: failed to write {}: {err}", path.display()))
}

fn validate_network_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("network: name is required".to_string());
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    {
        return Err("network: name must be [a-zA-Z0-9_.-]".to_string());
    }
    Ok(())
}

fn parse_ipv4_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let (ip_part, prefix_part) = cidr
        .split_once('/')
        .ok_or_else(|| format!("network: invalid CIDR {cidr}"))?;
    let ip = ip_part
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("network: invalid CIDR {cidr}"))?;
    let prefix = prefix_part
        .parse::<u8>()
        .map_err(|_| format!("network: invalid CIDR {cidr}"))?;
    if prefix > 32 {
        return Err(format!("network: invalid CIDR {cidr}"));
    }
    Ok((ip, prefix))
}

fn ipv4_to_u32(addr: Ipv4Addr) -> u32 {
    u32::from(addr)
}

fn u32_to_ipv4(value: u32) -> Ipv4Addr {
    Ipv4Addr::from(value)
}

fn subnet_network_addr(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32_to_ipv4(ipv4_to_u32(addr) & mask)
}

fn ip_in_subnet(addr: Ipv4Addr, subnet: Ipv4Addr, prefix: u8) -> bool {
    subnet_network_addr(addr, prefix) == subnet
}

fn default_gateway_for_subnet(subnet: Ipv4Addr) -> Ipv4Addr {
    u32_to_ipv4(ipv4_to_u32(subnet).saturating_add(1))
}

fn bridge_name_for_network(name: &str) -> String {
    let normalized = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let mut bridge = format!("fc-{normalized}");
    if bridge.len() > 15 {
        bridge.truncate(15);
    }
    bridge
}

fn create_network_record(
    name: &str,
    subnet: Option<&str>,
    gateway: Option<&str>,
) -> Result<NetworkRecord, String> {
    validate_network_name(name)?;
    let subnet = subnet.unwrap_or("172.20.0.0/16");
    let (subnet_ip, prefix) = parse_ipv4_cidr(subnet)?;
    let network_ip = subnet_network_addr(subnet_ip, prefix);
    let gateway_ip = match gateway {
        Some(value) => value
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("network: invalid gateway {value}"))?,
        None => default_gateway_for_subnet(network_ip),
    };
    if !ip_in_subnet(gateway_ip, network_ip, prefix) {
        return Err(format!(
            "network: gateway {gateway_ip} is outside subnet {network_ip}/{prefix}"
        ));
    }
    Ok(NetworkRecord {
        name: name.to_string(),
        driver: "bridge".to_string(),
        subnet: format!("{network_ip}/{prefix}"),
        gateway: gateway_ip.to_string(),
        bridge_name: bridge_name_for_network(name),
        bridge_cidr: format!("{gateway_ip}/{prefix}"),
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    })
}

fn resolve_named_network(runtime_dir: &Path, name: &str) -> Result<NetworkRecord, String> {
    let records = load_networks(runtime_dir)?;
    records
        .into_iter()
        .find(|record| record.name == name)
        .ok_or_else(|| format!("network: not found {name}"))
}

#[cfg(target_os = "linux")]
fn handle_network(
    runtime_dir: &Path,
    runtime: &ContainerRuntime,
    command: NetworkCommands,
) -> Result<(), String> {
    match command {
        NetworkCommands::Create {
            name,
            subnet,
            gateway,
        } => {
            if is_builtin_network_mode(&name) {
                return Err(format!("network: reserved name {name}"));
            }
            let mut records = load_networks(runtime_dir)?;
            if records.iter().any(|record| record.name == name) {
                return Err(format!("network: already exists {name}"));
            }
            let record = create_network_record(&name, subnet.as_deref(), gateway.as_deref())?;
            records.push(record.clone());
            records.sort_by(|a, b| a.name.cmp(&b.name));
            save_networks(runtime_dir, &records)?;
            println!(
                "network create: name={} driver={} subnet={} gateway={}",
                record.name, record.driver, record.subnet, record.gateway
            );
        }
        NetworkCommands::Ls => {
            let records = load_networks(runtime_dir)?;
            println!("NAME\tDRIVER\tSUBNET\tGATEWAY");
            println!("bridge\tbridge\t10.0.0.0/24\t10.0.0.1");
            for record in records {
                println!(
                    "{}\t{}\t{}\t{}",
                    record.name, record.driver, record.subnet, record.gateway
                );
            }
        }
        NetworkCommands::Rm { name } => {
            if is_builtin_network_mode(&name) {
                return Err(format!("network: cannot remove builtin network {name}"));
            }
            let running = runtime.list().map_err(|err| err.to_string())?;
            if running.iter().any(|record| {
                record.status == "running" && record.network_name.as_deref() == Some(name.as_str())
            }) {
                return Err(format!("network: in use by running containers {name}"));
            }
            let mut records = load_networks(runtime_dir)?;
            let before = records.len();
            records.retain(|record| record.name != name);
            if records.len() == before {
                return Err(format!("network: not found {name}"));
            }
            save_networks(runtime_dir, &records)?;
            println!("network rm: {name}");
        }
    }
    Ok(())
}

fn parse_driver_opts(opts: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for entry in opts {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if key.is_empty() || value.is_empty() {
            return Err("volume: opt must be key=value".to_string());
        }
        out.insert(key.to_string(), value.to_string());
    }
    Ok(out)
}

fn parse_env_entries(envs: &[String]) -> Result<Vec<String>, String> {
    for entry in envs {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next();
        if key.is_empty() || value.is_none() {
            return Err("run: env must be KEY=VALUE".to_string());
        }
    }
    Ok(envs.to_vec())
}

fn parse_key_values(kind: &str, entries: &[String]) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    for entry in entries {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if key.is_empty() || value.is_empty() {
            return Err(format!("{kind}: must be key=value"));
        }
        out.insert(key.to_string(), value.to_string());
    }
    Ok(out)
}

fn build_health_config(
    health_cmd: Option<&str>,
    health_interval: Option<u64>,
    health_timeout: Option<u64>,
    health_retries: Option<u32>,
    health_start_period: Option<u64>,
) -> Result<Option<ferro_core::container_store::HealthConfig>, String> {
    let has_overrides = health_interval.is_some()
        || health_timeout.is_some()
        || health_retries.is_some()
        || health_start_period.is_some();
    let Some(cmd) = health_cmd else {
        if has_overrides {
            return Err("run: health-cmd is required when health options are set".to_string());
        }
        return Ok(None);
    };
    if cmd.trim().is_empty() {
        return Err("run: health-cmd must not be empty".to_string());
    }
    Ok(Some(ferro_core::container_store::HealthConfig {
        cmd: vec!["/bin/sh".to_string(), "-c".to_string(), cmd.to_string()],
        interval_secs: health_interval.unwrap_or(30),
        timeout_secs: health_timeout.unwrap_or(5),
        retries: health_retries.unwrap_or(3),
        start_period_secs: health_start_period.unwrap_or(0),
    }))
}

fn effective_readonly(profile: &str, read_only: bool, read_write: bool) -> Result<bool, String> {
    if read_only && read_write {
        return Err("run: cannot set both --read-only and --read-write".to_string());
    }
    if read_only {
        return Ok(true);
    }
    if read_write {
        return Ok(false);
    }
    match profile {
        "prod" => Ok(true),
        "dev" => Ok(false),
        _ => Err("run: profile must be dev|prod".to_string()),
    }
}

fn parse_restart_policy(
    policy: &str,
) -> Result<ferro_core::container_store::RestartPolicy, String> {
    match policy {
        "no" => Ok(ferro_core::container_store::RestartPolicy::No),
        "on-failure" => Ok(ferro_core::container_store::RestartPolicy::OnFailure),
        "always" => Ok(ferro_core::container_store::RestartPolicy::Always),
        "unless-stopped" => Ok(ferro_core::container_store::RestartPolicy::UnlessStopped),
        _ => Err("run: restart must be no|on-failure|always|unless-stopped".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn parse_capabilities(entries: &[String]) -> Result<Vec<caps::Capability>, String> {
    let mut out = Vec::new();
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            return Err("run: cap-add must not be empty".to_string());
        }
        let normalized = if trimmed.starts_with("CAP_") {
            trimmed.to_string()
        } else {
            format!("CAP_{}", trimmed)
        };
        let cap = normalized
            .parse::<caps::Capability>()
            .map_err(|_| format!("run: unknown capability {trimmed}"))?;
        out.push(cap);
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn handle_exec(runtime: &ContainerRuntime, container: &str, cmd: &[String]) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("exec: container is required".to_string());
    }
    if cmd.is_empty() {
        return Err("exec: command is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let result = runtime
        .exec(&resolved, cmd)
        .map_err(|err| err.to_string())?;
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_container_id(runtime: &ContainerRuntime, container: &str) -> Result<String, String> {
    if runtime.inspect(container).is_ok() {
        return Ok(container.to_string());
    }
    let records = runtime.list().map_err(|err| err.to_string())?;
    let matches = records
        .into_iter()
        .filter(|record| record.name.as_deref() == Some(container))
        .map(|record| record.id)
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(format!("container not found: {container}")),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => Err(format!("container name is not unique: {container}")),
    }
}

fn handle_pull(store: &LocalImageStore, image: &str, lazy: bool) -> Result<(), String> {
    if lazy {
        let runtime_dir = runtime_dir();
        let canonical =
            ferro_core::image_fetch::pull_manifest_only_with_store(&runtime_dir, image, store)
                .map_err(|err| err.to_string())?;
        println!("pull: manifest-only image={canonical}");
        return Ok(());
    }
    ensure_image_present(store, image)?;
    let canonical = canonicalize_reference(image).map_err(|err| err.to_string())?;
    println!("pull: image={canonical}");
    Ok(())
}

fn handle_push(store: &LocalImageStore, image: &str) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    let canonical = canonicalize_reference(image).map_err(|err| err.to_string())?;
    let record = resolve_reference(store, &canonical)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("push: image not found: {canonical}"))?;

    let client = RegistryClient::new().map_err(|err| err.to_string())?;
    let auth = resolve_registry_auth(&canonical).map_err(|err| err.to_string())?;
    let runtime_dir = runtime_dir();
    let layer_paths =
        ferro_core::image_fetch::resolve_layer_paths_with_store(&runtime_dir, &canonical, store)
            .map_err(|err| err.to_string())?;
    let config_path =
        ferro_core::image_fetch::resolve_config_path_with_store(&runtime_dir, &canonical, store)
            .map_err(|err| err.to_string())?
            .ok_or_else(|| format!("push: missing config blob for {canonical}"))?;
    let manifest = parse_image_manifest(&record.manifest_json).map_err(|err| err.to_string())?;

    client
        .push_blob_from_file(
            &canonical,
            &manifest.config.digest,
            &config_path,
            auth.as_ref(),
        )
        .map_err(|err| err.to_string())?;
    for (layer, path) in manifest.layers.iter().zip(layer_paths.iter()) {
        if !path.exists() {
            return Err(format!("push: missing layer blob {}", layer.digest));
        }
        client
            .push_blob_from_file(&canonical, &layer.digest, path, auth.as_ref())
            .map_err(|err| err.to_string())?;
    }
    client
        .push_manifest_raw_with_media_type(
            &canonical,
            &record.manifest_json,
            &record.manifest_media_type,
            auth.as_ref(),
        )
        .map_err(|err| err.to_string())?;
    println!("push: image={canonical}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_scan(store: &LocalImageStore, image: &str, scanner: &str) -> Result<(), String> {
    ensure_image_present(store, image)?;
    let runtime_dir = runtime_dir();
    let layer_paths = resolve_layer_paths_with_store(&runtime_dir, image, store)
        .map_err(|err| format!("scan: missing image layers: {err}"))?;
    if layer_paths.is_empty() {
        return Err("scan: image has no layers".to_string());
    }
    let temp = tempfile::tempdir().map_err(|err| format!("scan: {err}"))?;
    let rootfs = temp.path().join("rootfs");
    let cas_root = runtime_dir.join("images").join("file-cas").join("blake3");
    construct_rootfs_with_dedup(&rootfs, &layer_paths, &cas_root)
        .map_err(|err| format!("scan: {err}"))?;

    let scanner = select_scanner(scanner)?;
    let output = run_scanner(&scanner, &rootfs)?;
    println!("{output}");
    Ok(())
}

fn select_scanner(requested: &str) -> Result<String, String> {
    match requested {
        "auto" => {
            if command_exists("trivy") {
                Ok("trivy".to_string())
            } else if command_exists("grype") {
                Ok("grype".to_string())
            } else {
                Err("scan: install trivy or grype, or pass --scanner".to_string())
            }
        }
        "trivy" | "grype" => Ok(requested.to_string()),
        other => Err(format!("scan: unsupported scanner {other}")),
    }
}

fn run_scanner(scanner: &str, rootfs: &Path) -> Result<String, String> {
    let output = match scanner {
        "trivy" => process::Command::new("trivy")
            .args(["fs", "--quiet", "--format", "json"])
            .arg(rootfs)
            .output(),
        "grype" => process::Command::new("grype")
            .args(["dir:"])
            .arg(rootfs)
            .args(["--output", "json"])
            .output(),
        _ => return Err(format!("scan: unsupported scanner {scanner}")),
    }
    .map_err(|err| format!("scan: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("scan: scanner failed: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(target_os = "linux")]
fn handle_compose(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    volume_store: &LocalVolumeStore,
    file: Option<&str>,
    command: ComposeCommands,
) -> Result<(), String> {
    let path = find_compose_file(file).map_err(|err| err.to_string())?;
    let project = ComposeProject::load(&path).map_err(|err| err.to_string())?;
    let project_dir = path.parent().unwrap_or_else(|| Path::new("."));
    match command {
        ComposeCommands::Up { profile } => {
            let order = compose_up(&project).map_err(|err| err.to_string())?;
            let enabled = build_compose_enabled_set(&project, &profile)?;
            for name in order {
                if !enabled.contains(&name) {
                    continue;
                }
                let service = project
                    .compose
                    .services
                    .get(&name)
                    .ok_or_else(|| format!("compose: missing service {name}"))?;
                if let Some(depends_on) = service.depends_on.as_ref() {
                    wait_for_compose_dependencies(runtime, depends_on)?;
                }
                run_compose_service(runtime, store, volume_store, project_dir, &name, service)?;
            }
        }
        ComposeCommands::Watch { profile, interval } => {
            let mut last_mtime = latest_mtime(project_dir)?;
            loop {
                handle_compose(
                    runtime,
                    store,
                    volume_store,
                    file,
                    ComposeCommands::Up {
                        profile: profile.clone(),
                    },
                )?;
                loop {
                    std::thread::sleep(Duration::from_secs(interval));
                    let current = latest_mtime(project_dir)?;
                    if current > last_mtime {
                        last_mtime = current;
                        break;
                    }
                }
                handle_compose(runtime, store, volume_store, file, ComposeCommands::Down)?;
            }
        }
        ComposeCommands::Down => {
            let order = compose_down(&project).map_err(|err| err.to_string())?;
            let containers = runtime.list().map_err(|err| err.to_string())?;
            for name in order {
                for record in containers.iter().filter(|rec| {
                    rec.name
                        .as_deref()
                        .map(|val| val == name || val.starts_with(&format!("{name}-")))
                        .unwrap_or(false)
                }) {
                    let _ = runtime.stop(&record.id, std::time::Duration::from_secs(5));
                    let _ = runtime.remove(&record.id);
                }
            }
        }
        ComposeCommands::Ps => {
            let services = compose_ps(&project).map_err(|err| err.to_string())?;
            println!("compose ps: {:?}", services);
        }
        ComposeCommands::Logs => {
            let services = compose_logs(&project).map_err(|err| err.to_string())?;
            println!("compose logs: {:?}", services);
        }
    }
    Ok(())
}

fn build_compose_enabled_set(
    project: &ComposeProject,
    profiles: &[String],
) -> Result<HashSet<String>, String> {
    let mut enabled = HashSet::new();
    for (name, service) in &project.compose.services {
        let active = match service.profiles.as_ref() {
            None => true,
            Some(list) if list.is_empty() => true,
            Some(list) => profiles.iter().any(|profile| list.contains(profile)),
        };
        if active {
            enabled.insert(name.clone());
        }
    }

    for (name, service) in &project.compose.services {
        if !enabled.contains(name) {
            continue;
        }
        if let Some(depends_on) = &service.depends_on {
            for dep in depends_on.iter() {
                if !enabled.contains(dep) {
                    return Err(format!(
                        "compose: service {name} depends on disabled profile service {dep}"
                    ));
                }
            }
        }
    }

    Ok(enabled)
}

#[cfg(target_os = "linux")]
fn wait_for_compose_dependencies(
    runtime: &ContainerRuntime,
    depends_on: &ComposeDependsOn,
) -> Result<(), String> {
    match depends_on {
        ComposeDependsOn::Simple(_) => Ok(()),
        ComposeDependsOn::Conditional(map) => {
            for (service, condition) in map {
                match condition.condition.as_str() {
                    "service_started" => {}
                    "service_healthy" => wait_for_compose_health(runtime, service)?,
                    "service_completed_successfully" => {
                        return Err(format!(
                            "compose: depends_on condition not supported: service_completed_successfully for {service}"
                        ));
                    }
                    other => {
                        return Err(format!(
                            "compose: unknown depends_on condition {other} for {service}"
                        ));
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn wait_for_compose_health(runtime: &ContainerRuntime, service: &str) -> Result<(), String> {
    let id = resolve_container_id(runtime, service)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let record = runtime.inspect(&id).map_err(|err| err.to_string())?;
        match record.health_status.as_str() {
            "healthy" => return Ok(()),
            "unhealthy" => {
                return Err(format!("compose: dependency {service} is unhealthy"));
            }
            "none" => {
                return Err(format!("compose: dependency {service} has no healthcheck"));
            }
            _ => {}
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "compose: timed out waiting for {service} to become healthy"
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(target_os = "linux")]
fn run_compose_service(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    volume_store: &LocalVolumeStore,
    project_dir: &Path,
    name: &str,
    service: &ComposeService,
) -> Result<(), String> {
    let image = if service.image.is_some() || service.build.is_some() {
        build_compose_image(store, project_dir, name, service)?
    } else {
        return Err(format!("compose: service {name} missing image or build"));
    };
    if let Some(networks) = service.networks.as_ref() {
        if networks.iter().any(|net| net != "default") {
            return Err(format!(
                "compose: custom networks not supported for service {name}"
            ));
        }
    }
    let cmd = compose_service_command(service);
    let env = compose_service_env(project_dir, service)?;
    let labels = compose_service_labels(service);
    let publish = compose_service_ports(service);
    let bind_mounts = compose_service_mounts(volume_store, service)?;
    let restart = service.restart.as_deref().unwrap_or("no");
    let restart = match restart {
        "always" => "always",
        "unless-stopped" => "unless-stopped",
        "no" => "no",
        "on-failure" => "on-failure",
        _ => "no",
    };
    let replicas = service
        .deploy
        .as_ref()
        .and_then(|deploy| deploy.replicas)
        .unwrap_or(1);

    for idx in 1..=replicas {
        let instance_name = if replicas == 1 {
            name.to_string()
        } else {
            format!("{name}-{idx}")
        };
        let network_mode = match service.network_mode.as_deref() {
            None => "bridge",
            Some("bridge") => "bridge",
            Some("host") => "host",
            Some("none") => "none",
            Some(other) => {
                return Err(format!(
                    "compose: unsupported network_mode {other} for service {name}"
                ))
            }
        };
        handle_run(
            &runtime_dir(),
            runtime,
            store,
            volume_store,
            &image,
            &cmd,
            network_mode,
            "ebpf",
            &bind_mounts,
            &[],
            &[],
            false,
            false,
            &env,
            &labels,
            &[],
            &[],
            service.entrypoint.as_deref(),
            None,
            None,
            Some(&instance_name),
            &publish,
            None,
            None,
            None,
            None,
            None,
            restart,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_compose_image(
    store: &LocalImageStore,
    project_dir: &Path,
    name: &str,
    service: &ComposeService,
) -> Result<String, String> {
    let runtime_dir = runtime_dir();
    let tag = service
        .image
        .clone()
        .unwrap_or_else(|| format!("local/compose-{name}:latest"));

    let Some(build) = service.build.as_ref() else {
        return Ok(tag);
    };

    let context = build.context.as_deref().unwrap_or(".");
    let dockerfile = build.dockerfile.as_deref().unwrap_or("Dockerfile");
    let dockerfile_path = project_dir.join(context).join(dockerfile);
    let result = ferro_core::dockerfile_build::build_from_dockerfile_with_store_and_compression(
        &dockerfile_path,
        Some(&tag),
        &runtime_dir,
        CompressionFormat::Gzip,
        store,
    )
    .map_err(|err| err.to_string())?;
    Ok(result.reference)
}

fn compose_service_command(service: &ComposeService) -> Vec<String> {
    match service.command.as_ref() {
        Some(ComposeCommandSpec::List(list)) => list.clone(),
        Some(ComposeCommandSpec::String(cmd)) => {
            vec!["sh".to_string(), "-c".to_string(), cmd.clone()]
        }
        None => Vec::new(),
    }
}

fn compose_service_env(
    project_dir: &Path,
    service: &ComposeService,
) -> Result<Vec<String>, String> {
    let mut env = HashMap::new();
    if let Some(files) = service.env_file.as_ref() {
        for file in files {
            let path = project_dir.join(file);
            let entries = load_env_file_map(&path)?;
            for (key, value) in entries {
                env.insert(key, value);
            }
        }
    }

    match service.environment.as_ref() {
        Some(ComposeEnvironment::Map(map)) => {
            for (key, value) in map {
                env.insert(key.clone(), value.clone());
            }
        }
        Some(ComposeEnvironment::List(list)) => {
            for entry in list {
                if let Some((key, value)) = entry.split_once('=') {
                    env.insert(key.to_string(), value.to_string());
                }
            }
        }
        None => {}
    }

    Ok(env
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect())
}

fn compose_service_labels(service: &ComposeService) -> Vec<String> {
    match service.labels.as_ref() {
        Some(map) => map
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
        None => Vec::new(),
    }
}

fn compose_service_ports(service: &ComposeService) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ports) = service.ports.as_ref() {
        for entry in ports {
            if entry.contains(':') {
                out.push(entry.clone());
                continue;
            }
            let (port, proto) = entry
                .split_once('/')
                .map(|(port, proto)| (port, Some(proto)))
                .unwrap_or((entry.as_str(), None));
            if let Some(proto) = proto {
                out.push(format!("{port}:{port}/{proto}"));
            } else {
                out.push(format!("{port}:{port}"));
            }
        }
    }
    out
}

fn compose_service_mounts(
    volume_store: &LocalVolumeStore,
    service: &ComposeService,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    if let Some(volumes) = service.volumes.as_ref() {
        for entry in volumes {
            let mut parts = entry.split(':');
            let source = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");
            if source.is_empty() || target.is_empty() {
                return Err(format!("compose: invalid volume entry {entry}"));
            }
            if source.starts_with('.') || source.contains('/') {
                out.push(entry.clone());
                continue;
            }
            let record = match volume_store.get(source).map_err(|err| err.to_string())? {
                Some(record) => record,
                None => volume_store.create(source).map_err(|err| err.to_string())?,
            };
            let mode = parts.next().unwrap_or("");
            if mode.is_empty() {
                out.push(format!("{}:{target}", record.path));
            } else {
                out.push(format!("{}:{target}:{mode}", record.path));
            }
        }
    }
    Ok(out)
}

#[derive(Debug, serde::Deserialize)]
struct DockerCreateRequest {
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
    #[serde(rename = "User")]
    user: Option<String>,
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
    #[serde(rename = "HostConfig")]
    host_config: Option<DockerHostConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct DockerHostConfig {
    #[serde(rename = "Binds")]
    binds: Option<Vec<String>>,
    #[serde(rename = "PortBindings")]
    port_bindings: Option<HashMap<String, Vec<DockerPortBinding>>>,
    #[serde(rename = "NetworkMode")]
    network_mode: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DockerPortBinding {
    #[serde(rename = "HostPort")]
    host_port: Option<String>,
}

#[derive(Debug, Clone)]
struct DockerCreateSpec {
    image: String,
    cmd: Vec<String>,
    env: Vec<String>,
    labels: Vec<String>,
    binds: Vec<String>,
    publish: Vec<String>,
    workdir: Option<String>,
    user: Option<String>,
    name: Option<String>,
    network_mode: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DockerNetworkCreateSpec {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: Option<String>,
    #[serde(rename = "IPAM")]
    ipam: Option<DockerIpamSpec>,
}

#[derive(Debug, Clone, Deserialize)]
struct DockerIpamSpec {
    #[serde(rename = "Config", default)]
    config: Vec<DockerIpamConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct DockerIpamConfig {
    #[serde(rename = "Subnet")]
    subnet: Option<String>,
    #[serde(rename = "Gateway")]
    gateway: Option<String>,
}

#[derive(Default)]
struct DockerCompatState {
    next_id: AtomicU64,
    pending: Mutex<HashMap<String, DockerCreateSpec>>,
}

#[cfg(target_os = "linux")]
fn run_daemon(
    store: &LocalImageStore,
    socket: &str,
    docker_compat: bool,
    metrics_addr: Option<&str>,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if !docker_compat {
        return Err("daemon: --docker-compat is required".to_string());
    }
    let socket_path = Path::new(socket);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    if socket_path.exists() {
        let md = std::fs::symlink_metadata(socket_path).map_err(|err| err.to_string())?;
        if !md.file_type().is_socket() {
            return Err(format!(
                "daemon: refusing to remove non-socket path {}",
                socket_path.display()
            ));
        }
        std::fs::remove_file(socket_path).map_err(|err| err.to_string())?;
    }

    let listener = UnixListener::bind(socket_path).map_err(|err| err.to_string())?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
        .map_err(|err| format!("daemon: set socket permissions: {err}"))?;
    let runtime_dir = runtime_dir();
    let runtime_dir = Arc::new(runtime_dir);
    let store = Arc::new(store.clone());
    let volume_store = Arc::new(
        LocalVolumeStore::open(runtime_dir.join("volumes")).map_err(|err| err.to_string())?,
    );
    let state = Arc::new(DockerCompatState::default());
    if let Some(addr) = metrics_addr {
        start_metrics_server(runtime_dir.clone(), store.clone(), addr)?;
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let runtime_dir = runtime_dir.clone();
                let store = store.clone();
                let volume_store = volume_store.clone();
                let state = state.clone();
                std::thread::spawn(move || {
                    let _ = handle_docker_compat_connection(
                        stream,
                        runtime_dir,
                        store,
                        volume_store,
                        state,
                    );
                });
            }
            Err(_) => break,
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn start_metrics_server(
    runtime_dir: Arc<PathBuf>,
    store: Arc<LocalImageStore>,
    addr: &str,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|err| format!("metrics: {err}"))?;
    let started_at = Instant::now();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let request = String::from_utf8_lossy(&buffer);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            if path != "/metrics" {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                continue;
            }
            let body = build_metrics(&runtime_dir, &store, started_at);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_metrics(runtime_dir: &Path, store: &LocalImageStore, started_at: Instant) -> String {
    let containers = match ContainerRuntime::new(runtime_dir) {
        Ok(runtime) => runtime.list().unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let images = store.list_references().unwrap_or_default();
    let running = containers.iter().filter(|c| c.status == "running").count();
    let exited = containers.iter().filter(|c| c.status == "exited").count();
    let uptime = started_at.elapsed().as_secs();

    format!(
        "# HELP ferrocrate_containers_total Total number of containers\\n\
# TYPE ferrocrate_containers_total gauge\\n\
ferrocrate_containers_total {}\\n\
# HELP ferrocrate_containers_running Running containers\\n\
# TYPE ferrocrate_containers_running gauge\\n\
ferrocrate_containers_running {}\\n\
# HELP ferrocrate_containers_exited Exited containers\\n\
# TYPE ferrocrate_containers_exited gauge\\n\
ferrocrate_containers_exited {}\\n\
# HELP ferrocrate_images_total Total number of images\\n\
# TYPE ferrocrate_images_total gauge\\n\
ferrocrate_images_total {}\\n\
# HELP ferrocrate_uptime_seconds Daemon uptime\\n\
# TYPE ferrocrate_uptime_seconds counter\\n\
ferrocrate_uptime_seconds {}\\n",
        containers.len(),
        running,
        exited,
        images.len(),
        uptime
    )
}

#[cfg(target_os = "linux")]
fn handle_docker_compat_connection(
    mut stream: UnixStream,
    runtime_dir: Arc<PathBuf>,
    store: Arc<LocalImageStore>,
    volume_store: Arc<LocalVolumeStore>,
    state: Arc<DockerCompatState>,
) -> Result<(), String> {
    let response_result: Result<Vec<u8>, String> = (|| {
        let request = read_http_request(&mut stream)?;
        let runtime = ContainerRuntime::new(&runtime_dir).map_err(|err| err.to_string())?;

        let (path, query) = split_path_query(&request.path);
        let path = normalize_docker_api_path(&path);
        let response = match (request.method.as_str(), path.as_str()) {
            ("GET", "/_ping") => http_response(200, "OK\n".as_bytes(), "text/plain"),
            ("GET", "/version") => {
                let body = serde_json::json!({
                    "Version": env!("CARGO_PKG_VERSION"),
                    "ApiVersion": "1.45",
                    "MinAPIVersion": "1.24",
                    "GitCommit": "unknown",
                    "Os": std::env::consts::OS,
                    "Arch": std::env::consts::ARCH
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("GET", "/info") => {
                let containers = runtime.list().map_err(|err| err.to_string())?;
                let images = store.list_references().map_err(|err| err.to_string())?;
                let running = containers.iter().filter(|c| c.status == "running").count();
                let paused = containers.iter().filter(|c| c.status == "paused").count();
                let stopped = containers
                    .iter()
                    .filter(|c| c.status == "exited" || c.status == "stopped")
                    .count();
                let body = serde_json::json!({
                    "ID": "ferrocrate",
                    "Containers": containers.len(),
                    "ContainersRunning": running,
                    "ContainersPaused": paused,
                    "ContainersStopped": stopped,
                    "Images": images.len(),
                    "Driver": "overlayfs",
                    "OperatingSystem": std::env::consts::OS,
                    "Architecture": std::env::consts::ARCH,
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("GET", "/containers/json") => {
                let records = runtime.list().map_err(|err| err.to_string())?;
                let entries: Vec<serde_json::Value> = records
                    .iter()
                    .map(|record| {
                        let name = record.name.clone().unwrap_or_else(|| record.id.clone());
                        serde_json::json!({
                            "Id": record.id,
                            "Image": record.image,
                            "Command": record.command.join(" "),
                            "Created": record.created_at_unix,
                            "State": record.status,
                            "Status": record.status,
                            "Names": vec![format!("/{name}")],
                        })
                    })
                    .collect();
                let json = serde_json::to_string(&entries)
                    .unwrap_or_else(|e| format!(r#"{{"error": "json serialize failed: {e}"}}"#));
                http_response(200, json.as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/json") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/json");
                let record = runtime.inspect(id).map_err(|err| err.to_string())?;
                let name = record.name.clone().unwrap_or_else(|| record.id.clone());
                let body = serde_json::json!({
                    "Id": record.id,
                    "Name": format!("/{name}"),
                    "Image": record.image,
                    "Config": {
                        "Env": record.env,
                        "Cmd": record.command,
                        "WorkingDir": record.workdir,
                        "User": record.user,
                        "Labels": record.labels,
                    },
                    "State": {
                        "Status": record.status,
                        "Pid": record.pid,
                        "ExitCode": record.last_exit_code,
                        "StartedAt": record.created_at_unix,
                    }
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/logs") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/logs");
                let logs = runtime.logs(id).map_err(|err| err.to_string())?;
                http_response(200, logs.as_bytes(), "text/plain")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/stats") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/stats");
                let stats = runtime.stats(id).map_err(|err| err.to_string())?;
                let body = serde_json::json!({
                    "memory_stats": {
                        "usage": stats.memory_current,
                        "limit": stats.memory_max
                    },
                    "pids_stats": {
                        "current": stats.pids_current
                    },
                    "cpu_stats": {
                        "cpu_usage": {
                            "total_usage": stats.cpu_usage_usec
                        }
                    }
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("POST", "/containers/create") => {
                let name = query.get("name").cloned();
                let spec = parse_docker_create_spec(&request.body, name)?;
                let id = format!("d{}", state.next_id.fetch_add(1, Ordering::SeqCst));
                if let Ok(mut pending) = state.pending.lock() {
                    pending.insert(id.clone(), spec);
                } else {
                    return Err("failed to acquire lock".to_string());
                }
                let body = serde_json::json!({ "Id": id, "Warnings": serde_json::Value::Null });
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/start") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/start");
                let spec = {
                    let mut pending = state
                        .pending
                        .lock()
                        .map_err(|e| format!("lock poisoned: {e}"))?;
                    pending.remove(id)
                }
                .ok_or_else(|| format!("docker: unknown container {id}"))?;
                handle_run(
                    runtime_dir.as_ref(),
                    &runtime,
                    &store,
                    &volume_store,
                    &spec.image,
                    &spec.cmd,
                    &spec.network_mode,
                    "ebpf",
                    &spec.binds,
                    &[],
                    &[],
                    false,
                    false,
                    &spec.env,
                    &spec.labels,
                    &[],
                    &[],
                    None,
                    spec.workdir.as_deref(),
                    spec.user.as_deref(),
                    spec.name.as_deref(),
                    &spec.publish,
                    None,
                    None,
                    None,
                    None,
                    None,
                    "no",
                    false,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )?;
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/stop") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/stop");
                runtime
                    .stop(id, Duration::from_secs(5))
                    .map_err(|err| err.to_string())?;
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/restart") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/restart");
                runtime
                    .restart(id, Duration::from_secs(5))
                    .map_err(|err| err.to_string())?;
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/kill") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/kill");
                runtime.kill(id).map_err(|err| err.to_string())?;
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/wait") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/wait");
                wait_for_container_exit(&runtime, id)?;
                let record = runtime.inspect(id).map_err(|err| err.to_string())?;
                let body = serde_json::json!({
                    "StatusCode": record.last_exit_code.unwrap_or(0),
                    "Error": serde_json::Value::Null
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("DELETE", path) if path.starts_with("/containers/") => {
                let id = path.trim_start_matches("/containers/");
                runtime.remove(id).map_err(|err| err.to_string())?;
                http_response(204, &[], "text/plain")
            }
            ("GET", "/images/json") => {
                let images = store.list_references().map_err(|err| err.to_string())?;
                let entries: Vec<serde_json::Value> = images
                    .into_iter()
                    .map(|record| {
                        serde_json::json!({
                            "Id": record.digest,
                            "RepoTags": vec![record.reference],
                            "Created": record.created_at_unix,
                        })
                    })
                    .collect();
                let json = serde_json::to_string(&entries)
                    .unwrap_or_else(|e| format!(r#"{{"error": "json serialize failed: {e}"}}"#));
                http_response(200, json.as_bytes(), "application/json")
            }
            ("GET", "/networks") => {
                let networks = load_networks(runtime_dir.as_ref())?;
                let mut entries = vec![serde_json::json!({
                    "Name": "bridge",
                    "Id": "bridge",
                    "Driver": "bridge",
                    "Scope": "local",
                })];
                entries.extend(networks.into_iter().map(|record| {
                    serde_json::json!({
                        "Name": record.name,
                        "Id": record.name,
                        "Driver": record.driver,
                        "Scope": "local",
                        "IPAM": {
                            "Config": [{
                                "Subnet": record.subnet,
                                "Gateway": record.gateway
                            }]
                        }
                    })
                }));
                let body = serde_json::to_string(&entries).map_err(|err| err.to_string())?;
                http_response(200, body.as_bytes(), "application/json")
            }
            ("POST", "/networks/create") => {
                let spec = parse_docker_network_create_spec(&request.body)?;
                if spec.driver.as_deref().unwrap_or("bridge") != "bridge" {
                    return Err("docker: only bridge network driver is supported".to_string());
                }
                let subnet = spec
                    .ipam
                    .as_ref()
                    .and_then(|ipam| ipam.config.first())
                    .and_then(|cfg| cfg.subnet.clone());
                let gateway = spec
                    .ipam
                    .as_ref()
                    .and_then(|ipam| ipam.config.first())
                    .and_then(|cfg| cfg.gateway.clone());
                handle_network(
                    runtime_dir.as_ref(),
                    &runtime,
                    NetworkCommands::Create {
                        name: spec.name.clone(),
                        subnet,
                        gateway,
                    },
                )?;
                let body = serde_json::json!({ "Id": spec.name, "Warning": "" });
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("DELETE", path) if path.starts_with("/networks/") => {
                let id = path.trim_start_matches("/networks/");
                handle_network(
                    runtime_dir.as_ref(),
                    &runtime,
                    NetworkCommands::Rm {
                        name: id.to_string(),
                    },
                )?;
                http_response(204, &[], "text/plain")
            }
            ("GET", path) if path.starts_with("/images/") && path.ends_with("/json") => {
                let name = path
                    .trim_start_matches("/images/")
                    .trim_end_matches("/json");
                let reference = resolve_reference(&store, name)
                    .map_err(|err| err.to_string())?
                    .ok_or_else(|| format!("docker: unknown image {name}"))?;
                let body = serde_json::json!({
                    "Id": reference.digest,
                    "RepoTags": vec![reference.reference],
                    "Created": reference.created_at_unix,
                    "Size": 0,
                    "VirtualSize": 0
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("POST", "/images/create") => {
                let from_image = query
                    .get("fromImage")
                    .ok_or_else(|| "docker: missing fromImage".to_string())?;
                let reference = if let Some(tag) = query.get("tag") {
                    format!("{from_image}:{tag}")
                } else {
                    from_image.to_string()
                };
                ensure_image_present(&store, &reference)?;
                http_response(200, b"{}", "application/json")
            }
            _ => docker_error_response(404, "not found"),
        };

        Ok(response)
    })();

    let response = match response_result {
        Ok(response) => response,
        Err(err) => docker_error_response(docker_status_for_error(&err), &err),
    };
    stream.write_all(&response).map_err(|err| err.to_string())?;
    Ok(())
}

fn docker_error_response(status: u16, message: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "message": message
    })
    .to_string();
    http_response(status, body.as_bytes(), "application/json")
}

fn docker_status_for_error(err: &str) -> u16 {
    let lowered = err.to_lowercase();
    if lowered.contains("not found")
        || lowered.contains("unknown image")
        || lowered.contains("unknown container")
    {
        return 404;
    }
    if lowered.contains("invalid")
        || lowered.contains("missing")
        || lowered.contains("unsupported")
        || lowered.contains("too large")
        || lowered.contains("bad request")
    {
        return 400;
    }
    500
}

fn normalize_docker_api_path(path: &str) -> String {
    if !path.starts_with("/v") {
        return path.to_string();
    }

    let mut parts = path.splitn(3, '/');
    let first = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    let rest = parts.next();
    if !first.is_empty() {
        return path.to_string();
    }
    if version.len() < 2 || !version.starts_with('v') {
        return path.to_string();
    }

    let version_body = &version[1..];
    let valid = version_body
        .chars()
        .all(|ch| ch.is_ascii_digit() || ch == '.')
        && version_body.chars().any(|ch| ch.is_ascii_digit());
    if !valid {
        return path.to_string();
    }

    match rest {
        Some(rest) if !rest.is_empty() => format!("/{rest}"),
        _ => "/".to_string(),
    }
}

fn parse_docker_create_spec(body: &[u8], name: Option<String>) -> Result<DockerCreateSpec, String> {
    let request: DockerCreateRequest =
        serde_json::from_slice(body).map_err(|err| err.to_string())?;
    let mut cmd = request.cmd.unwrap_or_default();
    if let Some(entry) = request.entrypoint {
        let mut merged = entry;
        merged.extend(cmd);
        cmd = merged;
    }
    let env = request.env.unwrap_or_default();
    let labels = request
        .labels
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    let host_config = request.host_config.unwrap_or(DockerHostConfig {
        binds: None,
        port_bindings: None,
        network_mode: None,
    });
    let publish = port_bindings_to_publish(host_config.port_bindings)?;
    let network_mode = match host_config.network_mode.as_deref() {
        None | Some("default") | Some("bridge") => "bridge".to_string(),
        Some("host") => "host".to_string(),
        Some("none") => "none".to_string(),
        Some(other) => return Err(format!("docker: unsupported network mode {other}")),
    };
    Ok(DockerCreateSpec {
        image: request.image,
        cmd,
        env,
        labels,
        binds: host_config.binds.unwrap_or_default(),
        publish,
        workdir: request.working_dir,
        user: request.user,
        name,
        network_mode,
    })
}

fn parse_docker_network_create_spec(body: &[u8]) -> Result<DockerNetworkCreateSpec, String> {
    let spec: DockerNetworkCreateSpec = serde_json::from_slice(body)
        .map_err(|err| format!("docker: invalid network create payload: {err}"))?;
    if spec.name.trim().is_empty() {
        return Err("docker: network name is required".to_string());
    }
    Ok(spec)
}

fn port_bindings_to_publish(
    bindings: Option<HashMap<String, Vec<DockerPortBinding>>>,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let Some(bindings) = bindings else {
        return Ok(out);
    };
    for (container_spec, host_bindings) in bindings {
        let (container_port, proto) = container_spec
            .split_once('/')
            .unwrap_or((container_spec.as_str(), "tcp"));
        for binding in host_bindings {
            let Some(host_port) = binding.host_port else {
                continue;
            };
            out.push(format!("{host_port}:{container_port}/{proto}"));
        }
    }
    Ok(out)
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut UnixStream) -> Result<HttpRequest, String> {
    const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
    const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;

    let mut buffer = Vec::new();
    let mut header_end = None;
    let mut temp = [0u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| err.to_string())?;
    loop {
        let read = stream.read(&mut temp).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);
        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            break;
        }
        if buffer.len() > MAX_HTTP_HEADER_BYTES {
            return Err("docker: request too large".to_string());
        }
    }
    let header_end = header_end.ok_or_else(|| "docker: invalid request".to_string())?;
    let header_str = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_str.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "docker: invalid request".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "docker: invalid request".to_string())?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| "docker: invalid request".to_string())?
        .to_string();
    let http_version = parts
        .next()
        .ok_or_else(|| "docker: invalid request".to_string())?;
    if parts.next().is_some() {
        return Err("docker: invalid request".to_string());
    }
    if http_version != "HTTP/1.1" && http_version != "HTTP/1.0" {
        return Err("docker: unsupported http version".to_string());
    }
    if method.is_empty() || !method.chars().all(|ch| ch.is_ascii_uppercase()) {
        return Err("docker: invalid request method".to_string());
    }
    if !path.starts_with('/') || path.contains('\0') {
        return Err("docker: invalid request path".to_string());
    }

    let mut content_length = 0usize;
    for line in lines {
        if line.contains('\0') {
            return Err("docker: invalid request header".to_string());
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "docker: invalid content-length".to_string())?;
            }
        } else {
            return Err("docker: invalid request header".to_string());
        }
    }
    if content_length > MAX_HTTP_BODY_BYTES {
        return Err("docker: request too large".to_string());
    }
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut temp).map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("docker: incomplete request body".to_string());
        }
        body.extend_from_slice(&temp[..read]);
        if body.len() > MAX_HTTP_BODY_BYTES {
            return Err("docker: request too large".to_string());
        }
    }
    body.truncate(content_length);
    Ok(HttpRequest { method, path, body })
}

fn http_response(status: u16, body: &[u8], content_type: &str) -> Vec<u8> {
    let status_line = match status {
        200 => "200 OK",
        201 => "201 Created",
        204 => "204 No Content",
        400 => "400 Bad Request",
        404 => "404 Not Found",
        500 => "500 Internal Server Error",
        _ => "200 OK",
    };
    let mut out = Vec::new();
    out.extend_from_slice(format!("HTTP/1.1 {status_line}\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(body);
    out
}

fn split_path_query(path: &str) -> (String, HashMap<String, String>) {
    let mut query_map = HashMap::new();
    let mut parts = path.splitn(2, '?');
    let base = parts.next().unwrap_or("").to_string();
    let query = parts.next().unwrap_or("");
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((key, value)) = pair.split_once('=') {
            query_map.insert(key.to_string(), value.to_string());
        }
    }
    (base, query_map)
}

fn load_env_file_map(path: &Path) -> Result<HashMap<String, String>, String> {
    let mut env = HashMap::new();
    let content = std::fs::read_to_string(path)
        .map_err(|err| format!("compose: failed to read env file {}: {err}", path.display()))?;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, raw_value) = trimmed
            .split_once('=')
            .ok_or_else(|| format!("compose: invalid env entry: {trimmed}"))?;
        let mut value = raw_value.trim().to_string();
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }
        env.insert(key.trim().to_string(), value);
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::{
        build_health_config, build_limits, desktop_forward_enabled, dispatch, effective_readonly,
        handle_build, handle_containers, handle_exec, handle_image_prune, handle_images,
        handle_inspect, handle_kill, handle_logs, handle_network, handle_pause, handle_pull,
        handle_push, handle_restart, handle_rm, handle_rmi, handle_run, handle_stats, handle_stop,
        handle_unpause, handle_volume, normalize_docker_api_path, parse_bind_mounts,
        parse_capabilities, parse_driver_opts, parse_env_entries, parse_key_values, parse_publish,
        parse_restart_policy, parse_tmpfs_mounts, read_http_request, should_desktop_forward,
        structured_desktop_error, top_level_command_name, validate_network_backend,
        validate_network_mode, AiCommands, Cli, Commands, ComposeCommands, ConfigCommands,
        NetworkCommands, VolumeCommands,
    };
    use clap::Parser;
    use ferro_core::image_store::LocalImageStore;
    use ferro_core::runtime::ContainerRuntime;
    use ferro_core::volume_store::LocalVolumeStore;
    use std::io::Write;
    use std::os::unix::net::UnixStream as StdUnixStream;

    #[test]
    fn parses_run_command() {
        let cli = Cli::parse_from(["ferrocrate", "run", "alpine:latest", "echo", "hi"]);
        match cli.command {
            Commands::Run {
                image,
                cmd,
                network_backend,
                network,
                bind_mounts,
                tmpfs_mounts,
                read_only_rootfs,
                read_write_rootfs,
                no_new_privs,
                env,
                labels,
                annotations,
                user,
                workdir,
                entrypoint,
                publish,
                health_cmd,
                health_interval,
                health_timeout,
                health_retries,
                health_start_period,
                restart_policy,
                memory_max,
                cpu_quota,
                cpu_period,
                pids_max,
                cap_add,
                name,
                profile,
                ai_model,
                ..
            } => {
                assert_eq!(image, "alpine:latest");
                assert_eq!(cmd, vec!["echo", "hi"]);
                assert_eq!(network_backend, "ebpf");
                assert_eq!(network, "bridge");
                assert!(bind_mounts.is_empty());
                assert!(tmpfs_mounts.is_empty());
                assert!(!read_only_rootfs);
                assert!(!read_write_rootfs);
                assert!(!no_new_privs);
                assert!(env.is_empty());
                assert!(labels.is_empty());
                assert!(annotations.is_empty());
                assert!(user.is_none());
                assert!(workdir.is_none());
                assert!(entrypoint.is_none());
                assert!(publish.is_empty());
                assert!(name.is_none());
                assert!(cap_add.is_empty());
                assert!(health_cmd.is_none());
                assert!(health_interval.is_none());
                assert!(health_timeout.is_none());
                assert!(health_retries.is_none());
                assert!(health_start_period.is_none());
                assert_eq!(restart_policy, "no");
                assert_eq!(profile, "dev");
                assert!(ai_model.is_none());
                assert!(memory_max.is_none());
                assert!(cpu_quota.is_none());
                assert!(cpu_period.is_none());
                assert!(pids_max.is_none());
                assert!(cap_add.is_empty());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_build_command_with_tag() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "build",
            "./Dockerfile",
            "--tag",
            "acme/app:dev",
        ]);

        match cli.command {
            Commands::Build {
                dockerfile,
                ferrofile,
                tag,
                compress,
            } => {
                assert_eq!(dockerfile.as_deref(), Some("./Dockerfile"));
                assert!(ferrofile.is_none());
                assert_eq!(tag.expect("tag"), "acme/app:dev");
                assert_eq!(compress, "gzip");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_rmi_command() {
        let cli = Cli::parse_from(["ferrocrate", "rmi", "alpine:latest"]);
        match cli.command {
            Commands::Rmi { image } => assert_eq!(image, "alpine:latest"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_image_prune_command() {
        let cli = Cli::parse_from(["ferrocrate", "image-prune"]);
        match cli.command {
            Commands::ImagePrune => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn rmi_handler_rejects_invalid_image() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let err = handle_rmi(&store, "").expect_err("invalid image");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn image_prune_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        handle_image_prune(&store).expect("prune");
    }

    #[test]
    fn parses_compose_command() {
        let cli = Cli::parse_from(["ferrocrate", "compose", "up"]);
        match cli.command {
            Commands::Compose { file, command } => {
                assert!(file.is_none());
                assert!(matches!(command, ComposeCommands::Up { profile } if profile.is_empty()));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_ai_train_alias_command() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "ai-train",
            "--model-type",
            "resource-predictor",
            "--format",
            "json",
        ]);
        match cli.command {
            Commands::AiTrain {
                model_type,
                data_dir,
                models_dir,
                output,
                format,
            } => {
                assert_eq!(model_type, "resource-predictor");
                assert!(data_dir.is_none());
                assert!(models_dir.is_none());
                assert!(output.is_none());
                assert_eq!(format, "json");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_ai_lineage_verify_flag() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "ai",
            "lineage",
            "model.rvf",
            "--verify",
            "--parent-file",
            "parent.rvf",
        ]);
        match cli.command {
            Commands::Ai {
                command:
                    AiCommands::Lineage {
                        path,
                        parent_file,
                        verify,
                        ..
                    },
            } => {
                assert_eq!(path, "model.rvf");
                assert!(verify);
                assert_eq!(parent_file.as_deref(), Some("parent.rvf"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_config_set() {
        let cli = Cli::parse_from(["ferrocrate", "config", "set", "ai.backend", "legacy"]);
        match cli.command {
            Commands::Config {
                command: ConfigCommands::Set { key, value },
            } => {
                assert_eq!(key, "ai.backend");
                assert_eq!(value, "legacy");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_doctor_command() {
        let cli = Cli::parse_from(["ferrocrate", "doctor", "--fix", "--bootstrap", "--json"]);
        match cli.command {
            Commands::Doctor {
                fix,
                bootstrap,
                json,
            } => {
                assert!(fix);
                assert!(bootstrap);
                assert!(json);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn normalizes_docker_versioned_paths() {
        assert_eq!(
            normalize_docker_api_path("/v1.45/containers/json"),
            "/containers/json"
        );
        assert_eq!(normalize_docker_api_path("/v1.24/_ping"), "/_ping");
        assert_eq!(
            normalize_docker_api_path("/containers/json"),
            "/containers/json"
        );
        assert_eq!(
            normalize_docker_api_path("/vbad/containers/json"),
            "/vbad/containers/json"
        );
    }

    #[test]
    fn read_http_request_rejects_bad_content_length() {
        let (mut writer, mut reader) = StdUnixStream::pair().expect("pair");
        writer
            .write_all(
                b"POST /containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: not-a-number\r\n\r\n",
            )
            .expect("write");
        drop(writer);
        let err = read_http_request(&mut reader).expect_err("invalid content-length");
        assert!(err.contains("invalid content-length"));
    }

    #[test]
    fn read_http_request_rejects_incomplete_body() {
        let (mut writer, mut reader) = StdUnixStream::pair().expect("pair");
        writer
            .write_all(
                b"POST /containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: 5\r\n\r\n{}",
            )
            .expect("write");
        drop(writer);
        let err = read_http_request(&mut reader).expect_err("incomplete body");
        assert!(err.contains("incomplete request body"));
    }

    #[test]
    fn parses_stop_command_with_timeout() {
        let cli = Cli::parse_from(["ferrocrate", "stop", "--timeout", "5", "abc123"]);
        match cli.command {
            Commands::Stop { container, timeout } => {
                assert_eq!(container, "abc123");
                assert_eq!(timeout, 5);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_kill_command() {
        let cli = Cli::parse_from(["ferrocrate", "kill", "abc123"]);
        match cli.command {
            Commands::Kill { container } => assert_eq!(container, "abc123"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_pause_command() {
        let cli = Cli::parse_from(["ferrocrate", "pause", "abc123"]);
        match cli.command {
            Commands::Pause { container } => assert_eq!(container, "abc123"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_unpause_command() {
        let cli = Cli::parse_from(["ferrocrate", "unpause", "abc123"]);
        match cli.command {
            Commands::Unpause { container } => assert_eq!(container, "abc123"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_rm_command() {
        let cli = Cli::parse_from(["ferrocrate", "rm", "abc123"]);
        match cli.command {
            Commands::Rm { container } => assert_eq!(container, "abc123"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_restart_command() {
        let cli = Cli::parse_from(["ferrocrate", "restart", "abc123"]);
        match cli.command {
            Commands::Restart { container, timeout } => {
                assert_eq!(container, "abc123");
                assert_eq!(timeout, 10);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_inspect_command() {
        let cli = Cli::parse_from(["ferrocrate", "inspect", "abc123"]);
        match cli.command {
            Commands::Inspect { container, format } => {
                assert_eq!(container, "abc123");
                assert_eq!(format, "text");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_volume_commands() {
        let create = Cli::parse_from(["ferrocrate", "volume", "create", "data"]);
        match create.command {
            Commands::Volume { command } => match command {
                VolumeCommands::Create { name, driver, opts } => {
                    assert_eq!(name, "data");
                    assert_eq!(driver, "local");
                    assert!(opts.is_empty());
                }
                _ => panic!("unexpected volume command"),
            },
            _ => panic!("unexpected command"),
        }

        let backup = Cli::parse_from(["ferrocrate", "volume", "backup", "data", "/tmp/data.tar"]);
        match backup.command {
            Commands::Volume { command } => match command {
                VolumeCommands::Backup { name, path } => {
                    assert_eq!(name, "data");
                    assert_eq!(path, "/tmp/data.tar");
                }
                _ => panic!("unexpected volume command"),
            },
            _ => panic!("unexpected command"),
        }

        let restore = Cli::parse_from(["ferrocrate", "volume", "restore", "data", "/tmp/data.tar"]);
        match restore.command {
            Commands::Volume { command } => match command {
                VolumeCommands::Restore { name, path } => {
                    assert_eq!(name, "data");
                    assert_eq!(path, "/tmp/data.tar");
                }
                _ => panic!("unexpected volume command"),
            },
            _ => panic!("unexpected command"),
        }

        let ls = Cli::parse_from(["ferrocrate", "volume", "ls"]);
        match ls.command {
            Commands::Volume { command } => assert!(matches!(command, VolumeCommands::Ls)),
            _ => panic!("unexpected command"),
        }

        let rm = Cli::parse_from(["ferrocrate", "volume", "rm", "data"]);
        match rm.command {
            Commands::Volume { command } => match command {
                VolumeCommands::Rm { name } => assert_eq!(name, "data"),
                _ => panic!("unexpected volume command"),
            },
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn parses_network_commands() {
        let create = Cli::parse_from([
            "ferrocrate",
            "network",
            "create",
            "--subnet",
            "172.20.0.0/16",
            "--gateway",
            "172.20.0.1",
            "custom-net",
        ]);
        match create.command {
            Commands::Network { command } => match command {
                NetworkCommands::Create {
                    name,
                    subnet,
                    gateway,
                } => {
                    assert_eq!(name, "custom-net");
                    assert_eq!(subnet.as_deref(), Some("172.20.0.0/16"));
                    assert_eq!(gateway.as_deref(), Some("172.20.0.1"));
                }
                _ => panic!("unexpected network command"),
            },
            _ => panic!("unexpected command"),
        }

        let ls = Cli::parse_from(["ferrocrate", "network", "ls"]);
        match ls.command {
            Commands::Network { command } => assert!(matches!(command, NetworkCommands::Ls)),
            _ => panic!("unexpected command"),
        }

        let rm = Cli::parse_from(["ferrocrate", "network", "rm", "custom-net"]);
        match rm.command {
            Commands::Network { command } => match command {
                NetworkCommands::Rm { name } => assert_eq!(name, "custom-net"),
                _ => panic!("unexpected network command"),
            },
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn volume_handlers_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime_dir = temp.path().to_path_buf();

        handle_volume(
            &runtime_dir,
            VolumeCommands::Create {
                name: "data".to_string(),
                driver: "local".to_string(),
                opts: Vec::new(),
            },
        )
        .expect("create volume");
        let store = ferro_core::volume_store::LocalVolumeStore::open(runtime_dir.join("volumes"))
            .expect("store");
        let record = store.get("data").expect("get").expect("record");
        std::fs::write(
            std::path::PathBuf::from(&record.path).join("hello.txt"),
            "hi",
        )
        .expect("write");
        drop(store);

        let archive = runtime_dir.join("backup.tar");
        handle_volume(
            &runtime_dir,
            VolumeCommands::Backup {
                name: "data".to_string(),
                path: archive.display().to_string(),
            },
        )
        .expect("backup volume");

        handle_volume(
            &runtime_dir,
            VolumeCommands::Rm {
                name: "data".to_string(),
            },
        )
        .expect("rm volume");

        handle_volume(
            &runtime_dir,
            VolumeCommands::Restore {
                name: "data".to_string(),
                path: archive.display().to_string(),
            },
        )
        .expect("restore volume");
        handle_volume(&runtime_dir, VolumeCommands::Ls).expect("ls volumes");
        handle_volume(
            &runtime_dir,
            VolumeCommands::Rm {
                name: "data".to_string(),
            },
        )
        .expect("rm volume");
    }

    #[test]
    fn network_handlers_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "test-net".to_string(),
                subnet: Some("172.30.0.0/16".to_string()),
                gateway: Some("172.30.0.1".to_string()),
            },
        )
        .expect("create network");
        handle_network(temp.path(), &runtime, NetworkCommands::Ls).expect("ls networks");
        handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Rm {
                name: "test-net".to_string(),
            },
        )
        .expect("rm network");
    }

    #[test]
    fn stop_kill_rm_restart_require_container() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");

        let err = handle_stop(&runtime, "", 1).expect_err("stop requires container");
        assert!(err.contains("stop: container is required"));

        let err = handle_kill(&runtime, "").expect_err("kill requires container");
        assert!(err.contains("kill: container is required"));

        let err = handle_pause(&runtime, "").expect_err("pause requires container");
        assert!(err.contains("pause: container is required"));

        let err = handle_unpause(&runtime, "").expect_err("unpause requires container");
        assert!(err.contains("unpause: container is required"));

        let err = handle_rm(&runtime, "").expect_err("rm requires container");
        assert!(err.contains("rm: container is required"));

        let err = handle_restart(&runtime, "", 1).expect_err("restart requires container");
        assert!(err.contains("restart: container is required"));
    }

    #[test]
    fn parses_pull_and_push_commands() {
        let pull = Cli::parse_from(["ferrocrate", "pull", "ghcr.io/acme/app:latest"]);
        match pull.command {
            Commands::Pull { image, lazy } => {
                assert_eq!(image, "ghcr.io/acme/app:latest");
                assert!(!lazy);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let push = Cli::parse_from(["ferrocrate", "push", "ghcr.io/acme/app:latest"]);
        match push.command {
            Commands::Push { image } => assert_eq!(image, "ghcr.io/acme/app:latest"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn run_handler_rejects_invalid_image() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let volume_store = LocalVolumeStore::open(temp.path()).expect("volume store");
        let err = handle_run(
            temp.path(),
            &runtime,
            &store,
            &volume_store,
            "",
            &[],
            "bridge",
            "ebpf",
            &[],
            &[],
            &[],
            false,
            false,
            &[],
            &[],
            &[],
            &[],
            None,
            None,
            None,
            None,
            &[],
            None,
            None,
            None,
            None,
            None,
            "no",
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect_err("invalid reference");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn rejects_invalid_bind_mount() {
        let err = parse_bind_mounts(&["/host".to_string()]).expect_err("invalid");
        assert!(err.contains("bind mount"));
    }

    #[test]
    fn rejects_invalid_tmpfs_mount() {
        let err = parse_tmpfs_mounts(&[":size=64m".to_string()]).expect_err("invalid");
        assert!(err.contains("tmpfs"));
    }

    #[test]
    fn parses_publish_mappings() {
        let mappings = parse_publish(&[
            "8080:80".to_string(),
            "8443:443/tcp".to_string(),
            "5353:53/udp".to_string(),
        ])
        .expect("publish mappings");
        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[0].host_port, 8080);
        assert_eq!(mappings[0].container_port, 80);
        assert_eq!(mappings[0].protocol, "tcp");
        assert_eq!(mappings[2].protocol, "udp");
    }

    #[test]
    fn rejects_invalid_publish_mappings() {
        let err = parse_publish(&["bad".to_string()]).expect_err("invalid");
        assert!(err.contains("publish"));
        let err = parse_publish(&["1:2/icmp".to_string()]).expect_err("invalid proto");
        assert!(err.contains("protocol"));
    }

    #[test]
    fn rejects_invalid_env_entry() {
        let err = parse_env_entries(&["NOVAL".to_string()]).expect_err("invalid");
        assert!(err.contains("env"));
    }

    #[test]
    fn rejects_invalid_label_entry() {
        let err = parse_key_values("label", &["bad".to_string()]).expect_err("invalid");
        assert!(err.contains("label"));
    }

    #[test]
    fn health_requires_cmd_when_options_set() {
        let err = build_health_config(None, Some(10), None, None, None).expect_err("missing cmd");
        assert!(err.contains("health-cmd"));
    }

    #[test]
    fn rejects_invalid_restart_policy() {
        let err = parse_restart_policy("nope").expect_err("invalid");
        assert!(err.contains("restart"));
    }

    #[test]
    fn rejects_invalid_capability() {
        let err = parse_capabilities(&["notacap".to_string()]).expect_err("invalid");
        assert!(err.contains("unknown capability"));
    }

    #[test]
    fn rejects_conflicting_readonly_flags() {
        let err = effective_readonly("dev", true, true).expect_err("conflict");
        assert!(err.contains("read-only"));
    }

    #[test]
    fn rejects_invalid_profile() {
        let err = effective_readonly("staging", false, false).expect_err("invalid profile");
        assert!(err.contains("profile"));
    }

    #[test]
    fn rejects_invalid_volume_opt() {
        let err = parse_driver_opts(&["invalid".to_string()]).expect_err("invalid");
        assert!(err.contains("opt"));
    }

    #[test]
    fn limits_require_cpu_period() {
        let err = build_limits(None, Some(100_000), None, None).expect_err("missing period");
        assert!(err.contains("cpu-period"));
    }

    #[test]
    fn dispatch_exec_requires_command() {
        let _guard = TestRuntimeDir::new();
        let err = dispatch(Commands::Exec {
            container: "c1".to_string(),
            cmd: vec![],
        })
        .expect_err("missing command");
        assert!(err.contains("exec: command is required"));
    }

    #[test]
    fn build_handler_requires_dockerfile_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let err = handle_build(&store, None, None, None, "gzip").expect_err("dockerfile required");
        assert!(err.contains("dockerfile path is required"));
    }

    #[test]
    fn build_handler_rejects_invalid_tag() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let err = handle_build(&store, Some("./Dockerfile"), None, Some(""), "gzip")
            .expect_err("invalid tag");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn images_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        handle_images(&store, "text").expect("images handler should succeed");
    }

    #[test]
    fn containers_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        handle_containers(&runtime, "text").expect("containers handler should succeed");
    }

    #[test]
    fn logs_handler_requires_container() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_logs(&runtime, "", "text").expect_err("container required");
        assert!(err.contains("logs: container is required"));
    }

    #[test]
    fn inspect_handler_requires_container() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_inspect(&runtime, "", "text").expect_err("container required");
        assert!(err.contains("inspect: container is required"));
    }

    #[test]
    fn stats_handler_requires_container() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_stats(&runtime, "", "text").expect_err("container required");
        assert!(err.contains("stats: container is required"));
    }

    #[test]
    fn exec_handler_requires_container_and_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err =
            handle_exec(&runtime, "", &["/bin/sh".to_string()]).expect_err("container required");
        assert!(err.contains("exec: container is required"));

        let err = handle_exec(&runtime, "c1", &[]).expect_err("command required");
        assert!(err.contains("exec: command is required"));
    }

    #[test]
    fn pull_handler_rejects_invalid_image() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let err = handle_pull(&store, "", false).expect_err("invalid image");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn push_handler_rejects_invalid_image() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let err = handle_push(&store, "").expect_err("invalid image");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn network_backend_validation() {
        validate_network_backend("ebpf").expect("ok");
        validate_network_backend("iptables").expect("ok");
        validate_network_backend("nftables").expect("ok");
        let err = validate_network_backend("bogus").expect_err("invalid backend");
        assert!(err.contains("network-backend"));
    }

    #[test]
    fn network_mode_validation() {
        validate_network_mode("bridge").expect("ok");
        validate_network_mode("host").expect("ok");
        validate_network_mode("none").expect("ok");
        validate_network_mode("wireguard").expect("ok");
        validate_network_mode("encrypted").expect("ok");
        let err = validate_network_mode("bogus").expect_err("invalid mode");
        assert!(err.contains("network"));
    }

    #[test]
    fn desktop_forward_env_defaults_disabled() {
        unsafe {
            std::env::remove_var("FERROCRATE_DESKTOP_FORWARD");
        }
        assert!(!desktop_forward_enabled());
    }

    #[test]
    fn desktop_forward_env_enables_true_values() {
        unsafe {
            std::env::set_var("FERROCRATE_DESKTOP_FORWARD", "1");
        }
        assert!(desktop_forward_enabled());
        unsafe {
            std::env::set_var("FERROCRATE_DESKTOP_FORWARD", "true");
        }
        assert!(desktop_forward_enabled());
        unsafe {
            std::env::remove_var("FERROCRATE_DESKTOP_FORWARD");
        }
    }

    #[test]
    fn desktop_forward_detects_runtime_commands() {
        assert!(should_desktop_forward(&[
            "run".to_string(),
            "alpine:latest".to_string()
        ]));
        assert!(should_desktop_forward(&[
            "compose".to_string(),
            "up".to_string()
        ]));
        assert!(!should_desktop_forward(&["images".to_string()]));
        assert!(!should_desktop_forward(&[
            "ai".to_string(),
            "stats".to_string()
        ]));
    }

    #[test]
    fn top_level_command_skips_flags() {
        let args = [
            "--verbose".to_string(),
            "--debug".to_string(),
            "run".to_string(),
            "alpine".to_string(),
        ];
        let command = top_level_command_name(&args);
        assert_eq!(command, Some("run"));
    }

    #[test]
    fn structured_desktop_error_supports_text_and_json() {
        unsafe {
            std::env::remove_var("FERROCRATE_ERROR_FORMAT");
            std::env::remove_var("FERROCRATE_ERROR_JSON");
        }
        let text =
            structured_desktop_error("desktop_bridge_unavailable", "bridge failed", "retry", true);
        assert!(text.contains("category=desktop_bridge_unavailable"));
        assert!(text.contains("hint: retry"));

        unsafe {
            std::env::set_var("FERROCRATE_ERROR_FORMAT", "json");
        }
        let json =
            structured_desktop_error("desktop_bridge_unavailable", "bridge failed", "retry", true);
        assert!(json.contains("\"category\":\"desktop_bridge_unavailable\""));
        assert!(json.contains("\"retryable\":true"));
        unsafe {
            std::env::remove_var("FERROCRATE_ERROR_FORMAT");
        }
    }

    struct TestRuntimeDir {
        original: Option<String>,
        _dir: tempfile::TempDir,
    }

    impl TestRuntimeDir {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let original = std::env::var("FERROCRATE_RUNTIME_DIR").ok();
            unsafe {
                std::env::set_var("FERROCRATE_RUNTIME_DIR", dir.path());
            }
            Self {
                original,
                _dir: dir,
            }
        }
    }

    impl Drop for TestRuntimeDir {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var("FERROCRATE_RUNTIME_DIR", value);
                }
            } else {
                unsafe {
                    std::env::remove_var("FERROCRATE_RUNTIME_DIR");
                }
            }
        }
    }
}

fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("FERROCRATE_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".ferrocrate");
    }
    PathBuf::from(".ferrocrate")
}
