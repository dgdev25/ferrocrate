#![allow(clippy::items_after_test_module)]
#![allow(missing_docs)]

use crate::network_lifecycle::{
    canonical_bridge_name, last_committed_bridge_identity, NetworkCreateRecord, NetworkRecord,
};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
#[cfg(target_os = "linux")]
use ferro_cli::authorization_admin;
#[cfg(target_os = "linux")]
use ferro_compose::compose::{
    compose_down, compose_logs, compose_ps, compose_up, find_compose_file, ComposeProject,
};
#[cfg(target_os = "linux")]
use ferro_compose::{
    Command as ComposeCommandSpec, DependsOn as ComposeDependsOn,
    Environment as ComposeEnvironment, FanoutAction, FanoutPlan, FanoutReplayStore,
    Service as ComposeService, ServiceMutation,
};
#[cfg(target_os = "linux")]
use ferro_core::authorization::surface::{SurfaceAuthorization, SurfacePermit};
#[cfg(target_os = "linux")]
use ferro_core::authorization::{Action as AuthorizationAction, RequestOrigin, ResourceKind};
use ferro_core::docker_auth::resolve_registry_auth;
use ferro_core::entitlements::{self, Entitlement, Feature};
#[cfg(target_os = "linux")]
use ferro_core::image_fetch::resolve_layer_paths_with_store;
use ferro_core::image_manifest::parse_image_manifest;
use ferro_core::image_store::LocalImageStore;
use ferro_core::image_tagging::{
    canonicalize_reference, execute_image_tag_authorized, prepare_image_tag, resolve_reference,
};
use ferro_core::layer_compression::CompressionFormat;
use ferro_core::registry::{parse_image_reference, RegistryClient};
#[cfg(target_os = "linux")]
use ferro_core::rootfs::construct_rootfs_with_dedup;
#[cfg(target_os = "linux")]
use ferro_core::runtime::ContainerRuntime;
use ferro_core::runtime::NetworkBackend;
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::collections::{BTreeMap, HashMap};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::net::TcpListener;
#[cfg(target_os = "macos")]
use std::net::TcpStream;
#[cfg(all(unix, target_os = "linux"))]
use std::os::unix::net::UnixListener;
#[cfg(all(unix, target_os = "linux"))]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;
#[cfg(target_os = "linux")]
use std::sync::atomic::AtomicU64;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;
use std::time::SystemTime;

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
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    #[cfg(target_os = "linux")]
    Witness {
        #[command(subcommand)]
        command: WitnessCommands,
    },
    #[cfg(target_os = "linux")]
    Emergency {
        #[command(subcommand)]
        command: EmergencyCommands,
    },
    #[cfg(target_os = "linux")]
    Run {
        image: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "bridge")]
        network: String,
        #[arg(long, default_value = "ebpf", value_parser = validate_network_backend)]
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
        #[arg(long)]
        dockerfile: Option<String>,
        #[arg(long)]
        ferrofile: Option<String>,
        #[arg(short, long)]
        tag: Option<String>,
        #[arg(long, default_value = "gzip", value_parser = validate_compression)]
        compress: String,
        /// Output image format: `oci` (default) or `rvf` (RVF native container).
        #[arg(long, default_value = "oci", value_parser = validate_image_format)]
        image_format: String,
        /// Path to a vector/embedding model to embed in the `.rvf` image (only with `--image-format rvf`).
        #[arg(long)]
        embed_model: Option<String>,
        /// Target platform. Only the host platform is currently supported;
        /// cross-platform output is rejected until a cross-target builder is
        /// available.
        #[arg(long)]
        platform: Option<String>,
        /// Import local build-cache metadata before building.
        #[arg(long = "cache-from")]
        cache_from: Option<String>,
        /// Export local build-cache metadata after a successful build.
        #[arg(long = "cache-to")]
        cache_to: Option<String>,
        /// Bind a named Dockerfile build context (`name=path`); repeatable.
        #[arg(long = "build-context")]
        build_context: Vec<String>,
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
    Context {
        #[command(subcommand)]
        command: ContextCommands,
    },
    Doctor {
        #[arg(long, default_value_t = false)]
        fix: bool,
        #[arg(long, default_value_t = false)]
        bootstrap: bool,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        #[arg(long, default_value_t = false)]
        confirm: bool,
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

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
pub enum PolicyCommands {
    Check {
        path: PathBuf,
    },
    Reload {
        path: PathBuf,
        #[arg(long)]
        rollback_approval: Option<PathBuf>,
    },
}

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
pub enum WitnessCommands {
    Show {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        journal_id: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        from_sequence: Option<u64>,
        #[arg(long)]
        stage: Option<String>,
    },
    Verify {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        trust_bundle: PathBuf,
        #[arg(long)]
        minimum_checkpoint: PathBuf,
        #[arg(long = "checkpoint", required = true)]
        checkpoints: Vec<PathBuf>,
        #[arg(long, default_value_t = 300)]
        max_age_seconds: u64,
    },
    Checkpoint {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        journal_id: String,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        key_dir: Option<PathBuf>,
        #[arg(long)]
        key_name: Option<String>,
        #[arg(long)]
        predecessor: Option<PathBuf>,
        #[arg(long)]
        recover_pending: bool,
    },
    RotateKey {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        journal_id: String,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        key_dir: PathBuf,
        #[arg(long)]
        old_key: String,
        #[arg(long)]
        new_key: String,
        #[arg(long)]
        predecessor: PathBuf,
    },
}

#[cfg(target_os = "linux")]
#[derive(Debug, Subcommand)]
pub enum EmergencyCommands {
    Activate {
        #[arg(long, default_value = "console", hide = true)]
        origin: String,
        #[arg(long)]
        sink: Option<PathBuf>,
        #[arg(long, default_value = "filesystem")]
        sink_backend: String,
        #[arg(long)]
        sink_receipt_key: Option<PathBuf>,
        #[arg(long)]
        sink_journal_id: Option<String>,
        #[arg(long)]
        sink_server_uid: Option<u32>,
        #[arg(long)]
        recovery_public_key: Option<PathBuf>,
        #[arg(long)]
        recovery_approval: Option<PathBuf>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        resource: Option<String>,
        #[arg(long)]
        nonce: Option<String>,
        #[arg(long)]
        deadline_uptime_ns: Option<u64>,
    },
    Execute {
        #[arg(long)]
        action: String,
        #[arg(long)]
        resource: String,
        #[arg(long, default_value = "filesystem")]
        sink_backend: String,
        #[arg(long)]
        sink: Option<PathBuf>,
    },
    Reconcile {
        #[arg(long, default_value = "filesystem")]
        sink_backend: String,
        #[arg(long)]
        sink: Option<PathBuf>,
    },
    SinkServe {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        journal_id: String,
        #[arg(long)]
        expected_uid: u32,
        #[arg(long)]
        requests: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
pub enum MigrateCommands {
    DockerAuth {
        #[arg(long)]
        output: Option<String>,
    },
    /// Validate a Compose file and emit a sanitized migration plan.
    ComposeReport {
        #[arg(long, short = 'f')]
        file: PathBuf,
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
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
        #[arg(long = "ipv6-subnet")]
        ipv6_subnet: Option<String>,
        #[arg(long = "ipv6-gateway")]
        ipv6_gateway: Option<String>,
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
    /// Discover GPUs and optionally select one with enough free VRAM.
    Gpu {
        #[arg(long = "required-vram-bytes")]
        required_vram_bytes: Option<u64>,
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
pub enum ContextCommands {
    Create {
        name: String,
        #[arg(long)]
        endpoint: String,
    },
    Inspect {
        name: Option<String>,
    },
    List,
    Use {
        name: String,
    },
    Rm {
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EntitlementCommands {
    Status {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

fn main() {
    // Initialize tracing subscriber for structured logging (CQ-03)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    match maybe_host_desktop_forward(&raw_args) {
        Ok(true) => return,
        Ok(false) => {}
        Err(err) => {
            tracing::error!("{err}");
            eprintln!("error: {err}");
            process::exit(1);
        }
    }
    let cli = Cli::parse();
    let qualification_before = ferro_core::observability::authorization_metrics_snapshot();
    let qualification_fixture = ferro_core::observability::qualification_fixture("cli");
    if let Err(err) = dispatch(cli.command) {
        let normalized = normalize_cli_error(err);
        let _ = ferro_core::observability::persist_authorization_fixture_evidence(
            &qualification_fixture,
            qualification_before,
            ferro_core::observability::authorization_metrics_snapshot(),
        );
        tracing::error!("{normalized}");
        eprintln!("error: {normalized}");
        process::exit(1);
    }
    let _ = ferro_core::observability::persist_authorization_fixture_evidence(
        &qualification_fixture,
        qualification_before,
        ferro_core::observability::authorization_metrics_snapshot(),
    );
}

#[cfg(all(any(test, not(target_os = "linux")), target_os = "macos"))]
fn desktop_forward_enabled() -> bool {
    if let Ok(value) = std::env::var("FERROCRATE_DESKTOP_FORWARD") {
        return value == "1" || value.eq_ignore_ascii_case("true");
    }
    true
}

#[cfg(all(any(test, not(target_os = "linux")), not(target_os = "macos")))]
fn desktop_forward_enabled() -> bool {
    if let Ok(value) = std::env::var("FERROCRATE_DESKTOP_FORWARD") {
        return value == "1" || value.eq_ignore_ascii_case("true");
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
    action: Option<DoctorAction>,
}

#[derive(Debug, Serialize)]
struct DoctorAction {
    id: String,
    description: String,
    command: Vec<String>,
    requires_confirmation: bool,
}

#[allow(dead_code)]
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
fn vm_state_status(value: &serde_json::Value) -> Option<String> {
    value
        .get("status")
        .and_then(|v| v.as_str())
        .map(|v| v.to_string())
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

#[cfg(target_os = "macos")]
fn doctor_guest_ssh_diagnose(
    ssh_port: u16,
    guest_user: Option<String>,
    ssh_key: Option<String>,
) -> Result<(), String> {
    let mut command = std::process::Command::new("ssh");
    command
        .arg("-p")
        .arg(ssh_port.to_string())
        .arg("-o")
        .arg("BatchMode=yes")
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
        .arg("true");
    let output = command
        .output()
        .map_err(|err| format!("ssh launch failed: {err}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.contains("Connection refused") {
        return Err("ssh connection refused (port forwarding down)".to_string());
    }
    if stderr.contains("Connection timed out") {
        return Err("ssh connection timed out".to_string());
    }
    if stderr.contains("Permission denied") {
        return Err("ssh permission denied (key/user mismatch)".to_string());
    }
    if stderr.contains("No such file") && stderr.contains("identity file") {
        return Err("ssh key file missing or unreadable".to_string());
    }
    Err(format!("ssh failed: {stderr}"))
}

fn handle_doctor(
    fix: bool,
    bootstrap: bool,
    dry_run: bool,
    confirm: bool,
    json: bool,
) -> Result<(), String> {
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
            action: (!desktop_present).then_some(DoctorAction {
                id: "install_desktop_artifacts".to_string(),
                description: "install paid desktop artifacts".to_string(),
                command: vec![
                    "bash".to_string(),
                    "scripts/install-macos.sh".to_string(),
                    "--channel".to_string(),
                    "paid".to_string(),
                    "--full-stack".to_string(),
                ],
                requires_confirmation: true,
            }),
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
            let action = (!ok && fix).then_some(DoctorAction {
                id: format!("install_{bin}"),
                description: format!("install {formula} via brew"),
                command: vec![
                    "brew".to_string(),
                    "install".to_string(),
                    formula.to_string(),
                ],
                requires_confirmation: true,
            });
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
                action,
            });
        }

        let mut vm_running = false;
        let mut vm_ssh_port = 2222u16;
        let mut vm_guest_user = None;
        let mut vm_ssh_key = None;
        let mut vm_status_label: Option<String> = None;
        let status_output = std::process::Command::new(&desktop_bin)
            .args(["vm", "status", "--json"])
            .output();
        match status_output {
            Ok(output) if output.status.success() => {
                let raw = String::from_utf8_lossy(&output.stdout);
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                    vm_status_label = vm_state_status(&value);
                }
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
        if !vm_running && fix && desktop_present && confirm && !dry_run {
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
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) {
                            vm_status_label = vm_state_status(&value);
                        }
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
                    "desktop VM is not running (state={}, state file: {})",
                    vm_status_label.as_deref().unwrap_or("unknown"),
                    doctor_default_vm_state_file().display()
                )
            },
            hint: (!vm_running).then_some(
                "initialize/start VM with `ferro-desktop vm init ...` then `ferro-desktop vm start`".to_string(),
            ),
            remediated: vm_remediated,
            action: (!vm_running && desktop_present).then_some(DoctorAction {
                id: "start_vm".to_string(),
                description: "start desktop VM".to_string(),
                command: vec![desktop_bin.display().to_string(), "vm".to_string(), "start".to_string()],
                requires_confirmation: true,
            }),
        });

        let mut ssh_ok = false;
        let mut ssh_diag: Option<String> = None;
        if vm_running {
            ssh_ok = TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], vm_ssh_port)),
                Duration::from_secs(2),
            )
            .is_ok();
            if !ssh_ok {
                ssh_diag = doctor_guest_ssh_diagnose(
                    vm_ssh_port,
                    vm_guest_user.clone(),
                    vm_ssh_key.clone(),
                )
                .err();
            }
        }
        checks.push(DoctorCheck {
            id: "guest_ssh".to_string(),
            ok: ssh_ok,
            message: if ssh_ok {
                format!("guest SSH reachable on 127.0.0.1:{vm_ssh_port}")
            } else {
                format!("guest SSH not reachable on 127.0.0.1:{vm_ssh_port}")
            },
            hint: (!ssh_ok).then_some(ssh_diag.clone().unwrap_or_else(|| {
                "ensure VM networking/port-forward is healthy (`ferro-desktop vm status --json`)"
                    .to_string()
            })),
            remediated: false,
            action: None,
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
            action: (!guest_ferro_ok).then_some(DoctorAction {
                id: "bootstrap_guest_runtime".to_string(),
                description: "bootstrap guest runtime via paid installer".to_string(),
                command: vec![
                    "bash".to_string(),
                    "scripts/install-macos.sh".to_string(),
                    "--channel".to_string(),
                    "paid".to_string(),
                    "--full-stack".to_string(),
                ],
                requires_confirmation: true,
            }),
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
            action: None,
        });

        #[cfg(target_os = "linux")]
        {
            let rootless = ferro_core::rootless::RootlessConfig::from_system();
            let runtime_socket = discover_rootless_socket();
            let socket_message = runtime_socket.as_ref().map_or_else(
                || "rootless Docker socket not discovered (set XDG_RUNTIME_DIR or use the configured daemon socket)".to_string(),
                |path| format!("rootless Docker socket discovered at {}", path.display()),
            );
            checks.push(DoctorCheck {
                id: "rootless_context".to_string(),
                ok: rootless.is_ok(),
                message: match rootless {
                    Ok(config) => format!(
                        "rootless context available for {} (uid map {}:{} size {}; gid map {}:{} size {}); {}",
                        config.username,
                        config.uid_mapping.container_id,
                        config.uid_mapping.host_id,
                        config.uid_mapping.size,
                        config.gid_mapping.container_id,
                        config.gid_mapping.host_id,
                        config.gid_mapping.size,
                        socket_message,
                    ),
                    Err(error) => format!("rootless context unavailable: {error}; {socket_message}"),
                },
                hint: Some(
                    "rootless contexts currently support the local runtime; CRI, Compose, and advanced network features remain explicitly qualification-gated".to_string(),
                ),
                remediated: false,
                action: None,
            });
        }
    }

    let healthy = checks.iter().all(|check| check.ok);
    #[cfg(target_os = "macos")]
    let mut healthy = healthy;

    #[cfg(target_os = "macos")]
    if fix && bootstrap && !healthy {
        if !confirm {
            return Err(
                "doctor bootstrap requires --confirm to execute. Use --dry-run to preview actions."
                    .to_string(),
            );
        }
        if dry_run {
            return Err(
                "doctor bootstrap requested with --dry-run; no changes applied.".to_string(),
            );
        }
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
                .arg("--force")
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
            action: None,
        });
        healthy = checks.iter().all(|check| check.ok);
    }

    if json {
        let payload = serde_json::json!({
            "healthy": healthy,
            "fix": fix,
            "bootstrap": bootstrap,
            "dry_run": dry_run,
            "confirm": confirm,
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
                if let Some(action) = &check.action {
                    println!("      action: {}", action.description);
                    println!("      command: {}", action.command.join(" "));
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

#[cfg(target_os = "linux")]
fn discover_rootless_socket() -> Option<PathBuf> {
    use std::os::unix::fs::FileTypeExt;

    let mut candidates = Vec::new();
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(runtime).join("docker.sock"));
    }
    candidates.push(runtime_dir().join("docker.sock"));
    candidates.into_iter().find(|path| {
        std::fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
    })
}

#[cfg(target_os = "linux")]
fn dispatch_policy(command: &PolicyCommands, runtime_dir: &Path) -> Result<(), String> {
    let output = match command {
        PolicyCommands::Check { path } => authorization_admin::policy_check(path),
        PolicyCommands::Reload {
            path,
            rollback_approval,
        } => {
            let active = runtime_dir.join("authorization/active-policy.toml");
            let candidate = ferro_core::authorization::policy::PolicyStore::load_candidate(path)
                .map_err(|error| error.to_string())?;
            let rollback = active.exists()
                && ferro_core::authorization::policy::PolicyStore::load(&active)
                    .map_err(|error| error.to_string())?
                    .snapshot()
                    .generation
                    > candidate.snapshot().generation;
            let action = if rollback {
                AuthorizationAction::PolicyRollback
            } else {
                AuthorizationAction::PolicyReload
            };
            let canonical_name = candidate
                .snapshot()
                .digest
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let runtime = ContainerRuntime::new(runtime_dir)
                .map_err(|error| error.to_string())?
                .with_request_origin(
                    RequestOrigin::cli_current().map_err(|error| error.to_string())?,
                );
            let origin = runtime
                .request_origin()
                .ok_or("policy reload identity unavailable")?;
            let authorization = runtime
                .surface_authorization()
                .map_err(|error| error.to_string())?;
            let permit = authorization
                .authorize_named(
                    &origin,
                    action,
                    ResourceKind::Policy,
                    &canonical_name,
                    candidate.snapshot().generation,
                )
                .map_err(|error| error.to_string())?;
            let result = authorization_admin::policy_reload(
                &candidate,
                &active,
                rollback_approval.as_deref(),
                &permit,
                action,
                &canonical_name,
            )
            .and_then(|output| {
                runtime
                    .install_policy_candidate(&candidate, rollback)
                    .map(|_| output)
                    .map_err(|error| error.to_string())
            });
            permit
                .finish(result.is_ok())
                .map_err(|error| error.to_string())?;
            result
        }
    }?;
    println!("{output}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn dispatch_witness(command: &WitnessCommands, runtime_dir: &Path) -> Result<(), String> {
    let output = match command {
        WitnessCommands::Show {
            journal,
            journal_id,
            limit,
            from_sequence,
            stage,
        } => authorization_admin::show(authorization_admin::ShowArgs {
            journal,
            journal_id,
            limit: *limit,
            from_sequence: *from_sequence,
            stage: stage.as_deref(),
        }),
        WitnessCommands::Verify {
            journal,
            trust_bundle,
            minimum_checkpoint,
            checkpoints,
            max_age_seconds,
        } => authorization_admin::verify(authorization_admin::VerifyArgs {
            journal,
            trust_bundle,
            minimum_checkpoint,
            checkpoints,
            max_age_seconds: *max_age_seconds,
        }),
        WitnessCommands::Checkpoint {
            journal,
            journal_id,
            artifact,
            key_dir,
            key_name,
            predecessor,
            recover_pending,
        } => {
            let args = authorization_admin::CheckpointArgs {
                journal,
                journal_id,
                artifact,
                key_dir: key_dir.as_deref(),
                key_name: key_name.as_deref(),
                predecessor: predecessor.as_deref(),
                recover_pending: *recover_pending,
            };
            let action = if *recover_pending {
                AuthorizationAction::CheckpointRecover
            } else {
                AuthorizationAction::CheckpointPublish
            };
            administer_witness(
                runtime_dir,
                journal,
                journal_id,
                artifact,
                action,
                &artifact.to_string_lossy(),
                |open| authorization_admin::checkpoint_on(args, open),
            )
        }
        WitnessCommands::RotateKey {
            journal,
            journal_id,
            artifact,
            key_dir,
            old_key,
            new_key,
            predecessor,
        } => {
            let args = authorization_admin::RotateArgs {
                journal,
                journal_id,
                artifact,
                key_dir,
                old_key,
                new_key,
                predecessor,
            };
            let predecessor_digest =
                Sha256::digest(std::fs::read(predecessor).map_err(|error| error.to_string())?);
            let binding = format!("old={old_key};new={new_key};predecessor={predecessor_digest:x}");
            administer_witness(
                runtime_dir,
                journal,
                journal_id,
                artifact,
                AuthorizationAction::KeyRotate,
                &binding,
                |open| authorization_admin::rotate_key_on(args, open),
            )
        }
    }?;
    println!("{output}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn administer_witness<F>(
    runtime_dir: &Path,
    journal: &Path,
    journal_id: &str,
    artifact: &Path,
    action: AuthorizationAction,
    resource_binding: &str,
    execute: F,
) -> Result<String, String>
where
    F: FnOnce(&ferro_core::witness::WitnessJournal) -> Result<String, String>,
{
    authorization_admin::require_host_admin()?;
    let root = runtime_dir.join("authorization");
    if journal != root.join("witness-journal") || artifact != root.join("checkpoint.bin") {
        return Err("administrative witness mutation requires the runtime's fixed journal and checkpoint paths".into());
    }
    let policies = std::sync::Arc::new(
        ferro_core::authorization::policy::PolicyStore::load(root.join("active-policy.toml"))
            .map_err(|error| error.to_string())?,
    );
    let gate = std::sync::Arc::new(ferro_core::authorization::gate::AuthorizationGate::new(
        policies,
    ));
    let open = authorization_admin::open_required_journal(journal, journal_id)?;
    let surface = ferro_core::authorization::surface::SurfaceAuthorization::local_administrative(
        gate,
        open.clone(),
        [0x41; 16],
    );
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    let permit = surface
        .authorize_named(
            &origin,
            action,
            ResourceKind::Administrative,
            resource_binding,
            1,
        )
        .map_err(|error| error.to_string())?;
    let result = execute(&open);
    permit
        .finish(result.is_ok())
        .map_err(|error| error.to_string())?;
    result
}

#[cfg(target_os = "linux")]
fn dispatch_emergency(command: &EmergencyCommands, runtime_dir: &Path) -> Result<(), String> {
    let output = match command {
        EmergencyCommands::SinkServe {
            socket,
            store,
            signing_key,
            journal_id,
            expected_uid,
            requests,
        } => {
            if nix::unistd::geteuid().as_raw() != 0
                && nix::unistd::geteuid().as_raw() != *expected_uid
            {
                return Err("emergency sink service requires host administrator authority".into());
            }
            authorization_admin::emergency_sink::serve(
                authorization_admin::emergency_sink::SinkServeConfig {
                    socket,
                    store,
                    signing_key,
                    journal_id: authorization_admin::decode_hex::<16>(journal_id)?,
                    expected_uid: *expected_uid,
                    requests: *requests,
                },
            )?;
            Ok("emergency sink service stopped".into())
        }
        EmergencyCommands::Activate {
            origin,
            sink,
            sink_backend,
            sink_receipt_key,
            sink_journal_id,
            sink_server_uid,
            recovery_public_key,
            recovery_approval,
            action,
            resource,
            nonce,
            deadline_uptime_ns,
        } => {
            if origin != "console" && !(cfg!(feature = "test-console") && origin == "test-console")
            {
                return Err("emergency activation is local-console-only and unavailable through Docker, CRI, or remote APIs".into());
            }
            let default_state_dir = runtime_dir.join("authorization");
            let unix_config;
            let selected = match sink_backend.as_str() {
                "filesystem" => authorization_admin::EmergencySink::Filesystem(
                    sink.as_deref().ok_or("--sink is required")?,
                ),
                "unix" => {
                    let endpoint = sink
                        .as_ref()
                        .and_then(|value| value.to_str())
                        .ok_or("--sink unix:/absolute/path is required")?;
                    unix_config = authorization_admin::emergency_sink::UnixSinkConfig::from_cli(
                        endpoint,
                        sink_receipt_key
                            .as_deref()
                            .ok_or("--sink-receipt-key is required for Unix sink")?,
                        authorization_admin::decode_hex::<16>(
                            sink_journal_id
                                .as_deref()
                                .ok_or("--sink-journal-id is required for Unix sink")?,
                        )?,
                        sink_server_uid.ok_or("--sink-server-uid is required for Unix sink")?,
                    )?;
                    authorization_admin::EmergencySink::Unix(&unix_config)
                }
                _ => return Err("--sink-backend must be filesystem or unix".into()),
            };
            authorization_admin::activate_emergency(authorization_admin::EmergencyActivate {
                origin,
                state_dir: &default_state_dir,
                sink: selected,
                recovery_public_key: recovery_public_key
                    .as_deref()
                    .ok_or("--recovery-public-key is required")?,
                recovery_approval: recovery_approval
                    .as_deref()
                    .ok_or("--recovery-approval is required")?,
                action: action.as_deref().ok_or("--action is required")?,
                resource: resource.as_deref().ok_or("--resource is required")?,
                nonce: nonce.as_deref().ok_or("--nonce is required")?,
                deadline_uptime_ns: deadline_uptime_ns.ok_or("--deadline-uptime-ns is required")?,
            })
        }
        EmergencyCommands::Reconcile { sink_backend, sink } => {
            let state_dir = runtime_dir.join("authorization");
            match sink_backend.as_str() {
                "filesystem" => authorization_admin::reconcile_emergency(
                    &state_dir,
                    authorization_admin::EmergencySink::Filesystem(
                        sink.as_deref().ok_or("--sink is required")?,
                    ),
                ),
                "unix" => {
                    let config = authorization_admin::persisted_unix_sink(&state_dir)?;
                    authorization_admin::reconcile_emergency(
                        &state_dir,
                        authorization_admin::EmergencySink::Unix(&config),
                    )
                }
                _ => Err("--sink-backend must be filesystem or unix".into()),
            }
        }
        EmergencyCommands::Execute {
            action,
            resource,
            sink_backend,
            sink,
        } => {
            let state_dir = runtime_dir.join("authorization");
            let unix_config;
            let selected = match sink_backend.as_str() {
                "filesystem" => authorization_admin::EmergencySink::Filesystem(
                    sink.as_deref().ok_or("--sink is required")?,
                ),
                "unix" => {
                    unix_config = authorization_admin::persisted_unix_sink(&state_dir)?;
                    authorization_admin::EmergencySink::Unix(&unix_config)
                }
                _ => return Err("--sink-backend must be filesystem or unix".into()),
            };
            authorization_admin::execute_emergency(
                &state_dir,
                selected,
                action,
                resource,
                |operation_id, material| {
                    let origin = RequestOrigin::cli_current_for_operation(operation_id)
                        .map_err(|error| error.to_string())?;
                    let container_id = resource
                        .strip_prefix("container:")
                        .ok_or("container resource must use container:ID")?;
                    let runtime = ContainerRuntime::new(runtime_dir)
                        .map_err(|error| error.to_string())?
                        .with_request_origin(origin.clone());
                    let record = runtime
                        .inspect(container_id)
                        .map_err(|error| error.to_string())?;
                    let emergency_action = match action.as_str() {
                        "container.stop" => AuthorizationAction::ContainerStop,
                        "container.kill" => AuthorizationAction::ContainerKill,
                        "container.remove" => AuthorizationAction::ContainerDelete,
                        _ => return Err("emergency action has no private executor".into()),
                    };
                    let authority =
                        ferro_core::authorization::emergency::EmergencyAuthority::verify(
                            &material.signed_payload,
                            material.signature,
                            material.recovery_key,
                            emergency_action,
                            container_id.to_owned(),
                            record.mutation_generation.max(1),
                            material.boot_id,
                            material.deadline_uptime_ns,
                            origin.principal(),
                            runtime.policy_binding().1,
                            operation_id,
                        )
                        .map_err(|error| error.to_string())?;
                    let runtime = runtime.with_emergency_authority(authority);
                    match action.as_str() {
                        "container.stop" => runtime
                            .stop(container_id, Duration::from_secs(10))
                            .map_err(|error| error.to_string()),
                        "container.kill" => runtime
                            .kill(container_id)
                            .map_err(|error| error.to_string()),
                        "container.remove" => runtime
                            .remove(container_id)
                            .map_err(|error| error.to_string()),
                        _ => Err("emergency action has no private executor".into()),
                    }
                },
            )
        }
    }?;
    println!("{output}");
    Ok(())
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

        match &command {
            Commands::Policy {
                command: command @ PolicyCommands::Check { .. },
            } => return dispatch_policy(command, &runtime_dir),
            Commands::Witness {
                command: command @ (WitnessCommands::Show { .. } | WitnessCommands::Verify { .. }),
            } => return dispatch_witness(command, &runtime_dir),
            Commands::Emergency { command } => return dispatch_emergency(command, &runtime_dir),
            _ => {}
        }
        authorization_admin::ensure_reconciled(&runtime_dir.join("authorization"))?;
        match &command {
            Commands::Policy { command } => return dispatch_policy(command, &runtime_dir),
            Commands::Witness { command } => return dispatch_witness(command, &runtime_dir),
            _ => {}
        }

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

        let runtime = ContainerRuntime::new(&runtime_dir)
            .map_err(|err| err.to_string())?
            .with_request_origin(
                ferro_core::authorization::RequestOrigin::cli_current()
                    .map_err(|error| format!("CLI identity resolution failed: {error}"))?,
            );
        let surface_authorization = runtime
            .surface_authorization()
            .map_err(|error| error.to_string())?;
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
                    None,
                )
            }
            #[cfg(target_os = "linux")]
            Commands::Build {
                dockerfile,
                ferrofile,
                tag,
                compress,
                image_format,
                embed_model,
                platform,
                cache_from,
                cache_to,
                build_context,
            } => handle_build(
                &image_store,
                &runtime
                    .request_origin()
                    .ok_or_else(|| "build: authenticated request origin unavailable".to_string())?,
                &surface_authorization,
                dockerfile.as_deref(),
                ferrofile.as_deref(),
                tag.as_deref(),
                compress.as_str(),
                image_format.as_str(),
                embed_model.as_deref(),
                platform.as_deref(),
                cache_from.as_deref(),
                cache_to.as_deref(),
                &build_context,
            ),
            Commands::Images { format } => handle_images(&image_store, &format),
            Commands::Rmi { image } => handle_rmi(&image_store, &image, &surface_authorization),
            Commands::ImagePrune => handle_image_prune(&image_store, &surface_authorization),
            Commands::Volume { command } => {
                handle_volume(&runtime_dir, command, &surface_authorization)
            }
            #[cfg(target_os = "linux")]
            Commands::Network { command } => {
                handle_network(&runtime_dir, &runtime, command, &surface_authorization)
            }
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
            Commands::Pull { image, lazy } => {
                handle_pull(&image_store, &image, lazy, &surface_authorization)
            }
            Commands::Push { image } => handle_push(&image_store, &image),
            #[cfg(target_os = "linux")]
            Commands::Scan { image, scanner } => {
                handle_scan(&image_store, &image, &scanner, &surface_authorization)
            }
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
            Commands::Policy { .. } | Commands::Witness { .. } | Commands::Emergency { .. } => {
                unreachable!("authorization administration handled before runtime initialization")
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
                dry_run,
                confirm,
                json,
            } => handle_doctor(fix, bootstrap, dry_run, confirm, json),
            Commands::Config { command } => handle_config(command),
            Commands::Context { command } => handle_context(command),
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
                dry_run,
                confirm,
                json,
            } => handle_doctor(fix, bootstrap, dry_run, confirm, json),
            Commands::Config { command } => handle_config(command),
            Commands::Context { command } => handle_context(command),
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
        AiCommands::Gpu {
            required_vram_bytes,
            format,
        } => {
            let gpus = ferro_mind::ai::gpu::discover_gpus()
                .map_err(|error| format!("ai gpu discovery: {error}"))?;
            let selected = required_vram_bytes
                .and_then(|required| ferro_mind::ai::gpu::select_gpu(&gpus, required));
            if format == "json" {
                let payload = serde_json::json!({
                    "gpus": gpus,
                    "required_vram_bytes": required_vram_bytes,
                    "selected": selected,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload)
                        .map_err(|error| format!("ai gpu: {error}"))?
                );
            } else {
                for gpu in &gpus {
                    println!(
                        "ai gpu: id={} name={} vram_total_bytes={} vram_free_bytes={} utilization_percent={:.1}",
                        gpu.id,
                        gpu.name,
                        gpu.vram_total_bytes,
                        gpu.vram_free_bytes,
                        gpu.utilization_percent
                    );
                }
                if let Some(selected) = selected {
                    println!("ai gpu selected: {}", selected.id);
                } else if required_vram_bytes.is_some() {
                    println!("ai gpu selected: none");
                }
            }
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
    ai_config: Option<&ferro_core::ai_runtime::AiRuntimeConfig>,
) -> Result<(), String> {
    let binding = bind_run_network(runtime_dir, network, bridge_cidr, bridge_name)?;
    let effective_network = binding.mode;
    let selected_network_name = binding.association;
    let resolved_bridge_cidr = binding.bridge_cidr;
    let resolved_bridge_name = binding.bridge_name;
    let _bridge_cidr_guard =
        ScopedEnv::set("FERROCRATE_BRIDGE_CIDR", resolved_bridge_cidr.as_deref());
    let _bridge_name_guard =
        ScopedEnv::set("FERROCRATE_BRIDGE_NAME", resolved_bridge_name.as_deref());
    let _net_limit_guard = ScopedEnv::set("FERROCRATE_BANDWIDTH_LIMIT", net_limit);
    let configured_backend = configured_ai_backend();
    let _backend_guard = ScopedEnv::set("FERROCRATE_AI_BACKEND", configured_backend.as_deref());
    let _model_guard = ScopedEnv::set("FERROCRATE_AI_MODEL", ai_model);
    let effective_backend = network_backend
        .parse::<NetworkBackend>()
        .map_err(|err| err.to_string())?;
    if !publish.is_empty() && effective_network != "bridge" {
        return Err("run: publish requires --network bridge".to_string());
    }
    // Provide a clear error when a user accidentally passes a .rvf file to `run`.
    if ferro_core::rvf_image::is_rvf_image(Path::new(image)) {
        return Err(format!(
            "run: '{}' is an RVF image file. \
             Use `ferrocrate build --image-format oci` to convert it to an OCI image first, \
             or wait for native RVF runtime support.",
            image
        ));
    }
    parse_image_reference(image).map_err(|error| error.to_string())?;
    let origin = runtime
        .request_origin()
        .ok_or_else(|| "run: authenticated request origin unavailable".to_string())?;
    let surface_authorization = runtime
        .surface_authorization()
        .map_err(|error| error.to_string())?;
    ensure_image_present(store, image, &origin, &surface_authorization)?;
    let limits = build_limits(memory_max, cpu_quota, cpu_period, pids_max)?;
    let mounts = parse_bind_mounts(bind_mounts)?;
    let volume_mounts =
        parse_volume_mounts(volume_store, volumes, &origin, &surface_authorization)?;
    let mut mounts = mounts;
    mounts.extend(volume_mounts);
    let tmpfs = parse_tmpfs_mounts(tmpfs_mounts)?;
    let env = parse_env_entries(env)?;
    // Resolve ai_runtime config: caller-supplied takes precedence over ferrofile.toml.
    let ferrofile_ai_config;
    let effective_ai_config: Option<&ferro_core::ai_runtime::AiRuntimeConfig> =
        if ai_config.is_some() {
            ai_config
        } else {
            let ferrofile_path = std::env::current_dir()
                .ok()
                .map(|d| d.join("ferrofile.toml"));
            ferrofile_ai_config = ferrofile_path.as_deref().and_then(|p| {
                ferro_core::ferrofile_build::ai_runtime_config_from_ferrofile(p)
                    .ok()
                    .flatten()
            });
            ferrofile_ai_config.as_ref()
        };
    if let Some(ai) = effective_ai_config {
        ferro_core::ai_runtime::check_coherence_gates(&ai.coherence_gates, &env)
            .map_err(|e| e.to_string())?;
    }
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
            selected_network_name.as_deref(),
            effective_backend,
            effective_ai_config,
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
        MigrateCommands::ComposeReport { file, output } => {
            handle_migrate_compose_report(&file, output.as_deref())
        }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CliContext {
    endpoint: String,
}

fn handle_context(command: ContextCommands) -> Result<(), String> {
    let mut config = load_cli_config()?;
    match command {
        ContextCommands::Create { name, endpoint } => {
            validate_context_name(&name)?;
            validate_context_endpoint(&endpoint)?;
            if config.contexts.contains_key(&name) {
                return Err(format!("context create: context already exists: {name}"));
            }
            config
                .contexts
                .insert(name.clone(), CliContext { endpoint });
            if config.current_context.is_none() {
                config.current_context = Some(name.clone());
            }
            save_cli_config(&config)?;
            println!("{name}");
            Ok(())
        }
        ContextCommands::Inspect { name } => {
            let selected = name.or_else(|| config.current_context.clone());
            let Some(name) = selected else {
                return Err("context inspect: no context selected".to_string());
            };
            let Some(context) = config.contexts.get(&name) else {
                return Err(format!("context inspect: context not found: {name}"));
            };
            let payload = serde_json::json!({
                "Name": name,
                "Current": config.current_context.as_deref() == Some(name.as_str()),
                "Endpoint": context.endpoint,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        ContextCommands::List => {
            for (name, context) in &config.contexts {
                let marker = if config.current_context.as_deref() == Some(name.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!("{marker} {name}\t{}", context.endpoint);
            }
            Ok(())
        }
        ContextCommands::Use { name } => {
            if !config.contexts.contains_key(&name) {
                return Err(format!("context use: context not found: {name}"));
            }
            config.current_context = Some(name.clone());
            save_cli_config(&config)?;
            println!("{name}");
            Ok(())
        }
        ContextCommands::Rm { name } => {
            if config.contexts.remove(&name).is_none() {
                return Err(format!("context rm: context not found: {name}"));
            }
            if config.current_context.as_deref() == Some(name.as_str()) {
                config.current_context = config.contexts.keys().next().cloned();
            }
            save_cli_config(&config)?;
            Ok(())
        }
    }
}

fn validate_context_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(
            "context name must be 1-64 ASCII letters, digits, '-', '_', or '.'".to_string(),
        );
    }
    Ok(())
}

fn validate_context_endpoint(endpoint: &str) -> Result<(), String> {
    let path = endpoint
        .strip_prefix("unix://")
        .ok_or_else(|| "context endpoint must use unix:///absolute/socket/path".to_string())?;
    if !Path::new(path).is_absolute() || path.contains('\0') {
        return Err("context endpoint must use an absolute Unix socket path".to_string());
    }
    Ok(())
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
    #[serde(default)]
    contexts: BTreeMap<String, CliContext>,
    #[serde(default)]
    current_context: Option<String>,
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

fn handle_migrate_compose_report(file: &Path, output: Option<&Path>) -> Result<(), String> {
    let project = ferro_compose::compose::ComposeProject::load(file)
        .map_err(|error| format!("migrate compose-report: {error}"))?;
    let graph = project
        .validate_dependencies()
        .map_err(|error| format!("migrate compose-report: {error}"))?;
    let mut services = serde_json::Map::new();
    let mut manual_review = Vec::new();
    for name in project.services() {
        let service = project
            .compose
            .services
            .get(&name)
            .ok_or_else(|| format!("migrate compose-report: service disappeared: {name}"))?;
        let has_image = service.image.is_some();
        let has_build = service.build.is_some();
        if !has_image && !has_build {
            manual_review.push(format!("{name}: no image or build source"));
        }
        if let Some(mode) = service.network_mode.as_deref() {
            if mode == "host" || mode.starts_with("service:") {
                manual_review.push(format!("{name}: network_mode={mode}"));
            }
        }
        if service.deploy.is_some() {
            manual_review.push(format!("{name}: deploy constraints require review"));
        }
        services.insert(
            name,
            serde_json::json!({
                "image": service.image,
                "build": service.build.as_ref().map(|build| serde_json::json!({
                    "context": build.context,
                    "dockerfile": build.dockerfile,
                })),
                "ports": service.ports.as_ref().map(Vec::len).unwrap_or(0),
                "volumes": service.volumes.as_ref().map(Vec::len).unwrap_or(0),
                "networks": service.networks,
                "depends_on": service.depends_on,
                "restart": service.restart,
                "profiles": service.profiles,
            }),
        );
    }
    let mut networks = project
        .compose
        .networks
        .as_ref()
        .map(|values| values.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    networks.sort();
    let mut volumes = project
        .compose
        .volumes
        .as_ref()
        .map(|values| values.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    volumes.sort();
    let report = serde_json::json!({
        "schema": "ferrocrate/migration-report/v1",
        "source": file,
        "compose_version": project.compose.version,
        "services": services,
        "networks": networks,
        "volumes": volumes,
        "dependency_order": graph.start_batches(),
        "manual_review": manual_review,
        "execution": "report-only; no containers, networks, volumes, or images were mutated",
    });
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("migrate compose-report: {error}"))?;
    if let Some(output) = output {
        ferro_core::fs_atomic::write_atomic(output, &bytes)
            .map_err(|error| format!("migrate compose-report: {error}"))?;
    } else {
        println!(
            "{}",
            String::from_utf8(bytes).map_err(|error| error.to_string())?
        );
    }
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
    wait_for_container_exit_with_timeout(runtime, id, None)
}

#[cfg(target_os = "linux")]
fn wait_for_container_exit_with_timeout(
    runtime: &ContainerRuntime,
    id: &str,
    timeout: Option<Duration>,
) -> Result<(), String> {
    let started = Instant::now();
    loop {
        let record = runtime.inspect(id).map_err(|err| err.to_string())?;
        match record.status.as_str() {
            "running" | "paused" => {
                if timeout.is_some_and(|limit| started.elapsed() >= limit) {
                    return Err(format!("wait: timed out waiting for container {id}"));
                }
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
    origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
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
                None => {
                    let plan = volume_store
                        .prepare_create(source, "local", BTreeMap::new())
                        .map_err(|err| err.to_string())?;
                    let permit = authorization
                        .authorize_volume_create_plan(origin, &plan)
                        .map_err(|err| err.to_string())?;
                    volume_store
                        .create_with_driver_authorized(plan, permit)
                        .map_err(|err| err.to_string())?
                }
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

fn ensure_image_present(
    store: &LocalImageStore,
    image: &str,
    origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    let canonical = canonicalize_reference(image).map_err(|err| err.to_string())?;
    let existing = resolve_reference(store, &canonical).map_err(|err| err.to_string())?;
    if existing.is_some() {
        return Ok(());
    }
    handle_pull_authorized(store, &canonical, false, origin, authorization)
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
#[allow(clippy::too_many_arguments)]
fn handle_build(
    store: &LocalImageStore,
    origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
    dockerfile: Option<&str>,
    ferrofile: Option<&str>,
    tag: Option<&str>,
    compression: &str,
    image_format: &str,
    embed_model: Option<&str>,
    platform: Option<&str>,
    cache_from: Option<&str>,
    cache_to: Option<&str>,
    build_context: &[String],
) -> Result<(), String> {
    validate_build_platform(platform)?;
    let runtime_dir = runtime_dir();
    let compression = parse_compression(compression)?;
    let named_contexts = parse_build_contexts(build_context)?;
    if let Some(source) = cache_from {
        ferro_core::dockerfile_build::import_build_cache(&runtime_dir, Path::new(source))
            .map_err(|error| format!("build: cache-from failed: {error}"))?;
    }

    let (result, source_desc) = if let Some(ferrofile_path) = ferrofile {
        if !named_contexts.is_empty() {
            return Err("build: --build-context is only supported with Dockerfiles".to_string());
        }
        let plan = ferro_core::ferrofile_build::prepare_ferrofile_build(
            Path::new(ferrofile_path),
            &runtime_dir,
            compression,
            store,
        )
        .map_err(|err| err.to_string())?;
        let permit = authorization
            .authorize_image_build_plan(origin, &plan)
            .map_err(|error| error.to_string())?;
        let r =
            ferro_core::dockerfile_build::execute_dockerfile_build_authorized(plan, store, permit)
                .map_err(|error| error.to_string())?;
        let desc = format!("ferrofile={}", ferrofile_path);
        (r, desc)
    } else {
        let dockerfile = dockerfile.unwrap_or("Dockerfile");
        let tag = tag.unwrap_or("local/build:latest");
        parse_image_reference(tag).map_err(|err| err.to_string())?;
        // Resolve relative dockerfile paths against current working directory
        let dockerfile_path = if Path::new(dockerfile).is_absolute() {
            PathBuf::from(dockerfile)
        } else {
            std::env::current_dir()
                .map_err(|err| format!("failed to get current directory: {err}"))?
                .join(dockerfile)
        };
        let plan = ferro_core::dockerfile_build::prepare_dockerfile_build_with_contexts(
            &dockerfile_path,
            Some(tag),
            &runtime_dir,
            compression,
            store,
            &named_contexts,
        )
        .map_err(|err| err.to_string())?;
        let permit = authorization
            .authorize_image_build_plan(origin, &plan)
            .map_err(|error| error.to_string())?;
        let r =
            ferro_core::dockerfile_build::execute_dockerfile_build_authorized(plan, store, permit)
                .map_err(|error| error.to_string())?;
        let desc = format!("dockerfile={}", dockerfile_path.display());
        (r, desc)
    };

    if image_format == "rvf" {
        let reference = result.reference.as_str();
        let (img_name, img_tag) = split_reference(reference);
        let output_name = reference.replace(':', "-").replace('/', "_");
        let output_path_str = format!("{}.rvf", output_name);
        let output_path = Path::new(&output_path_str);

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "0".to_string());

        let manifest = ferro_core::rvf_image::FerroImageManifest {
            name: img_name.to_string(),
            tag: img_tag.to_string(),
            entrypoint: vec![],
            cmd: vec![],
            env: vec![],
            arch: std::env::consts::ARCH.to_string(),
            os: "linux".to_string(),
            created_at,
            format_version: 1,
            layer_digest: result.layer_digest.clone(),
            layer_size: 0,
            overlay_model_type: None,
        };

        let params = ferro_core::rvf_image::RvfBuildParams {
            manifest,
            layer_digest: &result.layer_digest,
            runtime_dir: &runtime_dir,
            embed_model_path: embed_model.map(Path::new),
            output_path,
        };

        let rvf = ferro_core::rvf_image::build_rvf_image(&params).map_err(|e| e.to_string())?;

        if let Some(destination) = cache_to {
            ferro_core::dockerfile_build::export_build_cache(&runtime_dir, Path::new(destination))
                .map_err(|error| format!("build: cache-to failed: {error}"))?;
        }

        println!(
            "build: {} tag={} format=rvf output={} digest={} size={} segments={}",
            source_desc,
            reference,
            rvf.output_path.display(),
            rvf.file_digest,
            rvf.file_size,
            rvf.segment_count,
        );
        return Ok(());
    }

    if let Some(destination) = cache_to {
        ferro_core::dockerfile_build::export_build_cache(&runtime_dir, Path::new(destination))
            .map_err(|error| format!("build: cache-to failed: {error}"))?;
    }

    println!(
        "build: {} tag={} layer_digest={} config_digest={}",
        source_desc, result.reference, result.layer_digest, result.config_digest
    );
    Ok(())
}

fn validate_image_format(value: &str) -> Result<String, String> {
    match value {
        "oci" | "rvf" => Ok(value.to_string()),
        _ => Err("image-format must be one of: oci, rvf".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn validate_build_platform(platform: Option<&str>) -> Result<(), String> {
    let Some(platform) = platform else {
        return Ok(());
    };
    let (os, architecture) = platform
        .split_once('/')
        .ok_or_else(|| "build: platform must use OS/architecture form".to_string())?;
    if os != "linux" {
        return Err(format!(
            "build: platform {platform} is unsupported; only linux/{host_arch} is available",
            host_arch = host_build_arch()
        ));
    }
    let requested = match architecture {
        "amd64" | "x86_64" => "amd64",
        "arm64" | "aarch64" => "arm64",
        "riscv64" => "riscv64",
        other => {
            return Err(format!(
                "build: unsupported architecture {other}; cross-platform output is not enabled"
            ))
        }
    };
    if requested != host_build_arch() {
        return Err(format!(
            "build: platform {platform} is unsupported; only linux/{host_arch} is available",
            host_arch = host_build_arch()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_build_contexts(values: &[String]) -> Result<HashMap<String, PathBuf>, String> {
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    let mut contexts = HashMap::new();
    for value in values {
        let (name, path) = value
            .split_once('=')
            .ok_or_else(|| "build-context must use name=path".to_string())?;
        if name.is_empty() || path.is_empty() {
            return Err("build-context name and path must not be empty".to_string());
        }
        let path = Path::new(path);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        };
        if contexts.insert(name.to_string(), path).is_some() {
            return Err(format!("duplicate build context: {name}"));
        }
    }
    Ok(contexts)
}

#[cfg(target_os = "linux")]
fn host_build_arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "riscv64"
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        "unknown"
    }
}

/// Split a `name:tag` reference. Returns `(name, tag)`.
/// If no `:` is present, tag defaults to `"latest"`.
fn split_reference(reference: &str) -> (&str, &str) {
    match reference.rsplit_once(':') {
        Some((name, tag)) => (name, tag),
        None => (reference, "latest"),
    }
}

fn validate_network_backend(value: &str) -> Result<String, String> {
    NetworkBackend::from_str(value)
        .map(|_| value.to_string())
        .map_err(|err| err.to_string())
}

fn validate_network_mode(value: &str) -> Result<(), String> {
    match value {
        "bridge" | "host" | "none" | "wireguard" | "encrypted" => Ok(()),
        value if value.starts_with("managed:") => ferro_core::managed_overlay::ManagedOverlayRef::parse(value).map(|_| ()).map_err(|error| error.to_string()),
        _ => Err("network must be one of: bridge, host, none, wireguard, encrypted, managed:<overlay-id>".to_string()),
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

fn handle_rmi(
    store: &LocalImageStore,
    image: &str,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    parse_image_reference(image).map_err(|err| err.to_string())?;
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    handle_rmi_authorized(store, image, &origin, authorization)
}

fn handle_rmi_authorized(
    store: &LocalImageStore,
    image: &str,
    origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let canonical = canonicalize_reference(image).map_err(|err| err.to_string())?;
    let record = resolve_reference(store, &canonical)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("rmi: not found {canonical}"))?;
    let proof = authorization
        .authorize_image_binding(
            origin,
            AuthorizationAction::ImageDelete,
            &canonical,
            &record.digest,
            1,
        )
        .map_err(|error| error.to_string())?;
    execute_image_delete(store, &canonical, &record.digest, proof)
}

fn execute_image_delete(
    store: &LocalImageStore,
    canonical: &str,
    digest: &str,
    permit: SurfacePermit,
) -> Result<(), String> {
    let removed = store
        .remove_reference_authorized(canonical, digest, permit)
        .map_err(|err| err.to_string())?;
    if removed {
        println!("rmi: removed {canonical}");
    } else {
        println!("rmi: not found {canonical}");
    }
    Ok(())
}

fn handle_image_prune(
    store: &LocalImageStore,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    let records = store.list_references().map_err(|error| error.to_string())?;
    let permits = records
        .iter()
        .map(|record| {
            authorization.authorize_image_binding(
                &origin,
                AuthorizationAction::ImageDelete,
                &record.reference,
                &record.digest,
                1,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let removed = store
        .prune_references_authorized(permits)
        .map_err(|err| err.to_string())?;
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

fn handle_volume(
    runtime_dir: &Path,
    command: VolumeCommands,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    handle_volume_authorized(runtime_dir, command, &origin, authorization)
}

fn handle_volume_authorized(
    runtime_dir: &Path,
    command: VolumeCommands,
    origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let store = ferro_core::volume_store::LocalVolumeStore::open(runtime_dir.join("volumes"))
        .map_err(|err| err.to_string())?;
    match command {
        VolumeCommands::Create { name, driver, opts } => {
            let driver_opts = parse_driver_opts(&opts)?;
            let plan = store
                .prepare_create(&name, &driver, driver_opts)
                .map_err(|error| error.to_string())?;
            let proof = authorization
                .authorize_volume_create_plan(origin, &plan)
                .map_err(|error| error.to_string())?;
            let record = execute_volume_create(&store, plan, proof)?;
            println!("volume create: {} {}", record.name, record.path);
        }
        VolumeCommands::Backup { name, path } => {
            store.backup(&name, &path).map_err(|err| err.to_string())?;
            println!("volume backup: {name} -> {path}");
        }
        VolumeCommands::Restore { name, path } => {
            if store.get(&name).map_err(|err| err.to_string())?.is_none() {
                let plan = store
                    .prepare_create(&name, "local", BTreeMap::new())
                    .map_err(|error| error.to_string())?;
                let permit = authorization
                    .authorize_volume_create_plan(origin, &plan)
                    .map_err(|error| error.to_string())?;
                store
                    .create_with_driver_authorized(plan, permit)
                    .map_err(|err| err.to_string())?;
            }
            let permit = authorization
                .authorize_named(
                    origin,
                    AuthorizationAction::VolumeCreate,
                    ResourceKind::Volume,
                    &name,
                    1,
                )
                .map_err(|error| error.to_string())?;
            store
                .restore_authorized(&name, &path, permit)
                .map_err(|err| err.to_string())?;
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
            let proof = authorization
                .authorize_named(
                    origin,
                    AuthorizationAction::VolumeDelete,
                    ResourceKind::Volume,
                    &name,
                    1,
                )
                .map_err(|error| error.to_string())?;
            let removed = execute_volume_remove(&store, &name, proof)?;
            if removed {
                println!("volume rm: {name}");
            } else {
                println!("volume rm: not found {name}");
            }
        }
    }
    Ok(())
}

fn execute_volume_create(
    store: &LocalVolumeStore,
    plan: ferro_core::volume_store::VolumeCreatePlan,
    permit: SurfacePermit,
) -> Result<ferro_core::volume_store::VolumeRecord, String> {
    store
        .create_with_driver_authorized(plan, permit)
        .map_err(|error| error.to_string())
}

fn execute_volume_remove(
    store: &LocalVolumeStore,
    name: &str,
    permit: SurfacePermit,
) -> Result<bool, String> {
    store
        .remove_authorized(name, permit)
        .map_err(|error| error.to_string())
}

fn is_builtin_network_mode(value: &str) -> bool {
    matches!(value, "bridge" | "host" | "none" | "wireguard")
}

fn network_store_path(runtime_dir: &Path) -> PathBuf {
    crate::network_lifecycle::network_store_path(runtime_dir)
}

fn load_networks(runtime_dir: &Path) -> Result<Vec<NetworkRecord>, String> {
    crate::network_lifecycle::load_networks(runtime_dir)
}

fn save_networks(runtime_dir: &Path, records: &[NetworkRecord]) -> Result<(), String> {
    crate::network_lifecycle::save_networks(runtime_dir, records)
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

fn parse_ipv6_cidr(cidr: &str) -> Result<(std::net::Ipv6Addr, u8), String> {
    let (ip_part, prefix_part) = cidr
        .split_once('/')
        .ok_or_else(|| format!("network: invalid IPv6 CIDR {cidr}"))?;
    let ip = ip_part
        .parse::<std::net::Ipv6Addr>()
        .map_err(|_| format!("network: invalid IPv6 CIDR {cidr}"))?;
    let prefix = prefix_part
        .parse::<u8>()
        .map_err(|_| format!("network: invalid IPv6 prefix {prefix_part}"))?;
    if prefix > 128 {
        return Err(format!("network: invalid IPv6 CIDR {cidr}"));
    }
    Ok((ip, prefix))
}

fn ipv6_network_addr(addr: std::net::Ipv6Addr, prefix: u8) -> std::net::Ipv6Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    std::net::Ipv6Addr::from(u128::from(addr) & mask)
}

fn ipv6_in_subnet(addr: std::net::Ipv6Addr, subnet: std::net::Ipv6Addr, prefix: u8) -> bool {
    ipv6_network_addr(addr, prefix) == ipv6_network_addr(subnet, prefix)
}

fn default_ipv6_gateway(subnet: std::net::Ipv6Addr, prefix: u8) -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::from(u128::from(ipv6_network_addr(subnet, prefix)).saturating_add(1))
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
    canonical_bridge_name(name)
}

#[cfg(test)]
fn reset_network_kernel_effect_count() {
    crate::network_lifecycle::reset_network_kernel_effect_count();
}

#[cfg(test)]
fn network_kernel_effect_count() -> u32 {
    crate::network_lifecycle::network_kernel_effect_count()
}

fn create_network_record(
    name: &str,
    subnet: Option<&str>,
    gateway: Option<&str>,
    ipv6_subnet: Option<&str>,
    ipv6_gateway: Option<&str>,
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
    let ipv6_cidr = match ipv6_subnet {
        Some(value) => {
            let (addr, prefix) = parse_ipv6_cidr(value)?;
            let gateway = match ipv6_gateway {
                Some(gateway) => gateway
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(|_| format!("network: invalid IPv6 gateway {gateway}"))?,
                None => default_ipv6_gateway(addr, prefix),
            };
            if !ipv6_in_subnet(gateway, addr, prefix) {
                return Err(format!(
                    "network: IPv6 gateway {gateway} is outside subnet {addr}/{prefix}"
                ));
            }
            Some(format!("{gateway}/{prefix}"))
        }
        None if ipv6_gateway.is_some() => {
            return Err("network: --ipv6-gateway requires --ipv6-subnet".into())
        }
        None => None,
    };
    Ok(NetworkRecord {
        name: name.to_string(),
        driver: "bridge".to_string(),
        subnet: format!("{network_ip}/{prefix}"),
        gateway: gateway_ip.to_string(),
        bridge_name: bridge_name_for_network(name),
        bridge_cidr: format!("{gateway_ip}/{prefix}"),
        ipv6_cidr,
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        generation: 1,
    })
}

struct RunNetworkBinding {
    mode: String,
    association: Option<String>,
    bridge_cidr: Option<String>,
    bridge_name: Option<String>,
}

fn bind_run_network(
    runtime_dir: &Path,
    network: &str,
    bridge_cidr: Option<&str>,
    bridge_name: Option<&str>,
) -> Result<RunNetworkBinding, String> {
    let mut mode = network.to_string();
    if mode == "encrypted" {
        mode = "wireguard".to_string();
    }
    let mut resolved_bridge_cidr = bridge_cidr.map(|value| value.to_string());
    let mut resolved_bridge_name = bridge_name.map(|value| value.to_string());
    let association = if let Some(managed) = mode.strip_prefix("managed:") {
        ferro_core::managed_overlay::ManagedOverlayRef::parse(&mode)
            .map_err(|error| format!("run: invalid managed overlay: {error}"))?;
        Some(managed.to_string())
    } else if is_builtin_network_mode(&mode) {
        validate_network_mode(&mode)?;
        Some(mode.clone())
    } else {
        let named = resolve_named_network(runtime_dir, network)?;
        mode = "bridge".to_string();
        if resolved_bridge_cidr.is_none() {
            resolved_bridge_cidr = Some(named.bridge_cidr.clone());
        }
        if resolved_bridge_name.is_none() {
            resolved_bridge_name = Some(named.bridge_name.clone());
        }
        Some(named.name)
    };
    Ok(RunNetworkBinding {
        mode,
        association,
        bridge_cidr: resolved_bridge_cidr,
        bridge_name: resolved_bridge_name,
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
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    handle_network_authorized(runtime_dir, runtime, command, &origin, authorization)
}

#[cfg(target_os = "linux")]
fn handle_network_authorized(
    runtime_dir: &Path,
    runtime: &ContainerRuntime,
    command: NetworkCommands,
    origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let recovery = crate::network_lifecycle::recover_network_lifecycles(
        runtime_dir,
        cli_network_kernel().as_ref(),
    )
    .map_err(|error| format!("network recovery failed: {error}"))?;
    if let Some(entry) = recovery.entries.iter().find(|entry| {
        matches!(
            entry.verdict,
            crate::network_lifecycle::NetworkRecoveryVerdict::Quarantined
        )
    }) {
        return Err(format!(
            "network recovery quarantined {}: {}",
            entry.network,
            entry.detail.as_deref().unwrap_or("no detail")
        ));
    }

    match command {
        NetworkCommands::Create {
            name,
            subnet,
            gateway,
            ipv6_subnet,
            ipv6_gateway,
        } => {
            if is_builtin_network_mode(&name) {
                return Err(format!("network: reserved name {name}"));
            }
            let records = load_networks(runtime_dir)?;
            if records.iter().any(|record| record.name == name) {
                return Err(format!("network: already exists {name}"));
            }
            let record = create_network_record(
                &name,
                subnet.as_deref(),
                gateway.as_deref(),
                ipv6_subnet.as_deref(),
                ipv6_gateway.as_deref(),
            )?;
            if records.iter().any(|existing| {
                existing.bridge_name == record.bridge_name && existing.name != record.name
            }) {
                return Err(format!(
                    "network: bridge name collision {}",
                    record.bridge_name
                ));
            }
            let proof = authorization
                .authorize_named(
                    origin,
                    AuthorizationAction::NetworkCreate,
                    ResourceKind::Network,
                    &name,
                    record.generation,
                )
                .map_err(|error| error.to_string())?;
            execute_network_create(runtime_dir, &record, proof)?;
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
            let associations = runtime.list().map_err(|err| err.to_string())?;
            let records = load_networks(runtime_dir)?;
            let stored = records
                .iter()
                .find(|record| record.name == name)
                .ok_or_else(|| format!("network: not found {name}"))?
                .clone();
            let proof = authorization
                .authorize_named(
                    origin,
                    AuthorizationAction::NetworkDelete,
                    ResourceKind::Network,
                    &name,
                    stored.generation,
                )
                .map_err(|error| error.to_string())?;
            execute_network_remove(runtime_dir, &stored, &associations, proof)?;
            println!("network rm: {name}");
        }
    }
    Ok(())
}

fn cli_network_kernel() -> Box<dyn crate::network_lifecycle::NetworkKernel> {
    // Explicit opt-in for the file-backed emulator (Docker/CLI harnesses).
    // Default production path remains SystemBridgeKernel.
    if let Some(kernel) = crate::network_lifecycle::FileBackedNetworkKernel::from_env() {
        return Box::new(kernel);
    }
    #[cfg(test)]
    {
        Box::new(CliKernelProxy)
    }
    #[cfg(not(test))]
    {
        Box::new(crate::network_lifecycle::SystemBridgeKernel)
    }
}

#[cfg(test)]
struct CliKernelProxy;

#[cfg(test)]
impl crate::network_lifecycle::NetworkKernel for CliKernelProxy {
    fn create_bridge(
        &self,
        config: &ferro_net::BridgeConfig,
    ) -> Result<(), crate::network_lifecycle::NetworkKernelError> {
        crate::network_lifecycle::CliTestKernel::with_current(|kernel| kernel.create_bridge(config))
    }

    fn destroy_bridge(
        &self,
        identity: &crate::network_lifecycle::BridgeIdentity,
    ) -> Result<(), crate::network_lifecycle::NetworkKernelError> {
        crate::network_lifecycle::CliTestKernel::with_current(|kernel| {
            kernel.destroy_bridge(identity)
        })
    }

    fn observe_bridge(
        &self,
        name: &str,
    ) -> Result<
        Option<crate::network_lifecycle::BridgeIdentity>,
        crate::network_lifecycle::NetworkKernelError,
    > {
        crate::network_lifecycle::CliTestKernel::with_current(|kernel| kernel.observe_bridge(name))
    }
}

fn execute_network_create(
    runtime_dir: &Path,
    record: &NetworkRecord,
    permit: SurfacePermit,
) -> Result<(), String> {
    let create =
        NetworkCreateRecord::from_record(record.clone()).map_err(|error| error.to_string())?;
    crate::network_lifecycle::create_authorized(
        runtime_dir,
        &create,
        permit,
        cli_network_kernel().as_ref(),
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}

fn execute_network_remove(
    runtime_dir: &Path,
    record: &NetworkRecord,
    associations: &[ferro_core::container_store::ContainerRecord],
    permit: SurfacePermit,
) -> Result<(), String> {
    // Exact BridgeIdentity deletion authority requires the last StoreCommitted
    // observed identity. Synthesizing from the store record (ifindex: None)
    // would allow an inexact or absent-bridge path to unpublish without that
    // authority; fail closed before delete, unpublish, or any kernel effect.
    let expected = match last_committed_bridge_identity(runtime_dir, &record.name)
        .map_err(|error| error.to_string())?
    {
        Some(identity) => identity,
        None => {
            permit.finish(false).map_err(|error| error.to_string())?;
            return Err(format!(
                "network: missing committed bridge identity for {}",
                record.name
            ));
        }
    };
    crate::network_lifecycle::delete_authorized(
        runtime_dir,
        &record.name,
        &expected,
        associations,
        record.generation,
        permit,
        cli_network_kernel().as_ref(),
    )
    .map_err(|error| error.to_string())
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

fn handle_pull(
    store: &LocalImageStore,
    image: &str,
    lazy: bool,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    handle_pull_authorized(store, image, lazy, &origin, authorization)
}

fn handle_pull_authorized(
    store: &LocalImageStore,
    image: &str,
    lazy: bool,
    origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let binding =
        ferro_core::image_fetch::inspect_image_binding(image).map_err(|error| error.to_string())?;
    let proof = authorization
        .authorize_image_fetch_plan(origin, &binding, 1)
        .map_err(|error| error.to_string())?;
    execute_image_pull(store, lazy, binding, proof)
}

fn execute_image_pull(
    store: &LocalImageStore,
    lazy: bool,
    plan: ferro_core::image_fetch::ImageFetchPlan,
    permit: SurfacePermit,
) -> Result<(), String> {
    if lazy {
        let runtime_dir = runtime_dir();
        let canonical = ferro_core::image_fetch::pull_manifest_only_with_store_authorized(
            &runtime_dir,
            &plan,
            store,
            permit,
        )
        .map_err(|err| err.to_string())?;
        println!("pull: manifest-only image={canonical}");
        return Ok(());
    }
    let runtime_dir = runtime_dir();
    ferro_core::image_fetch::pull_image_with_store_authorized(&runtime_dir, &plan, store, permit)
        .map_err(|error| error.to_string())?;
    println!("pull: image={}", plan.canonical_reference());
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
fn handle_scan(
    store: &LocalImageStore,
    image: &str,
    scanner: &str,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    ensure_image_present(store, image, &origin, authorization)?;
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
enum ComposePrerequisite {
    ImageBuild(ferro_core::dockerfile_build::ImageBuildPlan),
    ImagePull(ferro_core::image_fetch::ImageFetchPlan),
    VolumeCreate(ferro_core::volume_store::VolumeCreatePlan),
}

#[cfg(target_os = "linux")]
impl ComposePrerequisite {
    fn mutation(&self) -> ServiceMutation {
        match self {
            Self::ImageBuild(plan) => ServiceMutation::new(
                plan.canonical_tag(),
                FanoutAction::ImageBuild,
                plan.plan_digest(),
            ),
            Self::ImagePull(plan) => ServiceMutation::new(
                plan.canonical_reference(),
                FanoutAction::ImagePull,
                plan.plan_digest(),
            ),
            Self::VolumeCreate(plan) => {
                ServiceMutation::new(plan.name(), FanoutAction::VolumeCreate, plan.plan_digest())
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct PreparedComposeService {
    name: String,
    instance: String,
    image: String,
    prerequisites: Vec<ComposePrerequisite>,
}

#[cfg(target_os = "linux")]
fn prepare_compose_service(
    store: &LocalImageStore,
    volume_store: &LocalVolumeStore,
    project_dir: &Path,
    name: String,
    instance: String,
    service: &ComposeService,
) -> Result<PreparedComposeService, String> {
    let image = service
        .image
        .clone()
        .unwrap_or_else(|| format!("local/compose-{name}:latest"));
    let mut prerequisites = Vec::new();
    if let Some(build) = service.build.as_ref() {
        let context = build.context.as_deref().unwrap_or(".");
        let dockerfile = build.dockerfile.as_deref().unwrap_or("Dockerfile");
        let plan = ferro_core::dockerfile_build::prepare_dockerfile_build(
            &project_dir.join(context).join(dockerfile),
            Some(&image),
            &runtime_dir(),
            CompressionFormat::Gzip,
            store,
        )
        .map_err(|error| error.to_string())?;
        prerequisites.push(ComposePrerequisite::ImageBuild(plan));
    } else if resolve_reference(store, &image)
        .map_err(|error| error.to_string())?
        .is_none()
    {
        prerequisites.push(ComposePrerequisite::ImagePull(
            ferro_core::image_fetch::inspect_image_binding(&image)
                .map_err(|error| error.to_string())?,
        ));
    }
    let mut planned_volumes = HashSet::new();
    if let Some(volumes) = service.volumes.as_ref() {
        for entry in volumes {
            let source = entry.split(':').next().unwrap_or("");
            if source.is_empty() || source.starts_with('.') || source.contains('/') {
                continue;
            }
            if planned_volumes.insert(source.to_string())
                && volume_store
                    .get(source)
                    .map_err(|error| error.to_string())?
                    .is_none()
            {
                prerequisites.push(ComposePrerequisite::VolumeCreate(
                    volume_store
                        .prepare_create(source, "local", BTreeMap::new())
                        .map_err(|error| error.to_string())?,
                ));
            }
        }
    }
    Ok(PreparedComposeService {
        name,
        instance,
        image,
        prerequisites,
    })
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
    let replay_store = FanoutReplayStore::open(runtime_dir()).map_err(|error| error.to_string())?;
    let project_dir = path.parent().unwrap_or_else(|| Path::new("."));
    match command {
        ComposeCommands::Up { profile } => {
            let order = compose_up(&project).map_err(|err| err.to_string())?;
            let enabled = build_compose_enabled_set(&project, &profile)?;
            let selected_services: Vec<_> = order
                .into_iter()
                .filter(|name| enabled.contains(name))
                .collect();
            let selected: Vec<(String, String)> = selected_services
                .into_iter()
                .flat_map(|name| {
                    let replicas = project
                        .compose
                        .services
                        .get(&name)
                        .and_then(|service| service.deploy.as_ref())
                        .and_then(|deploy| deploy.replicas)
                        .unwrap_or(1);
                    (1..=replicas)
                        .map(|index| {
                            let instance = if replicas == 1 {
                                name.clone()
                            } else {
                                format!("{name}-{index}")
                            };
                            (name.clone(), instance)
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            let parent_origin = ferro_core::authorization::RequestOrigin::cli_current()
                .map_err(|error| format!("compose identity resolution failed: {error}"))?;
            let mut parent_hasher = Sha256::new();
            parent_hasher.update(b"ferrocrate/compose-parent/v1");
            parent_hasher.update(std::process::id().to_be_bytes());
            parent_hasher.update(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_be_bytes(),
            );
            let parent_hash: [u8; 32] = parent_hasher.finalize().into();
            let mut parent_id = [0; 16];
            parent_id.copy_from_slice(&parent_hash[..16]);
            let (policy_generation, policy_digest) = runtime.policy_binding();
            let deadline = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .saturating_add(300_000)
                .min(u64::MAX as u128) as u64;
            let prepared: Vec<_> = selected
                .into_iter()
                .map(|(name, instance)| {
                    let service = project
                        .compose
                        .services
                        .get(&name)
                        .ok_or_else(|| format!("compose: missing service {name}"))?;
                    prepare_compose_service(
                        store,
                        volume_store,
                        project_dir,
                        name,
                        instance,
                        service,
                    )
                })
                .collect::<Result<_, _>>()?;
            let surface_authorization = runtime
                .surface_authorization()
                .map_err(|error| error.to_string())?;
            let mut failures = Vec::new();
            for prepared in prepared {
                let service = project
                    .compose
                    .services
                    .get(&prepared.name)
                    .ok_or_else(|| format!("compose: missing service {}", prepared.name))?;
                let mut mutations = prepared
                    .prerequisites
                    .iter()
                    .map(ComposePrerequisite::mutation)
                    .collect::<Vec<_>>();
                let initial_run_digest = if mutations.is_empty() {
                    compose_service_execution_digest(
                        runtime,
                        store,
                        volume_store,
                        project_dir,
                        &prepared.name,
                        service,
                        &prepared.instance,
                        &prepared.image,
                    )?
                    .1
                } else {
                    [0; 32]
                };
                mutations.push(ServiceMutation::new(
                    &prepared.instance,
                    FanoutAction::ContainerRun,
                    initial_run_digest,
                ));
                let root_plan = FanoutPlan::derive(
                    parent_id,
                    policy_generation,
                    policy_digest,
                    deadline,
                    0,
                    mutations,
                )
                .map_err(|error| error.to_string())?;
                let mut current_plan = root_plan.clone();
                let mut predecessor = None;
                let mut predecessor_outcome = [0; 32];
                let mut prerequisite_failed = false;
                for (ordinal, prerequisite) in prepared.prerequisites.into_iter().enumerate() {
                    let mutation = prerequisite.mutation();
                    let child = if let Some(previous) = predecessor.as_ref() {
                        current_plan = current_plan
                            .derive_dependent(previous, predecessor_outcome, mutation)
                            .map_err(|error| error.to_string())?;
                        current_plan.children()[0].clone()
                    } else {
                        root_plan.children()[ordinal].clone()
                    };
                    if let Err(error) = current_plan
                        .verify_child(&child, current_unix_ms())
                        .and_then(|_| replay_store.claim(&child))
                    {
                        failures.push(format!(
                            "{} prerequisite denied/skipped: {error}",
                            prepared.instance
                        ));
                        prerequisite_failed = true;
                        break;
                    }
                    if let Err(error) = execute_compose_prerequisite(
                        prerequisite,
                        &child,
                        &parent_origin,
                        &surface_authorization,
                        store,
                        volume_store,
                    ) {
                        failures.push(format!(
                            "{} prerequisite failed: {error}",
                            prepared.instance
                        ));
                        prerequisite_failed = true;
                        break;
                    }
                    predecessor_outcome = compose_predecessor_outcome_digest(&child);
                    predecessor = Some(child);
                }
                if prerequisite_failed {
                    continue;
                }
                if let Some(depends_on) = service.depends_on.as_ref() {
                    wait_for_compose_dependencies(runtime, depends_on)
                        .map_err(|error| format!("compose partial result: {error}"))?;
                }
                let run_digest = compose_service_execution_digest(
                    runtime,
                    store,
                    volume_store,
                    project_dir,
                    &prepared.name,
                    service,
                    &prepared.instance,
                    &prepared.image,
                )?
                .1;
                let run_child = if let Some(previous) = predecessor.as_ref() {
                    current_plan = current_plan
                        .derive_dependent(
                            previous,
                            predecessor_outcome,
                            ServiceMutation::new(
                                &prepared.instance,
                                FanoutAction::ContainerRun,
                                run_digest,
                            ),
                        )
                        .map_err(|error| error.to_string())?;
                    current_plan.children()[0].clone()
                } else {
                    root_plan.children()[0].clone()
                };
                if let Err(error) = current_plan
                    .verify_child(&run_child, current_unix_ms())
                    .and_then(|_| replay_store.claim(&run_child))
                {
                    failures.push(format!("{} run denied/skipped: {error}", prepared.instance));
                    continue;
                }
                let child_runtime = runtime.request_scoped(
                    ferro_core::authorization::RequestOrigin::compose_child(
                        &parent_origin,
                        *run_child.child_id(),
                        *run_child.parent_request_id(),
                        *run_child.idempotency_key(),
                        ferro_core::authorization::Action::ContainerRun,
                        &prepared.instance,
                        *run_child.request_digest(),
                        run_child.deadline_unix_ms(),
                        run_child.policy_generation(),
                        *run_child.policy_digest(),
                        run_child.attempt(),
                        run_child.ordinal(),
                        *run_child.plan_digest(),
                    ),
                );
                if let Err(error) = run_compose_service(
                    &child_runtime,
                    store,
                    volume_store,
                    project_dir,
                    &prepared.name,
                    service,
                    Some(&prepared.instance),
                    Some(&prepared.image),
                ) {
                    failures.push(format!("{} run failed: {error}", prepared.instance));
                }
            }
            if !failures.is_empty() {
                return Err(format!("compose partial result: {}", failures.join("; ")));
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
            let selected: Vec<_> = order
                .into_iter()
                .flat_map(|name| {
                    containers
                        .iter()
                        .filter(move |rec| {
                            rec.name
                                .as_deref()
                                .map(|val| val == name || val.starts_with(&format!("{name}-")))
                                .unwrap_or(false)
                        })
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect();
            let parent_origin = ferro_core::authorization::RequestOrigin::cli_current()
                .map_err(|error| format!("compose identity resolution failed: {error}"))?;
            let mut parent_hasher = Sha256::new();
            parent_hasher.update(b"ferrocrate/compose-down-parent/v1");
            parent_hasher.update(
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_be_bytes(),
            );
            let parent_hash: [u8; 32] = parent_hasher.finalize().into();
            let mut parent_id = [0; 16];
            parent_id.copy_from_slice(&parent_hash[..16]);
            let (generation, policy_digest) = runtime.policy_binding();
            let deadline = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .saturating_add(300_000)
                .min(u64::MAX as u128) as u64;
            let mutations = selected.iter().flat_map(|record| {
                [FanoutAction::ContainerStop, FanoutAction::ContainerDelete]
                    .into_iter()
                    .map(move |action| {
                        let runtime_action = match action {
                            FanoutAction::ContainerStop => {
                                ferro_core::authorization::Action::ContainerStop
                            }
                            FanoutAction::ContainerDelete => {
                                ferro_core::authorization::Action::ContainerDelete
                            }
                            FanoutAction::ContainerRun
                            | FanoutAction::ImagePull
                            | FanoutAction::VolumeCreate
                            | FanoutAction::ImageBuild => unreachable!(),
                        };
                        ServiceMutation::new(
                            record.name.clone().unwrap_or_else(|| record.id.clone()),
                            action,
                            if action == FanoutAction::ContainerDelete {
                                Sha256::digest(
                                    [
                                        b"ferrocrate/compose-down-delete-intent/v1".as_slice(),
                                        record.id.as_bytes(),
                                    ]
                                    .concat(),
                                )
                                .into()
                            } else {
                                ferro_core::authorization::compose_down_executor_digest(
                                    record,
                                    runtime_action,
                                )
                            },
                        )
                    })
            });
            let fanout =
                FanoutPlan::derive(parent_id, generation, policy_digest, deadline, 0, mutations)
                    .map_err(|error| error.to_string())?;
            let mut failures = Vec::new();
            for (index, record) in selected.iter().enumerate() {
                let stop_child = &fanout.children()[index * 2];
                if let Err(error) = fanout
                    .verify_child(stop_child, current_unix_ms())
                    .and_then(|_| replay_store.claim(stop_child))
                {
                    failures.push(format!("{}: stop denied/skipped: {error}", record.id));
                    continue;
                }
                let action = ferro_core::authorization::Action::ContainerStop;
                let resource = record.name.clone().unwrap_or_else(|| record.id.clone());
                let scoped = runtime.request_scoped(
                    ferro_core::authorization::RequestOrigin::compose_child(
                        &parent_origin,
                        *stop_child.child_id(),
                        parent_id,
                        *stop_child.idempotency_key(),
                        action,
                        resource.clone(),
                        *stop_child.request_digest(),
                        stop_child.deadline_unix_ms(),
                        stop_child.policy_generation(),
                        *stop_child.policy_digest(),
                        stop_child.attempt(),
                        stop_child.ordinal(),
                        *stop_child.plan_digest(),
                    ),
                );
                if let Err(error) = scoped.stop(&record.id, std::time::Duration::from_secs(5)) {
                    failures.push(format!(
                        "{}: stop failed; delete skipped: {error}",
                        record.id
                    ));
                    continue;
                }
                let stopped = runtime
                    .inspect(&record.id)
                    .map_err(|error| error.to_string())?;
                let delete_digest = ferro_core::authorization::compose_down_executor_digest(
                    &stopped,
                    ferro_core::authorization::Action::ContainerDelete,
                );
                let predecessor_digest: [u8; 32] = Sha256::digest(
                    [
                        b"ferrocrate/compose-predecessor-outcome/v1".as_slice(),
                        stop_child.child_id(),
                        stopped.status.as_bytes(),
                        &stopped.mutation_generation.to_be_bytes(),
                        fanout.plan_digest(),
                    ]
                    .concat(),
                )
                .into();
                let delete_plan = fanout
                    .derive_dependent(
                        stop_child,
                        predecessor_digest,
                        ServiceMutation::new(
                            resource.clone(),
                            FanoutAction::ContainerDelete,
                            delete_digest,
                        ),
                    )
                    .map_err(|error| error.to_string())?;
                let delete_child = &delete_plan.children()[0];
                let delete_parent = *delete_child.parent_request_id();
                if let Err(error) = delete_plan
                    .verify_child(delete_child, current_unix_ms())
                    .and_then(|_| replay_store.claim(delete_child))
                {
                    failures.push(format!("{}: delete denied/skipped: {error}", record.id));
                    continue;
                }
                let delete_runtime = runtime.request_scoped(
                    ferro_core::authorization::RequestOrigin::compose_child(
                        &parent_origin,
                        *delete_child.child_id(),
                        delete_parent,
                        *delete_child.idempotency_key(),
                        ferro_core::authorization::Action::ContainerDelete,
                        resource,
                        *delete_child.request_digest(),
                        delete_child.deadline_unix_ms(),
                        delete_child.policy_generation(),
                        *delete_child.policy_digest(),
                        delete_child.attempt(),
                        delete_child.ordinal(),
                        *delete_child.plan_digest(),
                    ),
                );
                if let Err(error) = delete_runtime.remove(&record.id) {
                    failures.push(format!("{}: delete failed: {error}", record.id));
                }
            }
            if !failures.is_empty() {
                return Err(format!(
                    "compose down partial result: {}",
                    failures.join("; ")
                ));
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

#[cfg(target_os = "linux")]
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
fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(target_os = "linux")]
fn execute_compose_prerequisite(
    prerequisite: ComposePrerequisite,
    child: &ferro_compose::FanoutChild,
    parent_origin: &RequestOrigin,
    authorization: &SurfaceAuthorization,
    store: &LocalImageStore,
    volume_store: &LocalVolumeStore,
) -> Result<(), String> {
    let (action, resource) = match &prerequisite {
        ComposePrerequisite::ImageBuild(plan) => {
            (AuthorizationAction::ImageBuild, plan.canonical_tag())
        }
        ComposePrerequisite::ImagePull(plan) => {
            (AuthorizationAction::ImagePull, plan.canonical_reference())
        }
        ComposePrerequisite::VolumeCreate(plan) => (AuthorizationAction::VolumeCreate, plan.name()),
    };
    let origin = RequestOrigin::compose_child(
        parent_origin,
        *child.child_id(),
        *child.parent_request_id(),
        *child.idempotency_key(),
        action,
        resource,
        *child.request_digest(),
        child.deadline_unix_ms(),
        child.policy_generation(),
        *child.policy_digest(),
        child.attempt(),
        child.ordinal(),
        *child.plan_digest(),
    );
    match prerequisite {
        ComposePrerequisite::ImageBuild(plan) => {
            let permit = authorization
                .authorize_image_build_plan(&origin, &plan)
                .map_err(|error| error.to_string())?;
            ferro_core::dockerfile_build::execute_dockerfile_build_authorized(plan, store, permit)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        ComposePrerequisite::ImagePull(plan) => {
            let permit = authorization
                .authorize_image_fetch_plan(&origin, &plan, 1)
                .map_err(|error| error.to_string())?;
            ferro_core::image_fetch::pull_image_with_store_authorized(
                &runtime_dir(),
                &plan,
                store,
                permit,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        }
        ComposePrerequisite::VolumeCreate(plan) => {
            let permit = authorization
                .authorize_volume_create_plan(&origin, &plan)
                .map_err(|error| error.to_string())?;
            volume_store
                .create_with_driver_authorized(plan, permit)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
    }
}

#[cfg(target_os = "linux")]
fn compose_predecessor_outcome_digest(child: &ferro_compose::FanoutChild) -> [u8; 32] {
    Sha256::digest(
        [
            b"ferrocrate/compose-predecessor-success/v1".as_slice(),
            child.child_id(),
            child.plan_digest(),
            child.request_digest(),
            &child.ordinal().to_be_bytes(),
        ]
        .concat(),
    )
    .into()
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_compose_service(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    volume_store: &LocalVolumeStore,
    project_dir: &Path,
    name: &str,
    service: &ComposeService,
    instance_override: Option<&str>,
    prepared_image: Option<&str>,
) -> Result<(), String> {
    let image = if let Some(image) = prepared_image {
        image.to_owned()
    } else {
        return Err(format!(
            "compose: service {name} image prerequisite was not prepared"
        ));
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
    let replicas = if instance_override.is_some() {
        1
    } else {
        service
            .deploy
            .as_ref()
            .and_then(|deploy| deploy.replicas)
            .unwrap_or(1)
    };

    for idx in 1..=replicas {
        let instance_name = if let Some(instance) = instance_override {
            instance.to_owned()
        } else if replicas == 1 {
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
            None,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn compose_service_execution_digest(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    volume_store: &LocalVolumeStore,
    project_dir: &Path,
    name: &str,
    service: &ComposeService,
    instance: &str,
    image: &str,
) -> Result<(String, [u8; 32]), String> {
    let cmd = compose_service_command(service);
    let env_entries = compose_service_env(project_dir, service)?;
    let env = parse_env_entries(&env_entries)?;
    let label_entries = compose_service_labels(service);
    let labels = parse_key_values("label", &label_entries)?;
    let publish = compose_service_ports(service);
    let ports = parse_publish(&publish)?;
    let mount_entries = compose_service_mounts(volume_store, service)?;
    let mounts = parse_bind_mounts(&mount_entries)?;
    let restart = parse_restart_policy(service.restart.as_deref().unwrap_or("no"))?;
    let network = match service.network_mode.as_deref() {
        None | Some("bridge") => "bridge",
        Some("host") => "host",
        Some("none") => "none",
        Some(other) => {
            return Err(format!(
                "compose: unsupported network_mode {other} for service {name}"
            ))
        }
    };
    let effective_cmd = if let Some(entrypoint) = service.entrypoint.as_deref() {
        let mut value = parse_entrypoint(entrypoint)?;
        value.extend_from_slice(&cmd);
        value
    } else {
        cmd
    };
    let digest = runtime
        .normalized_run_execution_digest(
            store,
            image,
            &effective_cmd,
            &env,
            &labels,
            &HashMap::new(),
            None,
            &restart,
            &[],
            None,
            &mounts,
            &[],
            false,
            false,
            None,
            None,
            Some(instance),
            &ports,
            network,
            NetworkBackend::Ebpf,
        )
        .map_err(|error| error.to_string())?;
    Ok((image.to_string(), digest))
}

#[cfg(target_os = "linux")]
fn compose_service_command(service: &ComposeService) -> Vec<String> {
    match service.command.as_ref() {
        Some(ComposeCommandSpec::List(list)) => list.clone(),
        Some(ComposeCommandSpec::String(cmd)) => {
            vec!["sh".to_string(), "-c".to_string(), cmd.clone()]
        }
        None => Vec::new(),
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn compose_service_labels(service: &ComposeService) -> Vec<String> {
    match service.labels.as_ref() {
        Some(map) => map
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect(),
        None => Vec::new(),
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
            let record = volume_store
                .get(source)
                .map_err(|err| err.to_string())?
                .ok_or_else(|| format!("compose: volume prerequisite was not created: {source}"))?;
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
struct DockerHostConfig {
    #[serde(rename = "Binds")]
    binds: Option<Vec<String>>,
    #[serde(rename = "PortBindings")]
    port_bindings: Option<HashMap<String, Vec<DockerPortBinding>>>,
    #[serde(rename = "NetworkMode")]
    network_mode: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
struct DockerPortBinding {
    #[serde(rename = "HostPort")]
    host_port: Option<String>,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Deserialize)]
struct DockerNetworkCreateSpec {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: Option<String>,
    #[serde(rename = "IPAM")]
    ipam: Option<DockerIpamSpec>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Deserialize)]
struct DockerIpamSpec {
    #[serde(rename = "Config", default)]
    config: Vec<DockerIpamConfig>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Deserialize)]
struct DockerIpamConfig {
    #[serde(rename = "Subnet")]
    subnet: Option<String>,
    #[serde(rename = "Gateway")]
    gateway: Option<String>,
}

#[cfg(target_os = "linux")]
struct DockerCompatState {
    next_id: AtomicU64,
    pending: Mutex<HashMap<String, DockerCreateSpec>>,
    events: Mutex<DockerEventStore>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DockerEvent {
    id: u64,
    time: u64,
    #[serde(default)]
    time_nano: u64,
    event_type: String,
    action: String,
    scope: String,
    resource: Option<String>,
    status: u16,
}

#[cfg(target_os = "linux")]
struct DockerEventStore {
    path: PathBuf,
    next_id: u64,
}

#[cfg(target_os = "linux")]
impl DockerCompatState {
    fn new(runtime_dir: &Path) -> Result<Self, String> {
        Ok(Self {
            next_id: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
            events: Mutex::new(DockerEventStore::open(runtime_dir.join("events.jsonl"))?),
        })
    }
}

#[cfg(target_os = "linux")]
impl DockerEventStore {
    fn open(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let mut next_id = 0;
        if let Ok(contents) = std::fs::read_to_string(&path) {
            for line in contents.lines().filter(|line| !line.trim().is_empty()) {
                if let Ok(event) = serde_json::from_str::<DockerEvent>(line) {
                    next_id = next_id.max(event.id.saturating_add(1));
                }
            }
        }
        Ok(Self { path, next_id })
    }

    fn append(&mut self, method: &str, path: &str, status: u16) -> Result<(), String> {
        let Some((event_type, action)) = docker_event_kind(method, path) else {
            return Ok(());
        };
        let resource = docker_event_resource(path);
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let event = DockerEvent {
            id: self.next_id,
            time: timestamp.as_secs(),
            time_nano: timestamp.as_nanos().min(u64::MAX as u128) as u64,
            event_type: event_type.to_string(),
            action,
            scope: "local".to_string(),
            resource,
            status,
        };
        self.next_id = self.next_id.saturating_add(1);
        let bytes = serde_json::to_vec(&event).map_err(|error| error.to_string())?;
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        file.sync_data().map_err(|error| error.to_string())?;
        Ok(())
    }

    fn query(&self, query: &HashMap<String, String>) -> Result<Vec<DockerEvent>, String> {
        // Event filters use the same Docker JSON contract as the container
        // listing endpoint. Validate them before evaluating any predicates so
        // malformed input cannot silently degrade into an unfiltered stream.
        parse_docker_filters(query)?;
        let contents = std::fs::read_to_string(&self.path).unwrap_or_default();
        let since = query
            .get("since")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("event query parameter `since` is not a u64: {value}"))
            })
            .transpose()?;
        let until = query
            .get("until")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| format!("event query parameter `until` is not a u64: {value}"))
            })
            .transpose()?;
        let event = query.get("event").or_else(|| query.get("action"));
        let kind = query.get("type");
        let scope = query.get("scope");
        let resource = query.get("container").or_else(|| query.get("image"));
        let filters = query
            .get("filters")
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
        let filter_values = |name: &str| -> Option<Vec<String>> {
            filters
                .as_ref()
                .and_then(|value| value.get(name))
                .and_then(|value| match value {
                    serde_json::Value::Array(values) => Some(
                        values
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .map(str::to_owned)
                            .collect(),
                    ),
                    serde_json::Value::String(value) => Some(vec![value.clone()]),
                    _ => None,
                })
        };
        let filter_events = filter_values("event");
        let filter_types = filter_values("type");
        let filter_containers = filter_values("container");
        let filter_images = filter_values("image");
        let filter_networks = filter_values("network");
        let filter_volumes = filter_values("volume");
        let filter_scopes = filter_values("scope");
        let parsed_events = contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str::<DockerEvent>(line)
                    .map_err(|error| format!("event journal contains malformed record: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        parsed_events
            .into_iter()
            .filter(|item| since.is_none_or(|value| item.time >= value))
            .filter(|item| until.is_none_or(|value| item.time <= value))
            .filter(|item| event.is_none_or(|value| item.action == *value))
            .filter(|item| kind.is_none_or(|value| item.event_type == *value))
            .filter(|item| scope.is_none_or(|value| item.scope == *value))
            .filter(|item| resource.is_none_or(|value| item.resource.as_deref() == Some(value)))
            .filter(|item| {
                filter_events
                    .as_ref()
                    .is_none_or(|values| values.iter().any(|value| value == &item.action))
            })
            .filter(|item| {
                filter_types
                    .as_ref()
                    .is_none_or(|values| values.iter().any(|value| value == &item.event_type))
            })
            .filter(|item| {
                let values = match item.event_type.as_str() {
                    "container" => filter_containers.as_ref(),
                    "image" => filter_images.as_ref(),
                    "network" => filter_networks.as_ref(),
                    "volume" => filter_volumes.as_ref(),
                    _ => None,
                };
                values.is_none_or(|values| {
                    item.resource
                        .as_ref()
                        .is_some_and(|resource| values.iter().any(|value| value == resource))
                })
            })
            .filter(|item| {
                filter_scopes
                    .as_ref()
                    .is_none_or(|values| values.iter().any(|value| value == &item.scope))
            })
            .collect::<Vec<_>>()
            .pipe(Ok)
    }
}

#[cfg(target_os = "linux")]
fn docker_event_kind(method: &str, path: &str) -> Option<(&'static str, String)> {
    if method == "GET" || path == "/_ping" || path == "/version" {
        return None;
    }
    let event_type = if path.contains("/containers/") {
        "container"
    } else if path.contains("/images/") {
        "image"
    } else if path.contains("/networks/") {
        "network"
    } else if path.contains("/volumes/") {
        "volume"
    } else {
        return None;
    };
    Some((
        event_type,
        path.rsplit('/').next().unwrap_or("request").to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn docker_event_resource(path: &str) -> Option<String> {
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    segments
        .windows(2)
        .find(|pair| matches!(pair[0], "containers" | "images" | "networks" | "volumes"))
        .map(|pair| pair[1].to_string())
}

#[cfg(target_os = "linux")]
fn docker_event_payload(event: &DockerEvent) -> serde_json::Value {
    let actor = event.resource.as_ref().map(|resource| {
        serde_json::json!({
            "ID": resource,
            "Attributes": {
                "status": event.action,
                "httpStatus": event.status.to_string(),
                "scope": event.scope,
            }
        })
    });
    let time_nano = if event.time_nano == 0 {
        event.time.saturating_mul(1_000_000_000)
    } else {
        event.time_nano
    };
    serde_json::json!({
        "Type": event.event_type,
        "Action": event.action,
        "Actor": actor.unwrap_or_else(|| serde_json::json!({"Attributes": {}})),
        "scope": event.scope,
        "time": event.time,
        "timeNano": time_nano,
    })
}

#[cfg(target_os = "linux")]
trait Pipe: Sized {
    fn pipe<T>(self, function: impl FnOnce(Self) -> T) -> T;
}

#[cfg(target_os = "linux")]
impl<T> Pipe for T {
    fn pipe<U>(self, function: impl FnOnce(Self) -> U) -> U {
        function(self)
    }
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
    let state = Arc::new(DockerCompatState::new(runtime_dir.as_ref())?);
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
    let qualification_before = ferro_core::observability::authorization_metrics_snapshot();
    let mut event_request: Option<(String, String)> = None;
    let mut event_follow_query: Option<HashMap<String, String>> = None;
    let mut log_follow: Option<(String, Option<String>)> = None;
    let mut stats_follow: Option<String> = None;
    let response_result: Result<Vec<u8>, String> = (|| {
        let (request, origin) = read_docker_request_after_auth(&mut stream, |socket| {
            ferro_cli::authorization_surfaces::authenticate_docker_peer(
                socket,
                ferro_cli::authorization_surfaces::DockerTelemetry::new(),
            )
            .map(|peer| peer.request_origin())
            .map_err(|error| format!("docker peer authentication failed: {error}"))
        })?;
        let runtime = ContainerRuntime::new(&runtime_dir)
            .map_err(|err| err.to_string())?
            .with_request_origin(origin.clone());
        let surface_authorization = runtime
            .surface_authorization()
            .map_err(|error| error.to_string())?;

        let (path, query) = split_path_query(&request.path)?;
        let path = normalize_docker_api_path(&path);
        event_request = Some((request.method.clone(), path.clone()));
        let response = match (request.method.as_str(), path.as_str()) {
            ("GET", "/events") => {
                let events = state
                    .events
                    .lock()
                    .map_err(|error| format!("docker: event store lock poisoned: {error}"))?
                    .query(&query)?;
                let body = events
                    .iter()
                    .map(docker_event_payload)
                    .map(|event| serde_json::to_string(&event).unwrap_or_default())
                    .collect::<Vec<_>>()
                    .join("\n");
                if query.get("follow").is_some_and(|value| value == "1") {
                    event_follow_query = Some(query.clone());
                    docker_chunked_headers(200, "application/x-ndjson")
                } else {
                    http_response(200, body.as_bytes(), "application/x-ndjson")
                }
            }
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
                let all = parse_docker_bool_query(query.get("all"), "all")?;
                let limit = parse_docker_limit_query(query.get("limit"))?;
                let filters = parse_docker_filters(&query)?;
                let mut records = runtime.list().map_err(|err| err.to_string())?;
                if !all {
                    records.retain(|record| matches!(record.status.as_str(), "running" | "paused"));
                }
                records.retain(|record| docker_container_matches_filters(record, &filters));
                records = docker_container_apply_time_bounds(
                    records,
                    query.get("since").map(String::as_str),
                    query.get("before").map(String::as_str),
                )?;
                records.sort_by(|left, right| {
                    right
                        .created_at_unix
                        .cmp(&left.created_at_unix)
                        .then_with(|| right.id.cmp(&left.id))
                });
                if let Some(limit) = limit {
                    records.truncate(limit);
                }
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
                let tail = query.get("tail").cloned();
                if query.get("follow").is_some_and(|value| value == "1") {
                    // Validate the container and tail before committing to a
                    // long-lived chunked response.
                    let raw = runtime.logs(id).map_err(|err| err.to_string())?;
                    let _ = docker_tail_logs(&raw, tail.as_deref())?;
                    log_follow = Some((id.to_string(), tail));
                    docker_chunked_headers(200, "text/plain")
                } else {
                    let logs = docker_tail_logs(
                        &runtime.logs(id).map_err(|err| err.to_string())?,
                        tail.as_deref(),
                    )?;
                    http_response(200, logs.as_bytes(), "text/plain")
                }
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/top") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/top");
                let body = docker_top_payload(&runtime, id)?;
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/stats") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/stats");
                let stats = runtime.stats(id).map_err(|err| err.to_string())?;
                if query.get("stream").is_some_and(|value| value == "1") {
                    stats_follow = Some(id.to_string());
                    docker_chunked_headers(200, "application/json")
                } else {
                    let body = docker_stats_payload(&stats);
                    http_response(200, body.to_string().as_bytes(), "application/json")
                }
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
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/pause") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/pause");
                runtime.pause(id).map_err(|err| err.to_string())?;
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/unpause") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/unpause");
                runtime.resume(id).map_err(|err| err.to_string())?;
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
                let timeout = query
                    .get("timeout")
                    .map(|value| {
                        value
                            .parse::<u64>()
                            .map(|seconds| (seconds > 0).then_some(Duration::from_secs(seconds)))
                            .map_err(|_| {
                                "docker: wait timeout must be a non-negative integer".to_string()
                            })
                    })
                    .transpose()?
                    .flatten();
                wait_for_container_exit_with_timeout(&runtime, id, timeout)?;
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
            ("GET", path) if path.starts_with("/networks/") => {
                let name = path.trim_start_matches("/networks/");
                if name == "bridge" {
                    let body = serde_json::json!({
                        "Name": "bridge", "Id": "bridge", "Driver": "bridge",
                        "Scope": "local", "IPAM": {"Config": []}, "Containers": {}
                    });
                    http_response(200, body.to_string().as_bytes(), "application/json")
                } else {
                    let record = load_networks(runtime_dir.as_ref())?
                        .into_iter()
                        .find(|record| record.name == name)
                        .ok_or_else(|| format!("docker: network not found: {name}"))?;
                    let body = serde_json::json!({
                        "Name": record.name, "Id": record.name, "Driver": record.driver,
                        "Scope": "local",
                        "IPAM": {"Config": [{"Subnet": record.subnet, "Gateway": record.gateway}]},
                        "Containers": {}
                    });
                    http_response(200, body.to_string().as_bytes(), "application/json")
                }
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
                handle_network_authorized(
                    runtime_dir.as_ref(),
                    &runtime,
                    NetworkCommands::Create {
                        name: spec.name.clone(),
                        subnet,
                        gateway,
                        ipv6_subnet: None,
                        ipv6_gateway: None,
                    },
                    &origin,
                    &surface_authorization,
                )?;
                let body = serde_json::json!({ "Id": spec.name, "Warning": "" });
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("POST", "/networks/prune") => {
                let associations = runtime.list().map_err(|error| error.to_string())?;
                let records = load_networks(runtime_dir.as_ref())?;
                let mut deleted = Vec::new();
                for record in records {
                    let proof = surface_authorization
                        .authorize_named(
                            &origin,
                            AuthorizationAction::NetworkDelete,
                            ResourceKind::Network,
                            &record.name,
                            record.generation,
                        )
                        .map_err(|error| error.to_string())?;
                    execute_network_remove(runtime_dir.as_ref(), &record, &associations, proof)?;
                    deleted.push(record.name);
                }
                let body = serde_json::json!({"NetworksDeleted": deleted});
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("DELETE", path) if path.starts_with("/networks/") => {
                let id = path.trim_start_matches("/networks/");
                handle_network_authorized(
                    runtime_dir.as_ref(),
                    &runtime,
                    NetworkCommands::Rm {
                        name: id.to_string(),
                    },
                    &origin,
                    &surface_authorization,
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
            ("GET", path) if path.starts_with("/images/") && path.ends_with("/history") => {
                let name = path
                    .trim_start_matches("/images/")
                    .trim_end_matches("/history");
                let reference = resolve_reference(&store, name)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("docker: unknown image {name}"))?;
                let manifest = parse_image_manifest(&reference.manifest_json)
                    .map_err(|error| format!("docker: invalid image manifest: {error}"))?;
                let history = manifest
                    .layers
                    .into_iter()
                    .map(|layer| {
                        serde_json::json!({
                            "Id": layer.digest,
                            "Created": reference.created_at_unix,
                            "CreatedBy": "",
                            "Tags": serde_json::Value::Null,
                            "Size": layer.size,
                            "Comment": "",
                        })
                    })
                    .collect::<Vec<_>>();
                let body = serde_json::to_string(&history).map_err(|error| error.to_string())?;
                http_response(200, body.as_bytes(), "application/json")
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
                handle_pull_authorized(&store, &reference, false, &origin, &surface_authorization)?;
                http_response(200, b"{}", "application/json")
            }
            ("POST", "/images/prune") => {
                let records = store.list_references().map_err(|error| error.to_string())?;
                let permits = records
                    .iter()
                    .map(|record| {
                        surface_authorization
                            .authorize_named(
                                &origin,
                                AuthorizationAction::ImageDelete,
                                ResourceKind::Image,
                                &record.reference,
                                1,
                            )
                            .map_err(|error| error.to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let removed = store
                    .prune_references_authorized(permits)
                    .map_err(|error| error.to_string())?;
                let body = serde_json::json!({
                    "ImagesDeleted": [],
                    "SpaceReclaimed": 0,
                    "ferrocrateRemoved": removed,
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("POST", path) if path.starts_with("/images/") && path.ends_with("/tag") => {
                let source = path.trim_start_matches("/images/").trim_end_matches("/tag");
                let repo = query
                    .get("repo")
                    .ok_or_else(|| "docker: image tag requires repo".to_string())?;
                let tag = query.get("tag").map(String::as_str).unwrap_or("latest");
                let target = format!("{repo}:{tag}");
                let plan = prepare_image_tag(&store, source, &target)
                    .map_err(|error| error.to_string())?;
                let permit = surface_authorization
                    .authorize_image_tag_plan(&origin, &plan)
                    .map_err(|error| error.to_string())?;
                execute_image_tag_authorized(&store, plan, permit)
                    .map_err(|error| error.to_string())?;
                http_response(201, &[], "text/plain")
            }
            ("DELETE", path) if path.starts_with("/images/") => {
                let reference = path.trim_start_matches("/images/");
                handle_rmi_authorized(&store, reference, &origin, &surface_authorization)?;
                http_response(200, b"[]", "application/json")
            }
            ("POST", "/volumes/create") => {
                let body: serde_json::Value = serde_json::from_slice(&request.body)
                    .map_err(|error| format!("docker: invalid volume create payload: {error}"))?;
                let name = body
                    .get("Name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "docker: volume Name is required".to_string())?;
                let driver = body
                    .get("Driver")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("local");
                let opts: Vec<String> = body
                    .get("DriverOpts")
                    .and_then(serde_json::Value::as_object)
                    .map(|map| {
                        map.iter()
                            .map(|(key, value)| {
                                format!("{key}={}", value.as_str().unwrap_or_default())
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let driver_opts = parse_driver_opts(&opts)?;
                let plan = volume_store
                    .prepare_create(name, driver, driver_opts)
                    .map_err(|error| error.to_string())?;
                let proof = surface_authorization
                    .authorize_volume_create_plan(&origin, &plan)
                    .map_err(|error| error.to_string())?;
                execute_volume_create(&volume_store, plan, proof)?;
                let record = volume_store
                    .get(name)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("docker: volume not found after create: {name}"))?;
                let body = serde_json::json!({"Name": record.name, "Driver": record.driver, "Mountpoint": record.path});
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("POST", "/volumes/prune") => {
                let records = volume_store.list().map_err(|error| error.to_string())?;
                let mut deleted = Vec::new();
                for record in records {
                    let proof = surface_authorization
                        .authorize_named(
                            &origin,
                            AuthorizationAction::VolumeDelete,
                            ResourceKind::Volume,
                            &record.name,
                            1,
                        )
                        .map_err(|error| error.to_string())?;
                    if execute_volume_remove(&volume_store, &record.name, proof)? {
                        deleted.push(record.name);
                    }
                }
                let body = serde_json::json!({"VolumesDeleted": deleted, "SpaceReclaimed": 0});
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("DELETE", path) if path.starts_with("/volumes/") => {
                let name = path.trim_start_matches("/volumes/");
                let proof = surface_authorization
                    .authorize_named(
                        &origin,
                        AuthorizationAction::VolumeDelete,
                        ResourceKind::Volume,
                        name,
                        1,
                    )
                    .map_err(|error| error.to_string())?;
                execute_volume_remove(&volume_store, name, proof)?;
                http_response(204, &[], "text/plain")
            }
            ("GET", "/volumes") => {
                let volumes = volume_store
                    .list()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .map(|record| {
                        serde_json::json!({
                            "Name": record.name,
                            "Driver": record.driver,
                            "Mountpoint": record.path,
                            "CreatedAt": record.created_at_unix.to_string(),
                            "Status": serde_json::Value::Null,
                        })
                    })
                    .collect::<Vec<_>>();
                let body = serde_json::json!({"Volumes": volumes, "Warnings": []});
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/volumes/") => {
                let name = path.trim_start_matches("/volumes/");
                let record = volume_store
                    .get(name)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("docker: volume not found: {name}"))?;
                let body = serde_json::json!({
                    "Name": record.name,
                    "Driver": record.driver,
                    "Mountpoint": record.path,
                    "CreatedAt": record.created_at_unix.to_string(),
                    "Status": serde_json::Value::Null,
                    "UsageData": serde_json::Value::Null,
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
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
    if let Some(query) = event_follow_query {
        stream_docker_events(&mut stream, &state, &query)?;
        return Ok(());
    }
    if let Some((id, tail)) = log_follow {
        let follow_runtime =
            ContainerRuntime::new(&runtime_dir).map_err(|error| error.to_string())?;
        stream_docker_logs(&mut stream, &follow_runtime, &id, tail.as_deref())?;
        return Ok(());
    }
    if let Some(id) = stats_follow {
        let follow_runtime =
            ContainerRuntime::new(&runtime_dir).map_err(|error| error.to_string())?;
        stream_docker_stats(&mut stream, &follow_runtime, &id)?;
        return Ok(());
    }
    if let Some((method, path)) = event_request {
        let status = response
            .get(..)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| text.lines().next())
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(500);
        if let Ok(mut events) = state.events.lock() {
            let _ = events.append(&method, &path, status);
        }
    }
    let fixture = ferro_core::observability::qualification_fixture("docker");
    let _ = ferro_core::observability::persist_authorization_fixture_evidence(
        &fixture,
        qualification_before,
        ferro_core::observability::authorization_metrics_snapshot(),
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_docker_request_after_auth(
    stream: &mut UnixStream,
    authenticate: impl FnOnce(&UnixStream) -> Result<ferro_core::authorization::RequestOrigin, String>,
) -> Result<(HttpRequest, ferro_core::authorization::RequestOrigin), String> {
    let origin = authenticate(stream)?;
    let request = read_http_request(stream)?;
    Ok((request, origin))
}

#[cfg(target_os = "linux")]
fn docker_error_response(status: u16, message: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "message": message
    })
    .to_string();
    http_response(status, body.as_bytes(), "application/json")
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn docker_tail_logs(logs: &str, tail: Option<&str>) -> Result<String, String> {
    let Some(tail) = tail else {
        return Ok(logs.to_string());
    };
    if tail.eq_ignore_ascii_case("all") {
        return Ok(logs.to_string());
    }
    let count = tail
        .parse::<usize>()
        .map_err(|_| "docker: logs tail must be a non-negative integer or all".to_string())?;
    let mut lines: Vec<&str> = logs.lines().collect();
    if count == 0 {
        return Ok(String::new());
    }
    if lines.len() > count {
        lines.drain(..lines.len() - count);
    }
    let mut result = lines.join("\n");
    if logs.ends_with('\n') && !result.is_empty() {
        result.push('\n');
    }
    Ok(result)
}

fn parse_docker_bool_query(value: Option<&String>, key: &str) -> Result<bool, String> {
    match value.map(String::as_str) {
        None => Ok(false),
        Some("1" | "true" | "TRUE" | "True") => Ok(true),
        Some("0" | "false" | "FALSE" | "False") => Ok(false),
        Some(other) => Err(format!("docker: {key} must be a boolean, got {other}")),
    }
}

fn parse_docker_limit_query(value: Option<&String>) -> Result<Option<usize>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = value
        .parse::<i64>()
        .map_err(|_| format!("docker: limit must be an integer, got {value}"))?;
    if parsed < 0 {
        return Ok(None);
    }
    usize::try_from(parsed)
        .map(Some)
        .map_err(|_| format!("docker: limit is too large, got {value}"))
}

fn parse_docker_filters(
    query: &HashMap<String, String>,
) -> Result<HashMap<String, Vec<String>>, String> {
    let Some(raw) = query.get("filters") else {
        return Ok(HashMap::new());
    };
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|error| format!("docker: invalid filters JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "docker: filters must be a JSON object".to_string())?;
    let mut filters = HashMap::new();
    for (key, values) in object {
        let values = values
            .as_array()
            .ok_or_else(|| format!("docker: filter {key} must be an array"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("docker: filter {key} values must be strings"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        filters.insert(key.clone(), values);
    }
    Ok(filters)
}

fn docker_container_matches_filters(
    record: &ferro_core::container_store::ContainerRecord,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    let matches_any = |key: &str, value: &str| {
        filters
            .get(key)
            .map(|values| values.is_empty() || values.iter().any(|candidate| candidate == value))
            .unwrap_or(true)
    };
    if !matches_any("status", &record.status) {
        return false;
    }
    if let Some(names) = filters.get("name") {
        let name = record.name.as_deref().unwrap_or(&record.id);
        if !names.is_empty() && !names.iter().any(|candidate| name.contains(candidate)) {
            return false;
        }
    }
    if let Some(images) = filters.get("ancestor") {
        if !images.is_empty()
            && !images
                .iter()
                .any(|candidate| record.image == *candidate || record.image.starts_with(candidate))
        {
            return false;
        }
    }
    if let Some(labels) = filters.get("label") {
        for selector in labels {
            let mut parts = selector.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let matched = record
                .labels
                .get(key)
                .is_some_and(|actual| parts.next().map_or(true, |expected| actual == expected));
            if !matched {
                return false;
            }
        }
    }
    true
}

/// Apply Docker's `since` and `before` list selectors after ordinary filters.
/// Selectors may name a container (ID or name) or provide a Unix timestamp.
/// The comparison is strict, matching Docker's boundary semantics: `since`
/// excludes the anchor and `before` excludes containers created at/after it.
fn docker_container_apply_time_bounds(
    records: Vec<ferro_core::container_store::ContainerRecord>,
    since_selector: Option<&str>,
    before_selector: Option<&str>,
) -> Result<Vec<ferro_core::container_store::ContainerRecord>, String> {
    let resolve = |selector: &str| {
        selector.parse::<u64>().ok().or_else(|| {
            records.iter().find_map(|record| {
                let name = record.name.as_deref().unwrap_or_default();
                (record.id == selector || name == selector).then_some(record.created_at_unix)
            })
        })
    };
    let bound = |key: &str, selector: Option<&str>| -> Result<Option<u64>, String> {
        selector.map_or(Ok(None), |selector| {
            resolve(selector).map(Some).ok_or_else(|| {
                format!("docker: {key} selector not found or not a Unix timestamp: {selector}")
            })
        })
    };
    let since = bound("since", since_selector)?;
    let before = bound("before", before_selector)?;
    Ok(records
        .into_iter()
        .filter(|record| since.is_none_or(|value| record.created_at_unix > value))
        .filter(|record| before.is_none_or(|value| record.created_at_unix < value))
        .collect())
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn parse_docker_network_create_spec(body: &[u8]) -> Result<DockerNetworkCreateSpec, String> {
    let spec: DockerNetworkCreateSpec = serde_json::from_slice(body)
        .map_err(|err| format!("docker: invalid network create payload: {err}"))?;
    if spec.name.trim().is_empty() {
        return Err("docker: network name is required".to_string());
    }
    Ok(spec)
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn docker_chunked_headers(status: u16, content_type: &str) -> Vec<u8> {
    let status_line = match status {
        200 => "200 OK",
        400 => "400 Bad Request",
        404 => "404 Not Found",
        _ => "200 OK",
    };
    format!(
        "HTTP/1.1 {status_line}\r\nTransfer-Encoding: chunked\r\nContent-Type: {content_type}\r\nConnection: keep-alive\r\n\r\n"
    )
    .into_bytes()
}

#[cfg(target_os = "linux")]
fn stream_docker_events(
    stream: &mut UnixStream,
    state: &DockerCompatState,
    query: &HashMap<String, String>,
) -> Result<(), String> {
    let mut cursor: Option<u64> = None;
    loop {
        let events = state
            .events
            .lock()
            .map_err(|error| format!("docker: event store lock poisoned: {error}"))?
            .query(query)?;
        for event in events {
            if cursor.is_some_and(|seen| event.id <= seen) {
                continue;
            }
            cursor = Some(event.id);
            let body = serde_json::to_vec(&docker_event_payload(&event))
                .map_err(|error| format!("docker: event serialization failed: {error}"))?;
            let chunk = format!("{:x}\r\n", body.len());
            stream
                .write_all(chunk.as_bytes())
                .and_then(|_| stream.write_all(&body))
                .and_then(|_| stream.write_all(b"\r\n"))
                .map_err(|error| error.to_string())?;
        }
        stream.flush().map_err(|error| error.to_string())?;
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(target_os = "linux")]
fn stream_docker_logs(
    stream: &mut UnixStream,
    runtime: &ContainerRuntime,
    id: &str,
    tail: Option<&str>,
) -> Result<(), String> {
    let mut emitted = 0usize;
    loop {
        let raw = runtime.logs(id).map_err(|error| error.to_string())?;
        if emitted == 0 {
            let initial = docker_tail_logs(&raw, tail)?;
            if !initial.is_empty() {
                write_chunk(stream, initial.as_bytes())?;
            }
            emitted = raw.len();
        } else if raw.len() >= emitted {
            if raw.len() > emitted {
                write_chunk(stream, &raw.as_bytes()[emitted..])?;
                emitted = raw.len();
            }
        } else {
            // The log files were rotated or truncated; resume from the new
            // beginning rather than indexing stale bytes.
            emitted = 0;
        }
        stream.flush().map_err(|error| error.to_string())?;
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(target_os = "linux")]
fn docker_stats_payload(stats: &ferro_core::cgroups::CgroupStats) -> serde_json::Value {
    serde_json::json!({
        "memory_stats": {"usage": stats.memory_current, "limit": stats.memory_max},
        "pids_stats": {"current": stats.pids_current},
        "cpu_stats": {"cpu_usage": {"total_usage": stats.cpu_usage_usec}}
    })
}

#[cfg(target_os = "linux")]
fn docker_top_payload(runtime: &ContainerRuntime, id: &str) -> Result<serde_json::Value, String> {
    let record = runtime.inspect(id).map_err(|error| error.to_string())?;
    let pid = record.pid;
    if pid == 0 {
        return Ok(serde_json::json!({
            "Titles": ["PID", "CMD", "STATE"],
            "Processes": []
        }));
    }
    let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| stat.split_whitespace().nth(2).map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string());
    let command = if record.command.is_empty() {
        record.image
    } else {
        record.command.join(" ")
    };
    Ok(serde_json::json!({
        "Titles": ["PID", "CMD", "STATE"],
        "Processes": [[pid.to_string(), command, state]]
    }))
}

#[cfg(target_os = "linux")]
fn stream_docker_stats(
    stream: &mut UnixStream,
    runtime: &ContainerRuntime,
    id: &str,
) -> Result<(), String> {
    loop {
        let stats = runtime.stats(id).map_err(|error| error.to_string())?;
        let mut body =
            serde_json::to_vec(&docker_stats_payload(&stats)).map_err(|error| error.to_string())?;
        body.push(b'\n');
        write_chunk(stream, &body)?;
        stream.flush().map_err(|error| error.to_string())?;
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(target_os = "linux")]
fn write_chunk(stream: &mut UnixStream, body: &[u8]) -> Result<(), String> {
    stream
        .write_all(format!("{:x}\r\n", body.len()).as_bytes())
        .and_then(|_| stream.write_all(body))
        .and_then(|_| stream.write_all(b"\r\n"))
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn split_path_query(path: &str) -> Result<(String, HashMap<String, String>), String> {
    let mut query_map = HashMap::new();
    let mut parts = path.splitn(2, '?');
    let base = parts.next().unwrap_or("").to_string();
    let query = parts.next().unwrap_or("");
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((key, value)) = pair.split_once('=') {
            query_map.insert(
                percent_decode_query_component(key)?,
                percent_decode_query_component(value)?,
            );
        }
    }
    Ok((base, query_map))
}

fn percent_decode_query_component(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err("docker: malformed percent-encoded query component".to_string());
                }
                let high = (bytes[index + 1] as char).to_digit(16).ok_or_else(|| {
                    "docker: malformed percent-encoded query component".to_string()
                })?;
                let low = (bytes[index + 2] as char).to_digit(16).ok_or_else(|| {
                    "docker: malformed percent-encoded query component".to_string()
                })?;
                decoded.push(((high << 4) | low) as u8);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| "docker: query component is not valid UTF-8".to_string())
}

#[cfg(target_os = "linux")]
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

mod network_lifecycle;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    use super::{
        bind_run_network, build_health_config, build_limits, desktop_forward_enabled,
        discover_rootless_socket, dispatch, docker_chunked_headers,
        docker_container_apply_time_bounds, docker_container_matches_filters, docker_event_payload,
        docker_tail_logs, docker_top_payload, effective_readonly, handle_build, handle_containers,
        handle_context, handle_exec, handle_image_prune, handle_images, handle_inspect,
        handle_kill, handle_logs, handle_migrate_compose_report, handle_network, handle_pause,
        handle_pull, handle_push, handle_restart, handle_rm, handle_rmi, handle_run, handle_stats,
        handle_stop, handle_unpause, handle_volume, host_build_arch, normalize_docker_api_path,
        parse_bind_mounts, parse_build_contexts, parse_capabilities, parse_docker_bool_query,
        parse_docker_filters, parse_docker_limit_query, parse_driver_opts, parse_env_entries,
        parse_key_values, parse_publish, parse_restart_policy, parse_tmpfs_mounts,
        read_docker_request_after_auth, read_http_request, should_desktop_forward,
        split_path_query, structured_desktop_error, top_level_command_name,
        validate_build_platform, validate_network_backend, validate_network_mode, AiCommands, Cli,
        Commands, ComposeCommands, ConfigCommands, ContextCommands, DockerEvent, DockerEventStore,
        MigrateCommands, NetworkCommands, VolumeCommands,
    };
    use clap::Parser;
    use ferro_core::authorization::surface::SurfaceAuthorization;
    use ferro_core::image_store::LocalImageStore;

    fn test_surface_authorization(path: &std::path::Path) -> SurfaceAuthorization {
        ContainerRuntime::new(path)
            .expect("test runtime")
            .surface_authorization()
            .expect("surface authorization")
    }
    use ferro_core::runtime::{ContainerRuntime, NetworkBackend};
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
    fn parses_compose_migration_report_command() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "migrate",
            "compose-report",
            "--file",
            "compose.yaml",
            "--output",
            "report.json",
        ]);
        match cli.command {
            Commands::Migrate {
                target: MigrateCommands::ComposeReport { file, output },
            } => {
                assert_eq!(file, std::path::PathBuf::from("compose.yaml"));
                assert_eq!(output, Some(std::path::PathBuf::from("report.json")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rootless_socket_discovery_requires_an_actual_unix_socket() {
        let _guard = ENV_MUTEX.lock().expect("environment lock");
        let temp = tempfile::tempdir().expect("socket fixture");
        let previous = std::env::var_os("XDG_RUNTIME_DIR");
        unsafe { std::env::set_var("XDG_RUNTIME_DIR", temp.path()) };
        let socket = temp.path().join("docker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        assert_eq!(discover_rootless_socket(), Some(socket.clone()));
        drop(listener);
        std::fs::remove_file(&socket).expect("remove socket");
        std::fs::write(&socket, b"not a socket").expect("write decoy");
        assert_ne!(discover_rootless_socket(), Some(socket));
        match previous {
            Some(value) => unsafe { std::env::set_var("XDG_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("XDG_RUNTIME_DIR") },
        }
    }

    #[test]
    fn compose_migration_report_is_deterministic_and_flags_manual_review() {
        let temp = tempfile::tempdir().expect("migration fixture");
        let compose = temp.path().join("compose.yaml");
        std::fs::write(
            &compose,
            r#"version: "3.8"
services:
  web:
    image: nginx:latest
    network_mode: host
networks:
  zeta: {}
  alpha: {}
volumes:
  cache: {}
"#,
        )
        .expect("compose");
        let first = temp.path().join("first.json");
        let second = temp.path().join("second.json");
        handle_migrate_compose_report(&compose, Some(&first)).expect("first report");
        handle_migrate_compose_report(&compose, Some(&second)).expect("second report");
        assert_eq!(
            std::fs::read(&first).expect("first bytes"),
            std::fs::read(&second).expect("second bytes")
        );
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&first).expect("report bytes")).expect("json");
        assert_eq!(report["networks"], serde_json::json!(["alpha", "zeta"]));
        assert_eq!(report["manual_review"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn published_port_preserves_ebpf_backend() {
        let args = Cli::try_parse_from([
            "ferrocrate",
            "run",
            "alpine",
            "-p",
            "8080:80",
            "--network-backend",
            "ebpf",
        ])
        .unwrap();
        let Commands::Run {
            network_backend, ..
        } = args.command
        else {
            panic!("run command")
        };
        assert_eq!(network_backend, "ebpf");
    }

    #[test]
    fn network_backend_validator_delegates_to_typed_parser() {
        for value in ["ebpf", "iptables", "nftables"] {
            assert_eq!(
                validate_network_backend(value),
                value
                    .parse::<NetworkBackend>()
                    .map(|_| value.to_string())
                    .map_err(|err| err.to_string())
            );
        }

        assert_eq!(
            validate_network_backend("unsupported"),
            "unsupported"
                .parse::<NetworkBackend>()
                .map(|_| "unsupported".to_string())
                .map_err(|err| err.to_string())
        );
    }

    #[test]
    fn parses_build_command_with_tag() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "build",
            "--dockerfile",
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
                image_format,
                embed_model,
                platform,
                cache_from,
                cache_to,
                build_context,
            } => {
                assert_eq!(dockerfile.as_deref(), Some("./Dockerfile"));
                assert!(ferrofile.is_none());
                assert_eq!(tag.expect("tag"), "acme/app:dev");
                assert_eq!(compress, "gzip");
                assert_eq!(image_format, "oci");
                assert!(embed_model.is_none());
                assert!(platform.is_none());
                assert!(cache_from.is_none());
                assert!(cache_to.is_none());
                assert!(build_context.is_empty());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_and_validates_named_build_contexts() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("assets");
        std::fs::create_dir_all(&path).unwrap();
        let value = format!("assets={}", path.display());
        let contexts = parse_build_contexts(&[value]).unwrap();
        assert_eq!(contexts.get("assets"), Some(&path));
        assert!(parse_build_contexts(&["assets".to_string()]).is_err());
        assert!(parse_build_contexts(&[
            format!("assets={}", path.display()),
            format!("assets={}", path.display()),
        ])
        .is_err());
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
        let authorization = test_surface_authorization(temp.path());
        let err = handle_rmi(&store, "", &authorization).expect_err("invalid image");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn image_prune_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let authorization = test_surface_authorization(temp.path());
        handle_image_prune(&store, &authorization).expect("prune");
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
    fn parses_ai_gpu_selection_options() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "ai",
            "gpu",
            "--required-vram-bytes",
            "4096",
            "--format",
            "json",
        ]);
        match cli.command {
            Commands::Ai {
                command:
                    AiCommands::Gpu {
                        required_vram_bytes,
                        format,
                    },
            } => {
                assert_eq!(required_vram_bytes, Some(4096));
                assert_eq!(format, "json");
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
        let cli = Cli::parse_from([
            "ferrocrate",
            "doctor",
            "--fix",
            "--bootstrap",
            "--dry-run",
            "--confirm",
            "--json",
        ]);
        match cli.command {
            Commands::Doctor {
                fix,
                bootstrap,
                dry_run,
                confirm,
                json,
            } => {
                assert!(fix);
                assert!(bootstrap);
                assert!(dry_run);
                assert!(confirm);
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

    #[cfg(target_os = "linux")]
    #[test]
    fn unauthorized_docker_peer_leaves_oversized_body_unread() {
        use std::os::unix::net::UnixStream;
        let (mut server, mut client) = UnixStream::pair().unwrap();
        let payload = vec![b'x'; 128 * 1024];
        client.write_all(&payload).unwrap();
        let error = read_docker_request_after_auth(&mut server, |_| Err("unauthorized".into()))
            .expect_err("authentication must fail before decoding");
        assert_eq!(error, "unauthorized");
        let mut first = [0u8; 1];
        server.read_exact(&mut first).unwrap();
        assert_eq!(first[0], b'x');
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
    fn bind_run_network_named_keeps_bridge_mode_and_logical_association() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record =
            super::create_network_record("app-net", Some("10.88.0.0/24"), None, None, None)
                .expect("record");
        super::save_networks(temp.path(), &[record.clone()]).expect("save");
        let binding = bind_run_network(temp.path(), "app-net", None, None).expect("bind");
        assert_eq!(binding.mode, "bridge");
        assert_eq!(binding.association.as_deref(), Some("app-net"));
        assert_eq!(
            binding.bridge_name.as_deref(),
            Some(record.bridge_name.as_str())
        );
        assert_eq!(
            binding.bridge_cidr.as_deref(),
            Some(record.bridge_cidr.as_str())
        );
    }

    #[test]
    fn bind_run_network_builtins_keep_mode_as_association() {
        let temp = tempfile::tempdir().expect("tempdir");
        for mode in ["bridge", "host", "none", "wireguard"] {
            let binding = bind_run_network(temp.path(), mode, None, None).expect(mode);
            assert_eq!(binding.mode, mode);
            assert_eq!(binding.association.as_deref(), Some(mode));
        }
        let encrypted = bind_run_network(temp.path(), "encrypted", None, None).expect("encrypted");
        assert_eq!(encrypted.mode, "wireguard");
        assert_eq!(encrypted.association.as_deref(), Some("wireguard"));
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
                    ..
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
    fn creates_dual_stack_network_record_with_canonical_ipv6_gateway() {
        let record = super::create_network_record(
            "dual-net",
            Some("10.88.0.0/24"),
            Some("10.88.0.1"),
            Some("fd42:4242::/64"),
            None,
        )
        .expect("dual-stack record");
        assert_eq!(record.ipv6_cidr.as_deref(), Some("fd42:4242::1/64"));
        let intent = crate::network_lifecycle::NetworkCreateRecord::from_record(record)
            .expect("lifecycle intent");
        assert_eq!(
            intent.intended_identity().ipv6_cidr.as_deref(),
            Some("fd42:4242::1/64")
        );
    }

    #[test]
    fn volume_handlers_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime_dir = temp.path().to_path_buf();
        let authorization = test_surface_authorization(&runtime_dir);

        handle_volume(
            &runtime_dir,
            VolumeCommands::Create {
                name: "data".to_string(),
                driver: "local".to_string(),
                opts: Vec::new(),
            },
            &authorization,
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
            &authorization,
        )
        .expect("backup volume");

        handle_volume(
            &runtime_dir,
            VolumeCommands::Rm {
                name: "data".to_string(),
            },
            &authorization,
        )
        .expect("rm volume");

        handle_volume(
            &runtime_dir,
            VolumeCommands::Restore {
                name: "data".to_string(),
                path: archive.display().to_string(),
            },
            &authorization,
        )
        .expect("restore volume");
        handle_volume(&runtime_dir, VolumeCommands::Ls, &authorization).expect("ls volumes");
        handle_volume(
            &runtime_dir,
            VolumeCommands::Rm {
                name: "data".to_string(),
            },
            &authorization,
        )
        .expect("rm volume");
    }

    #[test]
    fn network_handlers_run() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");
        handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "test-net".to_string(),
                subnet: Some("172.30.0.0/16".to_string()),
                gateway: Some("172.30.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        )
        .expect("create network");
        handle_network(temp.path(), &runtime, NetworkCommands::Ls, &authorization)
            .expect("ls networks");
        handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Rm {
                name: "test-net".to_string(),
            },
            &authorization,
        )
        .expect("rm network");
    }

    fn configured_cli_runtime(mode: &str) -> tempfile::TempDir {
        use ed25519_dalek::SigningKey;
        use ferro_core::authorization::admission::{AdmissionArtifact, AdmissionSnapshotManifest};
        use ferro_core::witness::{
            Checkpoint, CheckpointKind, FlushedHead, Invocation, JournalConfig, JournalMode,
            PrincipalSummary, ResourceSummary, WitnessAction, WitnessJournal, WitnessOutcome,
            WitnessRecord, WitnessResourceKind, WitnessStage,
        };
        use sha2::Digest;
        use std::os::unix::fs::PermissionsExt;

        assert!(matches!(mode, "disabled" | "shadow" | "enforce"));
        let runtime = tempfile::tempdir().expect("runtime directory");
        std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700))
            .expect("protect runtime directory");
        if mode == "disabled" {
            return runtime;
        }
        let auth = runtime.path().join("authorization");
        std::fs::create_dir(&auth).expect("create authorization directory");
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o700))
            .expect("protect authorization directory");
        let journal_id = [0x44u8; 16];
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let protected = |path: &std::path::Path, bytes: &[u8]| {
            std::fs::write(path, bytes).expect("write protected fixture");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("protect fixture");
        };
        protected(
            &auth.join("active-policy.toml"),
            format!("schema_version = 1\ngeneration = 1\nmode = \"{mode}\"\n").as_bytes(),
        );
        protected(
            &auth.join("journal-id"),
            format!("{}\n", hex(&journal_id)).as_bytes(),
        );

        let key = SigningKey::from_bytes(&[0x54; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let journal = WitnessJournal::open(JournalConfig::new(
            auth.join("witness-journal"),
            journal_id,
            JournalMode::Required,
        ))
        .expect("open production witness journal");
        let checkpoint = Checkpoint::sign(
            FlushedHead::new(journal_id, 1, 0, [0; 32]),
            now.saturating_sub(1),
            &key,
            CheckpointKind::Periodic,
        )
        .expect("sign checkpoint");
        let checkpoint_bytes = checkpoint.encode();
        let checkpoint_digest: [u8; 32] = sha2::Sha256::digest(&checkpoint_bytes).into();
        journal
            .append_checkpoint_publication(
                checkpoint_digest,
                WitnessRecord {
                    epoch: 1,
                    sequence: 1,
                    previous_hash: [0; 32],
                    event_id: [0x54; 16],
                    request_id: [0x55; 16],
                    runtime_instance_id: [0x56; 16],
                    boot_id: [0x57; 16],
                    principal: PrincipalSummary::pseudonymize(&[0x58; 32], b"qualification")
                        .expect("pseudonymize principal"),
                    invocation: Invocation::Manager,
                    action: WitnessAction::CheckpointPublish,
                    resource_kind: WitnessResourceKind::Administrative,
                    resource: ResourceSummary::pseudonymize(&[0x59; 32], b"checkpoint")
                        .expect("pseudonymize resource"),
                    resource_generation: 1,
                    policy_version: 0,
                    policy_digest: [0; 32],
                    decision_id: None,
                    rule: None,
                    decision: None,
                    reason: None,
                    request_digest: checkpoint_digest,
                    result_digest: Some(checkpoint_digest),
                    wall_time_ns: 0,
                    monotonic_ns: 0,
                    stage: WitnessStage::CheckpointPublished,
                    outcome: WitnessOutcome::Succeeded,
                    recovery_link: None,
                    path_class: None,
                    device_class: None,
                    correlation_digest: None,
                },
            )
            .expect("record checkpoint publication");
        let admission = auth.join("admission");
        std::fs::create_dir(&admission).expect("create admission directory");
        std::fs::set_permissions(&admission, std::fs::Permissions::from_mode(0o700))
            .expect("protect admission directory");
        protected(&admission.join("minimum.bin"), &checkpoint_bytes);
        protected(&admission.join("checkpoint-0001.bin"), &checkpoint_bytes);
        let trust = serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "journal_id": hex(&journal_id),
            "initial_public_key": hex(key.verifying_key().as_bytes()),
            "starting_epoch": 1
        }))
        .expect("serialize trust bundle");
        protected(&admission.join("trust.json"), &trust);
        let digest = |bytes: &[u8]| hex(&sha2::Sha256::digest(bytes));
        let manifest = AdmissionSnapshotManifest {
            schema: 1,
            generation: 1,
            journal_id: hex(&journal_id),
            trust_bundle: AdmissionArtifact {
                file: "trust.json".into(),
                sha256: digest(&trust),
            },
            minimum_checkpoint: AdmissionArtifact {
                file: "minimum.bin".into(),
                sha256: digest(&checkpoint_bytes),
            },
            checkpoint_chain: vec![AdmissionArtifact {
                file: "checkpoint-0001.bin".into(),
                sha256: digest(&checkpoint_bytes),
            }],
            trust_key_ids: vec![digest(key.verifying_key().as_bytes())],
            latest_checkpoint: "checkpoint-0001.bin".into(),
            latest_created_at_secs: now.saturating_sub(1),
        };
        protected(
            &admission.join("manifest.json"),
            &serde_json::to_vec(&manifest).expect("serialize admission manifest"),
        );
        drop(journal);
        runtime
    }

    fn create_and_remove_named_network(runtime_dir: &std::path::Path, name: &str) {
        let runtime = ContainerRuntime::new(runtime_dir).expect("runtime");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");
        handle_network(
            runtime_dir,
            &runtime,
            NetworkCommands::Create {
                name: name.to_string(),
                subnet: Some("172.30.0.0/16".to_string()),
                gateway: Some("172.30.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        )
        .expect("create network");
        let stored = super::load_networks(runtime_dir).expect("load networks");
        let record = stored
            .iter()
            .find(|record| record.name == name)
            .expect("created record");
        assert_eq!(record.bridge_name.len(), 15);
        assert!(record.bridge_name.starts_with("fc-"));
        handle_network(
            runtime_dir,
            &runtime,
            NetworkCommands::Rm {
                name: name.to_string(),
            },
            &authorization,
        )
        .expect("rm network");
        assert!(super::load_networks(runtime_dir)
            .expect("load networks")
            .iter()
            .all(|record| record.name != name));
    }

    #[test]
    fn network_create_remove_succeeds_in_disabled_mode() {
        let temp = configured_cli_runtime("disabled");
        super::reset_network_kernel_effect_count();
        create_and_remove_named_network(temp.path(), "disabled-net");
        assert!(super::network_kernel_effect_count() > 0);
    }

    #[test]
    fn network_create_remove_succeeds_in_shadow_mode() {
        let temp = configured_cli_runtime("shadow");
        super::reset_network_kernel_effect_count();
        create_and_remove_named_network(temp.path(), "shadow-net");
        assert!(super::network_kernel_effect_count() > 0);
    }

    #[test]
    fn network_create_enforce_denies_before_kernel_effects() {
        let temp = configured_cli_runtime("enforce");
        super::reset_network_kernel_effect_count();
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");
        let dropped_admin = nix::unistd::geteuid().as_raw() == 0
            && nix::unistd::seteuid(nix::unistd::Uid::from_raw(65534)).is_ok();
        let result = handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "enforce-net".to_string(),
                subnet: Some("172.31.0.0/16".to_string()),
                gateway: Some("172.31.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        );
        if dropped_admin {
            let _ = nix::unistd::seteuid(nix::unistd::Uid::from_raw(0));
        }
        let err = result.expect_err("enforce must deny create");
        assert!(
            err.contains("denied") || err.contains("authorization"),
            "stable denial shape, got {err}"
        );
        assert_eq!(
            super::network_kernel_effect_count(),
            0,
            "enforce denial must not call kernel: {err}"
        );
        assert!(super::load_networks(temp.path())
            .expect("load networks")
            .is_empty());
        assert!(!temp.path().join("network-operations.journal").exists());
    }

    /// Public create handler post-effect fault (not a private lifecycle-only test):
    /// crosses `handle_network`, fails during store publication after an observed
    /// kernel bridge, retains OutcomeUnknown + IdentityObserved, blocks replacement
    /// with zero new kernel effects, then recovery commits the original operation.
    #[test]
    fn network_create_post_effect_store_fault_is_outcome_unknown_and_blocks_replacement() {
        use ferro_core::witness::{
            decode_record, JournalConfig, JournalMode, WitnessJournal, WitnessOutcome, WitnessStage,
        };
        use std::os::unix::fs::PermissionsExt;

        let temp = configured_cli_runtime("shadow");
        let networks_dir = temp.path().join("networks");
        std::fs::create_dir_all(&networks_dir).expect("networks dir");
        // Deny store publication after IdentityObserved; journal + kernel stay writable.
        std::fs::set_permissions(&networks_dir, std::fs::Permissions::from_mode(0o555))
            .expect("lock networks dir");

        super::reset_network_kernel_effect_count();
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");

        let err = handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "fault-net".to_string(),
                subnet: Some("172.34.0.0/16".to_string()),
                gateway: Some("172.34.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        )
        .expect_err("store fault after kernel effect must not report success");
        assert!(
            err.contains("store publication")
                || err.contains("journal io")
                || err.contains("operation journal io")
                || err.contains("Permission")
                || err.contains("failed to write"),
            "post-effect store fault shape, got {err}"
        );
        assert!(
            super::network_kernel_effect_count() > 0,
            "kernel effect must occur before store fault"
        );
        assert!(
            super::load_networks(temp.path())
                .expect("load networks")
                .is_empty(),
            "store must remain empty after publication fault (not a success lie)"
        );

        let pending = crate::network_lifecycle::read_pending_operations(temp.path())
            .expect("read pending lifecycle");
        assert_eq!(pending.len(), 1, "retain one nonterminal lifecycle op");
        assert_eq!(pending[0].resource.name, "fault-net");
        assert_eq!(
            pending[0].phase,
            crate::network_lifecycle::NetworkLifecyclePhase::IdentityObserved,
            "must not terminal-lie as StoreCommitted"
        );
        let observed = pending[0]
            .observed
            .clone()
            .expect("IdentityObserved retains exact kernel identity");
        assert!(observed.ifindex.is_some_and(|idx| idx != 0));
        // Do not reset the in-process kernel adapter: recovery must observe the
        // same bridge the public create effect recorded.
        std::fs::set_permissions(&networks_dir, std::fs::Permissions::from_mode(0o755))
            .expect("unlock networks dir");
        let effects_before_replacement = super::network_kernel_effect_count();
        let replacement_err = handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "fault-net".to_string(),
                subnet: Some("172.34.0.0/16".to_string()),
                gateway: Some("172.34.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        )
        .expect_err("OutcomeUnknown/pending lifecycle must block replacement");
        assert!(!replacement_err.is_empty(), "replacement must fail closed");
        assert_eq!(
            super::network_kernel_effect_count(),
            effects_before_replacement,
            "replacement must not invoke kernel effects: {replacement_err}"
        );
        // The public handler performs recovery before dispatch. It must
        // reconcile the retained operation, then reject the replacement
        // against the recovered record without opening a second operation or
        // invoking another kernel effect.
        assert!(
            crate::network_lifecycle::read_pending_operations(temp.path())
                .expect("pending after replacement attempt")
                .is_empty(),
            "handler recovery must clear the retained lifecycle"
        );
        let stored = super::load_networks(temp.path()).expect("store after recovery");
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].name, "fault-net");
        assert_eq!(stored[0].bridge_name, observed.name);

        let reconciled = authorization
            .reconcile_pending(|pending| (*pending.recipe().observation_digest(), true))
            .expect("reconcile OutcomeUnknown surface op");
        assert_eq!(
            reconciled, 1,
            "exactly one OutcomeUnknown surface op recovered"
        );

        let effects_before_duplicate = super::network_kernel_effect_count();
        let after_recovery = handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "fault-net".to_string(),
                subnet: Some("172.34.0.0/16".to_string()),
                gateway: Some("172.34.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        )
        .expect_err("recovered original must occupy the name");
        assert!(
            after_recovery.contains("already exists"),
            "post-recovery must see original publication, got {after_recovery}"
        );
        assert_eq!(
            super::network_kernel_effect_count(),
            effects_before_duplicate,
            "post-recovery duplicate create must not re-effect the kernel"
        );

        drop(authorization);
        drop(runtime);

        let journal = WitnessJournal::open(JournalConfig::new(
            temp.path().join("authorization/witness-journal"),
            [0x44u8; 16],
            JournalMode::Required,
        ))
        .expect("reopen witness journal");
        assert!(
            journal.pending().expect("pending surface ops").is_empty(),
            "surface OutcomeUnknown must be reconciled after recovery"
        );
        let records = journal.records().expect("witness records");
        let outcomes: Vec<_> = records
            .iter()
            .filter_map(|bytes| decode_record(bytes).ok())
            .filter(|decoded| decoded.stage() == WitnessStage::Outcome)
            .map(|decoded| decoded.outcome())
            .collect();
        assert!(
            outcomes.contains(&WitnessOutcome::OutcomeUnknown),
            "post-effect fault must have witnessed OutcomeUnknown, got {outcomes:?}"
        );
    }

    #[test]
    fn network_bridge_identity_is_deterministic_15_chars_and_refuses_collision() {
        let first = super::canonical_bridge_name("alpha-network");
        let second = super::canonical_bridge_name("alpha-network");
        assert_eq!(first, second);
        assert_eq!(first.len(), 15);
        assert!(first.starts_with("fc-"));
        assert_ne!(first, super::canonical_bridge_name("beta-network"));

        let temp = configured_cli_runtime("disabled");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");
        let colliding = super::NetworkRecord {
            name: "other-logical".to_string(),
            driver: "bridge".to_string(),
            subnet: "172.32.0.0/16".to_string(),
            gateway: "172.32.0.1".to_string(),
            bridge_name: first.clone(),
            bridge_cidr: "172.32.0.1/16".to_string(),
            ipv6_cidr: None,
            created_at_unix: 1,
            generation: 1,
        };
        super::save_networks(temp.path(), &[colliding]).expect("seed colliding bridge name");
        assert_eq!(
            super::load_networks(temp.path())
                .expect("reload seed")
                .len(),
            1
        );
        super::reset_network_kernel_effect_count();
        let err = handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "alpha-network".to_string(),
                subnet: Some("172.30.0.0/16".to_string()),
                gateway: Some("172.30.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        )
        .expect_err("stored bridge-name collision must be refused");
        assert!(
            err.contains("collision") || err.contains("bridge"),
            "collision refusal, got {err}"
        );
        assert_eq!(super::network_kernel_effect_count(), 0);
    }

    #[test]
    fn network_remove_refuses_any_extant_container_association() {
        let temp = configured_cli_runtime("disabled");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");
        handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Create {
                name: "assoc-net".to_string(),
                subnet: Some("172.33.0.0/16".to_string()),
                gateway: Some("172.33.0.1".to_string()),
                ipv6_subnet: None,
                ipv6_gateway: None,
            },
            &authorization,
        )
        .expect("create network");
        drop(runtime);
        drop(authorization);

        let store = ferro_core::sqlite_container_store::SqliteContainerStore::open(
            temp.path().join("containers.db"),
        )
        .expect("container store");
        for (id, status) in [("stopped-assoc", "stopped"), ("exited-assoc", "exited")] {
            let mut record =
                serde_json::from_value::<ferro_core::container_store::ContainerRecord>(
                    serde_json::json!({
                        "id": id,
                        "pid": 0,
                        "image": "example.invalid/app:latest",
                        "command": ["true"],
                        "created_at_unix": 1,
                        "stdout_path": "",
                        "stderr_path": "",
                        "status": status,
                        "network_name": "assoc-net"
                    }),
                )
                .expect("container record");
            record.status = status.to_string();
            store.put(&record).expect("put associated container");
        }
        drop(store);

        let runtime = ContainerRuntime::new(temp.path()).expect("runtime reopen");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");
        super::reset_network_kernel_effect_count();
        let err = handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Rm {
                name: "assoc-net".to_string(),
            },
            &authorization,
        )
        .expect_err("must refuse extant container association");
        assert!(
            err.contains("in use") || err.contains("association"),
            "association refusal, got {err}"
        );
        assert_eq!(super::network_kernel_effect_count(), 0);
        assert!(super::load_networks(temp.path())
            .expect("load")
            .iter()
            .any(|record| record.name == "assoc-net"));
    }

    /// Public-path: store record without a StoreCommitted observed identity
    /// must fail closed. No synthesized BridgeIdentity, no unpublish, no
    /// kernel effect.
    #[test]
    fn network_remove_missing_committed_bridge_identity_fails_closed() {
        let temp = configured_cli_runtime("disabled");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime
            .surface_authorization()
            .expect("surface authorization");
        let orphaned = super::NetworkRecord {
            name: "orphan-net".to_string(),
            driver: "bridge".to_string(),
            subnet: "172.35.0.0/16".to_string(),
            gateway: "172.35.0.1".to_string(),
            bridge_name: super::canonical_bridge_name("orphan-net"),
            bridge_cidr: "172.35.0.1/16".to_string(),
            ipv6_cidr: None,
            created_at_unix: 1,
            generation: 1,
        };
        super::save_networks(temp.path(), &[orphaned]).expect("seed store without journal");
        assert!(
            crate::network_lifecycle::last_committed_bridge_identity(temp.path(), "orphan-net")
                .expect("read committed identity")
                .is_none(),
            "fixture must lack a committed observed BridgeIdentity"
        );

        super::reset_network_kernel_effect_count();
        let err = handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Rm {
                name: "orphan-net".to_string(),
            },
            &authorization,
        )
        .expect_err("missing committed identity must fail closed");
        assert!(
            err.contains("missing committed bridge identity")
                || err.contains("committed bridge identity"),
            "missing-identity refusal, got {err}"
        );
        assert_eq!(
            super::network_kernel_effect_count(),
            0,
            "must not call kernel when committed identity is missing: {err}"
        );
        assert!(
            super::load_networks(temp.path())
                .expect("load")
                .iter()
                .any(|record| record.name == "orphan-net"),
            "store record must remain published"
        );
        assert!(
            !temp.path().join("network-operations.journal").exists(),
            "must not open a delete lifecycle without exact identity authority"
        );
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
    fn build_handler_defaults_to_dockerfile_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime.surface_authorization().expect("authorization");
        let origin = ferro_core::authorization::RequestOrigin::cli_current().expect("origin");
        let err = handle_build(
            &store,
            &origin,
            &authorization,
            None,
            None,
            None,
            "gzip",
            "oci",
            None,
            None,
            None,
            None,
            &[],
        )
        .expect_err("dockerfile should be read");
        assert!(
            err.contains("Dockerfile"),
            "expected default dockerfile path in error, got: {err}"
        );
    }

    #[test]
    fn build_handler_rejects_invalid_tag() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let authorization = runtime.surface_authorization().expect("authorization");
        let origin = ferro_core::authorization::RequestOrigin::cli_current().expect("origin");
        let err = handle_build(
            &store,
            &origin,
            &authorization,
            Some("./Dockerfile"),
            None,
            Some(""),
            "gzip",
            "oci",
            None,
            None,
            None,
            None,
            &[],
        )
        .expect_err("invalid tag");
        assert!(err.contains("invalid image reference"));
    }

    #[test]
    fn build_platform_validation_is_explicit_and_host_bound() {
        validate_build_platform(None).expect("omitted platform uses host default");
        validate_build_platform(Some(&format!("linux/{}", host_build_arch())))
            .expect("host platform is supported");
        let error = validate_build_platform(Some("windows/amd64")).expect_err("OS mismatch");
        assert!(error.contains("only linux/"));
        let error = validate_build_platform(Some("linux/other")).expect_err("unknown arch");
        assert!(error.contains("unsupported architecture"));
    }

    #[test]
    fn images_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(temp.path()).expect("store");
        handle_images(&store, "text").expect("images handler should succeed");
    }

    #[test]
    fn docker_event_store_is_durable_and_filterable() {
        let temp = tempfile::tempdir().expect("event runtime");
        let mut store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        store.append("POST", "/containers/c1/start", 204).unwrap();
        store.append("POST", "/networks/n1", 404).unwrap();
        let reopened = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        assert_eq!(reopened.next_id, 2);
        let mut filter = HashMap::new();
        filter.insert("container".to_string(), "c1".to_string());
        let events = reopened.query(&filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "start");
        assert_eq!(events[0].status, 204);

        let mut docker_filters = HashMap::new();
        docker_filters.insert(
            "filters".to_string(),
            r#"{"event":["start"],"type":["container"],"container":["c1"]}"#.to_string(),
        );
        assert_eq!(reopened.query(&docker_filters).unwrap().len(), 1);

        docker_filters.insert(
            "filters".to_string(),
            r#"{"event":["create"],"type":["volume"]}"#.to_string(),
        );
        assert_eq!(reopened.query(&docker_filters).unwrap().len(), 0);

        docker_filters.insert(
            "filters".to_string(),
            r#"{"type":["network"],"network":["n1"]}"#.to_string(),
        );
        assert_eq!(reopened.query(&docker_filters).unwrap().len(), 1);

        docker_filters.insert(
            "filters".to_string(),
            r#"{"scope":["local"],"type":["container"]}"#.to_string(),
        );
        assert_eq!(reopened.query(&docker_filters).unwrap().len(), 1);
        let mut scope_query = HashMap::new();
        scope_query.insert("scope".to_string(), "swarm".to_string());
        assert!(reopened.query(&scope_query).unwrap().is_empty());
    }

    #[test]
    fn docker_event_payload_uses_engine_wire_shape() {
        let event = DockerEvent {
            id: 4,
            time: 12,
            time_nano: 12_345_678_901,
            event_type: "container".to_string(),
            action: "start".to_string(),
            scope: "local".to_string(),
            resource: Some("abc123".to_string()),
            status: 204,
        };
        let payload = docker_event_payload(&event);
        assert_eq!(payload["Type"], "container");
        assert_eq!(payload["Action"], "start");
        assert_eq!(payload["Actor"]["ID"], "abc123");
        assert_eq!(payload["Actor"]["Attributes"]["status"], "start");
        assert_eq!(payload["Actor"]["Attributes"]["httpStatus"], "204");
        assert_eq!(payload["time"], 12);
        assert_eq!(payload["timeNano"], 12_345_678_901u64);
    }

    #[test]
    fn docker_logs_tail_matches_engine_query_semantics() {
        assert_eq!(
            docker_tail_logs("one\ntwo\nthree\n", Some("2")).unwrap(),
            "two\nthree\n"
        );
        assert_eq!(docker_tail_logs("one\ntwo\n", Some("0")).unwrap(), "");
        assert_eq!(docker_tail_logs("one\n", Some("all")).unwrap(), "one\n");
        assert!(docker_tail_logs("one\n", Some("nope")).is_err());
    }

    #[test]
    fn docker_container_filters_match_status_name_label_and_ancestor() {
        let mut record: ferro_core::container_store::ContainerRecord =
            serde_json::from_value(serde_json::json!({
                "id": "abc",
                "pid": 0,
                "image": "alpine:3.20",
                "command": [],
                "created_at_unix": 0,
                "stdout_path": "",
                "stderr_path": "",
                "status": "running"
            }))
            .expect("record");
        record.name = Some("web".to_string());
        record.status = "running".to_string();
        record.labels.insert("tier".into(), "frontend".into());
        let filters = serde_json::from_value(serde_json::json!({
            "status": ["running"],
            "name": ["web"],
            "label": ["tier=frontend"],
            "ancestor": ["alpine"]
        }))
        .expect("filters");
        assert!(docker_container_matches_filters(&record, &filters));
        record.status = "exited".to_string();
        assert!(!docker_container_matches_filters(&record, &filters));
    }

    #[test]
    fn docker_container_time_bounds_resolve_ids_names_and_timestamps() {
        let make = |id: &str, name: &str, created_at_unix| {
            let mut record: ferro_core::container_store::ContainerRecord =
                serde_json::from_value(serde_json::json!({
                    "id": id,
                    "pid": 0,
                    "image": "alpine:3.20",
                    "command": [],
                    "created_at_unix": created_at_unix,
                    "stdout_path": "",
                    "stderr_path": "",
                    "status": "running"
                }))
                .expect("record");
            record.name = Some(name.to_string());
            record
        };
        let records = vec![
            make("a", "first", 10),
            make("b", "second", 20),
            make("c", "third", 30),
        ];

        let bounded =
            docker_container_apply_time_bounds(records.clone(), Some("first"), Some("c")).unwrap();
        assert_eq!(
            bounded.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["b"]
        );

        let timestamp_bounded =
            docker_container_apply_time_bounds(records, Some("20"), None).unwrap();
        assert_eq!(
            timestamp_bounded
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["c"]
        );
    }

    #[test]
    fn docker_container_time_bounds_reject_unknown_or_ambiguous_selectors() {
        let record: ferro_core::container_store::ContainerRecord =
            serde_json::from_value(serde_json::json!({
                "id": "a",
                "pid": 0,
                "image": "alpine:3.20",
                "command": [],
                "created_at_unix": 10,
                "stdout_path": "",
                "stderr_path": "",
                "status": "running"
            }))
            .expect("record");
        assert!(
            docker_container_apply_time_bounds(vec![record.clone()], Some("missing"), None)
                .is_err()
        );
        assert!(docker_container_apply_time_bounds(vec![record], None, Some("missing")).is_err());
    }

    #[test]
    fn docker_top_rejects_unknown_container_without_procfs_access() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = ContainerRuntime::new(temp.path()).unwrap();
        let error = docker_top_payload(&runtime, "missing").expect_err("unknown container");
        assert!(error.contains("not found") || error.contains("unknown"));
    }

    #[test]
    fn docker_filters_reject_malformed_json() {
        let mut query = HashMap::new();
        query.insert("filters".to_string(), "[]".to_string());
        assert!(parse_docker_filters(&query).is_err());
    }

    #[test]
    fn docker_query_decodes_encoded_filters_and_plus_spaces() {
        let (path, query) = split_path_query(
            "/containers/json?filters=%7B%22label%22%3A%5B%22tier%3Dfront+end%22%5D%7D&name=web%2Done",
        )
        .expect("encoded query");
        assert_eq!(path, "/containers/json");
        assert_eq!(query.get("name").map(String::as_str), Some("web-one"));
        assert_eq!(
            query.get("filters").map(String::as_str),
            Some(r#"{"label":["tier=front end"]}"#)
        );
        assert!(split_path_query("/containers/json?filters=%zz").is_err());
        assert!(split_path_query("/containers/json?filters=%C3").is_err());
    }

    #[test]
    fn docker_list_query_scalars_fail_closed() {
        assert!(parse_docker_bool_query(Some(&"maybe".to_string()), "all").is_err());
        assert!(parse_docker_limit_query(Some(&"ten".to_string())).is_err());
        assert_eq!(parse_docker_bool_query(None, "all").unwrap(), false);
        assert_eq!(
            parse_docker_limit_query(Some(&"-1".to_string())).unwrap(),
            None
        );
        assert_eq!(
            parse_docker_limit_query(Some(&"2".to_string())).unwrap(),
            Some(2)
        );
    }

    #[test]
    fn docker_event_query_rejects_malformed_filters() {
        let temp = tempfile::tempdir().expect("event runtime");
        let store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        let mut query = HashMap::new();
        query.insert("filters".to_string(), r#"{"event":"start"}"#.to_string());
        let error = store
            .query(&query)
            .expect_err("malformed event filters must fail");
        assert!(error.contains("must be an array"), "error={error}");
    }

    #[test]
    fn docker_event_query_rejects_corrupt_journal_records() {
        let temp = tempfile::tempdir().expect("event runtime");
        std::fs::write(temp.path().join("events.jsonl"), b"not-json\n").expect("corrupt journal");
        let store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        let error = store
            .query(&HashMap::new())
            .expect_err("corrupt event records must fail closed");
        assert!(error.contains("malformed record"), "error={error}");
    }

    #[test]
    fn docker_event_query_rejects_invalid_time_bounds() {
        let temp = tempfile::tempdir().expect("event runtime");
        let store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        let mut query = HashMap::new();
        query.insert("since".to_string(), "not-a-timestamp".to_string());
        let error = store
            .query(&query)
            .expect_err("invalid since must fail closed");
        assert!(error.contains("since"), "error={error}");
    }

    #[test]
    fn docker_event_follow_uses_chunked_keep_alive_headers() {
        let headers = String::from_utf8(docker_chunked_headers(200, "application/x-ndjson"))
            .expect("headers are utf8");
        assert!(headers.contains("Transfer-Encoding: chunked"));
        assert!(headers.contains("Connection: keep-alive"));
        assert!(headers.ends_with("\r\n\r\n"));
    }

    #[test]
    fn context_lifecycle_persists_selected_endpoint() {
        let _guard = ENV_MUTEX.lock().expect("env lock");
        let previous = std::env::var_os("FERROCRATE_RUNTIME_DIR");
        let temp = tempfile::tempdir().expect("context config");
        unsafe {
            std::env::set_var("FERROCRATE_RUNTIME_DIR", temp.path());
        }

        handle_context(ContextCommands::Create {
            name: "rootless".to_string(),
            endpoint: "unix:///run/user/1000/ferrocrate.sock".to_string(),
        })
        .expect("create context");
        handle_context(ContextCommands::Use {
            name: "rootless".to_string(),
        })
        .expect("select context");
        let config = super::load_cli_config().expect("load config");
        assert_eq!(config.current_context.as_deref(), Some("rootless"));
        assert_eq!(
            config.contexts["rootless"].endpoint,
            "unix:///run/user/1000/ferrocrate.sock"
        );
        assert!(handle_context(ContextCommands::Create {
            name: "bad/name".to_string(),
            endpoint: "unix:///tmp/socket".to_string(),
        })
        .is_err());
        handle_context(ContextCommands::Rm {
            name: "rootless".to_string(),
        })
        .expect("remove context");

        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_RUNTIME_DIR") },
        }
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
        let authorization = test_surface_authorization(temp.path());
        let err = handle_pull(&store, "", false, &authorization).expect_err("invalid image");
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
        let _guard = ENV_MUTEX.lock().unwrap();
        unsafe {
            std::env::remove_var("FERROCRATE_DESKTOP_FORWARD");
        }
        assert!(!desktop_forward_enabled());
    }

    #[test]
    fn desktop_forward_env_enables_true_values() {
        let _guard = ENV_MUTEX.lock().unwrap();
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

#[cfg(all(test, not(target_os = "linux")))]
mod tests_non_linux {
    use super::{desktop_forward_enabled, should_desktop_forward, structured_desktop_error};

    #[test]
    fn desktop_forward_env_toggle() {
        unsafe {
            std::env::remove_var("FERROCRATE_DESKTOP_FORWARD");
        }
        #[cfg(target_os = "macos")]
        assert!(desktop_forward_enabled());
        #[cfg(not(target_os = "macos"))]
        assert!(!desktop_forward_enabled());

        unsafe {
            std::env::set_var("FERROCRATE_DESKTOP_FORWARD", "1");
        }
        assert!(desktop_forward_enabled());
        unsafe {
            std::env::remove_var("FERROCRATE_DESKTOP_FORWARD");
        }
    }

    #[test]
    fn desktop_forward_runtime_command_detection() {
        assert!(should_desktop_forward(&[
            "run".to_string(),
            "alpine:latest".to_string()
        ]));
        assert!(!should_desktop_forward(&["images".to_string()]));
    }

    #[test]
    fn structured_desktop_error_text_and_json_modes() {
        unsafe {
            std::env::remove_var("FERROCRATE_ERROR_FORMAT");
            std::env::remove_var("FERROCRATE_ERROR_JSON");
        }
        let text =
            structured_desktop_error("desktop_bridge_unavailable", "bridge failed", "retry", true);
        assert!(text.contains("category=desktop_bridge_unavailable"));

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
