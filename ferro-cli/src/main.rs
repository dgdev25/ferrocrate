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
use ferro_core::image_manifest::{
    parse_image_manifest, Descriptor, ImageManifest, OCI_IMAGE_CONFIG_MEDIA_TYPE,
    OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE,
};
use ferro_core::image_store::LocalImageStore;
use ferro_core::image_tagging::{
    canonicalize_reference, execute_image_tag_authorized, prepare_image_tag, resolve_reference,
};
use ferro_core::layer_compression::CompressionFormat;
use ferro_core::registry::{parse_image_reference, RegistryClient};
#[cfg(target_os = "linux")]
use ferro_core::rootfs::construct_rootfs_with_dedup;
#[cfg(target_os = "linux")]
use ferro_core::rootfs_diff;
#[cfg(target_os = "linux")]
use ferro_core::runtime::ContainerRuntime;
use ferro_core::runtime::NetworkBackend;
#[cfg(target_os = "linux")]
use ferro_core::volume_store::LocalVolumeStore;
#[cfg(target_os = "linux")]
use ferro_core::witness::{decode_record, WitnessReader};
use ferro_mind::ai::agents::{orchestrate_task, OrchestrateRequest};
use ferro_mind::ai::audit::AuditLogger;
use ferro_mind::ai::explain::DecisionTrace;
use ferro_mind::ai::training::{
    handle_community_download_command, handle_community_list_command,
    handle_community_publish_command, handle_export_command, handle_import_command,
    handle_stats_command, handle_train_command, ModelType, TrainingConfig, TrainingPipeline,
};
#[cfg(target_os = "linux")]
use ferro_mind::ai::training::{
    handle_export_rvf_command, handle_rvf_branch_command, handle_rvf_lineage_command,
    handle_rvf_stats_command, handle_rvf_verify_command,
};
#[cfg(target_os = "linux")]
use flate2::{write::GzEncoder, Compression};
#[cfg(target_os = "linux")]
use nix::sys::signal::Signal;
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::collections::{BTreeMap, HashMap};
#[cfg(target_os = "linux")]
use std::io::Cursor;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use std::net::TcpListener;
#[cfg(target_os = "macos")]
use std::net::TcpStream;
#[cfg(all(unix, target_os = "linux"))]
use std::os::unix::net::UnixListener;
#[cfg(all(unix, target_os = "linux"))]
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
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
        /// Provide a Dockerfile secret (`id=NAME,src=PATH`); repeatable.
        #[arg(long = "secret")]
        secret: Vec<String>,
    },
    /// Inspect or extract an opt-in native RVF image.
    Rvf {
        #[command(subcommand)]
        command: RvfCommands,
    },
    Images {
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
    /// Report Docker-compatible image, container, and volume usage summary.
    SystemDf {
        #[arg(long, default_value = "json", value_parser = validate_output_format)]
        format: String,
    },
    ImageInspect {
        image: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Tag {
        source: String,
        target: String,
    },
    /// Snapshot a container rootfs into a new OCI image reference.
    #[cfg(target_os = "linux")]
    Commit {
        container: String,
        repository: String,
    },
    History {
        image: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Rmi {
        image: String,
    },
    ImagePrune {
        /// Docker image-prune selector (`dangling=true|false` or `until=UNIX_SECONDS`).
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
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
        #[arg(long)]
        all: bool,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        before: Option<String>,
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
    /// Remove stopped containers that match Docker prune filters.
    #[cfg(target_os = "linux")]
    ContainerPrune {
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
    /// Read the durable Docker-compatible event stream.
    #[cfg(target_os = "linux")]
    Events {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long = "filter")]
        filters: Vec<String>,
        #[arg(long)]
        follow: bool,
    },
    #[cfg(target_os = "linux")]
    Logs {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
        #[arg(long)]
        follow: bool,
    },
    #[cfg(target_os = "linux")]
    Stats {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
        #[arg(long)]
        follow: bool,
    },
    #[cfg(target_os = "linux")]
    Top {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    #[cfg(target_os = "linux")]
    Wait {
        container: String,
        #[arg(long, default_value = "not-running")]
        condition: String,
        #[arg(long)]
        timeout: Option<u64>,
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
        #[arg(long, default_value = "SIGKILL")]
        signal: String,
    },
    #[cfg(target_os = "linux")]
    Rm {
        container: String,
    },
    #[cfg(target_os = "linux")]
    Rename {
        container: String,
        name: String,
    },
    #[cfg(target_os = "linux")]
    Start {
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

#[derive(Debug, Subcommand)]
pub enum RvfCommands {
    /// Validate an RVF image and print its manifest and segment inventory.
    Inspect {
        image: PathBuf,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    /// Validate an RVF image and atomically export its OCI layer blob.
    Extract { image: PathBuf, output: PathBuf },
    /// Import a validated RVF image into the normal local OCI image store.
    Import {
        image: PathBuf,
        #[arg(long)]
        reference: Option<String>,
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
    /// Compute a Merkle root from newline-delimited 32-byte record hashes.
    MerkleRoot {
        #[arg(long)]
        leaves: PathBuf,
    },
    /// Verify a serialized inclusion or consistency proof without opening a journal.
    MerkleVerify {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long, default_value = "inclusion", value_parser = validate_merkle_proof_kind)]
        kind: String,
    },
    /// Export a bounded, canonical witness snapshot for independent retention.
    Export {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        journal_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 100_000)]
        max_records: usize,
    },
    /// Verify an exported witness snapshot without opening the live journal.
    VerifyExport {
        #[arg(long)]
        snapshot: PathBuf,
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
        /// Keep services running after the command returns (Docker-compatible;
        /// Ferrocrate Compose is detached by design today).
        #[arg(short = 'd', long, default_value_t = true)]
        detach: bool,
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
    Ls {
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
    Prune {
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
    Inspect {
        name: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
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
    Ls {
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
    Prune {
        #[arg(long = "filter")]
        filters: Vec<String>,
    },
    Inspect {
        name: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
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
    /// Attach an Ed25519 provenance signature to a persisted model version.
    /// The key file must contain exactly 32 raw private-key bytes or 64 hex
    /// characters; it is never printed or included in output.
    Sign {
        #[arg(long = "model-type")]
        model_type: String,
        #[arg(long)]
        version: u32,
        #[arg(long = "signer-key-id")]
        signer_key_id: String,
        #[arg(long = "key")]
        key: PathBuf,
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

#[derive(Debug, Clone, Subcommand)]
pub enum ConfigCommands {
    Set { key: String, value: String },
    Get { key: String },
}

#[derive(Debug, Clone, Subcommand)]
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
            | "history"
            | "image-inspect"
            | "tag"
            | "logs"
            | "inspect"
            | "stats"
            | "pause"
            | "unpause"
            | "stop"
            | "kill"
            | "rm"
            | "rename"
            | "start"
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
            let user_namespace_ok = ferro_core::rootless::user_namespace_available();
            let runtime_socket = discover_rootless_socket();
            let socket_message = runtime_socket.as_ref().map_or_else(
                || "rootless Docker socket not discovered (set XDG_RUNTIME_DIR or use the configured daemon socket)".to_string(),
                |path| format!("rootless Docker socket discovered at {}", path.display()),
            );
            checks.push(DoctorCheck {
                id: "rootless_context".to_string(),
                ok: rootless.is_ok() && user_namespace_ok,
                message: match rootless {
                    Ok(config) => format!(
                        "rootless context {} for {} (uid map {}:{} size {}; gid map {}:{} size {}); {}",
                        if user_namespace_ok {
                            "available"
                        } else {
                            "configured but user-namespace creation is unavailable"
                        },
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
    if let Some(explicit) = std::env::var_os("FERROCRATE_ROOTLESS_SOCKET") {
        candidates.push(PathBuf::from(explicit));
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime = PathBuf::from(runtime);
        candidates.push(runtime.join("ferrocrate.sock"));
        candidates.push(runtime.join("docker.sock"));
    }
    let runtime = runtime_dir();
    candidates.push(runtime.join("ferrocrate.sock"));
    candidates.push(runtime.join("docker.sock"));
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
fn validate_merkle_proof_kind(value: &str) -> Result<String, String> {
    match value {
        "inclusion" | "consistency" | "frontier-consistency" => Ok(value.to_string()),
        _ => Err("proof kind must be inclusion, consistency, or frontier-consistency".to_string()),
    }
}

#[cfg(target_os = "linux")]
fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value must have an even number of characters".to_string());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars = value.as_bytes();
    for pair in chars.chunks_exact(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hexadecimal character: 0x{value:02x}")),
    }
}

#[cfg(target_os = "linux")]
fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(target_os = "linux")]
fn read_merkle_leaves(path: &Path) -> Result<Vec<[u8; 32]>, String> {
    let content = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "witness merkle root: cannot read {}: {error}",
            path.display()
        )
    })?;
    let mut leaves = Vec::new();
    for (line_number, line) in content.lines().enumerate() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        let value = value.strip_prefix("sha256:").unwrap_or(value);
        let bytes = decode_hex_bytes(value).map_err(|error| {
            format!(
                "witness merkle root: line {} is not hexadecimal: {error}",
                line_number + 1
            )
        })?;
        if bytes.len() != 32 {
            return Err(format!(
                "witness merkle root: line {} must contain exactly 32 bytes",
                line_number + 1
            ));
        }
        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(&bytes);
        leaves.push(leaf);
    }
    if leaves.is_empty() {
        return Err("witness merkle root: leaf file contains no hashes".to_string());
    }
    Ok(leaves)
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
        WitnessCommands::MerkleRoot { leaves } => {
            let leaves = read_merkle_leaves(leaves)?;
            let root = ferro_core::witness::merkle_root(&leaves)
                .map_err(|error| format!("witness merkle root: {error}"))?;
            Ok(format!("sha256:{}", encode_hex(&root)))
        }
        WitnessCommands::MerkleVerify { proof, kind } => {
            let bytes = std::fs::read(proof).map_err(|error| {
                format!(
                    "witness merkle verify: cannot read {}: {error}",
                    proof.display()
                )
            })?;
            match kind.as_str() {
                "inclusion" => {
                    let parsed: ferro_core::witness::MerkleProof = serde_json::from_slice(&bytes)
                        .map_err(|error| {
                        format!("witness merkle verify: invalid inclusion proof: {error}")
                    })?;
                    ferro_core::witness::merkle_verify(&parsed)
                        .map_err(|error| format!("witness merkle verify: {error}"))?;
                }
                "consistency" => {
                    let parsed: ferro_core::witness::MerkleConsistencyProof =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            format!("witness merkle verify: invalid consistency proof: {error}")
                        })?;
                    ferro_core::witness::merkle_verify_consistency(&parsed)
                        .map_err(|error| format!("witness merkle verify: {error}"))?;
                }
                "frontier-consistency" => {
                    let parsed: ferro_core::witness::MerkleFrontierConsistencyProof =
                        serde_json::from_slice(&bytes).map_err(|error| {
                            format!("witness merkle verify: invalid frontier proof: {error}")
                        })?;
                    ferro_core::witness::merkle_verify_frontier_consistency(&parsed)
                        .map_err(|error| format!("witness merkle verify: {error}"))?;
                }
                _ => unreachable!("clap validates Merkle proof kind"),
            }
            Ok(format!("witness merkle verification=passed kind={kind}"))
        }
        WitnessCommands::Export {
            journal,
            journal_id,
            output,
            max_records,
        } => export_witness_snapshot(journal, journal_id, output, *max_records),
        WitnessCommands::VerifyExport { snapshot } => verify_witness_snapshot(snapshot),
    }?;
    println!("{output}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn export_witness_snapshot(
    journal: &Path,
    journal_id: &str,
    output: &Path,
    max_records: usize,
) -> Result<String, String> {
    if max_records == 0 || max_records > 1_000_000 {
        return Err("witness export max-records must be between 1 and 1000000".into());
    }
    let id = decode_witness_hex::<16>(journal_id)?;
    let mut reader =
        WitnessReader::open_read_only(journal, id).map_err(|error| error.to_string())?;
    let mut records = Vec::new();
    while let Some(bytes) = reader.next_record().map_err(|error| error.to_string())? {
        if records.len() >= max_records {
            return Err(format!(
                "witness export exceeds max-records ({max_records})"
            ));
        }
        let record = decode_record(&bytes).map_err(|error| error.to_string())?;
        records.push(serde_json::json!({
            "epoch": record.epoch(),
            "sequence": record.sequence(),
            "record_hash": encode_hex(&record.record_hash()),
            "canonical_record_hex": encode_hex(&bytes),
        }));
    }
    reader.finish().map_err(|error| error.to_string())?;
    let document = serde_json::json!({
        "schema": 1,
        "journal_id": journal_id,
        "record_count": records.len(),
        "records": records,
    });
    let bytes = serde_json::to_vec_pretty(&document).map_err(|error| error.to_string())?;
    ferro_core::fs_atomic::write_atomic(output, &bytes).map_err(|error| error.to_string())?;
    Ok(format!(
        "witness export: wrote {} records to {}",
        document["record_count"],
        output.display()
    ))
}

#[cfg(target_os = "linux")]
fn decode_witness_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!(
            "witness export journal-id must contain {} hex bytes",
            N
        ));
    }
    let mut out = [0_u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "witness export journal-id is not hexadecimal".to_string())?;
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessSnapshot {
    schema: u8,
    journal_id: String,
    record_count: usize,
    records: Vec<WitnessSnapshotRecord>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessSnapshotRecord {
    epoch: u64,
    sequence: u64,
    record_hash: String,
    canonical_record_hex: String,
}

#[cfg(target_os = "linux")]
fn verify_witness_snapshot(snapshot: &Path) -> Result<String, String> {
    let bytes = std::fs::read(snapshot).map_err(|error| format!("witness snapshot: {error}"))?;
    let document: WitnessSnapshot = serde_json::from_slice(&bytes)
        .map_err(|error| format!("witness snapshot is invalid JSON: {error}"))?;
    if document.schema != 1 {
        return Err("witness snapshot schema must be 1".into());
    }
    let _journal_id = decode_witness_hex::<16>(&document.journal_id)?;
    if document.record_count != document.records.len() {
        return Err("witness snapshot record_count does not match records".into());
    }
    let mut previous = None;
    for record in &document.records {
        if previous.is_some_and(|sequence| record.sequence <= sequence) {
            return Err("witness snapshot sequences are not strictly increasing".into());
        }
        let canonical = decode_witness_hex_vec(&record.canonical_record_hex)?;
        let decoded = decode_record(&canonical).map_err(|error| error.to_string())?;
        if decoded.epoch() != record.epoch || decoded.sequence() != record.sequence {
            return Err("witness snapshot record identity does not match canonical bytes".into());
        }
        let expected = encode_hex(&decoded.record_hash());
        if expected != record.record_hash {
            return Err(format!(
                "witness snapshot record hash mismatch at sequence {}",
                record.sequence
            ));
        }
        previous = Some(record.sequence);
    }
    Ok(format!(
        "witness snapshot verification=passed records={}",
        document.records.len()
    ))
}

#[cfg(target_os = "linux")]
fn decode_witness_hex_vec(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("witness snapshot canonical bytes must be hexadecimal".into());
    }
    (0..value.len() / 2)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| "witness snapshot canonical bytes are not hexadecimal".to_string())
        })
        .collect()
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
    if let Commands::Rvf { ref command } = command {
        return dispatch_rvf(command);
    }

    #[cfg(target_os = "linux")]
    {
        let runtime_dir = runtime_dir();

        // Context administration must not require opening the local runtime,
        // and selecting a remote endpoint must never be silently ignored by
        // commands that still execute against local state.
        if let Commands::Context { command: context } = &command {
            return handle_context(context.clone());
        }
        if let Commands::Config { command: config } = &command {
            return handle_config(config.clone());
        }
        if let Commands::Doctor {
            fix,
            bootstrap,
            dry_run,
            confirm,
            json,
        } = &command
        {
            return handle_doctor(*fix, *bootstrap, *dry_run, *confirm, *json);
        }

        match &command {
            Commands::Policy {
                command: command @ PolicyCommands::Check { .. },
            } => return dispatch_policy(command, &runtime_dir),
            Commands::Witness {
                command:
                    command @ (WitnessCommands::Show { .. }
                    | WitnessCommands::Verify { .. }
                    | WitnessCommands::MerkleRoot { .. }
                    | WitnessCommands::MerkleVerify { .. }
                    | WitnessCommands::Export { .. }),
            } => return dispatch_witness(command, &runtime_dir),
            Commands::Emergency { command } => return dispatch_emergency(command, &runtime_dir),
            _ => {}
        }
        if let Some(result) = dispatch_remote_context(&command) {
            return result;
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

        ensure_context_routing_available()?;

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
                // `run` is a detached CLI operation: the workload must remain
                // manageable after this short-lived process exits.
                unsafe { std::env::set_var("FERROCRATE_DETACH_WORKLOAD", "1") };
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
                secret,
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
                &secret,
            ),
            Commands::Images { format, filters } => handle_images(&image_store, &format, &filters),
            Commands::SystemDf { format } => {
                let volume_store = LocalVolumeStore::open(runtime_dir.join("volumes"))
                    .map_err(|error| error.to_string())?;
                let containers = runtime.list().map_err(|error| error.to_string())?;
                let images = image_store
                    .list_references()
                    .map_err(|error| error.to_string())?;
                let volumes = volume_store.list().map_err(|error| error.to_string())?;
                let body = serde_json::json!({
                    "LayersSize": images.iter().map(|image| docker_manifest_layer_size(&image.manifest_json)).fold(0u64, u64::saturating_add),
                    "Images": images.iter().map(|image| serde_json::json!({"Id": image.digest, "RepoTags": [image.reference], "Created": image.created_at_unix, "Size": docker_manifest_layer_size(&image.manifest_json), "SharedSize": 0, "Containers": containers.iter().filter(|container| container.image == image.reference).count()})).collect::<Vec<_>>(),
                    "Containers": containers.iter().map(|container| serde_json::json!({"Id": container.id, "Names": container.name.as_ref().map(|name| vec![format!("/{name}")]).unwrap_or_default(), "Image": container.image, "ImageID": "", "SizeRw": 0, "SizeRootFs": 0})).collect::<Vec<_>>(),
                    "Volumes": volumes.iter().map(|volume| serde_json::json!({"Name": volume.name, "Mountpoint": volume.path, "UsageData": {"Size": docker_directory_usage(Path::new(&volume.path)), "RefCount": 0}})).collect::<Vec<_>>(),
                    "BuildCache": [],
                });
                if format == "json" {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&body).unwrap_or_else(|_| body.to_string())
                    );
                } else {
                    println!("{}", body);
                }
                Ok(())
            }
            Commands::History { image, format } => handle_history(&image_store, &image, &format),
            Commands::ImageInspect { image, format } => {
                handle_image_inspect(&image_store, &image, &format)
            }
            Commands::Tag { source, target } => {
                handle_tag(&image_store, &source, &target, &surface_authorization)
            }
            #[cfg(target_os = "linux")]
            Commands::Commit {
                container,
                repository,
            } => handle_commit(
                &runtime_dir,
                &runtime,
                &image_store,
                &surface_authorization,
                &container,
                &repository,
            ),
            Commands::Rmi { image } => handle_rmi(&image_store, &image, &surface_authorization),
            Commands::ImagePrune { filters } => {
                handle_image_prune(&image_store, &surface_authorization, &filters)
            }
            Commands::Volume { command } => {
                handle_volume(&runtime_dir, command, &surface_authorization)
            }
            #[cfg(target_os = "linux")]
            Commands::Network { command } => {
                handle_network(&runtime_dir, &runtime, command, &surface_authorization)
            }
            #[cfg(target_os = "linux")]
            Commands::Containers {
                format,
                all,
                limit,
                since,
                before,
                filters,
            } => handle_containers(
                &runtime,
                &format,
                all,
                limit,
                since.as_deref(),
                before.as_deref(),
                &filters,
            ),
            #[cfg(target_os = "linux")]
            Commands::ContainerPrune { filters } => handle_container_prune(&runtime, &filters),
            #[cfg(target_os = "linux")]
            Commands::Events {
                since,
                until,
                filters,
                follow,
            } => handle_events(
                &runtime_dir,
                since.as_deref(),
                until.as_deref(),
                &filters,
                follow,
            ),
            #[cfg(target_os = "linux")]
            Commands::Logs {
                container,
                format,
                follow,
            } => handle_logs(&runtime, &container, &format, follow),
            #[cfg(target_os = "linux")]
            Commands::Inspect { container, format } => {
                handle_inspect(&runtime, &container, &format)
            }
            #[cfg(target_os = "linux")]
            Commands::Stats {
                container,
                format,
                follow,
            } => handle_stats(&runtime, &container, &format, follow),
            #[cfg(target_os = "linux")]
            Commands::Top { container, format } => handle_top(&runtime, &container, &format),
            #[cfg(target_os = "linux")]
            Commands::Wait {
                container,
                condition,
                timeout,
                format,
            } => handle_wait(&runtime, &container, &condition, timeout, &format),
            #[cfg(target_os = "linux")]
            Commands::Pause { container } => handle_pause(&runtime, &container),
            #[cfg(target_os = "linux")]
            Commands::Unpause { container } => handle_unpause(&runtime, &container),
            #[cfg(target_os = "linux")]
            Commands::Stop { container, timeout } => handle_stop(&runtime, &container, timeout),
            #[cfg(target_os = "linux")]
            Commands::Kill { container, signal } => handle_kill(&runtime, &container, &signal),
            #[cfg(target_os = "linux")]
            Commands::Rm { container } => handle_rm(&runtime, &container),
            #[cfg(target_os = "linux")]
            Commands::Rename { container, name } => handle_rename(&runtime, &container, &name),
            #[cfg(target_os = "linux")]
            Commands::Start { container } => {
                unsafe { std::env::set_var("FERROCRATE_DETACH_WORKLOAD", "1") };
                handle_start(&runtime, &container)
            }
            #[cfg(target_os = "linux")]
            Commands::Restart { container, timeout } => {
                unsafe { std::env::set_var("FERROCRATE_DETACH_WORKLOAD", "1") };
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
            Commands::Rvf { .. } => {
                unreachable!("RVF commands are dispatched before runtime setup")
            }
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
            Commands::Images { format, filters } => handle_images(&image_store, &format, &filters),
            Commands::Rmi { image } => handle_rmi(&image_store, &image),
            Commands::ImagePrune { filters } => handle_image_prune(&image_store, &filters),
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

fn dispatch_rvf(command: &RvfCommands) -> Result<(), String> {
    match command {
        RvfCommands::Inspect { image, format } => {
            let parsed = ferro_core::rvf_image::read_rvf_image(image)
                .map_err(|error| format!("rvf inspect: {error}"))?;
            let segments = parsed
                .segments
                .iter()
                .map(|segment| {
                    serde_json::json!({
                        "type": segment.seg_type,
                        "size": segment.payload.len(),
                    })
                })
                .collect::<Vec<_>>();
            let payload = serde_json::json!({
                "path": image,
                "manifest": parsed.manifest.clone(),
                "segments": segments,
            });
            if format == "json" {
                let text = serde_json::to_string_pretty(&payload)
                    .map_err(|error| format!("rvf inspect: {error}"))?;
                println!("{text}");
            } else {
                println!("rvf: {}", image.display());
                println!(
                    "  name={} tag={}",
                    payload["manifest"]["name"], payload["manifest"]["tag"]
                );
                println!("  layer_digest={}", payload["manifest"]["layer_digest"]);
                println!("  layer_size={}", payload["manifest"]["layer_size"]);
                println!("  segments={}", parsed.segments.len());
                for segment in parsed.segments {
                    println!(
                        "    type=0x{:02x} size={}",
                        segment.seg_type,
                        segment.payload.len()
                    );
                }
            }
            Ok(())
        }
        RvfCommands::Extract { image, output } => {
            let bytes = ferro_core::rvf_image::extract_layer(image, output)
                .map_err(|error| format!("rvf extract: {error}"))?;
            println!(
                "rvf: extracted validated OCI layer {} bytes -> {}",
                bytes,
                output.display()
            );
            Ok(())
        }
        RvfCommands::Import { image, reference } => import_rvf_image(image, reference.as_deref()),
    }
}

#[cfg(target_os = "linux")]
fn import_rvf_image(image: &Path, requested_reference: Option<&str>) -> Result<(), String> {
    let runtime_path = runtime_dir();
    import_rvf_image_at(image, requested_reference, &runtime_path)
}

#[cfg(target_os = "linux")]
fn import_rvf_image_at(
    image: &Path,
    requested_reference: Option<&str>,
    runtime_path: &Path,
) -> Result<(), String> {
    let parsed = ferro_core::rvf_image::read_rvf_image(image)
        .map_err(|error| format!("rvf import: {error}"))?;
    if parsed.manifest.os != "linux" || parsed.manifest.arch != host_build_arch() {
        return Err(format!(
            "rvf import: image platform {}/{} does not match linux/{}",
            parsed.manifest.os,
            parsed.manifest.arch,
            host_build_arch()
        ));
    }
    let reference = requested_reference
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}:{}", parsed.manifest.name, parsed.manifest.tag));
    let reference = canonicalize_reference(&reference).map_err(|error| error.to_string())?;
    let layer_path = runtime_path
        .join("images")
        .join("blobs")
        .join(parsed.manifest.layer_digest.replace(':', "_"));

    let config_json = serde_json::json!({
        "architecture": parsed.manifest.arch,
        "os": parsed.manifest.os,
        "created": parsed.manifest.created_at,
        "config": {
            "Entrypoint": parsed.manifest.entrypoint,
            "Cmd": parsed.manifest.cmd,
            "Env": parsed.manifest.env,
        },
        "rootfs": {"type": "layers", "diff_ids": []},
    });
    let config_bytes = serde_json::to_vec(&config_json)
        .map_err(|error| format!("rvf import: config serialization failed: {error}"))?;
    let config_digest = format!("sha256:{:x}", sha2::Sha256::digest(&config_bytes));
    let config_path = runtime_path
        .join("images")
        .join("configs")
        .join(config_digest.replace(':', "_"));
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
        config: Descriptor {
            media_type: OCI_IMAGE_CONFIG_MEDIA_TYPE.to_string(),
            digest: config_digest.clone(),
            size: config_bytes.len() as i64,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        },
        layers: vec![Descriptor {
            media_type: OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
            digest: parsed.manifest.layer_digest.clone(),
            size: parsed.manifest.layer_size as i64,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        }],
        artifact_type: None,
        subject: None,
        annotations: Default::default(),
    };
    let manifest_json = serde_json::to_string(&manifest)
        .map_err(|error| format!("rvf import: manifest serialization failed: {error}"))?;
    let runtime = ContainerRuntime::new(runtime_path).map_err(|error| error.to_string())?;
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    let authorization = runtime
        .surface_authorization()
        .map_err(|error| error.to_string())?;
    let store =
        LocalImageStore::open(runtime_path.join("images")).map_err(|error| error.to_string())?;
    let plan = store
        .prepare_reference_write(
            &reference,
            &config_digest,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            &manifest_json,
        )
        .map_err(|error| error.to_string())?;
    let permit = authorization
        .authorize_image_reference_write_plan(&origin, &plan)
        .map_err(|error| error.to_string())?;
    if let Some(parent) = layer_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("rvf import: {error}"))?;
    }
    copy_file_atomically(&layer_path, &parsed)
        .map_err(|error| format!("rvf import: layer publication failed: {error}"))?;
    write_bytes_atomically(&config_path, &config_bytes)
        .map_err(|error| format!("rvf import: config publication failed: {error}"))?;
    store
        .put_reference_authorized(plan, permit)
        .map_err(|error| error.to_string())?;
    println!("rvf: imported {} as {}", image.display(), reference);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn import_rvf_image(_image: &Path, _requested_reference: Option<&str>) -> Result<(), String> {
    Err("rvf import is currently supported only on Linux".to_string())
}

#[cfg(target_os = "linux")]
fn copy_file_atomically(
    destination: &Path,
    parsed: &ferro_core::rvf_image::RvfImage,
) -> Result<(), std::io::Error> {
    let layer = parsed
        .segments
        .iter()
        .find(|segment| segment.seg_type == ferro_core::rvf_image::SEG_LAYER)
        .expect("validated RVF layer");
    write_bytes_atomically(destination, &layer.payload)
}

#[cfg(target_os = "linux")]
fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("rvf-import.tmp");
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
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
        AiCommands::Sign {
            model_type,
            version,
            signer_key_id,
            key,
            models_dir,
            format,
        } => {
            let model_type = model_type
                .parse::<ModelType>()
                .map_err(|error| format!("ai sign: {error}"))?;
            if signer_key_id.trim().is_empty()
                || signer_key_id.chars().count() > 128
                || signer_key_id.chars().any(char::is_control)
            {
                return Err("ai sign: signer key id must be 1-128 non-control characters".into());
            }
            let key_bytes = read_signing_key_file(&key)?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            let mut config = TrainingConfig::default();
            if let Some(models_dir) = models_dir {
                config.models_dir = PathBuf::from(models_dir);
            }
            let mut pipeline = TrainingPipeline::new(config)
                .map_err(|error| format!("ai sign: load model history: {error}"))?;
            pipeline
                .sign_model_version(model_type, version, signer_key_id.clone(), &signing_key)
                .map_err(|error| format!("ai sign: {error}"))?;
            let signed = pipeline
                .list_versions(model_type)
                .into_iter()
                .find(|model| model.version == version)
                .ok_or_else(|| {
                    format!("ai sign: model version {version} disappeared after signing")
                })?;
            if format == "json" {
                let text = serde_json::to_string_pretty(signed)
                    .map_err(|error| format!("ai sign: {error}"))?;
                println!("{text}");
            } else {
                println!(
                    "ai sign: model_type={} version={} signer_key_id={} artifact_sha256={}",
                    signed.model_type, signed.version, signer_key_id, signed.artifact_sha256
                );
            }
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

/// Read a bounded Ed25519 signing key without accepting symlinked or oversized
/// files. Raw 32-byte keys and 64-character hexadecimal keys are supported so
/// operators can use either a secret-key export or a text secret provisioner.
fn read_signing_key_file(path: &Path) -> Result<[u8; 32], String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("read signing key metadata {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "signing key is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(format!(
                "signing key must not be group/other writable: {}",
                path.display()
            ));
        }
    }
    if metadata.len() > 4096 {
        return Err("signing key file exceeds 4096 bytes".into());
    }
    let bytes = std::fs::read(path)
        .map_err(|error| format!("read signing key {}: {error}", path.display()))?;
    if bytes.len() == 32 {
        return bytes
            .try_into()
            .map_err(|_| "signing key must contain exactly 32 bytes".to_string());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "signing key must be 32 raw bytes or 64 hexadecimal characters".to_string())?
        .trim();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("signing key must be 32 raw bytes or 64 hexadecimal characters".into());
    }
    let mut decoded = [0_u8; 32];
    for (index, slot) in decoded.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid hexadecimal signing key".to_string())?;
    }
    Ok(decoded)
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
    forced_id: Option<&str>,
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
    if !ferro_core::rvf_image::is_rvf_image(Path::new(image)) {
        parse_image_reference(image).map_err(|error| error.to_string())?;
    }
    let origin = runtime
        .request_origin()
        .ok_or_else(|| "run: authenticated request origin unavailable".to_string())?;
    let surface_authorization = runtime
        .surface_authorization()
        .map_err(|error| error.to_string())?;
    let effective_image = if ferro_core::rvf_image::is_rvf_image(Path::new(image)) {
        let parsed = ferro_core::rvf_image::read_rvf_image(Path::new(image))
            .map_err(|error| format!("run: RVF validation failed: {error}"))?;
        let reference =
            canonicalize_reference(&format!("{}:{}", parsed.manifest.name, parsed.manifest.tag))
                .map_err(|error| format!("run: RVF reference is invalid: {error}"))?;
        import_rvf_image_at(Path::new(image), Some(&reference), runtime_dir)?;
        reference
    } else {
        image.to_string()
    };
    parse_image_reference(&effective_image).map_err(|error| error.to_string())?;
    ensure_image_present(store, &effective_image, &origin, &surface_authorization)?;
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

    let run = |container_id: Option<&str>| {
        if let Some(container_id) = container_id {
            runtime.run_with_store_with_id(
                container_id.to_string(),
                store,
                &effective_image,
                &effective_cmd,
                &env,
                &labels,
                &annotations,
                health.clone(),
                restart_policy.clone(),
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
        } else {
            runtime.run_with_store(
                store,
                &effective_image,
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
        }
    };
    let record = run(forced_id).map_err(|err| err.to_string())?;
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
                "Available": context_endpoint_available(&context.endpoint),
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

fn context_endpoint_available(endpoint: &str) -> bool {
    let Some(path) = endpoint.strip_prefix("unix://") else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn context_endpoint_is_local(endpoint: &str) -> bool {
    let Some(path) = endpoint.strip_prefix("unix://") else {
        return false;
    };
    let path = Path::new(path);
    if path == runtime_dir().join("ferrocrate.sock")
        || path == Path::new("/var/run/ferrocrate.sock")
    {
        return true;
    }
    std::env::var_os("FERROCRATE_ROOTLESS_SOCKET")
        .is_some_and(|explicit| path == Path::new(&explicit))
}

/// Context records are already persisted and inspected, but the CLI command
/// handlers are local-runtime handlers. Refuse to silently execute against
/// local state when an operator selected a different daemon endpoint until a
/// transport client is wired for that context.
fn ensure_context_routing_available() -> Result<(), String> {
    let config = load_cli_config()?;
    let Some(name) = config.current_context else {
        return Ok(());
    };
    let Some(context) = config.contexts.get(&name) else {
        return Err(format!(
            "selected context '{name}' is missing from the context store"
        ));
    };
    if context_endpoint_is_local(&context.endpoint) {
        return Ok(());
    }
    Err(format!(
        "selected context '{name}' targets {}; remote daemon routing is not implemented; use a local context or `context use` with a local socket",
        context.endpoint
    ))
}

#[cfg(target_os = "linux")]
fn selected_remote_context_endpoint() -> Result<Option<String>, String> {
    let config = load_cli_config()?;
    let Some(name) = config.current_context else {
        return Ok(None);
    };
    let context = config
        .contexts
        .get(&name)
        .ok_or_else(|| format!("selected context '{name}' is missing from the context store"))?;
    if context_endpoint_is_local(&context.endpoint) {
        Ok(None)
    } else {
        let socket = context
            .endpoint
            .strip_prefix("unix://")
            .ok_or_else(|| "remote context endpoint must use unix://".to_string())?;
        Ok(Some(socket.to_string()))
    }
}

#[cfg(target_os = "linux")]
fn remote_docker_request(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    remote_docker_request_with_content_type(socket_path, method, path, body, None)
}

#[cfg(target_os = "linux")]
fn remote_docker_request_with_content_type(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    content_type: Option<&str>,
) -> Result<(u16, Vec<u8>), String> {
    if !Path::new(socket_path).is_absolute() || path.contains('\r') || path.contains('\n') {
        return Err("remote context request has an invalid socket or path".to_string());
    }
    let body = body.unwrap_or_default();
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|error| format!("remote context connect failed: {error}"))?;
    let content_header = content_type
        .map(|value| format!("Content-Type: {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: ferrocrate-remote\r\nConnection: close\r\nContent-Length: {}\r\n{content_header}\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|error| format!("remote context request failed: {error}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| format!("remote context request shutdown failed: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("remote context response failed: {error}"))?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "remote context returned malformed HTTP response".to_string())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "remote context returned non-UTF-8 headers".to_string())?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "remote context returned an invalid HTTP status".to_string())?;
    Ok((status, response[header_end + 4..].to_vec()))
}

#[cfg(target_os = "linux")]
fn remote_docker_stream_request<F>(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    mut on_chunk: F,
) -> Result<(), String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    if !Path::new(socket_path).is_absolute() || path.contains('\r') || path.contains('\n') {
        return Err("remote context request has an invalid socket or path".to_string());
    }
    let body = body.unwrap_or_default();
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|error| format!("remote context connect failed: {error}"))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: ferrocrate-remote\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|error| format!("remote context request failed: {error}"))?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| format!("remote context request shutdown failed: {error}"))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|error| format!("remote context stream response failed: {error}"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "remote context returned an invalid HTTP status".to_string())?;
    let mut chunked = false;
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|error| format!("remote context stream headers failed: {error}"))?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            match key.trim().to_ascii_lowercase().as_str() {
                "transfer-encoding" => chunked = value.trim().eq_ignore_ascii_case("chunked"),
                "content-length" => {
                    content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                        "remote context returned an invalid Content-Length".to_string()
                    })?);
                }
                _ => {}
            }
        }
    }
    if !(200..300).contains(&status) {
        let mut response = Vec::new();
        reader
            .read_to_end(&mut response)
            .map_err(|error| format!("remote context error response failed: {error}"))?;
        return Err(format!(
            "remote context request returned HTTP {status}: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    if chunked {
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|error| format!("remote context stream chunk header failed: {error}"))?;
            let size_text = line.trim().split(';').next().unwrap_or_default();
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| "remote context returned an invalid chunk size".to_string())?;
            if size == 0 {
                break;
            }
            let mut chunk = vec![0; size];
            reader
                .read_exact(&mut chunk)
                .map_err(|error| format!("remote context stream chunk truncated: {error}"))?;
            let mut terminator = [0_u8; 2];
            reader.read_exact(&mut terminator).map_err(|error| {
                format!("remote context stream chunk terminator failed: {error}")
            })?;
            if terminator != *b"\r\n" {
                return Err("remote context stream chunk has an invalid terminator".to_string());
            }
            on_chunk(&chunk)?;
        }
    } else if let Some(size) = content_length {
        let mut remaining = size;
        let mut chunk = vec![0_u8; 16 * 1024];
        while remaining > 0 {
            let target = remaining.min(chunk.len());
            reader
                .read_exact(&mut chunk[..target])
                .map_err(|error| format!("remote context stream body truncated: {error}"))?;
            on_chunk(&chunk[..target])?;
            remaining -= target;
        }
    } else {
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let size = reader
                .read(&mut chunk)
                .map_err(|error| format!("remote context stream body failed: {error}"))?;
            if size == 0 {
                break;
            }
            on_chunk(&chunk[..size])?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn dispatch_remote_context(command: &Commands) -> Option<Result<(), String>> {
    let endpoint = match selected_remote_context_endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => return Some(Err(error)),
    }?;
    let request_with_body = |method: &str, path: String, payload: Option<Vec<u8>>| {
        remote_docker_request(&endpoint, method, &path, payload.as_deref()).and_then(
            |(status, body)| {
                if (200..300).contains(&status) {
                    Ok(body)
                } else {
                    Err(format!(
                        "remote context request returned HTTP {status}: {}",
                        String::from_utf8_lossy(&body)
                    ))
                }
            },
        )
    };
    let request = |method: &str, path: String| request_with_body(method, path, None);
    let print_json = |body: Vec<u8>, format: &str| -> Result<(), String> {
        if format == "json" {
            let value: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|error| format!("remote context returned invalid JSON: {error}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
            );
        } else {
            println!("{}", String::from_utf8_lossy(&body));
        }
        Ok(())
    };
    let result = match command {
        Commands::Run {
            image,
            name,
            network,
            network_backend,
            bind_mounts,
            tmpfs_mounts,
            read_only_rootfs,
            read_write_rootfs,
            no_new_privs,
            profile,
            env,
            labels,
            annotations,
            user,
            workdir,
            entrypoint,
            publish,
            volumes,
            cap_add,
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
            cmd,
        } => (|| -> Result<(), String> {
            let unsupported = [
                (
                    *network_backend != "ebpf",
                    "--network-backend (remote Docker uses the daemon backend)",
                ),
                (*profile != "dev", "--profile"),
                (!annotations.is_empty(), "--annotation"),
                (bridge_cidr.is_some(), "--bridge-cidr"),
                (bridge_name.is_some(), "--bridge-name"),
                (net_limit.is_some(), "--net-limit"),
                (ai_model.is_some(), "--ai-model"),
            ];
            if let Some((_, option)) = unsupported.into_iter().find(|(enabled, _)| *enabled) {
                return Err(format!(
                    "remote run: {option} is not representable by the Docker transport"
                ));
            }
            let network_mode = match network.as_str() {
                "bridge" | "host" | "none" => network.as_str(),
                other => {
                    return Err(format!(
                    "remote run: network mode {other} is not representable by the Docker transport"
                ))
                }
            };
            let read_only = effective_readonly(profile, *read_only_rootfs, *read_write_rootfs)?;
            if let Some(name) = name {
                validate_docker_container_name(name)?;
            }
            let env = parse_env_entries(env)?;
            parse_bind_mounts(bind_mounts)?;
            validate_remote_volume_entries(volumes)?;
            parse_capabilities(cap_add)?;
            let _ = build_limits(*memory_max, *cpu_quota, *cpu_period, *pids_max)?;
            let health = build_health_config(
                health_cmd.as_deref(),
                *health_interval,
                *health_timeout,
                *health_retries,
                *health_start_period,
            )?;
            let restart_name = match parse_restart_policy(restart_policy)? {
                ferro_core::container_store::RestartPolicy::No => "no",
                ferro_core::container_store::RestartPolicy::OnFailure => "on-failure",
                ferro_core::container_store::RestartPolicy::Always => "always",
                ferro_core::container_store::RestartPolicy::UnlessStopped => "unless-stopped",
            };
            let labels = parse_key_values("run: label", labels)?;
            let entrypoint = entrypoint.as_deref().map(parse_entrypoint).transpose()?;
            let mappings = parse_publish(publish)?;
            let mut port_bindings = serde_json::Map::new();
            for mapping in mappings {
                let key = format!("{}/{}", mapping.container_port, mapping.protocol);
                let bindings = port_bindings
                    .entry(key)
                    .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                let bindings = bindings.as_array_mut().ok_or_else(|| {
                    "remote run: internal port-binding payload is not an array".to_string()
                })?;
                bindings.push(serde_json::json!({
                    "HostPort": mapping.host_port.to_string(),
                }));
            }
            let mut binds = bind_mounts.clone();
            binds.extend(volumes.iter().cloned());
            let mut tmpfs = serde_json::Map::new();
            for mount in parse_tmpfs_mounts(tmpfs_mounts)? {
                let target = format!("/{}", mount.target.display());
                let options = mount
                    .size
                    .map(|size| format!("size={size}"))
                    .unwrap_or_default();
                tmpfs.insert(target, serde_json::Value::String(options));
            }
            let payload = serde_json::json!({
                "Image": image,
                "Cmd": cmd,
                "Env": env,
                "Entrypoint": entrypoint,
                "WorkingDir": workdir,
                "User": user,
                "Labels": labels,
                "HostConfig": {
                    "Binds": binds,
                    "Tmpfs": tmpfs,
                    "PortBindings": port_bindings,
                    "NetworkMode": network_mode,
                    "RestartPolicy": {
                        "Name": restart_name,
                        "MaximumRetryCount": 0,
                    },
                    "Healthcheck": health.as_ref().map(docker_runtime_healthcheck),
                    "ReadonlyRootfs": read_only,
                    "CapAdd": cap_add,
                    "SecurityOpt": if *no_new_privs {
                        vec!["no-new-privileges".to_string()]
                    } else {
                        Vec::new()
                    },
                    "Memory": memory_max.unwrap_or(0),
                    "CpuQuota": cpu_quota.unwrap_or(0),
                    "CpuPeriod": cpu_period.unwrap_or(0),
                    "PidsLimit": pids_max.unwrap_or(0),
                },
            });
            let payload = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
            let create_path = match name {
                Some(name) => format!(
                    "/containers/create?name={}",
                    percent_encode_path_component(name)
                ),
                None => "/containers/create".to_string(),
            };
            let created = request_with_body("POST", create_path, Some(payload))?;
            let created: serde_json::Value = serde_json::from_slice(&created)
                .map_err(|error| format!("remote run create returned invalid JSON: {error}"))?;
            let id = created
                .get("Id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "remote run create response omitted Id".to_string())?;
            request("POST", format!("/containers/{id}/start"))?;
            if *rm {
                request(
                    "POST",
                    format!("/containers/{id}/wait?condition=not-running"),
                )?;
                request("DELETE", format!("/containers/{id}"))?;
            }
            println!("run: id={id}");
            Ok(())
        })(),
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
            secret,
        } => {
            (|| -> Result<(), String> {
                if ferrofile.is_some() {
                    return Err(
                        "remote build: --ferrofile is not representable by the Docker transport"
                            .to_string(),
                    );
                }
                if compress != "gzip" {
                    return Err(
                        "remote build: --compress is not representable by the Docker transport"
                            .to_string(),
                    );
                }
                if image_format != "oci" || embed_model.is_some() {
                    return Err("remote build: native RVF output is not representable by the Docker transport".to_string());
                }
                if cache_from.is_some() || cache_to.is_some() {
                    return Err(
                        "remote build: cache options are not representable by the Docker transport"
                            .to_string(),
                    );
                }
                if let Some(platform) = platform.as_deref() {
                    validate_build_platform(Some(platform))?;
                }
                if !build_context.is_empty() || !secret.is_empty() {
                    return Err("remote build: named contexts and secrets are not supported by this transport yet".to_string());
                }
                let dockerfile = dockerfile.as_deref().unwrap_or("Dockerfile");
                let dockerfile_path = if Path::new(dockerfile).is_absolute() {
                    PathBuf::from(dockerfile)
                } else {
                    std::env::current_dir()
                        .map_err(|error| {
                            format!("remote build: failed to get current directory: {error}")
                        })?
                        .join(dockerfile)
                };
                if !dockerfile_path.is_file() {
                    return Err(format!(
                        "remote build: Dockerfile does not exist: {}",
                        dockerfile_path.display()
                    ));
                }
                let context_dir = dockerfile_path.parent().unwrap_or_else(|| Path::new("."));
                let mut archive = tar::Builder::new(Vec::new());
                archive
                    .append_dir_all(".", context_dir)
                    .map_err(|error| format!("remote build: archive context failed: {error}"))?;
                let archive = archive
                    .into_inner()
                    .map_err(|error| format!("remote build: finalize context failed: {error}"))?;
                let filename = dockerfile_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("Dockerfile");
                let mut path = format!(
                    "/build?dockerfile={}",
                    percent_encode_path_component(filename)
                );
                if let Some(tag) = tag {
                    parse_image_reference(tag).map_err(|error| error.to_string())?;
                    path.push_str("&t=");
                    path.push_str(&percent_encode_path_component(tag));
                }
                if let Some(platform) = platform {
                    path.push_str("&platform=");
                    path.push_str(&percent_encode_path_component(&platform));
                }
                let (status, body) = remote_docker_request_with_content_type(
                    &endpoint,
                    "POST",
                    &path,
                    Some(&archive),
                    Some("application/x-tar"),
                )?;
                if !(200..300).contains(&status) {
                    return Err(format!(
                        "remote context request returned HTTP {status}: {}",
                        String::from_utf8_lossy(&body)
                    ));
                }
                if !body.is_empty() {
                    print_json(body, "json")?;
                }
                Ok(())
            })()
        }
        Commands::SystemDf { format } => {
            request("GET", "/system/df".to_string()).and_then(|body| print_json(body, format))
        }
        Commands::Images { format, filters } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            validate_docker_image_filters(&parsed)?;
            let path = if parsed.is_empty() {
                "/images/json".to_string()
            } else {
                let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
                format!(
                    "/images/json?filters={}",
                    percent_encode_path_component(&encoded)
                )
            };
            request("GET", path).and_then(|body| print_json(body, format))
        })(),
        Commands::History { image, format } => request(
            "GET",
            format!("/images/{}/history", percent_encode_path_component(image)),
        )
        .and_then(|body| print_json(body, format)),
        Commands::ImageInspect { image, format } => request(
            "GET",
            format!("/images/{}/json", percent_encode_path_component(image)),
        )
        .and_then(|body| print_json(body, format)),
        Commands::Tag { source, target } => (|| -> Result<(), String> {
            let source = canonicalize_reference(source).map_err(|error| error.to_string())?;
            let target = canonicalize_reference(target).map_err(|error| error.to_string())?;
            let (repo, tag) = split_reference(&target);
            request(
                "POST",
                format!(
                    "/images/{}/tag?repo={}&tag={}",
                    percent_encode_path_component(&source),
                    percent_encode_path_component(repo),
                    percent_encode_path_component(tag)
                ),
            )
            .map(|_| println!("tag: source={source} target={target}"))
        })(),
        Commands::Commit {
            container,
            repository,
        } => (|| -> Result<(), String> {
            if container.trim().is_empty() {
                return Err("remote commit: container is required".to_string());
            }
            request("POST", remote_commit_path(container, repository)?)
                .and_then(|body| print_json(body, "json"))
        })(),
        Commands::Rmi { image } => (|| -> Result<(), String> {
            let canonical = canonicalize_reference(image).map_err(|error| error.to_string())?;
            request(
                "DELETE",
                format!("/images/{}", percent_encode_path_component(&canonical)),
            )
            .map(|_| ())
        })(),
        Commands::ImagePrune { filters } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            validate_docker_image_prune_filters(&parsed)?;
            let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
            let path = format!(
                "/images/prune?filters={}",
                percent_encode_path_component(&encoded)
            );
            request("POST", path).map(|body| {
                if !body.is_empty() {
                    println!("{}", String::from_utf8_lossy(&body));
                }
            })
        })(),
        Commands::Pull { image, lazy } => (|| -> Result<(), String> {
            let parsed = ferro_core::registry::parse_image_reference(image)
                .map_err(|error| error.to_string())?;
            let from_image = format!("{}/{}", parsed.registry, parsed.repository);
            let mut path = format!(
                "/images/create?fromImage={}",
                percent_encode_path_component(&from_image)
            );
            if matches!(
                parsed.separator,
                ferro_core::registry::ReferenceSeparator::Tag
            ) {
                path.push_str("&tag=");
                path.push_str(&percent_encode_path_component(&parsed.reference));
            }
            if *lazy {
                path.push_str("&lazy=1");
            }
            request("POST", path).map(|_| println!("pull: image={}", parsed.canonical()))
        })(),
        Commands::Push { image } => (|| -> Result<(), String> {
            let canonical = canonicalize_reference(image).map_err(|error| error.to_string())?;
            request(
                "POST",
                format!("/images/{}/push", percent_encode_path_component(&canonical)),
            )
            .map(|_| println!("push: image={canonical}"))
        })(),
        Commands::Containers {
            format,
            all,
            limit,
            since,
            before,
            filters,
        } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            let mut path = format!("/containers/json?all={}", if *all { 1 } else { 0 });
            if let Some(limit) = limit {
                path.push_str(&format!("&limit={limit}"));
            }
            if let Some(value) = since {
                path.push_str("&since=");
                path.push_str(&percent_encode_path_component(value));
            }
            if let Some(value) = before {
                path.push_str("&before=");
                path.push_str(&percent_encode_path_component(value));
            }
            if !parsed.is_empty() {
                let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
                path.push_str("&filters=");
                path.push_str(&percent_encode_path_component(&encoded));
            }
            request("GET", path).and_then(|body| print_json(body, format))
        })(),
        Commands::ContainerPrune { filters } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            validate_docker_container_prune_filters(&parsed)?;
            let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
            request(
                "POST",
                format!(
                    "/containers/prune?filters={}",
                    percent_encode_path_component(&encoded)
                ),
            )
            .and_then(|body| print_json(body, "json"))
        })(),
        Commands::Events {
            since,
            until,
            filters,
            follow,
        } => (|| -> Result<(), String> {
            let mut path = "/events".to_string();
            let mut first = true;
            let mut add = |key: &str, value: &str| {
                path.push(if first { '?' } else { '&' });
                first = false;
                path.push_str(key);
                path.push('=');
                path.push_str(&percent_encode_path_component(value));
            };
            if let Some(value) = since.as_deref() {
                add("since", value);
            }
            if let Some(value) = until.as_deref() {
                add("until", value);
            }
            let mut filter_values: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for filter in filters {
                let (key, value) = filter
                    .split_once('=')
                    .ok_or_else(|| format!("events: filter must use key=value syntax: {filter}"))?;
                if key.is_empty() || value.is_empty() {
                    return Err("events: filter key and value must be non-empty".to_string());
                }
                filter_values
                    .entry(key.to_string())
                    .or_default()
                    .push(value.to_string());
            }
            if !filter_values.is_empty() {
                let encoded = serde_json::to_string(&filter_values)
                    .map_err(|error| format!("events: encode filters failed: {error}"))?;
                add("filters", &encoded);
            }
            if *follow {
                add("follow", "1");
                remote_docker_stream_request(&endpoint, "GET", &path, None, |chunk| {
                    print!("{}", String::from_utf8_lossy(chunk));
                    std::io::stdout().flush().map_err(|error| error.to_string())
                })
            } else {
                request("GET", path).map(|body| print!("{}", String::from_utf8_lossy(&body)))
            }
        })(),
        Commands::Exec { container, cmd } => (|| -> Result<(), String> {
            if cmd.is_empty() {
                return Err("exec: command is required".to_string());
            }
            let payload = serde_json::json!({
                "Cmd": cmd,
                "AttachStdout": true,
                "AttachStderr": true,
                "Tty": false,
            });
            let payload = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
            let create_body = request_with_body(
                "POST",
                format!(
                    "/containers/{}/exec",
                    percent_encode_path_component(container)
                ),
                Some(payload),
            )?;
            let create: serde_json::Value = serde_json::from_slice(&create_body)
                .map_err(|error| format!("remote exec create returned invalid JSON: {error}"))?;
            let id = create
                .get("Id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "remote exec create response omitted Id".to_string())?;
            let start = serde_json::to_vec(&serde_json::json!({
                "Detach": false,
                "Tty": false,
            }))
            .map_err(|error| error.to_string())?;
            let raw = request_with_body(
                "POST",
                format!("/exec/{}/start", percent_encode_path_component(id)),
                Some(start),
            )?;
            let (stdout, stderr) = decode_docker_raw_stream(&raw)?;
            if !stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&stdout));
            }
            if !stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&stderr));
            }
            Ok(())
        })(),
        Commands::Inspect { container, format } => request(
            "GET",
            format!(
                "/containers/{}/json",
                percent_encode_path_component(container)
            ),
        )
        .and_then(|body| print_json(body, format)),
        Commands::Logs {
            container,
            format,
            follow,
        } => {
            if *follow {
                if format == "json" {
                    Err("remote logs: --follow cannot be combined with --format json".to_string())
                } else {
                    remote_docker_stream_request(
                        &endpoint,
                        "GET",
                        &format!(
                            "/containers/{}/logs?stdout=1&stderr=1&follow=1",
                            percent_encode_path_component(container)
                        ),
                        None,
                        |chunk| {
                            print!("{}", String::from_utf8_lossy(chunk));
                            std::io::stdout().flush().map_err(|error| error.to_string())
                        },
                    )
                }
            } else {
                request(
                    "GET",
                    format!(
                        "/containers/{}/logs?stdout=1&stderr=1",
                        percent_encode_path_component(container)
                    ),
                )
                .and_then(|body| {
                    if format == "json" {
                        let output = serde_json::json!({
                            "container": container,
                            "logs": String::from_utf8_lossy(&body),
                        });
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&output)
                                .map_err(|error| error.to_string())?
                        );
                        Ok(())
                    } else {
                        print!("{}", String::from_utf8_lossy(&body));
                        Ok(())
                    }
                })
            }
        }
        Commands::Stats {
            container,
            format,
            follow,
        } => {
            if *follow {
                if format != "json" {
                    Err("remote stats: --follow requires --format json".to_string())
                } else {
                    remote_docker_stream_request(
                        &endpoint,
                        "GET",
                        &format!(
                            "/containers/{}/stats?stream=1",
                            percent_encode_path_component(container)
                        ),
                        None,
                        |chunk| {
                            std::io::stdout()
                                .write_all(chunk)
                                .and_then(|_| std::io::stdout().flush())
                                .map_err(|error| error.to_string())
                        },
                    )
                }
            } else {
                request(
                    "GET",
                    format!(
                        "/containers/{}/stats?stream=0",
                        percent_encode_path_component(container)
                    ),
                )
                .and_then(|body| print_json(body, format))
            }
        }
        Commands::Top { container, format } => request(
            "GET",
            format!(
                "/containers/{}/top",
                percent_encode_path_component(container)
            ),
        )
        .and_then(|body| print_json(body, format)),
        Commands::Wait {
            container,
            condition,
            timeout,
            format,
        } => (|| -> Result<(), String> {
            validate_wait_condition(condition)?;
            let mut path = format!(
                "/containers/{}/wait?condition={}",
                percent_encode_path_component(container),
                percent_encode_path_component(condition)
            );
            if let Some(timeout) = timeout {
                path.push_str(&format!("&timeout={timeout}"));
            }
            let body = request("POST", path)?;
            if format == "json" {
                return print_json(body, format);
            }
            let response: serde_json::Value = serde_json::from_slice(&body)
                .map_err(|error| format!("remote wait returned invalid JSON: {error}"))?;
            let status = response
                .get("StatusCode")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default();
            println!("wait: container={} status_code={status}", container);
            Ok(())
        })(),
        Commands::Pause { container } => request(
            "POST",
            format!(
                "/containers/{}/pause",
                percent_encode_path_component(container)
            ),
        )
        .map(|_| ()),
        Commands::Unpause { container } => request(
            "POST",
            format!(
                "/containers/{}/unpause",
                percent_encode_path_component(container)
            ),
        )
        .map(|_| ()),
        Commands::Stop { container, timeout } => request(
            "POST",
            format!(
                "/containers/{}/stop?t={timeout}",
                percent_encode_path_component(container)
            ),
        )
        .map(|_| ()),
        Commands::Kill { container, signal } => request(
            "POST",
            format!(
                "/containers/{}/kill?signal={}",
                percent_encode_path_component(container),
                percent_encode_path_component(signal)
            ),
        )
        .map(|_| ()),
        Commands::Restart { container, timeout } => request(
            "POST",
            format!(
                "/containers/{}/restart?t={timeout}",
                percent_encode_path_component(container)
            ),
        )
        .map(|_| ()),
        Commands::Start { container } => request(
            "POST",
            format!(
                "/containers/{}/start",
                percent_encode_path_component(container)
            ),
        )
        .map(|_| ()),
        Commands::Rm { container } => request(
            "DELETE",
            format!("/containers/{}", percent_encode_path_component(container)),
        )
        .map(|_| ()),
        Commands::Rename { container, name } => (|| -> Result<(), String> {
            if container.trim().is_empty() {
                return Err("rename: container is required".to_string());
            }
            validate_docker_container_name(name)?;
            request(
                "POST",
                format!(
                    "/containers/{}/rename?name={}",
                    percent_encode_path_component(container),
                    percent_encode_path_component(name)
                ),
            )
            .map(|_| println!("rename: container={container} name={name}"))
        })(),
        Commands::Network {
            command: NetworkCommands::Ls { filters },
        } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            validate_docker_network_filters(&parsed)?;
            let path = if parsed.is_empty() {
                "/networks".to_string()
            } else {
                let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
                format!(
                    "/networks?filters={}",
                    percent_encode_path_component(&encoded)
                )
            };
            request("GET", path).and_then(|body| print_json(body, "json"))
        })(),
        Commands::Network {
            command: NetworkCommands::Inspect { name, format },
        } => request(
            "GET",
            format!("/networks/{}", percent_encode_path_component(name)),
        )
        .and_then(|body| print_json(body, format)),
        Commands::Volume {
            command: VolumeCommands::Ls { filters },
        } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            validate_docker_volume_filters(&parsed)?;
            let path = if parsed.is_empty() {
                "/volumes".to_string()
            } else {
                let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
                format!(
                    "/volumes?filters={}",
                    percent_encode_path_component(&encoded)
                )
            };
            request("GET", path).and_then(|body| print_json(body, "json"))
        })(),
        Commands::Volume {
            command: VolumeCommands::Prune { filters },
        } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            validate_docker_volume_filters(&parsed)?;
            let path = if parsed.is_empty() {
                "/volumes/prune".to_string()
            } else {
                let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
                format!(
                    "/volumes/prune?filters={}",
                    percent_encode_path_component(&encoded)
                )
            };
            request("POST", path).and_then(|body| print_json(body, "json"))
        })(),
        Commands::Volume {
            command: VolumeCommands::Inspect { name, format },
        } => request(
            "GET",
            format!("/volumes/{}", percent_encode_path_component(name)),
        )
        .and_then(|body| print_json(body, format)),
        Commands::Network {
            command:
                NetworkCommands::Create {
                    name,
                    subnet,
                    gateway,
                    ipv6_subnet,
                    ipv6_gateway,
                },
        } => {
            let mut configs = Vec::new();
            if subnet.is_some() || gateway.is_some() {
                configs.push(serde_json::json!({
                    "Subnet": subnet,
                    "Gateway": gateway,
                }));
            }
            if ipv6_subnet.is_some() || ipv6_gateway.is_some() {
                configs.push(serde_json::json!({
                    "Subnet": ipv6_subnet,
                    "Gateway": ipv6_gateway,
                }));
            }
            let body = serde_json::json!({
                "Name": name,
                "Driver": "bridge",
                "EnableIPv6": ipv6_subnet.is_some(),
                "IPAM": {"Config": configs},
            });
            let body = match serde_json::to_vec(&body) {
                Ok(body) => body,
                Err(error) => return Some(Err(error.to_string())),
            };
            request_with_body("POST", "/networks/create".to_string(), Some(body))
                .and_then(|body| print_json(body, "json"))
        }
        Commands::Network {
            command: NetworkCommands::Rm { name },
        } => request(
            "DELETE",
            format!("/networks/{}", percent_encode_path_component(name)),
        )
        .map(|_| ()),
        Commands::Network {
            command: NetworkCommands::Prune { filters },
        } => (|| -> Result<(), String> {
            let parsed = parse_cli_filters(filters)?;
            validate_docker_network_filters(&parsed)?;
            let path = if parsed.is_empty() {
                "/networks/prune".to_string()
            } else {
                let encoded = serde_json::to_string(&parsed).map_err(|error| error.to_string())?;
                format!(
                    "/networks/prune?filters={}",
                    percent_encode_path_component(&encoded)
                )
            };
            request("POST", path).and_then(|body| print_json(body, "json"))
        })(),
        Commands::Volume {
            command: VolumeCommands::Create { name, driver, opts },
        } => {
            let mut driver_opts = serde_json::Map::new();
            for option in opts {
                let (key, value) = match option.split_once('=') {
                    Some(pair) => pair,
                    None => {
                        return Some(Err(format!(
                            "remote context volume option must use key=value: {option}"
                        )))
                    }
                };
                driver_opts.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
            let body = serde_json::json!({
                "Name": name,
                "Driver": driver,
                "DriverOpts": driver_opts,
            });
            let body = match serde_json::to_vec(&body) {
                Ok(body) => body,
                Err(error) => return Some(Err(error.to_string())),
            };
            request_with_body("POST", "/volumes/create".to_string(), Some(body))
                .and_then(|body| print_json(body, "json"))
        }
        Commands::Volume {
            command: VolumeCommands::Rm { name },
        } => request(
            "DELETE",
            format!("/volumes/{}", percent_encode_path_component(name)),
        )
        .map(|_| ()),
        _ => {
            Err("selected remote context has no transport mapping for this command yet".to_string())
        }
    };
    Some(result)
}

#[cfg(target_os = "linux")]
fn percent_encode_path_component(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn remote_commit_path(container: &str, repository: &str) -> Result<String, String> {
    if container.trim().is_empty() {
        return Err("remote commit: container is required".to_string());
    }
    let target = canonicalize_reference(repository).map_err(|error| error.to_string())?;
    let (repo, tag) = split_reference(&target);
    Ok(format!(
        "/commit?container={}&repo={}&tag={}",
        percent_encode_path_component(container),
        percent_encode_path_component(repo),
        percent_encode_path_component(tag),
    ))
}

#[cfg(target_os = "linux")]
fn decode_docker_raw_stream(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut offset = 0usize;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    while offset < raw.len() {
        if raw.len().saturating_sub(offset) < 8 {
            return Err("remote exec returned a truncated Docker stream header".to_string());
        }
        let stream = raw[offset];
        if stream != 1 && stream != 2 {
            return Err(format!(
                "remote exec returned an invalid stream id {stream}"
            ));
        }
        let size = u32::from_be_bytes([
            raw[offset + 4],
            raw[offset + 5],
            raw[offset + 6],
            raw[offset + 7],
        ]) as usize;
        offset += 8;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "remote exec stream frame is too large".to_string())?;
        if end > raw.len() {
            return Err("remote exec returned a truncated Docker stream frame".to_string());
        }
        match stream {
            1 => stdout.extend_from_slice(&raw[offset..end]),
            2 => stderr.extend_from_slice(&raw[offset..end]),
            _ => unreachable!(),
        }
        offset = end;
    }
    Ok((stdout, stderr))
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
    // Short-lived `run --rm` workloads commonly exit before the supervisor's
    // first store observation. Keep the two-observation confirmation below,
    // but avoid adding a 200 ms floor to every successful lifecycle.
    // Keep short-lived `run --rm` latency below one scheduler tick on the
    // qualified host without busy-spinning; the terminal state is still
    // confirmed twice before removal can race the supervisor publication.
    const RUNNING_POLL_INTERVAL: Duration = Duration::from_millis(10);
    const TERMINAL_CONFIRM_INTERVAL: Duration = Duration::from_millis(5);
    let started = Instant::now();
    let mut terminal_observations = 0u8;
    loop {
        let record = runtime.inspect(id).map_err(|err| err.to_string())?;
        match record.status.as_str() {
            "running" | "paused" => {
                terminal_observations = 0;
                if timeout.is_some_and(|limit| started.elapsed() >= limit) {
                    return Err(format!("wait: timed out waiting for container {id}"));
                }
                std::thread::sleep(RUNNING_POLL_INTERVAL);
            }
            _ => {
                // The supervisor publishes the terminal state in a separate
                // process from the CLI's `--rm` caller. Require two stable
                // observations so removal cannot race the final lifecycle
                // write and trip the store's compare-and-swap guard.
                terminal_observations = terminal_observations.saturating_add(1);
                if terminal_observations >= 2 {
                    return Ok(());
                }
                std::thread::sleep(TERMINAL_CONFIRM_INTERVAL);
            }
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
fn validate_remote_volume_entries(entries: &[String]) -> Result<(), String> {
    for entry in entries {
        let parts = entry.split(':').collect::<Vec<_>>();
        if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err("run: volume must be source:target[:ro]".to_string());
        }
        if parts.len() > 2 && parts[2] != "ro" {
            return Err("run: volume mode must be ro when specified".to_string());
        }
    }
    Ok(())
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
#[cfg(target_os = "linux")]
fn extract_docker_build_context(archive: &[u8], destination: &Path) -> Result<(), String> {
    let mut archive = tar::Archive::new(Cursor::new(archive));
    for entry in archive
        .entries()
        .map_err(|error| format!("docker build: invalid tar context: {error}"))?
    {
        let mut entry =
            entry.map_err(|error| format!("docker build: invalid tar entry: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("docker build: invalid context path: {error}"))?
            .into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(format!(
                "docker build: context path escapes archive root: {}",
                path.display()
            ));
        }
        let target = destination.join(&path);
        match entry.header().entry_type() {
            tar::EntryType::Directory => std::fs::create_dir_all(&target).map_err(|error| {
                format!("docker build: create context directory failed: {error}")
            })?,
            tar::EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent).map_err(|error| {
                        format!("docker build: create context parent failed: {error}")
                    })?;
                }
                let mut output = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .map_err(|error| {
                        format!("docker build: create context file failed: {error}")
                    })?;
                std::io::copy(&mut entry, &mut output).map_err(|error| {
                    format!("docker build: extract context file failed: {error}")
                })?;
            }
            kind => {
                return Err(format!(
                    "docker build: unsupported context entry type {kind:?}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn docker_manifest_layer_size(manifest_json: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(manifest_json)
        .ok()
        .and_then(|manifest| {
            manifest
                .get("layers")
                .and_then(serde_json::Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|layer| layer.get("size").and_then(serde_json::Value::as_u64))
        .fold(0u64, u64::saturating_add)
}

#[cfg(target_os = "linux")]
fn docker_directory_usage(root: &Path) -> u64 {
    let Ok(metadata) = std::fs::symlink_metadata(root) else {
        return 0;
    };
    if metadata.file_type().is_symlink() {
        return 0;
    }
    if metadata.is_file() {
        return metadata.len();
    }
    if !metadata.is_dir() {
        return 0;
    }
    std::fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| docker_directory_usage(&entry.path()))
        .fold(0u64, u64::saturating_add)
}

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
    secrets: &[String],
) -> Result<(), String> {
    validate_build_platform(platform)?;
    let runtime_dir = runtime_dir();
    let compression = parse_compression(compression)?;
    let named_contexts = parse_build_contexts(build_context)?;
    let secrets = parse_build_secrets(secrets)?;
    let retry_limit = build_retry_limit()?;
    if ferrofile.is_some() && !secrets.is_empty() {
        return Err("build: --secret is only supported with Dockerfiles".to_string());
    }
    if let Some(source) = cache_from {
        let auth = registry_cache_auth();
        if source.starts_with("registry://") {
            ferro_core::dockerfile_build::import_build_cache_from_registry(
                &runtime_dir,
                source,
                auth.as_ref(),
            )
            .map_err(|error| format!("build: registry cache-from failed: {error}"))?;
        } else {
            ferro_core::dockerfile_build::import_build_cache(&runtime_dir, Path::new(source))
                .map_err(|error| format!("build: cache-from failed: {error}"))?;
        }
    }

    let mut attempt = 0u32;
    let (result, source_desc) = loop {
        let outcome = if let Some(ferrofile_path) = ferrofile {
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
            ferro_core::dockerfile_build::execute_dockerfile_build_authorized_with_secrets(
                plan, store, permit, &secrets,
            )
            .map(|result| (result, format!("ferrofile={ferrofile_path}")))
            .map_err(|error| error.to_string())
        } else {
            let dockerfile = dockerfile.unwrap_or("Dockerfile");
            let tag = tag.unwrap_or("local/build:latest");
            parse_image_reference(tag).map_err(|err| err.to_string())?;
            // Resolve relative dockerfile paths against current working directory.
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
            ferro_core::dockerfile_build::execute_dockerfile_build_authorized_with_secrets(
                plan, store, permit, &secrets,
            )
            .map(|result| (result, format!("dockerfile={}", dockerfile_path.display())))
            .map_err(|error| error.to_string())
        };
        match outcome {
            Ok(value) => break value,
            Err(error) if attempt < retry_limit && build_error_is_retryable(&error) => {
                attempt += 1;
                let backoff = 50u64.saturating_mul(1u64 << attempt.min(5));
                eprintln!(
                    "build: transient attempt failure; retry {attempt}/{retry_limit} in {backoff}ms: {error}"
                );
                std::thread::sleep(Duration::from_millis(backoff));
            }
            Err(error) => return Err(error),
        }
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
            let auth = registry_cache_auth();
            if destination.starts_with("registry://") {
                ferro_core::dockerfile_build::export_build_cache_to_registry(
                    &runtime_dir,
                    destination,
                    auth.as_ref(),
                )
                .map_err(|error| format!("build: registry cache-to failed: {error}"))?;
            } else {
                ferro_core::dockerfile_build::export_build_cache(
                    &runtime_dir,
                    Path::new(destination),
                )
                .map_err(|error| format!("build: cache-to failed: {error}"))?;
            }
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
        let auth = registry_cache_auth();
        if destination.starts_with("registry://") {
            ferro_core::dockerfile_build::export_build_cache_to_registry(
                &runtime_dir,
                destination,
                auth.as_ref(),
            )
            .map_err(|error| format!("build: registry cache-to failed: {error}"))?;
        } else {
            ferro_core::dockerfile_build::export_build_cache(&runtime_dir, Path::new(destination))
                .map_err(|error| format!("build: cache-to failed: {error}"))?;
        }
    }

    println!(
        "build: {} tag={} layer_digest={} config_digest={}",
        source_desc, result.reference, result.layer_digest, result.config_digest
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn registry_cache_auth() -> Option<ferro_core::registry::RegistryAuth> {
    let username = std::env::var("FERROCRATE_REGISTRY_USERNAME").ok()?;
    let password = std::env::var("FERROCRATE_REGISTRY_PASSWORD").ok()?;
    Some(ferro_core::registry::RegistryAuth { username, password })
}

#[cfg(target_os = "linux")]
fn build_retry_limit() -> Result<u32, String> {
    let raw = std::env::var("FERROCRATE_BUILD_RETRIES").unwrap_or_else(|_| "0".to_string());
    let retries = raw
        .parse::<u32>()
        .map_err(|_| "build: FERROCRATE_BUILD_RETRIES must be an integer".to_string())?;
    if retries > 5 {
        return Err("build: FERROCRATE_BUILD_RETRIES must be between 0 and 5".to_string());
    }
    Ok(retries)
}

#[cfg(target_os = "linux")]
fn build_error_is_retryable(error: &str) -> bool {
    let lowered = error.to_ascii_lowercase();
    ![
        "authorization",
        "invalid dockerfile",
        "unsupported",
        "cancelled",
        "timed out",
        "secret",
        "traversal",
        "symlink",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
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
fn parse_build_secrets(values: &[String]) -> Result<HashMap<String, PathBuf>, String> {
    let cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    let mut secrets = HashMap::new();
    for value in values {
        let mut id = None;
        let mut source = None;
        for option in value.split(',') {
            let (key, value) = option
                .split_once('=')
                .ok_or_else(|| "secret must use id=NAME,src=PATH".to_string())?;
            match key {
                "id" => id = Some(value.to_string()),
                "src" | "source" => source = Some(value.to_string()),
                _ => return Err(format!("secret option is unsupported: {key}")),
            }
        }
        let id = id.ok_or_else(|| "secret requires id=NAME".to_string())?;
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(format!("secret id is invalid: {id}"));
        }
        let source = source.ok_or_else(|| format!("secret {id} requires src=PATH"))?;
        let source = Path::new(&source);
        let source = if source.is_absolute() {
            source.to_path_buf()
        } else {
            cwd.join(source)
        };
        let metadata = std::fs::symlink_metadata(&source)
            .map_err(|error| format!("secret {id} cannot be read: {error}"))?;
        if !metadata.file_type().is_file() || metadata.len() > 1024 * 1024 {
            return Err(format!(
                "secret {id} must be a regular file no larger than 1 MiB"
            ));
        }
        if secrets.insert(id.clone(), source).is_some() {
            return Err(format!("duplicate secret id: {id}"));
        }
    }
    Ok(secrets)
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

fn handle_images(
    store: &LocalImageStore,
    format: &str,
    filter_values: &[String],
) -> Result<(), String> {
    let filters = parse_cli_filters(filter_values)?;
    validate_docker_image_filters(&filters)?;
    let records = docker_image_apply_time_bounds(
        store
            .list_references()
            .map_err(|err| err.to_string())?
            .into_iter()
            .filter(|record| docker_image_matches_filters(record, &filters))
            .collect(),
        &filters,
    )?;
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

fn handle_history(store: &LocalImageStore, image: &str, format: &str) -> Result<(), String> {
    let canonical = canonicalize_reference(image).map_err(|error| error.to_string())?;
    let reference = resolve_reference(store, &canonical)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("history: not found {canonical}"))?;
    let manifest = parse_image_manifest(&reference.manifest_json)
        .map_err(|error| format!("history: invalid image manifest: {error}"))?;
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
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&history).map_err(|error| error.to_string())?
        );
    } else {
        for entry in history {
            println!(
                "{} {} {}",
                entry
                    .get("Id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<unknown>"),
                entry
                    .get("Size")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
                entry
                    .get("Created")
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn handle_image_inspect(store: &LocalImageStore, image: &str, format: &str) -> Result<(), String> {
    let canonical = canonicalize_reference(image).map_err(|error| error.to_string())?;
    let reference = resolve_reference(store, &canonical)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("image inspect: not found {canonical}"))?;
    let payload = serde_json::json!({
        "Id": reference.digest,
        "RepoTags": [reference.reference],
        "Created": reference.created_at_unix,
        "Size": 0,
        "VirtualSize": 0,
    });
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?
        );
    } else {
        println!("Id: {}", payload["Id"]);
        println!("RepoTags: {}", payload["RepoTags"][0]);
        println!("Created: {}", payload["Created"]);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_commit(
    runtime_dir: &Path,
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    authorization: &SurfaceAuthorization,
    container: &str,
    repository: &str,
) -> Result<(), String> {
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    let digest = commit_image(
        runtime_dir,
        runtime,
        store,
        authorization,
        &origin,
        container,
        repository,
    )?;
    let target = canonicalize_reference(repository).map_err(|error| error.to_string())?;
    println!("commit: container={container} image={target} digest={digest}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn commit_image(
    runtime_dir: &Path,
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    authorization: &SurfaceAuthorization,
    origin: &RequestOrigin,
    container: &str,
    repository: &str,
) -> Result<String, String> {
    let target = canonicalize_reference(repository).map_err(|error| error.to_string())?;
    let record = match runtime.inspect(container) {
        Ok(record) => record,
        Err(_) => runtime
            .list()
            .map_err(|error| format!("commit: list containers: {error}"))?
            .into_iter()
            .find(|candidate| {
                candidate.id == container || candidate.name.as_deref() == Some(container)
            })
            .ok_or_else(|| format!("commit: container not found: {container}"))?,
    };
    let rootfs = runtime_dir
        .join("containers")
        .join(&record.id)
        .join("rootfs");
    if !rootfs.is_dir() {
        return Err(format!(
            "commit: container rootfs is unavailable: {}",
            rootfs.display()
        ));
    }
    if !record.mounts.is_empty() || !record.tmpfs_mounts.is_empty() {
        return Err(
            "commit: bind and tmpfs mounts must be removed before committing the rootfs"
                .to_string(),
        );
    }

    // Build a deterministic-in-memory tar before authorization/publication so
    // an invalid or unreadable rootfs cannot consume a mutation permit.
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        append_commit_rootfs(&mut builder, &rootfs)
            .map_err(|error| format!("commit: snapshot rootfs: {error}"))?;
        builder
            .finish()
            .map_err(|error| format!("commit: finish snapshot: {error}"))?;
    }
    let diff_id = format!("sha256:{:x}", Sha256::digest(&tar_bytes));
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&tar_bytes)
        .map_err(|error| format!("commit: compress snapshot: {error}"))?;
    let layer_bytes = encoder
        .finish()
        .map_err(|error| format!("commit: finish compressed snapshot: {error}"))?;
    let layer_digest = format!("sha256:{:x}", Sha256::digest(&layer_bytes));

    let config_json = serde_json::json!({
        "architecture": host_build_arch(),
        "os": "linux",
        "config": {
            "Cmd": record.command.clone(),
            "Env": record.env.clone(),
            "WorkingDir": record.workdir.unwrap_or_default(),
            "User": record.user.unwrap_or_default(),
        },
        "container_config": {
            "Cmd": record.command,
            "Env": record.env,
        },
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created_by": "ferrocrate commit", "comment": record.id}],
    });
    let config_bytes = serde_json::to_vec(&config_json)
        .map_err(|error| format!("commit: serialize config: {error}"))?;
    let config_digest = format!("sha256:{:x}", Sha256::digest(&config_bytes));
    let manifest = ImageManifest {
        schema_version: 2,
        media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.to_string(),
        config: Descriptor {
            media_type: OCI_IMAGE_CONFIG_MEDIA_TYPE.to_string(),
            digest: config_digest.clone(),
            size: config_bytes.len() as i64,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        },
        layers: vec![Descriptor {
            media_type: OCI_IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
            digest: layer_digest.clone(),
            size: layer_bytes.len() as i64,
            urls: Vec::new(),
            annotations: None,
            artifact_type: None,
            platform: None,
        }],
        artifact_type: None,
        subject: None,
        annotations: HashMap::new(),
    };
    let manifest_json = serde_json::to_string(&manifest)
        .map_err(|error| format!("commit: serialize manifest: {error}"))?;
    let plan = store
        .prepare_reference_write(
            &target,
            &config_digest,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            &manifest_json,
        )
        .map_err(|error| format!("commit: prepare image publication: {error}"))?;
    let permit = authorization
        .authorize_image_reference_write_plan(origin, &plan)
        .map_err(|error| format!("commit: authorize image publication: {error}"))?;

    let image_dir = runtime_dir.join("images");
    let layer_path = image_dir.join("blobs").join(layer_digest.replace(':', "_"));
    let config_path = image_dir
        .join("configs")
        .join(config_digest.replace(':', "_"));
    write_bytes_atomically(&layer_path, &layer_bytes)
        .map_err(|error| format!("commit: publish layer: {error}"))?;
    write_bytes_atomically(&config_path, &config_bytes)
        .map_err(|error| format!("commit: publish config: {error}"))?;
    store
        .put_reference_authorized(plan, permit)
        .map_err(|error| format!("commit: publish image reference: {error}"))?;
    Ok(config_digest)
}

#[cfg(target_os = "linux")]
fn append_commit_rootfs<W: Write>(
    builder: &mut tar::Builder<W>,
    rootfs: &Path,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(rootfs)? {
        let entry = entry?;
        let name = entry.file_name();
        // These are runtime-only mounts in an active container. Reading them
        // races with teardown and would incorrectly capture host/kernel state.
        if matches!(name.to_str(), Some("proc" | "sys" | "dev" | "run")) {
            continue;
        }
        let path = entry.path();
        let archive_name = Path::new(".").join(&name);
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            builder.append_dir(&archive_name, &path)?;
            append_commit_rootfs_dir(builder, &path, &archive_name)?;
        } else if metadata.file_type().is_symlink() {
            append_commit_symlink(builder, &path, &archive_name)?;
        } else {
            builder.append_path_with_name(&path, &archive_name)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn append_commit_rootfs_dir<W: Write>(
    builder: &mut tar::Builder<W>,
    directory: &Path,
    archive_directory: &Path,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let path = entry.path();
        let archive_name = archive_directory.join(&name);
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.file_type().is_dir() {
            builder.append_dir(&archive_name, &path)?;
            append_commit_rootfs_dir(builder, &path, &archive_name)?;
        } else if metadata.file_type().is_symlink() {
            append_commit_symlink(builder, &path, &archive_name)?;
        } else {
            builder.append_path_with_name(&path, &archive_name)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn append_commit_symlink<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &Path,
    archive_name: &Path,
) -> Result<(), std::io::Error> {
    let target = std::fs::read_link(path)?;
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    header.set_mtime(0);
    header.set_link_name(target)?;
    header.set_cksum();
    builder.append_data(&mut header, archive_name, std::io::empty())
}

fn handle_tag(
    store: &LocalImageStore,
    source: &str,
    target: &str,
    authorization: &SurfaceAuthorization,
) -> Result<(), String> {
    let source = canonicalize_reference(source).map_err(|error| error.to_string())?;
    let target = canonicalize_reference(target).map_err(|error| error.to_string())?;
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    let plan = prepare_image_tag(store, &source, &target).map_err(|error| error.to_string())?;
    let permit = authorization
        .authorize_image_tag_plan(&origin, &plan)
        .map_err(|error| error.to_string())?;
    execute_image_tag_authorized(store, plan, permit).map_err(|error| error.to_string())?;
    println!("tag: source={source} target={target}");
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
    filter_values: &[String],
) -> Result<(), String> {
    let origin = RequestOrigin::cli_current().map_err(|error| error.to_string())?;
    let filters = parse_cli_filters(filter_values)?;
    validate_docker_image_prune_filters(&filters)?;
    let records = store
        .list_references()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|record| docker_image_prune_matches_filters(record, &filters))
        .collect::<Vec<_>>();
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
fn handle_containers(
    runtime: &ContainerRuntime,
    format: &str,
    all: bool,
    limit: Option<usize>,
    since: Option<&str>,
    before: Option<&str>,
    filter_values: &[String],
) -> Result<(), String> {
    let filters = parse_cli_filters(filter_values)?;
    validate_docker_container_filters(&filters)?;
    let mut records = runtime.list().map_err(|err| err.to_string())?;
    if !all {
        records.retain(|record| matches!(record.status.as_str(), "running" | "paused"));
    }
    records.retain(|record| docker_container_matches_filters(record, &filters));
    records = docker_container_apply_time_bounds(records, since, before)?;
    records.sort_by(|left, right| {
        right
            .created_at_unix
            .cmp(&left.created_at_unix)
            .then_with(|| right.id.cmp(&left.id))
    });
    if let Some(limit) = limit {
        records.truncate(limit);
    }
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
fn handle_container_prune(
    runtime: &ContainerRuntime,
    filter_values: &[String],
) -> Result<(), String> {
    let filters = parse_cli_filters(filter_values)?;
    validate_docker_container_prune_filters(&filters)?;
    let records = runtime
        .list()
        .map_err(|error| error.to_string())?
        .into_iter()
        .filter(|record| docker_container_prune_matches_filters(record, &filters))
        .collect::<Vec<_>>();
    let mut deleted = Vec::new();
    for record in records {
        runtime
            .remove(&record.id)
            .map_err(|error| error.to_string())?;
        deleted.push(record.id);
    }
    println!("container prune: removed={}", deleted.len());
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_logs(
    runtime: &ContainerRuntime,
    container: &str,
    format: &str,
    follow: bool,
) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("logs: container is required".to_string());
    }
    if follow && format == "json" {
        return Err("logs: --follow cannot be combined with --format json".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let mut emitted = 0usize;
    loop {
        let logs = runtime.logs(&resolved).map_err(|err| err.to_string())?;
        if logs.len() < emitted {
            emitted = 0;
        }
        if !follow && format == "json" {
            let output = serde_json::json!({
                "container": resolved,
                "logs": logs,
            });
            let json = serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?;
            println!("{json}");
            return Ok(());
        }
        if logs.len() > emitted {
            print!("{}", &logs[emitted..]);
            std::io::stdout().flush().map_err(|err| err.to_string())?;
            emitted = logs.len();
        }
        if !follow {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
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
fn handle_stats(
    runtime: &ContainerRuntime,
    container: &str,
    format: &str,
    follow: bool,
) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("stats: container is required".to_string());
    }
    if follow && format != "json" {
        return Err("stats: --follow requires --format json".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    loop {
        let stats = runtime.stats(&resolved).map_err(|err| err.to_string())?;
        if format == "json" {
            let output = StatsOutput {
                container: resolved.clone(),
                stats,
            };
            if follow {
                println!(
                    "{}",
                    serde_json::to_string(&output).map_err(|err| err.to_string())?
                );
            } else {
                let json = serde_json::to_string_pretty(&output).map_err(|err| err.to_string())?;
                println!("{json}");
            }
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
        if !follow {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(target_os = "linux")]
fn handle_top(runtime: &ContainerRuntime, container: &str, format: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("top: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let payload = docker_top_payload(runtime, &resolved)?;
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    let titles = payload
        .get("Titles")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    if !titles.is_empty() {
        println!("{titles}");
    }
    if let Some(processes) = payload
        .get("Processes")
        .and_then(serde_json::Value::as_array)
    {
        for process in processes {
            let row = process
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .map(|value| value.as_str().unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            if !row.is_empty() {
                println!("{row}");
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_wait_condition(condition: &str) -> Result<(), String> {
    if matches!(condition, "not-running" | "next-exit" | "removed") {
        Ok(())
    } else {
        Err(format!(
            "wait: condition must be not-running, next-exit, or removed, got {condition}"
        ))
    }
}

#[cfg(target_os = "linux")]
fn handle_wait(
    runtime: &ContainerRuntime,
    container: &str,
    condition: &str,
    timeout: Option<u64>,
    format: &str,
) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("wait: container is required".to_string());
    }
    validate_wait_condition(condition)?;
    let resolved = resolve_container_id(runtime, container)?;
    wait_for_container_exit_with_timeout(
        runtime,
        &resolved,
        timeout
            .filter(|seconds| *seconds > 0)
            .map(Duration::from_secs),
    )?;
    let record = runtime
        .inspect(&resolved)
        .map_err(|error| error.to_string())?;
    let status_code = record.last_exit_code.unwrap_or(0);
    if format == "json" {
        let output = serde_json::json!({
            "StatusCode": status_code,
            "Error": serde_json::Value::Null,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?
        );
    } else {
        println!("wait: container={} status_code={status_code}", resolved);
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
fn handle_kill(
    runtime: &ContainerRuntime,
    container: &str,
    signal_name: &str,
) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("kill: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let signal = parse_docker_kill_signal(Some(&signal_name.to_string()))?;
    runtime
        .kill_with_signal(&resolved, signal)
        .map_err(|err| err.to_string())?;
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
fn handle_rename(runtime: &ContainerRuntime, container: &str, name: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("rename: container is required".to_string());
    }
    validate_docker_container_name(name)?;
    let resolved = resolve_container_id(runtime, container)?;
    runtime
        .rename(&resolved, name)
        .map_err(|err| err.to_string())?;
    println!("rename: container={resolved} name={name}");
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

#[cfg(target_os = "linux")]
fn handle_start(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("start: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.start(&resolved).map_err(|err| err.to_string())?;
    println!("start: {resolved}");
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
        VolumeCommands::Ls { filters } => {
            let filters = parse_cli_filters(&filters)?;
            validate_docker_volume_filters(&filters)?;
            let records = store
                .list()
                .map_err(|err| err.to_string())?
                .into_iter()
                .filter(|record| docker_volume_matches_filters(record, &filters))
                .collect::<Vec<_>>();
            if records.is_empty() {
                println!("volumes: no entries");
            } else {
                for record in records {
                    println!("{} {}", record.name, record.path);
                }
            }
        }
        VolumeCommands::Inspect { name, format } => {
            let record = store
                .get(&name)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("volume: not found {name}"))?;
            let payload = serde_json::json!({
                "Name": record.name,
                "Driver": record.driver,
                "Mountpoint": record.path,
                "CreatedAt": record.created_at_unix.to_string(),
                "Status": serde_json::Value::Null,
                "UsageData": serde_json::Value::Null,
            });
            if format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?
                );
            } else {
                println!("Name: {}", payload["Name"]);
                println!("Driver: {}", payload["Driver"]);
                println!("Mountpoint: {}", payload["Mountpoint"]);
            }
        }
        VolumeCommands::Prune { filters } => {
            let filters = parse_cli_filters(&filters)?;
            validate_docker_volume_filters(&filters)?;
            let mut deleted = Vec::new();
            for record in store
                .list()
                .map_err(|error| error.to_string())?
                .into_iter()
                .filter(|record| docker_volume_matches_filters(record, &filters))
            {
                let proof = authorization
                    .authorize_named(
                        origin,
                        AuthorizationAction::VolumeDelete,
                        ResourceKind::Volume,
                        &record.name,
                        1,
                    )
                    .map_err(|error| error.to_string())?;
                if execute_volume_remove(&store, &record.name, proof)? {
                    deleted.push(record.name);
                }
            }
            println!("volume prune: removed={}", deleted.len());
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

#[allow(dead_code)]
fn network_store_path(runtime_dir: &Path) -> PathBuf {
    crate::network_lifecycle::network_store_path(runtime_dir)
}

fn load_networks(runtime_dir: &Path) -> Result<Vec<NetworkRecord>, String> {
    crate::network_lifecycle::load_networks(runtime_dir)
}

#[allow(dead_code)]
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
        NetworkCommands::Ls { filters } => {
            let filters = parse_cli_filters(&filters)?;
            validate_docker_network_filters(&filters)?;
            let records = load_networks(runtime_dir)?
                .into_iter()
                .filter(|record| {
                    docker_network_matches_filters(
                        &DockerNetworkView {
                            name: &record.name,
                            driver: &record.driver,
                        },
                        &filters,
                    )
                })
                .collect::<Vec<_>>();
            println!("NAME\tDRIVER\tSUBNET\tGATEWAY");
            if docker_network_matches_filters(
                &DockerNetworkView {
                    name: "bridge",
                    driver: "bridge",
                },
                &filters,
            ) {
                println!("bridge\tbridge\t10.0.0.0/24\t10.0.0.1");
            }
            for record in records {
                println!(
                    "{}\t{}\t{}\t{}",
                    record.name, record.driver, record.subnet, record.gateway
                );
            }
        }
        NetworkCommands::Inspect { name, format } => {
            let payload = if name == "bridge" {
                serde_json::json!({
                    "Name": "bridge", "Id": "bridge", "Driver": "bridge",
                    "Scope": "local", "IPAM": {"Config": []}, "Containers": {}
                })
            } else {
                let record = load_networks(runtime_dir)?
                    .into_iter()
                    .find(|record| record.name == name)
                    .ok_or_else(|| format!("network: not found {name}"))?;
                let ipv6_config = docker_network_ipv6_config(&record);
                let mut ipam_config = vec![serde_json::json!({
                    "Subnet": record.subnet,
                    "Gateway": record.gateway
                })];
                if let Some(config) = ipv6_config {
                    ipam_config.push(config);
                }
                serde_json::json!({
                    "Name": record.name, "Id": record.name, "Driver": record.driver,
                    "Scope": "local", "EnableIPv6": record.ipv6_cidr.is_some(),
                    "IPAM": {"Config": ipam_config}, "Containers": {}
                })
            };
            if format == "json" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).map_err(|error| error.to_string())?
                );
            } else {
                println!("Name: {}", payload["Name"]);
                println!("Driver: {}", payload["Driver"]);
                println!("Scope: {}", payload["Scope"]);
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
        NetworkCommands::Prune { filters } => {
            let filters = parse_cli_filters(&filters)?;
            validate_docker_network_filters(&filters)?;
            let associations = runtime.list().map_err(|err| err.to_string())?;
            let records = load_networks(runtime_dir)?;
            let mut deleted = Vec::new();
            for record in records.into_iter().filter(|record| {
                !is_builtin_network_mode(&record.name)
                    && docker_network_matches_filters(
                        &DockerNetworkView {
                            name: &record.name,
                            driver: &record.driver,
                        },
                        &filters,
                    )
                    && !associations.iter().any(|container| {
                        container.network_name.as_deref() == Some(record.name.as_str())
                    })
            }) {
                let proof = authorization
                    .authorize_named(
                        origin,
                        AuthorizationAction::NetworkDelete,
                        ResourceKind::Network,
                        &record.name,
                        record.generation,
                    )
                    .map_err(|error| error.to_string())?;
                execute_network_remove(runtime_dir, &record, &associations, proof)?;
                deleted.push(record.name);
            }
            println!("network prune: removed={}", deleted.len());
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

/// Docker's image-create endpoint is a JSON stream, even when a pull has no
/// layer progress to report. Returning a terminal status keeps socket clients
/// from having to special-case Ferrocrate's formerly empty `{}` response.
fn docker_pull_status(reference: &str, lazy: bool) -> Vec<u8> {
    let status = if lazy {
        "Manifest fetched"
    } else {
        "Pull complete"
    };
    let body = serde_json::json!({
        "status": status,
        "id": reference,
    });
    format!("{}\n", body).into_bytes()
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
        ComposeCommands::Up { profile, detach: _ } => {
            // Compose is a detached CLI operation: services must outlive the
            // short-lived `compose up` launcher just like Docker daemon
            // workloads. Without this lease override, the parent-death
            // safeguard kills valid services before a subsequent `compose
            // down` can reconcile them.
            unsafe { std::env::set_var("FERROCRATE_DETACH_WORKLOAD", "1") };
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
                        detach: true,
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
    let configured_network_backend =
        std::env::var("FERROCRATE_NETWORK_BACKEND").unwrap_or_else(|_| "ebpf".to_string());
    let bind_mounts = compose_service_mounts(project_dir, volume_store, service)?;
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
            &configured_network_backend,
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
    let mount_entries = compose_service_mounts(project_dir, volume_store, service)?;
    let mounts = parse_bind_mounts(&mount_entries)?;
    let configured_network_backend = std::env::var("FERROCRATE_NETWORK_BACKEND")
        .unwrap_or_else(|_| "ebpf".to_string())
        .parse::<NetworkBackend>()
        .map_err(|error| error.to_string())?;
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
            configured_network_backend,
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
    project_dir: &Path,
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
                let resolved = project_dir.join(source).canonicalize().map_err(|error| {
                    format!("compose: bind source {source} cannot be resolved: {error}")
                })?;
                let mode = parts.next().unwrap_or("");
                if mode.is_empty() {
                    out.push(format!("{}:{target}", resolved.display()));
                } else {
                    out.push(format!("{}:{target}:{mode}", resolved.display()));
                }
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
    #[serde(rename = "Healthcheck")]
    healthcheck: Option<DockerHealthcheck>,
    #[serde(rename = "HostConfig")]
    host_config: Option<DockerHostConfig>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
struct DockerHealthcheck {
    #[serde(rename = "Test", default)]
    test: Vec<String>,
    #[serde(rename = "Interval", default)]
    interval_nanos: u64,
    #[serde(rename = "Timeout", default)]
    timeout_nanos: u64,
    #[serde(rename = "Retries", default)]
    retries: u32,
    #[serde(rename = "StartPeriod", default)]
    start_period_nanos: u64,
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
    #[serde(rename = "AutoRemove", default)]
    auto_remove: bool,
    #[serde(rename = "Memory")]
    memory: Option<i64>,
    #[serde(rename = "CpuQuota")]
    cpu_quota: Option<i64>,
    #[serde(rename = "CpuPeriod")]
    cpu_period: Option<i64>,
    #[serde(rename = "PidsLimit")]
    pids_limit: Option<i64>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize)]
struct DockerPortBinding {
    #[serde(rename = "HostPort")]
    host_port: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    auto_remove: bool,
    health: Option<DockerHealthSpec>,
    #[serde(default)]
    memory_max: Option<u64>,
    #[serde(default)]
    cpu_quota: Option<u64>,
    #[serde(default)]
    cpu_period: Option<u64>,
    #[serde(default)]
    pids_max: Option<u64>,
    #[serde(default)]
    created_at_unix: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DockerHealthSpec {
    cmd: String,
    interval_secs: u64,
    timeout_secs: u64,
    retries: u32,
    start_period_secs: u64,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct DockerExecSpec {
    container: String,
    cmd: Vec<String>,
    running: bool,
    exit_code: Option<i32>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize)]
struct DockerExecCreateRequest {
    #[serde(rename = "Cmd")]
    cmd: Vec<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Deserialize, Default)]
struct DockerExecStartRequest {
    #[serde(rename = "Detach", default)]
    detach: bool,
    #[serde(rename = "Tty", default)]
    tty: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Deserialize)]
struct DockerNetworkCreateSpec {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Driver")]
    driver: Option<String>,
    #[serde(rename = "EnableIPv6", default)]
    enable_ipv6: bool,
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
fn validate_docker_exec_command(cmd: &[String]) -> Result<(), String> {
    if cmd.is_empty() || cmd.iter().any(|arg| arg.is_empty()) {
        return Err("docker: exec Cmd must contain at least one non-empty argument".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct DockerCompatState {
    next_id: AtomicU64,
    pending: Mutex<HashMap<String, DockerCreateSpec>>,
    pending_path: PathBuf,
    execs: Mutex<HashMap<String, DockerExecSpec>>,
    events: Mutex<DockerEventStore>,
}

#[cfg(target_os = "linux")]
fn docker_compat_id(prefix: &str, sequence: &AtomicU64) -> String {
    let timestamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{prefix}{timestamp:x}-{}",
        sequence.fetch_add(1, Ordering::SeqCst)
    )
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
    /// Stable actor attributes are persisted with the event rather than
    /// reconstructed at response time. This keeps filtered/replayed events
    /// deterministic after a daemon restart.
    #[serde(default)]
    attributes: BTreeMap<String, String>,
}

#[cfg(target_os = "linux")]
struct DockerEventStore {
    path: PathBuf,
    next_id: u64,
}

#[cfg(target_os = "linux")]
impl DockerCompatState {
    fn new(runtime_dir: &Path) -> Result<Self, String> {
        let pending_path = runtime_dir.join("docker-pending.json");
        let pending = if pending_path.exists() {
            let bytes = std::fs::read(&pending_path).map_err(|error| error.to_string())?;
            serde_json::from_slice(&bytes)
                .map_err(|error| format!("docker: invalid pending state: {error}"))?
        } else {
            HashMap::new()
        };
        Ok(Self {
            next_id: AtomicU64::new(0),
            pending: Mutex::new(pending),
            pending_path,
            execs: Mutex::new(HashMap::new()),
            events: Mutex::new(DockerEventStore::open(runtime_dir.join("events.jsonl"))?),
        })
    }

    fn persist_pending(&self) -> Result<(), String> {
        let bytes = {
            let pending = self
                .pending
                .lock()
                .map_err(|error| format!("docker: pending lock poisoned: {error}"))?;
            serde_json::to_vec_pretty(&*pending).map_err(|error| error.to_string())?
        };
        let parent = self
            .pending_path
            .parent()
            .ok_or_else(|| "docker: pending state has no parent".to_string())?;
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let temp = parent.join(format!(
            ".docker-pending.{}.{}.tmp",
            std::process::id(),
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(|error| error.to_string())?;
        use std::io::Write as _;
        if let Err(error) = file.write_all(&bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp);
            return Err(error.to_string());
        }
        std::fs::rename(&temp, &self.pending_path).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            error.to_string()
        })?;
        #[cfg(unix)]
        std::fs::set_permissions(
            &self.pending_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .map_err(|error| error.to_string())?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
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

    #[allow(dead_code)]
    fn append(&mut self, method: &str, path: &str, status: u16) -> Result<(), String> {
        self.append_with_context(method, path, status, &[], &[])
    }

    fn append_with_context(
        &mut self,
        method: &str,
        path: &str,
        status: u16,
        request_body: &[u8],
        response_bytes: &[u8],
    ) -> Result<(), String> {
        let Some((event_type, action)) = docker_event_kind(method, path) else {
            return Ok(());
        };
        let resource = docker_event_resource(path).or_else(|| {
            response_body_json(response_bytes)
                .and_then(|body| {
                    body.get("Id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .filter(|id| !id.is_empty() && id.len() <= 256)
        });
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mut attributes = BTreeMap::new();
        attributes.insert("method".to_string(), method.to_string());
        attributes.insert("path".to_string(), path.to_string());
        attributes.insert("httpStatus".to_string(), status.to_string());
        attributes.insert("scope".to_string(), "local".to_string());
        attributes.extend(docker_event_request_attributes(request_body));
        attributes.extend(docker_event_response_attributes(response_bytes));
        let event = DockerEvent {
            id: self.next_id,
            time: timestamp.as_secs(),
            time_nano: timestamp.as_nanos().min(u64::MAX as u128) as u64,
            event_type: event_type.to_string(),
            action,
            scope: "local".to_string(),
            resource,
            status,
            attributes,
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
        parse_docker_event_filters(query)?;
        let contents = std::fs::read_to_string(&self.path).unwrap_or_default();
        let since = query
            .get("since")
            .map(|value| parse_event_time_bound(value, "since"))
            .transpose()?;
        let until = query
            .get("until")
            .map(|value| parse_event_time_bound(value, "until"))
            .transpose()?;
        let event = query.get("event").or_else(|| query.get("action"));
        let kind = query.get("type");
        let scope = query.get("scope");
        let direct_resources = [
            ("container", "container"),
            ("image", "image"),
            ("network", "network"),
            ("volume", "volume"),
        ];
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
        let filter_labels = filter_values("label");
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
            .filter(|item| since.is_none_or(|value| event_time_nanos(item) >= value))
            .filter(|item| until.is_none_or(|value| event_time_nanos(item) <= value))
            .filter(|item| event.is_none_or(|value| item.action == *value))
            .filter(|item| kind.is_none_or(|value| item.event_type == *value))
            .filter(|item| scope.is_none_or(|value| item.scope == *value))
            .filter(|item| {
                let mut had_filter = false;
                let matches =
                    direct_resources
                        .iter()
                        .fold(false, |matches, (query_key, event_type)| {
                            let Some(value) = query.get(*query_key) else {
                                return matches;
                            };
                            had_filter = true;
                            matches
                                || (item.event_type == *event_type
                                    && item.resource.as_deref() == Some(value.as_str()))
                        });
                !had_filter || matches
            })
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
            .filter(|item| {
                filter_labels.as_ref().is_none_or(|selectors| {
                    selectors.iter().all(|selector| {
                        let mut parts = selector.splitn(2, '=');
                        let key = parts.next().unwrap_or_default();
                        item.attributes.get(key).is_some_and(|actual| {
                            parts.next().is_none_or(|expected| actual == expected)
                        })
                    })
                })
            })
            .collect::<Vec<_>>()
            .pipe(Ok)
    }
}

#[cfg(target_os = "linux")]
fn parse_event_time_bound(value: &str, name: &str) -> Result<u64, String> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "event query parameter `{name}` must be a Unix timestamp with up to 9 fractional digits: {value}"
        ));
    }
    let seconds = seconds
        .parse::<u64>()
        .map_err(|_| format!("event query parameter `{name}` is out of range: {value}"))?;
    let fraction = format!("{fraction:0<9}")
        .parse::<u64>()
        .map_err(|_| format!("event query parameter `{name}` is invalid: {value}"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| format!("event query parameter `{name}` is out of range: {value}"))
}

#[cfg(target_os = "linux")]
fn event_time_nanos(event: &DockerEvent) -> u64 {
    if event.time_nano == 0 {
        event.time.saturating_mul(1_000_000_000)
    } else {
        event.time_nano
    }
}

#[cfg(target_os = "linux")]
fn response_body_json(response: &[u8]) -> Option<serde_json::Value> {
    let body = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .and_then(|position| response.get(position + 4..))
        .unwrap_or(response);
    serde_json::from_slice(body).ok()
}

#[cfg(target_os = "linux")]
fn docker_event_request_attributes(body: &[u8]) -> BTreeMap<String, String> {
    const MAX_ATTRIBUTES: usize = 64;
    const MAX_TEXT: usize = 256;
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return BTreeMap::new();
    };
    let Some(object) = value.as_object() else {
        return BTreeMap::new();
    };
    let mut attributes = BTreeMap::new();
    for key in ["name", "Name", "Image", "Driver", "NetworkID", "Container"] {
        if let Some(text) = object.get(key).and_then(serde_json::Value::as_str) {
            if !text.is_empty() && text.len() <= MAX_TEXT {
                attributes.insert(key.to_string(), text.to_string());
            }
        }
    }
    if let Some(labels) = object.get("Labels").and_then(serde_json::Value::as_object) {
        for (key, value) in labels.iter().take(MAX_ATTRIBUTES) {
            let Some(value) = value.as_str() else {
                continue;
            };
            if key.is_empty() || key.len() > MAX_TEXT || value.len() > MAX_TEXT {
                continue;
            }
            attributes.insert(key.clone(), value.to_string());
            if attributes.len() >= MAX_ATTRIBUTES {
                break;
            }
        }
    }
    attributes
}

#[cfg(target_os = "linux")]
fn docker_event_response_attributes(response: &[u8]) -> BTreeMap<String, String> {
    const MAX_ATTRIBUTES: usize = 64;
    const MAX_TEXT: usize = 256;
    let Some(object) = response_body_json(response).and_then(|value| value.as_object().cloned())
    else {
        return BTreeMap::new();
    };

    // Docker clients commonly use these response fields when reconstructing
    // an event actor. Keep the extraction deliberately allow-listed and
    // bounded: response bodies can contain arbitrary plugin/container data,
    // and event attributes must never become an unbounded journal sink.
    let mut attributes = BTreeMap::new();
    for key in [
        "Id",
        "ID",
        "Name",
        "Driver",
        "Mountpoint",
        "CreatedAt",
        "Status",
        "Image",
        "NetworkID",
        "Container",
    ] {
        let Some(value) = object.get(key).and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !value.is_empty() && value.len() <= MAX_TEXT {
            attributes.insert(key.to_string(), value.to_string());
        }
        if attributes.len() >= MAX_ATTRIBUTES {
            break;
        }
    }
    // Container inspect/create responses place stable image, user, working
    // directory, and labels beneath `Config`. Preserve only scalar values and
    // bounded labels so replayed event actors remain useful without turning
    // arbitrary response JSON into a journal sink.
    if let Some(config) = object.get("Config").and_then(serde_json::Value::as_object) {
        for key in ["Image", "WorkingDir", "User", "Entrypoint"] {
            if attributes.len() >= MAX_ATTRIBUTES {
                break;
            }
            if let Some(value) = config.get(key).and_then(serde_json::Value::as_str) {
                if !value.is_empty() && value.len() <= MAX_TEXT {
                    attributes.insert(key.to_string(), value.to_string());
                }
            }
        }
        if let Some(labels) = config.get("Labels").and_then(serde_json::Value::as_object) {
            for (key, value) in labels.iter().take(MAX_ATTRIBUTES) {
                if attributes.len() >= MAX_ATTRIBUTES {
                    break;
                }
                let Some(value) = value.as_str() else {
                    continue;
                };
                if !key.is_empty() && key.len() <= MAX_TEXT && value.len() <= MAX_TEXT {
                    attributes.insert(key.clone(), value.to_string());
                }
            }
        }
    }
    attributes
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
    let resource = segments
        .windows(2)
        .find(|pair| matches!(pair[0], "containers" | "images" | "networks" | "volumes"))
        .map(|pair| pair[1])?;
    if matches!(
        resource,
        "create" | "prune" | "json" | "list" | "build" | "pull" | "push"
    ) {
        return None;
    }
    Some(resource.to_string())
}

#[cfg(target_os = "linux")]
fn docker_event_payload(event: &DockerEvent) -> serde_json::Value {
    let actor = event.resource.as_ref().map(|resource| {
        let mut attributes = event.attributes.clone();
        attributes.insert("status".to_string(), event.action.clone());
        attributes.insert("httpStatus".to_string(), event.status.to_string());
        attributes.insert("scope".to_string(), event.scope.clone());
        serde_json::json!({
            "ID": resource,
            "Attributes": attributes,
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
fn handle_events(
    runtime_dir: &Path,
    since: Option<&str>,
    until: Option<&str>,
    filters: &[String],
    follow: bool,
) -> Result<(), String> {
    let mut query = HashMap::new();
    if let Some(value) = since {
        query.insert("since".to_string(), value.to_string());
    }
    if let Some(value) = until {
        query.insert("until".to_string(), value.to_string());
    }
    let mut filter_values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for filter in filters {
        let (key, value) = filter
            .split_once('=')
            .ok_or_else(|| format!("events: filter must use key=value syntax: {filter}"))?;
        if key.is_empty() || value.is_empty() {
            return Err("events: filter key and value must be non-empty".to_string());
        }
        filter_values
            .entry(key.to_string())
            .or_default()
            .push(value.to_string());
    }
    if !filter_values.is_empty() {
        query.insert(
            "filters".to_string(),
            serde_json::to_string(&filter_values)
                .map_err(|error| format!("events: encode filters failed: {error}"))?,
        );
    }
    let mut last_id = None;
    loop {
        let store = DockerEventStore::open(runtime_dir.join("events.jsonl"))?;
        for event in store.query(&query)? {
            if last_id.is_some_and(|id| event.id <= id) {
                continue;
            }
            println!(
                "{}",
                serde_json::to_string(&docker_event_payload(&event))
                    .map_err(|error| format!("events: serialize failed: {error}"))?
            );
            last_id = Some(event.id);
        }
        if !follow {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
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
    // A daemon owns the request thread independently of each workload. Keep
    // launched containers alive after the Docker API request returns; the
    // short-lived CLI path sets the same policy for detached operations.
    unsafe { std::env::set_var("FERROCRATE_DETACH_WORKLOAD", "1") };
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
    let mut event_request: Option<(String, String, Vec<u8>)> = None;
    let mut event_follow_query: Option<HashMap<String, String>> = None;
    let mut log_follow: Option<(String, Option<String>)> = None;
    let mut stats_follow: Option<String> = None;
    let mut attach_hijack: Option<(String, bool, bool, bool, bool)> = None;
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
        event_request = Some((request.method.clone(), path.clone(), request.body.clone()));
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
                // Docker Engine treats `/events` as a streaming endpoint. The
                // Docker CLI advertises JSONL/NDJSON explicitly but does not
                // add a `follow=1` query parameter, while the repository's
                // finite socket fixtures intentionally omit that header.
                let accepts_event_stream = request.headers.get("accept").is_some_and(|value| {
                    value.split(',').any(|item| {
                        let item = item.trim().to_ascii_lowercase();
                        item.contains("jsonl")
                            || item.contains("ndjson")
                            || item.contains("json-seq")
                    })
                });
                if query.get("follow").is_some_and(|value| value == "1") || accepts_event_stream {
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
            ("GET", "/system/df") => {
                let containers = runtime.list().map_err(|err| err.to_string())?;
                let images = store.list_references().map_err(|err| err.to_string())?;
                let volumes = volume_store.list().map_err(|err| err.to_string())?;
                let body = serde_json::json!({
                    "LayersSize": images.iter().map(|image| docker_manifest_layer_size(&image.manifest_json)).fold(0u64, u64::saturating_add),
                    "Images": images.iter().map(|image| serde_json::json!({
                        "Id": image.digest,
                        "RepoTags": [image.reference],
                        "Created": image.created_at_unix,
                        "Size": docker_manifest_layer_size(&image.manifest_json),
                        "SharedSize": 0,
                        "Containers": containers.iter().filter(|container| container.image == image.reference).count(),
                    })).collect::<Vec<_>>(),
                    "Containers": containers.iter().map(|container| serde_json::json!({
                        "Id": container.id,
                        "Names": container.name.as_ref().map(|name| vec![format!("/{name}")]).unwrap_or_default(),
                        "Image": container.image,
                        "ImageID": "",
                        "SizeRw": 0,
                        "SizeRootFs": 0,
                    })).collect::<Vec<_>>(),
                    "Volumes": volumes.iter().map(|volume| serde_json::json!({
                        "Name": volume.name,
                        "Mountpoint": volume.path,
                        "UsageData": {"Size": docker_directory_usage(Path::new(&volume.path)), "RefCount": 0},
                    })).collect::<Vec<_>>(),
                    "BuildCache": [],
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
                let mut entries: Vec<serde_json::Value> = records
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
                if all {
                    let pending = state
                        .pending
                        .lock()
                        .map_err(|error| format!("docker: pending lock poisoned: {error}"))?;
                    for (id, spec) in pending.iter() {
                        if !docker_pending_matches_filters(id, spec, &filters) {
                            continue;
                        }
                        let name = spec.name.as_deref().unwrap_or(id);
                        entries.push(serde_json::json!({
                            "Id": id,
                            "Image": spec.image,
                            "Command": spec.cmd.join(" "),
                            "Created": 0,
                            "State": "created",
                            "Status": "created",
                            "Names": [format!("/{name}")],
                        }));
                    }
                }
                if let Some(limit) = limit {
                    entries.truncate(limit);
                }
                let json = serde_json::to_string(&entries)
                    .unwrap_or_else(|e| format!(r#"{{"error": "json serialize failed: {e}"}}"#));
                http_response(200, json.as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/json") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/json");
                let body = match runtime.inspect(id) {
                    Ok(record) => docker_inspect_payload(&record),
                    Err(error) => {
                        let pending = state.pending.lock().map_err(|lock_error| {
                            format!("docker: pending lock poisoned: {lock_error}")
                        })?;
                        let spec = pending.get(id).ok_or_else(|| error.to_string())?;
                        docker_pending_inspect_payload(id, spec)
                    }
                };
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/changes") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/changes");
                let pending = state
                    .pending
                    .lock()
                    .map_err(|error| format!("docker: pending lock poisoned: {error}"))?
                    .contains_key(id);
                if pending && runtime.inspect(id).is_err() {
                    return Ok(http_response(200, b"[]", "application/json"));
                }
                let record = runtime.inspect(id).map_err(|error| error.to_string())?;
                let rootfs = runtime_dir
                    .join("containers")
                    .join(&record.id)
                    .join("rootfs");
                let baseline = runtime_dir
                    .join("containers")
                    .join(&record.id)
                    .join("rootfs-baseline.json");
                let excluded = record
                    .mounts
                    .iter()
                    .map(|mount| rootfs.join(&mount.target))
                    .chain(
                        record
                            .tmpfs_mounts
                            .iter()
                            .map(|mount| rootfs.join(&mount.target)),
                    )
                    .collect::<Vec<_>>();
                let changes = if rootfs.is_dir() && baseline.is_file() {
                    rootfs_diff::diff(&rootfs, &baseline, &excluded)
                        .map_err(|error| format!("docker: container diff failed: {error}"))?
                } else {
                    Vec::new()
                };
                let body = serde_json::to_string(&changes).map_err(|error| error.to_string())?;
                http_response(200, body.as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/export") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/export");
                let record = runtime.inspect(id).map_err(|error| error.to_string())?;
                if !record.mounts.is_empty() || !record.tmpfs_mounts.is_empty() {
                    return Err(
                        "docker: container export with bind or tmpfs mounts is unsupported; remove mounts before exporting"
                            .to_string(),
                    );
                }
                let rootfs = runtime_dir
                    .join("containers")
                    .join(&record.id)
                    .join("rootfs");
                if !rootfs.is_dir() {
                    return Err(format!(
                        "docker: container rootfs is unavailable: {}",
                        rootfs.display()
                    ));
                }
                let mut archive = Vec::new();
                {
                    let mut builder = tar::Builder::new(&mut archive);
                    append_commit_rootfs(&mut builder, &rootfs)
                        .map_err(|error| format!("docker: export rootfs: {error}"))?;
                    builder
                        .finish()
                        .map_err(|error| format!("docker: finish export archive: {error}"))?;
                }
                http_response(200, &archive, "application/x-tar")
            }
            ("GET", path) if path.starts_with("/containers/") && path.ends_with("/logs") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/logs");
                let tail = query.get("tail").cloned();
                let pending = state
                    .pending
                    .lock()
                    .map_err(|error| format!("docker: pending lock poisoned: {error}"))?
                    .contains_key(id);
                if pending && runtime.inspect(id).is_err() {
                    // Docker exposes an empty log stream for a created
                    // container before it has a runtime log file.
                    return Ok(http_response(200, &[], "text/plain"));
                }
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
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/attach") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/attach");
                // Docker's attach query flags are validated even though the
                // local runtime exposes its persisted combined log stream as
                // stdout. Keep the flags explicit so `logs=0` does not leak
                // historical output into a new attach session.
                for key in ["logs", "stream", "stdout", "stderr"] {
                    let _ = parse_docker_bool_query(query.get(key), key)?;
                }
                let logs_requested = query
                    .get("logs")
                    .map(|value| parse_docker_bool_query(Some(value), "logs"))
                    .transpose()?
                    .unwrap_or(false);
                let stream_requested = query
                    .get("stream")
                    .map(|value| parse_docker_bool_query(Some(value), "stream"))
                    .transpose()?
                    .unwrap_or(false);
                let stdout_requested = query
                    .get("stdout")
                    .map(|value| parse_docker_bool_query(Some(value), "stdout"))
                    .transpose()?
                    .unwrap_or(true);
                let stderr_requested = query
                    .get("stderr")
                    .map(|value| parse_docker_bool_query(Some(value), "stderr"))
                    .transpose()?
                    .unwrap_or(true);
                let pending_attach = runtime.logs(id).is_err();
                if pending_attach {
                    let pending = state
                        .pending
                        .lock()
                        .map_err(|error| format!("docker: pending lock poisoned: {error}"))?
                        .contains_key(id);
                    if !pending {
                        return Err(format!("docker: container not found: {id}"));
                    }
                }
                let (stdout, stderr) = runtime.logs_split(id).unwrap_or_default();
                let output = if logs_requested {
                    docker_raw_stream(
                        if stdout_requested { &stdout } else { "" },
                        if stderr_requested { &stderr } else { "" },
                    )
                } else {
                    Vec::new()
                };
                let upgraded = request.headers.get("connection").is_some_and(|value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                }) && request
                    .headers
                    .get("upgrade")
                    .is_some_and(|value| value.eq_ignore_ascii_case("tcp"));
                if upgraded {
                    // Docker creates and attaches before it starts a
                    // `docker run` container. Return the 101 handshake
                    // immediately for that pending record so the client can
                    // issue `/start`; running records retain live streaming.
                    if !pending_attach {
                        attach_hijack = Some((
                            id.to_string(),
                            logs_requested,
                            stream_requested,
                            stdout_requested,
                            stderr_requested,
                        ));
                    }
                    docker_hijack_headers()
                } else {
                    http_response(200, &output, "application/vnd.docker.raw-stream")
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
            ("POST", "/commit") => {
                let container = query
                    .get("container")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "docker: commit requires container".to_string())?;
                let repository = query
                    .get("repo")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| "docker: commit requires repo".to_string())?;
                let tag = query.get("tag").map(String::as_str).unwrap_or("latest");
                if tag.is_empty() {
                    return Err("docker: commit tag must be non-empty".to_string());
                }
                let last_component_has_tag = repository
                    .rsplit('/')
                    .next()
                    .is_some_and(|component| component.contains(':'));
                let reference = if repository.contains('@') || last_component_has_tag {
                    repository.clone()
                } else {
                    format!("{repository}:{tag}")
                };
                let digest = commit_image(
                    &runtime_dir,
                    &runtime,
                    &store,
                    &surface_authorization,
                    &origin,
                    container,
                    &reference,
                )?;
                let body = serde_json::json!({"Id": digest});
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("POST", "/containers/create") => {
                let name = query.get("name").cloned();
                let spec = parse_docker_create_spec(&request.body, name)?;
                let id = docker_compat_id("d", &state.next_id);
                if let Ok(mut pending) = state.pending.lock() {
                    pending.insert(id.clone(), spec);
                } else {
                    return Err("failed to acquire lock".to_string());
                }
                if let Err(error) = state.persist_pending() {
                    if let Ok(mut pending) = state.pending.lock() {
                        pending.remove(&id);
                    }
                    return Err(error);
                }
                let body = serde_json::json!({ "Id": id, "Warnings": serde_json::Value::Null });
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("POST", "/containers/prune") => {
                let filters = parse_docker_filters(&query)?;
                validate_docker_container_prune_filters(&filters)?;
                let records = runtime
                    .list()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .filter(|record| docker_container_prune_matches_filters(record, &filters))
                    .collect::<Vec<_>>();
                let mut deleted = Vec::new();
                for record in records {
                    runtime
                        .remove(&record.id)
                        .map_err(|error| error.to_string())?;
                    deleted.push(record.id);
                }
                let pending_deleted = {
                    let mut pending = state
                        .pending
                        .lock()
                        .map_err(|error| format!("docker: pending lock poisoned: {error}"))?;
                    let ids = pending
                        .iter()
                        .filter(|(id, spec)| {
                            docker_pending_prune_matches_filters(id, spec, &filters)
                        })
                        .map(|(id, _)| id.clone())
                        .collect::<Vec<_>>();
                    for id in &ids {
                        pending.remove(id);
                    }
                    ids
                };
                if !pending_deleted.is_empty() {
                    state.persist_pending()?;
                    deleted.extend(pending_deleted);
                }
                let body = serde_json::json!({
                    "ContainersDeleted": deleted,
                    "SpaceReclaimed": 0
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/exec") => {
                let container = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/exec");
                let request: DockerExecCreateRequest = serde_json::from_slice(&request.body)
                    .map_err(|error| format!("docker: invalid exec create payload: {error}"))?;
                validate_docker_exec_command(&request.cmd)?;
                runtime
                    .inspect(container)
                    .map_err(|error| error.to_string())?;
                let id = docker_compat_id("e", &state.next_id);
                state
                    .execs
                    .lock()
                    .map_err(|error| format!("docker: exec lock poisoned: {error}"))?
                    .insert(
                        id.clone(),
                        DockerExecSpec {
                            container: container.to_string(),
                            cmd: request.cmd,
                            running: false,
                            exit_code: None,
                        },
                    );
                let body = serde_json::json!({"Id": id});
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/exec/") && path.ends_with("/json") => {
                let id = path.trim_start_matches("/exec/").trim_end_matches("/json");
                let spec = state
                    .execs
                    .lock()
                    .map_err(|error| format!("docker: exec lock poisoned: {error}"))?
                    .get(id)
                    .cloned()
                    .ok_or_else(|| "not found".to_string())?;
                let body = serde_json::json!({
                    "ID": id,
                    "ContainerID": spec.container,
                    "Running": spec.running,
                    "ExitCode": spec.exit_code,
                    "Pid": 0,
                    "OpenStdin": false,
                    "OpenStderr": true,
                    "OpenStdout": true,
                    "CanRemove": false,
                    "ProcessConfig": {"entrypoint": spec.cmd.first().cloned().unwrap_or_default(), "arguments": spec.cmd},
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("POST", path) if path.starts_with("/exec/") && path.ends_with("/start") => {
                let id = path.trim_start_matches("/exec/").trim_end_matches("/start");
                let start: DockerExecStartRequest = if request.body.is_empty() {
                    DockerExecStartRequest::default()
                } else {
                    serde_json::from_slice(&request.body)
                        .map_err(|error| format!("docker: invalid exec start payload: {error}"))?
                };
                let spec = {
                    let mut execs = state
                        .execs
                        .lock()
                        .map_err(|error| format!("docker: exec lock poisoned: {error}"))?;
                    let spec = execs
                        .get_mut(id)
                        .ok_or_else(|| format!("docker: exec not found: {id}"))?;
                    if spec.running {
                        return Err(format!("docker: exec already running: {id}"));
                    }
                    spec.running = true;
                    spec.clone()
                };
                let result = match runtime.exec(&spec.container, &spec.cmd) {
                    Ok(result) => result,
                    Err(error) => {
                        if let Ok(mut execs) = state.execs.lock() {
                            if let Some(state) = execs.get_mut(id) {
                                state.running = false;
                                state.exit_code = Some(-1);
                            }
                        }
                        return Err(error.to_string());
                    }
                };
                if let Ok(mut execs) = state.execs.lock() {
                    if let Some(state) = execs.get_mut(id) {
                        state.running = false;
                        state.exit_code = Some(result.exit_code);
                    }
                }
                if start.detach {
                    http_response(200, &[], "application/vnd.docker.raw-stream")
                } else if start.tty {
                    let output = format!("{}{}", result.stdout, result.stderr);
                    http_response(200, output.as_bytes(), "application/vnd.docker.raw-stream")
                } else {
                    let output = docker_raw_stream(&result.stdout, &result.stderr);
                    http_response(200, &output, "application/vnd.docker.raw-stream")
                }
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/rename") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/rename");
                let name = query.get("name").ok_or_else(|| {
                    "docker: rename requires the name query parameter".to_string()
                })?;
                validate_docker_container_name(name)?;
                runtime
                    .rename(id, name)
                    .map_err(|error| error.to_string())?;
                http_response(204, &[], "text/plain")
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
                };
                let Some(spec) = spec else {
                    runtime.start(id).map_err(|error| error.to_string())?;
                    return Ok(http_response(204, &[], "text/plain"));
                };
                state.persist_pending()?;
                let health = spec.health.as_ref();
                let network_backend = std::env::var("FERROCRATE_NETWORK_BACKEND")
                    .unwrap_or_else(|_| "ebpf".to_string());
                validate_network_backend(&network_backend)?;
                let start_result = handle_run(
                    runtime_dir.as_ref(),
                    &runtime,
                    &store,
                    &volume_store,
                    &spec.image,
                    &spec.cmd,
                    &spec.network_mode,
                    &network_backend,
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
                    health.map(|value| value.cmd.as_str()),
                    health.map(|value| value.interval_secs),
                    health.map(|value| value.timeout_secs),
                    health.map(|value| value.retries),
                    health.map(|value| value.start_period_secs),
                    "no",
                    spec.auto_remove,
                    None,
                    None,
                    None,
                    spec.memory_max,
                    spec.cpu_quota,
                    spec.cpu_period,
                    spec.pids_max,
                    None,
                    None,
                    Some(id),
                );
                if let Err(error) = start_result {
                    if let Ok(mut pending) = state.pending.lock() {
                        pending.insert(id.to_string(), spec);
                    }
                    let _ = state.persist_pending();
                    return Err(error);
                }
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/stop") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/stop");
                let timeout = parse_docker_stop_timeout(&query)?;
                runtime.stop(id, timeout).map_err(|err| err.to_string())?;
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/restart") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/restart");
                let timeout = parse_docker_stop_timeout(&query)?;
                runtime
                    .restart(id, timeout)
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
                let signal = parse_docker_kill_signal(query.get("signal"))?;
                runtime
                    .kill_with_signal(id, signal)
                    .map_err(|err| err.to_string())?;
                http_response(204, &[], "text/plain")
            }
            ("POST", path) if path.starts_with("/containers/") && path.ends_with("/wait") => {
                let id = path
                    .trim_start_matches("/containers/")
                    .trim_end_matches("/wait");
                let condition = query
                    .get("condition")
                    .map(String::as_str)
                    .unwrap_or("not-running");
                if !matches!(condition, "not-running" | "next-exit" | "removed") {
                    return Err(format!(
                        "docker: wait condition is unsupported: {condition}"
                    ));
                }
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
                // Docker CLI issues `/wait?condition=removed` concurrently
                // with `/start`, while the create record is still pending.
                // Reconcile that pre-start window before evaluating exit or
                // removal instead of returning a false 404.
                let prestart_deadline = timeout
                    .map(|value| Instant::now() + value)
                    .unwrap_or_else(|| Instant::now() + Duration::from_secs(30));
                let mut observed = false;
                loop {
                    match runtime.inspect(id) {
                        Ok(_) => {
                            observed = true;
                            if condition != "removed" {
                                break;
                            }
                        }
                        Err(error) => {
                            let pending = state
                                .pending
                                .lock()
                                .map_err(|lock_error| {
                                    format!("docker: pending lock poisoned: {lock_error}")
                                })?
                                .contains_key(id);
                            if condition != "removed" && !pending {
                                // A missing container cannot ever satisfy a
                                // non-removal wait condition. Return the
                                // Docker-compatible 404 immediately instead
                                // of polling for the default 30-second
                                // pre-start window.
                                return Err(error.to_string());
                            }
                            if condition == "removed" && !observed && pending {
                                // Docker CLI sends wait before start. Return
                                // the provisional removed result so it can
                                // issue `/start`; the auto-remove start path
                                // owns the eventual deletion.
                                break;
                            }
                            if condition == "removed" && (observed || !pending) {
                                break;
                            }
                            if Instant::now() >= prestart_deadline {
                                return Err(error.to_string());
                            }
                        }
                    }
                    if condition == "removed" && observed {
                        // Keep polling until the auto-remove start path makes
                        // the record disappear.
                        std::thread::sleep(Duration::from_millis(25));
                    }
                }
                let record = runtime.inspect(id).ok();
                if condition != "removed" {
                    wait_for_container_exit_with_timeout(&runtime, id, timeout)?;
                }
                let body = serde_json::json!({
                    "StatusCode": record.and_then(|value| value.last_exit_code).unwrap_or(0),
                    "Error": serde_json::Value::Null
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("DELETE", path) if path.starts_with("/containers/") => {
                let id = path.trim_start_matches("/containers/");
                let force = parse_docker_bool_query(query.get("force"), "force")?;
                let removed_pending = state
                    .pending
                    .lock()
                    .map_err(|error| format!("docker: pending lock poisoned: {error}"))?
                    .remove(id)
                    .is_some();
                if removed_pending {
                    state.persist_pending()?;
                    http_response(204, &[], "text/plain")
                } else {
                    if let Ok(record) = runtime.inspect(id) {
                        if record.status == "running" {
                            if !force {
                                return Err(format!("container {id} is still running"));
                            }
                            runtime
                                .kill_with_signal(id, Some(nix::sys::signal::Signal::SIGKILL))
                                .map_err(|error| error.to_string())?;
                        }
                    }
                    runtime.remove(id).map_err(|err| err.to_string())?;
                    http_response(204, &[], "text/plain")
                }
            }
            ("GET", "/images/json") => {
                let filters = parse_docker_filters(&query)?;
                let mut images = store.list_references().map_err(|err| err.to_string())?;
                images.retain(|record| docker_image_matches_filters(record, &filters));
                images = docker_image_apply_time_bounds(images, &filters)?;
                images.sort_by(|left, right| {
                    right
                        .created_at_unix
                        .cmp(&left.created_at_unix)
                        .then_with(|| right.reference.cmp(&left.reference))
                });
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
            ("POST", "/build") => {
                let dockerfile = query
                    .get("dockerfile")
                    .map(String::as_str)
                    .unwrap_or("Dockerfile");
                let dockerfile_path = Path::new(dockerfile);
                if dockerfile_path.is_absolute()
                    || dockerfile_path.components().any(|component| {
                        matches!(component, Component::ParentDir | Component::Prefix(_))
                    })
                {
                    return Err(
                        "docker build: Dockerfile path must stay within the build context"
                            .to_string(),
                    );
                }
                let temp = tempfile::Builder::new()
                    .prefix("api-build-")
                    .tempdir_in(runtime_dir.as_ref())
                    .map_err(|error| {
                        format!("docker build: create context directory failed: {error}")
                    })?;
                extract_docker_build_context(&request.body, temp.path())?;
                let dockerfile_path = temp.path().join(dockerfile_path);
                if !dockerfile_path.is_file() {
                    return Err(format!("docker build: Dockerfile not found: {dockerfile}"));
                }
                let tag = query.get("t").map(String::as_str);
                handle_build(
                    &store,
                    &origin,
                    &surface_authorization,
                    Some(
                        dockerfile_path.to_str().ok_or_else(|| {
                            "docker build: Dockerfile path is not UTF-8".to_string()
                        })?,
                    ),
                    None,
                    tag,
                    "gzip",
                    "oci",
                    None,
                    None,
                    None,
                    None,
                    &[],
                    &[],
                )?;
                http_response(
                    200,
                    br#"{"stream":"Successfully built"}
"#,
                    "application/json",
                )
            }
            ("GET", "/networks") => {
                let filters = parse_docker_filters(&query)?;
                validate_docker_network_filters(&filters)?;
                let networks = load_networks(runtime_dir.as_ref())?;
                let mut entries = Vec::new();
                if docker_network_matches_filters(
                    &DockerNetworkView {
                        name: "bridge",
                        driver: "bridge",
                    },
                    &filters,
                ) {
                    entries.push(serde_json::json!({
                        "Name": "bridge",
                        "Id": "bridge",
                        "Driver": "bridge",
                        "Scope": "local",
                    }));
                }
                entries.extend(networks.into_iter().filter_map(|record| {
                    docker_network_matches_filters(
                        &DockerNetworkView {
                            name: &record.name,
                            driver: &record.driver,
                        },
                        &filters,
                    )
                    .then(|| {
                        let ipv6_config = docker_network_ipv6_config(&record);
                        let mut ipam_config = vec![serde_json::json!({
                            "Subnet": record.subnet,
                            "Gateway": record.gateway
                        })];
                        if let Some(config) = ipv6_config {
                            ipam_config.push(config);
                        }
                        serde_json::json!({
                            "Name": record.name,
                            "Id": record.name,
                            "Driver": record.driver,
                            "Scope": "local",
                            "IPAM": {
                                "Config": ipam_config
                            }
                        })
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
                    let ipv6_config = docker_network_ipv6_config(&record);
                    let mut ipam_config = vec![serde_json::json!({
                        "Subnet": record.subnet,
                        "Gateway": record.gateway
                    })];
                    if let Some(config) = ipv6_config {
                        ipam_config.push(config);
                    }
                    let body = serde_json::json!({
                        "Name": record.name, "Id": record.name, "Driver": record.driver,
                        "Scope": "local",
                        "EnableIPv6": record.ipv6_cidr.is_some(),
                        "IPAM": {"Config": ipam_config},
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
                let configs = spec
                    .ipam
                    .as_ref()
                    .map(|ipam| ipam.config.as_slice())
                    .unwrap_or(&[]);
                let ipv4 = configs.iter().find(|cfg| {
                    cfg.subnet
                        .as_deref()
                        .is_none_or(|subnet| !subnet.contains(':'))
                });
                let ipv6 = configs.iter().find(|cfg| {
                    cfg.subnet
                        .as_deref()
                        .is_some_and(|subnet| subnet.contains(':'))
                });
                if spec.enable_ipv6 && ipv6.is_none() {
                    return Err(
                        "docker: EnableIPv6 requires an IPv6 IPAM subnet in the request"
                            .to_string(),
                    );
                }
                let subnet = ipv4.and_then(|cfg| cfg.subnet.clone());
                let gateway = ipv4.and_then(|cfg| cfg.gateway.clone());
                let ipv6_subnet = ipv6.and_then(|cfg| cfg.subnet.clone());
                let ipv6_gateway = ipv6.and_then(|cfg| cfg.gateway.clone());
                handle_network_authorized(
                    runtime_dir.as_ref(),
                    &runtime,
                    NetworkCommands::Create {
                        name: spec.name.clone(),
                        subnet,
                        gateway,
                        ipv6_subnet,
                        ipv6_gateway,
                    },
                    &origin,
                    &surface_authorization,
                )?;
                let body = serde_json::json!({ "Id": spec.name, "Warning": "" });
                http_response(201, body.to_string().as_bytes(), "application/json")
            }
            ("POST", "/networks/prune") => {
                let filters = parse_docker_filters(&query)?;
                validate_docker_network_filters(&filters)?;
                let associations = runtime.list().map_err(|error| error.to_string())?;
                let records = load_networks(runtime_dir.as_ref())?
                    .into_iter()
                    .filter(|record| {
                        docker_network_matches_filters(
                            &DockerNetworkView {
                                name: &record.name,
                                driver: &record.driver,
                            },
                            &filters,
                        )
                    })
                    .collect::<Vec<_>>();
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
                let encoded_name = path
                    .trim_start_matches("/images/")
                    .trim_end_matches("/json");
                let name = percent_decode_query_component(encoded_name)?;
                let reference = resolve_reference(&store, &name)
                    .map_err(|err| err.to_string())?
                    .ok_or_else(|| format!("docker: unknown image {name}"))?;
                let body = serde_json::json!({
                    "Id": reference.digest,
                    "RepoTags": vec![reference.reference],
                    "Created": docker_timestamp(reference.created_at_unix),
                    "Size": docker_manifest_layer_size(&reference.manifest_json),
                    "VirtualSize": docker_manifest_layer_size(&reference.manifest_json)
                });
                http_response(200, body.to_string().as_bytes(), "application/json")
            }
            ("GET", path) if path.starts_with("/images/") && path.ends_with("/history") => {
                let encoded_name = path
                    .trim_start_matches("/images/")
                    .trim_end_matches("/history");
                let name = percent_decode_query_component(encoded_name)?;
                let reference = resolve_reference(&store, &name)
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
                let lazy = query
                    .get("lazy")
                    .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"));
                handle_pull_authorized(&store, &reference, lazy, &origin, &surface_authorization)?;
                let body = docker_pull_status(&reference, lazy);
                http_response(200, &body, "application/json")
            }
            ("POST", "/plugins/pull") => docker_error_response(
                404,
                "docker: plugin pull is unsupported; install a signed local plugin manifest",
            ),
            ("POST", path) if path.starts_with("/images/") && path.ends_with("/push") => {
                let encoded = path
                    .trim_start_matches("/images/")
                    .trim_end_matches("/push");
                let reference = percent_decode_query_component(encoded)?;
                handle_push(&store, &reference)?;
                http_response(200, b"{}", "application/json")
            }
            ("POST", "/images/prune") => {
                let filters = parse_docker_filters(&query)?;
                validate_docker_image_prune_filters(&filters)?;
                let records = store
                    .list_references()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .filter(|record| docker_image_prune_matches_filters(record, &filters))
                    .collect::<Vec<_>>();
                let deleted = records
                    .iter()
                    .map(|record| record.reference.clone())
                    .collect::<Vec<_>>();
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
                    "ImagesDeleted": deleted,
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
                let filters = parse_docker_filters(&query)?;
                validate_docker_volume_filters(&filters)?;
                let records = volume_store
                    .list()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .filter(|record| docker_volume_matches_filters(record, &filters))
                    .collect::<Vec<_>>();
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
                let filters = parse_docker_filters(&query)?;
                validate_docker_volume_filters(&filters)?;
                let volumes = volume_store
                    .list()
                    .map_err(|error| error.to_string())?
                    .into_iter()
                    .filter(|record| docker_volume_matches_filters(record, &filters))
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
    if let Some((id, logs_requested, stream_requested, stdout_requested, stderr_requested)) =
        attach_hijack
    {
        let follow_runtime =
            ContainerRuntime::new(&runtime_dir).map_err(|error| error.to_string())?;
        stream_docker_attach(
            &mut stream,
            &follow_runtime,
            &id,
            logs_requested,
            stream_requested,
            stdout_requested,
            stderr_requested,
        )?;
        return Ok(());
    }
    if let Some((method, path, request_body)) = event_request {
        let status = response
            .get(..)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| text.lines().next())
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(500);
        if let Ok(mut events) = state.events.lock() {
            let _ = events.append_with_context(&method, &path, status, &request_body, &response);
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
    if lowered.contains("still running") {
        return 409;
    }
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
        || lowered.contains("requires ")
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

/// Parse Docker's stop/restart grace period (`t`) in seconds.
///
/// Docker defaults this value to ten seconds, accepts zero for an immediate
/// escalation, and uses `-1` for an unbounded graceful wait.  The latter is
/// represented internally by `Duration::MAX`; the process lifecycle handles
/// that sentinel without overflowing an `Instant` calculation.
fn parse_docker_stop_timeout(query: &HashMap<String, String>) -> Result<Duration, String> {
    let Some(value) = query.get("t") else {
        return Ok(Duration::from_secs(10));
    };
    let seconds = value
        .parse::<i64>()
        .map_err(|_| format!("docker: stop timeout must be an integer, got {value}"))?;
    if seconds == -1 {
        return Ok(Duration::MAX);
    }
    if seconds < 0 {
        return Err(format!(
            "docker: stop timeout must be non-negative or -1, got {value}"
        ));
    }
    Ok(Duration::from_secs(seconds as u64))
}

fn parse_docker_kill_signal(value: Option<&String>) -> Result<Option<Signal>, String> {
    let raw = value.map(String::as_str).unwrap_or("SIGKILL");
    let normalized = raw.to_ascii_uppercase();
    let normalized = normalized.strip_prefix("SIG").unwrap_or(&normalized);
    if normalized == "0" {
        return Ok(None);
    }
    let signal = match normalized {
        "HUP" => Ok(Signal::SIGHUP),
        "INT" => Ok(Signal::SIGINT),
        "QUIT" => Ok(Signal::SIGQUIT),
        "KILL" => Ok(Signal::SIGKILL),
        "TERM" => Ok(Signal::SIGTERM),
        "USR1" => Ok(Signal::SIGUSR1),
        "USR2" => Ok(Signal::SIGUSR2),
        "CONT" => Ok(Signal::SIGCONT),
        "STOP" => Ok(Signal::SIGSTOP),
        "TSTP" => Ok(Signal::SIGTSTP),
        "" => Err("docker: kill signal must not be empty".to_string()),
        other => other
            .parse::<i32>()
            .map_err(|_| format!("docker: unsupported kill signal: {raw}"))
            .and_then(|number| {
                Signal::try_from(number)
                    .map_err(|_| format!("docker: unsupported kill signal: {raw}"))
            }),
    };
    signal
        .map(Some)
        .map_err(|_| format!("docker: unsupported kill signal: {raw}"))
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
        let values = match values {
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("docker: filter {key} values must be strings"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::Value::Object(values) => values
                .iter()
                .map(|(name, enabled)| {
                    if enabled.as_bool() == Some(true) {
                        Ok(name.clone())
                    } else {
                        Err(format!(
                            "docker: filter {key} object values must be boolean true"
                        ))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(format!(
                    "docker: filter {key} must be an array or boolean object"
                ));
            }
        };
        filters.insert(key.clone(), values);
    }
    Ok(filters)
}

/// Docker's events client emits a scalar or boolean-keyed object for one
/// `--filter` value (for example `{"type":{"network":true}}`), while
/// listing endpoints conventionally use arrays. Normalize all event forms at
/// this boundary.
fn parse_docker_event_filters(
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
    for (key, value) in object {
        let values = match value {
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("docker: filter {key} values must be strings"))
                })
                .collect::<Result<Vec<_>, _>>()?,
            serde_json::Value::String(value) => vec![value.clone()],
            serde_json::Value::Object(values) => values
                .iter()
                .map(|(name, enabled)| {
                    if enabled.as_bool() == Some(true) {
                        Ok(name.clone())
                    } else {
                        Err(format!(
                            "docker: filter {key} object values must be boolean true"
                        ))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => {
                return Err(format!(
                    "docker: filter {key} must be a string, boolean object, or array"
                ));
            }
        };
        filters.insert(key.clone(), values);
    }
    Ok(filters)
}

fn parse_cli_filters(values: &[String]) -> Result<HashMap<String, Vec<String>>, String> {
    let mut filters = HashMap::new();
    for value in values {
        let (key, filter_value) = value
            .split_once('=')
            .ok_or_else(|| format!("image prune: filter must use key=value syntax: {value}"))?;
        if key.is_empty() || filter_value.is_empty() {
            return Err("image prune: filter key and value must be non-empty".to_string());
        }
        filters
            .entry(key.to_string())
            .or_insert_with(Vec::new)
            .push(filter_value.to_string());
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
                .is_some_and(|actual| parts.next().is_none_or(|expected| actual == expected));
            if !matched {
                return false;
            }
        }
    }
    true
}

fn validate_docker_container_filters(filters: &HashMap<String, Vec<String>>) -> Result<(), String> {
    for key in filters.keys() {
        if !matches!(key.as_str(), "status" | "name" | "ancestor" | "label") {
            return Err(format!(
                "docker: container filter `{key}` is unsupported; supported filters: status, name, ancestor, label"
            ));
        }
    }
    Ok(())
}

fn validate_docker_container_prune_filters(
    filters: &HashMap<String, Vec<String>>,
) -> Result<(), String> {
    for key in filters.keys() {
        if !matches!(key.as_str(), "label" | "until") {
            return Err(format!(
                "docker: container prune filter `{key}` is unsupported; supported filters: label, until"
            ));
        }
    }
    if let Some(values) = filters.get("until") {
        if values.len() > 1 {
            return Err(
                "docker: container prune until filter accepts at most one selector".to_string(),
            );
        }
        if let Some(value) = values.first() {
            value.parse::<u64>().map_err(|_| {
                format!("docker: container prune until filter must be a Unix timestamp: {value}")
            })?;
        }
    }
    Ok(())
}

fn docker_container_prune_matches_filters(
    record: &ferro_core::container_store::ContainerRecord,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    if matches!(record.status.as_str(), "running" | "paused") {
        return false;
    }
    if let Some(until) = filters.get("until").and_then(|values| values.first()) {
        let Ok(until) = until.parse::<u64>() else {
            return false;
        };
        if record.created_at_unix >= until {
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
                .is_some_and(|actual| parts.next().is_none_or(|expected| actual == expected));
            if !matched {
                return false;
            }
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn docker_pending_matches_filters(
    id: &str,
    spec: &DockerCreateSpec,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    let matches_any = |key: &str, value: &str| {
        filters
            .get(key)
            .map(|values| values.is_empty() || values.iter().any(|candidate| candidate == value))
            .unwrap_or(true)
    };
    if !matches_any("status", "created") {
        return false;
    }
    if let Some(names) = filters.get("name") {
        let name = spec.name.as_deref().unwrap_or(id);
        if !names.is_empty() && !names.iter().any(|candidate| name.contains(candidate)) {
            return false;
        }
    }
    if let Some(images) = filters.get("ancestor") {
        if !images
            .iter()
            .any(|candidate| spec.image == *candidate || spec.image.starts_with(candidate))
        {
            return false;
        }
    }
    if let Some(labels) = filters.get("label") {
        for selector in labels {
            let mut parts = selector.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let matched = spec.labels.iter().any(|entry| {
                let Some((actual_key, actual_value)) = entry.split_once('=') else {
                    return false;
                };
                actual_key == key && parts.next().is_none_or(|expected| actual_value == expected)
            });
            if !matched {
                return false;
            }
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn docker_pending_prune_matches_filters(
    _id: &str,
    spec: &DockerCreateSpec,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    if let Some(until) = filters.get("until").and_then(|values| values.first()) {
        let Ok(until) = until.parse::<u64>() else {
            return false;
        };
        if spec.created_at_unix == 0 || spec.created_at_unix >= until {
            return false;
        }
    }
    if let Some(labels) = filters.get("label") {
        for selector in labels {
            let mut parts = selector.splitn(2, '=');
            let key = parts.next().unwrap_or_default();
            let matched = spec.labels.iter().any(|entry| {
                let Some((actual_key, actual_value)) = entry.split_once('=') else {
                    return false;
                };
                actual_key == key && parts.next().is_none_or(|expected| actual_value == expected)
            });
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

fn docker_image_matches_filters(
    record: &ferro_core::image_store::ImageRecord,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    let Some(references) = filters.get("reference") else {
        return true;
    };
    references.is_empty()
        || references.iter().any(|candidate| {
            candidate == &record.reference
                || candidate == &record.digest
                || candidate
                    .strip_suffix('*')
                    .is_some_and(|prefix| record.reference.starts_with(prefix))
        })
}

fn validate_docker_image_filters(filters: &HashMap<String, Vec<String>>) -> Result<(), String> {
    for key in filters.keys() {
        if !matches!(key.as_str(), "reference" | "since" | "before") {
            return Err(format!(
                "docker: image filter `{key}` is unsupported; supported filters: reference, since, before"
            ));
        }
    }
    Ok(())
}

fn validate_docker_image_prune_filters(
    filters: &HashMap<String, Vec<String>>,
) -> Result<(), String> {
    for key in filters.keys() {
        if !matches!(key.as_str(), "dangling" | "until") {
            return Err(format!(
                "docker: image prune filter `{key}` is unsupported; supported filters: dangling, until"
            ));
        }
    }
    if let Some(values) = filters.get("dangling") {
        if values.len() > 1
            || values
                .first()
                .is_some_and(|value| !matches!(value.as_str(), "true" | "false"))
        {
            return Err("docker: image prune dangling filter must be true or false".to_string());
        }
    }
    if let Some(values) = filters.get("until") {
        if values.len() > 1 {
            return Err(
                "docker: image prune until filter accepts at most one selector".to_string(),
            );
        }
        if let Some(value) = values.first() {
            value.parse::<u64>().map_err(|_| {
                format!("docker: image prune until filter must be a Unix timestamp: {value}")
            })?;
        }
    }
    Ok(())
}

fn docker_image_prune_matches_filters(
    record: &ferro_core::image_store::ImageRecord,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    if let Some(value) = filters.get("dangling").and_then(|values| values.first()) {
        let dangling =
            record.reference.starts_with("sha256:") || record.reference.contains("@sha256:");
        if dangling != (value == "true") {
            return false;
        }
    }
    if let Some(value) = filters.get("until").and_then(|values| values.first()) {
        let Ok(until) = value.parse::<u64>() else {
            return false;
        };
        if record.created_at_unix >= until {
            return false;
        }
    }
    true
}

fn docker_volume_matches_filters(
    record: &ferro_core::volume_store::VolumeRecord,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    if let Some(names) = filters.get("name") {
        if !names.is_empty()
            && !names
                .iter()
                .any(|candidate| record.name.contains(candidate))
        {
            return false;
        }
    }
    if let Some(drivers) = filters.get("driver") {
        if !drivers.is_empty() && !drivers.iter().any(|candidate| candidate == &record.driver) {
            return false;
        }
    }
    true
}

fn validate_docker_volume_filters(filters: &HashMap<String, Vec<String>>) -> Result<(), String> {
    for key in filters.keys() {
        if !matches!(key.as_str(), "name" | "driver") {
            return Err(format!(
                "docker: volume filter `{key}` is unsupported; supported filters: name, driver"
            ));
        }
    }
    Ok(())
}

struct DockerNetworkView<'a> {
    name: &'a str,
    driver: &'a str,
}

fn docker_network_matches_filters(
    record: &DockerNetworkView<'_>,
    filters: &HashMap<String, Vec<String>>,
) -> bool {
    let name_matches = filters.get("name").is_none_or(|values| {
        values.is_empty() || values.iter().any(|value| record.name.contains(value))
    });
    let driver_matches = filters.get("driver").is_none_or(|values| {
        values.is_empty() || values.iter().any(|value| value == record.driver)
    });
    let scope_matches = filters
        .get("scope")
        .is_none_or(|values| values.is_empty() || values.iter().any(|value| value == "local"));
    let type_matches = filters.get("type").is_none_or(|values| {
        values.is_empty()
            || values.iter().any(|value| {
                (value == "builtin" && record.name == "bridge")
                    || (value == "custom" && record.name != "bridge")
            })
    });
    name_matches && driver_matches && scope_matches && type_matches
}

#[cfg(target_os = "linux")]
fn docker_network_ipv6_config(record: &NetworkRecord) -> Option<serde_json::Value> {
    let (gateway, prefix) = record.ipv6_cidr.as_deref()?.split_once('/')?;
    let gateway = gateway.parse::<std::net::Ipv6Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix > 128 {
        return None;
    }
    let subnet = ipv6_network_addr(gateway, prefix);
    Some(serde_json::json!({
        "Subnet": format!("{subnet}/{prefix}"),
        "Gateway": gateway.to_string(),
    }))
}

fn validate_docker_network_filters(filters: &HashMap<String, Vec<String>>) -> Result<(), String> {
    for key in filters.keys() {
        if !matches!(key.as_str(), "name" | "driver" | "scope" | "type") {
            return Err(format!(
                "docker: network filter `{key}` is unsupported; supported filters: name, driver, scope, type"
            ));
        }
    }
    Ok(())
}

fn docker_image_apply_time_bounds(
    images: Vec<ferro_core::image_store::ImageRecord>,
    filters: &HashMap<String, Vec<String>>,
) -> Result<Vec<ferro_core::image_store::ImageRecord>, String> {
    let resolve = |selector: &str| {
        selector.parse::<u64>().ok().or_else(|| {
            images.iter().find_map(|record| {
                (record.reference == selector || record.digest == selector)
                    .then_some(record.created_at_unix)
            })
        })
    };
    let bound = |key: &str| -> Result<Option<u64>, String> {
        let values = filters.get(key).cloned().unwrap_or_default();
        if values.len() > 1 {
            return Err(format!(
                "docker: image filter {key} accepts at most one selector"
            ));
        }
        values.first().map_or(Ok(None), |selector| {
            resolve(selector)
                .map(Some)
                .ok_or_else(|| format!("docker: image filter {key} selector not found: {selector}"))
        })
    };
    let since = bound("since")?;
    let before = bound("before")?;
    Ok(images
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
    let name = name
        .map(|name| validate_docker_container_name(&name).map(|_| name))
        .transpose()?;
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
        auto_remove: false,
        memory: None,
        cpu_quota: None,
        cpu_period: None,
        pids_limit: None,
    });
    let publish = port_bindings_to_publish(host_config.port_bindings)?;
    let network_mode = match host_config.network_mode.as_deref() {
        None | Some("default") | Some("bridge") => "bridge".to_string(),
        Some("host") => "host".to_string(),
        Some("none") => "none".to_string(),
        Some(other) => return Err(format!("docker: unsupported network mode {other}")),
    };
    let health = parse_docker_healthcheck(request.healthcheck)?;
    let memory_max = normalize_docker_limit(host_config.memory, "Memory")?;
    let cpu_quota = normalize_docker_limit(host_config.cpu_quota, "CpuQuota")?;
    let cpu_period = normalize_docker_limit(host_config.cpu_period, "CpuPeriod")?;
    let pids_max = normalize_docker_limit(host_config.pids_limit, "PidsLimit")?;
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
        auto_remove: host_config.auto_remove,
        health,
        memory_max,
        cpu_quota,
        cpu_period,
        pids_max,
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0),
    })
}

#[cfg(target_os = "linux")]
fn normalize_docker_limit(value: Option<i64>, field: &str) -> Result<Option<u64>, String> {
    match value {
        None | Some(0) => Ok(None),
        Some(value) if value > 0 => Ok(Some(value as u64)),
        Some(-1) if field == "PidsLimit" => Ok(None),
        Some(_) => Err(format!(
            "docker: {field} must be zero, positive, or -1 for PidsLimit"
        )),
    }
}

#[cfg(target_os = "linux")]
fn parse_docker_healthcheck(
    healthcheck: Option<DockerHealthcheck>,
) -> Result<Option<DockerHealthSpec>, String> {
    let Some(healthcheck) = healthcheck else {
        return Ok(None);
    };
    let Some(kind) = healthcheck.test.first().map(String::as_str) else {
        return Err("docker: Healthcheck.Test must contain a command or NONE".to_string());
    };
    if kind == "NONE" {
        if healthcheck.test.len() != 1 {
            return Err("docker: Healthcheck NONE must not include a command".to_string());
        }
        return Ok(None);
    }
    let cmd = match kind {
        "CMD-SHELL" => healthcheck
            .test
            .get(1)
            .filter(|command| !command.trim().is_empty())
            .cloned()
            .ok_or_else(|| "docker: CMD-SHELL healthcheck requires a command".to_string())?,
        "CMD" => {
            let args = healthcheck.test.get(1..).unwrap_or_default();
            if args.is_empty() || args.iter().any(|arg| arg.trim().is_empty()) {
                return Err("docker: CMD healthcheck requires non-empty arguments".to_string());
            }
            args.iter()
                .map(|arg| shell_quote_health_arg(arg))
                .collect::<Vec<_>>()
                .join(" ")
        }
        other => return Err(format!("docker: unsupported Healthcheck.Test mode {other}")),
    };
    Ok(Some(DockerHealthSpec {
        cmd,
        interval_secs: duration_nanos_to_secs(healthcheck.interval_nanos, "Interval")?,
        timeout_secs: duration_nanos_to_secs(healthcheck.timeout_nanos, "Timeout")?,
        retries: healthcheck.retries.max(1),
        start_period_secs: duration_nanos_to_secs(healthcheck.start_period_nanos, "StartPeriod")?,
    }))
}

#[cfg(target_os = "linux")]
fn duration_nanos_to_secs(value: u64, field: &str) -> Result<u64, String> {
    if value == 0 {
        return Ok(match field {
            "Interval" => 30,
            "Timeout" => 5,
            _ => 0,
        });
    }
    let seconds = value.div_ceil(1_000_000_000);
    if seconds == 0 {
        return Err(format!("docker: Healthcheck.{field} is too small"));
    }
    Ok(seconds)
}

#[cfg(target_os = "linux")]
fn shell_quote_health_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(target_os = "linux")]
fn validate_docker_container_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 128 {
        return Err("docker: container name must contain 1-128 characters".to_string());
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err("docker: container name contains unsupported characters".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn docker_inspect_payload(
    record: &ferro_core::container_store::ContainerRecord,
) -> serde_json::Value {
    let name = record.name.clone().unwrap_or_else(|| record.id.clone());
    let health = record.health.as_ref().map(|_| {
        serde_json::json!({
            "Status": record.health_status.clone(),
            "FailingStreak": record.health_failures,
            "Log": [],
        })
    });
    serde_json::json!({
        "Id": record.id,
        "Name": format!("/{name}"),
        "Image": record.image,
        "Config": {
            "Env": record.env,
            "Cmd": record.command,
            "WorkingDir": record.workdir,
            "User": record.user,
            "Labels": record.labels,
            "Healthcheck": record.health.as_ref().map(docker_runtime_healthcheck),
        },
        "HostConfig": {
            "Memory": record
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.memory_max)
                .unwrap_or(0),
            "CpuQuota": record
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.cpu_quota)
                .unwrap_or(0),
            "CpuPeriod": record
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.cpu_period)
                .unwrap_or(0),
            "PidsLimit": record
                .resource_limits
                .as_ref()
                .and_then(|limits| limits.pids_max)
                .unwrap_or(0),
        },
        "State": {
            "Status": record.status,
            "Pid": record.pid,
            "ExitCode": record.last_exit_code,
            "StartedAt": docker_timestamp(record.created_at_unix),
            "Health": health,
        }
    })
}

#[cfg(target_os = "linux")]
fn docker_timestamp(unix_seconds: u64) -> String {
    // Convert Unix seconds without adding a formatting dependency to the CLI.
    // The date conversion follows the proleptic Gregorian civil calendar.
    let seconds = unix_seconds.min(i64::MAX as u64) as i64;
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000000000Z")
}

#[cfg(target_os = "linux")]
fn docker_pending_inspect_payload(id: &str, spec: &DockerCreateSpec) -> serde_json::Value {
    let labels = spec
        .labels
        .iter()
        .filter_map(|entry| entry.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<BTreeMap<_, _>>();
    serde_json::json!({
        "Id": id,
        "Name": format!("/{}", spec.name.as_deref().unwrap_or(id)),
        "Image": spec.image,
        "Config": {
            "Env": spec.env,
            "Cmd": spec.cmd,
            "WorkingDir": spec.workdir,
            "User": spec.user,
            "Labels": labels,
            "Healthcheck": spec.health.as_ref().map(docker_pending_healthcheck),
        },
        "HostConfig": {
            "Memory": spec.memory_max.unwrap_or(0),
            "CpuQuota": spec.cpu_quota.unwrap_or(0),
            "CpuPeriod": spec.cpu_period.unwrap_or(0),
            "PidsLimit": spec.pids_max.unwrap_or(0),
        },
        "State": {
            "Status": "created",
            "Pid": 0,
            "ExitCode": 0,
            "StartedAt": docker_timestamp(0),
            "Health": serde_json::Value::Null,
        }
    })
}

#[cfg(target_os = "linux")]
fn docker_pending_healthcheck(health: &DockerHealthSpec) -> serde_json::Value {
    serde_json::json!({
        "Test": ["CMD-SHELL", health.cmd],
        "Interval": health.interval_secs.saturating_mul(1_000_000_000),
        "Timeout": health.timeout_secs.saturating_mul(1_000_000_000),
        "Retries": health.retries,
        "StartPeriod": health.start_period_secs.saturating_mul(1_000_000_000),
    })
}

#[cfg(target_os = "linux")]
fn docker_runtime_healthcheck(
    health: &ferro_core::container_store::HealthConfig,
) -> serde_json::Value {
    let test = if health.cmd.len() == 3
        && health.cmd.first().is_some_and(|value| value == "/bin/sh")
        && health.cmd.get(1).is_some_and(|value| value == "-c")
    {
        vec![
            serde_json::Value::String("CMD-SHELL".to_string()),
            serde_json::Value::String(health.cmd[2].clone()),
        ]
    } else {
        std::iter::once(serde_json::Value::String("CMD".to_string()))
            .chain(health.cmd.iter().cloned().map(serde_json::Value::String))
            .collect()
    };
    serde_json::json!({
        "Test": test,
        "Interval": health.interval_secs.saturating_mul(1_000_000_000),
        "Timeout": health.timeout_secs.saturating_mul(1_000_000_000),
        "Retries": health.retries,
        "StartPeriod": health.start_period_secs.saturating_mul(1_000_000_000),
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
    headers: HashMap<String, String>,
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
    let mut headers = HashMap::new();
    for line in lines {
        if line.contains('\0') {
            return Err("docker: invalid request header".to_string());
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            let normalized_key = key.trim().to_ascii_lowercase();
            let normalized_value = value.trim().to_string();
            headers.insert(normalized_key.clone(), normalized_value.clone());
            if normalized_key == "content-length" {
                content_length = normalized_value
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
    Ok(HttpRequest {
        method,
        path,
        body,
        headers,
    })
}

#[cfg(target_os = "linux")]
fn http_response(status: u16, body: &[u8], content_type: &str) -> Vec<u8> {
    let status_line = match status {
        200 => "200 OK",
        201 => "201 Created",
        204 => "204 No Content",
        400 => "400 Bad Request",
        404 => "404 Not Found",
        409 => "409 Conflict",
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
fn docker_hijack_headers() -> Vec<u8> {
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n".to_vec()
}

#[cfg(target_os = "linux")]
fn docker_raw_stream(stdout: &str, stderr: &str) -> Vec<u8> {
    let mut output = Vec::with_capacity(stdout.len() + stderr.len() + 16);
    for (stream, payload) in [(1u8, stdout.as_bytes()), (2u8, stderr.as_bytes())] {
        if payload.is_empty() {
            continue;
        }
        output.push(stream);
        output.extend_from_slice(&[0, 0, 0]);
        output.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        output.extend_from_slice(payload);
    }
    output
}

#[cfg(target_os = "linux")]
fn stream_docker_events(
    stream: &mut UnixStream,
    state: &DockerCompatState,
    query: &HashMap<String, String>,
) -> Result<(), String> {
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("docker: event stream write timeout setup failed: {error}"))?;
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
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("docker: log stream write timeout setup failed: {error}"))?;
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
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| format!("docker: stats stream write timeout setup failed: {error}"))?;
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
fn stream_docker_attach(
    stream: &mut UnixStream,
    runtime: &ContainerRuntime,
    id: &str,
    logs_requested: bool,
    stream_requested: bool,
    stdout_requested: bool,
    stderr_requested: bool,
) -> Result<(), String> {
    // Docker attaches before `/containers/{id}/start` for `docker run`. Wait
    // briefly for the pending record to become a real runtime record instead
    // of rejecting the valid pre-start handshake with a 404.
    let deadline = Instant::now() + Duration::from_secs(30);
    let record = loop {
        match runtime.inspect(id) {
            Ok(record) => break record,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => return Err(error.to_string()),
        }
    };
    if record.pid == 0 {
        if logs_requested {
            let (stdout, stderr) = runtime.logs_split(id).map_err(|error| error.to_string())?;
            let frame = docker_raw_stream(
                if stdout_requested { &stdout } else { "" },
                if stderr_requested { &stderr } else { "" },
            );
            stream
                .write_all(&frame)
                .map_err(|error| error.to_string())?;
            stream.flush().map_err(|error| error.to_string())?;
        }
        return Ok(());
    }
    let (initial_stdout, initial_stderr) =
        runtime.logs_split(id).map_err(|error| error.to_string())?;
    if logs_requested && (!initial_stdout.is_empty() || !initial_stderr.is_empty()) {
        let frame = docker_raw_stream(
            if stdout_requested {
                &initial_stdout
            } else {
                ""
            },
            if stderr_requested {
                &initial_stderr
            } else {
                ""
            },
        );
        stream
            .write_all(&frame)
            .map_err(|error| error.to_string())?;
        stream.flush().map_err(|error| error.to_string())?;
    }
    if !stream_requested {
        return Ok(());
    }
    let mut stdin = std::fs::OpenOptions::new()
        .write(true)
        .open(format!("/proc/{}/fd/0", record.pid))
        .map_err(|error| format!("docker: container stdin is unavailable: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|error| error.to_string())?;
    let mut emitted_stdout = initial_stdout.len();
    let mut emitted_stderr = initial_stderr.len();
    let mut input = [0_u8; 16 * 1024];
    loop {
        match stream.read(&mut input) {
            Ok(0) => return Ok(()),
            Ok(size) => {
                use std::io::Write as _;
                stdin
                    .write_all(&input[..size])
                    .map_err(|error| format!("docker: writing container stdin: {error}"))?;
                stdin
                    .flush()
                    .map_err(|error| format!("docker: flushing container stdin: {error}"))?;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.to_string()),
        }
        let (stdout, stderr) = runtime.logs_split(id).map_err(|error| error.to_string())?;
        if stdout.len() < emitted_stdout {
            emitted_stdout = 0;
        }
        if stderr.len() < emitted_stderr {
            emitted_stderr = 0;
        }
        if stdout.len() > emitted_stdout || stderr.len() > emitted_stderr {
            let frame = docker_raw_stream(
                if stdout_requested {
                    &stdout[emitted_stdout..]
                } else {
                    ""
                },
                if stderr_requested {
                    &stderr[emitted_stderr..]
                } else {
                    ""
                },
            );
            stream
                .write_all(&frame)
                .map_err(|error| error.to_string())?;
            stream.flush().map_err(|error| error.to_string())?;
            emitted_stdout = stdout.len();
            emitted_stderr = stderr.len();
        }
        std::thread::sleep(Duration::from_millis(250));
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
    use ferro_core::image_manifest::parse_image_manifest;
    use sha2::Digest;
    use std::collections::{BTreeMap, HashMap};
    use std::io::Read;
    use std::sync::Mutex;
    use std::time::Duration;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn docker_status_for_running_container_delete_is_conflict() {
        assert_eq!(
            super::docker_status_for_error("container c1 is still running"),
            409
        );
    }

    #[test]
    fn docker_http_response_preserves_conflict_status() {
        let response = super::http_response(409, br#"{"message":"conflict"}"#, "application/json");
        assert!(response.starts_with(b"HTTP/1.1 409 Conflict\r\n"));
    }

    use super::{
        bind_run_network, build_error_is_retryable, build_health_config, build_limits,
        context_endpoint_available, context_endpoint_is_local, decode_docker_raw_stream,
        desktop_forward_enabled, discover_rootless_socket, dispatch, dispatch_remote_context,
        docker_chunked_headers, docker_container_apply_time_bounds,
        docker_container_matches_filters, docker_container_prune_matches_filters,
        docker_directory_usage, docker_event_payload, docker_event_resource,
        docker_event_response_attributes, docker_hijack_headers, docker_image_apply_time_bounds,
        docker_image_matches_filters, docker_image_prune_matches_filters, docker_inspect_payload,
        docker_manifest_layer_size, docker_network_ipv6_config, docker_network_matches_filters,
        docker_pending_inspect_payload, docker_pending_matches_filters,
        docker_pending_prune_matches_filters, docker_raw_stream, docker_runtime_healthcheck,
        docker_tail_logs, docker_top_payload, docker_volume_matches_filters, effective_readonly,
        ensure_context_routing_available, extract_docker_build_context, handle_build,
        handle_containers, handle_context, handle_events, handle_exec, handle_image_prune,
        handle_images, handle_inspect, handle_kill, handle_logs, handle_migrate_compose_report,
        handle_network, handle_pause, handle_pull, handle_push, handle_restart, handle_rm,
        handle_rmi, handle_run, handle_stats, handle_stop, handle_top, handle_unpause,
        handle_volume, handle_wait, host_build_arch, import_rvf_image_at,
        normalize_docker_api_path, parse_bind_mounts, parse_build_contexts, parse_build_secrets,
        parse_capabilities, parse_docker_bool_query, parse_docker_create_spec,
        parse_docker_filters, parse_docker_kill_signal, parse_docker_limit_query,
        parse_docker_network_create_spec, parse_docker_stop_timeout, parse_driver_opts,
        parse_env_entries, parse_key_values, parse_publish, parse_restart_policy,
        parse_tmpfs_mounts, percent_encode_path_component, read_docker_request_after_auth,
        read_http_request, read_merkle_leaves, remote_commit_path, remote_docker_request,
        remote_docker_stream_request, should_desktop_forward, split_path_query,
        structured_desktop_error, top_level_command_name, validate_build_platform,
        validate_docker_container_name, validate_docker_container_prune_filters,
        validate_docker_exec_command, validate_docker_image_prune_filters,
        validate_docker_network_filters, validate_docker_volume_filters, validate_network_backend,
        validate_network_mode, validate_wait_condition, AiCommands, Cli, Commands, ComposeCommands,
        ConfigCommands, ContextCommands, DockerCompatState, DockerCreateSpec, DockerEvent,
        DockerEventStore, DockerExecCreateRequest, DockerHealthSpec, MigrateCommands,
        NetworkCommands, RvfCommands, VolumeCommands, WitnessCommands,
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
    use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
    use std::path::PathBuf;

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

    #[cfg(target_os = "linux")]
    #[test]
    fn rootless_socket_discovery_prefers_explicit_ferrocrate_socket() {
        let _guard = ENV_MUTEX.lock().expect("environment lock");
        let temp = tempfile::tempdir().expect("socket fixture");
        let previous_runtime = std::env::var_os("XDG_RUNTIME_DIR");
        let previous_socket = std::env::var_os("FERROCRATE_ROOTLESS_SOCKET");
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", temp.path());
            std::env::set_var(
                "FERROCRATE_ROOTLESS_SOCKET",
                temp.path().join("ferrocrate.sock"),
            );
        }
        let socket = temp.path().join("ferrocrate.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        assert_eq!(discover_rootless_socket(), Some(socket));
        drop(listener);
        match previous_runtime {
            Some(value) => unsafe { std::env::set_var("XDG_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("XDG_RUNTIME_DIR") },
        }
        match previous_socket {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_ROOTLESS_SOCKET", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_ROOTLESS_SOCKET") },
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
                secret,
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
                assert!(secret.is_empty());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_rvf_inspect_and_extract_commands() {
        let inspect = Cli::parse_from([
            "ferrocrate",
            "rvf",
            "inspect",
            "image.rvf",
            "--format",
            "json",
        ]);
        match inspect.command {
            Commands::Rvf {
                command: RvfCommands::Inspect { image, format },
            } => {
                assert_eq!(image, PathBuf::from("image.rvf"));
                assert_eq!(format, "json");
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let filtered_ls = Cli::parse_from([
            "ferrocrate",
            "volume",
            "ls",
            "--filter",
            "name=data",
            "--filter",
            "driver=local",
        ]);
        match filtered_ls.command {
            Commands::Volume { command } => match command {
                VolumeCommands::Ls { filters } => {
                    assert_eq!(filters, vec!["name=data", "driver=local"]);
                }
                _ => panic!("unexpected volume command"),
            },
            _ => panic!("unexpected command"),
        }

        let extract = Cli::parse_from(["ferrocrate", "rvf", "extract", "image.rvf", "layer.tar"]);
        match extract.command {
            Commands::Rvf {
                command: RvfCommands::Extract { image, output },
            } => {
                assert_eq!(image, PathBuf::from("image.rvf"));
                assert_eq!(output, PathBuf::from("layer.tar"));

                let import = Cli::parse_from([
                    "ferrocrate",
                    "rvf",
                    "import",
                    "image.rvf",
                    "--reference",
                    "local/imported:latest",
                ]);
                match import.command {
                    Commands::Rvf {
                        command: RvfCommands::Import { image, reference },
                    } => {
                        assert_eq!(image, PathBuf::from("image.rvf"));
                        assert_eq!(reference.as_deref(), Some("local/imported:latest"));
                    }
                    other => panic!("unexpected command: {other:?}"),
                }
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_witness_merkle_commands_and_reads_hash_leaves() {
        let root = Cli::parse_from([
            "ferrocrate",
            "witness",
            "merkle-root",
            "--leaves",
            "leaves.txt",
        ]);
        assert!(matches!(
            root.command,
            Commands::Witness {
                command: WitnessCommands::MerkleRoot { leaves }
            } if leaves == *"leaves.txt"
        ));

        let verify = Cli::parse_from([
            "ferrocrate",
            "witness",
            "merkle-verify",
            "--proof",
            "proof.json",
            "--kind",
            "consistency",
        ]);
        assert!(matches!(
            verify.command,
            Commands::Witness {
                command: WitnessCommands::MerkleVerify { proof, kind }
            } if proof == *"proof.json" && kind == "consistency"
        ));

        let compact = Cli::parse_from([
            "ferrocrate",
            "witness",
            "merkle-verify",
            "--proof",
            "frontier.json",
            "--kind",
            "frontier-consistency",
        ]);
        assert!(matches!(
            compact.command,
            Commands::Witness {
                command: WitnessCommands::MerkleVerify { proof, kind }
            } if proof == *"frontier.json" && kind == "frontier-consistency"
        ));

        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("leaves.txt");
        std::fs::write(&path, "# record hashes\nsha256:0000000000000000000000000000000000000000000000000000000000000001\n").unwrap();
        let leaves = read_merkle_leaves(&path).expect("leaves");
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0][31], 1);
    }

    #[test]
    fn rvf_import_publishes_a_verified_oci_reference_and_layer() {
        let runtime = configured_cli_runtime("disabled");
        let layer = b"validated-rvf-layer".to_vec();
        let layer_digest = format!("sha256:{:x}", sha2::Sha256::digest(&layer));
        let image = runtime.path().join("demo.rvf");
        let manifest = ferro_core::rvf_image::FerroImageManifest {
            name: "local/demo".to_string(),
            tag: "latest".to_string(),
            entrypoint: vec!["/bin/demo".to_string()],
            cmd: vec!["--serve".to_string()],
            env: vec!["MODE=test".to_string()],
            arch: host_build_arch().to_string(),
            os: "linux".to_string(),
            created_at: "2026-08-16T00:00:00Z".to_string(),
            format_version: 1,
            layer_digest,
            layer_size: layer.len() as u64,
            overlay_model_type: None,
        };
        let segments = vec![
            ferro_core::rvf_image::RvfSegment {
                seg_type: ferro_core::rvf_image::SEG_MANIFEST,
                payload: serde_json::to_vec(&manifest).expect("manifest"),
            },
            ferro_core::rvf_image::RvfSegment {
                seg_type: ferro_core::rvf_image::SEG_LAYER,
                payload: layer,
            },
        ];
        let mut bytes = Vec::new();
        ferro_core::rvf_image::write_rvf(&mut bytes, &segments).expect("rvf bytes");
        std::fs::write(&image, bytes).expect("write rvf");
        import_rvf_image_at(&image, None, runtime.path()).expect("import rvf");
        let store = LocalImageStore::open(runtime.path().join("images")).expect("store");
        let imported_reference =
            ferro_core::image_tagging::canonicalize_reference("local/demo:latest")
                .expect("reference");
        let record = store
            .resolve_reference(&imported_reference)
            .expect("resolve")
            .expect("imported reference");
        let parsed = parse_image_manifest(&record.manifest_json).expect("manifest");
        assert_eq!(parsed.layers.len(), 1);
        assert!(runtime
            .path()
            .join("images/blobs")
            .join(parsed.layers[0].digest.replace(':', "_"))
            .exists());
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
    fn parses_build_secrets_without_following_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("token");
        std::fs::write(&path, b"secret-value").unwrap();
        let values = vec![format!("id=token,src={}", path.display())];
        let parsed = parse_build_secrets(&values).unwrap();
        assert_eq!(parsed.get("token"), Some(&path));
        assert!(parse_build_secrets(&["id=token".to_string()]).is_err());
        assert!(parse_build_secrets(&[
            "id=token,src=missing".to_string(),
            "id=token,src=missing".to_string()
        ])
        .is_err());
    }

    #[test]
    fn build_retry_classifier_excludes_authorization_and_policy_errors() {
        assert!(build_error_is_retryable("registry connection reset"));
        assert!(!build_error_is_retryable(
            "image build authorization failed"
        ));
        assert!(!build_error_is_retryable("RUN cancelled by build control"));
        assert!(!build_error_is_retryable(
            "unsupported Dockerfile directive"
        ));
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
    fn parses_history_command() {
        let cli = Cli::parse_from(["ferrocrate", "history", "alpine:latest", "--format", "json"]);
        match cli.command {
            Commands::History { image, format } => {
                assert_eq!(image, "alpine:latest");
                assert_eq!(format, "json");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn docker_pull_status_is_a_terminal_json_stream_record() {
        let body = super::docker_pull_status("alpine:latest", false);
        let line = std::str::from_utf8(&body)
            .expect("status body utf8")
            .trim_end();
        let value: serde_json::Value = serde_json::from_str(line).expect("status JSON");
        assert_eq!(value["status"], "Pull complete");
        assert_eq!(value["id"], "alpine:latest");
        assert!(body.ends_with(b"\n"));

        let lazy = super::docker_pull_status("alpine:latest", true);
        let value: serde_json::Value = serde_json::from_slice(&lazy).expect("lazy status JSON");
        assert_eq!(value["status"], "Manifest fetched");
    }

    #[test]
    fn parses_tag_command() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "tag",
            "alpine:latest",
            "registry.local/app:v2",
        ]);
        match cli.command {
            Commands::Tag { source, target } => {
                assert_eq!(source, "alpine:latest");
                assert_eq!(target, "registry.local/app:v2");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_commit_command() {
        let cli = Cli::parse_from(["ferrocrate", "commit", "web", "example/web:v1"]);
        match cli.command {
            Commands::Commit {
                container,
                repository,
            } => {
                assert_eq!(container, "web");
                assert_eq!(repository, "example/web:v1");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_image_inspect_command() {
        let cli = Cli::parse_from(["ferrocrate", "image-inspect", "alpine:latest"]);
        match cli.command {
            Commands::ImageInspect { image, format } => {
                assert_eq!(image, "alpine:latest");
                assert_eq!(format, "text");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_image_list_filters() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "images",
            "--filter",
            "reference=alpine*",
            "--filter",
            "since=100",
        ]);
        match cli.command {
            Commands::Images { format, filters } => {
                assert_eq!(format, "text");
                assert_eq!(filters, vec!["reference=alpine*", "since=100"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_system_df_command() {
        let cli = Cli::try_parse_from(["ferrocrate", "system-df", "--format", "json"])
            .expect("parse system df");
        assert!(matches!(cli.command, Commands::SystemDf { format } if format == "json"));
    }

    #[test]
    fn parses_image_prune_command() {
        let cli = Cli::parse_from(["ferrocrate", "image-prune"]);
        match cli.command {
            Commands::ImagePrune { filters } => assert!(filters.is_empty()),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_image_prune_filters() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "image-prune",
            "--filter",
            "dangling=true",
            "--filter",
            "until=100",
        ]);
        match cli.command {
            Commands::ImagePrune { filters } => {
                assert_eq!(filters, vec!["dangling=true", "until=100"]);
            }
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
        handle_image_prune(&store, &authorization, &[]).expect("prune");
    }

    #[test]
    fn parses_compose_command() {
        let cli = Cli::parse_from(["ferrocrate", "compose", "up", "-d"]);
        match cli.command {
            Commands::Compose { file, command } => {
                assert!(file.is_none());
                assert!(
                    matches!(command, ComposeCommands::Up { profile, detach } if profile.is_empty() && detach)
                );
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
    fn parses_ai_sign_command() {
        let cli = Cli::parse_from([
            "ferrocrate",
            "ai",
            "sign",
            "--model-type",
            "resource-predictor",
            "--version",
            "7",
            "--signer-key-id",
            "operator-1",
            "--key",
            "/run/secrets/model-key",
            "--models-dir",
            "/var/lib/ferrocrate/models",
            "--format",
            "json",
        ]);
        match cli.command {
            Commands::Ai {
                command:
                    AiCommands::Sign {
                        model_type,
                        version,
                        signer_key_id,
                        key,
                        models_dir,
                        format,
                    },
            } => {
                assert_eq!(model_type, "resource-predictor");
                assert_eq!(version, 7);
                assert_eq!(signer_key_id, "operator-1");
                assert_eq!(key, PathBuf::from("/run/secrets/model-key"));
                assert_eq!(models_dir.as_deref(), Some("/var/lib/ferrocrate/models"));
                assert_eq!(format, "json");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn signing_key_file_accepts_raw_and_hex_and_rejects_symlink() {
        let temp = tempfile::tempdir().expect("tempdir");
        let raw_path = temp.path().join("raw-key");
        let raw = [0x2a_u8; 32];
        std::fs::write(&raw_path, raw).expect("raw key");
        #[cfg(unix)]
        std::fs::set_permissions(
            &raw_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("raw key permissions");
        assert_eq!(
            super::read_signing_key_file(&raw_path).expect("raw key parse"),
            raw
        );

        let hex_path = temp.path().join("hex-key");
        std::fs::write(&hex_path, "2a".repeat(32)).expect("hex key");
        #[cfg(unix)]
        std::fs::set_permissions(
            &hex_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .expect("hex key permissions");
        assert_eq!(
            super::read_signing_key_file(&hex_path).expect("hex key parse"),
            raw
        );

        #[cfg(unix)]
        {
            let link = temp.path().join("link-key");
            std::os::unix::fs::symlink(&raw_path, &link).expect("symlink");
            assert!(super::read_signing_key_file(&link).is_err());
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

    #[test]
    fn read_http_request_preserves_case_insensitive_upgrade_headers() {
        let (mut writer, mut reader) = StdUnixStream::pair().expect("pair");
        writer
            .write_all(
                b"POST /containers/c1/attach HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: tcp\r\nContent-Length: 0\r\n\r\n",
            )
            .expect("write");
        let request = read_http_request(&mut reader).expect("request");
        assert_eq!(
            request.headers.get("connection").map(String::as_str),
            Some("keep-alive, Upgrade")
        );
        assert_eq!(
            request.headers.get("upgrade").map(String::as_str),
            Some("tcp")
        );
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
            Commands::Kill { container, signal } => {
                assert_eq!(container, "abc123");
                assert_eq!(signal, "SIGKILL");
            }
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
    fn parses_rename_command() {
        let cli = Cli::parse_from(["ferrocrate", "rename", "abc123", "web"]);
        match cli.command {
            Commands::Rename { container, name } => {
                assert_eq!(container, "abc123");
                assert_eq!(name, "web");
            }
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
    fn parses_start_command() {
        let cli = Cli::parse_from(["ferrocrate", "start", "abc123"]);
        match cli.command {
            Commands::Start { container } => assert_eq!(container, "abc123"),
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
            Commands::Volume { command } => {
                assert!(matches!(command, VolumeCommands::Ls { filters } if filters.is_empty()))
            }
            _ => panic!("unexpected command"),
        }

        let inspect = Cli::parse_from([
            "ferrocrate",
            "volume",
            "inspect",
            "data",
            "--format",
            "json",
        ]);
        match inspect.command {
            Commands::Volume { command } => match command {
                VolumeCommands::Inspect { name, format } => {
                    assert_eq!(name, "data");
                    assert_eq!(format, "json");
                }
                _ => panic!("unexpected volume command"),
            },
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

        let prune = Cli::parse_from(["ferrocrate", "network", "prune"]);
        match prune.command {
            Commands::Network { command } => {
                assert!(matches!(command, NetworkCommands::Prune { filters } if filters.is_empty()))
            }
            _ => panic!("unexpected command"),
        }

        let prune = Cli::parse_from(["ferrocrate", "volume", "prune"]);
        match prune.command {
            Commands::Volume { command } => {
                assert!(matches!(command, VolumeCommands::Prune { filters } if filters.is_empty()))
            }
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn bind_run_network_named_keeps_bridge_mode_and_logical_association() {
        let temp = tempfile::tempdir().expect("tempdir");
        let record =
            super::create_network_record("app-net", Some("10.88.0.0/24"), None, None, None)
                .expect("record");
        super::save_networks(temp.path(), std::slice::from_ref(&record)).expect("save");
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
            Commands::Network { command } => {
                assert!(matches!(command, NetworkCommands::Ls { filters } if filters.is_empty()))
            }
            _ => panic!("unexpected command"),
        }

        let inspect = Cli::parse_from(["ferrocrate", "network", "inspect", "mesh"]);
        match inspect.command {
            Commands::Network { command } => match command {
                NetworkCommands::Inspect { name, format } => {
                    assert_eq!(name, "mesh");
                    assert_eq!(format, "text");
                }
                _ => panic!("unexpected network command"),
            },
            _ => panic!("unexpected command"),
        }

        let filtered_ls = Cli::parse_from([
            "ferrocrate",
            "network",
            "ls",
            "--filter",
            "name=mesh",
            "--filter",
            "driver=bridge",
        ]);
        match filtered_ls.command {
            Commands::Network { command } => match command {
                NetworkCommands::Ls { filters } => {
                    assert_eq!(filters, vec!["name=mesh", "driver=bridge"]);
                }
                _ => panic!("unexpected network command"),
            },
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
    fn parses_docker_dual_stack_network_ipam() {
        let spec = parse_docker_network_create_spec(
            br#"{
                "Name":"dual-stack",
                "Driver":"bridge",
                "EnableIPv6":true,
                "IPAM":{"Config":[
                    {"Subnet":"10.88.0.0/24","Gateway":"10.88.0.1"},
                    {"Subnet":"fd42:4242::/64","Gateway":"fd42:4242::1"}
                ]}
            }"#,
        )
        .expect("dual-stack payload");
        assert!(spec.enable_ipv6);
        assert_eq!(
            spec.ipam
                .as_ref()
                .and_then(|ipam| ipam.config.get(1))
                .and_then(|config| config.subnet.as_deref()),
            Some("fd42:4242::/64")
        );
    }

    #[test]
    fn docker_network_ipv6_config_reconstructs_subnet_from_record_gateway() {
        let record = super::create_network_record(
            "dual-net",
            Some("10.88.0.0/24"),
            Some("10.88.0.1"),
            Some("fd42:4242::/64"),
            None,
        )
        .expect("dual-stack record");
        assert_eq!(
            docker_network_ipv6_config(&record),
            Some(serde_json::json!({
                "Subnet": "fd42:4242::/64",
                "Gateway": "fd42:4242::1",
            }))
        );
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
        handle_volume(
            &runtime_dir,
            VolumeCommands::Ls { filters: vec![] },
            &authorization,
        )
        .expect("ls volumes");
        handle_volume(
            &runtime_dir,
            VolumeCommands::Inspect {
                name: "data".to_string(),
                format: "json".to_string(),
            },
            &authorization,
        )
        .expect("inspect volume");
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
        handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Ls { filters: vec![] },
            &authorization,
        )
        .expect("ls networks");
        handle_network(
            temp.path(),
            &runtime,
            NetworkCommands::Inspect {
                name: "test-net".to_string(),
                format: "json".to_string(),
            },
            &authorization,
        )
        .expect("inspect network");
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

        let err = handle_kill(&runtime, "", "SIGKILL").expect_err("kill requires container");
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
            &[],
        )
        .expect_err("dockerfile should be read");
        assert!(
            err.contains("Dockerfile"),
            "expected default dockerfile path in error, got: {err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn docker_build_context_extraction_rejects_symlink_entries() {
        let temp = tempfile::tempdir().expect("context destination");
        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path("escape").expect("path");
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("/tmp/escape").expect("link");
            header.set_size(0);
            header.set_cksum();
            builder.append(&header, &[][..]).expect("append symlink");
            builder.finish().expect("finish");
        }
        let error = extract_docker_build_context(&bytes, temp.path()).expect_err("symlink");
        assert!(
            error.contains("unsupported context entry type"),
            "error={error}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn docker_system_df_sums_manifest_layer_sizes() {
        let manifest = r#"{"layers":[{"size":7},{"size":11}],"config":{"size":3}}"#;
        assert_eq!(docker_manifest_layer_size(manifest), 18);
        assert_eq!(docker_manifest_layer_size("{}"), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn docker_system_df_reports_regular_volume_bytes_and_skips_symlinks() {
        let temp = tempfile::tempdir().expect("volume usage root");
        std::fs::write(temp.path().join("payload"), b"12345").expect("payload");
        #[cfg(unix)]
        std::os::unix::fs::symlink("payload", temp.path().join("link")).expect("symlink");
        assert_eq!(docker_directory_usage(temp.path()), 5);
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
        handle_images(&store, "text", &[]).expect("images handler should succeed");
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
    fn docker_event_collection_routes_do_not_fake_resource_ids() {
        assert_eq!(docker_event_resource("/containers/create"), None);
        assert_eq!(docker_event_resource("/networks/prune"), None);
        assert_eq!(
            docker_event_resource("/images/i1/tag"),
            Some("i1".to_string())
        );
        assert_eq!(
            docker_event_resource("/volumes/volume-a"),
            Some("volume-a".to_string())
        );
    }

    #[test]
    fn docker_event_create_captures_response_identity_and_safe_request_attributes() {
        let temp = tempfile::tempdir().expect("event runtime");
        let mut store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        store
            .append_with_context(
                "POST",
                "/containers/create",
                201,
                br#"{"Image":"busybox","Labels":{"tier":"frontend"},"Env":["TOKEN=secret"]}"#,
                br#"{"Id":"container-1","Warnings":[]}"#,
            )
            .unwrap();
        let events = store.query(&HashMap::new()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].resource.as_deref(), Some("container-1"));
        assert_eq!(
            events[0].attributes.get("Image"),
            Some(&"busybox".to_string())
        );
        assert_eq!(
            events[0].attributes.get("Id"),
            Some(&"container-1".to_string())
        );
        assert_eq!(
            events[0].attributes.get("tier"),
            Some(&"frontend".to_string())
        );
        assert!(!events[0]
            .attributes
            .values()
            .any(|value| value.contains("secret")));
        let payload = docker_event_payload(&events[0]);
        assert_eq!(payload["Actor"]["ID"], "container-1");
    }

    #[test]
    fn docker_event_response_attributes_are_allow_listed_and_bounded() {
        let attributes = docker_event_response_attributes(
            br#"{"Id":"image-1","Name":"alpine:latest","Secret":"must-not-persist","Labels":{"token":"hidden"}}"#,
        );
        assert_eq!(attributes.get("Id"), Some(&"image-1".to_string()));
        assert_eq!(attributes.get("Name"), Some(&"alpine:latest".to_string()));
        assert!(!attributes.contains_key("Secret"));
        assert!(!attributes.contains_key("Labels"));
        assert!(docker_event_response_attributes(br#"not-json"#).is_empty());
    }

    #[test]
    fn docker_event_response_attributes_project_nested_container_config() {
        let attributes = docker_event_response_attributes(
            br#"{"Id":"container-1","Config":{"Image":"alpine:3.20","WorkingDir":"/srv","Labels":{"tier":"frontend","secret":"redacted-by-source"},"Env":["TOKEN=hidden"]},"Secret":"ignored"}"#,
        );
        assert_eq!(attributes.get("Image"), Some(&"alpine:3.20".to_string()));
        assert_eq!(attributes.get("WorkingDir"), Some(&"/srv".to_string()));
        assert_eq!(attributes.get("tier"), Some(&"frontend".to_string()));
        assert_eq!(
            attributes.get("secret"),
            Some(&"redacted-by-source".to_string())
        );
        assert!(!attributes.contains_key("Env"));
        assert!(!attributes.contains_key("Secret"));
    }

    #[test]
    fn docker_create_name_is_bounded_and_path_safe() {
        assert!(validate_docker_container_name("web_1.test-2").is_ok());
        assert!(validate_docker_container_name("").is_err());
        assert!(validate_docker_container_name("../escape").is_err());
        assert!(validate_docker_container_name("name/with/slash").is_err());
        assert!(validate_docker_container_name(&"x".repeat(129)).is_err());
    }

    #[test]
    fn docker_create_spec_rejects_unsafe_query_name_before_pending_state() {
        let error = parse_docker_create_spec(
            br#"{"Image":"busybox","Cmd":["true"]}"#,
            Some("../escape".to_string()),
        )
        .expect_err("unsafe Docker names must fail closed");
        assert!(error.contains("unsupported characters"));
    }

    #[test]
    fn docker_create_spec_parses_healthcheck_modes_and_bounds() {
        let spec = parse_docker_create_spec(
            br#"{"Image":"busybox","Healthcheck":{"Test":["CMD-SHELL","test -f /ready"],"Interval":2000000000,"Timeout":1000000000,"Retries":2}}"#,
            None,
        )
        .expect("CMD-SHELL healthcheck");
        let health = spec.health.expect("health config");
        assert_eq!(health.cmd, "test -f /ready");
        assert_eq!(health.interval_secs, 2);
        assert_eq!(health.timeout_secs, 1);
        assert_eq!(health.retries, 2);

        let cmd = parse_docker_create_spec(
            br#"{"Image":"busybox","Healthcheck":{"Test":["CMD","/bin/check","ready"]}}"#,
            None,
        )
        .expect("CMD healthcheck");
        assert_eq!(cmd.health.expect("CMD config").cmd, "'/bin/check' 'ready'");

        let none = parse_docker_create_spec(
            br#"{"Image":"busybox","Healthcheck":{"Test":["NONE"]}}"#,
            None,
        )
        .expect("NONE healthcheck");
        assert!(none.health.is_none());
        assert!(parse_docker_create_spec(
            br#"{"Image":"busybox","Healthcheck":{"Test":["CMD-SHELL"]}}"#,
            None,
        )
        .is_err());
    }

    #[test]
    fn docker_create_spec_preserves_host_resource_limits() {
        let spec = parse_docker_create_spec(
            br#"{"Image":"busybox","HostConfig":{"Memory":67108864,"CpuQuota":50000,"CpuPeriod":100000,"PidsLimit":32}}"#,
            None,
        )
        .expect("resource limits");
        assert_eq!(spec.memory_max, Some(67_108_864));
        assert_eq!(spec.cpu_quota, Some(50_000));
        assert_eq!(spec.cpu_period, Some(100_000));
        assert_eq!(spec.pids_max, Some(32));

        let unlimited = parse_docker_create_spec(
            br#"{"Image":"busybox","HostConfig":{"PidsLimit":-1}}"#,
            None,
        )
        .expect("unlimited pids");
        assert_eq!(unlimited.pids_max, None);
        assert!(parse_docker_create_spec(
            br#"{"Image":"busybox","HostConfig":{"Memory":-1}}"#,
            None,
        )
        .is_err());
    }

    #[test]
    fn docker_inspect_projects_healthcheck_configuration() {
        let pending = DockerCreateSpec {
            image: "busybox".to_string(),
            cmd: vec!["true".to_string()],
            env: Vec::new(),
            labels: Vec::new(),
            binds: Vec::new(),
            publish: Vec::new(),
            workdir: None,
            user: None,
            name: None,
            network_mode: "bridge".to_string(),
            auto_remove: false,
            health: Some(DockerHealthSpec {
                cmd: "test -f /ready".to_string(),
                interval_secs: 2,
                timeout_secs: 1,
                retries: 3,
                start_period_secs: 4,
            }),
            memory_max: None,
            cpu_quota: None,
            cpu_period: None,
            pids_max: None,
            created_at_unix: 0,
        };
        let payload = docker_pending_inspect_payload("pending", &pending);
        assert_eq!(payload["Config"]["Healthcheck"]["Test"][0], "CMD-SHELL");
        assert_eq!(
            payload["Config"]["Healthcheck"]["Interval"],
            2_000_000_000u64
        );

        let health = ferro_core::container_store::HealthConfig {
            cmd: vec!["/bin/check".to_string(), "ready".to_string()],
            interval_secs: 5,
            timeout_secs: 2,
            retries: 2,
            start_period_secs: 1,
        };
        let projected = docker_runtime_healthcheck(&health);
        assert_eq!(projected["Test"][0], "CMD");
        assert_eq!(projected["Test"][1], "/bin/check");
    }

    #[test]
    fn docker_inspect_projects_persisted_runtime_resource_limits() {
        let record: ferro_core::container_store::ContainerRecord =
            serde_json::from_value(serde_json::json!({
                "id": "running-limits",
                "pid": 4242,
                "image": "alpine:3.20",
                "command": ["true"],
                "created_at_unix": 1,
                "stdout_path": "",
                "stderr_path": "",
                "status": "running",
                "resource_limits": {
                    "memory_max": 67108864,
                    "cpu_quota": 50000,
                    "cpu_period": 100000,
                    "pids_max": 32
                }
            }))
            .expect("running record");

        let payload = docker_inspect_payload(&record);
        assert_eq!(payload["HostConfig"]["Memory"], 67_108_864u64);
        assert_eq!(payload["HostConfig"]["CpuQuota"], 50_000u64);
        assert_eq!(payload["HostConfig"]["CpuPeriod"], 100_000u64);
        assert_eq!(payload["HostConfig"]["PidsLimit"], 32u64);
    }

    #[test]
    fn docker_pending_create_state_reopens_atomically() {
        let temp = tempfile::tempdir().expect("runtime");
        let state = DockerCompatState::new(temp.path()).expect("state");
        state.pending.lock().expect("pending lock").insert(
            "dfixture".to_string(),
            DockerCreateSpec {
                image: "busybox".to_string(),
                cmd: vec!["true".to_string()],
                env: Vec::new(),
                labels: Vec::new(),
                binds: Vec::new(),
                publish: Vec::new(),
                workdir: None,
                user: None,
                name: Some("fixture".to_string()),
                network_mode: "bridge".to_string(),
                auto_remove: false,
                health: None,
                memory_max: None,
                cpu_quota: None,
                cpu_period: None,
                pids_max: None,
                created_at_unix: 0,
            },
        );
        state.persist_pending().expect("persist pending");
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(temp.path().join("docker-pending.json"))
                .expect("pending metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let reopened = DockerCompatState::new(temp.path()).expect("reopen state");
        assert!(reopened
            .pending
            .lock()
            .expect("reopened pending lock")
            .contains_key("dfixture"));
    }

    #[test]
    fn docker_pending_list_applies_name_status_ancestor_and_label_filters() {
        let spec = DockerCreateSpec {
            image: "busybox:latest".to_string(),
            cmd: vec!["true".to_string()],
            env: Vec::new(),
            labels: vec!["tier=frontend".to_string()],
            binds: Vec::new(),
            publish: Vec::new(),
            workdir: None,
            user: None,
            name: Some("frontend".to_string()),
            network_mode: "bridge".to_string(),
            auto_remove: false,
            health: None,
            memory_max: None,
            cpu_quota: None,
            cpu_period: None,
            pids_max: None,
            created_at_unix: 0,
        };
        let mut filters = HashMap::new();
        filters.insert("status".to_string(), vec!["created".to_string()]);
        filters.insert("name".to_string(), vec!["front".to_string()]);
        filters.insert("ancestor".to_string(), vec!["busybox".to_string()]);
        filters.insert("label".to_string(), vec!["tier=frontend".to_string()]);
        assert!(docker_pending_matches_filters("dfixture", &spec, &filters));
        filters.insert("status".to_string(), vec!["running".to_string()]);
        assert!(!docker_pending_matches_filters("dfixture", &spec, &filters));
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
            attributes: BTreeMap::from([
                ("method".to_string(), "POST".to_string()),
                ("path".to_string(), "/containers/abc123/start".to_string()),
            ]),
        };
        let payload = docker_event_payload(&event);
        assert_eq!(payload["Type"], "container");
        assert_eq!(payload["Action"], "start");
        assert_eq!(payload["Actor"]["ID"], "abc123");
        assert_eq!(payload["Actor"]["Attributes"]["status"], "start");
        assert_eq!(payload["Actor"]["Attributes"]["httpStatus"], "204");
        assert_eq!(
            payload["Actor"]["Attributes"]["path"],
            "/containers/abc123/start"
        );
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
    fn docker_container_prune_filters_only_stopped_matching_records() {
        let mut record: ferro_core::container_store::ContainerRecord =
            serde_json::from_value(serde_json::json!({
                "id": "abc",
                "pid": 0,
                "image": "alpine:3.20",
                "command": [],
                "created_at_unix": 10,
                "stdout_path": "",
                "stderr_path": "",
                "status": "exited"
            }))
            .expect("record");
        record.labels.insert("tier".into(), "frontend".into());
        let filters = serde_json::from_value(serde_json::json!({
            "until": ["20"],
            "label": ["tier=frontend"]
        }))
        .expect("filters");
        validate_docker_container_prune_filters(&filters).expect("valid filters");
        assert!(docker_container_prune_matches_filters(&record, &filters));

        record.status = "running".to_string();
        assert!(!docker_container_prune_matches_filters(&record, &filters));
        record.status = "exited".to_string();
        record.created_at_unix = 20;
        assert!(!docker_container_prune_matches_filters(&record, &filters));
    }

    #[test]
    fn docker_pending_prune_filters_match_labels_and_until() {
        let spec = DockerCreateSpec {
            image: "busybox".to_string(),
            cmd: vec!["true".to_string()],
            env: Vec::new(),
            labels: vec!["tier=frontend".to_string()],
            binds: Vec::new(),
            publish: Vec::new(),
            workdir: None,
            user: None,
            name: Some("pending".to_string()),
            network_mode: "bridge".to_string(),
            auto_remove: false,
            health: None,
            memory_max: None,
            cpu_quota: None,
            cpu_period: None,
            pids_max: None,
            created_at_unix: 10,
        };
        let labels = serde_json::from_value(serde_json::json!({
            "label": ["tier=frontend"]
        }))
        .expect("filters");
        assert!(docker_pending_prune_matches_filters(
            "pending-id",
            &spec,
            &labels
        ));
        let until = serde_json::from_value(serde_json::json!({"until": ["10"]})).expect("filters");
        assert!(!docker_pending_prune_matches_filters(
            "pending-id",
            &spec,
            &until
        ));
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
    fn docker_exec_create_payload_preserves_argv_and_rejects_empty_commands() {
        let request: DockerExecCreateRequest =
            serde_json::from_value(serde_json::json!({"Cmd": ["/bin/echo", "hello"]}))
                .expect("exec request");
        assert_eq!(request.cmd, vec!["/bin/echo", "hello"]);
        let empty: DockerExecCreateRequest =
            serde_json::from_value(serde_json::json!({"Cmd": []})).expect("empty request");
        assert!(empty.cmd.is_empty());
        assert!(validate_docker_exec_command(&request.cmd).is_ok());
        assert!(validate_docker_exec_command(&empty.cmd).is_err());
        let blank = vec!["".to_string()];
        assert!(validate_docker_exec_command(&blank).is_err());
    }

    #[test]
    fn docker_exec_raw_stream_frames_stdout_and_stderr() {
        let stream = docker_raw_stream("out\n", "err\n");
        assert_eq!(stream[0], 1);
        assert_eq!(u32::from_be_bytes(stream[4..8].try_into().unwrap()), 4);
        assert_eq!(&stream[8..12], b"out\n");
        assert_eq!(stream[12], 2);
        assert_eq!(u32::from_be_bytes(stream[16..20].try_into().unwrap()), 4);
        assert_eq!(&stream[20..24], b"err\n");
        assert!(docker_raw_stream("", "").is_empty());
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
        assert!(!parse_docker_bool_query(None, "all").unwrap());
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
    fn docker_stop_timeout_defaults_and_validates_unbounded_values() {
        let empty = HashMap::new();
        assert_eq!(
            parse_docker_stop_timeout(&empty).unwrap(),
            Duration::from_secs(10)
        );

        let mut query = HashMap::new();
        query.insert("t".to_string(), "0".to_string());
        assert_eq!(parse_docker_stop_timeout(&query).unwrap(), Duration::ZERO);
        query.insert("t".to_string(), "7".to_string());
        assert_eq!(
            parse_docker_stop_timeout(&query).unwrap(),
            Duration::from_secs(7)
        );
        query.insert("t".to_string(), "-1".to_string());
        assert_eq!(parse_docker_stop_timeout(&query).unwrap(), Duration::MAX);
        query.insert("t".to_string(), "-2".to_string());
        assert!(parse_docker_stop_timeout(&query).is_err());
        query.insert("t".to_string(), "soon".to_string());
        assert!(parse_docker_stop_timeout(&query).is_err());
    }

    #[test]
    fn docker_kill_signal_accepts_names_and_rejects_unsafe_unknowns() {
        assert_eq!(
            parse_docker_kill_signal(None).unwrap(),
            Some(nix::sys::signal::Signal::SIGKILL)
        );
        assert_eq!(
            parse_docker_kill_signal(Some(&"TERM".to_string())).unwrap(),
            Some(nix::sys::signal::Signal::SIGTERM)
        );
        assert_eq!(
            parse_docker_kill_signal(Some(&"SIGUSR1".to_string())).unwrap(),
            Some(nix::sys::signal::Signal::SIGUSR1)
        );
        assert_eq!(
            parse_docker_kill_signal(Some(&"0".to_string())).unwrap(),
            None
        );
        assert!(parse_docker_kill_signal(Some(&"not-a-signal".to_string())).is_err());
    }

    #[test]
    fn docker_image_filters_match_reference_and_time_bounds() {
        let make =
            |reference: &str, digest: &str, created_at_unix| ferro_core::image_store::ImageRecord {
                reference: reference.to_string(),
                digest: digest.to_string(),
                manifest_media_type: "application/json".to_string(),
                manifest_json: "{}".to_string(),
                created_at_unix,
            };
        let images = vec![
            make("alpine:latest", "sha256:a", 10),
            make("alpine:3.20", "sha256:b", 20),
            make("busybox:latest", "sha256:c", 30),
        ];
        let mut filters = HashMap::new();
        filters.insert("reference".to_string(), vec!["alpine:*".to_string()]);
        assert!(docker_image_matches_filters(&images[0], &filters));
        assert!(!docker_image_matches_filters(&images[2], &filters));
        filters.insert("since".to_string(), vec!["alpine:latest".to_string()]);
        filters.insert("before".to_string(), vec!["30".to_string()]);
        let bounded = docker_image_apply_time_bounds(images, &filters).unwrap();
        assert_eq!(
            bounded
                .iter()
                .map(|image| image.digest.as_str())
                .collect::<Vec<_>>(),
            vec!["sha256:b"]
        );
    }

    #[test]
    fn docker_volume_filters_match_name_and_driver() {
        let record = ferro_core::volume_store::VolumeRecord {
            name: "database".to_string(),
            path: "/var/lib/ferrocrate/volumes/database".to_string(),
            driver: "local".to_string(),
            driver_opts: Default::default(),
            created_at_unix: 1,
        };
        let filters = serde_json::from_value(serde_json::json!({
            "name": ["database"],
            "driver": ["local"]
        }))
        .expect("filters");
        assert!(docker_volume_matches_filters(&record, &filters));

        let substring =
            serde_json::from_value(serde_json::json!({"name": ["data"]})).expect("filters");
        assert!(docker_volume_matches_filters(&record, &substring));

        let mismatched =
            serde_json::from_value(serde_json::json!({"name": ["cache"]})).expect("filters");
        assert!(!docker_volume_matches_filters(&record, &mismatched));
    }

    #[test]
    fn docker_volume_filters_reject_unsupported_selectors() {
        let filters =
            serde_json::from_value(serde_json::json!({"dangling": ["true"]})).expect("filters");
        let error = validate_docker_volume_filters(&filters).expect_err("unsupported filter");
        assert!(error.contains("unsupported"));
    }

    #[test]
    fn docker_network_filters_match_name_driver_and_type() {
        let custom = super::DockerNetworkView {
            name: "app-net",
            driver: "bridge",
        };
        let filters = serde_json::from_value(serde_json::json!({
            "name": ["app-net"],
            "driver": ["bridge"],
            "scope": ["local"],
            "type": ["custom"]
        }))
        .expect("filters");
        assert!(docker_network_matches_filters(&custom, &filters));

        let substring =
            serde_json::from_value(serde_json::json!({"name": ["app"]})).expect("filters");
        assert!(docker_network_matches_filters(&custom, &substring));

        let builtin = super::DockerNetworkView {
            name: "bridge",
            driver: "bridge",
        };
        assert!(!docker_network_matches_filters(&builtin, &filters));
        let unsupported =
            serde_json::from_value(serde_json::json!({"label": ["x=y"]})).expect("filters");
        assert!(validate_docker_network_filters(&unsupported).is_err());
    }

    #[test]
    fn docker_image_time_filters_reject_unknown_selectors() {
        let image = ferro_core::image_store::ImageRecord {
            reference: "alpine:latest".to_string(),
            digest: "sha256:a".to_string(),
            manifest_media_type: "application/json".to_string(),
            manifest_json: "{}".to_string(),
            created_at_unix: 10,
        };
        let mut filters = HashMap::new();
        filters.insert("since".to_string(), vec!["missing:tag".to_string()]);
        assert!(docker_image_apply_time_bounds(vec![image], &filters).is_err());
    }

    #[test]
    fn docker_image_prune_filters_are_strict_and_deterministic() {
        let make = |reference: &str, created_at_unix| ferro_core::image_store::ImageRecord {
            reference: reference.to_string(),
            digest: "sha256:digest".to_string(),
            manifest_media_type: "application/json".to_string(),
            manifest_json: "{}".to_string(),
            created_at_unix,
        };
        let tagged = make("alpine:latest", 10);
        let dangling = make("sha256:orphan", 10);
        let mut filters = HashMap::new();
        filters.insert("dangling".to_string(), vec!["true".to_string()]);
        assert!(!docker_image_prune_matches_filters(&tagged, &filters));
        assert!(docker_image_prune_matches_filters(&dangling, &filters));
        filters.insert("until".to_string(), vec!["10".to_string()]);
        assert!(!docker_image_prune_matches_filters(&dangling, &filters));
        let unsupported =
            serde_json::from_value(serde_json::json!({"label": ["x=y"]})).expect("filters");
        assert!(validate_docker_image_prune_filters(&unsupported).is_err());
    }

    #[test]
    fn docker_event_query_rejects_malformed_filters() {
        let temp = tempfile::tempdir().expect("event runtime");
        let store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        let mut query = HashMap::new();
        query.insert("filters".to_string(), r#"{"event":true}"#.to_string());
        let error = store
            .query(&query)
            .expect_err("malformed event filters must fail");
        assert!(error.contains("boolean object"), "error={error}");
    }

    #[test]
    fn events_cli_validates_filters_and_local_follow_mode() {
        let temp = tempfile::tempdir().expect("event runtime");
        let error = handle_events(temp.path(), None, None, &["label".to_string()], false)
            .expect_err("malformed CLI filter must fail");
        assert!(error.contains("key=value"), "error={error}");
    }

    #[test]
    fn docker_event_query_filters_persisted_actor_attributes() {
        let temp = tempfile::tempdir().expect("event runtime");
        let mut store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        store.append("POST", "/containers/c1/start", 204).unwrap();

        let mut query = HashMap::new();
        query.insert(
            "filters".to_string(),
            r#"{"label":["method=POST","path=/containers/c1/start"]}"#.to_string(),
        );
        assert_eq!(store.query(&query).unwrap().len(), 1);

        query.insert(
            "filters".to_string(),
            r#"{"label":["path=/containers/c1/stop"]}"#.to_string(),
        );
        assert!(store.query(&query).unwrap().is_empty());
    }

    #[test]
    fn docker_event_query_supports_network_and_volume_resource_filters() {
        let temp = tempfile::tempdir().expect("event runtime");
        let mut store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        store.append("POST", "/networks/mesh/connect", 200).unwrap();
        store.append("POST", "/volumes/data/prune", 200).unwrap();

        let mut query = HashMap::new();
        query.insert("network".to_string(), "mesh".to_string());
        assert_eq!(store.query(&query).unwrap().len(), 1);
        assert_eq!(store.query(&query).unwrap()[0].event_type, "network");

        query.clear();
        query.insert("volume".to_string(), "data".to_string());
        assert_eq!(store.query(&query).unwrap().len(), 1);
        assert_eq!(store.query(&query).unwrap()[0].event_type, "volume");
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
    fn docker_event_query_supports_nanosecond_time_bounds() {
        let temp = tempfile::tempdir().expect("event runtime");
        let mut store = DockerEventStore::open(temp.path().join("events.jsonl")).unwrap();
        store
            .append("POST", "/containers/early/start", 200)
            .unwrap();
        store.append("POST", "/containers/late/start", 200).unwrap();
        let mut query = HashMap::new();
        query.insert("since".to_string(), "0.000000001".to_string());
        query.insert("until".to_string(), "18446744072.000000000".to_string());
        assert_eq!(store.query(&query).unwrap().len(), 2);
        query.insert("since".to_string(), "18446744072.000000000".to_string());
        assert!(store.query(&query).unwrap().is_empty());
        query.insert("since".to_string(), "1.1234567890".to_string());
        assert!(store.query(&query).is_err());
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
    fn docker_attach_hijack_uses_upgrade_headers() {
        let headers = String::from_utf8(docker_hijack_headers()).expect("headers are utf8");
        assert!(headers.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(headers.contains("Connection: Upgrade\r\n"));
        assert!(headers.contains("Upgrade: tcp\r\n"));
        assert!(headers.contains("application/vnd.docker.raw-stream"));
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
        let error = ensure_context_routing_available()
            .expect_err("remote context must not be silently ignored");
        assert!(error.contains("remote daemon routing is not implemented"));
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

    #[cfg(unix)]
    #[test]
    fn context_endpoint_availability_requires_a_real_unix_socket() {
        let temp = tempfile::tempdir().expect("context socket fixture");
        let socket = temp.path().join("ferrocrate.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        assert!(context_endpoint_available(&format!(
            "unix://{}",
            socket.display()
        )));
        drop(listener);
        std::fs::remove_file(&socket).expect("remove socket");
        std::fs::write(&socket, b"decoy").expect("write decoy");
        assert!(!context_endpoint_available(&format!(
            "unix://{}",
            socket.display()
        )));
        assert!(!context_endpoint_available("tcp://127.0.0.1:2375"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_rootless_socket_is_classified_as_local_context() {
        let _guard = ENV_MUTEX.lock().expect("env lock");
        let previous = std::env::var_os("FERROCRATE_ROOTLESS_SOCKET");
        let temp = tempfile::tempdir().expect("rootless socket fixture");
        let socket = temp.path().join("custom-ferrocrate.sock");
        unsafe { std::env::set_var("FERROCRATE_ROOTLESS_SOCKET", &socket) };
        assert!(context_endpoint_is_local(&format!(
            "unix://{}",
            socket.display()
        )));
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_ROOTLESS_SOCKET", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_ROOTLESS_SOCKET") },
        }
    }

    #[cfg(unix)]
    #[test]
    fn remote_context_transport_forwards_http_over_unix_socket() {
        let temp = tempfile::tempdir().expect("remote socket fixture");
        let socket = temp.path().join("remote.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept remote request");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).ok();
            assert!(String::from_utf8_lossy(&request).contains("GET /images/json"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]")
                .expect("write response");
        });
        let (status, body) =
            remote_docker_request(&socket.to_string_lossy(), "GET", "/images/json", None)
                .expect("remote request");
        worker.join().expect("remote worker");
        assert_eq!(status, 200);
        assert_eq!(body, b"[]");
        assert_eq!(percent_encode_path_component("web/name"), "web%2Fname");
    }

    #[cfg(unix)]
    #[test]
    fn remote_system_df_routes_to_docker_endpoint() {
        let _guard = ENV_MUTEX.lock().expect("env lock");
        let previous = std::env::var_os("FERROCRATE_RUNTIME_DIR");
        let temp = tempfile::tempdir().expect("remote df config");
        let socket = temp.path().join("remote-df.sock");
        let listener = UnixListener::bind(&socket).expect("bind remote df socket");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept remote df request");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .expect("read remote df request");
            assert!(String::from_utf8_lossy(&request).contains("GET /system/df"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .expect("respond");
        });
        unsafe {
            std::env::set_var("FERROCRATE_RUNTIME_DIR", temp.path());
        }
        handle_context(ContextCommands::Create {
            name: "remote".to_string(),
            endpoint: format!("unix://{}", socket.display()),
        })
        .expect("create context");
        handle_context(ContextCommands::Use {
            name: "remote".to_string(),
        })
        .expect("use context");
        let command = Cli::try_parse_from(["ferrocrate", "system-df"])
            .expect("parse df")
            .command;
        dispatch_remote_context(&command)
            .expect("remote context should claim system df")
            .expect("remote df should succeed");
        worker.join().expect("remote df worker");
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_RUNTIME_DIR") },
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn remote_commit_path_preserves_repository_and_tag() {
        assert_eq!(
            remote_commit_path("web/name", "example/app:v2").unwrap(),
            "/commit?container=web%2Fname&repo=registry-1.docker.io%2Fexample%2Fapp&tag=v2"
        );
        assert!(remote_commit_path("", "example/app:v2").is_err());
    }

    #[test]
    fn remote_stream_transport_decodes_chunked_logs() {
        let temp = tempfile::tempdir().expect("remote stream fixture");
        let socket = temp.path().join("remote-stream.sock");
        let listener = UnixListener::bind(&socket).expect("bind stream socket");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept stream request");
            let mut request = Vec::new();
            stream
                .read_to_end(&mut request)
                .expect("read stream request");
            assert!(String::from_utf8_lossy(&request)
                .contains("GET /containers/c1/logs?stdout=1&stderr=1&follow=1"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
                )
                .expect("write stream response");
        });
        let mut output = Vec::new();
        remote_docker_stream_request(
            &socket.to_string_lossy(),
            "GET",
            "/containers/c1/logs?stdout=1&stderr=1&follow=1",
            None,
            |chunk| {
                output.extend_from_slice(chunk);
                Ok(())
            },
        )
        .expect("decode stream");
        worker.join().expect("stream worker");
        assert_eq!(output, b"hello world");
    }

    #[test]
    fn parses_logs_follow_flag() {
        let cli = Cli::try_parse_from(["ferrocrate", "logs", "c1", "--follow"])
            .expect("parse logs follow");
        match cli.command {
            Commands::Logs {
                container, follow, ..
            } => {
                assert_eq!(container, "c1");
                assert!(follow);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_stats_follow_flag() {
        let cli =
            Cli::try_parse_from(["ferrocrate", "stats", "c1", "--follow", "--format", "json"])
                .expect("parse stats follow");
        match cli.command {
            Commands::Stats {
                container,
                format,
                follow,
            } => {
                assert_eq!(container, "c1");
                assert_eq!(format, "json");
                assert!(follow);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_top_command() {
        let cli = Cli::try_parse_from(["ferrocrate", "top", "c1", "--format", "json"])
            .expect("parse top");
        match cli.command {
            Commands::Top { container, format } => {
                assert_eq!(container, "c1");
                assert_eq!(format, "json");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_wait_command_and_rejects_unknown_condition() {
        let cli = Cli::try_parse_from([
            "ferrocrate",
            "wait",
            "c1",
            "--condition",
            "next-exit",
            "--timeout",
            "3",
            "--format",
            "json",
        ])
        .expect("parse wait");
        match cli.command {
            Commands::Wait {
                container,
                condition,
                timeout,
                format,
            } => {
                assert_eq!(container, "c1");
                assert_eq!(condition, "next-exit");
                assert_eq!(timeout, Some(3));
                assert_eq!(format, "json");
            }
            other => panic!("unexpected command: {other:?}"),
        }
        assert!(validate_wait_condition("bogus").is_err());
    }

    #[test]
    fn remote_run_rejects_unrepresentable_options_before_connecting() {
        let _guard = ENV_MUTEX.lock().expect("env lock");
        let previous = std::env::var_os("FERROCRATE_RUNTIME_DIR");
        let temp = tempfile::tempdir().expect("remote run config");
        unsafe {
            std::env::set_var("FERROCRATE_RUNTIME_DIR", temp.path());
        }
        handle_context(ContextCommands::Create {
            name: "remote".to_string(),
            endpoint: "unix:///tmp/remote-run.sock".to_string(),
        })
        .expect("create context");
        handle_context(ContextCommands::Use {
            name: "remote".to_string(),
        })
        .expect("select context");
        let command = Cli::try_parse_from(["ferrocrate", "run", "alpine", "--profile", "prod"])
            .expect("parse run")
            .command;
        let result = dispatch_remote_context(&command)
            .expect("remote context should claim run")
            .expect_err("local-only option must be rejected");
        assert!(result.contains("--profile"), "error={result}");

        let conflicting =
            Cli::try_parse_from(["ferrocrate", "run", "alpine", "--read-only", "--read-write"])
                .expect("parse conflicting rootfs flags")
                .command;
        let result = dispatch_remote_context(&conflicting)
            .expect("remote context should claim run")
            .expect_err("conflicting rootfs flags must be rejected");
        assert!(
            result.contains("read-only and --read-write"),
            "error={result}"
        );

        let invalid_name =
            Cli::try_parse_from(["ferrocrate", "run", "alpine", "--name", "bad/name"])
                .expect("parse invalid remote name")
                .command;
        let result = dispatch_remote_context(&invalid_name)
            .expect("remote context should claim run")
            .expect_err("invalid Docker names must be rejected");
        assert!(result.contains("container name"), "error={result}");

        let invalid_cap = Cli::try_parse_from([
            "ferrocrate",
            "run",
            "alpine",
            "--cap-add",
            "NOT_A_CAPABILITY",
        ])
        .expect("parse invalid remote capability")
        .command;
        let result = dispatch_remote_context(&invalid_cap)
            .expect("remote context should claim run")
            .expect_err("invalid capabilities must be rejected");
        assert!(result.contains("unknown capability"), "error={result}");

        let invalid_bind =
            Cli::try_parse_from(["ferrocrate", "run", "alpine", "--bind", "/host-only"])
                .expect("parse invalid remote bind")
                .command;
        let result = dispatch_remote_context(&invalid_bind)
            .expect("remote context should claim run")
            .expect_err("invalid bind mounts must be rejected");
        assert!(result.contains("bind mount"), "error={result}");

        let invalid_volume =
            Cli::try_parse_from(["ferrocrate", "run", "alpine", "--volume", "data-only"])
                .expect("parse invalid remote volume")
                .command;
        let result = dispatch_remote_context(&invalid_volume)
            .expect("remote context should claim run")
            .expect_err("invalid volumes must be rejected");
        assert!(result.contains("volume must be"), "error={result}");

        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_RUNTIME_DIR") },
        }
    }

    #[test]
    fn remote_run_sends_docker_create_then_start() {
        let _guard = ENV_MUTEX.lock().expect("env lock");
        let previous = std::env::var_os("FERROCRATE_RUNTIME_DIR");
        let temp = tempfile::tempdir().expect("remote run config");
        let socket = temp.path().join("remote-run.sock");
        let listener = UnixListener::bind(&socket).expect("bind remote run socket");
        let worker = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in [
                b"HTTP/1.1 201 Created\r\nContent-Length: 34\r\nConnection: close\r\n\r\n{\"Id\":\"remote-id\",\"Warnings\":null}".as_slice(),
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().expect("accept remote run request");
                let mut request = Vec::new();
                stream.read_to_end(&mut request).expect("read remote run request");
                requests.push(request);
                stream.write_all(response).expect("write remote run response");
            }
            requests
        });
        unsafe {
            std::env::set_var("FERROCRATE_RUNTIME_DIR", temp.path());
        }
        handle_context(ContextCommands::Create {
            name: "remote".to_string(),
            endpoint: format!("unix://{}", socket.display()),
        })
        .expect("create context");
        handle_context(ContextCommands::Use {
            name: "remote".to_string(),
        })
        .expect("select context");
        let command = Cli::try_parse_from([
            "ferrocrate",
            "run",
            "alpine:latest",
            "--name",
            "web-name",
            "--env",
            "MODE=test",
            "--label",
            "tier=frontend",
            "--publish",
            "8080:80/tcp",
            "--read-only",
            "--no-new-privileges",
            "--cap-add",
            "NET_ADMIN",
            "--tmpfs",
            "/tmp:size=64m",
            "--restart",
            "always",
            "--health-cmd",
            "test -f /ready",
            "--health-interval",
            "10",
            "--memory-max",
            "1048576",
            "--cpu-quota",
            "50000",
            "--cpu-period",
            "100000",
            "--pids-max",
            "64",
            "echo",
            "ready",
        ])
        .expect("parse run")
        .command;
        dispatch_remote_context(&command)
            .expect("remote context should claim run")
            .expect("remote run should succeed");
        let requests = worker.join().expect("remote run worker");
        let create = String::from_utf8_lossy(&requests[0]);
        assert!(create.contains("POST /containers/create?name=web-name"));
        assert!(create.contains("\"Image\":\"alpine:latest\""));
        assert!(create.contains("\"NetworkMode\":\"bridge\""));
        assert!(create.contains("\"ReadonlyRootfs\":true"));
        assert!(create.contains("\"CapAdd\":[\"NET_ADMIN\"]"));
        assert!(create.contains("\"Tmpfs\":{\"/tmp\":\"size=64m\"}"));
        assert!(create.contains("\"RestartPolicy\":{\"MaximumRetryCount\":0,\"Name\":\"always\"}"));
        assert!(create.contains("\"Healthcheck\":{\"Interval\":10000000000"));
        assert!(create.contains("\"Test\":[\"CMD-SHELL\",\"test -f /ready\"]"));
        assert!(create.contains("\"Memory\":1048576"));
        assert!(create.contains("\"CpuQuota\":50000"));
        assert!(create.contains("\"CpuPeriod\":100000"));
        assert!(create.contains("\"PidsLimit\":64"));
        assert!(create.contains("\"SecurityOpt\":[\"no-new-privileges\"]"));
        assert!(create.contains("\"80/tcp\":[{\"HostPort\":\"8080\"}]"));
        assert!(String::from_utf8_lossy(&requests[1]).contains("POST /containers/remote-id/start"));

        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_RUNTIME_DIR") },
        }
    }

    #[cfg(unix)]
    #[test]
    fn remote_build_sends_tar_context_to_docker_build_api() {
        let _guard = ENV_MUTEX.lock().expect("env lock");
        let previous = std::env::var_os("FERROCRATE_RUNTIME_DIR");
        let temp = tempfile::tempdir().expect("remote build config");
        let context = temp.path().join("context");
        std::fs::create_dir(&context).expect("create context");
        std::fs::write(context.join("Dockerfile"), b"FROM scratch\n").expect("write Dockerfile");
        let platform = format!("linux/{}", host_build_arch());
        let socket = temp.path().join("remote-build.sock");
        let listener = UnixListener::bind(&socket).expect("bind socket");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).expect("read");
            let request = String::from_utf8_lossy(&request);
            assert!(request.contains(
                "POST /build?dockerfile=Dockerfile&t=example%2Fapp%3Adev&platform=linux%2F"
            ));
            assert!(request.contains("Content-Type: application/x-tar"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .expect("respond");
        });
        unsafe {
            std::env::set_var("FERROCRATE_RUNTIME_DIR", temp.path());
        }
        handle_context(ContextCommands::Create {
            name: "remote".to_string(),
            endpoint: format!("unix://{}", socket.display()),
        })
        .expect("create context");
        handle_context(ContextCommands::Use {
            name: "remote".to_string(),
        })
        .expect("use context");
        let command = Cli::try_parse_from([
            "ferrocrate",
            "build",
            "--dockerfile",
            context.join("Dockerfile").to_str().unwrap(),
            "--tag",
            "example/app:dev",
            "--platform",
            platform.as_str(),
        ])
        .unwrap()
        .command;
        dispatch_remote_context(&command).unwrap().unwrap();
        worker.join().unwrap();
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_RUNTIME_DIR") },
        }
    }

    #[test]
    fn remote_run_rm_waits_for_exit_then_removes_container() {
        let _guard = ENV_MUTEX.lock().expect("env lock");
        let previous = std::env::var_os("FERROCRATE_RUNTIME_DIR");
        let temp = tempfile::tempdir().expect("remote run rm config");
        let socket = temp.path().join("remote-run-rm.sock");
        let listener = UnixListener::bind(&socket).expect("bind remote run rm socket");
        let worker = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in [
                b"HTTP/1.1 201 Created\r\nContent-Length: 34\r\nConnection: close\r\n\r\n{\"Id\":\"remote-rm-id\",\"Warnings\":null}".as_slice(),
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\n{\"StatusCode\":0}".as_slice(),
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().expect("accept remote run rm request");
                let mut request = Vec::new();
                stream
                    .read_to_end(&mut request)
                    .expect("read remote run rm request");
                requests.push(request);
                stream
                    .write_all(response)
                    .expect("write remote run rm response");
            }
            requests
        });
        unsafe {
            std::env::set_var("FERROCRATE_RUNTIME_DIR", temp.path());
        }
        handle_context(ContextCommands::Create {
            name: "remote".to_string(),
            endpoint: format!("unix://{}", socket.display()),
        })
        .expect("create context");
        handle_context(ContextCommands::Use {
            name: "remote".to_string(),
        })
        .expect("select context");
        let command = Cli::try_parse_from(["ferrocrate", "run", "alpine:latest", "--rm"])
            .expect("parse run")
            .command;
        dispatch_remote_context(&command)
            .expect("remote context should claim run")
            .expect("remote run --rm should succeed");
        let requests = worker.join().expect("remote run rm worker");
        assert!(String::from_utf8_lossy(&requests[0]).contains("POST /containers/create"));
        assert!(
            String::from_utf8_lossy(&requests[1]).contains("POST /containers/remote-rm-id/start")
        );
        assert!(String::from_utf8_lossy(&requests[2])
            .contains("POST /containers/remote-rm-id/wait?condition=not-running"));
        assert!(String::from_utf8_lossy(&requests[3]).contains("DELETE /containers/remote-rm-id"));

        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_RUNTIME_DIR", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_RUNTIME_DIR") },
        }
    }

    #[test]
    fn remote_exec_raw_stream_decoder_separates_stdout_and_stderr() {
        let raw = docker_raw_stream("out\n", "err\n");
        let (stdout, stderr) = decode_docker_raw_stream(&raw).expect("decode stream");
        assert_eq!(stdout, b"out\n");
        assert_eq!(stderr, b"err\n");
        assert!(decode_docker_raw_stream(&raw[..7]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn remote_context_transport_supports_authorized_lifecycle_methods() {
        let temp = tempfile::tempdir().expect("remote socket fixture");
        let socket = temp.path().join("remote.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind socket");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept remote request");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).ok();
            let request = String::from_utf8_lossy(&request);
            assert!(request.contains("POST /containers/web%2Fname/stop?t=7"));
            assert!(request.contains("{\"Name\":\"mesh\"}"));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write response");
        });
        let (status, body) = remote_docker_request(
            &socket.to_string_lossy(),
            "POST",
            "/containers/web%2Fname/stop?t=7",
            Some(br#"{"Name":"mesh"}"#),
        )
        .expect("remote lifecycle request");
        worker.join().expect("remote worker");
        assert_eq!(status, 204);
        assert!(body.is_empty());
    }

    #[test]
    fn containers_handler_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        handle_containers(&runtime, "text", false, None, None, None, &[])
            .expect("containers handler should succeed");
    }

    #[test]
    fn logs_handler_requires_container() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_logs(&runtime, "", "text", false).expect_err("container required");
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
        let err = handle_stats(&runtime, "", "text", false).expect_err("container required");
        assert!(err.contains("stats: container is required"));
    }

    #[test]
    fn top_handler_requires_container() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let err = handle_top(&runtime, "", "text").expect_err("container required");
        assert!(err.contains("top: container is required"));
    }

    #[test]
    fn wait_handler_validates_container_and_condition() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let missing =
            handle_wait(&runtime, "", "not-running", None, "text").expect_err("container required");
        assert!(missing.contains("wait: container is required"));
        let invalid =
            handle_wait(&runtime, "c1", "bogus", None, "text").expect_err("condition validation");
        assert!(invalid.contains("condition must be"));
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
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl TestRuntimeDir {
        fn new() -> Self {
            let guard = ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let dir = tempfile::tempdir().expect("tempdir");
            let original = std::env::var("FERROCRATE_RUNTIME_DIR").ok();
            unsafe {
                std::env::set_var("FERROCRATE_RUNTIME_DIR", dir.path());
            }
            Self {
                original,
                _dir: dir,
                _guard: guard,
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
