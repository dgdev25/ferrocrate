use clap::{Parser, Subcommand, CommandFactory};
use clap_complete::{Shell, generate};
use ferro_core::docker_auth::resolve_registry_auth;
use ferro_core::image_manifest::parse_image_manifest;
use ferro_core::image_store::LocalImageStore;
use ferro_core::image_tagging::{canonicalize_reference, resolve_reference};
use ferro_core::layer_compression::CompressionFormat;
use ferro_core::registry::{RegistryClient, parse_image_reference};
use ferro_core::runtime::ContainerRuntime;
use ferro_core::rootfs::construct_rootfs_with_dedup;
use ferro_core::image_fetch::resolve_layer_paths_with_store;
use ferro_mind::ai::audit::AuditLogger;
use ferro_mind::ai::explain::DecisionTrace;
use ferro_core::volume_store::LocalVolumeStore;
use ferro_compose::compose::{
    ComposeProject, compose_down, compose_logs, compose_ps, compose_up, find_compose_file,
};
use ferro_compose::{
    Command as ComposeCommandSpec,
    DependsOn as ComposeDependsOn,
    Environment as ComposeEnvironment,
    Service as ComposeService,
};
use serde::Serialize;
use owo_colors::OwoColorize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::process;
use std::path::{Path, PathBuf};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use std::io::{Read, Write};
use std::time::SystemTime;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Parser)]
#[command(name = "ferrocrate", version, about = "FerroCrate CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
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
        #[arg(trailing_var_arg = true)]
        cmd: Vec<String>,
    },
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
    Volume {
        #[command(subcommand)]
        command: VolumeCommands,
    },
    #[command(alias = "ps")]
    Containers {
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Logs {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Stats {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Inspect {
        container: String,
        #[arg(long, default_value = "text", value_parser = validate_output_format)]
        format: String,
    },
    Pause {
        container: String,
    },
    Unpause {
        container: String,
    },
    Stop {
        container: String,
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
    Kill {
        container: String,
    },
    Rm {
        container: String,
    },
    Restart {
        container: String,
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
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
    Scan {
        image: String,
        #[arg(long, default_value = "auto")]
        scanner: String,
    },
    Compose {
        #[arg(short, long)]
        file: Option<String>,
        #[command(subcommand)]
        command: ComposeCommands,
    },
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
    Tui,
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
    Backup { name: String, path: String },
    Restore { name: String, path: String },
    Ls,
    Rm { name: String },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = dispatch(cli.command) {
        eprintln!("error: {err}");
        process::exit(1);
    }
}

fn dispatch(command: Commands) -> Result<(), String> {
    let runtime_dir = runtime_dir();
    let runtime = ContainerRuntime::new(&runtime_dir).map_err(|err| err.to_string())?;
    let image_store = LocalImageStore::open(runtime_dir.join("images"))
        .map_err(|err| err.to_string())?;
    let volume_store = LocalVolumeStore::open(runtime_dir.join("volumes"))
        .map_err(|err| err.to_string())?;

    match command {
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
        } => {
            handle_run(
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
            )
        }
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
        Commands::Containers { format } => handle_containers(&runtime, &format),
        Commands::Logs { container, format } => handle_logs(&runtime, &container, &format),
        Commands::Inspect { container, format } => handle_inspect(&runtime, &container, &format),
        Commands::Stats { container, format } => handle_stats(&runtime, &container, &format),
        Commands::Pause { container } => handle_pause(&runtime, &container),
        Commands::Unpause { container } => handle_unpause(&runtime, &container),
        Commands::Stop { container, timeout } => {
            handle_stop(&runtime, &container, timeout)
        }
        Commands::Kill { container } => handle_kill(&runtime, &container),
        Commands::Rm { container } => handle_rm(&runtime, &container),
        Commands::Restart { container, timeout } => {
            handle_restart(&runtime, &container, timeout)
        }
        Commands::Exec { container, cmd } => handle_exec(&runtime, &container, &cmd),
        Commands::Pull { image, lazy } => handle_pull(&image_store, &image, lazy),
        Commands::Push { image } => handle_push(&image_store, &image),
        Commands::Scan { image, scanner } => handle_scan(&image_store, &image, &scanner),
        Commands::Compose { file, command } => {
            handle_compose(
                &runtime,
                &image_store,
                &volume_store,
                file.as_deref(),
                command,
            )
        }
        Commands::Daemon {
            socket,
            docker_compat,
            metrics_addr,
        } => run_daemon(&runtime, &image_store, &socket, docker_compat, metrics_addr.as_deref()),
        Commands::Completion { shell } => handle_completion(&shell),
        Commands::Tui => handle_tui(&runtime),
        Commands::AiAudit { action, summary, evidence } => {
            handle_ai_audit(&action, &summary, &evidence)
        }
        Commands::Migrate { target } => handle_migrate(target),
    }
}

fn handle_run(
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
) -> Result<(), String> {
    let _bridge_cidr_guard = ScopedEnv::set("FERROCRATE_BRIDGE_CIDR", bridge_cidr);
    let _bridge_name_guard = ScopedEnv::set("FERROCRATE_BRIDGE_NAME", bridge_name);
    let _net_limit_guard = ScopedEnv::set("FERROCRATE_BANDWIDTH_LIMIT", net_limit);
    validate_network_mode(network)?;
    let network = if network == "encrypted" { "wireguard" } else { network };
    let mut effective_backend = network_backend.to_string();
    if !publish.is_empty() && network != "bridge" {
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
            network,
            &effective_backend,
        )
        .map_err(|err| err.to_string())?;
    println!(
        "run: container_id={} pid={} network_backend={}",
        record.id, record.pid, effective_backend
    );
    if rm {
        wait_for_container_exit(runtime, &record.id)?;
        runtime
            .remove(&record.id)
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn handle_completion(shell: &str) -> Result<(), String> {
    let shell = parse_shell(shell)?;
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "ferrocrate", &mut std::io::stdout());
    Ok(())
}

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
        println!("{:<20} {:<12} {:<20} {}", "CONTAINER", "STATUS", "IMAGE", "COMMAND");
        let containers = runtime.list().map_err(|err| err.to_string())?;
        for record in containers {
            let name = record.name.unwrap_or(record.id);
            let cmd = record.command.join(" ");
            println!("{:<20} {:<12} {:<20} {}", name, record.status, record.image, cmd);
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
    let logger = AuditLogger::from_env().ok_or_else(|| {
        "ai-audit: FERROCRATE_AI_AUDIT_LOG not set or AI disabled".to_string()
    })?;
    let mut trace = DecisionTrace::new("manual", summary);
    for entry in evidence {
        if let Some((key, value)) = entry.split_once('=') {
            trace = trace.with_evidence(key, value);
        }
    }
    logger
        .log(action, &trace)
        .map_err(|err| format!("ai-audit: {err}"))?;
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
        let entries = std::fs::read_dir(&path)
            .map_err(|err| format!("watch: {err}"))?;
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
                None => volume_store
                    .create(source)
                    .map_err(|err| err.to_string())?,
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

fn parse_publish(entries: &[String]) -> Result<Vec<ferro_core::container_store::PortMappingRecord>, String> {
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

fn parse_tmpfs_mounts(tmpfs_mounts: &[String]) -> Result<Vec<ferro_core::mounts::TmpfsMount>, String> {
    let mut out = Vec::new();
    for entry in tmpfs_mounts {
        let parts = entry.split(':').collect::<Vec<_>>();
        if parts.is_empty() || parts[0].is_empty() {
            return Err("run: tmpfs must be target[:size=...]".to_string());
        }
        let size = parts.get(1).map(|val| val.trim_start_matches("size=").to_string());
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
    let existing = resolve_reference(store, &canonical)
        .map_err(|err| err.to_string())?;
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
    let removed = store.remove_reference(image).map_err(|err| err.to_string())?;
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

fn handle_pause(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("pause: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.pause(&resolved).map_err(|err| err.to_string())?;
    println!("pause: {resolved}");
    Ok(())
}

fn handle_unpause(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("unpause: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.resume(&resolved).map_err(|err| err.to_string())?;
    println!("unpause: {resolved}");
    Ok(())
}

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

fn handle_kill(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("kill: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.kill(&resolved).map_err(|err| err.to_string())?;
    println!("kill: {resolved}");
    Ok(())
}

fn handle_rm(runtime: &ContainerRuntime, container: &str) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("rm: container is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    runtime.remove(&resolved).map_err(|err| err.to_string())?;
    println!("rm: {resolved}");
    Ok(())
}

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

fn parse_restart_policy(policy: &str) -> Result<ferro_core::container_store::RestartPolicy, String> {
    match policy {
        "no" => Ok(ferro_core::container_store::RestartPolicy::No),
        "on-failure" => Ok(ferro_core::container_store::RestartPolicy::OnFailure),
        "always" => Ok(ferro_core::container_store::RestartPolicy::Always),
        "unless-stopped" => Ok(ferro_core::container_store::RestartPolicy::UnlessStopped),
        _ => Err("run: restart must be no|on-failure|always|unless-stopped".to_string()),
    }
}

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

fn handle_exec(runtime: &ContainerRuntime, container: &str, cmd: &[String]) -> Result<(), String> {
    if container.trim().is_empty() {
        return Err("exec: container is required".to_string());
    }
    if cmd.is_empty() {
        return Err("exec: command is required".to_string());
    }
    let resolved = resolve_container_id(runtime, container)?;
    let result = runtime.exec(&resolved, cmd).map_err(|err| err.to_string())?;
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }
    Ok(())
}

fn resolve_container_id(runtime: &ContainerRuntime, container: &str) -> Result<String, String> {
    if runtime.inspect(container).is_ok() {
        return Ok(container.to_string());
    }
    let records = runtime.list().map_err(|err| err.to_string())?;
    let mut matches = records
        .into_iter()
        .filter(|record| record.name.as_deref() == Some(container))
        .map(|record| record.id)
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(format!("container not found: {container}")),
        1 => Ok(matches.remove(0)),
        _ => Err(format!("container name is not unique: {container}")),
    }
}

fn handle_pull(store: &LocalImageStore, image: &str, lazy: bool) -> Result<(), String> {
    if lazy {
        let runtime_dir = runtime_dir();
        let canonical = ferro_core::image_fetch::pull_manifest_only_with_store(
            &runtime_dir,
            image,
            store,
        )
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
    let layer_paths = ferro_core::image_fetch::resolve_layer_paths_with_store(
        &runtime_dir,
        &canonical,
        store,
    )
        .map_err(|err| err.to_string())?;
    let config_path = ferro_core::image_fetch::resolve_config_path_with_store(
        &runtime_dir,
        &canonical,
        store,
    )
    .map_err(|err| err.to_string())?
    .ok_or_else(|| format!("push: missing config blob for {canonical}"))?;
    let manifest = parse_image_manifest(&record.manifest_json)
        .map_err(|err| err.to_string())?;

    client
        .push_blob_from_file(&canonical, &manifest.config.digest, &config_path, auth.as_ref())
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
                run_compose_service(
                    runtime,
                    store,
                    volume_store,
                    project_dir,
                    &name,
                    service,
                )?;
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
                    ComposeCommands::Up { profile: profile.clone() },
                )?;
                loop {
                    std::thread::sleep(Duration::from_secs(interval));
                    let current = latest_mtime(project_dir)?;
                    if current > last_mtime {
                        last_mtime = current;
                        break;
                    }
                }
                handle_compose(
                    runtime,
                    store,
                    volume_store,
                    file,
                    ComposeCommands::Down,
                )?;
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
                return Err(format!(
                    "compose: dependency {service} has no healthcheck"
                ));
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
        )?;
    }
    Ok(())
}

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

fn compose_service_env(project_dir: &Path, service: &ComposeService) -> Result<Vec<String>, String> {
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

    Ok(env.into_iter().map(|(key, value)| format!("{key}={value}")).collect())
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

#[derive(Default)]
struct DockerCompatState {
    next_id: AtomicU64,
    pending: Mutex<HashMap<String, DockerCreateSpec>>,
}

fn run_daemon(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    socket: &str,
    docker_compat: bool,
    metrics_addr: Option<&str>,
) -> Result<(), String> {
    let _ = (runtime, store);
    if !docker_compat {
        return Err("daemon: --docker-compat is required".to_string());
    }
    let socket_path = Path::new(socket);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|err| err.to_string())?;
    }

    let listener = UnixListener::bind(socket_path).map_err(|err| err.to_string())?;
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

fn handle_docker_compat_connection(
    mut stream: UnixStream,
    runtime_dir: Arc<PathBuf>,
    store: Arc<LocalImageStore>,
    volume_store: Arc<LocalVolumeStore>,
    state: Arc<DockerCompatState>,
) -> Result<(), String> {
    let request = read_http_request(&mut stream)?;
    let runtime = ContainerRuntime::new(&runtime_dir).map_err(|err| err.to_string())?;

    let (path, query) = split_path_query(&request.path);
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
            http_response(200, serde_json::to_string(&entries).unwrap().as_bytes(), "application/json")
        }
        ("GET", path) if path.starts_with("/containers/") && path.ends_with("/json") => {
            let id = path.trim_start_matches("/containers/").trim_end_matches("/json");
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
            let id = path.trim_start_matches("/containers/").trim_end_matches("/logs");
            let logs = runtime.logs(id).map_err(|err| err.to_string())?;
            http_response(200, logs.as_bytes(), "text/plain")
        }
        ("GET", path) if path.starts_with("/containers/") && path.ends_with("/stats") => {
            let id = path.trim_start_matches("/containers/").trim_end_matches("/stats");
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
            state.pending.lock().unwrap().insert(id.clone(), spec);
            let body = serde_json::json!({ "Id": id, "Warnings": serde_json::Value::Null });
            http_response(201, body.to_string().as_bytes(), "application/json")
        }
        ("POST", path) if path.starts_with("/containers/") && path.ends_with("/start") => {
            let id = path.trim_start_matches("/containers/").trim_end_matches("/start");
            let spec = {
                let mut pending = state.pending.lock().unwrap();
                pending.remove(id)
            }
            .ok_or_else(|| format!("docker: unknown container {id}"))?;
            handle_run(
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
            )?;
            http_response(204, &[], "text/plain")
        }
        ("POST", path) if path.starts_with("/containers/") && path.ends_with("/stop") => {
            let id = path.trim_start_matches("/containers/").trim_end_matches("/stop");
            runtime
                .stop(id, Duration::from_secs(5))
                .map_err(|err| err.to_string())?;
            http_response(204, &[], "text/plain")
        }
        ("POST", path) if path.starts_with("/containers/") && path.ends_with("/restart") => {
            let id = path.trim_start_matches("/containers/").trim_end_matches("/restart");
            runtime
                .restart(id, Duration::from_secs(5))
                .map_err(|err| err.to_string())?;
            http_response(204, &[], "text/plain")
        }
        ("POST", path) if path.starts_with("/containers/") && path.ends_with("/kill") => {
            let id = path.trim_start_matches("/containers/").trim_end_matches("/kill");
            runtime.kill(id).map_err(|err| err.to_string())?;
            http_response(204, &[], "text/plain")
        }
        ("POST", path) if path.starts_with("/containers/") && path.ends_with("/wait") => {
            let id = path.trim_start_matches("/containers/").trim_end_matches("/wait");
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
            http_response(200, serde_json::to_string(&entries).unwrap().as_bytes(), "application/json")
        }
        ("GET", path) if path.starts_with("/images/") && path.ends_with("/json") => {
            let name = path.trim_start_matches("/images/").trim_end_matches("/json");
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
        _ => http_response(404, b"{\"message\":\"not found\"}", "application/json"),
    };

    stream.write_all(&response).map_err(|err| err.to_string())?;
    Ok(())
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
        Some(other) => {
            return Err(format!(
                "docker: unsupported network mode {other}"
            ))
        }
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
            .map(|(port, proto)| (port, proto))
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

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut UnixStream) -> Result<HttpRequest, String> {
    let mut buffer = Vec::new();
    let mut header_end = None;
    let mut temp = [0u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
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
        if buffer.len() > 1024 * 1024 {
            return Err("docker: request too large".to_string());
        }
    }
    let header_end = header_end.ok_or_else(|| "docker: invalid request".to_string())?;
    let header_str = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_str.lines();
    let request_line = lines.next().ok_or_else(|| "docker: invalid request".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }
    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut temp).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&temp[..read]);
    }
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
        Cli, Commands, ComposeCommands, VolumeCommands, dispatch, handle_build, handle_containers, handle_exec,
        handle_image_prune, handle_images, handle_inspect, handle_logs, handle_pause, handle_pull,
        handle_push, handle_rmi, handle_run, handle_stats, handle_stop, handle_kill, handle_rm, handle_restart,
        handle_unpause, build_limits, handle_volume,
        build_health_config, effective_readonly, parse_bind_mounts, parse_capabilities,
        parse_driver_opts, parse_env_entries, parse_key_values, parse_restart_policy, parse_publish,
        parse_tmpfs_mounts,
        validate_network_backend, validate_network_mode,
    };
    use clap::Parser;
    use ferro_core::image_store::LocalImageStore;
    use ferro_core::runtime::ContainerRuntime;
    use ferro_core::volume_store::LocalVolumeStore;

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
        std::fs::write(std::path::PathBuf::from(&record.path).join("hello.txt"), "hi")
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

        handle_volume(&runtime_dir, VolumeCommands::Rm { name: "data".to_string() })
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
        handle_volume(&runtime_dir, VolumeCommands::Rm { name: "data".to_string() })
            .expect("rm volume");
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
        let err = handle_exec(&runtime, "", &["/bin/sh".to_string()])
            .expect_err("container required");
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
            Self { original, _dir: dir }
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
