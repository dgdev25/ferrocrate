use clap::{Parser, Subcommand};
use ferro_core::docker_auth::resolve_registry_auth;
use ferro_core::image_manifest::parse_image_manifest;
use ferro_core::image_store::LocalImageStore;
use ferro_core::image_tagging::{canonicalize_reference, resolve_reference};
use ferro_core::layer_compression::CompressionFormat;
use ferro_core::registry::{RegistryClient, parse_image_reference};
use ferro_core::runtime::ContainerRuntime;
use ferro_compose::compose::{
    ComposeProject, compose_down, compose_logs, compose_ps, compose_up, find_compose_file,
};
use ferro_compose::{Command as ComposeCommandSpec, Environment as ComposeEnvironment, Service as ComposeService};
use serde::Serialize;
use owo_colors::OwoColorize;
use std::collections::{BTreeMap, HashMap};
use std::process;
use std::path::{Path, PathBuf};

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
    Compose {
        #[arg(short, long)]
        file: Option<String>,
        #[command(subcommand)]
        command: ComposeCommands,
    },
}

#[derive(Debug, Subcommand)]
pub enum ComposeCommands {
    Up,
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

    match command {
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
            memory_max,
            cpu_quota,
            cpu_period,
            pids_max,
        } => {
            handle_run(
                &runtime,
                &image_store,
                &image,
                &cmd,
                &network,
                &network_backend,
                &bind_mounts,
                &tmpfs_mounts,
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
        Commands::Compose { file, command } => {
            handle_compose(&runtime, &image_store, file.as_deref(), command)
        }
    }
}

fn handle_run(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    image: &str,
    cmd: &[String],
    network: &str,
    network_backend: &str,
    bind_mounts: &[String],
    tmpfs_mounts: &[String],
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
    memory_max: Option<u64>,
    cpu_quota: Option<u64>,
    cpu_period: Option<u64>,
    pids_max: Option<u64>,
) -> Result<(), String> {
    validate_network_mode(network)?;
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
        .run(
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
    Ok(())
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
    ferro_core::image_fetch::pull_image(&runtime_dir, &canonical)
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
    dockerfile: Option<&str>,
    ferrofile: Option<&str>,
    tag: Option<&str>,
    compression: &str,
) -> Result<(), String> {
    let runtime_dir = runtime_dir();
    let compression = parse_compression(compression)?;
    if let Some(ferrofile_path) = ferrofile {
        let result = ferro_core::ferrofile_build::build_from_ferrofile(
            Path::new(ferrofile_path),
            &runtime_dir,
            compression,
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

    let result = ferro_core::dockerfile_build::build_from_dockerfile_with_compression(
        Path::new(dockerfile),
        Some(tag),
        &runtime_dir,
        compression,
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
        "bridge" | "host" | "none" => Ok(()),
        _ => Err("network must be one of: bridge, host, none".to_string()),
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
        let canonical = ferro_core::image_fetch::pull_manifest_only(&runtime_dir, image)
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
    let layer_paths = ferro_core::image_fetch::resolve_layer_paths(&runtime_dir, &canonical)
        .map_err(|err| err.to_string())?;
    let manifest = parse_image_manifest(&record.manifest_json)
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
        .push_manifest_raw(&canonical, &record.manifest_json, auth.as_ref())
        .map_err(|err| err.to_string())?;
    println!("push: image={canonical}");
    Ok(())
}

fn handle_compose(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    file: Option<&str>,
    command: ComposeCommands,
) -> Result<(), String> {
    let path = find_compose_file(file).map_err(|err| err.to_string())?;
    let project = ComposeProject::load(&path).map_err(|err| err.to_string())?;
    let project_dir = path.parent().unwrap_or_else(|| Path::new("."));
    match command {
        ComposeCommands::Up => {
            let order = compose_up(&project).map_err(|err| err.to_string())?;
            for name in order {
                let service = project
                    .compose
                    .services
                    .get(&name)
                    .ok_or_else(|| format!("compose: missing service {name}"))?;
                run_compose_service(runtime, store, project_dir, &name, service)?;
            }
        }
        ComposeCommands::Down => {
            let order = compose_down(&project).map_err(|err| err.to_string())?;
            for name in order {
                if let Ok(id) = resolve_container_id(runtime, &name) {
                    let _ = runtime.stop(&id, std::time::Duration::from_secs(5));
                    let _ = runtime.remove(&id);
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

fn run_compose_service(
    runtime: &ContainerRuntime,
    store: &LocalImageStore,
    project_dir: &Path,
    name: &str,
    service: &ComposeService,
) -> Result<(), String> {
    let image = service
        .image
        .as_deref()
        .ok_or_else(|| format!("compose: service {name} missing image"))?;
    let cmd = compose_service_command(service);
    let env = compose_service_env(project_dir, service)?;
    let labels = compose_service_labels(service);
    let publish = compose_service_ports(service);
    let bind_mounts = compose_service_mounts(service);
    let restart = service.restart.as_deref().unwrap_or("no");

    handle_run(
        runtime,
        store,
        image,
        &cmd,
        "bridge",
        "ebpf",
        &bind_mounts,
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
        Some(name),
        &publish,
        None,
        None,
        None,
        None,
        None,
        restart,
        None,
        None,
        None,
        None,
    )
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

fn compose_service_mounts(service: &ComposeService) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(volumes) = service.volumes.as_ref() {
        for entry in volumes {
            let source = entry.split(':').next().unwrap_or("");
            if source.starts_with('.') || source.contains('/') {
                out.push(entry.clone());
            }
        }
    }
    out
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
                assert!(matches!(command, ComposeCommands::Up));
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
        let err = handle_run(
            &runtime,
            &store,
            "",
            &[],
            "bridge",
            "ebpf",
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
        let err = handle_build(None, None, None, "gzip").expect_err("dockerfile required");
        assert!(err.contains("dockerfile path is required"));
    }

    #[test]
    fn build_handler_rejects_invalid_tag() {
        let err = handle_build(Some("./Dockerfile"), None, Some(""), "gzip")
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
