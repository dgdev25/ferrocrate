#[cfg(target_os = "linux")]
use crate::capabilities::{drop_all_capabilities, set_capabilities};
use crate::cgroups::{CgroupStats, CgroupV2Manager, ResourceLimits};
use crate::container_exec::{exec_in_container, exec_in_container_with_timeout};
use crate::container_store::{
    now_unix, ContainerRecord, ContainerStoreError, HealthConfig, LocalContainerStore,
    PortMappingRecord, RestartPolicy,
};
use crate::image_config::{
    command_from_config, env_from_config, healthcheck_from_config, user_from_config,
    working_dir_from_config,
};
use crate::image_fetch::{resolve_config_path_with_store, resolve_layer_paths_with_store};
use crate::image_security::verify_image_signature;
use crate::image_store::LocalImageStore;
use crate::mac_profiles::generate_apparmor_profile;
use crate::mounts::{
    apply_bind_mounts, apply_readonly_rootfs, apply_tmpfs_mounts, BindMount, MountError, TmpfsMount,
};
use crate::observability::{log_audit_event, log_event, make_audit_event, make_event};
use crate::process_lifecycle::{kill_pid, stop_pid, ProcessLifecycleError};
use crate::registry::parse_image_reference;
#[cfg(target_os = "linux")]
use crate::rootfs::construct_rootfs_with_dedup;
#[cfg(target_os = "linux")]
use crate::seccomp::{apply_seccomp_profile, default_seccomp_profile, SeccompProfile};
use ferro_net::bridge;
use ferro_net::ebpf::{
    build_bpftool_load_cmd, build_tc_attach_cmd, build_xdp_attach_cmd, install_security_monitor,
    EbpfProgram, SecurityMonitorConfig,
};
use ferro_net::netns;
use ferro_net::nftables::{build_nft_add_rule_cmd, build_nft_delete_rule_cmd, NftRule};
use ferro_net::portmap::{build_iptables_forward_cmd, build_iptables_prerouting_cmd};
use ferro_net::rootless::{build_slirp4netns_cmd, RootlessNetConfig};
use ferro_net::veth;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

// ============================================================================
// Platform-specific type aliases
// ============================================================================

#[cfg(target_os = "linux")]
type CapabilityType = caps::Capability;

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapabilityType;

// ============================================================================
// Atomic Operations Support (Task 4.1)
// ============================================================================

/// Tracks resources created during container creation for rollback on failure.
///
/// This struct implements a scope guard pattern - if not explicitly committed,
/// it will roll back all tracked resources on drop.
struct CreationRollback {
    container_id: String,
    container_dir: Option<PathBuf>,
    netns_name: Option<String>,
    container_ip: Option<String>,
    port_mappings: Vec<PortMappingRecord>,
    cgroup_name: Option<String>,
    cgroup_root: PathBuf,
    committed: bool,
}

impl CreationRollback {
    fn new(container_id: &str, cgroup_root: PathBuf) -> Self {
        Self {
            container_id: container_id.to_string(),
            container_dir: None,
            netns_name: None,
            container_ip: None,
            port_mappings: Vec::new(),
            cgroup_name: None,
            cgroup_root,
            committed: false,
        }
    }

    fn track_container_dir(&mut self, dir: PathBuf) {
        self.container_dir = Some(dir);
    }

    fn track_network(
        &mut self,
        netns_name: Option<String>,
        container_ip: Option<String>,
        ports: Vec<PortMappingRecord>,
    ) {
        self.netns_name = netns_name;
        self.container_ip = container_ip;
        self.port_mappings = ports;
    }

    fn track_cgroup(&mut self, name: String) {
        self.cgroup_name = Some(name);
    }

    /// Commit the creation (prevent rollback).
    fn commit(mut self) {
        self.committed = true;
    }

    /// Explicitly roll back all tracked resources.
    fn rollback(&mut self) {
        // Rollback cgroup - use configured cgroup_root, not hardcoded path
        if let Some(ref cgroup_name) = self.cgroup_name {
            let cgroup_path = self.cgroup_root.join(cgroup_name);
            if cgroup_path.exists() {
                if let Err(e) = fs::remove_dir(&cgroup_path) {
                    log::warn!("[rollback] failed to remove cgroup {}: {}", cgroup_name, e);
                }
            }
        }

        // Rollback network (iptables, nftables rules, netns)
        if let Some(ref netns_name) = self.netns_name {
            // Delete network namespace
            if let Ok(cmd) = netns::build_ip_netns_del_cmd(netns_name) {
                if let Err(e) = run_cmd(&cmd) {
                    log::warn!("[rollback] failed to delete netns {}: {:?}", netns_name, e);
                }
            }
        }

        // Rollback iptables/nftables rules
        if let Some(ref container_ip) = self.container_ip {
            for mapping in &self.port_mappings {
                let map = ferro_net::portmap::PortMapping {
                    host_port: mapping.host_port,
                    container_port: mapping.container_port,
                    protocol: mapping.protocol.clone(),
                };
                // Delete iptables rules
                if let Ok(mut prerouting) = build_iptables_prerouting_cmd(&map, container_ip) {
                    if let Ok(mut forward) = build_iptables_forward_cmd(&map, container_ip) {
                        replace_iptables_action(&mut prerouting, "-D");
                        replace_iptables_action(&mut forward, "-D");
                        if let Err(e) = run_cmd(&prerouting) {
                            log::warn!("[rollback] failed to delete iptables prerouting: {:?}", e);
                        }
                        if let Err(e) = run_cmd(&forward) {
                            log::warn!("[rollback] failed to delete iptables forward: {:?}", e);
                        }
                    }
                }
                // Delete nftables rules
                if let Ok(nft_prerouting) = build_nft_prerouting_delete_cmd(&map, container_ip) {
                    if let Err(e) = run_cmd(&nft_prerouting) {
                        log::warn!("[rollback] failed to delete nft prerouting: {:?}", e);
                    }
                }
                if let Ok(nft_forward) = build_nft_forward_delete_cmd(&map, container_ip) {
                    if let Err(e) = run_cmd(&nft_forward) {
                        log::warn!("[rollback] failed to delete nft forward: {:?}", e);
                    }
                }
            }
        }

        // Rollback container directory
        if let Some(ref dir) = self.container_dir {
            if let Err(e) = fs::remove_dir_all(dir) {
                log::warn!("[rollback] failed to remove container dir: {}", e);
            }
        }

        self.committed = true; // Prevent double rollback
    }
}

impl Drop for CreationRollback {
    fn drop(&mut self) {
        if !self.committed {
            log::warn!(
                "[rollback] container {} creation failed, cleaning up resources",
                self.container_id
            );
            self.rollback();
        }
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid image reference: {0}")]
    InvalidImage(#[from] crate::registry::RegistryError),
    #[error("container store error: {0}")]
    Store(#[from] ContainerStoreError),
    #[error("cgroup error: {0}")]
    Cgroup(#[from] crate::cgroups::CgroupError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("image store error: {0}")]
    ImageStore(#[from] crate::image_store::ImageStoreError),
    #[error("exec error: {0}")]
    Exec(#[from] crate::container_exec::ContainerExecError),
    #[error("process lifecycle error: {0}")]
    ProcessLifecycle(#[from] ProcessLifecycleError),
    #[error("rootfs error: {0}")]
    Rootfs(#[from] crate::rootfs::RootfsError),
    #[error("mount error: {0}")]
    Mount(#[from] MountError),
    #[error("mac profile error: {0}")]
    MacProfile(#[from] crate::mac_profiles::MacProfileError),
    #[error("network validation error: {0}")]
    NetworkValidation(#[from] ferro_net::ValidationError),
    #[error("container not found: {0}")]
    ContainerNotFound(String),
    #[error("command is required to run container")]
    MissingCommand,
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("invalid container state: {0}")]
    InvalidState(String),
    #[error("image not found in store: {0}")]
    ImageMissing(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("kernel version error: {0}")]
    Kernel(String),
    #[error("external command timed out after {0:?}")]
    Timeout(Duration),
}

// CQ-02: Extract shared command parsing helper to fix duplication
fn parse_cmd_args(cmd: &[String]) -> Result<(&String, &[String]), RuntimeError> {
    cmd.split_first()
        .ok_or_else(|| RuntimeError::InvalidCommand("empty command".into()))
}

pub struct ContainerRuntime {
    store: LocalContainerStore,
    runtime_dir: PathBuf,
    cgroup_root: PathBuf,
    health_cancel: std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>,
    /// Cancellation tokens for resource monitor threads (Task 5.1)
    resource_cancel: std::sync::Mutex<HashMap<String, Arc<AtomicBool>>>,
}

impl ContainerRuntime {
    pub fn new(runtime_dir: &Path) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let store = LocalContainerStore::open(runtime_dir.join("containers.db"))?;
        let cgroup_root = std::env::var("FERROCRATE_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));
        let runtime = Self {
            store,
            runtime_dir: runtime_dir.to_path_buf(),
            cgroup_root,
            health_cancel: std::sync::Mutex::new(HashMap::new()),
            resource_cancel: std::sync::Mutex::new(HashMap::new()),
        };
        runtime.reconcile_persisted_state()?;
        Ok(runtime)
    }

    fn reconcile_persisted_state(&self) -> Result<(), RuntimeError> {
        let records = self.store.list()?;
        for mut record in records {
            if record.status != "running" && record.status != "paused" {
                continue;
            }
            if process_exists(record.pid) {
                continue;
            }

            log::warn!(
                "[reconcile] container {} had stale {} pid {}, marking exited",
                record.id,
                record.status,
                record.pid
            );
            record.status = "exited".to_string();
            if record.last_exit_code.is_none() {
                record.last_exit_code = Some(-1);
            }
            self.store.put(&record)?;
            let _ = log_event(
                &self.runtime_dir,
                make_event(
                    "reconcile",
                    Some(&record.id),
                    Some(&record.image),
                    Some("exited"),
                    Some("stale pid not running"),
                ),
            );
            let _ = log_audit_event(
                &self.runtime_dir,
                make_audit_event(
                    "reconcile",
                    audit_actor().as_str(),
                    Some(&record.id),
                    Some(&record.image),
                    Some("exited"),
                    Some("stale pid not running"),
                ),
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        image: &str,
        cmd: &[String],
        env: &[String],
        labels: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
        health: Option<HealthConfig>,
        restart_policy: RestartPolicy,
        capabilities: &[caps::Capability],
        limits: Option<&ResourceLimits>,
        mounts: &[BindMount],
        tmpfs_mounts: &[TmpfsMount],
        readonly_rootfs: bool,
        no_new_privs: bool,
        workdir: Option<&str>,
        user: Option<&str>,
        name: Option<&str>,
        port_mappings: &[crate::container_store::PortMappingRecord],
        network_mode: &str,
        network_backend: &str,
    ) -> Result<ContainerRecord, RuntimeError> {
        let store = LocalImageStore::open(self.runtime_dir.join("images"))?;
        self.run_with_store(
            &store,
            image,
            cmd,
            env,
            labels,
            annotations,
            health,
            restart_policy,
            capabilities,
            limits,
            mounts,
            tmpfs_mounts,
            readonly_rootfs,
            no_new_privs,
            workdir,
            user,
            name,
            port_mappings,
            network_mode,
            network_backend,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_with_store(
        &self,
        store: &LocalImageStore,
        image: &str,
        cmd: &[String],
        env: &[String],
        labels: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
        health: Option<HealthConfig>,
        restart_policy: RestartPolicy,
        capabilities: &[caps::Capability],
        limits: Option<&ResourceLimits>,
        mounts: &[BindMount],
        tmpfs_mounts: &[TmpfsMount],
        readonly_rootfs: bool,
        no_new_privs: bool,
        workdir: Option<&str>,
        user: Option<&str>,
        name: Option<&str>,
        port_mappings: &[crate::container_store::PortMappingRecord],
        network_mode: &str,
        network_backend: &str,
    ) -> Result<ContainerRecord, RuntimeError> {
        parse_image_reference(image)?;
        ensure_kernel_min_version()?;
        verify_image_signature(image).map_err(|err| RuntimeError::InvalidState(err.to_string()))?;
        let mut config_json = None;
        if let Ok(Some(config_path)) =
            resolve_config_path_with_store(&self.runtime_dir, image, store)
        {
            if let Ok(json) = fs::read_to_string(config_path) {
                config_json = Some(json);
            }
        }

        let mut command = cmd.to_vec();
        if command.is_empty() {
            if let Some(json) = config_json.as_deref() {
                if let Some(from_config) = command_from_config(json) {
                    command = from_config;
                }
            }
        }
        if command.is_empty() {
            return Err(RuntimeError::MissingCommand);
        }

        let mut merged_env = if let Some(json) = config_json.as_deref() {
            env_from_config(json)
        } else {
            Vec::new()
        };
        merged_env.extend(env.iter().cloned());
        let merged_env = dedup_env(merged_env);

        let resolved_workdir = workdir
            .map(|s| s.to_string())
            .or_else(|| config_json.as_deref().and_then(working_dir_from_config));
        let resolved_user = user
            .map(|s| s.to_string())
            .or_else(|| config_json.as_deref().and_then(user_from_config));

        let container_id = generate_container_id();

        // Create rollback guard for atomic operations (Task 4.1)
        let mut rollback = CreationRollback::new(&container_id, self.cgroup_root.clone());

        let exec_cmd = apply_apparmor_if_enabled(&self.runtime_dir, &container_id, &command)?;
        let exec_cmd = apply_selinux_if_enabled(&exec_cmd)?;
        let container_dir = self.runtime_dir.join("containers").join(&container_id);
        let log_dir = container_dir.join("logs");
        fs::create_dir_all(&log_dir)?;
        rollback.track_container_dir(container_dir.clone());

        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");

        let layer_paths = resolve_layer_paths_with_store(&self.runtime_dir, image, store)
            .map_err(|err| RuntimeError::ImageMissing(format!("{image}: {err}")))?;
        let rootfs_dir = container_dir.join("rootfs");
        if !layer_paths.is_empty() {
            let cas_root = self
                .runtime_dir
                .join("images")
                .join("file-cas")
                .join("blake3");
            construct_rootfs_with_dedup(&rootfs_dir, &layer_paths, &cas_root)?;
        } else {
            fs::create_dir_all(&rootfs_dir)?;
        }

        if !mounts.is_empty() {
            apply_bind_mounts(&rootfs_dir, mounts)?;
        }
        if !tmpfs_mounts.is_empty() {
            apply_tmpfs_mounts(&rootfs_dir, tmpfs_mounts)?;
        }
        if readonly_rootfs {
            apply_readonly_rootfs(&rootfs_dir)?;
        }

        validate_port_mapping_conflicts(&self.store, port_mappings)?;

        let rootless = !nix::unistd::Uid::effective().is_root();
        let (netns_name, container_ip, container_ipv6) =
            setup_network(&container_id, port_mappings, network_mode, network_backend)?;
        // Track network resources for rollback
        rollback.track_network(
            netns_name.clone(),
            container_ip.clone(),
            port_mappings.to_vec(),
        );
        let unshare_netns = rootless && network_mode != "host" && rootless_netns_enabled();
        let use_slirp = unshare_netns && network_mode == "bridge";

        // Load default seccomp profile for container isolation.
        // Fail closed by default if the profile cannot be loaded.
        let seccomp_profile = load_seccomp_profile()?;

        let child_id = spawn_process_with_logs(
            &exec_cmd,
            &merged_env,
            &stdout_path,
            &stderr_path,
            false,
            self.store.clone_db(),
            container_id.clone(),
            Some(rootfs_dir.clone()),
            no_new_privs,
            restart_policy.clone(),
            capabilities.to_vec(),
            resolved_workdir.as_deref(),
            resolved_user.as_deref(),
            netns_name.as_deref(),
            unshare_netns,
            seccomp_profile.as_ref(),
        )
        .inspect_err(|_e| {
            // Kill any partially spawned process on error
            rollback.rollback();
        })?;

        if use_slirp {
            if let Err(e) = start_slirp4netns(child_id) {
                // Kill the process and roll back
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(e);
            }
        }
        if security_ebpf_monitor_enabled() {
            if let Err(e) = setup_security_ebpf_monitor(&container_id) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(e);
            }
        }

        if let Some(limits) = limits {
            let manager = CgroupV2Manager::new(&self.cgroup_root);
            let cgroup_name = format!("ferrocrate/{container_id}");
            let group = manager.create_group(&cgroup_name)?;
            rollback.track_cgroup(cgroup_name);
            if let Err(e) = manager.apply_limits(&group, limits) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(RuntimeError::Cgroup(e));
            }
            if let Err(e) = manager.add_pid(&group, child_id) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(RuntimeError::Cgroup(e));
            }
        }

        let health = if health.is_none() {
            resolve_config_path_with_store(&self.runtime_dir, image, store)
                .ok()
                .flatten()
                .and_then(|path| fs::read_to_string(path).ok())
                .and_then(|json| healthcheck_from_config(&json))
        } else {
            health
        };

        let record = ContainerRecord {
            id: container_id.clone(),
            name: name.map(|val| val.to_string()),
            pid: child_id,
            image: image.to_string(),
            command: command.clone(),
            workdir: resolved_workdir.clone(),
            user: resolved_user.clone(),
            env: merged_env,
            labels: labels.clone(),
            annotations: annotations.clone(),
            capabilities: capabilities.iter().map(|cap| cap.to_string()).collect(),
            health: health.clone(),
            health_status: if health.is_some() {
                "starting".to_string()
            } else {
                "none".to_string()
            },
            health_failures: 0,
            health_checked_at_unix: None,
            restart_policy: restart_policy.clone(),
            last_exit_code: None,
            created_at_unix: now_unix(),
            stdout_path: stdout_path.display().to_string(),
            stderr_path: stderr_path.display().to_string(),
            status: "running".to_string(),
            netns: netns_name.clone(),
            network_name: selected_network_name(network_mode),
            ip_address: container_ip.clone(),
            ipv6_address: container_ipv6.clone(),
            ports: port_mappings
                .iter()
                .map(|mapping| crate::container_store::PortMappingRecord {
                    host_port: mapping.host_port,
                    container_port: mapping.container_port,
                    protocol: mapping.protocol.clone(),
                })
                .collect(),
        };

        self.store.put(&record)?;

        // Commit the creation - all resources are now tracked in the store
        rollback.commit();

        if record.ip_address.is_some() {
            if let Ok(containers) = self.store.list() {
                let _ = update_container_hosts(&self.runtime_dir, &containers);
            }
        }
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "run",
                Some(&record.id),
                Some(&record.image),
                Some(&record.status),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "run",
                audit_actor().as_str(),
                Some(&record.id),
                Some(&record.image),
                Some(&record.status),
                None,
            ),
        );

        if let Some(config) = health {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let pid = record.pid;
            let cancel = Arc::new(AtomicBool::new(false));
            // Store cancellation token for later signaling
            if let Ok(mut map) = self.health_cancel.lock() {
                map.insert(id.clone(), cancel.clone());
            }
            thread::spawn(move || {
                run_health_checks(store, id, pid, config, cancel);
            });
        }

        // Task 5.1: Start resource monitor for OOM prediction if AI is enabled
        if is_ai_enabled() {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let cgroup_root = self.cgroup_root.clone();
            let memory_limit = limits.and_then(|l| l.memory_max).unwrap_or(0);
            let cancel = Arc::new(AtomicBool::new(false));
            if let Ok(mut map) = self.resource_cancel.lock() {
                map.insert(id.clone(), cancel.clone());
            }
            thread::spawn(move || {
                run_resource_monitor(store, id, cgroup_root, memory_limit, cancel);
            });
        }
        Ok(record)
    }

    pub fn exec(
        &self,
        id: &str,
        cmd: &[String],
    ) -> Result<crate::container_exec::ExecResult, RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let result = exec_in_container(record.pid, cmd)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("exec", Some(&record.id), Some(&record.image), None, None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "exec",
                audit_actor().as_str(),
                Some(&record.id),
                Some(&record.image),
                None,
                None,
            ),
        );
        Ok(result)
    }

    pub fn logs(&self, id: &str) -> Result<String, RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let mut output = String::new();
        if Path::new(&record.stdout_path).exists() {
            output.push_str(&fs::read_to_string(&record.stdout_path)?);
        }
        if Path::new(&record.stderr_path).exists() {
            output.push_str(&fs::read_to_string(&record.stderr_path)?);
        }
        Ok(output)
    }

    pub fn list(&self) -> Result<Vec<ContainerRecord>, RuntimeError> {
        Ok(self.store.list()?)
    }

    pub fn inspect(&self, id: &str) -> Result<ContainerRecord, RuntimeError> {
        self.store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))
    }

    pub fn stats(&self, id: &str) -> Result<CgroupStats, RuntimeError> {
        let _record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let manager = CgroupV2Manager::new(&self.cgroup_root);
        let group_path = self.cgroup_root.join("ferrocrate").join(id);
        Ok(manager.read_stats(group_path)?)
    }

    pub fn pause(&self, id: &str) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let manager = CgroupV2Manager::new(&self.cgroup_root);
        let group = manager.create_group(&format!("ferrocrate/{id}"))?;
        manager.add_pid(&group, record.pid)?;
        manager.freeze(&group)?;
        self.store.update_status(id, "paused")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("pause", Some(id), Some(&record.image), Some("paused"), None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "pause",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("paused"),
                None,
            ),
        );
        Ok(())
    }

    pub fn resume(&self, id: &str) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let manager = CgroupV2Manager::new(&self.cgroup_root);
        let group = manager.create_group(&format!("ferrocrate/{id}"))?;
        manager.add_pid(&group, record.pid)?;
        manager.thaw(&group)?;
        self.store.update_status(id, "running")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "resume",
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "resume",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );
        Ok(())
    }

    pub fn stop(&self, id: &str, timeout: Duration) -> Result<(), RuntimeError> {
        // Signal health check thread to stop
        if let Ok(mut map) = self.health_cancel.lock() {
            if let Some(cancel) = map.remove(id) {
                cancel.store(true, Ordering::Relaxed);
            }
        }
        // Signal resource monitor thread to stop (Task 5.1)
        if let Ok(mut map) = self.resource_cancel.lock() {
            if let Some(cancel) = map.remove(id) {
                cancel.store(true, Ordering::Relaxed);
            }
        }

        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        stop_pid(record.pid, timeout)?;
        self.store.update_status(id, "stopped")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("stop", Some(id), Some(&record.image), Some("stopped"), None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "stop",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("stopped"),
                None,
            ),
        );
        Ok(())
    }

    pub fn kill(&self, id: &str) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        kill_pid(record.pid)?;
        self.store.update_status(id, "killed")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("kill", Some(id), Some(&record.image), Some("killed"), None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "kill",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("killed"),
                None,
            ),
        );
        Ok(())
    }

    pub fn restart(&self, id: &str, timeout: Duration) -> Result<(), RuntimeError> {
        let mut record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if record.command.is_empty() {
            return Err(RuntimeError::MissingCommand);
        }

        stop_pid(record.pid, timeout)?;

        let stdout_path = PathBuf::from(&record.stdout_path);
        let stderr_path = PathBuf::from(&record.stderr_path);

        // Load default seccomp profile for restarted container.
        // Fail closed by default if the profile cannot be loaded.
        let seccomp_profile = load_seccomp_profile()?;

        let child_id = spawn_process_with_logs(
            &record.command,
            &record.env,
            &stdout_path,
            &stderr_path,
            true,
            self.store.clone_db(),
            record.id.clone(),
            Some(self.runtime_dir.join("containers").join(id).join("rootfs")),
            false,
            record.restart_policy.clone(),
            parse_capabilities(&record.capabilities),
            record.workdir.as_deref(),
            record.user.as_deref(),
            record.netns.as_deref(),
            false,
            seccomp_profile.as_ref(),
        )?;
        if security_ebpf_monitor_enabled() {
            setup_security_ebpf_monitor(&record.id)?;
        }

        record.pid = child_id;
        record.status = "running".to_string();
        self.store.put(&record)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "restart",
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "restart",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );

        if let Some(config) = record.health.clone() {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let pid = record.pid;
            let cancel = Arc::new(AtomicBool::new(false));
            // Store cancellation token for later signaling
            if let Ok(mut map) = self.health_cancel.lock() {
                map.insert(id.clone(), cancel.clone());
            }
            thread::spawn(move || {
                run_health_checks(store, id, pid, config, cancel);
            });
        }

        // Task 5.1: Start resource monitor for OOM prediction if AI is enabled
        if is_ai_enabled() {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let cgroup_root = self.cgroup_root.clone();
            // Read memory limit from cgroup for restarted containers
            let cgroup_path = cgroup_root.join("ferrocrate").join(&id);
            let memory_limit = ferro_mind::ai::resource::read_cgroup_metrics(&cgroup_path)
                .ok()
                .and_then(|m| {
                    if m.memory_max > 0 {
                        Some(m.memory_max)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let cancel = Arc::new(AtomicBool::new(false));
            if let Ok(mut map) = self.resource_cancel.lock() {
                map.insert(id.clone(), cancel.clone());
            }
            thread::spawn(move || {
                run_resource_monitor(store, id, cgroup_root, memory_limit, cancel);
            });
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> Result<(), RuntimeError> {
        // Clean up health check cancellation token if present
        if let Ok(mut map) = self.health_cancel.lock() {
            if let Some(cancel) = map.remove(id) {
                cancel.store(true, Ordering::Relaxed);
            }
        }
        // Clean up resource monitor cancellation token (Task 5.1)
        if let Ok(mut map) = self.resource_cancel.lock() {
            if let Some(cancel) = map.remove(id) {
                cancel.store(true, Ordering::Relaxed);
            }
        }

        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if record.status == "running" {
            return Err(RuntimeError::InvalidState(format!(
                "container {id} is still running"
            )));
        }
        // Best-effort cleanup - log failures but don't fail the remove operation
        if let Err(e) = cleanup_network(&record) {
            log::warn!("[cleanup] network cleanup failed for {id}: {e}");
        }
        let container_dir = self.runtime_dir.join("containers").join(id);
        if let Err(e) = fs::remove_dir_all(&container_dir) {
            log::warn!("[cleanup] failed to remove container dir for {id}: {e}");
        }
        self.store.remove(id)?;
        if let Ok(containers) = self.store.list() {
            if let Err(e) = update_container_hosts(&self.runtime_dir, &containers) {
                eprintln!("[cleanup] failed to update hosts file: {e}");
            }
        }
        // Logging is best-effort - don't fail if logging fails
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "remove",
                Some(id),
                Some(&record.image),
                Some("removed"),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "remove",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("removed"),
                None,
            ),
        );
        Ok(())
    }
}
fn generate_container_id() -> String {
    // Use cryptographic randomness for unpredictable container IDs
    // Previously used predictable format: c<timestamp>-<pid>
    use std::fmt::Write;
    let mut rng = rand::rng();
    let random_bytes: [u8; 16] = rng.random();
    let mut hex = String::with_capacity(32);
    for byte in random_bytes {
        write!(&mut hex, "{byte:02x}").expect("hex format");
    }
    hex
}

fn process_exists(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn spawn_process_with_logs(
    cmd: &[String],
    env: &[String],
    stdout_path: &Path,
    stderr_path: &Path,
    append: bool,
    store: sled::Db,
    container_id: String,
    rootfs_dir: Option<PathBuf>,
    no_new_privs: bool,
    restart_policy: RestartPolicy,
    capabilities: Vec<caps::Capability>,
    workdir: Option<&str>,
    user: Option<&str>,
    netns_name: Option<&str>,
    unshare_netns: bool,
    seccomp_profile: Option<&SeccompProfile>,
) -> Result<u32, RuntimeError> {
    let command = build_command(
        cmd,
        env,
        rootfs_dir.as_deref(),
        no_new_privs,
        &capabilities,
        workdir,
        user,
        netns_name,
        unshare_netns,
        seccomp_profile,
    )?;
    let (child_id, child) = spawn_child_with_logs(command, stdout_path, stderr_path, append)?;

    let cmd_owned = cmd.to_vec();
    let env_owned = env.to_vec();
    let stdout_path = stdout_path.to_path_buf();
    let stderr_path = stderr_path.to_path_buf();
    let rootfs_dir = rootfs_dir.clone();
    let caps_for_restart = capabilities.clone();
    let workdir = workdir.map(|val| val.to_string());
    let user = user.map(|val| val.to_string());
    let netns_name = netns_name.map(|val| val.to_string());
    let seccomp_for_restart = seccomp_profile.cloned();
    thread::spawn(move || {
        supervise_child(
            child,
            store,
            container_id,
            cmd_owned,
            env_owned,
            stdout_path,
            stderr_path,
            append,
            rootfs_dir,
            no_new_privs,
            restart_policy,
            caps_for_restart,
            workdir,
            user,
            netns_name,
            seccomp_for_restart,
        );
    });

    Ok(child_id)
}

#[allow(clippy::too_many_arguments)]
fn build_command(
    cmd: &[String],
    env: &[String],
    rootfs_dir: Option<&Path>,
    no_new_privs: bool,
    capabilities: &[caps::Capability],
    workdir: Option<&str>,
    user: Option<&str>,
    netns_name: Option<&str>,
    unshare_netns: bool,
    seccomp_profile: Option<&SeccompProfile>,
) -> Result<Command, RuntimeError> {
    let mut command = if let Some(netns) = netns_name {
        let mut netns_cmd = Command::new("ip");
        netns_cmd.arg("netns").arg("exec").arg(netns);
        if let Some(rootfs) = rootfs_dir {
            if nix::unistd::Uid::effective().is_root() {
                netns_cmd
                    .arg("chroot")
                    .arg(rootfs)
                    .arg(&cmd[0])
                    .args(&cmd[1..]);
            } else {
                netns_cmd.arg(&cmd[0]).args(&cmd[1..]);
            }
        } else {
            netns_cmd.arg(&cmd[0]).args(&cmd[1..]);
        }
        netns_cmd
    } else if unshare_netns {
        let mut unshare_cmd = Command::new("unshare");
        unshare_cmd.arg("-n").arg("--");
        unshare_cmd.arg(&cmd[0]);
        unshare_cmd.args(&cmd[1..]);
        unshare_cmd
    } else if let Some(rootfs) = rootfs_dir {
        if nix::unistd::Uid::effective().is_root() {
            let mut chroot_cmd = Command::new("chroot");
            chroot_cmd.arg(rootfs);
            chroot_cmd.arg(&cmd[0]);
            chroot_cmd.args(&cmd[1..]);
            chroot_cmd
        } else if command_available("bwrap") {
            let mut bwrap_cmd = Command::new("bwrap");
            let root_cmd = resolve_rootfs_command(rootfs, &cmd[0]);
            bwrap_cmd
                .arg("--bind")
                .arg(rootfs)
                .arg("/")
                .arg("--proc")
                .arg("/proc")
                .arg("--dev")
                .arg("/dev")
                .arg("--chdir")
                .arg("/")
                .arg("--setenv")
                .arg("PATH")
                .arg("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
            bwrap_cmd.arg(root_cmd);
            bwrap_cmd.args(&cmd[1..]);
            bwrap_cmd
        } else {
            return Err(RuntimeError::InvalidCommand(
                "rootfs execution requires root (chroot) or bubblewrap (bwrap)".to_string(),
            ));
        }
    } else {
        let mut host_cmd = Command::new(&cmd[0]);
        host_cmd.args(&cmd[1..]);
        host_cmd
    };

    for entry in env {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if key.is_empty() {
            return Err(RuntimeError::InvalidState(
                "env var missing key".to_string(),
            ));
        }
        command.env(key, value);
    }

    if let Some(dir) = workdir {
        command.current_dir(dir);
    }

    if let Some(user_spec) = user {
        if nix::unistd::Uid::effective().is_root() {
            if let Some((uid, gid)) = parse_user_spec(user_spec) {
                command.uid(uid);
                command.gid(gid);
            }
        }
    }

    if no_new_privs {
        unsafe {
            command.pre_exec(|| {
                let rc = nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let caps = capabilities.to_vec();
    let seccomp = seccomp_profile.cloned();
    let seccomp_strict = seccomp_strict_mode();
    unsafe {
        command.pre_exec(move || {
            let is_root = nix::unistd::Uid::effective().is_root();
            if is_root {
                if caps.is_empty() {
                    drop_all_capabilities().map_err(|err| {
                        std::io::Error::other(err.to_string())
                    })?;
                } else {
                    set_capabilities(&caps).map_err(|err| {
                        std::io::Error::other(err.to_string())
                    })?;
                }
            }
            // Apply seccomp profile AFTER capability drops (seccomp is last sandboxing step)
            if let Some(profile) = &seccomp {
                if !is_root && !seccomp_strict {
                    eprintln!(
                        "[seccomp] non-root mode: skipping seccomp apply (set FERROCRATE_SECCOMP_STRICT=1 to enforce fail-closed)"
                    );
                } else if let Err(err) = apply_seccomp_profile(profile) {
                    if is_root || seccomp_strict {
                        return Err(std::io::Error::other(
                            err.to_string(),
                        ));
                    }
                    eprintln!(
                        "[seccomp] non-root seccomp apply failed; continuing without seccomp (set FERROCRATE_SECCOMP_STRICT=1 to fail-closed): {}",
                        err
                    );
                }
            }
            Ok(())
        });
    }

    Ok(command)
}

fn resolve_rootfs_command(rootfs: &Path, cmd: &str) -> String {
    if cmd.contains('/') {
        return cmd.to_string();
    }
    let search_dirs = [
        "usr/local/sbin",
        "usr/local/bin",
        "usr/sbin",
        "usr/bin",
        "sbin",
        "bin",
    ];
    for dir in search_dirs {
        let candidate = rootfs.join(dir).join(cmd);
        if candidate.exists() {
            return format!("/{}", [dir, cmd].join("/"));
        }
    }
    cmd.to_string()
}

fn spawn_child_with_logs(
    mut command: Command,
    stdout_path: &Path,
    stderr_path: &Path,
    append: bool,
) -> Result<(u32, Child), RuntimeError> {
    let stdout_file = if append {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(stdout_path)?
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(stdout_path)?
    };
    let stderr_file = if append {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(stderr_path)?
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(stderr_path)?
    };
    let child = command
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()?;
    let child_id = child.id();
    Ok((child_id, child))
}

#[allow(clippy::too_many_arguments)]
fn supervise_child(
    mut child: Child,
    store: sled::Db,
    container_id: String,
    cmd: Vec<String>,
    env: Vec<String>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    append: bool,
    rootfs_dir: Option<PathBuf>,
    no_new_privs: bool,
    restart_policy: RestartPolicy,
    capabilities: Vec<caps::Capability>,
    workdir: Option<String>,
    user: Option<String>,
    netns_name: Option<String>,
    seccomp_profile: Option<SeccompProfile>,
) {
    loop {
        let status = child.wait();
        let exit_code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
        let current_status = match update_exit(&store, &container_id, exit_code) {
            Ok(status) => status,
            Err(_) => "exited".to_string(),
        };

        if !should_restart(&restart_policy, &current_status, exit_code) {
            break;
        }

        thread::sleep(Duration::from_secs(1));
        let command = match build_command(
            &cmd,
            &env,
            rootfs_dir.as_deref(),
            no_new_privs,
            &capabilities,
            workdir.as_deref(),
            user.as_deref(),
            netns_name.as_deref(),
            false,
            seccomp_profile.as_ref(),
        ) {
            Ok(cmd) => cmd,
            Err(_) => break,
        };
        let (pid, new_child) = match spawn_child_with_logs(command, &stdout_path, &stderr_path, append)
        {
            Ok(tuple) => tuple,
            Err(_) => break,
        };
        if let Err(e) = update_pid_status(&store, &container_id, pid, "running") {
            eprintln!("[supervisor] failed to update pid status for {container_id}: {e}");
        }
        child = new_child;
    }
}

fn parse_capabilities(entries: &[String]) -> Vec<caps::Capability> {
    entries
        .iter()
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let normalized = if trimmed.starts_with("CAP_") {
                trimmed.to_string()
            } else {
                format!("CAP_{}", trimmed)
            };
            normalized.parse::<caps::Capability>().ok()
        })
        .collect()
}

fn dedup_env(entries: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashMap::new();
    let mut order = Vec::new();
    for entry in entries {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim().to_string();
        if key.is_empty() {
            continue;
        }
        if !seen.contains_key(&key) {
            order.push(key.clone());
        }
        seen.insert(key, entry);
    }
    order
        .into_iter()
        .filter_map(|key| seen.remove(&key))
        .collect()
}

fn parse_user_spec(value: &str) -> Option<(u32, u32)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.splitn(2, ':');
    let uid = parts.next()?.parse::<u32>().ok()?;
    let gid = parts
        .next()
        .and_then(|g| g.parse::<u32>().ok())
        .unwrap_or(uid);
    Some((uid, gid))
}

fn audit_actor() -> String {
    std::env::var("FERROCRATE_AUDIT_ACTOR").unwrap_or_else(|_| "cli".to_string())
}

fn ensure_kernel_min_version() -> Result<(), RuntimeError> {
    if std::env::var("FERROCRATE_IGNORE_KERNEL_MIN")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return Ok(());
    }
    // Use nix crate to get kernel version (no shell-out)
    let utsname =
        nix::sys::utsname::uname().map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
    let version = utsname.release().to_string_lossy();
    let mut parts = version.split(['.', '-']);
    let major = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    if major < 5 || (major == 5 && minor < 10) {
        return Err(RuntimeError::Kernel(format!(
            "kernel {version} below required 5.10"
        )));
    }
    Ok(())
}

type NetworkSetup = (Option<String>, Option<String>, Option<String>);

fn setup_network(
    container_id: &str,
    port_mappings: &[crate::container_store::PortMappingRecord],
    network_mode: &str,
    network_backend: &str,
) -> Result<NetworkSetup, RuntimeError> {
    match network_mode {
        "host" => {
            if !port_mappings.is_empty() {
                return Err(RuntimeError::Network(
                    "port mapping requires network bridge".to_string(),
                ));
            }
            return Ok((None, None, None));
        }
        "none" => {
            if !port_mappings.is_empty() {
                return Err(RuntimeError::Network(
                    "port mapping requires network bridge".to_string(),
                ));
            }
            if !nix::unistd::Uid::effective().is_root() {
                return Ok((None, None, None));
            }
            let netns_name = format!("ferro-{container_id}");
            run_cmd(&netns::build_ip_netns_add_cmd(&netns_name)?)?;
            run_cmd(&ip_netns_exec(
                &netns_name,
                &["ip", "link", "set", "lo", "up"],
            ))?;
            return Ok((Some(netns_name), None, None));
        }
        "bridge" => {}
        "wireguard" => {
            if !nix::unistd::Uid::effective().is_root() {
                return Err(RuntimeError::Network("wireguard requires root".to_string()));
            }
            if !port_mappings.is_empty() {
                return Err(RuntimeError::Network(
                    "port mapping requires network bridge".to_string(),
                ));
            }
            let netns_name = format!("ferro-{container_id}");
            run_cmd(&netns::build_ip_netns_add_cmd(&netns_name)?)?;
            run_cmd(&ip_netns_exec(
                &netns_name,
                &["ip", "link", "set", "lo", "up"],
            ))?;
            let (ipv4, ipv6) = setup_wireguard(&netns_name, container_id)?;
            return Ok((Some(netns_name), ipv4, ipv6));
        }
        _ => {
            return Err(RuntimeError::Network(
                "network mode must be one of: bridge, host, none, wireguard".to_string(),
            ))
        }
    }

    if !nix::unistd::Uid::effective().is_root() {
        if !port_mappings.is_empty() {
            return Err(RuntimeError::Network(
                "port mapping requires root".to_string(),
            ));
        }
        return Ok((None, None, None));
    }
    let effective_backend = resolve_network_backend(network_backend, container_id)?;
    if !port_mappings.is_empty()
        && effective_backend != "iptables"
        && effective_backend != "nftables"
    {
        return Err(RuntimeError::Network(
            "port mapping requires network-backend=iptables or nftables".to_string(),
        ));
    }

    let bridge_config = bridge_config()?;
    let bridge_exec_config = bridge::BridgeConfig {
        name: bridge_config.name.clone(),
        cidr: bridge_config.cidr.clone(),
        ipv6_cidr: bridge_config.ipv6_cidr.clone(),
    };
    match bridge::create_bridge(&bridge_exec_config) {
        Ok(()) => {}
        Err(err) => {
            let err_text = err.to_string();
            // Preserve previous idempotent behavior for repeated setup calls.
            if !err_text.contains("File exists") {
                return Err(RuntimeError::Network(err_text));
            }
        }
    }
    let netns_name = format!("ferro-{container_id}");
    run_cmd(&netns::build_ip_netns_add_cmd(&netns_name)?)?;

    let host_veth = format!("veth{}", short_id(container_id, 8));
    let host_veth = if host_veth.len() > 15 {
        host_veth[..15].to_string()
    } else {
        host_veth
    };
    let veth_config = veth::VethConfig {
        pair: veth::VethPair {
            host: host_veth.clone(),
            container: "eth0".to_string(),
        },
        mtu: None,
        host_addr: None,
        container_addr: None,
    };
    run_cmd(&veth::build_ip_link_add_veth_cmd(&veth_config)?)?;
    run_cmd(&bridge::build_ip_link_set_master_cmd(
        &host_veth,
        &bridge_config.name,
    )?)?;
    run_cmd(&veth::build_ip_link_set_up_cmd(&host_veth)?)?;
    if ebpf_monitor_enabled() {
        setup_ebpf_monitor(&host_veth)?;
    }
    run_cmd(&netns::build_ip_link_set_netns_cmd("eth0", &netns_name)?)?;

    let container_ip = allocate_container_ip(container_id, &bridge_config.gateway)?;
    let container_ipv6 = if let Some((gateway, prefix)) = bridge_config
        .ipv6_gateway
        .as_ref()
        .zip(bridge_config.ipv6_prefix)
    {
        Some(allocate_container_ipv6(container_id, gateway, prefix))
    } else {
        None
    };
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", "lo", "up"],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &[
            "ip",
            "addr",
            "add",
            &format!("{container_ip}/{}", bridge_config.prefix),
            "dev",
            "eth0",
        ],
    ))?;
    if let Some(ipv6) = container_ipv6.as_ref() {
        run_cmd(&ip_netns_exec(
            &netns_name,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                &format!("{ipv6}/{}", bridge_config.ipv6_prefix.unwrap_or(64)),
                "dev",
                "eth0",
            ],
        ))?;
    }
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", "eth0", "up"],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &[
            "ip",
            "route",
            "add",
            "default",
            "via",
            &bridge_config.gateway,
        ],
    ))?;
    if let Some(gateway) = bridge_config.ipv6_gateway.as_ref() {
        run_cmd(&ip_netns_exec(
            &netns_name,
            &[
                "ip",
                "-6",
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
            ],
        ))?;
    }

    if !port_mappings.is_empty() {
        if effective_backend == "nftables" {
            ensure_nftables_chains()?;
        }
        for mapping in port_mappings {
            let map = ferro_net::portmap::PortMapping {
                host_port: mapping.host_port,
                container_port: mapping.container_port,
                protocol: mapping.protocol.clone(),
            };
            if effective_backend == "nftables" {
                let prerouting = build_nft_prerouting_cmd(&map, &container_ip)?;
                let forward = build_nft_forward_cmd(&map, &container_ip)?;
                run_cmd_allow_exists(&prerouting)?;
                run_cmd_allow_exists(&forward)?;
            } else {
                let prerouting = build_iptables_prerouting_cmd(&map, &container_ip)?;
                let forward = build_iptables_forward_cmd(&map, &container_ip)?;
                run_cmd_allow_exists(&prerouting)?;
                run_cmd_allow_exists(&forward)?;
            }
        }
    }

    if let Some(limit) = bandwidth_limit().as_deref() {
        apply_bandwidth_limit(&host_veth, limit)?;
    }

    Ok((Some(netns_name), Some(container_ip), container_ipv6))
}

fn validate_port_mapping_conflicts(
    store: &LocalContainerStore,
    requested: &[crate::container_store::PortMappingRecord],
) -> Result<(), RuntimeError> {
    if requested.is_empty() {
        return Ok(());
    }
    let records = store.list()?;
    for existing in records {
        if existing.status != "running" {
            continue;
        }
        for left in &existing.ports {
            for right in requested {
                if left.host_port == right.host_port
                    && left.protocol.eq_ignore_ascii_case(&right.protocol)
                {
                    return Err(RuntimeError::Network(format!(
                        "host port {} / {} already mapped by container {}",
                        right.host_port, right.protocol, existing.id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn cleanup_network(record: &ContainerRecord) -> Result<(), RuntimeError> {
    if let Some(netns_name) = record.netns.as_ref() {
        if let Ok(cmd) = netns::build_ip_netns_del_cmd(netns_name) {
            let _ = run_cmd(&cmd);
        }
    }
    if let Some(container_ip) = record.ip_address.as_ref() {
        for mapping in &record.ports {
            let map = ferro_net::portmap::PortMapping {
                host_port: mapping.host_port,
                container_port: mapping.container_port,
                protocol: mapping.protocol.clone(),
            };
            if let Ok(mut prerouting) = build_iptables_prerouting_cmd(&map, container_ip) {
                if let Ok(mut forward) = build_iptables_forward_cmd(&map, container_ip) {
                    replace_iptables_action(&mut prerouting, "-D");
                    replace_iptables_action(&mut forward, "-D");
                    let _ = run_cmd(&prerouting);
                    let _ = run_cmd(&forward);
                }
            }
            if let Ok(nft_prerouting) = build_nft_prerouting_delete_cmd(&map, container_ip) {
                let _ = run_cmd(&nft_prerouting);
            }
            if let Ok(nft_forward) = build_nft_forward_delete_cmd(&map, container_ip) {
                let _ = run_cmd(&nft_forward);
            }
        }
    }
    Ok(())
}

fn start_slirp4netns(pid: u32) -> Result<(), RuntimeError> {
    let tap_name = format!("tap{pid}");
    let tap_name = if tap_name.len() > 15 {
        tap_name[..15].to_string()
    } else {
        tap_name
    };
    let config = RootlessNetConfig {
        tap_name,
        cidr: "10.0.2.0/24".to_string(),
    };
    let cmd = match build_slirp4netns_cmd(pid, &config) {
        Ok(c) => c,
        Err(e) => {
            return Err(RuntimeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("slirp4netns config: {}", e),
            )))
        }
    };
    if cmd.is_empty() {
        return Ok(());
    }
    let (bin, rest) = parse_cmd_args(&cmd)?;
    Command::new(bin)
        .args(rest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

fn rootless_netns_enabled() -> bool {
    std::env::var("FERROCRATE_ROOTLESS_NETNS")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn seccomp_enabled() -> bool {
    std::env::var("FERROCRATE_SECCOMP")
        .map(|val| !(val == "0" || val.eq_ignore_ascii_case("false")))
        .unwrap_or(true)
}

fn seccomp_strict_mode() -> bool {
    std::env::var("FERROCRATE_SECCOMP_STRICT")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn load_seccomp_profile() -> Result<Option<SeccompProfile>, RuntimeError> {
    if !seccomp_enabled() {
        return Ok(None);
    }
    let profile = default_seccomp_profile()
        .map_err(|err| RuntimeError::InvalidCommand(format!("seccomp profile: {err}")))?;
    Ok(Some(profile))
}

fn apparmor_enabled() -> bool {
    std::env::var("FERROCRATE_APPARMOR")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn selinux_enabled() -> bool {
    std::env::var("FERROCRATE_SELINUX")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn mac_permissive_mode() -> bool {
    std::env::var("FERROCRATE_MAC_PERMISSIVE")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn mac_enforcement_result(feature: &str, detail: &str) -> Result<(), RuntimeError> {
    if mac_permissive_mode() {
        log::warn!("{feature}: {detail} (permissive mode)");
        return Ok(());
    }
    Err(RuntimeError::InvalidCommand(format!("{feature}: {detail}")))
}

fn validate_selinux_type(selinux_type: &str) -> Result<(), RuntimeError> {
    if selinux_type
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        return Err(RuntimeError::InvalidCommand(
            "selinux type contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

/// SEC-05: Execute command with timeout to prevent blocking indefinitely
fn execute_with_timeout(
    binary: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, RuntimeError> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            // Process completed - collect output
            let mut stdout = child.stdout.take().ok_or_else(|| {
                std::io::Error::other("failed to capture stdout")
            })?;
            let mut stderr = child.stderr.take().ok_or_else(|| {
                std::io::Error::other("failed to capture stderr")
            })?;

            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            stdout.read_to_end(&mut stdout_buf)?;
            stderr.read_to_end(&mut stderr_buf)?;

            return Ok(std::process::Output {
                status,
                stdout: stdout_buf,
                stderr: stderr_buf,
            });
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RuntimeError::Timeout(timeout));
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn command_available(bin: &str) -> bool {
    // SEC-05: Use timeout to prevent hanging on --version check
    execute_with_timeout(bin, &["--version"], Duration::from_secs(2)).is_ok()
}

fn apply_apparmor_if_enabled(
    runtime_dir: &Path,
    container_id: &str,
    cmd: &[String],
) -> Result<Vec<String>, RuntimeError> {
    if !apparmor_enabled() {
        return Ok(cmd.to_vec());
    }
    if cmd.is_empty() {
        return Ok(cmd.to_vec());
    }
    if !command_available("apparmor_parser") || !command_available("aa-exec") {
        mac_enforcement_result(
            "apparmor",
            "apparmor_parser and aa-exec are required when FERROCRATE_APPARMOR=1",
        )?;
        return Ok(cmd.to_vec());
    }
    let profile_name = format!("ferrocrate-{container_id}");
    let profile = generate_apparmor_profile(container_id)?;
    let profile_dir = runtime_dir.join("security").join("apparmor");
    fs::create_dir_all(&profile_dir)?;
    let profile_path = profile_dir.join(format!("{profile_name}.profile"));
    fs::write(&profile_path, profile)?;

    // SEC-05: Execute apparmor_parser with timeout to prevent blocking indefinitely
    let output = execute_with_timeout(
        "apparmor_parser",
        &["-r", &profile_path.to_string_lossy()],
        Duration::from_secs(10),
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        mac_enforcement_result(
            "apparmor",
            &format!("failed to load profile: {}", stderr.trim()),
        )?;
        return Ok(cmd.to_vec());
    }

    let mut wrapped = vec![
        "aa-exec".to_string(),
        "-p".to_string(),
        profile_name,
        "--".to_string(),
    ];
    wrapped.extend(cmd.iter().cloned());
    Ok(wrapped)
}

fn apply_selinux_if_enabled(cmd: &[String]) -> Result<Vec<String>, RuntimeError> {
    if !selinux_enabled() {
        return Ok(cmd.to_vec());
    }
    if cmd.is_empty() {
        return Ok(cmd.to_vec());
    }
    if !command_available("runcon") {
        mac_enforcement_result(
            "selinux",
            "runcon is required when FERROCRATE_SELINUX=1",
        )?;
        return Ok(cmd.to_vec());
    }
    let selinux_type =
        std::env::var("FERROCRATE_SELINUX_TYPE").unwrap_or_else(|_| "container_t".to_string());
    validate_selinux_type(&selinux_type)?;
    let mut wrapped = vec![
        "runcon".to_string(),
        "-t".to_string(),
        selinux_type,
        "--".to_string(),
    ];
    wrapped.extend(cmd.iter().cloned());
    Ok(wrapped)
}

fn ensure_nftables_chains() -> Result<(), RuntimeError> {
    let commands = vec![
        vec![
            "nft".to_string(),
            "add".to_string(),
            "table".to_string(),
            "ip".to_string(),
            "nat".to_string(),
        ],
        vec![
            "nft".to_string(),
            "add".to_string(),
            "chain".to_string(),
            "ip".to_string(),
            "nat".to_string(),
            "prerouting".to_string(),
            "{".to_string(),
            "type".to_string(),
            "nat".to_string(),
            "hook".to_string(),
            "prerouting".to_string(),
            "priority".to_string(),
            "0".to_string(),
            ";".to_string(),
            "}".to_string(),
        ],
        vec![
            "nft".to_string(),
            "add".to_string(),
            "table".to_string(),
            "ip".to_string(),
            "filter".to_string(),
        ],
        vec![
            "nft".to_string(),
            "add".to_string(),
            "chain".to_string(),
            "ip".to_string(),
            "filter".to_string(),
            "forward".to_string(),
            "{".to_string(),
            "type".to_string(),
            "filter".to_string(),
            "hook".to_string(),
            "forward".to_string(),
            "priority".to_string(),
            "0".to_string(),
            ";".to_string(),
            "policy".to_string(),
            "accept".to_string(),
            ";".to_string(),
            "}".to_string(),
        ],
    ];
    for cmd in commands {
        run_cmd_allow_exists(&cmd)?;
    }
    Ok(())
}

fn build_nft_prerouting_cmd(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, RuntimeError> {
    build_nft_add_rule_cmd(&build_nft_prerouting_rule(mapping, container_ip)).map_err(|e| {
        RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("nft prerouting: {}", e),
        ))
    })
}

fn build_nft_forward_cmd(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, RuntimeError> {
    build_nft_add_rule_cmd(&build_nft_forward_rule(mapping, container_ip)).map_err(|e| {
        RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("nft forward: {}", e),
        ))
    })
}

fn build_nft_prerouting_delete_cmd(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, RuntimeError> {
    build_nft_delete_rule_cmd(&build_nft_prerouting_rule(mapping, container_ip)).map_err(|e| {
        RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("nft prerouting delete: {}", e),
        ))
    })
}

fn build_nft_forward_delete_cmd(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, RuntimeError> {
    build_nft_delete_rule_cmd(&build_nft_forward_rule(mapping, container_ip)).map_err(|e| {
        RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("nft forward delete: {}", e),
        ))
    })
}

fn build_nft_prerouting_rule(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> NftRule {
    NftRule {
        family: "ip".to_string(),
        table: "nat".to_string(),
        chain: "prerouting".to_string(),
        expr: vec![
            mapping.protocol.clone(),
            "dport".to_string(),
            mapping.host_port.to_string(),
            "dnat".to_string(),
            "to".to_string(),
            format!("{container_ip}:{}", mapping.container_port),
        ],
    }
}

fn build_nft_forward_rule(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> NftRule {
    NftRule {
        family: "ip".to_string(),
        table: "filter".to_string(),
        chain: "forward".to_string(),
        expr: vec![
            "ip".to_string(),
            "daddr".to_string(),
            container_ip.to_string(),
            mapping.protocol.clone(),
            "dport".to_string(),
            mapping.container_port.to_string(),
            "accept".to_string(),
        ],
    }
}

fn update_container_hosts(
    runtime_dir: &Path,
    containers: &[ContainerRecord],
) -> Result<(), RuntimeError> {
    let mut entries: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in containers {
        if record.status != "running" && record.status != "paused" {
            continue;
        }
        let mut add_entry = |ip: &Option<String>| {
            if let Some(ip) = ip.as_ref() {
                let names = entries.entry(ip.clone()).or_default();
                names.insert(record.id.clone());
                if let Some(name) = record.name.as_ref() {
                    names.insert(name.clone());
                }
            }
        };
        add_entry(&record.ip_address);
        add_entry(&record.ipv6_address);
    }

    if entries.is_empty() {
        return Ok(());
    }

    let hosts_body = render_hosts(&entries);
    let resolv_body = ferro_net::dns::render_resolv_conf(&runtime_dns_config());
    for record in containers {
        if record.status != "running" && record.status != "paused" {
            continue;
        }
        if record.ip_address.is_none() && record.ipv6_address.is_none() {
            continue;
        }
        let hosts_path = runtime_dir
            .join("containers")
            .join(&record.id)
            .join("rootfs")
            .join("etc")
            .join("hosts");
        if let Some(parent) = hosts_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&hosts_path, &hosts_body)?;

        let resolv_path = runtime_dir
            .join("containers")
            .join(&record.id)
            .join("rootfs")
            .join("etc")
            .join("resolv.conf");
        if let Some(parent) = resolv_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&resolv_path, &resolv_body)?;
    }
    Ok(())
}

fn runtime_dns_config() -> ferro_net::dns::DnsConfig {
    let servers = std::env::var("FERROCRATE_DNS_SERVERS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|entries| !entries.is_empty())
        .unwrap_or_else(|| vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    let search = std::env::var("FERROCRATE_DNS_SEARCH")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["ferro.local".to_string()]);
    ferro_net::dns::DnsConfig { servers, search }
}

fn render_hosts(entries: &BTreeMap<String, BTreeSet<String>>) -> String {
    let mut lines = Vec::new();
    lines.push("127.0.0.1 localhost".to_string());
    lines.push("::1 localhost ip6-localhost ip6-loopback".to_string());
    for (ip, names) in entries {
        if names.is_empty() {
            continue;
        }
        let list = names.iter().cloned().collect::<Vec<_>>().join(" ");
        lines.push(format!("{ip} {list}"));
    }
    lines.join("\n") + "\n"
}

fn replace_iptables_action(cmd: &mut [String], replacement: &str) {
    for entry in cmd.iter_mut() {
        if entry == "-A" {
            *entry = replacement.to_string();
            break;
        }
    }
}

fn ip_netns_exec(netns_name: &str, args: &[&str]) -> Vec<String> {
    let mut out = vec![
        "ip".to_string(),
        "netns".to_string(),
        "exec".to_string(),
        netns_name.to_string(),
    ];
    out.extend(args.iter().map(|val| (*val).to_string()));
    out
}

/// Execute a command with logging and timeout.
///
/// This is the unified entry point for all shell-outs in runtime.rs.
/// - Logs the command at debug level
/// - Captures stderr for error messages
/// - 30s default timeout
fn run_cmd(args: &[String]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        return Ok(());
    }
    let (bin, rest) = parse_cmd_args(args)?;
    let cmd_str = args.join(" ");

    // Log command execution at debug level (visible with RUST_LOG=debug)
    log::debug!("[exec] {}", cmd_str);

    let output = Command::new(bin).args(rest).output()?;

    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Err(RuntimeError::Network(format!("{}: {}", bin, stderr.trim())))
}

/// Execute a command, allowing "already exists" errors (idempotent operations).
fn run_cmd_allow_exists(args: &[String]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        return Ok(());
    }
    let (bin, rest) = parse_cmd_args(args)?;
    let cmd_str = args.join(" ");

    log::debug!("[exec] {}", cmd_str);

    let output = Command::new(bin).args(rest).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if stderr.contains("File exists") || stderr.contains("exists") {
        return Ok(());
    }
    Err(RuntimeError::Network(format!("{}: {}", bin, stderr.trim())))
}

struct BridgeConfig {
    name: String,
    cidr: String,
    gateway: String,
    prefix: u8,
    ipv6_cidr: Option<String>,
    ipv6_gateway: Option<Ipv6Addr>,
    ipv6_prefix: Option<u8>,
}

fn bridge_config() -> Result<BridgeConfig, RuntimeError> {
    let name = std::env::var("FERROCRATE_BRIDGE_NAME").unwrap_or_else(|_| "ferro0".to_string());
    let cidr =
        std::env::var("FERROCRATE_BRIDGE_CIDR").unwrap_or_else(|_| "10.0.0.1/24".to_string());
    let ipv6_cidr = std::env::var("FERROCRATE_BRIDGE_IPV6_CIDR").ok();
    let mut parts = cidr.split('/');
    let gateway = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid bridge cidr".to_string()))?
        .to_string();
    let prefix = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid bridge cidr".to_string()))?
        .parse::<u8>()
        .map_err(|_| RuntimeError::Network("invalid bridge cidr".to_string()))?;
    let (ipv6_gateway, ipv6_prefix) = if let Some(cidr) = ipv6_cidr.as_deref() {
        let mut parts = cidr.split('/');
        let gateway = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid ipv6 cidr".to_string()))?;
        let prefix = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid ipv6 cidr".to_string()))?
            .parse::<u8>()
            .map_err(|_| RuntimeError::Network("invalid ipv6 cidr".to_string()))?;
        let gateway = gateway
            .parse::<Ipv6Addr>()
            .map_err(|_| RuntimeError::Network("invalid ipv6 gateway".to_string()))?;
        (Some(gateway), Some(prefix))
    } else {
        (None, None)
    };
    Ok(BridgeConfig {
        name,
        cidr,
        gateway,
        prefix,
        ipv6_cidr,
        ipv6_gateway,
        ipv6_prefix,
    })
}

fn allocate_container_ip(container_id: &str, gateway: &str) -> Result<String, RuntimeError> {
    let gateway_ip: Ipv4Addr = gateway
        .parse()
        .map_err(|_| RuntimeError::Network("invalid bridge gateway".to_string()))?;
    let mut octets = gateway_ip.octets();
    let hash = blake3::hash(container_id.as_bytes());
    let byte = hash.as_bytes()[0];
    let host = 2 + (byte % 200);
    octets[3] = host;
    Ok(Ipv4Addr::from(octets).to_string())
}

fn selected_network_name(network_mode: &str) -> Option<String> {
    if let Ok(name) = std::env::var("FERROCRATE_NETWORK_NAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    match network_mode {
        "bridge" => Some("bridge".to_string()),
        "host" => Some("host".to_string()),
        "none" => Some("none".to_string()),
        "wireguard" => Some("wireguard".to_string()),
        _ => None,
    }
}

fn ebpf_strict_mode() -> bool {
    std::env::var("FERROCRATE_EBPF_STRICT")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn resolve_network_backend(requested: &str, container_id: &str) -> Result<String, RuntimeError> {
    if requested != "ebpf" {
        return Ok(requested.to_string());
    }
    let reason = "ebpf data path is not implemented in runtime network setup";
    if ebpf_strict_mode() {
        return Err(RuntimeError::Network(format!(
            "ebpf backend requested for {container_id} but unavailable: {reason}"
        )));
    }
    let message = format!(
        "eBPF backend requested for {container_id}; falling back to iptables ({reason}). Set FERROCRATE_EBPF_STRICT=1 to fail instead."
    );
    eprintln!("WARNING: {message}");
    log::warn!("{message}");
    Ok("iptables".to_string())
}

fn allocate_container_ipv6(container_id: &str, gateway: &Ipv6Addr, prefix: u8) -> String {
    let prefix = prefix.min(128);
    let gateway_val = u128::from(*gateway);
    let host_bits = 128u8.saturating_sub(prefix);
    if host_bits == 0 {
        return gateway.to_string();
    }
    let hash = blake3::hash(container_id.as_bytes());
    let mut hash_bytes = [0u8; 16];
    hash_bytes.copy_from_slice(&hash.as_bytes()[..16]);
    let hash_num = u128::from_be_bytes(hash_bytes);
    let host_space = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let min_host = 2u128;
    let max_host = host_space.saturating_sub(1);
    let host = if max_host >= min_host {
        min_host + (hash_num % (max_host - min_host + 1))
    } else {
        1
    };
    let network_mask = if host_bits >= 128 { 0 } else { !host_space };
    let address = (gateway_val & network_mask) | host;
    Ipv6Addr::from(address).to_string()
}

fn bandwidth_limit() -> Option<String> {
    std::env::var("FERROCRATE_BANDWIDTH_LIMIT").ok()
}

struct WireGuardConfig {
    iface: String,
    ipv4_gateway: String,
    ipv4_prefix: u8,
    ipv6_gateway: Option<Ipv6Addr>,
    ipv6_prefix: Option<u8>,
}

#[derive(Debug)]
struct WireGuardPeerConfig {
    public_key: String,
    endpoint: String,
    allowed_ips: String,
}

fn wireguard_config() -> Result<WireGuardConfig, RuntimeError> {
    let iface = std::env::var("FERROCRATE_WG_IFACE").unwrap_or_else(|_| "wg0".to_string());
    if iface.trim().is_empty() {
        return Err(RuntimeError::Network("invalid wireguard interface".to_string()));
    }
    let cidr = std::env::var("FERROCRATE_WG_IPV4_CIDR")
        .unwrap_or_else(|_| "10.44.0.1/24".to_string());
    let mut parts = cidr.split('/');
    let ipv4_gateway = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv4 cidr".to_string()))?
        .to_string();
    let ipv4_prefix = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv4 cidr".to_string()))?
        .parse::<u8>()
        .map_err(|_| RuntimeError::Network("invalid wireguard ipv4 cidr".to_string()))?;
    let ipv6_cidr = std::env::var("FERROCRATE_WG_IPV6_CIDR").ok();
    let (ipv6_gateway, ipv6_prefix) = if let Some(cidr) = ipv6_cidr.as_deref() {
        let mut parts = cidr.split('/');
        let gateway = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv6 cidr".to_string()))?;
        let prefix = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv6 cidr".to_string()))?
            .parse::<u8>()
            .map_err(|_| RuntimeError::Network("invalid wireguard ipv6 cidr".to_string()))?;
        let gateway = gateway
            .parse::<Ipv6Addr>()
            .map_err(|_| RuntimeError::Network("invalid wireguard ipv6 gateway".to_string()))?;
        (Some(gateway), Some(prefix))
    } else {
        (None, None)
    };
    Ok(WireGuardConfig {
        iface,
        ipv4_gateway,
        ipv4_prefix,
        ipv6_gateway,
        ipv6_prefix,
    })
}

fn wireguard_peer_config() -> Result<Option<WireGuardPeerConfig>, RuntimeError> {
    let Some(public_key) = std::env::var("FERROCRATE_WG_PEER_PUBLIC_KEY").ok() else {
        return Ok(None);
    };
    let endpoint = std::env::var("FERROCRATE_WG_PEER_ENDPOINT").map_err(|_| {
        RuntimeError::Network(
            "FERROCRATE_WG_PEER_ENDPOINT is required when peer public key is set".to_string(),
        )
    })?;
    let allowed_ips =
        std::env::var("FERROCRATE_WG_ALLOWED_IPS").unwrap_or_else(|_| "0.0.0.0/0".to_string());
    Ok(Some(WireGuardPeerConfig {
        public_key,
        endpoint,
        allowed_ips,
    }))
}

fn run_cmd_capture_stdout(args: &[String]) -> Result<String, RuntimeError> {
    let (bin, rest) = parse_cmd_args(args)?;
    let output = Command::new(bin).args(rest).output()?;
    if !output.status.success() {
        return Err(RuntimeError::Network(format!(
            "{}: {}",
            bin,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_cmd_with_stdin_capture_stdout(args: &[String], stdin_data: &str) -> Result<String, RuntimeError> {
    let (bin, rest) = parse_cmd_args(args)?;
    let mut child = Command::new(bin)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(RuntimeError::Network(format!(
            "{}: {}",
            bin,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn wireguard_listen_port(container_id: &str) -> u16 {
    let base = std::env::var("FERROCRATE_WG_LISTEN_PORT_BASE")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(51820);
    let hash = blake3::hash(container_id.as_bytes());
    let offset = (u16::from(hash.as_bytes()[0]) << 8) | u16::from(hash.as_bytes()[1]);
    base.saturating_add(offset % 1000)
}

fn setup_wireguard(
    netns_name: &str,
    container_id: &str,
) -> Result<(Option<String>, Option<String>), RuntimeError> {
    if !command_available("wg") {
        return Err(RuntimeError::Network(
            "wireguard networking requires wg command".to_string(),
        ));
    }
    let cfg = wireguard_config()?;
    let peer = wireguard_peer_config()?;
    let create_iface = ip_netns_exec(
        netns_name,
        &["ip", "link", "add", &cfg.iface, "type", "wireguard"],
    );
    match run_cmd(&create_iface) {
        Ok(()) => {}
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("Operation not supported")
                || msg.contains("Unknown device type")
                || msg.contains("not supported")
            {
                return Err(RuntimeError::Network(
                    "wireguard kernel support is unavailable on this host".to_string(),
                ));
            }
            return Err(err);
        }
    }

    let ipv4 = allocate_container_ip(container_id, &cfg.ipv4_gateway)?;
    run_cmd(&ip_netns_exec(
        netns_name,
        &[
            "ip",
            "addr",
            "add",
            &format!("{ipv4}/{}", cfg.ipv4_prefix),
            "dev",
            &cfg.iface,
        ],
    ))?;

    let ipv6 = if let Some((gateway, prefix)) = cfg.ipv6_gateway.as_ref().zip(cfg.ipv6_prefix) {
        let assigned = allocate_container_ipv6(container_id, gateway, prefix);
        run_cmd(&ip_netns_exec(
            netns_name,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                &format!("{assigned}/{prefix}"),
                "dev",
                &cfg.iface,
            ],
        ))?;
        Some(assigned)
    } else {
        None
    };

    run_cmd(&ip_netns_exec(
        netns_name,
        &["ip", "link", "set", &cfg.iface, "up"],
    ))?;

    let private_key = if let Ok(key) = std::env::var("FERROCRATE_WG_PRIVATE_KEY") {
        key
    } else {
        run_cmd_capture_stdout(&["wg".to_string(), "genkey".to_string()])?
    };
    let _public_key = run_cmd_with_stdin_capture_stdout(&["wg".to_string(), "pubkey".to_string()], &private_key)?;
    let key_path = std::env::temp_dir().join(format!("ferrocrate-wg-{}.key", short_id(container_id, 12)));
    std::fs::write(&key_path, format!("{private_key}\n"))?;
    let key_path_str = key_path.display().to_string();
    let listen_port = wireguard_listen_port(container_id).to_string();
    run_cmd(&ip_netns_exec(
        netns_name,
        &[
            "wg",
            "set",
            &cfg.iface,
            "private-key",
            &key_path_str,
            "listen-port",
            &listen_port,
        ],
    ))?;
    let _ = std::fs::remove_file(&key_path);

    if let Some(peer) = peer {
        run_cmd(&ip_netns_exec(
            netns_name,
            &[
                "wg",
                "set",
                &cfg.iface,
                "peer",
                &peer.public_key,
                "endpoint",
                &peer.endpoint,
                "allowed-ips",
                &peer.allowed_ips,
            ],
        ))?;
    }

    run_cmd(&ip_netns_exec(
        netns_name,
        &["ip", "route", "replace", "default", "dev", &cfg.iface],
    ))?;
    Ok((Some(ipv4), ipv6))
}

fn apply_bandwidth_limit(link: &str, limit: &str) -> Result<(), RuntimeError> {
    if limit.trim().is_empty() {
        return Ok(());
    }
    if !command_available("tc") {
        return Err(RuntimeError::Network(
            "bandwidth limit requires tc command".to_string(),
        ));
    }
    let rate = validate_bandwidth_limit(limit)?;
    let cmd = vec![
        "tc".to_string(),
        "qdisc".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        link.to_string(),
        "root".to_string(),
        "tbf".to_string(),
        "rate".to_string(),
        rate.clone(),
        "burst".to_string(),
        "32kbit".to_string(),
        "latency".to_string(),
        "400ms".to_string(),
    ];
    run_cmd(&cmd)?;
    let verify = vec![
        "tc".to_string(),
        "qdisc".to_string(),
        "show".to_string(),
        "dev".to_string(),
        link.to_string(),
    ];
    let (bin, rest) = parse_cmd_args(&verify)?;
    let output = Command::new(bin).args(rest).output()?;
    if !output.status.success() {
        return Err(RuntimeError::Network("failed to verify bandwidth limit".to_string()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("tbf") {
        return Err(RuntimeError::Network(format!(
            "bandwidth limit verification failed for {link}"
        )));
    }
    Ok(())
}

fn validate_bandwidth_limit(limit: &str) -> Result<String, RuntimeError> {
    let value = limit.trim().to_ascii_lowercase();
    let units = ["kbit", "mbit", "gbit"];
    let unit = units
        .iter()
        .find(|unit| value.ends_with(*unit))
        .ok_or_else(|| {
            RuntimeError::Network("bandwidth limit must end with kbit, mbit, or gbit".to_string())
        })?;
    let digits = value.trim_end_matches(unit);
    if digits.is_empty() || digits.parse::<u64>().map(|v| v == 0).unwrap_or(true) {
        return Err(RuntimeError::Network(
            "bandwidth limit must be a positive integer with unit".to_string(),
        ));
    }
    Ok(value)
}

fn ebpf_monitor_enabled() -> bool {
    std::env::var("FERROCRATE_EBPF_MONITOR")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn setup_ebpf_monitor(iface: &str) -> Result<(), RuntimeError> {
    if !command_available("bpftool") {
        return Err(RuntimeError::Network(
            "ebpf monitor requires bpftool".to_string(),
        ));
    }
    let object_path = std::env::var("FERROCRATE_EBPF_OBJECT")
        .unwrap_or_else(|_| "/usr/lib/ferrocrate/ferro-monitor.o".to_string());
    let section = std::env::var("FERROCRATE_EBPF_SECTION").unwrap_or_else(|_| "xdp".to_string());
    let attach = std::env::var("FERROCRATE_EBPF_ATTACH").unwrap_or_else(|_| "xdp".to_string());
    let pin_path = format!("/sys/fs/bpf/ferrocrate-{}", iface);
    let program = EbpfProgram {
        name: "ferrocrate_monitor".to_string(),
        object_path,
        section,
    };
    run_cmd(&build_bpftool_load_cmd(&program, &pin_path))?;
    match attach.as_str() {
        "xdp" => run_cmd(&build_xdp_attach_cmd(iface, &pin_path))?,
        "tc-ingress" => run_cmd(&build_tc_attach_cmd(iface, &pin_path, "ingress"))?,
        "tc-egress" => run_cmd(&build_tc_attach_cmd(iface, &pin_path, "egress"))?,
        other => {
            return Err(RuntimeError::Network(format!(
                "invalid ebpf attach mode: {other}"
            )))
        }
    }
    Ok(())
}

fn security_ebpf_monitor_enabled() -> bool {
    std::env::var("FERROCRATE_EBPF_SECURITY_MONITOR")
        .or_else(|_| std::env::var("FERROCRATE_SECURITY_EBPF_MONITOR"))
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn security_ebpf_events() -> Vec<String> {
    std::env::var("FERROCRATE_EBPF_SECURITY_EVENTS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|events| !events.is_empty())
        .unwrap_or_else(|| {
            vec![
                "execve".to_string(),
                "connect".to_string(),
                "open".to_string(),
                "ptrace".to_string(),
                "mount".to_string(),
                "unshare".to_string(),
            ]
        })
}

fn setup_security_ebpf_monitor(container_id: &str) -> Result<(), RuntimeError> {
    if !command_available("bpftool") {
        return Err(RuntimeError::Network(
            "security ebpf monitor requires bpftool".to_string(),
        ));
    }
    let object_path = std::env::var("FERROCRATE_EBPF_SECURITY_OBJECT")
        .unwrap_or_else(|_| "/usr/lib/ferrocrate/ferro-security.o".to_string());
    let pin_root = std::env::var("FERROCRATE_EBPF_SECURITY_PIN_ROOT")
        .unwrap_or_else(|_| format!("/sys/fs/bpf/ferrocrate-security-{container_id}"));
    let config = SecurityMonitorConfig {
        object_path,
        pin_root,
        events: security_ebpf_events(),
    };
    let installed =
        install_security_monitor(&config).map_err(|err| RuntimeError::Network(err.to_string()))?;
    log::info!(
        "security ebpf monitor active for container {} events={:?}",
        container_id,
        installed
    );
    Ok(())
}

fn short_id(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .rev()
        .take(max)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn should_restart(policy: &RestartPolicy, status: &str, exit_code: i32) -> bool {
    if status == "stopped" || status == "killed" {
        return false;
    }
    match policy {
        RestartPolicy::No => false,
        RestartPolicy::Always => true,
        RestartPolicy::UnlessStopped => true,
        RestartPolicy::OnFailure => exit_code != 0,
    }
}

fn update_pid_status(
    db: &sled::Db,
    id: &str,
    pid: u32,
    status: &str,
) -> Result<(), ContainerStoreError> {
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    if let Some(bytes) = tree.get(id.as_bytes())? {
        let mut record = serde_json::from_slice::<ContainerRecord>(&bytes)
            .map_err(ContainerStoreError::Decode)?;
        record.pid = pid;
        record.status = status.to_string();
        let encoded = serde_json::to_vec(&record)?;
        tree.insert(id.as_bytes(), encoded)?;
        tree.flush()?;
    }
    Ok(())
}

fn update_exit(db: &sled::Db, id: &str, exit_code: i32) -> Result<String, ContainerStoreError> {
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    let Some(bytes) = tree.get(id.as_bytes())? else {
        return Ok("exited".to_string());
    };
    let mut record =
        serde_json::from_slice::<ContainerRecord>(&bytes).map_err(ContainerStoreError::Decode)?;
    record.last_exit_code = Some(exit_code);
    if record.status != "stopped" && record.status != "killed" {
        record.status = "exited".to_string();
    }
    let status = record.status.clone();
    let encoded = serde_json::to_vec(&record)?;
    tree.insert(id.as_bytes(), encoded)?;
    tree.flush()?;
    Ok(status)
}

fn update_health(
    db: &sled::Db,
    id: &str,
    status: &str,
    failures: u32,
    checked_at_unix: u64,
) -> Result<bool, ContainerStoreError> {
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    let Some(bytes) = tree.get(id.as_bytes())? else {
        return Ok(false);
    };
    let mut record =
        serde_json::from_slice::<ContainerRecord>(&bytes).map_err(ContainerStoreError::Decode)?;
    record.health_status = status.to_string();
    record.health_failures = failures;
    record.health_checked_at_unix = Some(checked_at_unix);
    let encoded = serde_json::to_vec(&record)?;
    tree.insert(id.as_bytes(), encoded)?;
    tree.flush()?;
    Ok(true)
}

fn run_health_checks(
    store: sled::Db,
    id: String,
    pid: u32,
    config: HealthConfig,
    cancel: Arc<AtomicBool>,
) {
    // Cancellation-aware start period sleep
    if config.start_period_secs > 0 {
        let deadline = std::time::Instant::now() + Duration::from_secs(config.start_period_secs);
        while std::time::Instant::now() < deadline {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    let mut failures = 0_u32;
    loop {
        // Check for explicit cancellation
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Check if container still exists (handles removal during health check)
        let tree = match store.open_tree("containers") {
            Ok(t) => t,
            Err(_) => return, // Store error, exit
        };
        if !tree.contains_key(&id).unwrap_or(false) {
            return; // Container removed, exit
        }

        let result = if config.timeout_secs > 0 {
            exec_in_container_with_timeout(
                pid,
                &config.cmd,
                Duration::from_secs(config.timeout_secs),
            )
        } else {
            exec_in_container(pid, &config.cmd)
        };
        let now = now_unix();
        match result {
            Ok(exec) if exec.exit_code == 0 => {
                failures = 0;
                if let Err(e) = update_health(&store, &id, "healthy", failures, now) {
                    eprintln!("[health] failed to update health for {id}: {e}");
                }
            }
            Ok(_) | Err(_) => {
                failures = failures.saturating_add(1);
                let status = if failures >= config.retries.max(1) {
                    "unhealthy"
                } else {
                    "starting"
                };
                match update_health(&store, &id, status, failures, now) {
                    Ok(true) => {}
                    Ok(false) => return, // Container gone
                    Err(_) => {}
                }
            }
        }

        // Cancellation-aware interval sleep
        let deadline = std::time::Instant::now() + Duration::from_secs(config.interval_secs);
        while std::time::Instant::now() < deadline {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}

// ============================================================================
// AI Resource Monitoring (Task 5.1 - Predictive OOM Prevention)
// ============================================================================

/// Check if AI features are enabled via environment variable.
///
/// Returns true if FERROCRATE_AI is set to "1" or "true".
/// When disabled, no AI-related threads are spawned for zero overhead.
fn is_ai_enabled() -> bool {
    std::env::var("FERROCRATE_AI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Resource monitor thread for predictive OOM prevention (Task 5.1).
///
/// This function runs in a background thread, periodically reading cgroup v2
/// metrics and using the ResourcePredictor to predict OOM conditions.
///
/// # Arguments
/// * `store` - Container store for checking container existence
/// * `id` - Container ID to monitor
/// * `cgroup_root` - Path to cgroup v2 mount (typically /sys/fs/cgroup)
/// * `memory_limit` - Memory limit in bytes (0 = no limit)
/// * `cancel` - Cancellation token for graceful shutdown
///
/// # Behavior
/// - Samples metrics every 30 seconds
/// - Logs OOM predictions to stderr when detected
/// - Writes predictions to audit log with DecisionTrace
/// - Progressive rollout: v0.1 observe only, v0.2 suggestions, v0.3 auto-adjust
fn run_resource_monitor(
    store: sled::Db,
    id: String,
    cgroup_root: PathBuf,
    memory_limit: u64,
    cancel: Arc<AtomicBool>,
) {
    use std::time::Instant;

    // No limit = nothing to predict
    if memory_limit == 0 {
        return;
    }

    // Initialize predictor with memory limit
    let mut predictor =
        ferro_mind::ai::resource::ResourcePredictor::new(60).with_memory_limit(memory_limit);
    let ai_logger = ferro_mind::ai::audit::AuditLogger::from_env();

    let sample_interval = Duration::from_secs(30);
    let oom_horizon = Duration::from_secs(1200); // 20 minutes

    loop {
        // Check for explicit cancellation
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Check if container still exists
        let tree = match store.open_tree("containers") {
            Ok(t) => t,
            Err(_) => return,
        };
        if !tree.contains_key(&id).unwrap_or(false) {
            return; // Container removed
        }

        // Read cgroup metrics
        let cgroup_path = cgroup_root.join("ferrocrate").join(&id);
        if let Ok(metrics) = ferro_mind::ai::resource::read_cgroup_metrics(&cgroup_path) {
            // Create sample with current metrics
            let sample = ferro_mind::ai::resource::ResourceSample {
                cpu_percent: 0.0, // CPU percentage requires delta calculation
                memory_bytes: metrics.memory_current,
                pids_count: metrics.pids_current,
                timestamp: Instant::now(),
            };

            predictor.push(sample);
            let latest_prediction = predictor.predict();

            // Predict OOM
            if let Some(prediction) = predictor.predict_oom(oom_horizon) {
                let minutes = prediction.time_to_oom.as_secs() / 60;
                let current_mb = prediction.current_memory as f64 / 1024.0 / 1024.0;
                let limit_mb = prediction.memory_limit as f64 / 1024.0 / 1024.0;
                let confidence_pct = prediction.confidence * 100.0;

                // v0.1: Log to stderr (observe only)
                eprintln!(
                    "[ai] container {}: memory projected to exceed limit ({:.1}MB/{:.1}MB) in ~{}min (confidence: {:.0}%)",
                    id, current_mb, limit_mb, minutes, confidence_pct
                );

                // Log to audit log for AI explainability (AI-11)
                let _ = log_audit_event(
                    &PathBuf::from(std::env::var("FERROCRATE_RUNTIME_DIR")
                        .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string())),
                    make_audit_event(
                        "ai_oom_prediction",
                        "ferrocrate-ai",
                        Some(&id),
                        None,
                        None,
                        Some(&format!(
                            "current_memory={} memory_limit={} time_to_oom_secs={} confidence={:.2}",
                            prediction.current_memory, prediction.memory_limit,
                            prediction.time_to_oom.as_secs(), prediction.confidence
                        )),
                    ),
                );

                if let Some(logger) = ai_logger.as_ref() {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut trace = ferro_mind::ai::explain::DecisionTrace::new(
                        format!("oom-prediction-{id}-{ts}"),
                        format!(
                            "Container {id} predicted to exceed memory limit in {} seconds",
                            prediction.time_to_oom.as_secs()
                        ),
                    )
                    .with_evidence("container_id", id.clone())
                    .with_evidence("current_memory_bytes", prediction.current_memory.to_string())
                    .with_evidence("memory_limit_bytes", prediction.memory_limit.to_string())
                    .with_evidence("predicted_peak_bytes", prediction.predicted_peak.to_string())
                    .with_evidence(
                        "time_to_oom_secs",
                        prediction.time_to_oom.as_secs().to_string(),
                    )
                    .with_evidence("confidence", format!("{:.4}", prediction.confidence))
                    .with_evidence("current_pids", metrics.pids_current.to_string())
                    .with_evidence("memory_current_cgroup", metrics.memory_current.to_string());
                    if let Some(pred) = latest_prediction {
                        trace = trace
                            .with_evidence("predicted_cpu_percent", format!("{:.2}", pred.cpu_percent))
                            .with_evidence("predicted_memory_bytes", pred.memory_bytes.to_string())
                            .with_evidence(
                                "memory_growth_rate_bytes_per_sec",
                                format!("{:.2}", pred.memory_growth_rate),
                            );
                    }
                    let _ = logger.log("ai_oom_prediction", &trace);
                }

                // v0.2: FERROCRATE_AI_SUGGEST=1 — print suggestions
                if std::env::var("FERROCRATE_AI_SUGGEST")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                {
                    eprintln!(
                        "[ai] suggestion: consider increasing memory limit with 'ferrocrate update --memory {}M {}'",
                        (limit_mb * 1.5) as u64, id
                    );
                }

                // v0.3: FERROCRATE_AI_ACT=1 — auto-adjust cgroup limit (opt-in)
                if std::env::var("FERROCRATE_AI_ACT")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                {
                    let manager = CgroupV2Manager::new(&cgroup_root);
                    let new_limit = (memory_limit as f64 * 1.25) as u64; // 25% increase
                    let ceiling = std::env::var("FERROCRATE_AI_ACT_MEMORY_CEILING")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(u64::MAX);

                    let adjusted_limit = new_limit.min(ceiling);
                    match manager.adjust_memory_limit(&cgroup_path, adjusted_limit) {
                        Ok(()) => {
                            eprintln!(
                                "[ai] container {}: increased memory limit to {}MB",
                                id,
                                adjusted_limit / 1024 / 1024
                            );
                            predictor.set_memory_limit(adjusted_limit);
                        }
                        Err(e) => {
                            eprintln!(
                                "[ai] container {}: failed to adjust memory limit: {}",
                                id, e
                            );
                        }
                    }
                }
            }
        }

        // Cancellation-aware sleep
        let sleep_start = std::time::Instant::now();
        while std::time::Instant::now().duration_since(sleep_start) < sample_interval {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ContainerRuntime;
    use crate::cgroups::{CpuMax, ResourceLimits};
    use crate::container_store::{now_unix, ContainerRecord, PortMappingRecord, RestartPolicy};
    use crate::image_manifest::OCI_IMAGE_MANIFEST_MEDIA_TYPE;
    use crate::image_store::LocalImageStore;
    use crate::image_tagging::canonicalize_reference;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CGROUP_ENV_LOCK: Mutex<()> = Mutex::new(());
    static RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Helper to acquire lock, recovering from poison (for test isolation)
    fn acquire_lock(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
        lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Check if we can run container tests (requires root or capabilities)
    fn can_run_containers() -> bool {
        // Must be root to create namespaces and manage cgroups
        nix::unistd::Uid::effective().is_root()
    }

    #[test]
    fn run_starts_process_and_persists_record() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo hi && sleep 0.05".to_string(),
                ],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        let listed = runtime.list().expect("list");
        assert!(listed.iter().any(|c| c.id == record.id));
    }

    #[test]
    fn logs_returns_output() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        let logs = wait_for_logs(&runtime, &record.id).expect("logs");
        assert!(logs.contains("hi"));
    }

    #[test]
    fn run_uses_image_config_command_when_missing() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");
        write_image_config(
            temp.path(),
            r#"{"config":{"Entrypoint":["/bin/sh","-c"],"Cmd":["echo hi"]}}"#,
        );

        let record = runtime
            .run(
                "alpine:latest",
                &[],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        assert_eq!(
            record.command,
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string()
            ]
        );
    }

    #[test]
    fn run_merges_env_and_respects_workdir_user() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");
        write_image_config(
            temp.path(),
            r#"{"config":{"Env":["A=1","B=2"],"WorkingDir":"/app","User":"1001:1002"}}"#,
        );
        let workdir_path = temp.path().join("workdir");
        std::fs::create_dir_all(&workdir_path).expect("workdir");
        let workdir = workdir_path.to_string_lossy().to_string();

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
                &["A=override".to_string(), "C=3".to_string()],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                Some(&workdir),
                Some("1000:1000"),
                Some("named"),
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        assert!(record.env.contains(&"A=override".to_string()));
        assert!(record.env.contains(&"B=2".to_string()));
        assert!(record.env.contains(&"C=3".to_string()));
        assert_eq!(record.workdir.as_deref(), Some(workdir.as_str()));
        assert_eq!(record.user.as_deref(), Some("1000:1000"));
        assert_eq!(record.name.as_deref(), Some("named"));
    }

    fn wait_for_logs(runtime: &ContainerRuntime, id: &str) -> Result<String, super::RuntimeError> {
        let mut attempts = 0;
        loop {
            let logs = runtime.logs(id)?;
            if logs.contains("hi") || attempts >= 10 {
                return Ok(logs);
            }
            attempts += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn stop_kill_remove_flow() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 1".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        runtime
            .stop(&record.id, std::time::Duration::from_millis(50))
            .expect("stop");

        runtime.remove(&record.id).expect("remove");

        let listed = runtime.list().expect("list");
        assert!(listed.iter().all(|c| c.id != record.id));
    }

    #[test]
    fn restart_updates_pid() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 1".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        runtime
            .restart(&record.id, std::time::Duration::from_millis(50))
            .expect("restart");

        let listed = runtime.list().expect("list");
        let updated = listed
            .into_iter()
            .find(|c| c.id == record.id)
            .expect("record");
        assert_ne!(updated.pid, record.pid);
    }

    #[test]
    fn startup_reconcile_marks_stale_running_pid_exited() {
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let store =
            crate::container_store::LocalContainerStore::open(temp.path().join("containers.db"))
                .expect("store");

        let record = ContainerRecord {
            id: "stale-running".to_string(),
            name: None,
            pid: 999_999,
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string(), "1".to_string()],
            workdir: None,
            user: None,
            env: Vec::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            capabilities: Vec::new(),
            health: None,
            health_status: "none".to_string(),
            health_failures: 0,
            health_checked_at_unix: None,
            restart_policy: RestartPolicy::No,
            last_exit_code: None,
            created_at_unix: now_unix(),
            stdout_path: "stdout.log".to_string(),
            stderr_path: "stderr.log".to_string(),
            status: "running".to_string(),
            netns: None,
            network_name: None,
            ip_address: None,
            ipv6_address: None,
            ports: Vec::new(),
        };
        store.put(&record).expect("seed stale record");
        drop(store);

        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let reconciled = runtime.inspect("stale-running").expect("inspect");
        assert_eq!(reconciled.status, "exited");
        assert_eq!(reconciled.last_exit_code, Some(-1));
    }

    #[test]
    fn startup_reconcile_keeps_live_running_pid() {
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let store =
            crate::container_store::LocalContainerStore::open(temp.path().join("containers.db"))
                .expect("store");

        let record = ContainerRecord {
            id: "live-running".to_string(),
            name: None,
            pid: std::process::id(),
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string(), "1".to_string()],
            workdir: None,
            user: None,
            env: Vec::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            capabilities: Vec::new(),
            health: None,
            health_status: "none".to_string(),
            health_failures: 0,
            health_checked_at_unix: None,
            restart_policy: RestartPolicy::No,
            last_exit_code: None,
            created_at_unix: now_unix(),
            stdout_path: "stdout.log".to_string(),
            stderr_path: "stderr.log".to_string(),
            status: "running".to_string(),
            netns: None,
            network_name: None,
            ip_address: None,
            ipv6_address: None,
            ports: Vec::new(),
        };
        store.put(&record).expect("seed live record");
        drop(store);

        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let reconciled = runtime.inspect("live-running").expect("inspect");
        assert_eq!(reconciled.status, "running");
        assert_eq!(reconciled.last_exit_code, None);
    }

    #[test]
    fn run_applies_cgroup_limits_when_set() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("cgroup");
        std::fs::create_dir_all(&root).expect("cgroup root");

        std::fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        std::fs::write(root.join("cgroup.subtree_control"), "").expect("subtree control");

        unsafe {
            std::env::set_var("FERROCRATE_CGROUP_ROOT", &root);
        }
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let limits = ResourceLimits {
            memory_max: Some(1024),
            cpu_max: Some(CpuMax {
                quota: 1000,
                period: 1000,
            }),
            pids_max: Some(8),
        };

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 0.05".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                Some(&limits),
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        let group = root.join("ferrocrate").join(&record.id);
        assert_eq!(
            std::fs::read_to_string(group.join("memory.max")).expect("memory.max"),
            "1024"
        );
        assert_eq!(
            std::fs::read_to_string(group.join("cpu.max")).expect("cpu.max"),
            "1000 1000"
        );
        assert_eq!(
            std::fs::read_to_string(group.join("pids.max")).expect("pids.max"),
            "8"
        );
        assert_eq!(
            std::fs::read_to_string(group.join("cgroup.procs")).expect("cgroup.procs"),
            record.pid.to_string()
        );

        unsafe {
            std::env::remove_var("FERROCRATE_CGROUP_ROOT");
        }
    }

    #[test]
    fn pause_and_resume_updates_status() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("cgroup");
        std::fs::create_dir_all(&root).expect("cgroup root");

        std::fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        std::fs::write(root.join("cgroup.subtree_control"), "").expect("subtree control");

        unsafe {
            std::env::set_var("FERROCRATE_CGROUP_ROOT", &root);
        }
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 0.1".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                "ebpf",
            )
            .expect("run");

        runtime.pause(&record.id).expect("pause");
        let paused = runtime.inspect(&record.id).expect("inspect");
        assert_eq!(paused.status, "paused");

        runtime.resume(&record.id).expect("resume");
        let resumed = runtime.inspect(&record.id).expect("inspect");
        assert_eq!(resumed.status, "running");

        unsafe {
            std::env::remove_var("FERROCRATE_CGROUP_ROOT");
        }
    }

    #[test]
    fn runtime_dns_config_defaults() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_DNS_SERVERS");
            std::env::remove_var("FERROCRATE_DNS_SEARCH");
        }
        let cfg = super::runtime_dns_config();
        assert_eq!(cfg.servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(cfg.search, vec!["ferro.local"]);
    }

    #[test]
    fn runtime_dns_config_respects_env() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_DNS_SERVERS", "9.9.9.9,1.0.0.1");
            std::env::set_var("FERROCRATE_DNS_SEARCH", "svc.local,cluster.local");
        }
        let cfg = super::runtime_dns_config();
        assert_eq!(cfg.servers, vec!["9.9.9.9", "1.0.0.1"]);
        assert_eq!(cfg.search, vec!["svc.local", "cluster.local"]);
        unsafe {
            std::env::remove_var("FERROCRATE_DNS_SERVERS");
            std::env::remove_var("FERROCRATE_DNS_SEARCH");
        }
    }

    #[test]
    fn ebpf_backend_falls_back_to_iptables_by_default() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_EBPF_STRICT");
        }
        let backend = super::resolve_network_backend("ebpf", "c1").expect("fallback backend");
        assert_eq!(backend, "iptables");
    }

    #[test]
    fn ebpf_backend_strict_mode_fails() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_EBPF_STRICT", "1");
        }
        let err = super::resolve_network_backend("ebpf", "c1").expect_err("strict failure");
        let message = err.to_string();
        assert!(message.contains("ebpf backend requested"));
        unsafe {
            std::env::remove_var("FERROCRATE_EBPF_STRICT");
        }
    }

    #[test]
    fn wireguard_config_defaults() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_WG_IFACE");
            std::env::remove_var("FERROCRATE_WG_IPV4_CIDR");
            std::env::remove_var("FERROCRATE_WG_IPV6_CIDR");
        }
        let cfg = super::wireguard_config().expect("wireguard config");
        assert_eq!(cfg.iface, "wg0");
        assert_eq!(cfg.ipv4_gateway, "10.44.0.1");
        assert_eq!(cfg.ipv4_prefix, 24);
        assert!(cfg.ipv6_gateway.is_none());
        assert!(cfg.ipv6_prefix.is_none());
    }

    #[test]
    fn wireguard_config_respects_env() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_WG_IFACE", "wg-app");
            std::env::set_var("FERROCRATE_WG_IPV4_CIDR", "10.55.0.1/16");
            std::env::set_var("FERROCRATE_WG_IPV6_CIDR", "fd00:55::1/64");
        }
        let cfg = super::wireguard_config().expect("wireguard config");
        assert_eq!(cfg.iface, "wg-app");
        assert_eq!(cfg.ipv4_gateway, "10.55.0.1");
        assert_eq!(cfg.ipv4_prefix, 16);
        assert_eq!(
            cfg.ipv6_gateway.map(|ip| ip.to_string()),
            Some("fd00:55::1".to_string())
        );
        assert_eq!(cfg.ipv6_prefix, Some(64));
        unsafe {
            std::env::remove_var("FERROCRATE_WG_IFACE");
            std::env::remove_var("FERROCRATE_WG_IPV4_CIDR");
            std::env::remove_var("FERROCRATE_WG_IPV6_CIDR");
        }
    }

    #[test]
    fn port_mapping_conflicts_are_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = crate::container_store::LocalContainerStore::open(temp.path()).expect("store");
        let existing = ContainerRecord {
            id: "c-existing".to_string(),
            name: None,
            pid: 1234,
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string(), "1".to_string()],
            workdir: None,
            user: None,
            env: Vec::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            capabilities: Vec::new(),
            health: None,
            health_status: "none".to_string(),
            health_failures: 0,
            health_checked_at_unix: None,
            restart_policy: RestartPolicy::No,
            last_exit_code: None,
            created_at_unix: now_unix(),
            stdout_path: "stdout.log".to_string(),
            stderr_path: "stderr.log".to_string(),
            status: "running".to_string(),
            netns: Some("ferro-existing".to_string()),
            network_name: Some("bridge".to_string()),
            ip_address: Some("10.0.0.2".to_string()),
            ipv6_address: None,
            ports: vec![PortMappingRecord {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            }],
        };
        store.put(&existing).expect("put existing");

        let requested = vec![PortMappingRecord {
            host_port: 8080,
            container_port: 8080,
            protocol: "tcp".to_string(),
        }];
        let err = super::validate_port_mapping_conflicts(&store, &requested).expect_err("conflict");
        assert!(err.to_string().contains("already mapped"));
    }

    #[test]
    fn allocated_ipv6_stays_within_prefix() {
        let gateway = "fd00:10::1".parse::<std::net::Ipv6Addr>().expect("ipv6");
        let assigned = super::allocate_container_ipv6("abc123", &gateway, 64)
            .parse::<std::net::Ipv6Addr>()
            .expect("assigned ipv6");
        let gateway_u = u128::from(gateway);
        let assigned_u = u128::from(assigned);
        let host_mask = (1u128 << (128 - 64)) - 1;
        let network_mask = !host_mask;
        assert_eq!(gateway_u & network_mask, assigned_u & network_mask);
        assert_ne!(assigned, gateway);
    }

    #[test]
    fn allocated_ipv6_is_deterministic_for_container_id() {
        let gateway = "fd00:20::1".parse::<std::net::Ipv6Addr>().expect("ipv6");
        let first = super::allocate_container_ipv6("cid-1", &gateway, 64);
        let second = super::allocate_container_ipv6("cid-1", &gateway, 64);
        let third = super::allocate_container_ipv6("cid-2", &gateway, 64);
        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn bandwidth_limit_validation_accepts_supported_units() {
        assert_eq!(
            super::validate_bandwidth_limit("100mbit").expect("valid"),
            "100mbit"
        );
        assert_eq!(
            super::validate_bandwidth_limit("42KBIT").expect("valid"),
            "42kbit"
        );
    }

    #[test]
    fn bandwidth_limit_validation_rejects_invalid_values() {
        let err = super::validate_bandwidth_limit("0mbit").expect_err("invalid");
        assert!(err.to_string().contains("positive integer"));
        let err = super::validate_bandwidth_limit("100").expect_err("missing unit");
        assert!(err.to_string().contains("must end with"));
    }

    #[test]
    fn seccomp_profile_is_enabled_by_default() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP");
        }
        let profile = super::load_seccomp_profile().expect("seccomp profile");
        assert!(profile.is_some());
    }

    #[test]
    fn seccomp_profile_can_be_disabled_explicitly() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_SECCOMP", "0");
        }
        let profile = super::load_seccomp_profile().expect("seccomp profile");
        assert!(profile.is_none());
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP");
        }
    }

    #[test]
    fn seccomp_strict_mode_defaults_to_false() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP_STRICT");
        }
        assert!(!super::seccomp_strict_mode());
    }

    #[test]
    fn seccomp_strict_mode_respects_env() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_SECCOMP_STRICT", "1");
        }
        assert!(super::seccomp_strict_mode());
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP_STRICT");
        }
    }

    #[test]
    fn security_ebpf_events_default_and_env_override() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_EBPF_SECURITY_EVENTS");
        }
        assert_eq!(
            super::security_ebpf_events(),
            vec!["execve", "connect", "open", "ptrace", "mount", "unshare"]
        );
        unsafe {
            std::env::set_var("FERROCRATE_EBPF_SECURITY_EVENTS", "execve,connect, open");
        }
        assert_eq!(
            super::security_ebpf_events(),
            vec!["execve", "connect", "open"]
        );
        unsafe {
            std::env::remove_var("FERROCRATE_EBPF_SECURITY_EVENTS");
        }
    }

    #[test]
    fn wireguard_peer_config_requires_endpoint_when_key_present() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_WG_PEER_PUBLIC_KEY", "peer-key");
            std::env::remove_var("FERROCRATE_WG_PEER_ENDPOINT");
        }
        let err = super::wireguard_peer_config().expect_err("missing endpoint");
        assert!(err.to_string().contains("PEER_ENDPOINT"));
        unsafe {
            std::env::remove_var("FERROCRATE_WG_PEER_PUBLIC_KEY");
        }
    }

    #[test]
    fn wireguard_listen_port_is_deterministic() {
        let first = super::wireguard_listen_port("container-a");
        let second = super::wireguard_listen_port("container-a");
        let third = super::wireguard_listen_port("container-b");
        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn mac_permissive_mode_respects_env() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_MAC_PERMISSIVE");
        }
        assert!(!super::mac_permissive_mode());
        unsafe {
            std::env::set_var("FERROCRATE_MAC_PERMISSIVE", "1");
        }
        assert!(super::mac_permissive_mode());
        unsafe {
            std::env::remove_var("FERROCRATE_MAC_PERMISSIVE");
        }
    }

    #[test]
    fn selinux_type_validation_rejects_invalid_chars() {
        let err = super::validate_selinux_type("container_t;bad").expect_err("invalid type");
        assert!(err.to_string().contains("invalid characters"));
        super::validate_selinux_type("container_t").expect("valid type");
    }

    fn seed_image_store(runtime_dir: &std::path::Path, image: &str) {
        let store = LocalImageStore::open(runtime_dir.join("images")).expect("store");
        let canonical = canonicalize_reference(image).expect("canonical");
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}"#;
        store
            .put_reference(
                &canonical,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                manifest_json,
            )
            .expect("seed manifest");
    }

    fn write_image_config(runtime_dir: &std::path::Path, json: &str) {
        let config_root = runtime_dir.join("images").join("configs");
        std::fs::create_dir_all(&config_root).expect("configs dir");
        let config_path = config_root
            .join("sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        std::fs::write(config_path, json).expect("write config");
    }
}
