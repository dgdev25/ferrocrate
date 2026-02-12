use crate::container_exec::{exec_in_container, exec_in_container_with_timeout};
use crate::container_store::{
    ContainerRecord, HealthConfig, LocalContainerStore, RestartPolicy, ContainerStoreError, now_unix,
};
use crate::cgroups::{CgroupStats, CgroupV2Manager, ResourceLimits};
use crate::capabilities::{drop_all_capabilities, set_capabilities};
use crate::image_config::{
    command_from_config, env_from_config, healthcheck_from_config, user_from_config,
    working_dir_from_config,
};
use crate::image_fetch::{resolve_layer_paths_with_store, resolve_config_path_with_store};
use crate::image_security::verify_image_signature;
use crate::image_store::LocalImageStore;
use crate::mac_profiles::generate_apparmor_profile;
use crate::observability::{log_audit_event, log_event, make_audit_event, make_event};
use crate::rootfs::construct_rootfs_with_dedup;
use crate::mounts::{BindMount, TmpfsMount, MountError, apply_bind_mounts, apply_readonly_rootfs, apply_tmpfs_mounts};
use crate::process_lifecycle::{ProcessLifecycleError, kill_pid, stop_pid};
use crate::registry::parse_image_reference;
use ferro_net::bridge;
use ferro_net::ebpf::{EbpfProgram, build_bpftool_load_cmd, build_tc_attach_cmd, build_xdp_attach_cmd};
use ferro_net::netns;
use ferro_net::nftables::{NftRule, build_nft_add_rule_cmd, build_nft_delete_rule_cmd};
use ferro_net::portmap::{build_iptables_forward_cmd, build_iptables_prerouting_cmd};
use ferro_net::rootless::{RootlessNetConfig, build_slirp4netns_cmd};
use ferro_net::veth;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::fs::OpenOptions;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use thiserror::Error;

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
    #[error("container not found: {0}")]
    ContainerNotFound(String),
    #[error("command is required to run container")]
    MissingCommand,
    #[error("invalid container state: {0}")]
    InvalidState(String),
    #[error("image not found in store: {0}")]
    ImageMissing(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("kernel version error: {0}")]
    Kernel(String),
}

pub struct ContainerRuntime {
    store: LocalContainerStore,
    runtime_dir: PathBuf,
    cgroup_root: PathBuf,
}

impl ContainerRuntime {
    pub fn new(runtime_dir: &Path) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let store = LocalContainerStore::open(runtime_dir.join("containers.db"))?;
        let cgroup_root = std::env::var("FERROCRATE_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));
        Ok(Self {
            store,
            runtime_dir: runtime_dir.to_path_buf(),
            cgroup_root,
        })
    }

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
        verify_image_signature(image)
            .map_err(|err| RuntimeError::InvalidState(err.to_string()))?;
        let mut config_json = None;
        if let Ok(Some(config_path)) = resolve_config_path_with_store(&self.runtime_dir, image, store)
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
        let exec_cmd = apply_apparmor_if_enabled(&self.runtime_dir, &container_id, &command)?;
        let exec_cmd = apply_selinux_if_enabled(&exec_cmd)?;
        let container_dir = self.runtime_dir.join("containers").join(&container_id);
        let log_dir = container_dir.join("logs");
        fs::create_dir_all(&log_dir)?;

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

        let rootless = !nix::unistd::Uid::effective().is_root();
        let (netns_name, container_ip, container_ipv6) =
            setup_network(&container_id, port_mappings, network_mode, network_backend)?;
        let unshare_netns = rootless && network_mode != "host" && rootless_netns_enabled();
        let use_slirp = unshare_netns && network_mode == "bridge";

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
        )?;

        if use_slirp {
            start_slirp4netns(child_id)?;
        }

        if let Some(limits) = limits {
            let manager = CgroupV2Manager::new(&self.cgroup_root);
            let group = manager.create_group(&format!("ferrocrate/{container_id}"))?;
            manager.apply_limits(&group, limits)?;
            manager.add_pid(&group, child_id)?;
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
            health_status: if health.is_some() { "starting".to_string() } else { "none".to_string() },
            health_failures: 0,
            health_checked_at_unix: None,
            restart_policy: restart_policy.clone(),
            last_exit_code: None,
            created_at_unix: now_unix(),
            stdout_path: stdout_path.display().to_string(),
            stderr_path: stderr_path.display().to_string(),
            status: "running".to_string(),
            netns: netns_name.clone(),
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
            thread::spawn(move || {
                run_health_checks(store, id, pid, config);
            });
        }
        Ok(record)
    }

    pub fn exec(&self, id: &str, cmd: &[String]) -> Result<crate::container_exec::ExecResult, RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let result = exec_in_container(record.pid, cmd)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "exec",
                Some(&record.id),
                Some(&record.image),
                None,
                None,
            ),
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
            make_event("resume", Some(id), Some(&record.image), Some("running"), None),
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
        )?;

        record.pid = child_id;
        record.status = "running".to_string();
        self.store.put(&record)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("restart", Some(id), Some(&record.image), Some("running"), None),
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
            thread::spawn(move || {
                run_health_checks(store, id, pid, config);
            });
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if record.status == "running" {
            return Err(RuntimeError::InvalidState(format!(
                "container {id} is still running"
            )));
        }
        let _ = cleanup_network(&record);
        let container_dir = self.runtime_dir.join("containers").join(id);
        let _ = fs::remove_dir_all(&container_dir);
        let _ = self.store.remove(id)?;
        if let Ok(containers) = self.store.list() {
            let _ = update_container_hosts(&self.runtime_dir, &containers);
        }
        let _ = log_event(
            &self.runtime_dir,
            make_event("remove", Some(id), Some(&record.image), Some("removed"), None),
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
    format!("c{}-{}", now_unix(), std::process::id())
}

fn stream_to_file_with_options<R: std::io::Read>(
    mut reader: R,
    path: &Path,
    append: bool,
) -> Result<(), std::io::Error> {
    let mut file = if append {
        OpenOptions::new().create(true).append(true).open(path)?
    } else {
        fs::File::create(path)?
    };
    std::io::copy(&mut reader, &mut file)?;
    Ok(())
}

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
    )?;
    let (child_id, child, join_handles) = spawn_child_with_logs(
        command,
        stdout_path,
        stderr_path,
        append,
    )?;

    let cmd_owned = cmd.to_vec();
    let env_owned = env.to_vec();
    let stdout_path = stdout_path.to_path_buf();
    let stderr_path = stderr_path.to_path_buf();
    let rootfs_dir = rootfs_dir.clone();
    let no_new_privs = no_new_privs;
    let caps_for_restart = capabilities.clone();
    let workdir = workdir.map(|val| val.to_string());
    let user = user.map(|val| val.to_string());
    let netns_name = netns_name.map(|val| val.to_string());
    thread::spawn(move || {
        supervise_child(
            child,
            join_handles,
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
        );
    });

    Ok(child_id)
}

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
) -> Result<Command, RuntimeError> {
    let mut command = if let Some(netns) = netns_name {
        let mut netns_cmd = Command::new("ip");
        netns_cmd.arg("netns").arg("exec").arg(netns);
        if let Some(rootfs) = rootfs_dir {
            if nix::unistd::Uid::effective().is_root() {
                netns_cmd.arg("chroot").arg(rootfs).arg(&cmd[0]).args(&cmd[1..]);
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
        } else {
            let mut host_cmd = Command::new(&cmd[0]);
            host_cmd.args(&cmd[1..]);
            host_cmd
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
            return Err(RuntimeError::InvalidState("env var missing key".to_string()));
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
    unsafe {
        command.pre_exec(move || {
            if nix::unistd::Uid::effective().is_root() {
                if caps.is_empty() {
                    drop_all_capabilities()
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
                } else {
                    set_capabilities(&caps)
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
                }
            }
            Ok(())
        });
    }

    Ok(command)
}

fn spawn_child_with_logs(
    mut command: Command,
    stdout_path: &Path,
    stderr_path: &Path,
    append: bool,
) -> Result<(u32, Child, Vec<thread::JoinHandle<()>>), RuntimeError> {
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let mut join_handles = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let out_path = stdout_path.to_path_buf();
        join_handles.push(thread::spawn(move || {
            let _ = stream_to_file_with_options(stdout, &out_path, append);
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let err_path = stderr_path.to_path_buf();
        join_handles.push(thread::spawn(move || {
            let _ = stream_to_file_with_options(stderr, &err_path, append);
        }));
    }
    let child_id = child.id();
    Ok((child_id, child, join_handles))
}

fn supervise_child(
    mut child: Child,
    mut join_handles: Vec<thread::JoinHandle<()>>,
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
) {
    loop {
        let status = child.wait();
        for handle in join_handles.drain(..) {
            let _ = handle.join();
        }
        let exit_code = status
            .ok()
            .and_then(|s| s.code())
            .unwrap_or(-1);
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
        ) {
            Ok(cmd) => cmd,
            Err(_) => break,
        };
        let (pid, new_child, new_handles) =
            match spawn_child_with_logs(command, &stdout_path, &stderr_path, append) {
                Ok(tuple) => tuple,
                Err(_) => break,
            };
        let _ = update_pid_status(&store, &container_id, pid, "running");
        child = new_child;
        join_handles = new_handles;
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
    let gid = parts.next().and_then(|g| g.parse::<u32>().ok()).unwrap_or(uid);
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
    let output = Command::new("uname")
        .arg("-r")
        .output()
        .map_err(RuntimeError::Io)?;
    let raw = String::from_utf8_lossy(&output.stdout);
    let version = raw.trim();
    let mut parts = version.split(|c| c == '.' || c == '-');
    let major = parts.next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    if major < 5 || (major == 5 && minor < 10) {
        return Err(RuntimeError::Kernel(format!(
            "kernel {version} below required 5.10"
        )));
    }
    Ok(())
}

fn setup_network(
    container_id: &str,
    port_mappings: &[crate::container_store::PortMappingRecord],
    network_mode: &str,
    network_backend: &str,
) -> Result<(Option<String>, Option<String>, Option<String>), RuntimeError> {
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
            run_cmd(&netns::build_ip_netns_add_cmd(&netns_name))?;
            run_cmd(&ip_netns_exec(&netns_name, &["ip", "link", "set", "lo", "up"]))?;
            return Ok((Some(netns_name), None, None));
        }
        "bridge" => {}
        "wireguard" => {
            if !nix::unistd::Uid::effective().is_root() {
                return Err(RuntimeError::Network(
                    "wireguard requires root".to_string(),
                ));
            }
            if !port_mappings.is_empty() {
                return Err(RuntimeError::Network(
                    "port mapping requires network bridge".to_string(),
                ));
            }
            let netns_name = format!("ferro-{container_id}");
            run_cmd(&netns::build_ip_netns_add_cmd(&netns_name))?;
            run_cmd(&ip_netns_exec(&netns_name, &["ip", "link", "set", "lo", "up"]))?;
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
    let effective_backend = if network_backend == "ebpf" {
        "iptables"
    } else {
        network_backend
    };
    if !port_mappings.is_empty()
        && effective_backend != "iptables"
        && effective_backend != "nftables"
    {
        return Err(RuntimeError::Network(
            "port mapping requires network-backend=iptables or nftables".to_string(),
        ));
    }

    let bridge_config = bridge_config()?;
    run_cmd_allow_exists(&bridge::build_ip_link_add_bridge_cmd(&bridge_config.name))?;
    run_cmd_allow_exists(&bridge::build_ip_addr_add_bridge_cmd(
        &bridge_config.name,
        &bridge_config.cidr,
    ))?;
    if let Some(ipv6_cidr) = bridge_config.ipv6_cidr.as_ref() {
        run_cmd_allow_exists(&bridge::build_ip_addr_add_ipv6_bridge_cmd(
            &bridge_config.name,
            ipv6_cidr,
        ))?;
    }
    run_cmd(&bridge::build_ip_link_set_up_cmd(&bridge_config.name))?;

    let netns_name = format!("ferro-{container_id}");
    run_cmd(&netns::build_ip_netns_add_cmd(&netns_name))?;

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
    run_cmd(&veth::build_ip_link_add_veth_cmd(&veth_config))?;
    run_cmd(&bridge::build_ip_link_set_master_cmd(
        &host_veth,
        &bridge_config.name,
    ))?;
    run_cmd(&veth::build_ip_link_set_up_cmd(&host_veth))?;
    if ebpf_monitor_enabled() {
        setup_ebpf_monitor(&host_veth)?;
    }
    run_cmd(&netns::build_ip_link_set_netns_cmd("eth0", &netns_name))?;

    let container_ip = allocate_container_ip(container_id, &bridge_config.gateway)?;
    let container_ipv6 = if let Some((gateway, prefix)) =
        bridge_config.ipv6_gateway.as_ref().zip(bridge_config.ipv6_prefix)
    {
        Some(allocate_container_ipv6(container_id, gateway, prefix))
    } else {
        None
    };
    run_cmd(&ip_netns_exec(&netns_name, &["ip", "link", "set", "lo", "up"]))?;
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
    run_cmd(&ip_netns_exec(&netns_name, &["ip", "link", "set", "eth0", "up"]))?;
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
                let prerouting = build_nft_prerouting_cmd(&map, &container_ip);
                let forward = build_nft_forward_cmd(&map, &container_ip);
                run_cmd(&prerouting)?;
                run_cmd(&forward)?;
            } else {
                let prerouting = build_iptables_prerouting_cmd(&map, &container_ip);
                let forward = build_iptables_forward_cmd(&map, &container_ip);
                run_cmd(&prerouting)?;
                run_cmd(&forward)?;
            }
        }
    }

    if let Some(limit) = bandwidth_limit().as_deref() {
        apply_bandwidth_limit(&host_veth, limit)?;
    }

    Ok((Some(netns_name), Some(container_ip), container_ipv6))
}

fn cleanup_network(record: &ContainerRecord) -> Result<(), RuntimeError> {
    if let Some(netns_name) = record.netns.as_ref() {
        let _ = run_cmd(&netns::build_ip_netns_del_cmd(netns_name));
    }
    if let Some(container_ip) = record.ip_address.as_ref() {
        for mapping in &record.ports {
            let map = ferro_net::portmap::PortMapping {
                host_port: mapping.host_port,
                container_port: mapping.container_port,
                protocol: mapping.protocol.clone(),
            };
            let mut prerouting = build_iptables_prerouting_cmd(&map, container_ip);
            let mut forward = build_iptables_forward_cmd(&map, container_ip);
            replace_iptables_action(&mut prerouting, "-D");
            replace_iptables_action(&mut forward, "-D");
            let _ = run_cmd(&prerouting);
            let _ = run_cmd(&forward);
            let nft_prerouting = build_nft_prerouting_delete_cmd(&map, container_ip);
            let nft_forward = build_nft_forward_delete_cmd(&map, container_ip);
            let _ = run_cmd(&nft_prerouting);
            let _ = run_cmd(&nft_forward);
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
    let cmd = build_slirp4netns_cmd(pid, &config);
    if cmd.is_empty() {
        return Ok(());
    }
    let (bin, rest) = cmd.split_first().unwrap();
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
        return Ok(cmd.to_vec());
    }
    let profile_name = format!("ferrocrate-{container_id}");
    let profile = generate_apparmor_profile(container_id)?;
    let profile_dir = runtime_dir.join("security").join("apparmor");
    fs::create_dir_all(&profile_dir)?;
    let profile_path = profile_dir.join(format!("{profile_name}.profile"));
    fs::write(&profile_path, profile)?;

    let output = Command::new("apparmor_parser")
        .arg("-r")
        .arg(&profile_path)
        .output()?;
    if !output.status.success() {
        return Ok(cmd.to_vec());
    }

    let mut wrapped = Vec::new();
    wrapped.push("aa-exec".to_string());
    wrapped.push("-p".to_string());
    wrapped.push(profile_name);
    wrapped.push("--".to_string());
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
        return Ok(cmd.to_vec());
    }
    let selinux_type =
        std::env::var("FERROCRATE_SELINUX_TYPE").unwrap_or_else(|_| "container_t".to_string());
    let mut wrapped = Vec::new();
    wrapped.push("runcon".to_string());
    wrapped.push("-t".to_string());
    wrapped.push(selinux_type);
    wrapped.push("--".to_string());
    wrapped.extend(cmd.iter().cloned());
    Ok(wrapped)
}

fn command_available(bin: &str) -> bool {
    Command::new(bin).arg("--version").output().is_ok()
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
) -> Vec<String> {
    build_nft_add_rule_cmd(&build_nft_prerouting_rule(mapping, container_ip))
}

fn build_nft_forward_cmd(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> Vec<String> {
    build_nft_add_rule_cmd(&build_nft_forward_rule(mapping, container_ip))
}

fn build_nft_prerouting_delete_cmd(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> Vec<String> {
    build_nft_delete_rule_cmd(&build_nft_prerouting_rule(mapping, container_ip))
}

fn build_nft_forward_delete_cmd(
    mapping: &ferro_net::portmap::PortMapping,
    container_ip: &str,
) -> Vec<String> {
    build_nft_delete_rule_cmd(&build_nft_forward_rule(mapping, container_ip))
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
    }
    Ok(())
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

fn replace_iptables_action(cmd: &mut Vec<String>, replacement: &str) {
    for entry in cmd.iter_mut() {
        if entry == "-A" {
            *entry = replacement.to_string();
            break;
        }
    }
}

fn ip_netns_exec(netns_name: &str, args: &[&str]) -> Vec<String> {
    let mut out = vec!["ip".to_string(), "netns".to_string(), "exec".to_string(), netns_name.to_string()];
    out.extend(args.iter().map(|val| (*val).to_string()));
    out
}

fn run_cmd(args: &[String]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        return Ok(());
    }
    let (bin, rest) = args.split_first().unwrap();
    let output = Command::new(bin).args(rest).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Err(RuntimeError::Network(format!(
        "command failed: {} {}",
        bin,
        stderr.trim()
    )))
}

fn run_cmd_allow_exists(args: &[String]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        return Ok(());
    }
    let (bin, rest) = args.split_first().unwrap();
    let output = Command::new(bin).args(rest).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if stderr.contains("File exists") || stderr.contains("exists") {
        return Ok(());
    }
    Err(RuntimeError::Network(format!(
        "command failed: {} {}",
        bin,
        stderr.trim()
    )))
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
    let name =
        std::env::var("FERROCRATE_BRIDGE_NAME").unwrap_or_else(|_| "ferro0".to_string());
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

fn allocate_container_ipv6(container_id: &str, gateway: &Ipv6Addr, _prefix: u8) -> String {
    let mut segments = gateway.segments();
    let hash = blake3::hash(container_id.as_bytes());
    let byte = hash.as_bytes()[0] as u16;
    segments[7] = 2 + (byte % 200);
    Ipv6Addr::from(segments).to_string()
}

fn bandwidth_limit() -> Option<String> {
    std::env::var("FERROCRATE_BANDWIDTH_LIMIT").ok()
}

fn apply_bandwidth_limit(link: &str, limit: &str) -> Result<(), RuntimeError> {
    if limit.trim().is_empty() {
        return Ok(());
    }
    let cmd = vec![
        "tc".to_string(),
        "qdisc".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        link.to_string(),
        "root".to_string(),
        "tbf".to_string(),
        "rate".to_string(),
        limit.to_string(),
        "burst".to_string(),
        "32kbit".to_string(),
        "latency".to_string(),
        "400ms".to_string(),
    ];
    run_cmd(&cmd)
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

fn short_id(value: &str, max: usize) -> String {
    value.chars().filter(|c| c.is_ascii_alphanumeric()).rev().take(max).collect::<String>().chars().rev().collect()
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

fn update_exit(
    db: &sled::Db,
    id: &str,
    exit_code: i32,
) -> Result<String, ContainerStoreError> {
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    let Some(bytes) = tree.get(id.as_bytes())? else {
        return Ok("exited".to_string());
    };
    let mut record = serde_json::from_slice::<ContainerRecord>(&bytes)
        .map_err(ContainerStoreError::Decode)?;
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
    let mut record = serde_json::from_slice::<ContainerRecord>(&bytes)
        .map_err(ContainerStoreError::Decode)?;
    record.health_status = status.to_string();
    record.health_failures = failures;
    record.health_checked_at_unix = Some(checked_at_unix);
    let encoded = serde_json::to_vec(&record)?;
    tree.insert(id.as_bytes(), encoded)?;
    tree.flush()?;
    Ok(true)
}

fn run_health_checks(store: sled::Db, id: String, pid: u32, config: HealthConfig) {
    if config.start_period_secs > 0 {
        thread::sleep(Duration::from_secs(config.start_period_secs));
    }

    let mut failures = 0_u32;
    loop {
        let result = if config.timeout_secs > 0 {
            exec_in_container_with_timeout(pid, &config.cmd, Duration::from_secs(config.timeout_secs))
        } else {
            exec_in_container(pid, &config.cmd)
        };
        let now = now_unix();
        match result {
            Ok(exec) if exec.exit_code == 0 => {
                failures = 0;
                let _ = update_health(&store, &id, "healthy", failures, now);
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
                    Ok(false) => break,
                    Err(_) => {}
                }
            }
        }
        thread::sleep(Duration::from_secs(config.interval_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::ContainerRuntime;
    use crate::container_store::RestartPolicy;
    use crate::image_store::LocalImageStore;
    use crate::image_manifest::OCI_IMAGE_MANIFEST_MEDIA_TYPE;
    use crate::image_tagging::canonicalize_reference;
    use crate::cgroups::{CpuMax, ResourceLimits};
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CGROUP_ENV_LOCK: Mutex<()> = Mutex::new(());
    static RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn run_starts_process_and_persists_record() {
        let _guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
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
        let _guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                "echo hi".to_string(),
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

        let logs = wait_for_logs(&runtime, &record.id).expect("logs");
        assert!(logs.contains("hi"));
    }

    #[test]
    fn run_uses_image_config_command_when_missing() {
        let _guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
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
            vec!["/bin/sh".to_string(), "-c".to_string(), "echo hi".to_string()]
        );
    }

    #[test]
    fn run_merges_env_and_respects_workdir_user() {
        let _guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
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
        let _guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
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
        let _guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
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
    fn run_applies_cgroup_limits_when_set() {
        let _guard = CGROUP_ENV_LOCK.lock().expect("lock env");
        let _runtime_guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("cgroup");
        std::fs::create_dir_all(&root).expect("cgroup root");

        std::fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        std::fs::write(root.join("cgroup.subtree_control"), "").expect("subtree control");

        unsafe { std::env::set_var("FERROCRATE_CGROUP_ROOT", &root); }
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let limits = ResourceLimits {
            memory_max: Some(1024),
            cpu_max: Some(CpuMax { quota: 1000, period: 1000 }),
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

        unsafe { std::env::remove_var("FERROCRATE_CGROUP_ROOT"); }
    }

    #[test]
    fn pause_and_resume_updates_status() {
        let _guard = CGROUP_ENV_LOCK.lock().expect("lock env");
        let _runtime_guard = RUNTIME_TEST_LOCK.lock().expect("lock runtime");
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("cgroup");
        std::fs::create_dir_all(&root).expect("cgroup root");

        std::fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        std::fs::write(root.join("cgroup.subtree_control"), "").expect("subtree control");

        unsafe { std::env::set_var("FERROCRATE_CGROUP_ROOT", &root); }
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

        unsafe { std::env::remove_var("FERROCRATE_CGROUP_ROOT"); }
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
        let config_path = config_root.join(
            "sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        std::fs::write(config_path, json).expect("write config");
    }
}
