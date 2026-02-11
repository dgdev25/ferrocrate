use crate::container_exec::exec_in_container;
use crate::container_store::{
    ContainerRecord, HealthConfig, LocalContainerStore, RestartPolicy, ContainerStoreError, now_unix,
};
use crate::cgroups::{CgroupV2Manager, ResourceLimits};
use crate::capabilities::{drop_all_capabilities, set_capabilities};
use crate::image_config::healthcheck_from_config;
use crate::image_fetch::resolve_layer_paths;
use crate::image_fetch::resolve_config_path;
use crate::observability::{log_event, make_event};
use crate::rootfs::construct_rootfs;
use crate::mounts::{BindMount, TmpfsMount, MountError, apply_bind_mounts, apply_readonly_rootfs, apply_tmpfs_mounts};
use crate::process_lifecycle::{ProcessLifecycleError, kill_pid, stop_pid};
use crate::registry::parse_image_reference;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
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
    #[error("exec error: {0}")]
    Exec(#[from] crate::container_exec::ContainerExecError),
    #[error("process lifecycle error: {0}")]
    ProcessLifecycle(#[from] ProcessLifecycleError),
    #[error("rootfs error: {0}")]
    Rootfs(#[from] crate::rootfs::RootfsError),
    #[error("mount error: {0}")]
    Mount(#[from] MountError),
    #[error("container not found: {0}")]
    ContainerNotFound(String),
    #[error("command is required to run container")]
    MissingCommand,
    #[error("invalid container state: {0}")]
    InvalidState(String),
    #[error("image not found in store: {0}")]
    ImageMissing(String),
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
    ) -> Result<ContainerRecord, RuntimeError> {
        parse_image_reference(image)?;
        if cmd.is_empty() {
            return Err(RuntimeError::MissingCommand);
        }

        let container_id = generate_container_id();
        let container_dir = self.runtime_dir.join("containers").join(&container_id);
        let log_dir = container_dir.join("logs");
        fs::create_dir_all(&log_dir)?;

        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");

        let layer_paths = resolve_layer_paths(&self.runtime_dir, image)
            .map_err(|_| RuntimeError::ImageMissing(image.to_string()))?;
        let rootfs_dir = container_dir.join("rootfs");
        if !layer_paths.is_empty() {
            construct_rootfs(&rootfs_dir, &layer_paths)?;
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

        let child_id = spawn_process_with_logs(
            cmd,
            env,
            &stdout_path,
            &stderr_path,
            false,
            self.store.clone_db(),
            container_id.clone(),
            Some(rootfs_dir.clone()),
            no_new_privs,
            restart_policy.clone(),
            capabilities.to_vec(),
        )?;

        if let Some(limits) = limits {
            let manager = CgroupV2Manager::new(&self.cgroup_root);
            let group = manager.create_group(&format!("ferrocrate/{container_id}"))?;
            manager.apply_limits(&group, limits)?;
            manager.add_pid(&group, child_id)?;
        }

        let health = if health.is_none() {
            resolve_config_path(&self.runtime_dir, image)
                .ok()
                .flatten()
                .and_then(|path| fs::read_to_string(path).ok())
                .and_then(|json| healthcheck_from_config(&json))
        } else {
            health
        };

        let record = ContainerRecord {
            id: container_id.clone(),
            pid: child_id,
            image: image.to_string(),
            command: cmd.to_vec(),
            env: env.to_vec(),
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
        };

        self.store.put(&record)?;
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
        )?;

        record.pid = child_id;
        record.status = "running".to_string();
        self.store.put(&record)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("restart", Some(id), Some(&record.image), Some("running"), None),
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
        let container_dir = self.runtime_dir.join("containers").join(id);
        let _ = fs::remove_dir_all(&container_dir);
        let _ = self.store.remove(id)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("remove", Some(id), Some(&record.image), Some("removed"), None),
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
) -> Result<u32, RuntimeError> {
    let command = build_command(
        cmd,
        env,
        rootfs_dir.as_deref(),
        no_new_privs,
        &capabilities,
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
) -> Result<Command, RuntimeError> {
    let mut command = if let Some(rootfs) = rootfs_dir {
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
        let result = exec_in_container(pid, &config.cmd);
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

    #[test]
    fn run_starts_process_and_persists_record() {
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
            )
            .expect("run");

        let listed = runtime.list().expect("list");
        assert!(listed.iter().any(|c| c.id == record.id));
    }

    #[test]
    fn logs_returns_output() {
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
            )
            .expect("run");

        let logs = wait_for_logs(&runtime, &record.id).expect("logs");
        assert!(logs.contains("hi"));
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
}
