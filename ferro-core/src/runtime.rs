use crate::container_exec::exec_in_container;
use crate::container_store::{ContainerRecord, LocalContainerStore, ContainerStoreError, now_unix};
use crate::process_lifecycle::{ProcessLifecycleError, kill_pid, stop_pid};
use crate::registry::parse_image_reference;
use std::fs;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid image reference: {0}")]
    InvalidImage(#[from] crate::registry::RegistryError),
    #[error("container store error: {0}")]
    Store(#[from] ContainerStoreError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("exec error: {0}")]
    Exec(#[from] crate::container_exec::ContainerExecError),
    #[error("process lifecycle error: {0}")]
    ProcessLifecycle(#[from] ProcessLifecycleError),
    #[error("container not found: {0}")]
    ContainerNotFound(String),
    #[error("command is required to run container")]
    MissingCommand,
    #[error("invalid container state: {0}")]
    InvalidState(String),
}

pub struct ContainerRuntime {
    store: LocalContainerStore,
    runtime_dir: PathBuf,
}

impl ContainerRuntime {
    pub fn new(runtime_dir: &Path) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let store = LocalContainerStore::open(runtime_dir.join("containers.db"))?;
        Ok(Self {
            store,
            runtime_dir: runtime_dir.to_path_buf(),
        })
    }

    pub fn run(&self, image: &str, cmd: &[String]) -> Result<ContainerRecord, RuntimeError> {
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

        let child_id = spawn_process_with_logs(
            cmd,
            &stdout_path,
            &stderr_path,
            false,
            self.store.clone_db(),
            container_id.clone(),
        )?;

        let record = ContainerRecord {
            id: container_id.clone(),
            pid: child_id,
            image: image.to_string(),
            command: cmd.to_vec(),
            created_at_unix: now_unix(),
            stdout_path: stdout_path.display().to_string(),
            stderr_path: stderr_path.display().to_string(),
            status: "running".to_string(),
        };

        self.store.put(&record)?;
        Ok(record)
    }

    pub fn exec(&self, id: &str, cmd: &[String]) -> Result<crate::container_exec::ExecResult, RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        Ok(exec_in_container(record.pid, cmd)?)
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

    pub fn stop(&self, id: &str, timeout: Duration) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        stop_pid(record.pid, timeout)?;
        self.store.update_status(id, "exited")?;
        Ok(())
    }

    pub fn kill(&self, id: &str) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        kill_pid(record.pid)?;
        self.store.update_status(id, "killed")?;
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
            &stdout_path,
            &stderr_path,
            true,
            self.store.clone_db(),
            record.id.clone(),
        )?;

        record.pid = child_id;
        record.status = "running".to_string();
        self.store.put(&record)?;
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
    stdout_path: &Path,
    stderr_path: &Path,
    append: bool,
    store: sled::Db,
    container_id: String,
) -> Result<u32, RuntimeError> {
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

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
    thread::spawn(move || {
        let _ = child.wait();
        for handle in join_handles {
            let _ = handle.join();
        }
        let _ = update_status(&store, &container_id, "exited");
    });

    Ok(child_id)
}

fn update_status(db: &sled::Db, id: &str, status: &str) -> Result<(), ContainerStoreError> {
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    if let Some(bytes) = tree.get(id.as_bytes())? {
        let mut record = serde_json::from_slice::<ContainerRecord>(&bytes)
            .map_err(ContainerStoreError::Decode)?;
        record.status = status.to_string();
        let encoded = serde_json::to_vec(&record)?;
        tree.insert(id.as_bytes(), encoded)?;
        tree.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ContainerRuntime;

    #[test]
    fn run_starts_process_and_persists_record() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");

        let record = runtime
            .run(
                "alpine:latest",
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo hi && sleep 0.05".to_string(),
                ],
            )
            .expect("run");

        let listed = runtime.list().expect("list");
        assert!(listed.iter().any(|c| c.id == record.id));
    }

    #[test]
    fn logs_returns_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");

        let record = runtime
            .run(
                "alpine:latest",
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo hi".to_string(),
                ],
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

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 1".to_string()],
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

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 1".to_string()],
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
}
