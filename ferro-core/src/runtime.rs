use crate::container_exec::exec_in_container;
use crate::container_store::{ContainerRecord, LocalContainerStore, ContainerStoreError, now_unix};
use crate::registry::parse_image_reference;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
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
    #[error("container not found: {0}")]
    ContainerNotFound(String),
    #[error("command is required to run container")]
    MissingCommand,
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

        let mut child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut join_handles = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            let out_path = stdout_path.clone();
            join_handles.push(thread::spawn(move || stream_to_file(stdout, &out_path)));
        }
        if let Some(stderr) = child.stderr.take() {
            let err_path = stderr_path.clone();
            join_handles.push(thread::spawn(move || stream_to_file(stderr, &err_path)));
        }

        let child_id = child.id();
        let store_clone = self.store.clone_db();
        let container_id_clone = container_id.clone();
        thread::spawn(move || {
            let _ = child.wait();
            for handle in join_handles {
                let _ = handle.join();
            }
            let _ = update_status(&store_clone, &container_id_clone, "exited");
        });

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
}

fn generate_container_id() -> String {
    format!("c{}-{}", now_unix(), std::process::id())
}

fn stream_to_file<R: std::io::Read>(mut reader: R, path: &Path) -> Result<(), std::io::Error> {
    let mut file = fs::File::create(path)?;
    std::io::copy(&mut reader, &mut file)?;
    Ok(())
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
}
