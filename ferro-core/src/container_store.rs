use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const CONTAINER_INDEX_TREE: &str = "container_index";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerRecord {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub pid: u32,
    pub image: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub health: Option<HealthConfig>,
    #[serde(default = "default_health_status")]
    pub health_status: String,
    #[serde(default)]
    pub health_failures: u32,
    #[serde(default)]
    pub health_checked_at_unix: Option<u64>,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    #[serde(default)]
    pub last_exit_code: Option<i32>,
    pub created_at_unix: u64,
    pub stdout_path: String,
    pub stderr_path: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    No,
    OnFailure,
    Always,
    UnlessStopped,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy::No
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthConfig {
    pub cmd: Vec<String>,
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub retries: u32,
    pub start_period_secs: u64,
}

#[derive(Debug, Error)]
pub enum ContainerStoreError {
    #[error("failed to open container store: {0}")]
    Open(#[from] sled::Error),
    #[error("failed to encode container record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode container record: {0}")]
    Decode(#[source] serde_json::Error),
}

pub struct LocalContainerStore {
    db: sled::Db,
}

impl LocalContainerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ContainerStoreError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn put(&self, record: &ContainerRecord) -> Result<(), ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let encoded = serde_json::to_vec(record)?;
        tree.insert(record.id.as_bytes(), encoded)?;
        tree.flush()?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<ContainerRecord>, ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let maybe = tree.get(id.as_bytes())?;
        maybe
            .map(|bytes| {
                serde_json::from_slice::<ContainerRecord>(&bytes)
                    .map_err(ContainerStoreError::Decode)
            })
            .transpose()
    }

    pub fn remove(&self, id: &str) -> Result<bool, ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let removed = tree.remove(id.as_bytes())?.is_some();
        tree.flush()?;
        Ok(removed)
    }

    pub fn list(&self) -> Result<Vec<ContainerRecord>, ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let mut out = Vec::new();
        for entry in &tree {
            let (_, value) = entry?;
            let record = serde_json::from_slice::<ContainerRecord>(&value)
                .map_err(ContainerStoreError::Decode)?;
            out.push(record);
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    pub fn update_status(&self, id: &str, status: &str) -> Result<(), ContainerStoreError> {
        if let Some(mut record) = self.get(id)? {
            record.status = status.to_string();
            self.put(&record)?;
        }
        Ok(())
    }

    pub fn clone_db(&self) -> sled::Db {
        self.db.clone()
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_health_status() -> String {
    "none".to_string()
}

#[cfg(test)]
mod tests {
    use super::{ContainerRecord, LocalContainerStore, RestartPolicy, now_unix};
    use std::collections::HashMap;

    #[test]
    fn stores_and_lists_containers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalContainerStore::open(temp.path()).expect("open store");

        let record = ContainerRecord {
            id: "c1".to_string(),
            name: Some("demo".to_string()),
            pid: 1234,
            image: "alpine:latest".to_string(),
            command: vec!["echo".to_string(), "hi".to_string()],
            workdir: Some("/app".to_string()),
            user: Some("1000:1000".to_string()),
            env: vec!["HELLO=world".to_string()],
            labels: [("tier".to_string(), "test".to_string())].into_iter().collect(),
            annotations: [("owner".to_string(), "cli".to_string())].into_iter().collect(),
            capabilities: vec!["CAP_NET_BIND_SERVICE".to_string()],
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
        };

        store.put(&record).expect("store record");
        let listed = store.list().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, "c1");
    }

    #[test]
    fn removes_containers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalContainerStore::open(temp.path()).expect("open store");

        let record = ContainerRecord {
            id: "c1".to_string(),
            name: None,
            pid: 1234,
            image: "alpine:latest".to_string(),
            command: vec!["echo".to_string(), "hi".to_string()],
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
        };

        store.put(&record).expect("store record");
        let removed = store.remove("c1").expect("remove");
        assert!(removed);
        let listed = store.list().expect("list");
        assert!(listed.is_empty());
    }
}
