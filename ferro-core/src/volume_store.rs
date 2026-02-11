use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const VOLUME_INDEX_TREE: &str = "volume_index";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeRecord {
    pub name: String,
    pub path: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Error)]
pub enum VolumeStoreError {
    #[error("failed to open volume store: {0}")]
    Open(#[from] sled::Error),
    #[error("failed to encode volume record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode volume record: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("volume already exists: {0}")]
    Exists(String),
}

pub struct LocalVolumeStore {
    db: sled::Db,
    root: PathBuf,
}

impl LocalVolumeStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, VolumeStoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let db = sled::open(root.join("volumes.db"))?;
        Ok(Self { db, root })
    }

    pub fn create(&self, name: &str) -> Result<VolumeRecord, VolumeStoreError> {
        let tree = self.db.open_tree(VOLUME_INDEX_TREE)?;
        if tree.get(name.as_bytes())?.is_some() {
            return Err(VolumeStoreError::Exists(name.to_string()));
        }
        let volume_dir = self.root.join(name);
        fs::create_dir_all(&volume_dir)?;
        let record = VolumeRecord {
            name: name.to_string(),
            path: volume_dir.display().to_string(),
            created_at_unix: now_unix(),
        };
        let encoded = serde_json::to_vec(&record)?;
        tree.insert(name.as_bytes(), encoded)?;
        tree.flush()?;
        Ok(record)
    }

    pub fn list(&self) -> Result<Vec<VolumeRecord>, VolumeStoreError> {
        let tree = self.db.open_tree(VOLUME_INDEX_TREE)?;
        let mut out = Vec::new();
        for entry in &tree {
            let (_, value) = entry?;
            let record = serde_json::from_slice::<VolumeRecord>(&value)
                .map_err(VolumeStoreError::Decode)?;
            out.push(record);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn remove(&self, name: &str) -> Result<bool, VolumeStoreError> {
        let tree = self.db.open_tree(VOLUME_INDEX_TREE)?;
        let removed = tree.remove(name.as_bytes())?.is_some();
        if removed {
            let volume_dir = self.root.join(name);
            if volume_dir.exists() {
                fs::remove_dir_all(volume_dir)?;
            }
        }
        tree.flush()?;
        Ok(removed)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::LocalVolumeStore;

    #[test]
    fn creates_lists_and_removes_volumes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalVolumeStore::open(temp.path()).expect("store");

        let record = store.create("data").expect("create");
        assert_eq!(record.name, "data");

        let listed = store.list().expect("list");
        assert_eq!(listed.len(), 1);

        let removed = store.remove("data").expect("remove");
        assert!(removed);
        let listed = store.list().expect("list");
        assert!(listed.is_empty());
    }
}
