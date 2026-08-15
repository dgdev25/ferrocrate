use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tar::{Archive, Builder};
use thiserror::Error;

const VOLUME_INDEX_TREE: &str = "volume_index";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeRecord {
    pub name: String,
    pub path: String,
    #[serde(default = "default_driver")]
    pub driver: String,
    #[serde(default)]
    pub driver_opts: BTreeMap<String, String>,
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
    #[error("unknown volume driver: {0}")]
    UnknownDriver(String),
    #[error("volume not found: {0}")]
    NotFound(String),
    #[error("volume authorization binding failed: {0}")]
    Authorization(String),
}

pub trait VolumeDriver: Send + Sync {
    fn name(&self) -> &str;
    fn create(
        &self,
        root: &Path,
        name: &str,
        options: &BTreeMap<String, String>,
    ) -> Result<String, VolumeStoreError>;
    fn remove(&self, root: &Path, record: &VolumeRecord) -> Result<(), VolumeStoreError>;
}

#[derive(Default)]
struct LocalVolumeDriver;

impl VolumeDriver for LocalVolumeDriver {
    fn name(&self) -> &str {
        "local"
    }

    fn create(
        &self,
        root: &Path,
        name: &str,
        _options: &BTreeMap<String, String>,
    ) -> Result<String, VolumeStoreError> {
        let volume_dir = root.join(name);
        fs::create_dir_all(&volume_dir)?;
        Ok(volume_dir.display().to_string())
    }

    fn remove(&self, root: &Path, record: &VolumeRecord) -> Result<(), VolumeStoreError> {
        let volume_dir = root.join(&record.name);
        if volume_dir.exists() {
            fs::remove_dir_all(volume_dir)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct VolumeDriverRegistry {
    drivers: HashMap<String, Arc<dyn VolumeDriver>>,
}

impl VolumeDriverRegistry {
    fn new() -> Self {
        let mut registry = Self::default();
        registry.register(LocalVolumeDriver);
        registry
    }

    fn register<D: VolumeDriver + 'static>(&mut self, driver: D) {
        self.drivers
            .insert(driver.name().to_string(), Arc::new(driver));
    }

    fn get(&self, name: &str) -> Option<Arc<dyn VolumeDriver>> {
        self.drivers.get(name).cloned()
    }
}

pub struct LocalVolumeStore {
    db: sled::Db,
    root: PathBuf,
    drivers: VolumeDriverRegistry,
}

impl LocalVolumeStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, VolumeStoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let db = sled::open(root.join("volumes.db"))?;
        Ok(Self {
            db,
            root,
            drivers: VolumeDriverRegistry::new(),
        })
    }

    pub fn create(&self, name: &str) -> Result<VolumeRecord, VolumeStoreError> {
        self.create_with_driver(name, "local", BTreeMap::new())
    }

    pub(crate) fn create_with_driver(
        &self,
        name: &str,
        driver: &str,
        driver_opts: BTreeMap<String, String>,
    ) -> Result<VolumeRecord, VolumeStoreError> {
        let tree = self.db.open_tree(VOLUME_INDEX_TREE)?;
        if tree.get(name.as_bytes())?.is_some() {
            return Err(VolumeStoreError::Exists(name.to_string()));
        }
        let driver_impl = self
            .drivers
            .get(driver)
            .ok_or_else(|| VolumeStoreError::UnknownDriver(driver.to_string()))?;
        let path = driver_impl.create(&self.root, name, &driver_opts)?;
        let record = VolumeRecord {
            name: name.to_string(),
            path,
            driver: driver.to_string(),
            driver_opts,
            created_at_unix: now_unix(),
        };
        let encoded = serde_json::to_vec(&record)?;
        tree.insert(name.as_bytes(), encoded)?;
        tree.flush()?;
        Ok(record)
    }

    pub fn create_with_driver_authorized(
        &self,
        name: &str,
        driver: &str,
        driver_opts: BTreeMap<String, String>,
        permit: crate::authorization::surface::SurfacePermit,
    ) -> Result<VolumeRecord, VolumeStoreError> {
        crate::authorization::surface::SurfaceAuthorization::validate_execution(
            &permit,
            crate::authorization::Action::VolumeCreate,
            crate::authorization::ResourceKind::Volume,
            name,
            1,
        )
        .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
        match self.create_with_driver(name, driver, driver_opts) {
            Ok(record) => {
                permit
                    .finish(true)
                    .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
                Ok(record)
            }
            Err(error) => {
                permit
                    .finish(false)
                    .map_err(|finish| VolumeStoreError::Authorization(finish.to_string()))?;
                Err(error)
            }
        }
    }

    pub fn list(&self) -> Result<Vec<VolumeRecord>, VolumeStoreError> {
        let tree = self.db.open_tree(VOLUME_INDEX_TREE)?;
        let mut out = Vec::new();
        for entry in &tree {
            let (_, value) = entry?;
            let record =
                serde_json::from_slice::<VolumeRecord>(&value).map_err(VolumeStoreError::Decode)?;
            out.push(record);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    pub fn get(&self, name: &str) -> Result<Option<VolumeRecord>, VolumeStoreError> {
        let tree = self.db.open_tree(VOLUME_INDEX_TREE)?;
        let Some(value) = tree.get(name.as_bytes())? else {
            return Ok(None);
        };
        let record =
            serde_json::from_slice::<VolumeRecord>(&value).map_err(VolumeStoreError::Decode)?;
        Ok(Some(record))
    }

    pub(crate) fn remove(&self, name: &str) -> Result<bool, VolumeStoreError> {
        let tree = self.db.open_tree(VOLUME_INDEX_TREE)?;
        let Some(value) = tree.get(name.as_bytes())? else {
            return Ok(false);
        };
        let record =
            serde_json::from_slice::<VolumeRecord>(&value).map_err(VolumeStoreError::Decode)?;
        if let Some(driver) = self.drivers.get(&record.driver) {
            driver.remove(&self.root, &record)?;
        } else {
            let volume_dir = self.root.join(name);
            if volume_dir.exists() {
                fs::remove_dir_all(volume_dir)?;
            }
        }
        tree.remove(name.as_bytes())?;
        tree.flush()?;
        Ok(true)
    }

    pub fn remove_authorized(
        &self,
        name: &str,
        permit: crate::authorization::surface::SurfacePermit,
    ) -> Result<bool, VolumeStoreError> {
        crate::authorization::surface::SurfaceAuthorization::validate_execution(
            &permit,
            crate::authorization::Action::VolumeDelete,
            crate::authorization::ResourceKind::Volume,
            name,
            1,
        )
        .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
        match self.remove(name) {
            Ok(removed) => {
                permit
                    .finish(true)
                    .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
                Ok(removed)
            }
            Err(error) => {
                permit
                    .finish(false)
                    .map_err(|finish| VolumeStoreError::Authorization(finish.to_string()))?;
                Err(error)
            }
        }
    }

    pub fn backup(&self, name: &str, dest: impl AsRef<Path>) -> Result<(), VolumeStoreError> {
        let record = self
            .get(name)?
            .ok_or_else(|| VolumeStoreError::NotFound(name.to_string()))?;
        let volume_dir = PathBuf::from(&record.path);
        if !volume_dir.exists() {
            return Err(VolumeStoreError::NotFound(name.to_string()));
        }
        let file = fs::File::create(dest)?;
        let mut builder = Builder::new(file);
        builder.append_dir_all(".", &volume_dir)?;
        builder.finish()?;
        Ok(())
    }

    pub(crate) fn restore(
        &self,
        name: &str,
        src: impl AsRef<Path>,
    ) -> Result<(), VolumeStoreError> {
        let record = self
            .get(name)?
            .ok_or_else(|| VolumeStoreError::NotFound(name.to_string()))?;
        let volume_dir = PathBuf::from(&record.path);
        fs::create_dir_all(&volume_dir)?;
        let file = fs::File::open(src)?;
        let mut archive = Archive::new(file);
        archive.unpack(&volume_dir)?;
        Ok(())
    }

    pub fn restore_authorized(
        &self,
        name: &str,
        src: impl AsRef<Path>,
        permit: crate::authorization::surface::SurfacePermit,
    ) -> Result<(), VolumeStoreError> {
        crate::authorization::surface::SurfaceAuthorization::validate_execution(
            &permit,
            crate::authorization::Action::VolumeCreate,
            crate::authorization::ResourceKind::Volume,
            name,
            1,
        )
        .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
        match self.restore(name, src) {
            Ok(()) => {
                permit
                    .finish(true)
                    .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
                Ok(())
            }
            Err(error) => {
                permit
                    .finish_unknown()
                    .map_err(|finish| VolumeStoreError::Authorization(finish.to_string()))?;
                Err(error)
            }
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_driver() -> String {
    "local".to_string()
}

#[cfg(test)]
mod tests {
    use super::{LocalVolumeStore, VolumeStoreError};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn creates_lists_and_removes_volumes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalVolumeStore::open(temp.path()).expect("store");

        let record = store.create("data").expect("create");
        assert_eq!(record.name, "data");
        assert_eq!(record.driver, "local");

        let listed = store.list().expect("list");
        assert_eq!(listed.len(), 1);

        let removed = store.remove("data").expect("remove");
        assert!(removed);
        let listed = store.list().expect("list");
        assert!(listed.is_empty());
    }

    #[test]
    fn rejects_unknown_volume_driver() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalVolumeStore::open(temp.path()).expect("store");
        let err = store
            .create_with_driver("data", "unknown", BTreeMap::new())
            .expect_err("unknown driver");
        assert!(matches!(err, VolumeStoreError::UnknownDriver(_)));
    }

    #[test]
    fn backup_and_restore_volume() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalVolumeStore::open(temp.path()).expect("store");

        let record = store.create("data").expect("create");
        let volume_dir = PathBuf::from(&record.path);
        std::fs::write(volume_dir.join("hello.txt"), "hi").expect("write");

        let archive = temp.path().join("backup.tar");
        store.backup("data", &archive).expect("backup");

        store.remove("data").expect("remove");
        store.create("data").expect("recreate");
        store.restore("data", &archive).expect("restore");

        let restored = std::fs::read_to_string(
            PathBuf::from(&store.get("data").unwrap().unwrap().path).join("hello.txt"),
        )
        .expect("read");
        assert_eq!(restored, "hi");
    }
}
