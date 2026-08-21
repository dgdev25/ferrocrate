use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tar::{Archive, Builder};
use thiserror::Error;

const VOLUME_SQLITE_FILE: &str = "volumes.sqlite";

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
    Open(#[from] rusqlite::Error),
    #[error("failed to lock volume store: {0}")]
    Lock(String),
    #[error("legacy Sled volume store detected; the Sled importer was removed. See docs/architecture/legacy-sled-importers.md")]
    LegacyMigrationRequired,
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
    #[error("invalid volume name: {0}")]
    InvalidName(String),
}

/// Immutable preparation result for a single volume creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeCreatePlan {
    name: String,
    driver: String,
    driver_opts: BTreeMap<String, String>,
    generation: u64,
    plan_digest: [u8; 32],
}

impl VolumeCreatePlan {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn driver(&self) -> &str {
        &self.driver
    }
    pub fn driver_options(&self) -> &BTreeMap<String, String> {
        &self.driver_opts
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }
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
    db: Mutex<Connection>,
    root: PathBuf,
    drivers: VolumeDriverRegistry,
}

fn volume_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<VolumeRecord> {
    let options: String = row.get(3)?;
    let driver_opts = serde_json::from_str(&options).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(error))
    })?;
    let created_at_unix: i64 = row.get(4)?;
    Ok(VolumeRecord {
        name: row.get(0)?,
        path: row.get(1)?,
        driver: row.get(2)?,
        driver_opts,
        created_at_unix: created_at_unix.max(0) as u64,
    })
}

impl LocalVolumeStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, VolumeStoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let db_path = root.join(VOLUME_SQLITE_FILE);
        if !db_path.exists() && root.join("conf").exists() {
            return Err(VolumeStoreError::LegacyMigrationRequired);
        }
        let connection = Connection::open(&db_path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS volumes (
                name TEXT PRIMARY KEY NOT NULL,
                path TEXT NOT NULL,
                driver TEXT NOT NULL,
                driver_opts TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL
            )",
        )?;
        Ok(Self {
            db: Mutex::new(connection),
            root,
            drivers: VolumeDriverRegistry::new(),
        })
    }

    #[allow(dead_code)]
    fn create(&self, name: &str) -> Result<VolumeRecord, VolumeStoreError> {
        self.create_with_driver(name, "local", BTreeMap::new())
    }

    pub fn prepare_create(
        &self,
        name: &str,
        driver: &str,
        driver_opts: BTreeMap<String, String>,
    ) -> Result<VolumeCreatePlan, VolumeStoreError> {
        validate_volume_name(name)?;
        if self.get(name)?.is_some() {
            return Err(VolumeStoreError::Exists(name.to_string()));
        }
        if self.drivers.get(driver).is_none() {
            return Err(VolumeStoreError::UnknownDriver(driver.to_string()));
        }
        let generation = 1_u64;
        let mut hash = Sha256::new();
        hash.update(b"ferrocrate/volume-create-plan/v1");
        for value in [name, driver] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        hash.update(generation.to_be_bytes());
        hash.update((driver_opts.len() as u64).to_be_bytes());
        for (key, value) in &driver_opts {
            for item in [key.as_str(), value.as_str()] {
                hash.update((item.len() as u64).to_be_bytes());
                hash.update(item.as_bytes());
            }
        }
        Ok(VolumeCreatePlan {
            name: name.to_string(),
            driver: driver.to_string(),
            driver_opts,
            generation,
            plan_digest: hash.finalize().into(),
        })
    }

    fn create_with_driver(
        &self,
        name: &str,
        driver: &str,
        driver_opts: BTreeMap<String, String>,
    ) -> Result<VolumeRecord, VolumeStoreError> {
        validate_volume_name(name)?;
        let db = self
            .db
            .lock()
            .map_err(|error| VolumeStoreError::Lock(error.to_string()))?;
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM volumes WHERE name = ?1)",
            params![name],
            |row| row.get(0),
        )?;
        if exists {
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
        let driver_opts = serde_json::to_string(&record.driver_opts)?;
        db.execute(
            "INSERT INTO volumes (name, path, driver, driver_opts, created_at_unix)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.name,
                record.path,
                record.driver,
                driver_opts,
                record.created_at_unix as i64
            ],
        )?;
        Ok(record)
    }

    pub fn create_with_driver_authorized(
        &self,
        plan: VolumeCreatePlan,
        permit: crate::authorization::surface::SurfacePermit,
    ) -> Result<VolumeRecord, VolumeStoreError> {
        crate::authorization::surface::SurfaceAuthorization::validate_execution(
            &permit,
            crate::authorization::Action::VolumeCreate,
            crate::authorization::ResourceKind::Volume,
            plan.name(),
            plan.generation(),
        )
        .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
        if permit.proof().canonical().operation_plan_digest() != Some(&plan.plan_digest()) {
            permit
                .finish(false)
                .map_err(|error| VolumeStoreError::Authorization(error.to_string()))?;
            return Err(VolumeStoreError::Authorization(
                "volume creation plan does not match authorization proof".to_string(),
            ));
        }
        match self.create_with_driver(&plan.name, &plan.driver, plan.driver_opts) {
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
        let db = self
            .db
            .lock()
            .map_err(|error| VolumeStoreError::Lock(error.to_string()))?;
        let mut statement = db.prepare(
            "SELECT name, path, driver, driver_opts, created_at_unix
             FROM volumes ORDER BY name",
        )?;
        let mut out = Vec::new();
        let rows = statement.query_map([], volume_record_from_row)?;
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get(&self, name: &str) -> Result<Option<VolumeRecord>, VolumeStoreError> {
        let db = self
            .db
            .lock()
            .map_err(|error| VolumeStoreError::Lock(error.to_string()))?;
        match db.query_row(
            "SELECT name, path, driver, driver_opts, created_at_unix
             FROM volumes WHERE name = ?1",
            params![name],
            volume_record_from_row,
        ) {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn remove(&self, name: &str) -> Result<bool, VolumeStoreError> {
        let Some(record) = self.get(name)? else {
            return Ok(false);
        };
        if let Some(driver) = self.drivers.get(&record.driver) {
            driver.remove(&self.root, &record)?;
        } else {
            let volume_dir = self.root.join(name);
            if volume_dir.exists() {
                fs::remove_dir_all(volume_dir)?;
            }
        }
        let db = self
            .db
            .lock()
            .map_err(|error| VolumeStoreError::Lock(error.to_string()))?;
        db.execute("DELETE FROM volumes WHERE name = ?1", params![name])?;
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

    fn restore(&self, name: &str, src: impl AsRef<Path>) -> Result<(), VolumeStoreError> {
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

fn validate_volume_name(name: &str) -> Result<(), VolumeStoreError> {
    let valid = !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(VolumeStoreError::InvalidName(name.to_string()))
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
    fn preparing_volume_create_is_side_effect_free_and_binds_options() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalVolumeStore::open(temp.path()).expect("store");
        let mut first = BTreeMap::new();
        first.insert("type".to_string(), "tmpfs".to_string());
        let mut second = first.clone();
        second.insert("size".to_string(), "64m".to_string());

        let plan = store.prepare_create("data", "local", first).expect("plan");
        let changed = store.prepare_create("data", "local", second).expect("plan");

        assert_eq!(plan.name(), "data");
        assert_eq!(plan.driver(), "local");
        assert_eq!(plan.generation(), 1);
        assert_ne!(plan.plan_digest(), changed.plan_digest());
        assert!(store.get("data").unwrap().is_none());
        assert!(!temp.path().join("data").exists());
    }

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

    #[test]
    fn default_open_rejects_legacy_volume_directory() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("conf")).unwrap();
        let error = match LocalVolumeStore::open(temp.path()) {
            Ok(_) => panic!("legacy boundary"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("legacy-sled-importers"));
    }
}
