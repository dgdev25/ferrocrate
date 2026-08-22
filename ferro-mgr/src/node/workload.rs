//! Declarative, versioned desired workload specification.
//!
//! A workload names the services that should run on the node, how many
//! instances of each, and the update and health policies that govern
//! convergence. The store persists one snapshot per save and rejects
//! revisions that do not strictly increase, mirroring the desired-state
//! monotonicity enforced for overlays in [`crate::agent::reconcile`].

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_WORKLOAD_BYTES: usize = 256 * 1024;

/// Rolling-update policy for one service.
///
/// `revision_floor` is the minimum number of healthy instances that must be
/// available at every moment of an update; `health_attempts` bounds how many
/// probes a newly started instance gets before the update aborts and rolls
/// back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePolicy {
    pub max_surge: usize,
    pub max_unavailable: usize,
    pub revision_floor: usize,
    pub health_attempts: u32,
}

/// Consecutive-failure threshold before a running instance is restarted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthPolicy {
    pub retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub name: String,
    pub image: String,
    pub instances: u32,
    pub cpu_millis_per_instance: u64,
    pub memory_bytes_per_instance: u64,
    pub port: u16,
    pub update: UpdatePolicy,
    pub health: HealthPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredWorkload {
    pub revision: u64,
    pub services: Vec<ServiceSpec>,
}

#[derive(Debug, Error)]
pub enum WorkloadError {
    #[error("workload file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("workload file is invalid")]
    Invalid,
    #[error("service `{service}` is invalid: {reason}")]
    InvalidService { service: String, reason: String },
    #[error("workload revision {0} is not newer than the stored revision {1}")]
    StaleRevision(u64, u64),
}

impl DesiredWorkload {
    /// Validate the whole specification.
    pub fn validate(&self) -> Result<(), WorkloadError> {
        if self.services.is_empty() {
            return Err(WorkloadError::Invalid);
        }
        let mut names: Vec<&str> = self.services.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WorkloadError::Invalid);
        }
        for service in &self.services {
            service.validate()?;
        }
        Ok(())
    }

    /// Deterministic instance ID for a service at a revision.
    pub fn instance_id(service: &str, revision: u64, index: u32) -> String {
        format!("{service}-r{revision}-{index}")
    }
}

impl ServiceSpec {
    fn validate(&self) -> Result<(), WorkloadError> {
        let invalid = |reason: &str| WorkloadError::InvalidService {
            service: self.name.clone(),
            reason: reason.into(),
        };
        if self.name.trim().is_empty() {
            return Err(invalid("name must not be empty"));
        }
        if self.image.trim().is_empty() {
            return Err(invalid("image must not be empty"));
        }
        if self.instances == 0 {
            return Err(invalid("instances must be at least one"));
        }
        if self.cpu_millis_per_instance == 0 || self.memory_bytes_per_instance == 0 {
            return Err(invalid("per-instance resources must be non-zero"));
        }
        let instances = self.instances as usize;
        if self.update.revision_floor > instances {
            return Err(invalid("revision_floor must not exceed the instance count"));
        }
        if self.update.max_surge == 0 || self.update.max_unavailable == 0 {
            return Err(invalid("max_surge and max_unavailable must be non-zero"));
        }
        if self.update.health_attempts == 0 {
            return Err(invalid("health_attempts must be non-zero"));
        }
        if self.health.retries == 0 {
            return Err(invalid("health retries must be non-zero"));
        }
        Ok(())
    }

    /// Desired instance IDs for this service at the given revision.
    pub fn instance_ids(&self, revision: u64) -> Vec<String> {
        (0..self.instances)
            .map(|index| DesiredWorkload::instance_id(&self.name, revision, index))
            .collect()
    }
}

/// Atomic, monotonic-revision store for desired workloads.
pub struct WorkloadStore {
    path: PathBuf,
}

impl WorkloadStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<Option<DesiredWorkload>, WorkloadError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_WORKLOAD_BYTES as u64
        {
            return Err(WorkloadError::Invalid);
        }
        let workload: DesiredWorkload =
            serde_json::from_slice(&fs::read(&self.path)?).map_err(|_| WorkloadError::Invalid)?;
        workload.validate().map_err(|_| WorkloadError::Invalid)?;
        Ok(Some(workload))
    }

    /// Persist a workload. The revision must strictly increase.
    pub fn save(&self, workload: &DesiredWorkload) -> Result<(), WorkloadError> {
        workload.validate()?;
        if let Some(current) = self.load()? {
            if workload.revision <= current.revision {
                return Err(WorkloadError::StaleRevision(
                    workload.revision,
                    current.revision,
                ));
            }
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec(workload).map_err(|_| WorkloadError::Invalid)?;
        let temporary = self.path.with_extension("tmp");
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn service(name: &str, instances: u32) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            image: "registry.local/demo:1".into(),
            instances,
            cpu_millis_per_instance: 500,
            memory_bytes_per_instance: 64 * 1024 * 1024,
            port: 8080,
            update: UpdatePolicy {
                max_surge: 1,
                max_unavailable: 1,
                revision_floor: instances as usize,
                health_attempts: 3,
            },
            health: HealthPolicy { retries: 2 },
        }
    }

    pub(crate) fn workload(revision: u64, services: Vec<ServiceSpec>) -> DesiredWorkload {
        DesiredWorkload { revision, services }
    }

    #[test]
    fn store_round_trips_and_enforces_monotonic_revisions() {
        let directory = tempfile::tempdir().unwrap();
        let store = WorkloadStore::new(directory.path().join("workload.json"));
        assert_eq!(store.load().unwrap(), None);

        store.save(&workload(3, vec![service("web", 2)])).unwrap();
        assert_eq!(store.load().unwrap().map(|w| w.revision), Some(3));

        match store.save(&workload(3, vec![service("web", 2)])) {
            Err(WorkloadError::StaleRevision(3, 3)) => {}
            other => panic!("expected stale revision 3/3, got {other:?}"),
        }
        match store.save(&workload(2, vec![service("web", 2)])) {
            Err(WorkloadError::StaleRevision(2, 3)) => {}
            other => panic!("expected stale revision 2/3, got {other:?}"),
        }
        store.save(&workload(4, vec![service("web", 3)])).unwrap();
        assert_eq!(store.load().unwrap().map(|w| w.revision), Some(4));
    }

    #[test]
    fn invalid_specifications_are_rejected() {
        let mut floor_too_high = service("web", 2);
        floor_too_high.update.revision_floor = 3;
        assert!(workload(1, vec![floor_too_high]).validate().is_err());

        let zero_instances = service("web", 0);
        assert!(workload(1, vec![zero_instances]).validate().is_err());

        let duplicate = workload(1, vec![service("web", 1), service("web", 2)]);
        assert!(matches!(duplicate.validate(), Err(WorkloadError::Invalid)));

        let mut zero_surge = service("web", 1);
        zero_surge.update.max_surge = 0;
        assert!(workload(1, vec![zero_surge]).validate().is_err());
    }

    #[test]
    fn instance_ids_are_deterministic() {
        assert_eq!(
            DesiredWorkload::instance_id("web", 7, 1),
            "web-r7-1".to_string()
        );
        let spec = service("api", 3);
        assert_eq!(
            spec.instance_ids(9),
            vec!["api-r9-0", "api-r9-1", "api-r9-2"]
        );
    }
}
