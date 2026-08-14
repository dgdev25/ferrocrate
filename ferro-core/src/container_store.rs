use crate::ai_runtime::AiRuntimeConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub const CONTAINER_INDEX_TREE: &str = "container_index";

/// Immutable authority used to prove that deletion-only cleanup still targets
/// the resource created by the witnessed operation. Legacy records deserialize
/// to an unverifiable value and must be quarantined instead of cleaned up.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreationProvenance {
    #[serde(default)]
    pub runtime_instance_id: Option<[u8; 16]>,
    #[serde(default)]
    pub boot_id: Option<[u8; 16]>,
    #[serde(default)]
    pub journal_id: Option<[u8; 16]>,
    #[serde(default)]
    pub resource_uuid: Option<String>,
    #[serde(default)]
    pub resource_generation: u64,
    #[serde(default)]
    pub creator_operation_id: Option<[u8; 16]>,
    #[serde(default)]
    pub image_digest: Option<String>,
}

impl CreationProvenance {
    pub fn is_verifiable(&self) -> bool {
        self.runtime_instance_id.is_some()
            && self.boot_id.is_some()
            && self.journal_id.is_some()
            && self.resource_uuid.as_deref().is_some_and(is_uuid)
            && self.resource_generation > 0
            && self.creator_operation_id.is_some()
    }
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

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
    #[serde(default)]
    pub netns: Option<String>,
    #[serde(default)]
    pub network_name: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub ipv6_address: Option<String>,
    #[serde(default)]
    pub ports: Vec<PortMappingRecord>,
    #[serde(default)]
    pub network_backend: Option<String>,
    #[serde(default)]
    pub network_ownership: Option<NetworkOwnershipRecord>,
    #[serde(default)]
    pub managed_overlay: Option<String>,
    #[serde(default)]
    pub managed_host_veth: Option<String>,
    #[serde(default)]
    pub ai_runtime: Option<AiRuntimeConfig>,
    #[serde(default)]
    pub creation_provenance: CreationProvenance,
    #[serde(default = "default_mutation_generation")]
    pub mutation_generation: u64,
    #[serde(default)]
    pub pending_mutation: Option<MutationReservation>,
}

fn default_mutation_generation() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationReservation {
    pub operation_id: [u8; 16],
    pub generation: u64,
    pub expected_status: String,
}

impl ContainerRecord {
    pub(crate) fn authorization_candidate(id: String, image: String) -> Self {
        Self {
            id,
            name: None,
            pid: 0,
            image,
            command: Vec::new(),
            workdir: None,
            user: None,
            env: Vec::new(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            capabilities: Vec::new(),
            health: None,
            health_status: "none".into(),
            health_failures: 0,
            health_checked_at_unix: None,
            restart_policy: RestartPolicy::No,
            last_exit_code: None,
            created_at_unix: 0,
            stdout_path: String::new(),
            stderr_path: String::new(),
            status: "created".into(),
            netns: None,
            network_name: None,
            ip_address: None,
            ipv6_address: None,
            ports: Vec::new(),
            network_backend: None,
            network_ownership: None,
            managed_overlay: None,
            managed_host_veth: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkOwnershipRecord {
    #[serde(default)]
    pub schema_version: u32,
    pub owner_id: String,
    #[serde(default)]
    pub network_id: Option<String>,
    pub host_interface: String,
    #[serde(default)]
    pub host_ifindex: Option<u32>,
    #[serde(default)]
    pub namespace_identity: Option<KernelObjectIdentityRecord>,
    #[serde(default)]
    pub managed_interface: Option<String>,
    #[serde(default)]
    pub managed_ifindex: Option<u32>,
    #[serde(default)]
    pub loopback_ifindex: Option<u32>,
    #[serde(default)]
    pub bridge_ifindex: Option<u32>,
    #[serde(default)]
    pub source_cidr: Option<String>,
    #[serde(default)]
    pub bridge: Option<String>,
    #[serde(default)]
    pub firewall_id: Option<String>,
    #[serde(default)]
    pub firewall_marker: Option<String>,
    #[serde(default)]
    pub firewall_expected_state: Option<String>,
    #[serde(default)]
    pub ebpf_pin_path: Option<String>,
    #[serde(default)]
    pub external_ipv4: Option<String>,
    #[serde(default)]
    pub next_hop_mac: Option<String>,
    #[serde(default)]
    pub snat_port_start: Option<u16>,
    #[serde(default)]
    pub snat_port_end: Option<u16>,
    #[serde(default)]
    pub object_sha256: Option<String>,
    #[serde(default)]
    pub object_abi: Option<u32>,
    #[serde(default)]
    pub ebpf_filters: Vec<EbpfFilterOwnershipRecord>,
    #[serde(default)]
    pub ebpf_pins: Vec<EbpfPinOwnershipRecord>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelObjectIdentityRecord {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfFilterOwnershipRecord {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub interface_ifindex: Option<u32>,
    pub direction: String,
    pub priority: u32,
    pub handle: String,
    #[serde(default)]
    pub program_id: Option<u32>,
    #[serde(default)]
    pub program_tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EbpfPinOwnershipRecord {
    pub relative_path: String,
    pub device: u64,
    pub inode: u64,
    pub directory: bool,
    #[serde(default)]
    pub map_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortMappingRecord {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum RestartPolicy {
    #[default]
    No,
    OnFailure,
    Always,
    UnlessStopped,
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
    #[error("container mutation compare-and-swap failed")]
    MutationConflict,
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

    /// Default page size for list operations
    const DEFAULT_PAGE_SIZE: usize = 100;

    /// List all containers with a default page size limit.
    /// For large deployments, use list_paginated() instead.
    pub fn list(&self) -> Result<Vec<ContainerRecord>, ContainerStoreError> {
        self.list_paginated(None, None)
    }

    /// List containers with pagination support.
    ///
    /// # Arguments
    /// * `offset` - Number of containers to skip (default: 0)
    /// * `limit` - Maximum number of containers to return (default: 100)
    ///
    /// # Security
    /// Always applies a maximum limit to prevent OOM attacks from listing
    /// millions of containers.
    pub fn list_paginated(
        &self,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<Vec<ContainerRecord>, ContainerStoreError> {
        let offset = offset.unwrap_or(0);
        // Enforce maximum limit to prevent OOM
        let limit = limit.unwrap_or(Self::DEFAULT_PAGE_SIZE).min(1000);
        let effective_limit = offset + limit;

        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let mut out = Vec::with_capacity(limit);
        let mut count = 0;

        for entry in &tree {
            if count >= effective_limit {
                break;
            }
            count += 1;
            if count <= offset {
                continue;
            }
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

    pub(crate) fn reserve_mutation(
        &self,
        id: &str,
        expected_status: &str,
        expected_generation: u64,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        tree.transaction(|tree| {
            let bytes = tree.get(id.as_bytes())?.ok_or_else(|| {
                sled::transaction::ConflictableTransactionError::Abort(
                    ContainerStoreError::MutationConflict,
                )
            })?;
            let mut record: ContainerRecord = serde_json::from_slice(&bytes).map_err(|error| {
                sled::transaction::ConflictableTransactionError::Abort(ContainerStoreError::Decode(
                    error,
                ))
            })?;
            if record.status != expected_status
                || record.mutation_generation != expected_generation
                || record.pending_mutation.is_some()
            {
                return Err(sled::transaction::ConflictableTransactionError::Abort(
                    ContainerStoreError::MutationConflict,
                ));
            }
            record.pending_mutation = Some(MutationReservation {
                operation_id,
                generation: expected_generation,
                expected_status: expected_status.to_owned(),
            });
            let encoded = serde_json::to_vec(&record).map_err(|error| {
                sled::transaction::ConflictableTransactionError::Abort(ContainerStoreError::Encode(
                    error,
                ))
            })?;
            tree.insert(id.as_bytes(), encoded)?;
            Ok(())
        })
        .map_err(|error| match error {
            sled::transaction::TransactionError::Abort(error) => error,
            sled::transaction::TransactionError::Storage(error) => ContainerStoreError::Open(error),
        })?;
        tree.flush()?;
        Ok(())
    }

    pub(crate) fn finish_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let Some(mut record) = self.get(id)? else {
            return Ok(());
        };
        if record
            .pending_mutation
            .as_ref()
            .map(|value| value.operation_id)
            != Some(operation_id)
        {
            return Err(ContainerStoreError::MutationConflict);
        }
        record.pending_mutation = None;
        record.mutation_generation = record.mutation_generation.saturating_add(1);
        self.put(&record)
    }

    pub fn clone_db(&self) -> sled::Db {
        self.db.clone()
    }
}

/// Get current Unix timestamp in seconds.
///
/// Returns the current time as seconds since Unix epoch.
/// If system time is broken (clock going backwards), logs a warning and returns 0
/// as an indicator of invalid time.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_else(|e| {
            // Use proper logging instead of eprintln!
            log::warn!("system time error in now_unix(), returning 0: {}", e);
            0
        })
}

fn default_health_status() -> String {
    "none".to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        now_unix, ContainerRecord, ContainerStoreError, LocalContainerStore, RestartPolicy,
    };
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
            labels: [("tier".to_string(), "test".to_string())]
                .into_iter()
                .collect(),
            annotations: [("owner".to_string(), "cli".to_string())]
                .into_iter()
                .collect(),
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
            netns: Some("ferro-c1".to_string()),
            network_name: Some("bridge".to_string()),
            ip_address: Some("10.0.0.2".to_string()),
            ipv6_address: Some("fd00::2".to_string()),
            ports: vec![super::PortMappingRecord {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            }],
            network_backend: None,
            network_ownership: None,
            managed_overlay: None,
            managed_host_veth: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
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
            netns: None,
            network_name: None,
            ip_address: None,
            ipv6_address: None,
            ports: Vec::new(),
            network_backend: None,
            network_ownership: None,
            managed_overlay: None,
            managed_host_veth: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
        };

        store.put(&record).expect("store record");
        let removed = store.remove("c1").expect("remove");
        assert!(removed);
        let listed = store.list().expect("list");
        assert!(listed.is_empty());
    }

    #[test]
    fn mutation_reservation_is_a_persisted_compare_and_swap() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record = ContainerRecord::authorization_candidate("cas".into(), "image".into());
        record.status = "running".into();
        store.put(&record).unwrap();
        store
            .reserve_mutation("cas", "running", 1, [1; 16])
            .unwrap();
        assert!(matches!(
            store.reserve_mutation("cas", "running", 1, [2; 16]),
            Err(ContainerStoreError::MutationConflict)
        ));
        store.finish_mutation("cas", [1; 16]).unwrap();
        let updated = store.get("cas").unwrap().unwrap();
        assert_eq!(updated.mutation_generation, 2);
        assert!(updated.pending_mutation.is_none());
    }
}
