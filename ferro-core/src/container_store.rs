use crate::ai_runtime::AiRuntimeConfig;
use serde::{Deserialize, Serialize};
#[cfg(feature = "legacy-sled-importers")]
use sha2::{Digest, Sha256};
#[cfg(feature = "legacy-sled-importers")]
use sled::transaction::Transactional;
use std::collections::HashMap;
#[cfg(feature = "legacy-sled-importers")]
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(feature = "legacy-sled-importers")]
pub const CONTAINER_INDEX_TREE: &str = "container_index";
#[cfg(feature = "legacy-sled-importers")]
pub const LIFECYCLE_OPERATION_TREE: &str = "lifecycle_operations";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LifecycleOperation {
    pub operation_id: [u8; 16],
    pub container_id: String,
    pub action: String,
    pub generation: u64,
    pub phase: LifecyclePhase,
    pub pid: u32,
    pub process_start_time: Option<u64>,
    pub state: String,
    #[serde(default)]
    pub pid_after: Option<u32>,
    #[serde(default)]
    pub process_start_time_after: Option<u64>,
    #[serde(default)]
    pub state_after: Option<String>,
    #[serde(default)]
    pub freezer_state_after: Option<bool>,
    pub ownership_digest: [u8; 32],
    #[serde(default)]
    pub execution_generation_after: Option<u64>,
    #[serde(default)]
    pub result_digest: Option<[u8; 32]>,
    #[serde(default)]
    pub effect_succeeded: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum LifecyclePhase {
    Reserved,
    EffectApplied,
    StoreDeleted,
}

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
    #[serde(default = "default_namespace_owned")]
    pub namespace_owned: bool,
    /// Kernel identity of the persisted network namespace.  This is separate
    /// from bridge ownership because `network_mode=none` has a namespace but
    /// no bridge/backend record.
    #[serde(default)]
    pub namespace_identity: Option<KernelObjectIdentityRecord>,
    #[serde(default)]
    pub network_name: Option<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub ipv6_address: Option<String>,
    #[serde(default)]
    pub ports: Vec<PortMappingRecord>,
    #[serde(default)]
    pub mounts: Vec<ContainerMountRecord>,
    #[serde(default)]
    pub tmpfs_mounts: Vec<ContainerTmpfsMountRecord>,
    #[serde(default)]
    pub readonly_rootfs: bool,
    #[serde(default)]
    pub no_new_privileges: bool,
    #[serde(default)]
    pub network_backend: Option<String>,
    #[serde(default)]
    pub network_ownership: Option<NetworkOwnershipRecord>,
    #[serde(default)]
    pub managed_overlay: Option<String>,
    #[serde(default)]
    pub managed_cleanup_provenance: Option<crate::managed_overlay::ManagedCleanupProvenance>,
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

fn default_namespace_owned() -> bool {
    true
}

/// Durable bind-mount configuration required to replay a container after a
/// stop, restart, or daemon/process recovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerMountRecord {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}

/// Durable tmpfs configuration required to replay a container after restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerTmpfsMountRecord {
    pub target: String,
    #[serde(default)]
    pub size: Option<String>,
}

fn default_mutation_generation() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MutationReservation {
    pub operation_id: [u8; 16],
    pub generation: u64,
    pub expected_status: String,
    pub action: String,
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
            namespace_owned: true,
            namespace_identity: None,
            network_name: None,
            ip_address: None,
            ipv6_address: None,
            ports: Vec::new(),
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            readonly_rootfs: false,
            no_new_privileges: false,
            network_backend: None,
            network_ownership: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
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
    #[cfg(feature = "legacy-sled-importers")]
    #[error("failed to open container store: {0}")]
    Open(#[from] sled::Error),
    #[error("failed to encode container record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode container record: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("container SQLite migration failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("container store filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("legacy container store detected; reopen with the `legacy-sled-importers` feature")]
    LegacyMigrationRequired,
    #[error("container store lock failed: {0}")]
    Lock(String),
    #[error("container mutation compare-and-swap failed")]
    MutationConflict,
}

#[cfg(feature = "legacy-sled-importers")]
#[derive(Clone)]
pub struct LocalContainerStore {
    db: sled::Db,
}

#[cfg(feature = "legacy-sled-importers")]
#[allow(dead_code)]
impl LocalContainerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ContainerStoreError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    pub fn put(&self, record: &ContainerRecord) -> Result<(), ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let encoded = serde_json::to_vec(record)?;
        tree.transaction(|tree| {
            if record.pending_mutation.is_some() {
                return Err(sled::transaction::ConflictableTransactionError::Abort(
                    ContainerStoreError::MutationConflict,
                ));
            }
            if let Some(existing) = tree.get(record.id.as_bytes())? {
                let existing: ContainerRecord =
                    serde_json::from_slice(&existing).map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(error),
                        )
                    })?;
                if existing.pending_mutation.is_some() {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    ));
                }
            }
            tree.insert(record.id.as_bytes(), encoded.as_slice())?;
            Ok(())
        })
        .map_err(|error| match error {
            sled::transaction::TransactionError::Abort(error) => error,
            sled::transaction::TransactionError::Storage(error) => ContainerStoreError::Open(error),
        })?;
        tree.flush()?;
        Ok(())
    }

    pub(crate) fn put_for_mutation(
        &self,
        record: &ContainerRecord,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let operations = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        let encoded = serde_json::to_vec(record)?;
        (&tree, &operations)
            .transaction(|(tree, operations)| {
                let current = tree.get(record.id.as_bytes())?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                let current: ContainerRecord =
                    serde_json::from_slice(&current).map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(error),
                        )
                    })?;
                let reservation = current.pending_mutation.as_ref().ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                if reservation.operation_id != operation_id
                    || reservation.generation != current.mutation_generation
                    || record.pending_mutation.as_ref() != Some(reservation)
                    || record.mutation_generation != current.mutation_generation
                {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    ));
                }
                let operation_bytes = operations.get(operation_id)?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                let mut operation: LifecycleOperation = serde_json::from_slice(&operation_bytes)
                    .map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(error),
                        )
                    })?;
                operation.pid_after = Some(record.pid);
                operation.process_start_time_after = process_start_time(record.pid);
                operation.state_after = Some(record.status.clone());
                let operation_encoded = serde_json::to_vec(&operation).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::Encode(error),
                    )
                })?;
                tree.insert(record.id.as_bytes(), encoded.as_slice())?;
                operations.insert(&operation_id, operation_encoded)?;
                Ok(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(error) => error,
                sled::transaction::TransactionError::Storage(error) => {
                    ContainerStoreError::Open(error)
                }
            })?;
        tree.flush()?;
        operations.flush()?;
        Ok(())
    }

    pub(crate) fn put_reserved_creation(
        &self,
        record: &ContainerRecord,
    ) -> Result<(), ContainerStoreError> {
        let reservation = record
            .pending_mutation
            .as_ref()
            .ok_or(ContainerStoreError::MutationConflict)?;
        let containers = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let operations = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        let record_bytes = serde_json::to_vec(record)?;
        let operation = lifecycle_operation(
            record,
            reservation.operation_id,
            &reservation.action,
            LifecyclePhase::Reserved,
        );
        let operation_bytes = serde_json::to_vec(&operation)?;
        (&containers, &operations)
            .transaction(|(containers, operations)| {
                if containers.get(record.id.as_bytes())?.is_some()
                    || operations.get(reservation.operation_id)?.is_some()
                {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    ));
                }
                containers.insert(record.id.as_bytes(), record_bytes.as_slice())?;
                operations.insert(&reservation.operation_id, operation_bytes.as_slice())?;
                Ok(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(error) => error,
                sled::transaction::TransactionError::Storage(error) => {
                    ContainerStoreError::Open(error)
                }
            })?;
        containers.flush()?;
        operations.flush()?;
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

    pub(crate) fn transition_status_for_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
        expected_generation: u64,
        expected_status: &str,
        next_status: &str,
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
            let reservation = record.pending_mutation.as_ref().ok_or_else(|| {
                sled::transaction::ConflictableTransactionError::Abort(
                    ContainerStoreError::MutationConflict,
                )
            })?;
            if reservation.operation_id != operation_id
                || reservation.generation != expected_generation
                || reservation.expected_status != expected_status
                || record.mutation_generation != expected_generation
                || record.status != expected_status
            {
                return Err(sled::transaction::ConflictableTransactionError::Abort(
                    ContainerStoreError::MutationConflict,
                ));
            }
            record.status = next_status.to_owned();
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

    pub(crate) fn reserve_mutation(
        &self,
        id: &str,
        expected_status: &str,
        expected_generation: u64,
        operation_id: [u8; 16],
        action: &str,
    ) -> Result<(), ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let operations = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        (&tree, &operations)
            .transaction(|(tree, operations)| {
                let bytes = tree.get(id.as_bytes())?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                let mut record: ContainerRecord =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(error),
                        )
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
                    action: action.to_owned(),
                });
                let operation =
                    lifecycle_operation(&record, operation_id, action, LifecyclePhase::Reserved);
                let operation = serde_json::to_vec(&operation).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::Encode(error),
                    )
                })?;
                if operations.insert(&operation_id, operation)?.is_some() {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    ));
                }
                let encoded = serde_json::to_vec(&record).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::Encode(error),
                    )
                })?;
                tree.insert(id.as_bytes(), encoded)?;
                Ok(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(error) => error,
                sled::transaction::TransactionError::Storage(error) => {
                    ContainerStoreError::Open(error)
                }
            })?;
        tree.flush()?;
        operations.flush()?;
        Ok(())
    }

    pub(crate) fn lifecycle_operation(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<LifecycleOperation>, ContainerStoreError> {
        self.db
            .open_tree(LIFECYCLE_OPERATION_TREE)?
            .get(operation_id)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(ContainerStoreError::Decode))
            .transpose()
    }

    pub(crate) fn lifecycle_operations(
        &self,
    ) -> Result<Vec<LifecycleOperation>, ContainerStoreError> {
        self.db
            .open_tree(LIFECYCLE_OPERATION_TREE)?
            .iter()
            .map(|entry| {
                let (_, bytes) = entry?;
                serde_json::from_slice(&bytes).map_err(ContainerStoreError::Decode)
            })
            .collect()
    }

    pub(crate) fn mark_mutation_effect(
        &self,
        id: &str,
        operation_id: [u8; 16],
        succeeded: bool,
    ) -> Result<(), ContainerStoreError> {
        self.mark_mutation_effect_observed(id, operation_id, succeeded, None)
    }

    pub(crate) fn mark_mutation_effect_observed(
        &self,
        id: &str,
        operation_id: [u8; 16],
        succeeded: bool,
        freezer_state: Option<bool>,
    ) -> Result<(), ContainerStoreError> {
        let containers = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let operations = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        (&containers, &operations)
            .transaction(|(containers, operations)| {
                let record_bytes = containers.get(id.as_bytes())?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                let record: ContainerRecord =
                    serde_json::from_slice(&record_bytes).map_err(|e| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(e),
                        )
                    })?;
                let operation_bytes = operations.get(operation_id)?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                let mut operation: LifecycleOperation = serde_json::from_slice(&operation_bytes)
                    .map_err(|e| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(e),
                        )
                    })?;
                if record
                    .pending_mutation
                    .as_ref()
                    .map(|pending| pending.operation_id)
                    != Some(operation_id)
                    || operation.container_id != id
                    || operation.generation != record.mutation_generation
                {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    ));
                }
                operation.phase = LifecyclePhase::EffectApplied;
                operation.pid_after = Some(record.pid);
                operation.process_start_time_after = process_start_time(record.pid);
                operation.state_after = Some(record.status);
                operation.freezer_state_after = freezer_state;
                operation.execution_generation_after =
                    Some(if operation.action == "container.restart" && succeeded {
                        record.mutation_generation.saturating_add(1)
                    } else {
                        record.mutation_generation
                    });
                let mut digest = Sha256::new();
                digest.update(b"ferrocrate/lifecycle-result/v1");
                digest.update(operation_id);
                digest.update([u8::from(succeeded)]);
                operation.result_digest = Some(digest.finalize().into());
                operation.effect_succeeded = Some(succeeded);
                let encoded = serde_json::to_vec(&operation).map_err(|e| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::Encode(e),
                    )
                })?;
                operations.insert(&operation_id, encoded)?;
                Ok(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(error) => error,
                sled::transaction::TransactionError::Storage(error) => {
                    ContainerStoreError::Open(error)
                }
            })?;
        operations.flush()?;
        Ok(())
    }

    pub(crate) fn delete_for_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let containers = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let operations = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        (&containers, &operations)
            .transaction(|(containers, operations)| {
                let bytes = containers.get(id.as_bytes())?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                let record: ContainerRecord = serde_json::from_slice(&bytes).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::Decode(error),
                    )
                })?;
                if record.pending_mutation.as_ref().map(|p| p.operation_id) != Some(operation_id) {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    ));
                }
                let operation_bytes = operations.get(operation_id)?.ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                let mut operation: LifecycleOperation = serde_json::from_slice(&operation_bytes)
                    .map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(error),
                        )
                    })?;
                operation.phase = LifecyclePhase::StoreDeleted;
                let encoded = serde_json::to_vec(&operation).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::Encode(error),
                    )
                })?;
                operations.insert(&operation_id, encoded)?;
                containers.remove(id.as_bytes())?;
                Ok(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(error) => error,
                sled::transaction::TransactionError::Storage(error) => {
                    ContainerStoreError::Open(error)
                }
            })?;
        containers.flush()?;
        operations.flush()?;
        Ok(())
    }

    pub(crate) fn acknowledge_mutation(
        &self,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let operations = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        operations.remove(operation_id)?;
        operations.flush()?;
        Ok(())
    }

    pub(crate) fn finish_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let operations = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        (&tree, &operations)
            .transaction(|(tree, operations)| {
                let Some(bytes) = tree.get(id.as_bytes())? else {
                    return Ok(());
                };
                let mut record: ContainerRecord =
                    serde_json::from_slice(&bytes).map_err(|error| {
                        sled::transaction::ConflictableTransactionError::Abort(
                            ContainerStoreError::Decode(error),
                        )
                    })?;
                let reservation = record.pending_mutation.as_ref().ok_or_else(|| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    )
                })?;
                if reservation.operation_id != operation_id
                    || reservation.generation != record.mutation_generation
                {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::MutationConflict,
                    ));
                }
                record.pending_mutation = None;
                record.mutation_generation = record.mutation_generation.saturating_add(1);
                let encoded = serde_json::to_vec(&record).map_err(|error| {
                    sled::transaction::ConflictableTransactionError::Abort(
                        ContainerStoreError::Encode(error),
                    )
                })?;
                tree.insert(id.as_bytes(), encoded)?;
                operations.remove(&operation_id)?;
                Ok(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(error) => error,
                sled::transaction::TransactionError::Storage(error) => {
                    ContainerStoreError::Open(error)
                }
            })?;
        tree.flush()?;
        operations.flush()?;
        Ok(())
    }

    pub fn clone_db(&self) -> sled::Db {
        self.db.clone()
    }

    /// Export the legacy sled trees into a transactional SQLite snapshot.
    /// The source remains untouched so operators can roll back while the
    /// runtime migration is qualified on each host.
    pub fn export_sqlite_snapshot(
        &self,
        sqlite_path: impl AsRef<Path>,
    ) -> Result<(), ContainerStoreError> {
        let connection = rusqlite::Connection::open(sqlite_path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS containers (
                 id TEXT PRIMARY KEY NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS lifecycle_operations (
                 operation_id BLOB PRIMARY KEY NOT NULL,
                 payload BLOB NOT NULL
             );",
        )?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute("DELETE FROM containers", [])?;
        transaction.execute("DELETE FROM lifecycle_operations", [])?;
        let mut offset = 0;
        loop {
            let page = self.list_paginated(Some(offset), Some(1000))?;
            if page.is_empty() {
                break;
            }
            for record in page {
                transaction.execute(
                    "INSERT INTO containers (id, payload) VALUES (?1, ?2)",
                    rusqlite::params![record.id, serde_json::to_vec(&record)?],
                )?;
            }
            offset += 1000;
        }
        for operation in self.lifecycle_operations()? {
            transaction.execute(
                "INSERT INTO lifecycle_operations (operation_id, payload) VALUES (?1, ?2)",
                rusqlite::params![
                    operation.operation_id.to_vec(),
                    serde_json::to_vec(&operation)?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Import a previously exported SQLite snapshot without overwriting
    /// conflicting durable state. All rows are decoded and identity-checked
    /// before either sled tree is mutated; the two trees are then committed as
    /// one sled transaction so a failed migration cannot leave a partial
    /// container/lifecycle view.
    pub fn import_sqlite_snapshot(
        &self,
        sqlite_path: impl AsRef<Path>,
    ) -> Result<(), ContainerStoreError> {
        let connection = rusqlite::Connection::open(sqlite_path)?;
        let mut containers_statement =
            connection.prepare("SELECT id, payload FROM containers ORDER BY id")?;
        let containers = containers_statement
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((id, payload))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut decoded_containers = Vec::with_capacity(containers.len());
        for (id, payload) in containers {
            let record: ContainerRecord =
                serde_json::from_slice(&payload).map_err(ContainerStoreError::Decode)?;
            if record.id != id {
                return Err(ContainerStoreError::MutationConflict);
            }
            if record.pending_mutation.is_some() {
                return Err(ContainerStoreError::MutationConflict);
            }
            decoded_containers.push((id.into_bytes(), payload));
        }

        let mut operations_statement = connection.prepare(
            "SELECT operation_id, payload FROM lifecycle_operations ORDER BY operation_id",
        )?;
        let operations = operations_statement
            .query_map([], |row| {
                let operation_id: Vec<u8> = row.get(0)?;
                let payload: Vec<u8> = row.get(1)?;
                Ok((operation_id, payload))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut decoded_operations = Vec::with_capacity(operations.len());
        for (operation_id, payload) in operations {
            let operation: LifecycleOperation =
                serde_json::from_slice(&payload).map_err(ContainerStoreError::Decode)?;
            if operation_id.len() != 16 || operation.operation_id.as_slice() != operation_id {
                return Err(ContainerStoreError::MutationConflict);
            }
            decoded_operations.push((operation_id, payload));
        }

        let containers_tree = self.db.open_tree(CONTAINER_INDEX_TREE)?;
        let operations_tree = self.db.open_tree(LIFECYCLE_OPERATION_TREE)?;
        (&containers_tree, &operations_tree)
            .transaction(|(containers, operations)| {
                for (id, payload) in &decoded_containers {
                    if let Some(existing) = containers.get(id)? {
                        if existing.as_ref() != payload.as_slice() {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                ContainerStoreError::MutationConflict,
                            ));
                        }
                    } else {
                        containers.insert(id.as_slice(), payload.as_slice())?;
                    }
                }
                for (operation_id, payload) in &decoded_operations {
                    if let Some(existing) = operations.get(operation_id)? {
                        if existing.as_ref() != payload.as_slice() {
                            return Err(sled::transaction::ConflictableTransactionError::Abort(
                                ContainerStoreError::MutationConflict,
                            ));
                        }
                    } else {
                        operations.insert(operation_id.as_slice(), payload.as_slice())?;
                    }
                }
                Ok(())
            })
            .map_err(|error| match error {
                sled::transaction::TransactionError::Abort(error) => error,
                sled::transaction::TransactionError::Storage(error) => {
                    ContainerStoreError::Open(error)
                }
            })?;
        containers_tree.flush()?;
        operations_tree.flush()?;
        Ok(())
    }
}

#[cfg(feature = "legacy-sled-importers")]
#[allow(dead_code)]
fn lifecycle_operation(
    record: &ContainerRecord,
    operation_id: [u8; 16],
    action: &str,
    phase: LifecyclePhase,
) -> LifecycleOperation {
    let mut digest = Sha256::new();
    digest.update(b"ferrocrate/lifecycle-ownership/v1");
    digest.update(record.id.as_bytes());
    digest.update(
        record
            .creation_provenance
            .runtime_instance_id
            .unwrap_or_default(),
    );
    digest.update(record.creation_provenance.resource_generation.to_be_bytes());
    LifecycleOperation {
        operation_id,
        container_id: record.id.clone(),
        action: action.to_owned(),
        generation: record.mutation_generation,
        phase,
        pid: record.pid,
        process_start_time: process_start_time(record.pid),
        state: record.status.clone(),
        pid_after: None,
        process_start_time_after: None,
        state_after: None,
        freezer_state_after: None,
        ownership_digest: digest.finalize().into(),
        execution_generation_after: None,
        result_digest: None,
        effect_succeeded: None,
    }
}

pub(crate) fn process_start_time(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    fields.nth(19)?.parse().ok()
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

#[cfg(all(test, feature = "legacy-sled-importers"))]
mod tests {
    use super::{
        now_unix, ContainerRecord, ContainerStoreError, LifecyclePhase, LocalContainerStore,
        RestartPolicy,
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
            namespace_owned: true,
            namespace_identity: None,
            network_name: Some("bridge".to_string()),
            ip_address: Some("10.0.0.2".to_string()),
            ipv6_address: Some("fd00::2".to_string()),
            ports: vec![super::PortMappingRecord {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            }],
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            readonly_rootfs: false,
            no_new_privileges: false,
            network_backend: None,
            network_ownership: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
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
    fn exports_transactional_sqlite_snapshot() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = LocalContainerStore::open(temp.path().join("containers.db")).expect("open");
        let sqlite = temp.path().join("containers.sqlite");
        store.export_sqlite_snapshot(&sqlite).expect("export");
        let db = rusqlite::Connection::open(sqlite).expect("sqlite");
        let containers: i64 = db
            .query_row("SELECT COUNT(*) FROM containers", [], |row| row.get(0))
            .expect("containers count");
        let operations: i64 = db
            .query_row("SELECT COUNT(*) FROM lifecycle_operations", [], |row| {
                row.get(0)
            })
            .expect("operations count");
        assert_eq!(containers, 0);
        assert_eq!(operations, 0);
    }

    #[test]
    fn imports_sqlite_snapshot_round_trip_without_overwriting_conflicts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let source = LocalContainerStore::open(temp.path().join("source.db")).expect("source");
        let record: ContainerRecord = serde_json::from_value(serde_json::json!({
            "id": "round-trip",
            "pid": 0,
            "image": "alpine:latest",
            "command": ["true"],
            "created_at_unix": 1,
            "stdout_path": "stdout.log",
            "stderr_path": "stderr.log",
            "status": "created"
        }))
        .expect("record");
        source.put(&record).expect("seed source");
        let sqlite = temp.path().join("snapshot.sqlite");
        source
            .export_sqlite_snapshot(&sqlite)
            .expect("export snapshot");

        let destination =
            LocalContainerStore::open(temp.path().join("destination.db")).expect("destination");
        destination
            .import_sqlite_snapshot(&sqlite)
            .expect("import snapshot");
        assert_eq!(destination.get("round-trip").unwrap(), Some(record.clone()));
        destination
            .import_sqlite_snapshot(&sqlite)
            .expect("idempotent import");

        let conflicting: ContainerRecord = serde_json::from_value(serde_json::json!({
            "id": "round-trip",
            "pid": 0,
            "image": "different:latest",
            "command": ["false"],
            "created_at_unix": 1,
            "stdout_path": "stdout.log",
            "stderr_path": "stderr.log",
            "status": "created"
        }))
        .expect("conflicting record");
        let conflict_source =
            LocalContainerStore::open(temp.path().join("conflict.db")).expect("conflict source");
        conflict_source.put(&conflicting).expect("seed conflict");
        let conflict_sqlite = temp.path().join("conflict.sqlite");
        conflict_source
            .export_sqlite_snapshot(&conflict_sqlite)
            .expect("export conflict");
        assert!(matches!(
            destination.import_sqlite_snapshot(&conflict_sqlite),
            Err(ContainerStoreError::MutationConflict)
        ));
        assert_eq!(destination.get("round-trip").unwrap(), Some(record));
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
            namespace_owned: true,
            namespace_identity: None,
            network_name: None,
            ip_address: None,
            ipv6_address: None,
            ports: Vec::new(),
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            readonly_rootfs: false,
            no_new_privileges: false,
            network_backend: None,
            network_ownership: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
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
            .reserve_mutation("cas", "running", 1, [1; 16], "container.stop")
            .unwrap();
        assert!(matches!(
            store.reserve_mutation("cas", "running", 1, [2; 16], "container.kill"),
            Err(ContainerStoreError::MutationConflict)
        ));
        store.finish_mutation("cas", [1; 16]).unwrap();
        let updated = store.get("cas").unwrap().unwrap();
        assert_eq!(updated.mutation_generation, 2);
        assert!(updated.pending_mutation.is_none());
    }

    #[test]
    fn unconditional_writer_rejects_generation_change_during_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record =
            ContainerRecord::authorization_candidate("cas-finish".into(), "image".into());
        record.status = "running".into();
        store.put(&record).unwrap();
        store
            .reserve_mutation("cas-finish", "running", 1, [3; 16], "container.stop")
            .unwrap();
        let mut raced = store.get("cas-finish").unwrap().unwrap();
        raced.mutation_generation = 9;
        assert!(matches!(
            store.put(&raced),
            Err(ContainerStoreError::MutationConflict)
        ));
        assert!(store
            .get("cas-finish")
            .unwrap()
            .unwrap()
            .pending_mutation
            .is_some());
        store.finish_mutation("cas-finish", [3; 16]).unwrap();
    }

    #[test]
    fn effect_marker_and_status_transition_require_exact_reserved_operation() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record =
            ContainerRecord::authorization_candidate("exact-op".into(), "image".into());
        record.status = "running".into();
        store.put(&record).unwrap();
        store
            .reserve_mutation("exact-op", "running", 1, [7; 16], "container.pause")
            .unwrap();
        assert!(matches!(
            store.transition_status_for_mutation("exact-op", [8; 16], 1, "running", "paused"),
            Err(ContainerStoreError::MutationConflict)
        ));
        assert!(matches!(
            store.mark_mutation_effect("exact-op", [8; 16], true),
            Err(ContainerStoreError::MutationConflict)
        ));
        store
            .transition_status_for_mutation("exact-op", [7; 16], 1, "running", "paused")
            .unwrap();
        store
            .mark_mutation_effect("exact-op", [7; 16], true)
            .unwrap();
    }

    #[test]
    fn delete_keeps_operation_tombstone_until_terminal_ack() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record =
            ContainerRecord::authorization_candidate("remove-cas".into(), "image".into());
        record.status = "stopped".into();
        store.put(&record).unwrap();
        store
            .reserve_mutation("remove-cas", "stopped", 1, [7; 16], "container.delete")
            .unwrap();
        store.delete_for_mutation("remove-cas", [7; 16]).unwrap();
        assert!(store.get("remove-cas").unwrap().is_none());
        let operation = store.lifecycle_operation([7; 16]).unwrap().unwrap();
        assert_eq!(operation.phase, LifecyclePhase::StoreDeleted);
        assert_eq!(operation.container_id, "remove-cas");
        store.acknowledge_mutation([7; 16]).unwrap();
        assert!(store.lifecycle_operation([7; 16]).unwrap().is_none());
    }

    #[test]
    fn witnessed_creation_persists_record_and_operation_together() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record =
            ContainerRecord::authorization_candidate("create-cas".into(), "image".into());
        record.pending_mutation = Some(super::MutationReservation {
            operation_id: [8; 16],
            generation: 1,
            expected_status: "created".into(),
            action: "container.run".into(),
        });
        store.put_reserved_creation(&record).unwrap();
        assert!(store.get("create-cas").unwrap().is_some());
        assert!(store.lifecycle_operation([8; 16]).unwrap().is_some());
    }

    #[test]
    fn durable_launch_update_atomically_binds_new_process_identity() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record =
            ContainerRecord::authorization_candidate("launch-cas".into(), "image".into());
        record.pending_mutation = Some(super::MutationReservation {
            operation_id: [18; 16],
            generation: 1,
            expected_status: "created".into(),
            action: "container.run".into(),
        });
        store.put_reserved_creation(&record).unwrap();
        record.pid = std::process::id();
        record.status = "running".into();
        store.put_for_mutation(&record, [18; 16]).unwrap();
        let operation = store.lifecycle_operation([18; 16]).unwrap().unwrap();
        assert_eq!(operation.pid_after, Some(std::process::id()));
        assert!(operation.process_start_time_after.is_some());
        assert_eq!(operation.state_after.as_deref(), Some("running"));
    }

    #[test]
    fn effect_marker_is_redacted_and_bound_to_operation_generation() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record =
            ContainerRecord::authorization_candidate("exec-marker".into(), "image".into());
        record.status = "running".into();
        record.pid = std::process::id();
        store.put(&record).unwrap();
        store
            .reserve_mutation("exec-marker", "running", 1, [9; 16], "container.exec")
            .unwrap();
        store
            .mark_mutation_effect("exec-marker", [9; 16], true)
            .unwrap();
        let operation = store.lifecycle_operation([9; 16]).unwrap().unwrap();
        assert_eq!(operation.phase, LifecyclePhase::EffectApplied);
        assert!(operation.result_digest.is_some());
        assert!(operation.process_start_time.is_some());
        assert_eq!(operation.execution_generation_after, Some(1));
    }

    #[test]
    fn restart_effect_records_old_and_new_execution_generations() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalContainerStore::open(dir.path()).unwrap();
        let mut record =
            ContainerRecord::authorization_candidate("restart-marker".into(), "image".into());
        record.status = "stopped".into();
        store.put(&record).unwrap();
        store
            .reserve_mutation(
                "restart-marker",
                "stopped",
                1,
                [10; 16],
                "container.restart",
            )
            .unwrap();
        store
            .mark_mutation_effect("restart-marker", [10; 16], true)
            .unwrap();
        let operation = store.lifecycle_operation([10; 16]).unwrap().unwrap();
        assert_eq!(operation.generation, 1);
        assert_eq!(operation.execution_generation_after, Some(2));
    }
}
