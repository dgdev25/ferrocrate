use crate::ai_runtime::AiRuntimeConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

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
    /// Kernel start time (clock ticks) of the recorded workload PID,
    /// captured at spawn. Destructive signals must verify the live process
    /// still has this start time; a recycled PID never matches. Records
    /// written before this field existed never pass verification.
    #[serde(default)]
    pub process_start_time: Option<u64>,
    pub image: String,
    pub command: Vec<String>,
    /// Whether the workload was created with a Docker-compatible terminal.
    /// Defaults to false for records written before durable TTY support.
    #[serde(default)]
    pub tty: bool,
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
    /// The five most recent health probe results, oldest first.
    #[serde(default)]
    pub health_log: Vec<HealthLogEntry>,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    #[serde(default)]
    pub restart_count: u32,
    /// Set only by an explicit operator stop or kill. This is durable intent
    /// used by restart reconciliation for the `unless-stopped` policy.
    #[serde(default)]
    pub user_stopped: bool,
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
    pub resource_limits: Option<ResourceLimitRecord>,
    #[serde(default)]
    pub network_backend: Option<String>,
    #[serde(default)]
    pub network_ownership: Option<NetworkOwnershipRecord>,
    /// Durable per-network endpoint identities. Records written before
    /// multi-network support leave this empty and are projected from the
    /// legacy single-network fields by `effective_network_endpoints`.
    #[serde(default)]
    pub network_endpoints: Vec<NetworkEndpointRecord>,
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

/// Resource limits requested at launch and projected by compatibility APIs.
/// This is deliberately a storage DTO so records remain independent of the
/// cgroup manager's live filesystem representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimitRecord {
    #[serde(default)]
    pub memory_max: Option<u64>,
    #[serde(default)]
    pub cpu_quota: Option<u64>,
    #[serde(default)]
    pub cpu_period: Option<u64>,
    #[serde(default)]
    pub pids_max: Option<u64>,
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
            process_start_time: None,
            image,
            command: Vec::new(),
            tty: false,
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
            health_log: Vec::new(),
            restart_policy: RestartPolicy::No,
            restart_count: 0,
            user_stopped: false,
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
            resource_limits: None,
            network_backend: None,
            network_ownership: None,
            network_endpoints: Vec::new(),
            managed_overlay: None,
            managed_cleanup_provenance: None,
            managed_host_veth: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
        }
    }

    /// Return the canonical endpoint view while keeping pre-migration records
    /// readable. New writes populate `network_endpoints`; the legacy fields
    /// remain as a compatibility projection for older clients and stores.
    pub fn effective_network_endpoints(&self) -> Vec<NetworkEndpointRecord> {
        if !self.network_endpoints.is_empty() {
            return self.network_endpoints.clone();
        }
        let Some(network_name) = self.network_name.clone() else {
            return Vec::new();
        };
        vec![NetworkEndpointRecord {
            endpoint_id: self
                .network_ownership
                .as_ref()
                .map(|ownership| ownership.host_interface.clone())
                .unwrap_or_else(|| self.id.clone()),
            network_name,
            interface_name: "eth0".to_string(),
            ipv4_address: self.ip_address.clone(),
            ipv6_address: self.ipv6_address.clone(),
            generation: 1,
            namespace_identity: self.namespace_identity,
            network_backend: self.network_backend.clone(),
            ownership: self.network_ownership.clone(),
        }]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEndpointRecord {
    pub network_name: String,
    pub endpoint_id: String,
    pub interface_name: String,
    #[serde(default)]
    pub ipv4_address: Option<String>,
    #[serde(default)]
    pub ipv6_address: Option<String>,
    #[serde(default = "default_endpoint_generation")]
    pub generation: u64,
    #[serde(default)]
    pub namespace_identity: Option<KernelObjectIdentityRecord>,
    #[serde(default)]
    pub network_backend: Option<String>,
    #[serde(default)]
    pub ownership: Option<NetworkOwnershipRecord>,
}

fn default_endpoint_generation() -> u64 {
    1
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
    /// Docker's `on-failure:N` policy. A zero limit is represented by the
    /// legacy `OnFailure` variant so persisted records retain their existing
    /// wire representation and semantics (unbounded retries).
    OnFailureWithRetries(u32),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthLogEntry {
    pub start_unix: u64,
    pub end_unix: u64,
    pub exit_code: i32,
    pub output: String,
}

#[derive(Debug, Error)]
pub enum ContainerStoreError {
    #[error("failed to encode container record: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("failed to decode container record: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("container SQLite migration failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("container store filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("legacy Sled container store detected; the Sled importer was removed. See docs/architecture/legacy-sled-importers.md")]
    LegacyMigrationRequired,
    #[error("container store lock failed: {0}")]
    Lock(String),
    #[error("container mutation compare-and-swap failed")]
    MutationConflict,
    #[error("Conflict. The container name \"/{name}\" is already in use by container \"{container_id}\". You have to remove (or rename) that container to be able to reuse that name.")]
    NameConflict { name: String, container_id: String },
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

#[cfg(test)]
mod network_endpoint_tests {
    use super::*;

    #[test]
    fn legacy_single_network_record_projects_one_endpoint() {
        let mut record = ContainerRecord::authorization_candidate(
            "legacy".into(),
            "example@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
        );
        record.netns = Some("ferro-legacy".into());
        record.namespace_identity = Some(KernelObjectIdentityRecord {
            device: 12,
            inode: 34,
        });
        record.network_name = Some("legacy-net".into());
        record.ip_address = Some("172.28.0.7".into());
        record.ipv6_address = Some("fd28::7".into());
        record.network_backend = Some("nftables".into());

        let endpoints = record.effective_network_endpoints();

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].network_name, "legacy-net");
        assert_eq!(endpoints[0].endpoint_id, "legacy");
        assert_eq!(endpoints[0].interface_name, "eth0");
        assert_eq!(endpoints[0].ipv4_address.as_deref(), Some("172.28.0.7"));
        assert_eq!(endpoints[0].ipv6_address.as_deref(), Some("fd28::7"));
        assert_eq!(endpoints[0].generation, 1);
        assert_eq!(endpoints[0].namespace_identity, record.namespace_identity);
    }
}
