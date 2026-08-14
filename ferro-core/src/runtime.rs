#[cfg(target_os = "linux")]
use crate::ai_runtime::AiRuntimeConfig;
use crate::authorization::runtime::{
    MediationError, RunMountFact, RunSecurityFacts, RuntimeAuthorization,
};
use crate::authorization::{
    gate::{AuthorizationGate, AuthorizedRequest},
    Action,
};
#[cfg(target_os = "linux")]
use crate::capabilities::{drop_all_capabilities, set_capabilities};
use crate::cgroups::{CgroupStats, CgroupV2Manager, ResourceLimits};
use crate::container_exec::{exec_in_container, exec_in_container_with_timeout};
use crate::container_store::{
    now_unix, ContainerRecord, ContainerStoreError, EbpfFilterOwnershipRecord,
    EbpfPinOwnershipRecord, HealthConfig, KernelObjectIdentityRecord, LifecycleOperation,
    LifecyclePhase, LocalContainerStore, MutationReservation, NetworkOwnershipRecord,
    PortMappingRecord, RestartPolicy,
};
use crate::image_config::{
    command_from_config, env_from_config, healthcheck_from_config, user_from_config,
    working_dir_from_config,
};
use crate::image_fetch::{resolve_config_path_with_store, resolve_layer_paths_with_store};
use crate::image_security::verify_image_signature;
use crate::image_store::LocalImageStore;
use crate::mac_profiles::generate_apparmor_profile;
#[cfg(target_os = "linux")]
use crate::managed_overlay::{ManagedOverlayClient, ManagedOverlayRequest, ManagedOverlayResponse};
use crate::mounts::{
    apply_authorized_bind_mounts, apply_readonly_rootfs, apply_tmpfs_mounts,
    normalize_mount_target, BindMount, MountError, TmpfsMount,
};
use crate::observability::{log_audit_event, log_event, make_audit_event, make_event};
use crate::process_lifecycle::{kill_pid, stop_pid, ProcessLifecycleError};
use crate::registry::parse_image_reference;
#[cfg(target_os = "linux")]
use crate::rootfs::construct_rootfs_with_dedup;
#[cfg(target_os = "linux")]
use crate::seccomp::{
    apply_seccomp_profile, default_seccomp_profile, parse_seccomp_profile, SeccompProfile,
};
use dashmap::DashMap;
use ferro_net::bridge;
use ferro_net::ebpf::{
    embedded_object_abi, embedded_object_sha256, install_security_monitor, EbpfNetwork,
    EbpfNetworkConfig, PinnedNetworkIdentity, PinnedObjectIdentity, PreparedEbpfNetwork,
    SecurityMonitorConfig, VerifiedPinnedNetwork, FERRO_NETWORK_ROOT,
};
use ferro_net::ebpf_abi::{EndpointKey, EndpointValue, PortKey, PortValue};
use ferro_net::exec_cmd as net_exec_cmd;
use ferro_net::netns;
use ferro_net::portmap::{build_network_plan as build_portmap_plan, NetworkPlan};
use ferro_net::rootless::{build_slirp4netns_cmd, RootlessNetConfig};
use ferro_net::subnet::network_cidr_v4;
use ferro_net::veth;
use ferro_net::BackendProbe;
pub use ferro_net::NetworkBackend;
use ferro_net::{WireGuardInterfaceConfig, WireGuardManager, WireGuardPeer};
use rand::Rng;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
#[cfg(test)]
use std::io::Read;
use std::io::{self, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{info, warn};

// ============================================================================
// Atomic Operations Support (Task 4.1)
// ============================================================================

/// Tracks resources created during container creation for rollback on failure.
///
/// This struct implements a scope guard pattern - if not explicitly committed,
/// it will roll back all tracked resources on drop.
struct CreationRollback {
    container_id: String,
    container_dir: Option<PathBuf>,
    netns_name: Option<String>,
    namespace_identity: Option<KernelObjectIdentityRecord>,
    host_veth: Option<(String, Option<u32>)>,
    container_ip: Option<String>,
    port_mappings: Vec<PortMappingRecord>,
    network_backend: Option<NetworkBackend>,
    network_ownership: Option<NetworkOwnershipRecord>,
    ebpf_network: Option<EbpfNetwork>,
    network_persisted: bool,
    shared_network_created: bool,
    bridge_created: Option<(String, Option<u32>)>,
    ip_forward: Option<GlobalValueOwnership>,
    pending_firewall_cleanup: Vec<Vec<String>>,
    journal: NetworkMutationJournal,
    cgroup_name: Option<String>,
    cgroup_root: PathBuf,
    committed: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct GlobalValueOwnership {
    previous: String,
    expected: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PendingNetworkCleanup {
    schema_version: u32,
    container_id: String,
    netns_name: Option<String>,
    namespace_identity: Option<KernelObjectIdentityRecord>,
    host_veth: Option<(String, Option<u32>)>,
    container_ip: Option<String>,
    port_mappings: Vec<PortMappingRecord>,
    network_backend: Option<String>,
    network_ownership: Option<NetworkOwnershipRecord>,
    network_persisted: bool,
    shared_network_created: bool,
    bridge_created: Option<(String, Option<u32>)>,
    ip_forward: Option<GlobalValueOwnership>,
    pending_firewall_cleanup: Vec<Vec<String>>,
}

impl CreationRollback {
    fn new(container_id: &str, cgroup_root: PathBuf) -> Self {
        Self {
            container_id: container_id.to_string(),
            container_dir: None,
            netns_name: None,
            namespace_identity: None,
            host_veth: None,
            container_ip: None,
            port_mappings: Vec::new(),
            network_backend: None,
            network_ownership: None,
            ebpf_network: None,
            network_persisted: false,
            shared_network_created: false,
            bridge_created: None,
            ip_forward: None,
            pending_firewall_cleanup: Vec::new(),
            journal: NetworkMutationJournal::default(),
            cgroup_name: None,
            cgroup_root,
            committed: false,
        }
    }

    fn from_pending(
        container_dir: PathBuf,
        cgroup_root: PathBuf,
        pending: PendingNetworkCleanup,
    ) -> Result<Self, RuntimeError> {
        if pending.schema_version != 1 || pending.container_id.is_empty() {
            return Err(RuntimeError::Network(
                "malformed pending network cleanup journal".to_string(),
            ));
        }
        let network_backend = pending
            .network_backend
            .as_deref()
            .map(str::parse::<NetworkBackend>)
            .transpose()
            .map_err(|error| {
                RuntimeError::Network(format!("malformed pending backend: {error}"))
            })?;
        Ok(Self {
            container_id: pending.container_id,
            container_dir: Some(container_dir),
            netns_name: pending.netns_name,
            namespace_identity: pending.namespace_identity,
            host_veth: pending.host_veth,
            container_ip: pending.container_ip,
            port_mappings: pending.port_mappings,
            network_backend,
            network_ownership: pending.network_ownership,
            ebpf_network: None,
            network_persisted: pending.network_persisted,
            shared_network_created: pending.shared_network_created,
            bridge_created: pending.bridge_created,
            ip_forward: pending.ip_forward,
            pending_firewall_cleanup: pending.pending_firewall_cleanup,
            journal: NetworkMutationJournal::default(),
            cgroup_name: None,
            cgroup_root,
            committed: false,
        })
    }

    fn track_container_dir(&mut self, dir: PathBuf) {
        self.container_dir = Some(dir);
    }

    fn track_network(
        &mut self,
        setup: &mut NetworkSetup,
        ports: &[PortMappingRecord],
    ) -> Result<(), RuntimeError> {
        self.netns_name = setup.netns_name.clone();
        self.container_ip = setup.container_ip.clone();
        self.port_mappings = ports.to_vec();
        if self.network_backend.is_none() {
            self.network_backend = setup.backend;
            self.network_ownership = setup.ownership.clone();
            self.shared_network_created = setup.ebpf_network.is_some();
            self.ebpf_network = setup.ebpf_network.take();
            if self.network_backend == Some(NetworkBackend::Ebpf) && !self.shared_network_created {
                self.network_persisted = true;
            }
        }
        self.persist_cleanup_journal()
    }

    fn track_network_context(
        &mut self,
        container_ip: String,
        ports: &[PortMappingRecord],
    ) -> Result<(), RuntimeError> {
        self.container_ip = Some(container_ip);
        self.port_mappings = ports.to_vec();
        self.persist_cleanup_journal()
    }

    fn adopt_backend(
        &mut self,
        backend: NetworkBackend,
        ownership: NetworkOwnershipRecord,
        ebpf_network: Option<EbpfNetwork>,
    ) -> Result<(), RuntimeError> {
        self.network_backend = Some(backend);
        self.network_ownership = Some(ownership);
        self.shared_network_created = ebpf_network.is_some();
        self.ebpf_network = ebpf_network;
        self.pending_firewall_cleanup.clear();
        if backend == NetworkBackend::Ebpf && !self.shared_network_created {
            self.network_persisted = true;
        }
        self.journal.record(NetworkMutationKind::BackendRecords);
        self.persist_cleanup_journal()
    }

    fn track_cgroup(&mut self, name: String) {
        self.cgroup_name = Some(name);
    }

    fn track_bridge_created(&mut self, name: String) -> Result<(), RuntimeError> {
        self.bridge_created = Some((name, None));
        self.journal.record(NetworkMutationKind::Bridge);
        self.persist_cleanup_journal()
    }

    fn identify_bridge(&mut self, ifindex: u32) -> Result<(), RuntimeError> {
        if let Some((_, identity)) = self.bridge_created.as_mut() {
            *identity = Some(ifindex);
        }
        self.persist_cleanup_journal()
    }

    fn track_namespace_created(&mut self, name: String) -> Result<(), RuntimeError> {
        self.netns_name = Some(name);
        self.journal.record(NetworkMutationKind::Namespace);
        self.persist_cleanup_journal()
    }

    fn identify_namespace(
        &mut self,
        identity: KernelObjectIdentityRecord,
    ) -> Result<(), RuntimeError> {
        self.namespace_identity = Some(identity);
        if let Some(ownership) = self.network_ownership.as_mut() {
            ownership.namespace_identity = Some(identity);
        }
        self.persist_cleanup_journal()
    }

    fn track_veth_created(&mut self, host: String) -> Result<(), RuntimeError> {
        self.host_veth = Some((host, None));
        self.journal.record(NetworkMutationKind::Veth);
        self.persist_cleanup_journal()
    }

    fn identify_veth(&mut self, ifindex: u32) -> Result<(), RuntimeError> {
        if let Some((host, identity)) = self.host_veth.as_mut() {
            *identity = Some(ifindex);
            if let Some(ownership) = self.network_ownership.as_mut() {
                ownership.host_interface = host.clone();
                ownership.host_ifindex = Some(ifindex);
            }
        }
        self.persist_cleanup_journal()
    }

    fn track_ip_forward(&mut self, ownership: GlobalValueOwnership) -> Result<(), RuntimeError> {
        self.ip_forward = Some(ownership);
        self.persist_cleanup_journal()
    }

    fn acquire_firewall_rollback(&mut self, command: Vec<String>) -> Result<(), RuntimeError> {
        self.pending_firewall_cleanup.push(command);
        self.persist_cleanup_journal()
    }

    fn persist_network(&mut self) -> Result<(), RuntimeError> {
        if let Some(network) = self.ebpf_network.take() {
            network
                .persist()
                .map_err(|error| RuntimeError::Network(error.to_string()))?;
            self.network_persisted = true;
            self.persist_cleanup_journal()?;
        }
        Ok(())
    }

    fn pending_cleanup(&self) -> PendingNetworkCleanup {
        PendingNetworkCleanup {
            schema_version: 1,
            container_id: self.container_id.clone(),
            netns_name: self.netns_name.clone(),
            namespace_identity: self.namespace_identity,
            host_veth: self.host_veth.clone(),
            container_ip: self.container_ip.clone(),
            port_mappings: self.port_mappings.clone(),
            network_backend: self.network_backend.map(|backend| backend.to_string()),
            network_ownership: self.network_ownership.clone(),
            network_persisted: self.network_persisted,
            shared_network_created: self.shared_network_created,
            bridge_created: self.bridge_created.clone(),
            ip_forward: self.ip_forward.clone(),
            pending_firewall_cleanup: self.pending_firewall_cleanup.clone(),
        }
    }

    fn cleanup_journal_path(&self) -> Option<PathBuf> {
        self.container_dir
            .as_ref()
            .map(|directory| directory.join("network-cleanup-pending.json"))
    }

    fn persist_cleanup_journal(&self) -> Result<(), RuntimeError> {
        let Some(path) = self.cleanup_journal_path() else {
            return Ok(());
        };
        let temporary = path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.pending_cleanup())
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    /// Commit the creation (prevent rollback).
    fn commit(mut self) {
        if let Some(path) = self.cleanup_journal_path() {
            if let Err(error) = fs::remove_file(path) {
                if error.kind() != io::ErrorKind::NotFound {
                    log::warn!("[network] failed to remove transferred cleanup journal: {error}");
                }
            }
        }
        self.committed = true;
    }

    /// Explicitly roll back all tracked resources.
    fn rollback(&mut self) {
        // Rollback cgroup - use configured cgroup_root, not hardcoded path
        if let Some(ref cgroup_name) = self.cgroup_name {
            let cgroup_path = self.cgroup_root.join(cgroup_name);
            if cgroup_path.exists() {
                if let Err(e) = fs::remove_dir(&cgroup_path) {
                    log::warn!("[rollback] failed to remove cgroup {}: {}", cgroup_name, e);
                }
            }
        }

        if !self.network_persisted {
            if let Some(mut network) = self.ebpf_network.take() {
                if let Err(error) = network.detach() {
                    log::warn!("[rollback] failed to detach prepared eBPF network: {error}");
                }
            }
        }
        let mut identity_cleanup_failure = false;
        let safe_netns = match (&self.netns_name, self.namespace_identity) {
            (Some(name), Some(expected)) if self.network_ownership.is_none() => {
                let path = Path::new("/var/run/netns").join(name);
                match fs::symlink_metadata(path) {
                    Ok(metadata)
                        if metadata.dev() == expected.device
                            && metadata.ino() == expected.inode =>
                    {
                        Some(name.as_str())
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    _ => {
                        identity_cleanup_failure = true;
                        log::warn!(
                            "[rollback] network namespace identity changed; refusing deletion"
                        );
                        None
                    }
                }
            }
            (Some(name), None) if self.network_ownership.is_none() => {
                if Path::new("/var/run/netns").join(name).exists() {
                    identity_cleanup_failure = true;
                    log::warn!("[rollback] network namespace identity is unavailable; refusing name-only deletion");
                }
                None
            }
            (Some(name), _) => Some(name.as_str()),
            _ => None,
        };
        let mut retain_container_dir = identity_cleanup_failure;
        while let Some(command) = self.pending_firewall_cleanup.pop() {
            if let Err(error) = run_cmd_allow_missing(&command) {
                retain_container_dir = true;
                log::warn!("[rollback] failed to remove provisional firewall state: {error}");
            }
        }
        if let Err(error) = cleanup_network_resources(
            &self.container_id,
            safe_netns,
            self.container_ip.as_deref(),
            &self.port_mappings,
            self.network_backend,
            self.network_ownership.as_ref(),
            self.shared_network_created && self.network_persisted,
        ) {
            retain_container_dir = true;
            log::warn!("[rollback] failed to clean network resources: {error}");
            if let Some(container_dir) = self.container_dir.as_ref() {
                let _ = self.persist_cleanup_journal();
            }
        }

        if self.network_ownership.is_none() {
            if let Some((host, expected_ifindex)) = self.host_veth.take() {
                let path = Path::new("/sys/class/net").join(&host);
                match (path.exists(), interface_ifindex(&host)) {
                    (false, _) => {}
                    (true, Ok(actual)) if expected_ifindex == Some(actual) => {
                        if let Err(error) = run_cmd_allow_missing(&[
                            "ip".to_string(),
                            "link".to_string(),
                            "delete".to_string(),
                            host,
                        ]) {
                            retain_container_dir = true;
                            log::warn!("[rollback] failed to remove owned veth: {error}");
                        }
                    }
                    _ => {
                        retain_container_dir = true;
                        log::warn!("[rollback] host veth identity changed; refusing deletion");
                    }
                }
            }
        }

        if let Some((bridge, expected_ifindex)) = self.bridge_created.take() {
            match interface_ifindex(&bridge) {
                Ok(actual) if expected_ifindex == Some(actual) => {
                    match bridge::build_ip_link_del_cmd(&bridge) {
                        Ok(command) => {
                            if let Err(error) = run_cmd_allow_missing(&command) {
                                retain_container_dir = true;
                                log::warn!("[rollback] failed to remove owned bridge: {error}");
                            }
                        }
                        Err(error) => {
                            retain_container_dir = true;
                            log::warn!("[rollback] invalid owned bridge cleanup: {error}");
                        }
                    }
                }
                Ok(actual) => {
                    retain_container_dir = true;
                    log::warn!(
                        "[rollback] bridge {bridge} identity changed from {expected_ifindex:?} to {actual}; refusing deletion"
                    );
                }
                Err(_) => {}
            }
        }

        if let Some(ownership) = self.ip_forward.take() {
            match restore_ip_forwarding(&ownership) {
                Ok(()) => {}
                Err(error) => {
                    retain_container_dir = true;
                    log::warn!("[rollback] failed to restore ip_forward: {error}");
                }
            }
        }

        if retain_container_dir {
            if let Some(container_dir) = self.container_dir.as_ref() {
                let _ = self.persist_cleanup_journal();
            }
        }

        // Rollback container directory
        if !retain_container_dir {
            if let Some(ref dir) = self.container_dir {
                if let Err(e) = fs::remove_dir_all(dir) {
                    log::warn!("[rollback] failed to remove container dir: {}", e);
                }
            }
        }

        self.committed = true; // Prevent double rollback
    }
}

impl Drop for CreationRollback {
    fn drop(&mut self) {
        if !self.committed {
            log::warn!(
                "[rollback] container {} creation failed, cleaning up resources",
                self.container_id
            );
            self.rollback();
        }
    }
}

fn recover_pending_network_cleanups(
    runtime_dir: &Path,
    store: &LocalContainerStore,
    cgroup_root: &Path,
    authorization: &RuntimeAuthorization,
) -> Result<(), RuntimeError> {
    let containers = runtime_dir.join("containers");
    let entries = match fs::read_dir(&containers) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let container_dir = entry.path();
        let journal_path = container_dir.join("network-cleanup-pending.json");
        let bytes = match fs::read(&journal_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let pending: PendingNetworkCleanup = serde_json::from_slice(&bytes).map_err(|error| {
            RuntimeError::Network(format!(
                "malformed pending cleanup journal {}: {error}",
                journal_path.display()
            ))
        })?;
        if entry.file_name().to_string_lossy() != pending.container_id {
            return Err(RuntimeError::Network(format!(
                "pending cleanup journal {} has a foreign container identity",
                journal_path.display()
            )));
        }
        let recovery = authorization.begin_internal_network_recovery(&pending.container_id)?;
        if store.get(&pending.container_id)?.is_some() {
            fs::remove_file(&journal_path)?;
            authorization.finish_internal_recovery(
                recovery,
                internal_cleanup_observation(&pending.container_id, true),
                true,
            )?;
            continue;
        }
        let mut rollback = CreationRollback::from_pending(
            container_dir.clone(),
            cgroup_root.to_path_buf(),
            pending,
        )?;
        rollback.rollback();
        if journal_path.exists() {
            authorization.finish_internal_recovery(
                recovery,
                internal_cleanup_observation(&entry.file_name().to_string_lossy(), false),
                false,
            )?;
            return Err(RuntimeError::Network(format!(
                "pending network cleanup for {} remains incomplete; inspect {}",
                entry.file_name().to_string_lossy(),
                journal_path.display()
            )));
        }
        authorization.finish_internal_recovery(
            recovery,
            internal_cleanup_observation(&entry.file_name().to_string_lossy(), true),
            true,
        )?;
    }
    Ok(())
}

fn internal_cleanup_observation(
    container_id: &str,
    absent: bool,
) -> crate::witness::ObservationDigest {
    let mut digest = sha2::Sha256::new();
    digest.update(b"ferrocrate/internal-cleanup-observation/v1");
    digest.update(container_id.as_bytes());
    digest.update([u8::from(absent)]);
    crate::witness::ObservationDigest::from_bytes(digest.finalize().into())
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("invalid image reference: {0}")]
    InvalidImage(#[from] crate::registry::RegistryError),
    #[error("container store error: {0}")]
    Store(#[from] ContainerStoreError),
    #[error("cgroup error: {0}")]
    Cgroup(#[from] crate::cgroups::CgroupError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("image store error: {0}")]
    ImageStore(#[from] crate::image_store::ImageStoreError),
    #[error("exec error: {0}")]
    Exec(#[from] crate::container_exec::ContainerExecError),
    #[error("process lifecycle error: {0}")]
    ProcessLifecycle(#[from] ProcessLifecycleError),
    #[error("rootfs error: {0}")]
    Rootfs(#[from] crate::rootfs::RootfsError),
    #[error("mount error: {0}")]
    Mount(#[from] MountError),
    #[error("mac profile error: {0}")]
    MacProfile(#[from] crate::mac_profiles::MacProfileError),
    #[error("network validation error: {0}")]
    NetworkValidation(#[from] ferro_net::ValidationError),
    #[error("container not found: {0}")]
    ContainerNotFound(String),
    #[error("command is required to run container")]
    MissingCommand,
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("invalid container state: {0}")]
    InvalidState(String),
    #[error("image not found in store: {0}")]
    ImageMissing(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("kernel version error: {0}")]
    Kernel(String),
    #[error("external command timed out after {0:?}")]
    Timeout(Duration),
    #[error("runtime mutation mediation failed: {0}")]
    Authorization(String),
    #[error("witness journal error: {0}")]
    Witness(#[from] crate::witness::JournalError),
}

impl From<MediationError> for RuntimeError {
    fn from(error: MediationError) -> Self {
        Self::Authorization(error.to_string())
    }
}

// CQ-02: Extract shared command parsing helper to fix duplication
fn parse_cmd_args(cmd: &[String]) -> Result<(&String, &[String]), RuntimeError> {
    cmd.split_first()
        .ok_or_else(|| RuntimeError::InvalidCommand("empty command".into()))
}

pub struct ContainerRuntime {
    store: LocalContainerStore,
    runtime_dir: PathBuf,
    cgroup_root: PathBuf,
    health_cancel: DashMap<String, Arc<AtomicBool>>,
    /// Cancellation tokens for resource monitor threads (Task 5.1)
    resource_cancel: DashMap<String, Arc<AtomicBool>>,
    authorization: RuntimeAuthorization,
    phase_hook: Arc<dyn LifecyclePhaseHook>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePhasePoint {
    DecisionDurable,
    ReservationDurable,
    EffectObserved,
    TerminalDurable,
    ReservationCleared,
}

pub trait LifecyclePhaseHook: Send + Sync {
    fn reached(&self, action: &str, phase: LifecyclePhasePoint) -> Result<(), RuntimeError>;
}

struct NoopLifecyclePhaseHook;
impl LifecyclePhaseHook for NoopLifecyclePhaseHook {
    fn reached(&self, _action: &str, _phase: LifecyclePhasePoint) -> Result<(), RuntimeError> {
        Ok(())
    }
}

struct NormalizedRunRequest {
    facts: RunSecurityFacts,
    capabilities: Vec<caps::Capability>,
    network_mode: String,
    network_backend: NetworkBackend,
    bind_mounts: Vec<BindMount>,
    tmpfs_mounts: Vec<TmpfsMount>,
    _bind_handles: Vec<std::fs::File>,
}

impl ContainerRuntime {
    pub fn new(runtime_dir: &Path) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let runtime_id = load_or_create_runtime_id(runtime_dir)?;
        Self::initialize(
            runtime_dir,
            RuntimeAuthorization::compatibility_with_id(runtime_id),
            Arc::new(NoopLifecyclePhaseHook),
        )
    }

    fn initialize(
        runtime_dir: &Path,
        authorization: RuntimeAuthorization,
        phase_hook: Arc<dyn LifecyclePhaseHook>,
    ) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let store = LocalContainerStore::open(runtime_dir.join("containers.db"))?;
        let cgroup_root = std::env::var("FERROCRATE_CGROUP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));
        let runtime = Self {
            store,
            runtime_dir: runtime_dir.to_path_buf(),
            cgroup_root,
            health_cancel: DashMap::new(),
            resource_cancel: DashMap::new(),
            authorization,
            phase_hook,
        };
        runtime.reconcile_pending_mutations()?;
        recover_pending_network_cleanups(
            runtime_dir,
            &runtime.store,
            &runtime.cgroup_root,
            &runtime.authorization,
        )?;
        runtime.reconcile_persisted_state()?;
        Ok(runtime)
    }

    /// Configure policy evaluation and optional durable witnessing. Supplying
    /// no journal keeps policy mediation enabled without persistence.
    pub fn new_with_authorization(
        runtime_dir: &Path,
        gate: Arc<AuthorizationGate>,
        journal: Option<Arc<crate::witness::WitnessJournal>>,
    ) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let runtime_id = load_or_create_runtime_id(runtime_dir)?;
        Self::initialize(
            runtime_dir,
            RuntimeAuthorization::new_with_id(gate, journal, runtime_id),
            Arc::new(NoopLifecyclePhaseHook),
        )
    }

    pub fn new_with_authorization_and_phase_hook(
        runtime_dir: &Path,
        gate: Arc<AuthorizationGate>,
        journal: Option<Arc<crate::witness::WitnessJournal>>,
        phase_hook: Arc<dyn LifecyclePhaseHook>,
    ) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let runtime_id = load_or_create_runtime_id(runtime_dir)?;
        Self::initialize(
            runtime_dir,
            RuntimeAuthorization::new_with_id(gate, journal, runtime_id),
            phase_hook,
        )
    }

    fn reconcile_persisted_state(&self) -> Result<(), RuntimeError> {
        let records = self.store.list()?;
        self.reconcile_network_state(&records)?;
        for mut record in records {
            if record.status != "running" && record.status != "paused" {
                continue;
            }
            if process_exists(record.pid) {
                continue;
            }

            log::warn!(
                "[reconcile] container {} had stale {} pid {}, marking exited",
                record.id,
                record.status,
                record.pid
            );
            let recovery = self
                .authorization
                .begin_internal_container_recovery(&record.id)?;
            record.status = "exited".to_string();
            if record.last_exit_code.is_none() {
                record.last_exit_code = Some(-1);
            }
            self.store.put(&record)?;
            self.authorization.finish_internal_recovery(
                recovery,
                internal_cleanup_observation(&record.id, true),
                true,
            )?;
            let _ = log_event(
                &self.runtime_dir,
                make_event(
                    "reconcile",
                    Some(&record.id),
                    Some(&record.image),
                    Some("exited"),
                    Some("stale pid not running"),
                ),
            );
            let _ = log_audit_event(
                &self.runtime_dir,
                make_audit_event(
                    "reconcile",
                    audit_actor().as_str(),
                    Some(&record.id),
                    Some(&record.image),
                    Some("exited"),
                    Some("stale pid not running"),
                ),
            );
        }
        Ok(())
    }

    fn reconcile_pending_mutations(&self) -> Result<(), RuntimeError> {
        let mut records = self.store.list()?;
        let Some(journal) = self.authorization.journal() else {
            for record in records {
                let Some(reservation) = record.pending_mutation else {
                    continue;
                };
                self.store
                    .finish_mutation(&record.id, reservation.operation_id)?;
            }
            return Ok(());
        };

        // The journal decision is durable before the store reservation. Enumerate
        // journal pending state first so a crash in that interval is discoverable.
        for pending in journal.pending()? {
            let operation = pending.operation_id();
            let matched = records.iter_mut().find(|record| {
                record
                    .pending_mutation
                    .as_ref()
                    .is_some_and(|reservation| reservation.operation_id == *operation.as_bytes())
            });
            let Some(record) = matched else {
                let tombstone = self.store.lifecycle_operation(*operation.as_bytes())?;
                let recovered_delete = tombstone.as_ref().is_some_and(|entry| {
                    entry.action == "container.delete"
                        && entry.phase == LifecyclePhase::StoreDeleted
                });
                journal.reconcile_observed(
                    operation,
                    recovery_observation_tombstone(
                        tombstone.as_ref(),
                        pending.recipe().original_action(),
                    ),
                    if recovered_delete {
                        crate::witness::RecoveryClassification::Recovered
                    } else {
                        crate::witness::RecoveryClassification::Quarantined
                    },
                )?;
                if tombstone.is_some() {
                    self.store.acknowledge_mutation(*operation.as_bytes())?;
                }
                continue;
            };
            let reservation = record
                .pending_mutation
                .clone()
                .expect("matched reservation");
            let action_matches = runtime_witness_action_name(pending.recipe().original_action())
                == reservation.action;
            let generation_matches =
                pending.recipe().resource_generation() == reservation.generation;
            let durable_operation = self.store.lifecycle_operation(reservation.operation_id)?;
            let truth_matches = action_matches
                && generation_matches
                && recovery_truth_matches(record, durable_operation.as_ref(), &reservation.action);
            let classification = if truth_matches {
                crate::witness::RecoveryClassification::Recovered
            } else {
                record.status = "quarantined".into();
                crate::witness::RecoveryClassification::Quarantined
            };
            let recovered_delete = reservation.action == "container.delete"
                && classification == crate::witness::RecoveryClassification::Recovered;
            if recovered_delete {
                self.store
                    .delete_for_mutation(&record.id, reservation.operation_id)?;
            } else {
                self.store.put(&record)?;
            }
            journal.reconcile_observed(
                operation,
                recovery_observation(Some(record), pending.recipe().original_action()),
                classification,
            )?;
            if recovered_delete {
                self.store.acknowledge_mutation(reservation.operation_id)?;
            } else {
                self.store
                    .finish_mutation(&record.id, reservation.operation_id)?;
            }
        }
        // A crash after the terminal journal flush but before store cleanup
        // leaves no journal-pending entry. The independent operation tree is
        // authoritative for completing that final idempotent clear.
        for operation in self.store.lifecycle_operations()? {
            let id = crate::witness::OperationId::from_bytes(operation.operation_id);
            if !matches!(
                journal.recover(id),
                Err(crate::witness::JournalError::AlreadyComplete)
            ) {
                continue;
            }
            if operation.phase == LifecyclePhase::StoreDeleted {
                self.store.acknowledge_mutation(operation.operation_id)?;
            } else if self.store.get(&operation.container_id)?.is_some() {
                self.store
                    .finish_mutation(&operation.container_id, operation.operation_id)?;
            }
        }
        Ok(())
    }

    fn reconcile_network_state(&self, records: &[ContainerRecord]) -> Result<(), RuntimeError> {
        let mut reconciled_networks = BTreeSet::new();
        for record in records
            .iter()
            .filter(|record| matches!(record.status.as_str(), "running" | "paused"))
        {
            self.reconcile_record_network(record, records, &mut reconciled_networks)?;
        }
        Ok(())
    }

    fn reconcile_record_network(
        &self,
        record: &ContainerRecord,
        records: &[ContainerRecord],
        reconciled_networks: &mut BTreeSet<String>,
    ) -> Result<(), RuntimeError> {
        if record.network_name.as_deref() != Some("bridge") {
            return Ok(());
        }
        if record.network_backend.is_none() || record.network_ownership.is_none() {
            classify_legacy_network_record(record.network_name.as_deref(), false)?;
        }
        let ownership = record.network_ownership.as_ref().ok_or_else(|| {
            RuntimeError::Network(format!(
                "bridge container {} has no network ownership",
                record.id
            ))
        })?;
        verify_container_kernel_ownership(record.netns.as_deref(), ownership, true)?;
        if record.network_backend.as_deref() != Some("ebpf") {
            return verify_firewall_ownership(record, ownership);
        }
        let network_id = ownership.network_id.as_deref().ok_or_else(|| {
            RuntimeError::Network("eBPF record has no network identity".to_string())
        })?;
        if reconciled_networks.insert(network_id.to_string()) {
            let group = records
                .iter()
                .filter(|candidate| {
                    candidate.network_backend.as_deref() == Some("ebpf")
                        && candidate
                            .network_ownership
                            .as_ref()
                            .and_then(|ownership| ownership.network_id.as_deref())
                            == Some(network_id)
                })
                .cloned()
                .collect::<Vec<_>>();
            self.reconcile_shared_ebpf_group(&group)?;
        }
        Ok(())
    }

    fn reconcile_shared_ebpf_group(&self, records: &[ContainerRecord]) -> Result<(), RuntimeError> {
        let first = records.first().ok_or_else(|| {
            RuntimeError::Network("cannot reconcile an empty eBPF network".to_string())
        })?;
        let ownership = first
            .network_ownership
            .as_ref()
            .ok_or_else(|| RuntimeError::Network("shared eBPF ownership is missing".to_string()))?;
        let config = ebpf_config_from_ownership(ownership)?;
        verify_recovery_host_contract(&config)?;
        verify_shared_ebpf_metadata(ownership, &config)?;
        for record in records.iter().skip(1) {
            let candidate = record.network_ownership.as_ref().ok_or_else(|| {
                RuntimeError::Network("shared eBPF ownership is missing".to_string())
            })?;
            if !same_shared_ebpf_ownership(ownership, candidate) {
                return Err(RuntimeError::Network(
                    "running records disagree about shared eBPF ownership".to_string(),
                ));
            }
        }
        match plan_network_recovery(observe_owned_ebpf_state(ownership)?)? {
            NetworkRecoveryAction::VerifyAndReuse => Ok(()),
            NetworkRecoveryAction::ReloadShared => {
                let interface = config.interface.clone();
                let before = shared_tc_filter_snapshot(&interface)?;
                let mut network = prepare_ebpf_classifiers(config)?
                    .attach()
                    .map_err(|error| RuntimeError::Network(error.to_string()))?;
                for record in records {
                    install_record_on_attached_network(&mut network, record)?;
                }
                let mut filters = shared_tc_filter_snapshot(&interface)?;
                filters.retain(|filter| !before.contains(filter));
                let network_id = ownership
                    .network_id
                    .as_deref()
                    .expect("validated network id");
                let pins = capture_ebpf_pins(&Path::new(FERRO_NETWORK_ROOT).join(network_id))?;
                if filters.len() != 4 || pins.is_empty() {
                    return Err(RuntimeError::Network(
                        "recovered eBPF network ownership capture is incomplete".to_string(),
                    ));
                }
                network
                    .persist()
                    .map_err(|error| RuntimeError::Network(error.to_string()))?;
                for record in records {
                    let mut updated = record.clone();
                    let updated_ownership = updated.network_ownership.as_mut().expect("validated");
                    updated_ownership.ebpf_filters = filters.clone();
                    updated_ownership.ebpf_pins = pins.clone();
                    self.store.put(&updated)?;
                }
                Ok(())
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        image: &str,
        cmd: &[String],
        env: &[String],
        labels: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
        health: Option<HealthConfig>,
        restart_policy: RestartPolicy,
        capabilities: &[caps::Capability],
        limits: Option<&ResourceLimits>,
        mounts: &[BindMount],
        tmpfs_mounts: &[TmpfsMount],
        readonly_rootfs: bool,
        no_new_privs: bool,
        workdir: Option<&str>,
        user: Option<&str>,
        name: Option<&str>,
        port_mappings: &[crate::container_store::PortMappingRecord],
        network_mode: &str,
        network_backend: NetworkBackend,
        ai_config: Option<&AiRuntimeConfig>,
    ) -> Result<ContainerRecord, RuntimeError> {
        let store = LocalImageStore::open(self.runtime_dir.join("images"))?;
        self.run_with_store(
            &store,
            image,
            cmd,
            env,
            labels,
            annotations,
            health,
            restart_policy,
            capabilities,
            limits,
            mounts,
            tmpfs_mounts,
            readonly_rootfs,
            no_new_privs,
            workdir,
            user,
            name,
            port_mappings,
            network_mode,
            network_backend,
            ai_config,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn run_with_store(
        &self,
        store: &LocalImageStore,
        image: &str,
        cmd: &[String],
        env: &[String],
        labels: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
        health: Option<HealthConfig>,
        restart_policy: RestartPolicy,
        capabilities: &[caps::Capability],
        limits: Option<&ResourceLimits>,
        mounts: &[BindMount],
        tmpfs_mounts: &[TmpfsMount],
        readonly_rootfs: bool,
        no_new_privs: bool,
        workdir: Option<&str>,
        user: Option<&str>,
        name: Option<&str>,
        port_mappings: &[crate::container_store::PortMappingRecord],
        network_mode: &str,
        network_backend: NetworkBackend,
        ai_config: Option<&AiRuntimeConfig>,
    ) -> Result<ContainerRecord, RuntimeError> {
        let container_id = generate_container_id();
        let pinned_image = store.resolve_reference(image)?.map_or_else(
            || image.to_owned(),
            |record| {
                format!(
                    "{}@{}",
                    record
                        .reference
                        .split('@')
                        .next()
                        .unwrap_or(&record.reference),
                    record.digest
                )
            },
        );
        let normalized = normalize_run_request(
            capabilities,
            mounts,
            tmpfs_mounts,
            readonly_rootfs,
            no_new_privs,
            network_mode,
            network_backend,
            port_mappings,
        )?;
        let mut candidate =
            ContainerRecord::authorization_candidate(container_id.clone(), pinned_image);
        candidate.capabilities = normalized.facts.capabilities.clone();
        candidate.network_name = Some(network_mode.to_owned());
        let permit = self
            .authorization
            .authorize_run(&candidate, &normalized.facts)?;
        self.phase_hook
            .reached("container.run", LifecyclePhasePoint::DecisionDurable)?;
        let creation_provenance = permit.creation_provenance();
        let operation_id = permit.operation_id();
        let witnessed = self.authorization.requires_provenance();
        if witnessed {
            candidate.creation_provenance = creation_provenance.clone();
            candidate.pending_mutation = Some(MutationReservation {
                operation_id,
                generation: candidate.mutation_generation,
                expected_status: candidate.status.clone(),
                action: "container.run".into(),
            });
            // Durable create provenance and reservation precede every external
            // creation side effect, closing the decision-to-store crash window.
            self.store.put_reserved_creation(&candidate)?;
            self.phase_hook
                .reached("container.run", LifecyclePhasePoint::ReservationDurable)?;
        }
        let (proof, intent) = permit.execution_authority();
        let authorized_image = proof
            .canonical()
            .image_reference()
            .unwrap_or(image)
            .to_owned();
        validate_normalized_run(proof, &normalized)?;
        let result = self.run_with_store_authorized(
            proof,
            intent,
            creation_provenance.clone(),
            container_id.clone(),
            store,
            &authorized_image,
            cmd,
            env,
            labels,
            annotations,
            health,
            restart_policy,
            &normalized.capabilities,
            limits,
            &normalized.bind_mounts,
            &normalized.tmpfs_mounts,
            normalized.facts.readonly_rootfs,
            normalized.facts.no_new_privileges,
            workdir,
            user,
            name,
            port_mappings,
            &normalized.network_mode,
            normalized.network_backend,
            ai_config,
        );
        if witnessed {
            self.store
                .mark_mutation_effect(&container_id, operation_id, result.is_ok())?;
            self.phase_hook
                .reached("container.run", LifecyclePhasePoint::EffectObserved)?;
        }
        self.authorization.complete(permit, result.is_ok())?;
        self.phase_hook
            .reached("container.run", LifecyclePhasePoint::TerminalDurable)?;
        if witnessed {
            self.store.finish_mutation(&container_id, operation_id)?;
            self.phase_hook
                .reached("container.run", LifecyclePhasePoint::ReservationCleared)?;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_store_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        creation_provenance: crate::container_store::CreationProvenance,
        container_id: String,
        store: &LocalImageStore,
        image: &str,
        cmd: &[String],
        env: &[String],
        labels: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
        health: Option<HealthConfig>,
        restart_policy: RestartPolicy,
        capabilities: &[caps::Capability],
        limits: Option<&ResourceLimits>,
        mounts: &[BindMount],
        tmpfs_mounts: &[TmpfsMount],
        readonly_rootfs: bool,
        no_new_privs: bool,
        workdir: Option<&str>,
        user: Option<&str>,
        name: Option<&str>,
        port_mappings: &[crate::container_store::PortMappingRecord],
        network_mode: &str,
        network_backend: NetworkBackend,
        ai_config: Option<&AiRuntimeConfig>,
    ) -> Result<ContainerRecord, RuntimeError> {
        parse_image_reference(image)?;
        ensure_kernel_min_version()?;
        verify_image_signature(image).map_err(|err| RuntimeError::InvalidState(err.to_string()))?;
        let mut config_json = None;
        if let Ok(Some(config_path)) =
            resolve_config_path_with_store(&self.runtime_dir, image, store)
        {
            if let Ok(json) = fs::read_to_string(config_path) {
                config_json = Some(json);
            }
        }

        let mut command = cmd.to_vec();
        if command.is_empty() {
            if let Some(json) = config_json.as_deref() {
                if let Some(from_config) = command_from_config(json) {
                    command = from_config;
                }
            }
        }
        if command.is_empty() {
            return Err(RuntimeError::MissingCommand);
        }

        let mut merged_env = if let Some(json) = config_json.as_deref() {
            env_from_config(json)
        } else {
            Vec::new()
        };
        merged_env.extend(env.iter().cloned());
        if let Some(ai) = ai_config {
            merged_env.extend(crate::ai_runtime::ai_runtime_env(ai));
        }
        let merged_env = dedup_env(merged_env);

        let resolved_workdir = workdir
            .map(|s| s.to_string())
            .or_else(|| config_json.as_deref().and_then(working_dir_from_config));
        let resolved_user = user
            .map(|s| s.to_string())
            .or_else(|| config_json.as_deref().and_then(user_from_config));

        // Create rollback guard for atomic operations (Task 4.1)
        let mut rollback = CreationRollback::new(&container_id, self.cgroup_root.clone());

        let exec_cmd = apply_apparmor_if_enabled(&self.runtime_dir, &container_id, &command)?;
        let exec_cmd = apply_selinux_if_enabled(&exec_cmd)?;
        let container_dir = self.runtime_dir.join("containers").join(&container_id);
        let log_dir = container_dir.join("logs");
        fs::create_dir_all(&log_dir)?;
        rollback.track_container_dir(container_dir.clone());

        let stdout_path = log_dir.join("stdout.log");
        let stderr_path = log_dir.join("stderr.log");

        let layer_paths = resolve_layer_paths_with_store(&self.runtime_dir, image, store)
            .map_err(|err| RuntimeError::ImageMissing(format!("{image}: {err}")))?;
        let rootfs_dir = container_dir.join("rootfs");
        if !layer_paths.is_empty() {
            let cas_root = self
                .runtime_dir
                .join("images")
                .join("file-cas")
                .join("shake256");
            construct_rootfs_with_dedup(&rootfs_dir, &layer_paths, &cas_root)?;
        } else {
            fs::create_dir_all(&rootfs_dir)?;
        }

        if !mounts.is_empty() {
            apply_authorized_bind_mounts(&rootfs_dir, mounts)?;
        }
        if !tmpfs_mounts.is_empty() {
            apply_tmpfs_mounts(&rootfs_dir, tmpfs_mounts)?;
        }
        if readonly_rootfs {
            apply_readonly_rootfs(&rootfs_dir)?;
        }

        validate_port_mapping_conflicts(&self.store, port_mappings)?;

        let rootless = !nix::unistd::Uid::effective().is_root();
        let existing_records = self.store.list()?;
        let mut network_setup = setup_network(
            &container_id,
            port_mappings,
            network_mode,
            network_backend,
            &mut rollback,
            &existing_records,
        )?;
        // Track network resources for rollback
        rollback.track_network(&mut network_setup, port_mappings)?;
        let netns_name = network_setup.netns_name.clone();
        let container_ip = network_setup.container_ip.clone();
        let container_ipv6 = network_setup.container_ipv6.clone();
        let unshare_netns = rootless && network_mode != "host" && rootless_netns_enabled();
        let use_slirp = unshare_netns && network_mode == "bridge";

        // Load seccomp profile for container isolation.
        // Guest authority uses the restricted guest profile; others use the default.
        let seccomp_profile = resolve_seccomp_profile(ai_config)?;

        let child_id = spawn_process_with_logs(
            &exec_cmd,
            &merged_env,
            &stdout_path,
            &stderr_path,
            false,
            self.store.clone_db(),
            container_id.clone(),
            Some(rootfs_dir.clone()),
            no_new_privs,
            restart_policy.clone(),
            capabilities.to_vec(),
            resolved_workdir.as_deref(),
            resolved_user.as_deref(),
            netns_name.as_deref(),
            unshare_netns,
            seccomp_profile.as_ref(),
        )
        .inspect_err(|_e| {
            // Kill any partially spawned process on error
            rollback.rollback();
        })?;

        if use_slirp {
            if let Err(e) = start_slirp4netns(child_id) {
                // Kill the process and roll back
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(e);
            }
        }
        if security_ebpf_monitor_enabled() {
            if let Err(e) = setup_security_ebpf_monitor(&container_id) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(e);
            }
        }

        if let Some(limits) = limits {
            let manager = CgroupV2Manager::new(&self.cgroup_root);
            let cgroup_name = format!("ferrocrate/{container_id}");
            let group = manager.create_group(&cgroup_name)?;
            rollback.track_cgroup(cgroup_name);
            if let Err(e) = manager.apply_limits(&group, limits) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(RuntimeError::Cgroup(e));
            }
            if let Err(e) = manager.add_pid(&group, child_id) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(RuntimeError::Cgroup(e));
            }
        }

        let health = if health.is_none() {
            resolve_config_path_with_store(&self.runtime_dir, image, store)
                .ok()
                .flatten()
                .and_then(|path| fs::read_to_string(path).ok())
                .and_then(|json| healthcheck_from_config(&json))
        } else {
            health
        };

        let record = ContainerRecord {
            id: container_id.clone(),
            name: name.map(|val| val.to_string()),
            pid: child_id,
            image: image.to_string(),
            command: command.clone(),
            workdir: resolved_workdir.clone(),
            user: resolved_user.clone(),
            env: merged_env,
            labels: labels.clone(),
            annotations: annotations.clone(),
            capabilities: capabilities.iter().map(|cap| cap.to_string()).collect(),
            health: health.clone(),
            health_status: if health.is_some() {
                "starting".to_string()
            } else {
                "none".to_string()
            },
            health_failures: 0,
            health_checked_at_unix: None,
            restart_policy: restart_policy.clone(),
            last_exit_code: None,
            created_at_unix: now_unix(),
            stdout_path: stdout_path.display().to_string(),
            stderr_path: stderr_path.display().to_string(),
            status: "running".to_string(),
            netns: netns_name.clone(),
            network_name: selected_network_name(network_mode),
            ip_address: container_ip.clone(),
            ipv6_address: container_ipv6.clone(),
            ports: port_mappings
                .iter()
                .map(|mapping| crate::container_store::PortMappingRecord {
                    host_port: mapping.host_port,
                    container_port: mapping.container_port,
                    protocol: mapping.protocol.clone(),
                })
                .collect(),
            network_backend: network_setup.backend.map(|backend| backend.to_string()),
            network_ownership: network_setup.ownership.clone(),
            managed_overlay: network_setup.managed_overlay.clone(),
            managed_host_veth: network_setup.managed_host_veth.clone(),
            ai_runtime: ai_config.cloned(),
            creation_provenance: creation_provenance.clone(),
            mutation_generation: 1,
            pending_mutation: creation_provenance.journal_id.map(|_| MutationReservation {
                operation_id: creation_provenance
                    .creator_operation_id
                    .expect("witnessed creation has operation identity"),
                generation: 1,
                expected_status: "created".into(),
                action: "container.run".into(),
            }),
        };

        rollback.persist_network()?;
        self.store.put(&record)?;

        // Commit the creation - all resources are now tracked in the store
        rollback.commit();

        if record.ip_address.is_some() {
            if let Ok(containers) = self.store.list() {
                let _ = update_container_hosts(&self.runtime_dir, &containers);
            }
        }
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "run",
                Some(&record.id),
                Some(&record.image),
                Some(&record.status),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "run",
                audit_actor().as_str(),
                Some(&record.id),
                Some(&record.image),
                Some(&record.status),
                None,
            ),
        );

        if let Some(config) = health {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let pid = record.pid;
            let cancel = Arc::new(AtomicBool::new(false));
            // Store cancellation token for later signaling
            self.health_cancel.insert(id.clone(), cancel.clone());
            thread::spawn(move || {
                run_health_checks(store, id, pid, config, cancel);
            });
        }

        // Task 5.1: Start resource monitor for OOM prediction if AI is enabled
        if is_ai_enabled() {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let cgroup_root = self.cgroup_root.clone();
            let memory_limit = limits.and_then(|l| l.memory_max).unwrap_or(0);
            let cancel = Arc::new(AtomicBool::new(false));
            self.resource_cancel.insert(id.clone(), cancel.clone());
            thread::spawn(move || {
                run_resource_monitor(store, id, cgroup_root, memory_limit, cancel);
            });
        }
        Ok(record)
    }

    pub fn exec(
        &self,
        id: &str,
        cmd: &[String],
    ) -> Result<crate::container_exec::ExecResult, RuntimeError> {
        let permit = self.authorize_existing(Action::ContainerExec, id)?;
        let operation_id = permit.operation_id();
        let (proof, intent) = permit.execution_authority();
        let result = self.exec_authorized(proof, intent, id, cmd);
        self.store
            .mark_mutation_effect(id, operation_id, result.is_ok())?;
        self.phase_hook
            .reached("container.exec", LifecyclePhasePoint::EffectObserved)?;
        self.authorization.complete(permit, result.is_ok())?;
        self.phase_hook
            .reached("container.exec", LifecyclePhasePoint::TerminalDurable)?;
        self.store.finish_mutation(id, operation_id)?;
        self.phase_hook
            .reached("container.exec", LifecyclePhasePoint::ReservationCleared)?;
        result
    }

    fn exec_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
        cmd: &[String],
    ) -> Result<crate::container_exec::ExecResult, RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let result = exec_in_container(record.pid, cmd)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("exec", Some(&record.id), Some(&record.image), None, None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "exec",
                audit_actor().as_str(),
                Some(&record.id),
                Some(&record.image),
                None,
                None,
            ),
        );
        Ok(result)
    }

    #[inline]
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

    #[inline]
    pub fn list(&self) -> Result<Vec<ContainerRecord>, RuntimeError> {
        Ok(self.store.list()?)
    }

    #[inline]
    pub fn inspect(&self, id: &str) -> Result<ContainerRecord, RuntimeError> {
        self.store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))
    }

    #[inline]
    pub fn stats(&self, id: &str) -> Result<CgroupStats, RuntimeError> {
        let _record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let manager = CgroupV2Manager::new(&self.cgroup_root);
        let group_path = self.cgroup_root.join("ferrocrate").join(id);
        Ok(manager.read_stats(group_path)?)
    }

    pub fn pause(&self, id: &str) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerPause, id, |runtime, proof, intent| {
            runtime.pause_authorized(proof, intent, id)
        })
    }

    fn pause_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
    ) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let manager = CgroupV2Manager::new(&self.cgroup_root);
        let group = manager.create_group(&format!("ferrocrate/{id}"))?;
        manager.add_pid(&group, record.pid)?;
        manager.freeze(&group)?;
        self.store.update_status(id, "paused")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("pause", Some(id), Some(&record.image), Some("paused"), None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "pause",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("paused"),
                None,
            ),
        );
        Ok(())
    }

    pub fn resume(&self, id: &str) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerResume, id, |runtime, proof, intent| {
            runtime.resume_authorized(proof, intent, id)
        })
    }

    fn resume_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
    ) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let manager = CgroupV2Manager::new(&self.cgroup_root);
        let group = manager.create_group(&format!("ferrocrate/{id}"))?;
        manager.add_pid(&group, record.pid)?;
        manager.thaw(&group)?;
        self.store.update_status(id, "running")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "resume",
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "resume",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );
        Ok(())
    }

    pub fn stop(&self, id: &str, timeout: Duration) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerStop, id, |runtime, proof, intent| {
            runtime.stop_authorized(proof, intent, id, timeout)
        })
    }

    fn stop_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        // Signal health check thread to stop
        if let Some((_, cancel)) = self.health_cancel.remove(id) {
            cancel.store(true, Ordering::Relaxed);
        }
        // Signal resource monitor thread to stop (Task 5.1)
        if let Some((_, cancel)) = self.resource_cancel.remove(id) {
            cancel.store(true, Ordering::Relaxed);
        }

        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        stop_pid(record.pid, timeout)?;
        self.store.update_status(id, "stopped")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("stop", Some(id), Some(&record.image), Some("stopped"), None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "stop",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("stopped"),
                None,
            ),
        );
        Ok(())
    }

    pub fn kill(&self, id: &str) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerKill, id, |runtime, proof, intent| {
            runtime.kill_authorized(proof, intent, id)
        })
    }

    fn kill_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
    ) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        kill_pid(record.pid)?;
        self.store.update_status(id, "killed")?;
        let _ = log_event(
            &self.runtime_dir,
            make_event("kill", Some(id), Some(&record.image), Some("killed"), None),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "kill",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("killed"),
                None,
            ),
        );
        Ok(())
    }

    pub fn restart(&self, id: &str, timeout: Duration) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerRestart, id, |runtime, proof, intent| {
            runtime.restart_authorized(proof, intent, id, timeout)
        })
    }

    fn restart_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
        timeout: Duration,
    ) -> Result<(), RuntimeError> {
        let mut record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if record.command.is_empty() {
            return Err(RuntimeError::MissingCommand);
        }

        let records = self.store.list()?;
        self.reconcile_record_network(&record, &records, &mut BTreeSet::new())?;

        stop_pid(record.pid, timeout)?;

        let stdout_path = PathBuf::from(&record.stdout_path);
        let stderr_path = PathBuf::from(&record.stderr_path);

        // Load seccomp profile for restarted container.
        // Uses the authority stored in the container record, if present.
        let seccomp_profile = resolve_seccomp_profile(record.ai_runtime.as_ref())?;

        let child_id = spawn_process_with_logs(
            &record.command,
            &record.env,
            &stdout_path,
            &stderr_path,
            true,
            self.store.clone_db(),
            record.id.clone(),
            Some(self.runtime_dir.join("containers").join(id).join("rootfs")),
            false,
            record.restart_policy.clone(),
            parse_capabilities(&record.capabilities),
            record.workdir.as_deref(),
            record.user.as_deref(),
            record.netns.as_deref(),
            false,
            seccomp_profile.as_ref(),
        )?;
        if security_ebpf_monitor_enabled() {
            setup_security_ebpf_monitor(&record.id)?;
        }

        record.pid = child_id;
        record.status = "running".to_string();
        self.store.put(&record)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "restart",
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "restart",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("running"),
                None,
            ),
        );

        if let Some(config) = record.health.clone() {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let pid = record.pid;
            let cancel = Arc::new(AtomicBool::new(false));
            // Store cancellation token for later signaling
            self.health_cancel.insert(id.clone(), cancel.clone());
            thread::spawn(move || {
                run_health_checks(store, id, pid, config, cancel);
            });
        }

        // Task 5.1: Start resource monitor for OOM prediction if AI is enabled
        if is_ai_enabled() {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let cgroup_root = self.cgroup_root.clone();
            // Read memory limit from cgroup for restarted containers
            let cgroup_path = cgroup_root.join("ferrocrate").join(&id);
            let memory_limit = ferro_mind::ai::resource::read_cgroup_metrics(&cgroup_path)
                .ok()
                .and_then(|m| {
                    if m.memory_max > 0 {
                        Some(m.memory_max)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let cancel = Arc::new(AtomicBool::new(false));
            self.resource_cancel.insert(id.clone(), cancel.clone());
            thread::spawn(move || {
                run_resource_monitor(store, id, cgroup_root, memory_limit, cancel);
            });
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerDelete, id, |runtime, proof, intent| {
            runtime.remove_authorized(proof, intent, id)
        })
    }

    fn remove_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
    ) -> Result<(), RuntimeError> {
        // Clean up health check cancellation token if present
        if let Some((_, cancel)) = self.health_cancel.remove(id) {
            cancel.store(true, Ordering::Relaxed);
        }
        // Clean up resource monitor cancellation token (Task 5.1)
        if let Some((_, cancel)) = self.resource_cancel.remove(id) {
            cancel.store(true, Ordering::Relaxed);
        }

        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if self.authorization.requires_provenance()
            && !self.authorization.provenance_matches(&record)
        {
            self.store.update_status(id, "quarantined")?;
            return Err(RuntimeError::InvalidState(format!(
                "container {id} has unverifiable creation provenance and was quarantined"
            )));
        }
        if record.status == "running" {
            return Err(RuntimeError::InvalidState(format!(
                "container {id} is still running"
            )));
        }
        let records = self.store.list()?;
        cleanup_network(&record, &records)?;
        let container_dir = self.runtime_dir.join("containers").join(id);
        if let Err(e) = fs::remove_dir_all(&container_dir) {
            log::warn!("[cleanup] failed to remove container dir for {id}: {e}");
        }
        self.store.update_status(id, "removed-pending")?;
        if let Ok(containers) = self.store.list() {
            if let Err(e) = update_container_hosts(&self.runtime_dir, &containers) {
                warn!("failed to update hosts file: {e}");
            }
        }
        // Logging is best-effort - don't fail if logging fails
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "remove",
                Some(id),
                Some(&record.image),
                Some("removed"),
                None,
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "remove",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some("removed"),
                None,
            ),
        );
        Ok(())
    }

    fn authorize_existing(
        &self,
        action: Action,
        id: &str,
    ) -> Result<crate::authorization::runtime::MutationPermit, RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let permit = self.authorization.authorize(action, &record)?;
        self.phase_hook.reached(
            runtime_action_name(action),
            LifecyclePhasePoint::DecisionDurable,
        )?;
        let current = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if let Err(error) = self.authorization.revalidate(&permit, &current) {
            self.authorization.complete(permit, false)?;
            return Err(error.into());
        }
        if let Err(error) = self.store.reserve_mutation(
            id,
            &current.status,
            current.mutation_generation.max(1),
            permit.operation_id(),
            runtime_action_name(action),
        ) {
            self.authorization.complete(permit, false)?;
            return Err(error.into());
        }
        self.phase_hook.reached(
            runtime_action_name(action),
            LifecyclePhasePoint::ReservationDurable,
        )?;
        Ok(permit)
    }

    fn mediate_existing<T>(
        &self,
        action: Action,
        id: &str,
        execute: impl FnOnce(
            &Self,
            &AuthorizedRequest,
            Option<&crate::witness::DurableIntent>,
        ) -> Result<T, RuntimeError>,
    ) -> Result<T, RuntimeError> {
        let permit = self.authorize_existing(action, id)?;
        let operation_id = permit.operation_id();
        let (proof, intent) = permit.execution_authority();
        let result = execute(self, proof, intent);
        let freezer_state = match action {
            Action::ContainerPause | Action::ContainerResume => fs::read_to_string(
                self.cgroup_root
                    .join("ferrocrate")
                    .join(id)
                    .join("cgroup.freeze"),
            )
            .ok()
            .and_then(|value| match value.trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            }),
            _ => None,
        };
        self.store.mark_mutation_effect_observed(
            id,
            operation_id,
            result.is_ok(),
            freezer_state,
        )?;
        self.phase_hook.reached(
            runtime_action_name(action),
            LifecyclePhasePoint::EffectObserved,
        )?;
        if action == Action::ContainerDelete && result.is_ok() {
            self.store.delete_for_mutation(id, operation_id)?;
            self.authorization.complete(permit, true)?;
            self.phase_hook.reached(
                runtime_action_name(action),
                LifecyclePhasePoint::TerminalDurable,
            )?;
            self.store.acknowledge_mutation(operation_id)?;
            self.phase_hook.reached(
                runtime_action_name(action),
                LifecyclePhasePoint::ReservationCleared,
            )?;
        } else {
            self.authorization.complete(permit, result.is_ok())?;
            self.phase_hook.reached(
                runtime_action_name(action),
                LifecyclePhasePoint::TerminalDurable,
            )?;
            self.store.finish_mutation(id, operation_id)?;
            self.phase_hook.reached(
                runtime_action_name(action),
                LifecyclePhasePoint::ReservationCleared,
            )?;
        }
        result
    }
}
fn generate_container_id() -> String {
    // Use cryptographic randomness for unpredictable container IDs
    // Previously used predictable format: c<timestamp>-<pid>
    use std::fmt::Write;
    let mut rng = rand::rng();
    let random_bytes: [u8; 16] = rng.random();
    let mut hex = String::with_capacity(32);
    for byte in random_bytes {
        write!(&mut hex, "{byte:02x}").expect("hex format");
    }
    hex
}

#[allow(clippy::too_many_arguments)]
fn normalize_run_request(
    capabilities: &[caps::Capability],
    mounts: &[BindMount],
    tmpfs_mounts: &[TmpfsMount],
    readonly_rootfs: bool,
    no_new_privileges: bool,
    network_mode: &str,
    network_backend: NetworkBackend,
    ports: &[PortMappingRecord],
) -> Result<NormalizedRunRequest, RuntimeError> {
    let mut handles = Vec::with_capacity(mounts.len());
    let mut normalized_mounts = Vec::with_capacity(mounts.len());
    let mut mount_facts = Vec::with_capacity(mounts.len() + tmpfs_mounts.len());
    for mount in mounts {
        if mount.source.starts_with("/proc/self/fd") {
            return Err(RuntimeError::InvalidState(
                "caller-supplied runtime fd mount is forbidden".into(),
            ));
        }
        let source = mount.source.canonicalize()?;
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(nix::libc::O_PATH | nix::libc::O_CLOEXEC);
        let handle = options.open(&source)?;
        let metadata = handle.metadata()?;
        let fd = handle.as_raw_fd();
        let mount_id = fd_mount_id(fd)?;
        let target = normalize_mount_target(&mount.target)?;
        mount_facts.push(RunMountFact {
            class: if mount.read_only {
                crate::authorization::MountClass::ReadOnly
            } else {
                crate::authorization::MountClass::HostPath
            },
            mount_id,
            device_id: metadata.dev(),
            inode: metadata.ino(),
            open_flags: u64::from(mount.read_only),
            target_digest: mount_target_digest(&target),
        });
        normalized_mounts.push(BindMount {
            source: PathBuf::from(format!("/proc/self/fd/{fd}")),
            target,
            read_only: mount.read_only,
        });
        handles.push(handle);
    }
    let normalized_tmpfs = tmpfs_mounts
        .iter()
        .map(|mount| {
            Ok(TmpfsMount {
                target: normalize_mount_target(&mount.target)?,
                size: mount.size.clone(),
            })
        })
        .collect::<Result<Vec<_>, MountError>>()?;
    for (index, mount) in normalized_tmpfs.iter().enumerate() {
        let mut digest = sha2::Sha256::new();
        digest.update(b"ferrocrate/tmpfs-binding/v1");
        digest.update(mount.target.as_os_str().as_bytes());
        if let Some(size) = &mount.size {
            digest.update(size.as_bytes());
        }
        let digest: [u8; 32] = digest.finalize().into();
        mount_facts.push(RunMountFact {
            class: crate::authorization::MountClass::Tmpfs,
            mount_id: u64::MAX - index as u64,
            device_id: 0,
            inode: u64::from_be_bytes(digest[..8].try_into().expect("digest width")),
            open_flags: 0,
            target_digest: mount_target_digest(&mount.target),
        });
    }
    let mut network_ids = vec![
        format!("mode:{network_mode}"),
        format!("backend:{network_backend:?}"),
    ];
    network_ids.extend(ports.iter().map(|port| {
        format!(
            "port:{}:{}/{}",
            port.host_port, port.container_port, port.protocol
        )
    }));
    Ok(NormalizedRunRequest {
        facts: RunSecurityFacts {
            capabilities: capabilities.iter().map(ToString::to_string).collect(),
            mounts: mount_facts,
            network_ids,
            privileged: capabilities.contains(&caps::Capability::CAP_SYS_ADMIN),
            readonly_rootfs,
            no_new_privileges,
        },
        capabilities: capabilities.to_vec(),
        network_mode: network_mode.to_owned(),
        network_backend,
        bind_mounts: normalized_mounts,
        tmpfs_mounts: normalized_tmpfs,
        _bind_handles: handles,
    })
}

fn fd_mount_id(fd: i32) -> Result<u64, RuntimeError> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:\t"))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            RuntimeError::InvalidState("opened mount has no kernel mount identity".into())
        })
}

fn mount_target_digest(target: &Path) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    digest.update(b"ferrocrate/mount-target/v1");
    digest.update(target.as_os_str().as_bytes());
    digest.finalize().into()
}

fn recovery_truth_matches(
    record: &ContainerRecord,
    operation: Option<&LifecycleOperation>,
    action: &str,
) -> bool {
    match action {
        "container.exec" => operation.is_some_and(|operation| {
            operation.phase == LifecyclePhase::EffectApplied
                && operation.result_digest.is_some()
                && operation.pid_after == Some(record.pid)
                && operation.process_start_time_after == process_start_time_for_pid(record.pid)
        }),
        "container.pause" => {
            record.status == "paused"
                && operation.and_then(|op| op.state_after.as_deref()) == Some("paused")
                && operation.and_then(|op| op.freezer_state_after) == Some(true)
        }
        "container.resume" => {
            record.status == "running"
                && operation.and_then(|op| op.state_after.as_deref()) == Some("running")
                && operation.and_then(|op| op.freezer_state_after) == Some(false)
                && process_exists(record.pid)
        }
        "container.stop" | "container.kill" => operation.is_some_and(|operation| {
            let expected = if action == "container.stop" {
                "stopped"
            } else {
                "killed"
            };
            record.status == expected
                && operation.state_after.as_deref() == Some(expected)
                && process_start_time_for_pid(operation.pid) != operation.process_start_time
        }),
        "container.restart" => {
            record.status == "running"
                && process_exists(record.pid)
                && operation.is_some_and(|op| {
                    op.execution_generation_after == Some(op.generation.saturating_add(1))
                        && op.pid_after == Some(record.pid)
                        && op.process_start_time_after == process_start_time_for_pid(record.pid)
                })
        }
        "container.delete" => record.status == "removed-pending",
        "container.run" => record.creation_provenance.is_verifiable(),
        _ => false,
    }
}

fn process_start_time_for_pid(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn recovery_observation(
    record: Option<&ContainerRecord>,
    action: crate::witness::WitnessAction,
) -> crate::witness::ObservationDigest {
    let mut digest = sha2::Sha256::new();
    digest.update(b"ferrocrate/live-recovery-observation/v1");
    digest.update([action as u8]);
    if let Some(record) = record {
        digest.update(record.id.as_bytes());
        digest.update(record.status.as_bytes());
        digest.update(record.pid.to_be_bytes());
        digest.update(record.mutation_generation.to_be_bytes());
        digest.update([u8::from(process_exists(record.pid))]);
    } else {
        digest.update(b"reservation-absent");
    }
    crate::witness::ObservationDigest::from_bytes(digest.finalize().into())
}

fn recovery_observation_tombstone(
    operation: Option<&LifecycleOperation>,
    action: crate::witness::WitnessAction,
) -> crate::witness::ObservationDigest {
    let mut digest = sha2::Sha256::new();
    digest.update(b"ferrocrate/live-recovery-tombstone/v1");
    digest.update([action as u8]);
    if let Some(operation) = operation {
        digest.update(operation.operation_id);
        digest.update(operation.container_id.as_bytes());
        digest.update(operation.generation.to_be_bytes());
        digest.update(operation.ownership_digest);
        digest.update([operation.phase as u8]);
    } else {
        digest.update(b"operation-absent");
    }
    crate::witness::ObservationDigest::from_bytes(digest.finalize().into())
}

fn validate_normalized_run(
    proof: &AuthorizedRequest,
    normalized: &NormalizedRunRequest,
) -> Result<(), RuntimeError> {
    let facts = proof.canonical().context().facts();
    if facts.requested_capabilities() != normalized.facts.capabilities
        || facts.network_ids() != normalized.facts.network_ids
        || facts.privileged() != normalized.facts.privileged
        || facts.readonly_rootfs() != normalized.facts.readonly_rootfs
        || facts.no_new_privileges() != normalized.facts.no_new_privileges
        || proof.canonical().mount_handles().len() != normalized.facts.mounts.len()
    {
        return Err(RuntimeError::Authorization(
            "authorized run facts became stale".into(),
        ));
    }
    for (expected, observed) in proof
        .canonical()
        .mount_handles()
        .iter()
        .zip(&normalized.facts.mounts)
    {
        if expected.class() != observed.class
            || expected.mount_id() != observed.mount_id
            || expected.device_id() != observed.device_id
            || expected.inode() != observed.inode
            || expected.open_flags() != observed.open_flags
            || expected.target_digest() != &observed.target_digest
        {
            return Err(RuntimeError::Authorization(
                "authorized mount identity became stale".into(),
            ));
        }
    }
    for (index, handle) in normalized._bind_handles.iter().enumerate() {
        let metadata = handle.metadata()?;
        let observed = &normalized.facts.mounts[index];
        if metadata.dev() != observed.device_id
            || metadata.ino() != observed.inode
            || fd_mount_id(handle.as_raw_fd())? != observed.mount_id
        {
            return Err(RuntimeError::Authorization(
                "authorized mount handle was replaced".into(),
            ));
        }
    }
    Ok(())
}

fn runtime_action_name(action: Action) -> &'static str {
    match action {
        Action::ContainerRun => "container.run",
        Action::ContainerExec => "container.exec",
        Action::ContainerPause => "container.pause",
        Action::ContainerResume => "container.resume",
        Action::ContainerStop => "container.stop",
        Action::ContainerKill => "container.kill",
        Action::ContainerRestart => "container.restart",
        Action::ContainerDelete => "container.delete",
        _ => "container.unsupported",
    }
}

fn runtime_witness_action_name(action: crate::witness::WitnessAction) -> &'static str {
    match action {
        crate::witness::WitnessAction::ContainerRun => "container.run",
        crate::witness::WitnessAction::ContainerExec => "container.exec",
        crate::witness::WitnessAction::ContainerPause => "container.pause",
        crate::witness::WitnessAction::ContainerResume => "container.resume",
        crate::witness::WitnessAction::ContainerStop => "container.stop",
        crate::witness::WitnessAction::ContainerKill => "container.kill",
        crate::witness::WitnessAction::ContainerRestart => "container.restart",
        crate::witness::WitnessAction::ContainerDelete => "container.delete",
        _ => "container.unsupported",
    }
}

fn load_or_create_runtime_id(runtime_dir: &Path) -> Result<[u8; 16], RuntimeError> {
    let path = runtime_dir.join("runtime-instance-id");
    match fs::read(&path) {
        Ok(bytes) => {
            return bytes.try_into().map_err(|_| {
                RuntimeError::Authorization("runtime instance identity is malformed".into())
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let id: [u8; 16] = rand::rng().random();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    match options.open(&path) {
        Ok(mut file) => {
            file.write_all(&id)?;
            file.sync_all()?;
            Ok(id)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let bytes = fs::read(path)?;
            bytes.try_into().map_err(|_| {
                RuntimeError::Authorization("runtime instance identity is malformed".into())
            })
        }
        Err(error) => Err(error.into()),
    }
}

fn process_exists(pid: u32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn spawn_process_with_logs(
    cmd: &[String],
    env: &[String],
    stdout_path: &Path,
    stderr_path: &Path,
    append: bool,
    store: sled::Db,
    container_id: String,
    rootfs_dir: Option<PathBuf>,
    no_new_privs: bool,
    restart_policy: RestartPolicy,
    capabilities: Vec<caps::Capability>,
    workdir: Option<&str>,
    user: Option<&str>,
    netns_name: Option<&str>,
    unshare_netns: bool,
    seccomp_profile: Option<&SeccompProfile>,
) -> Result<u32, RuntimeError> {
    let command = build_command(
        cmd,
        env,
        rootfs_dir.as_deref(),
        no_new_privs,
        &capabilities,
        workdir,
        user,
        netns_name,
        unshare_netns,
        seccomp_profile,
    )?;
    let (child_id, child) = spawn_child_with_logs(command, stdout_path, stderr_path, append)?;

    let cmd_owned = cmd.to_vec();
    let env_owned = env.to_vec();
    let stdout_path = stdout_path.to_path_buf();
    let stderr_path = stderr_path.to_path_buf();
    let rootfs_dir = rootfs_dir.clone();
    let caps_for_restart = capabilities.clone();
    let workdir = workdir.map(|val| val.to_string());
    let user = user.map(|val| val.to_string());
    let netns_name = netns_name.map(|val| val.to_string());
    let seccomp_for_restart = seccomp_profile.cloned();
    thread::spawn(move || {
        supervise_child(
            child,
            store,
            container_id,
            cmd_owned,
            env_owned,
            stdout_path,
            stderr_path,
            append,
            rootfs_dir,
            no_new_privs,
            restart_policy,
            caps_for_restart,
            workdir,
            user,
            netns_name,
            seccomp_for_restart,
        );
    });

    Ok(child_id)
}

#[allow(clippy::too_many_arguments)]
fn build_command(
    cmd: &[String],
    env: &[String],
    rootfs_dir: Option<&Path>,
    no_new_privs: bool,
    capabilities: &[caps::Capability],
    workdir: Option<&str>,
    user: Option<&str>,
    netns_name: Option<&str>,
    unshare_netns: bool,
    seccomp_profile: Option<&SeccompProfile>,
) -> Result<Command, RuntimeError> {
    let running_as_root = nix::unistd::Uid::effective().is_root();
    let direct_container_setup = running_as_root && (netns_name.is_some() || rootfs_dir.is_some());

    let mut command = if direct_container_setup {
        let mut direct_cmd = Command::new(&cmd[0]);
        direct_cmd.args(&cmd[1..]);
        direct_cmd
    } else if let Some(netns) = netns_name {
        let mut netns_cmd = Command::new("ip");
        netns_cmd.arg("netns").arg("exec").arg(netns);
        if let Some(rootfs) = rootfs_dir {
            if running_as_root {
                netns_cmd
                    .arg("chroot")
                    .arg(rootfs)
                    .arg(&cmd[0])
                    .args(&cmd[1..]);
            } else {
                netns_cmd.arg(&cmd[0]).args(&cmd[1..]);
            }
        } else {
            netns_cmd.arg(&cmd[0]).args(&cmd[1..]);
        }
        netns_cmd
    } else if unshare_netns {
        let mut unshare_cmd = Command::new("unshare");
        unshare_cmd.arg("-n").arg("--");
        unshare_cmd.arg(&cmd[0]);
        unshare_cmd.args(&cmd[1..]);
        unshare_cmd
    } else if let Some(rootfs) = rootfs_dir {
        if running_as_root {
            let mut chroot_cmd = Command::new("chroot");
            chroot_cmd.arg(rootfs);
            chroot_cmd.arg(&cmd[0]);
            chroot_cmd.args(&cmd[1..]);
            chroot_cmd
        } else if command_available("bwrap") {
            let mut bwrap_cmd = Command::new("bwrap");
            let root_cmd = resolve_rootfs_command(rootfs, &cmd[0]);
            bwrap_cmd
                .arg("--bind")
                .arg(rootfs)
                .arg("/")
                .arg("--proc")
                .arg("/proc")
                .arg("--dev")
                .arg("/dev")
                .arg("--chdir")
                .arg("/")
                .arg("--setenv")
                .arg("PATH")
                .arg("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
            bwrap_cmd.arg(root_cmd);
            bwrap_cmd.args(&cmd[1..]);
            bwrap_cmd
        } else {
            return Err(RuntimeError::InvalidCommand(
                "rootfs execution requires root (chroot) or bubblewrap (bwrap)".to_string(),
            ));
        }
    } else {
        let mut host_cmd = Command::new(&cmd[0]);
        host_cmd.args(&cmd[1..]);
        host_cmd
    };

    for entry in env {
        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if key.is_empty() {
            return Err(RuntimeError::InvalidState(
                "env var missing key".to_string(),
            ));
        }
        command.env(key, value);
    }

    if let Some(dir) = workdir.filter(|_| !direct_container_setup) {
        command.current_dir(dir);
    }

    if let Some(user_spec) = user {
        if running_as_root && !direct_container_setup {
            if let Some((uid, gid)) = parse_user_spec(user_spec) {
                command.uid(uid);
                command.gid(gid);
            }
        }
    }

    let caps = capabilities.to_vec();
    let seccomp = seccomp_profile.cloned();
    let seccomp_permissive = seccomp_permissive_mode();
    let setup_netns = if direct_container_setup {
        netns_name.map(str::to_string)
    } else {
        None
    };
    let setup_rootfs = if direct_container_setup {
        rootfs_dir.map(Path::to_path_buf)
    } else {
        None
    };
    let setup_workdir = if direct_container_setup {
        workdir.map(str::to_string)
    } else {
        None
    };
    let setup_user = if direct_container_setup {
        user.map(str::to_string)
    } else {
        None
    };
    unsafe {
        command.pre_exec(move || {
            if let Some(netns) = setup_netns.as_deref() {
                enter_runtime_netns(netns).map_err(|err| {
                    io::Error::new(err.kind(), format!("pre_exec enter netns {netns}: {err}"))
                })?;
            }
            if let Some(rootfs) = setup_rootfs.as_deref() {
                enter_runtime_rootfs(rootfs, setup_workdir.as_deref()).map_err(|err| {
                    io::Error::new(err.kind(), format!("pre_exec enter rootfs: {err}"))
                })?;
            }
            if let Some(user_spec) = setup_user.as_deref() {
                apply_runtime_identity(user_spec).map_err(|err| {
                    io::Error::new(
                        err.kind(),
                        format!("pre_exec set identity {user_spec}: {err}"),
                    )
                })?;
            }
            if no_new_privs {
                if let Err(err) = set_no_new_privileges() {
                    if err.raw_os_error() == Some(nix::libc::EINVAL)
                        || err.raw_os_error() == Some(nix::libc::EPERM)
                    {
                        warn!("pre_exec ignoring no_new_privs error: {err}");
                    } else {
                        return Err(io::Error::new(
                            err.kind(),
                            format!("pre_exec set no_new_privs: {err}"),
                        ));
                    }
                }
            }
            let is_root = nix::unistd::Uid::effective().is_root();
            if is_root {
                if caps.is_empty() {
                    drop_all_capabilities().map_err(|err| {
                        std::io::Error::other(format!("pre_exec drop capabilities: {err}"))
                    })?;
                } else {
                    set_capabilities(&caps).map_err(|err| {
                        std::io::Error::other(format!("pre_exec set capabilities: {err}"))
                    })?;
                }
            }
            // Apply seccomp profile AFTER capability drops (seccomp is last sandboxing step)
            if let Some(profile) = &seccomp {
                if let Err(err) = apply_seccomp_profile(profile) {
                    let err_text = err.to_string();
                    let invalid_arg = err_text.contains("Invalid argument")
                        || err_text.contains("invalid argument");
                    if !seccomp_permissive && !invalid_arg {
                        return Err(std::io::Error::other(err.to_string()));
                    }
                    warn!("seccomp apply failed, continuing without seccomp: {}", err);
                }
            }
            Ok(())
        });
    }

    Ok(command)
}

fn enter_runtime_netns(netns_name: &str) -> io::Result<()> {
    let path = netns::netns_path(netns_name);
    let file = fs::File::open(&path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("open netns {}: {}", path.display(), err),
        )
    })?;
    nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET)
        .map_err(|err| io::Error::from_raw_os_error(err as i32))
}

fn enter_runtime_rootfs(rootfs: &Path, workdir: Option<&str>) -> io::Result<()> {
    let path = CString::new(rootfs.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "rootfs path contains NUL"))?;
    let rc = unsafe { nix::libc::chroot(path.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    std::env::set_current_dir(container_workdir(workdir))
}

fn container_workdir(workdir: Option<&str>) -> String {
    match workdir.map(str::trim).filter(|dir| !dir.is_empty()) {
        Some("/") | None => "/".to_string(),
        Some(dir) if dir.starts_with('/') => dir.to_string(),
        Some(dir) => format!("/{dir}"),
    }
}

fn apply_runtime_identity(user_spec: &str) -> io::Result<()> {
    let Some((uid, gid)) = parse_user_spec(user_spec) else {
        return Ok(());
    };
    nix::unistd::setgid(nix::unistd::Gid::from_raw(gid))
        .map_err(|err| io::Error::other(err.to_string()))?;
    nix::unistd::setuid(nix::unistd::Uid::from_raw(uid))
        .map_err(|err| io::Error::other(err.to_string()))
}

fn set_no_new_privileges() -> io::Result<()> {
    let rc = unsafe {
        nix::libc::prctl(
            nix::libc::PR_SET_NO_NEW_PRIVS,
            1 as nix::libc::c_ulong,
            0 as nix::libc::c_ulong,
            0 as nix::libc::c_ulong,
            0 as nix::libc::c_ulong,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn resolve_rootfs_command(rootfs: &Path, cmd: &str) -> String {
    if cmd.contains('/') {
        return cmd.to_string();
    }
    let search_dirs = [
        "usr/local/sbin",
        "usr/local/bin",
        "usr/sbin",
        "usr/bin",
        "sbin",
        "bin",
    ];
    for dir in search_dirs {
        let candidate = rootfs.join(dir).join(cmd);
        if candidate.exists() {
            return format!("/{}", [dir, cmd].join("/"));
        }
    }
    cmd.to_string()
}

fn spawn_child_with_logs(
    mut command: Command,
    stdout_path: &Path,
    stderr_path: &Path,
    append: bool,
) -> Result<(u32, Child), RuntimeError> {
    let stdout_file = if append {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(stdout_path)?
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(stdout_path)?
    };
    let stderr_file = if append {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(stderr_path)?
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(stderr_path)?
    };
    let child = command
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()?;
    let child_id = child.id();
    Ok((child_id, child))
}

#[allow(clippy::too_many_arguments)]
fn supervise_child(
    mut child: Child,
    store: sled::Db,
    container_id: String,
    cmd: Vec<String>,
    env: Vec<String>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    append: bool,
    rootfs_dir: Option<PathBuf>,
    no_new_privs: bool,
    restart_policy: RestartPolicy,
    capabilities: Vec<caps::Capability>,
    workdir: Option<String>,
    user: Option<String>,
    netns_name: Option<String>,
    seccomp_profile: Option<SeccompProfile>,
) {
    let mut adaptive_policy = ferro_mind::ai::restart::AdaptiveRestartPolicy::new(&container_id);
    let mut restart_count: u32 = 0;
    let mut container_start_time = std::time::Instant::now();

    loop {
        let status = child.wait();
        let exit_code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
        let current_status = match update_exit(&store, &container_id, exit_code) {
            Ok(status) => status,
            Err(_) => "exited".to_string(),
        };

        let uptime_secs = container_start_time.elapsed().as_secs();
        adaptive_policy.record_restart(exit_code, uptime_secs);

        if !should_restart(&restart_policy, &current_status, exit_code) {
            break;
        }

        // Get adaptive delay (respects learned patterns)
        let adaptive_signal = ferro_mind::ai::restart::RestartSignal {
            exit_code,
            recent_failures: restart_count,
            uptime_secs,
        };
        let delay_secs = match adaptive_policy.decide(&adaptive_signal) {
            ferro_mind::ai::restart::RestartDecision::RestartAfterDelay { delay_secs } => {
                delay_secs
            }
            ferro_mind::ai::restart::RestartDecision::DoNotRestart => {
                // Adaptive policy says don't restart, but honor the existing policy too
                1 // Fall back to minimum delay; should_restart check above already handles the quit case
            }
            ferro_mind::ai::restart::RestartDecision::Restart => 1,
        };
        thread::sleep(Duration::from_secs(delay_secs.max(1)));
        let command = match build_command(
            &cmd,
            &env,
            rootfs_dir.as_deref(),
            no_new_privs,
            &capabilities,
            workdir.as_deref(),
            user.as_deref(),
            netns_name.as_deref(),
            false,
            seccomp_profile.as_ref(),
        ) {
            Ok(cmd) => cmd,
            Err(_) => break,
        };
        let (pid, new_child) =
            match spawn_child_with_logs(command, &stdout_path, &stderr_path, append) {
                Ok(tuple) => tuple,
                Err(_) => break,
            };
        if let Err(e) = update_pid_status(&store, &container_id, pid, "running") {
            warn!("failed to update pid status for {container_id}: {e}");
        }
        child = new_child;
        container_start_time = std::time::Instant::now();
        adaptive_policy.record_outcome(ferro_mind::ai::restart::RestartOutcome::Success);
        restart_count += 1;
    }
}

fn parse_capabilities(entries: &[String]) -> Vec<caps::Capability> {
    entries
        .iter()
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let normalized = if trimmed.starts_with("CAP_") {
                trimmed.to_string()
            } else {
                format!("CAP_{}", trimmed)
            };
            normalized.parse::<caps::Capability>().ok()
        })
        .collect()
}

fn dedup_env(entries: Vec<String>) -> Vec<String> {
    let mut seen: HashMap<String, String> = HashMap::with_capacity(entries.len());
    let mut order: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = entry.split('=').next().unwrap_or("").trim().to_string();
        if key.is_empty() {
            continue;
        }
        if !seen.contains_key(&key) {
            order.push(key.clone());
        }
        seen.insert(key, entry);
    }
    order
        .into_iter()
        .filter_map(|key| seen.remove(&key))
        .collect()
}

fn parse_user_spec(value: &str) -> Option<(u32, u32)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.splitn(2, ':');
    let uid = parts.next()?.parse::<u32>().ok()?;
    let gid = parts
        .next()
        .and_then(|g| g.parse::<u32>().ok())
        .unwrap_or(uid);
    Some((uid, gid))
}

fn audit_actor() -> String {
    std::env::var("FERROCRATE_AUDIT_ACTOR").unwrap_or_else(|_| "cli".to_string())
}

fn ensure_kernel_min_version() -> Result<(), RuntimeError> {
    if std::env::var("FERROCRATE_IGNORE_KERNEL_MIN")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return Ok(());
    }
    // Use nix crate to get kernel version (no shell-out)
    let utsname =
        nix::sys::utsname::uname().map_err(|e| RuntimeError::Io(std::io::Error::other(e)))?;
    let version = utsname.release().to_string_lossy();
    let mut parts = version.split(['.', '-']);
    let major = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    if major < 5 || (major == 5 && minor < 10) {
        return Err(RuntimeError::Kernel(format!(
            "kernel {version} below required 5.10"
        )));
    }
    Ok(())
}

struct NetworkSetup {
    netns_name: Option<String>,
    container_ip: Option<String>,
    container_ipv6: Option<String>,
    backend: Option<NetworkBackend>,
    ownership: Option<NetworkOwnershipRecord>,
    ebpf_network: Option<EbpfNetwork>,
    managed_overlay: Option<String>,
    managed_host_veth: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedEbpfAction {
    PrepareAndAttach,
    VerifyAndReuse,
}

fn bridge_network_id(bridge: &str, cidr: &str) -> String {
    let digest = rvf_crypto::shake256_256(format!("bridge\0{bridge}\0{cidr}").as_bytes());
    format!("bridge-{}", hex::encode(&digest[..12]))
}

fn shared_ebpf_action<'a>(
    network_id: &str,
    existing_network_ids: impl IntoIterator<Item = &'a str>,
) -> SharedEbpfAction {
    if existing_network_ids
        .into_iter()
        .any(|existing| existing == network_id)
    {
        SharedEbpfAction::VerifyAndReuse
    } else {
        SharedEbpfAction::PrepareAndAttach
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkMutationKind {
    Bridge,
    Namespace,
    Veth,
    BackendRecords,
    Shaping,
}

#[derive(Debug, Default)]
struct NetworkMutationJournal {
    completed: Vec<NetworkMutationKind>,
}

impl NetworkMutationJournal {
    fn record(&mut self, mutation: NetworkMutationKind) {
        self.completed.push(mutation);
    }

    #[cfg(test)]
    fn rollback_order(&self) -> Vec<NetworkMutationKind> {
        self.completed.iter().rev().copied().collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedNetworkState {
    Complete,
    CompletelyMissing,
    PartialOrReplaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkRecoveryAction {
    VerifyAndReuse,
    ReloadShared,
}

fn plan_network_recovery(
    observed: ObservedNetworkState,
) -> Result<NetworkRecoveryAction, RuntimeError> {
    match observed {
        ObservedNetworkState::Complete => Ok(NetworkRecoveryAction::VerifyAndReuse),
        ObservedNetworkState::CompletelyMissing => Ok(NetworkRecoveryAction::ReloadShared),
        ObservedNetworkState::PartialOrReplaced => Err(RuntimeError::Network(
            "partial or replaced owned network state requires operator repair".to_string(),
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnedResourceState {
    Present,
    Missing,
}

fn verify_kernel_identity(
    expected: KernelIdentity,
    observed: Option<KernelIdentity>,
) -> Result<OwnedResourceState, RuntimeError> {
    match observed {
        None => Ok(OwnedResourceState::Missing),
        Some(observed) if observed == expected => Ok(OwnedResourceState::Present),
        Some(observed) => Err(RuntimeError::Network(format!(
            "owned kernel resource identity changed: expected {}:{}, found {}:{}",
            expected.device, expected.inode, observed.device, observed.inode
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyNetworkAction {
    NotManagedBridge,
    CleanupProvenRules,
}

fn classify_legacy_network_record(
    network_name: Option<&str>,
    ownership_proven: bool,
) -> Result<LegacyNetworkAction, RuntimeError> {
    if network_name != Some("bridge") {
        return Ok(LegacyNetworkAction::NotManagedBridge);
    }
    if ownership_proven {
        Ok(LegacyNetworkAction::CleanupProvenRules)
    } else {
        Err(RuntimeError::Network(
            "legacy bridge record has no ownership metadata; networking was not removed. Recreate the original rules or remove them manually, then migrate the record"
                .to_string(),
        ))
    }
}

impl NetworkSetup {
    fn isolated(
        netns_name: Option<String>,
        container_ip: Option<String>,
        container_ipv6: Option<String>,
    ) -> Self {
        Self {
            netns_name,
            container_ip,
            container_ipv6,
            backend: None,
            ownership: None,
            ebpf_network: None,
            managed_overlay: None,
            managed_host_veth: None,
        }
    }
}

fn setup_network(
    container_id: &str,
    port_mappings: &[crate::container_store::PortMappingRecord],
    network_mode: &str,
    network_backend: NetworkBackend,
    rollback: &mut CreationRollback,
    existing_records: &[ContainerRecord],
) -> Result<NetworkSetup, RuntimeError> {
    if let Some(overlay_id) = network_mode.strip_prefix("managed:") {
        return setup_managed_network(container_id, overlay_id, network_backend, rollback);
    }
    match network_mode {
        "host" => {
            if !port_mappings.is_empty() {
                return Err(RuntimeError::Network(
                    "port mapping requires network bridge".to_string(),
                ));
            }
            return Ok(NetworkSetup::isolated(None, None, None));
        }
        "none" => {
            if !port_mappings.is_empty() {
                return Err(RuntimeError::Network(
                    "port mapping requires network bridge".to_string(),
                ));
            }
            if !nix::unistd::Uid::effective().is_root() {
                return Ok(NetworkSetup::isolated(None, None, None));
            }
            let netns_name = format!("ferro-{container_id}");
            run_cmd(&netns::build_ip_netns_add_cmd(&netns_name)?)?;
            rollback.track_namespace_created(netns_name.clone())?;
            let identity = kernel_path_identity(&netns::netns_path(&netns_name))?;
            rollback.identify_namespace(identity)?;
            run_cmd(&ip_netns_exec(
                &netns_name,
                &["ip", "link", "set", "lo", "up"],
            ))?;
            return Ok(NetworkSetup::isolated(Some(netns_name), None, None));
        }
        "bridge" => {}
        "wireguard" => {
            if !nix::unistd::Uid::effective().is_root() {
                return Err(RuntimeError::Network("wireguard requires root".to_string()));
            }
            if !port_mappings.is_empty() {
                return Err(RuntimeError::Network(
                    "port mapping requires network bridge".to_string(),
                ));
            }
            let netns_name = format!("ferro-{container_id}");
            run_cmd(&netns::build_ip_netns_add_cmd(&netns_name)?)?;
            rollback.track_namespace_created(netns_name.clone())?;
            let identity = kernel_path_identity(&netns::netns_path(&netns_name))?;
            rollback.identify_namespace(identity)?;
            run_cmd(&ip_netns_exec(
                &netns_name,
                &["ip", "link", "set", "lo", "up"],
            ))?;
            let (ipv4, ipv6) = setup_wireguard(&netns_name, container_id)?;
            return Ok(NetworkSetup::isolated(Some(netns_name), ipv4, ipv6));
        }
        _ => {
            return Err(RuntimeError::Network(
                "network mode must be one of: bridge, host, none, wireguard".to_string(),
            ))
        }
    }

    ensure_bridge_backend_root(nix::unistd::Uid::effective().is_root(), network_backend)?;
    let active_backend = resolve_network_backend(network_backend, &RuntimeBackendProbe)?;
    debug_assert_eq!(active_backend, network_backend);
    info!(
        requested_backend = %network_backend,
        active_backend = %active_backend,
        "network backend selected"
    );
    let bridge_config = bridge_config()?;
    let network_id = bridge_network_id(&bridge_config.name, &bridge_config.cidr);
    let mut ebpf_preparation = if active_backend == NetworkBackend::Ebpf {
        Some(prepare_shared_ebpf_network(&network_id, existing_records)?)
    } else {
        None
    };
    let bridge_exec_config = bridge::BridgeConfig {
        name: bridge_config.name.clone(),
        cidr: bridge_config.cidr.clone(),
        ipv6_cidr: bridge_config.ipv6_cidr.clone(),
    };
    let bridge_existed = Path::new("/sys/class/net")
        .join(&bridge_config.name)
        .exists();
    match bridge::create_bridge(&bridge_exec_config) {
        Ok(()) => {
            if !bridge_existed {
                rollback.track_bridge_created(bridge_config.name.clone())?;
            }
        }
        Err(err) => {
            let err_text = err.to_string();
            // Preserve previous idempotent behavior for repeated setup calls.
            if !err_text.contains("File exists") {
                return Err(RuntimeError::Network(err_text));
            }
        }
    }
    let bridge_ifindex = interface_ifindex(&bridge_config.name)?;
    if !bridge_existed {
        rollback.identify_bridge(bridge_ifindex)?;
    }
    ensure_ip_forwarding(rollback)?;
    let subnet = network_cidr_v4(&bridge_config.gateway, bridge_config.prefix)
        .map_err(RuntimeError::Network)?;
    let netns_name = format!("ferro-{container_id}");
    run_cmd(&netns::build_ip_netns_add_cmd(&netns_name)?)?;
    rollback.track_namespace_created(netns_name.clone())?;
    let namespace_identity = kernel_path_identity(&netns::netns_path(&netns_name))?;
    rollback.identify_namespace(namespace_identity)?;

    let host_veth = format!("veth{}", short_id(container_id, 8));
    let host_veth = if host_veth.len() > 15 {
        host_veth[..15].to_string()
    } else {
        host_veth
    };
    // The container-side peer must NOT be named "eth0" while in the host namespace:
    // it would collide with the host's own eth0 (common on VMs/cloud) → EEXIST.
    // Create it with a unique name, move it into the netns, then rename to eth0 there.
    let cont_veth = format!("vc{}", short_id(container_id, 8));
    let veth_config = veth::VethConfig {
        pair: veth::VethPair {
            host: host_veth.clone(),
            container: cont_veth.clone(),
        },
        mtu: None,
        host_addr: None,
        container_addr: None,
    };
    run_cmd(&veth::build_ip_link_add_veth_cmd(&veth_config)?)?;
    rollback.track_veth_created(host_veth.clone())?;
    let host_ifindex = interface_ifindex(&host_veth)?;
    rollback.identify_veth(host_ifindex)?;
    run_cmd(&bridge::build_ip_link_set_master_cmd(
        &host_veth,
        &bridge_config.name,
    )?)?;
    run_cmd(&veth::build_ip_link_set_up_cmd(&host_veth)?)?;
    run_cmd(&netns::build_ip_link_set_netns_cmd(
        &cont_veth,
        &netns_name,
    )?)?;
    // Rename the moved interface to eth0 inside the netns (while still down).
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", &cont_veth, "name", "eth0"],
    ))?;

    let container_ip = allocate_container_ip(container_id, &bridge_config.gateway)?;
    rollback.track_network_context(container_ip.clone(), port_mappings)?;
    let container_ipv6 = if let Some((gateway, prefix)) = bridge_config
        .ipv6_gateway
        .as_ref()
        .zip(bridge_config.ipv6_prefix)
    {
        Some(allocate_container_ipv6(container_id, gateway, prefix))
    } else {
        None
    };
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", "lo", "up"],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &[
            "ip",
            "addr",
            "add",
            &format!("{container_ip}/{}", bridge_config.prefix),
            "dev",
            "eth0",
        ],
    ))?;
    if let Some(ipv6) = container_ipv6.as_ref() {
        run_cmd(&ip_netns_exec(
            &netns_name,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                &format!("{ipv6}/{}", bridge_config.ipv6_prefix.unwrap_or(64)),
                "dev",
                "eth0",
            ],
        ))?;
    }
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", "eth0", "up"],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &[
            "ip",
            "route",
            "add",
            "default",
            "via",
            &bridge_config.gateway,
        ],
    ))?;
    if let Some(gateway) = bridge_config.ipv6_gateway.as_ref() {
        run_cmd(&ip_netns_exec(
            &netns_name,
            &[
                "ip",
                "-6",
                "route",
                "add",
                "default",
                "via",
                &gateway.to_string(),
            ],
        ))?;
    }

    let plan = build_network_plan(
        active_backend,
        container_id,
        port_mappings,
        &container_ip,
        &subnet,
        &bridge_config.name,
    )?;
    let ownership = match active_backend {
        NetworkBackend::Ebpf => setup_ebpf_backend(
            ebpf_preparation.take().expect("eBPF preparation"),
            container_id,
            &host_veth,
            &netns_name,
            &container_ip,
            port_mappings,
            &subnet,
            &bridge_config.name,
            bridge_ifindex,
            host_ifindex,
            namespace_identity,
            rollback,
        ),
        NetworkBackend::Iptables | NetworkBackend::Nftables => {
            let firewall_expected_state =
                apply_and_capture_network_plan(active_backend, &plan, rollback)?;
            let ownership = NetworkOwnershipRecord {
                schema_version: 2,
                owner_id: container_id.to_string(),
                network_id: Some(network_id.clone()),
                host_interface: host_veth.clone(),
                host_ifindex: Some(host_ifindex),
                namespace_identity: Some(namespace_identity),
                managed_interface: None,
                managed_ifindex: None,
                loopback_ifindex: None,
                bridge_ifindex: Some(bridge_ifindex),
                source_cidr: Some(subnet.clone()),
                bridge: Some(bridge_config.name.clone()),
                firewall_id: plan.firewall_id().map(str::to_string),
                firewall_marker: plan.ownership_marker(),
                firewall_expected_state: Some(firewall_expected_state),
                ebpf_pin_path: None,
                external_ipv4: None,
                next_hop_mac: None,
                snat_port_start: None,
                snat_port_end: None,
                object_sha256: None,
                object_abi: None,
                ebpf_filters: Vec::new(),
                ebpf_pins: Vec::new(),
            };
            rollback.adopt_backend(active_backend, ownership.clone(), None)?;
            Ok(ownership)
        }
    };
    let ownership = ownership?;

    if let Some(limit) = bandwidth_limit().as_deref() {
        apply_bandwidth_limit(&host_veth, limit)?;
        rollback.journal.record(NetworkMutationKind::Shaping);
    }

    Ok(NetworkSetup {
        netns_name: Some(netns_name),
        container_ip: Some(container_ip),
        container_ipv6,
        backend: Some(active_backend),
        ownership: Some(ownership),
        ebpf_network: None,
        managed_overlay: None,
        managed_host_veth: None,
    })
}

#[cfg(target_os = "linux")]
fn setup_managed_network(
    container_id: &str,
    overlay_id: &str,
    _network_backend: NetworkBackend,
    rollback: &mut CreationRollback,
) -> Result<NetworkSetup, RuntimeError> {
    if !nix::unistd::Uid::effective().is_root() {
        return Err(RuntimeError::Network(
            "managed overlay requires root".to_string(),
        ));
    }
    let socket = std::env::var("FERROCRATE_AGENT_SOCKET")
        .unwrap_or_else(|_| "/run/ferrocrate/agent.sock".to_string());
    let request = ManagedOverlayRequest::AttachContainer {
        overlay_id: overlay_id.to_string(),
        container_id: container_id.to_string(),
        now_unix: crate::container_store::now_unix() as i64,
    };
    let response = ManagedOverlayClient::new(socket)
        .request(&request)
        .map_err(|error| {
            RuntimeError::Network(format!("managed overlay agent unavailable: {error}"))
        })?;
    let ManagedOverlayResponse::Attached(attachment) = response else {
        return Err(RuntimeError::Network(
            "managed overlay agent rejected attachment".to_string(),
        ));
    };
    let netns_name = attachment.netns.clone();
    run_cmd(&netns::build_ip_netns_add_cmd(&netns_name)?)?;
    rollback.track_namespace_created(netns_name.clone())?;
    rollback.identify_namespace(kernel_path_identity(&netns::netns_path(&netns_name))?)?;
    let host_veth = format!("veth{}", short_id(container_id, 8));
    let host_veth = host_veth[..host_veth.len().min(15)].to_string();
    let cont_veth = format!("vc{}", short_id(container_id, 8));
    let config = veth::VethConfig {
        pair: veth::VethPair {
            host: host_veth.clone(),
            container: cont_veth.clone(),
        },
        mtu: Some(attachment.mtu.into()),
        host_addr: None,
        container_addr: None,
    };
    run_cmd(&veth::build_ip_link_add_veth_cmd(&config)?)?;
    rollback.track_veth_created(host_veth.clone())?;
    let host_ifindex = interface_ifindex(&host_veth)?;
    rollback.identify_veth(host_ifindex)?;
    rollback.host_veth = Some((host_veth.clone(), Some(host_ifindex)));
    rollback.netns_name = Some(netns_name.clone());
    run_cmd(&bridge::build_ip_link_set_master_cmd(
        &host_veth,
        &attachment.bridge,
    )?)?;
    run_cmd(&veth::build_ip_link_set_up_cmd(&host_veth)?)?;
    run_cmd(&netns::build_ip_link_set_netns_cmd(
        &cont_veth,
        &netns_name,
    )?)?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", &cont_veth, "name", "eth0"],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", "lo", "up"],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &[
            "ip",
            "addr",
            "add",
            &format!("{}/{}", attachment.ipv4, attachment.prefix),
            "dev",
            "eth0",
        ],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "link", "set", "eth0", "up"],
    ))?;
    run_cmd(&ip_netns_exec(
        &netns_name,
        &["ip", "route", "add", "default", "via", &attachment.gateway],
    ))?;
    rollback.track_network_context(attachment.ipv4.clone(), &[])?;
    let mut setup =
        NetworkSetup::isolated(Some(netns_name), Some(attachment.ipv4), attachment.ipv6);
    setup.managed_overlay = Some(overlay_id.to_string());
    setup.managed_host_veth = Some(host_veth);
    Ok(setup)
}

fn build_network_plan(
    backend: NetworkBackend,
    owner_id: &str,
    port_mappings: &[PortMappingRecord],
    container_ip: &str,
    source_cidr: &str,
    bridge: &str,
) -> Result<NetworkPlan, RuntimeError> {
    let mappings = port_mappings
        .iter()
        .map(|mapping| ferro_net::portmap::PortMapping {
            host_port: mapping.host_port,
            container_port: mapping.container_port,
            protocol: mapping.protocol.clone(),
        })
        .collect::<Vec<_>>();
    build_portmap_plan(
        backend,
        owner_id,
        &mappings,
        container_ip,
        source_cidr,
        bridge,
    )
    .map_err(|error| RuntimeError::Network(error.to_string()))
}

trait FirewallCommandRunner {
    fn run(&mut self, command: &[String]) -> Result<(), RuntimeError>;
    fn run_cleanup(&mut self, command: &[String]) -> Result<(), RuntimeError> {
        self.run(command)
    }
    fn capture(
        &mut self,
        backend: NetworkBackend,
        firewall_id: &str,
    ) -> Result<Option<String>, RuntimeError>;
}

struct HostFirewallCommandRunner;

impl FirewallCommandRunner for HostFirewallCommandRunner {
    fn run(&mut self, command: &[String]) -> Result<(), RuntimeError> {
        run_cmd(command)
    }

    fn run_cleanup(&mut self, command: &[String]) -> Result<(), RuntimeError> {
        run_cmd_allow_missing(command)
    }

    fn capture(
        &mut self,
        backend: NetworkBackend,
        firewall_id: &str,
    ) -> Result<Option<String>, RuntimeError> {
        capture_firewall_owned_state(backend, firewall_id)
    }
}

fn cleanup_firewall_plan_with<R: FirewallCommandRunner>(
    backend: NetworkBackend,
    plan: &NetworkPlan,
    expected_state: &str,
    runner: &mut R,
) -> Result<(), RuntimeError> {
    let firewall_id = plan
        .firewall_id()
        .ok_or_else(|| RuntimeError::Network("firewall plan has no ownership id".to_string()))?;
    let Some(mut live_state) = runner.capture(backend, firewall_id)? else {
        return Ok(());
    };
    verify_resumable_firewall_state(expected_state, &live_state)?;
    for command in plan.cleanup_commands() {
        runner.run_cleanup(command)?;
        match runner.capture(backend, firewall_id)? {
            Some(current) => {
                verify_resumable_firewall_state(expected_state, &current)?;
                live_state = current;
            }
            None => return Ok(()),
        }
    }
    if live_state.trim().is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::Network(
            "owned firewall cleanup left residual state".to_string(),
        ))
    }
}

fn apply_and_capture_network_plan(
    backend: NetworkBackend,
    plan: &NetworkPlan,
    rollback: &mut CreationRollback,
) -> Result<String, RuntimeError> {
    let mut runner = HostFirewallCommandRunner;
    apply_and_capture_network_plan_with(backend, plan, rollback, &mut runner)
}

trait FirewallRollbackSink {
    fn clear(&mut self);
    fn acquire(&mut self, command: Vec<String>) -> Result<(), RuntimeError>;
}

impl FirewallRollbackSink for CreationRollback {
    fn clear(&mut self) {
        self.pending_firewall_cleanup.clear();
    }

    fn acquire(&mut self, command: Vec<String>) -> Result<(), RuntimeError> {
        self.acquire_firewall_rollback(command)
    }
}

impl FirewallRollbackSink for Vec<Vec<String>> {
    fn clear(&mut self) {
        Vec::clear(self);
    }

    fn acquire(&mut self, command: Vec<String>) -> Result<(), RuntimeError> {
        self.push(command);
        Ok(())
    }
}

fn apply_and_capture_network_plan_with<R: FirewallCommandRunner, S: FirewallRollbackSink>(
    backend: NetworkBackend,
    plan: &NetworkPlan,
    acquired_rollback: &mut S,
    runner: &mut R,
) -> Result<String, RuntimeError> {
    let firewall_id = plan
        .firewall_id()
        .ok_or_else(|| RuntimeError::Network("firewall plan has no ownership id".to_string()))?;
    acquired_rollback.clear();
    let mut previous = runner.capture(backend, firewall_id)?;
    for (index, command) in plan.commands().iter().enumerate() {
        runner.run(command)?;
        let current = runner.capture(backend, firewall_id)?.ok_or_else(|| {
            RuntimeError::Network(format!(
                "firewall mutation {} succeeded without an observable owned object",
                command.join(" ")
            ))
        })?;
        if previous.as_deref() == Some(current.as_str()) {
            return Err(RuntimeError::Network(format!(
                "firewall mutation {} did not acquire a distinct owned object",
                command.join(" ")
            )));
        }
        for rollback_command in plan.rollback_commands_for(index) {
            acquired_rollback.acquire(rollback_command)?;
        }
        previous = Some(current);
    }
    let state = previous.ok_or_else(|| {
        RuntimeError::Network("firewall setup produced no owned state".to_string())
    })?;
    let marker = plan.ownership_marker().ok_or_else(|| {
        RuntimeError::Network("firewall plan has no canonical marker".to_string())
    })?;
    if !state.contains(&marker) {
        return Err(RuntimeError::Network(
            "created firewall object has no exact ownership marker".to_string(),
        ));
    }
    Ok(state)
}

struct SharedEbpfPreparation {
    network_id: String,
    route: EbpfExternalRoute,
    snat_port_start: u16,
    snat_port_end: u16,
    loopback_ifindex: u32,
    prepared: Option<PreparedEbpfNetwork>,
    existing_ownership: Option<NetworkOwnershipRecord>,
    recovery_records: Vec<ContainerRecord>,
    filters_before: Vec<EbpfFilterOwnershipRecord>,
}

fn prepare_shared_ebpf_network(
    network_id: &str,
    existing_records: &[ContainerRecord],
) -> Result<SharedEbpfPreparation, RuntimeError> {
    let route = ebpf_external_route()?;
    let loopback_ifindex = interface_ifindex("lo")?;
    let (snat_port_start, snat_port_end) = ebpf_snat_range()?;
    let config = EbpfNetworkConfig {
        network_id: network_id.to_string(),
        interface: route.interface.clone(),
        external_ipv4: route.address,
        external_ifindex: route.ifindex,
        loopback_ifindex,
        next_hop_mac: route.next_hop_mac,
        snat_port_start,
        snat_port_end,
        expected_object_sha256: embedded_object_sha256(),
    };
    let matching = existing_records
        .iter()
        .filter(|record| {
            record.network_backend.as_deref() == Some("ebpf")
                && record
                    .network_ownership
                    .as_ref()
                    .and_then(|ownership| ownership.network_id.as_deref())
                    == Some(network_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    let action = shared_ebpf_action(
        network_id,
        matching.iter().filter_map(|record| {
            record
                .network_ownership
                .as_ref()
                .and_then(|ownership| ownership.network_id.as_deref())
        }),
    );
    let filters_before = shared_tc_filter_snapshot(&route.interface)?;

    match action {
        SharedEbpfAction::PrepareAndAttach => Ok(SharedEbpfPreparation {
            network_id: network_id.to_string(),
            route,
            snat_port_start,
            snat_port_end,
            loopback_ifindex,
            prepared: Some(prepare_ebpf_classifiers(config)?),
            existing_ownership: None,
            recovery_records: Vec::new(),
            filters_before,
        }),
        SharedEbpfAction::VerifyAndReuse => {
            let ownership = matching
                .first()
                .and_then(|record| record.network_ownership.clone())
                .ok_or_else(|| {
                    RuntimeError::Network("shared eBPF ownership is missing".to_string())
                })?;
            verify_shared_ebpf_metadata(&ownership, &config)?;
            for record in &matching {
                let candidate = record.network_ownership.as_ref().ok_or_else(|| {
                    RuntimeError::Network("shared eBPF ownership is missing".to_string())
                })?;
                if !same_shared_ebpf_ownership(&ownership, candidate) {
                    return Err(RuntimeError::Network(
                        "conflicting persisted ownership for one eBPF bridge network".to_string(),
                    ));
                }
            }
            match plan_network_recovery(observe_owned_ebpf_state(&ownership)?)? {
                NetworkRecoveryAction::VerifyAndReuse => Ok(SharedEbpfPreparation {
                    network_id: network_id.to_string(),
                    route,
                    snat_port_start,
                    snat_port_end,
                    loopback_ifindex,
                    prepared: None,
                    existing_ownership: Some(ownership),
                    recovery_records: Vec::new(),
                    filters_before,
                }),
                NetworkRecoveryAction::ReloadShared => Ok(SharedEbpfPreparation {
                    network_id: network_id.to_string(),
                    route,
                    snat_port_start,
                    snat_port_end,
                    loopback_ifindex,
                    prepared: Some(prepare_ebpf_classifiers(config)?),
                    existing_ownership: Some(ownership),
                    recovery_records: matching,
                    filters_before,
                }),
            }
        }
    }
}

fn prepare_ebpf_classifiers(
    config: EbpfNetworkConfig,
) -> Result<PreparedEbpfNetwork, RuntimeError> {
    let loopback_ifindex = config.loopback_ifindex;
    let mut prepared =
        EbpfNetwork::prepare(config).map_err(|error| RuntimeError::Network(error.to_string()))?;
    prepared
        .prepare_interface("lo", loopback_ifindex)
        .map_err(|error| RuntimeError::Network(error.to_string()))?;
    Ok(prepared)
}

fn verify_shared_ebpf_metadata(
    ownership: &NetworkOwnershipRecord,
    config: &EbpfNetworkConfig,
) -> Result<(), RuntimeError> {
    let expected_hash = hex::encode(config.expected_object_sha256);
    let expected_mac = format_mac(config.next_hop_mac);
    let expected_address = Ipv4Addr::from(config.external_ipv4).to_string();
    if ownership.schema_version != 2
        || ownership.network_id.as_deref() != Some(config.network_id.as_str())
        || ownership.managed_interface.as_deref() != Some(config.interface.as_str())
        || ownership.managed_ifindex != Some(config.external_ifindex)
        || ownership.loopback_ifindex != Some(config.loopback_ifindex)
        || ownership.external_ipv4.as_deref() != Some(expected_address.as_str())
        || ownership.next_hop_mac.as_deref() != Some(expected_mac.as_str())
        || ownership.snat_port_start != Some(config.snat_port_start)
        || ownership.snat_port_end != Some(config.snat_port_end)
        || ownership.object_sha256.as_deref() != Some(expected_hash.as_str())
        || ownership.object_abi
            != Some(embedded_object_abi().map_err(|error| {
                RuntimeError::Network(format!("embedded eBPF ABI validation failed: {error}"))
            })?)
    {
        return Err(RuntimeError::Network(
            "persisted shared eBPF metadata is malformed or foreign".to_string(),
        ));
    }
    let actual_ifindex = interface_ifindex(&config.interface)?;
    if actual_ifindex != config.external_ifindex {
        return Err(RuntimeError::Network(format!(
            "managed interface identity changed: expected {}, found {actual_ifindex}",
            config.external_ifindex
        )));
    }
    Ok(())
}

fn same_shared_ebpf_ownership(
    left: &NetworkOwnershipRecord,
    right: &NetworkOwnershipRecord,
) -> bool {
    left.network_id == right.network_id
        && left.managed_interface == right.managed_interface
        && left.managed_ifindex == right.managed_ifindex
        && left.loopback_ifindex == right.loopback_ifindex
        && left.ebpf_pin_path == right.ebpf_pin_path
        && left.ebpf_filters == right.ebpf_filters
        && left.ebpf_pins == right.ebpf_pins
        && left.external_ipv4 == right.external_ipv4
        && left.next_hop_mac == right.next_hop_mac
        && left.snat_port_start == right.snat_port_start
        && left.snat_port_end == right.snat_port_end
        && left.object_sha256 == right.object_sha256
        && left.object_abi == right.object_abi
}

fn same_filter_slot(left: &EbpfFilterOwnershipRecord, right: &EbpfFilterOwnershipRecord) -> bool {
    left.interface == right.interface
        && left.interface_ifindex == right.interface_ifindex
        && left.direction == right.direction
        && left.priority == right.priority
        && left.handle == right.handle
}

fn observe_owned_ebpf_state(
    ownership: &NetworkOwnershipRecord,
) -> Result<ObservedNetworkState, RuntimeError> {
    if ownership.ebpf_pins.is_empty() || ownership.ebpf_filters.is_empty() {
        return Ok(ObservedNetworkState::PartialOrReplaced);
    }
    let root = PathBuf::from(
        ownership
            .ebpf_pin_path
            .as_deref()
            .ok_or_else(|| RuntimeError::Network("shared eBPF pin root is missing".to_string()))?,
    );
    let mut present = 0usize;
    let mut missing = 0usize;
    for pin in &ownership.ebpf_pins {
        let path = root.join(&pin.relative_path);
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if !metadata.file_type().is_symlink()
                    && metadata.dev() == pin.device
                    && metadata.ino() == pin.inode
                    && metadata.is_dir() == pin.directory =>
            {
                present += 1;
            }
            Ok(_) => return Ok(ObservedNetworkState::PartialOrReplaced),
            Err(error) if error.kind() == io::ErrorKind::NotFound => missing += 1,
            Err(error) => return Err(error.into()),
        }
    }
    let mut interfaces = Vec::<(String, u32)>::new();
    for filter in &ownership.ebpf_filters {
        let interface = filter.interface.clone().filter(|value| !value.is_empty());
        let ifindex = filter.interface_ifindex;
        let (Some(interface), Some(ifindex)) = (interface, ifindex) else {
            return Ok(ObservedNetworkState::PartialOrReplaced);
        };
        if let Some((_, current)) = interfaces.iter().find(|(name, _)| name == &interface) {
            if *current != ifindex {
                return Ok(ObservedNetworkState::PartialOrReplaced);
            }
        } else {
            interfaces.push((interface, ifindex));
        }
    }
    let mut observed = Vec::new();
    for (interface, expected_ifindex) in &interfaces {
        let expected_for_interface = ownership
            .ebpf_filters
            .iter()
            .filter(|filter| filter.interface.as_deref() == Some(interface.as_str()))
            .count();
        if !Path::new("/sys/class/net").join(interface).exists() {
            missing += expected_for_interface;
            continue;
        }
        if interface_ifindex(interface)? != *expected_ifindex {
            return Ok(ObservedNetworkState::PartialOrReplaced);
        }
        observed.extend(tc_filter_snapshot(interface, "ingress")?);
        observed.extend(tc_filter_snapshot(interface, "egress")?);
    }
    for filter in &ownership.ebpf_filters {
        if observed.contains(filter) {
            present += 1;
        } else if observed
            .iter()
            .any(|candidate| same_filter_slot(filter, candidate))
        {
            return Ok(ObservedNetworkState::PartialOrReplaced);
        } else if Path::new("/sys/class/net")
            .join(filter.interface.as_deref().unwrap_or_default())
            .exists()
        {
            missing += 1;
        }
    }
    let owned_count = ownership.ebpf_pins.len() + ownership.ebpf_filters.len();
    if present == owned_count {
        Ok(ObservedNetworkState::Complete)
    } else if missing == owned_count {
        Ok(ObservedNetworkState::CompletelyMissing)
    } else {
        Ok(ObservedNetworkState::PartialOrReplaced)
    }
}

fn setup_ebpf_backend(
    mut preparation: SharedEbpfPreparation,
    container_id: &str,
    host_veth: &str,
    netns_name: &str,
    container_ip: &str,
    port_mappings: &[PortMappingRecord],
    source_cidr: &str,
    bridge: &str,
    bridge_ifindex: u32,
    host_ifindex: u32,
    namespace_identity: KernelObjectIdentityRecord,
    rollback: &mut CreationRollback,
) -> Result<NetworkOwnershipRecord, RuntimeError> {
    let endpoint_address = container_ip
        .parse::<Ipv4Addr>()
        .map_err(|_| RuntimeError::Network("invalid eBPF endpoint IPv4 address".to_string()))?
        .octets();
    let endpoint = EndpointValue {
        ifindex: host_ifindex,
        mac: netns_interface_mac(netns_name, "eth0")?,
        flags: 0,
    };

    if let Some(prepared) = preparation.prepared.take() {
        let mut network = prepared
            .attach()
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
        let mut filters = shared_tc_filter_snapshot(&preparation.route.interface)?;
        filters.retain(|filter| !preparation.filters_before.contains(filter));
        if filters.len() != 4 {
            return Err(RuntimeError::Network(format!(
                "shared eBPF ownership capture expected external and loopback classifier pairs, found {} filters",
                filters.len()
            )));
        }
        let pin_path = Path::new(FERRO_NETWORK_ROOT).join(&preparation.network_id);
        let pins = capture_ebpf_pins(&pin_path)?;
        let ownership = build_ebpf_ownership(
            &preparation,
            container_id,
            host_veth,
            source_cidr,
            bridge,
            bridge_ifindex,
            host_ifindex,
            namespace_identity,
            filters,
            pins,
        )?;
        rollback.adopt_backend(NetworkBackend::Ebpf, ownership.clone(), Some(network))?;
        let network = rollback.ebpf_network.as_mut().ok_or_else(|| {
            RuntimeError::Network(
                "attached eBPF network was not transactionally adopted".to_string(),
            )
        })?;
        for record in &preparation.recovery_records {
            install_record_on_attached_network(network, record)?;
        }
        network
            .install_endpoint(
                EndpointKey {
                    address: endpoint_address,
                },
                endpoint,
            )
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
        install_ports_on_attached_network(network, endpoint_address, port_mappings)?;
        Ok(ownership)
    } else {
        let mut ownership = preparation.existing_ownership.take().ok_or_else(|| {
            RuntimeError::Network("verified shared eBPF ownership is missing".to_string())
        })?;
        ownership.owner_id = container_id.to_string();
        ownership.host_interface = host_veth.to_string();
        ownership.host_ifindex = Some(host_ifindex);
        ownership.namespace_identity = Some(namespace_identity);
        ownership.bridge_ifindex = Some(bridge_ifindex);
        let verified = verify_ebpf_record_mutation_ownership(&ownership, false)?;
        rollback.adopt_backend(NetworkBackend::Ebpf, ownership.clone(), None)?;
        verify_ebpf_classifier_ownership(&ownership)?;
        verified
            .install_endpoint(
                EndpointKey {
                    address: endpoint_address,
                },
                endpoint,
            )
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
        for mapping in port_mappings {
            verify_ebpf_classifier_ownership(&ownership)?;
            verified
                .install_port(
                    PortKey {
                        protocol: protocol_number(&mapping.protocol)?,
                        host_port: mapping.host_port,
                    },
                    PortValue {
                        endpoint_address,
                        endpoint_port: mapping.container_port,
                    },
                )
                .map_err(|error| RuntimeError::Network(error.to_string()))?;
        }
        Ok(ownership)
    }
}

fn install_record_on_attached_network(
    network: &mut EbpfNetwork,
    record: &ContainerRecord,
) -> Result<(), RuntimeError> {
    let address = record
        .ip_address
        .as_deref()
        .ok_or_else(|| {
            RuntimeError::Network("recovering endpoint has no IPv4 address".to_string())
        })?
        .parse::<Ipv4Addr>()
        .map_err(|_| RuntimeError::Network("recovering endpoint has invalid IPv4".to_string()))?
        .octets();
    let ownership = record.network_ownership.as_ref().ok_or_else(|| {
        RuntimeError::Network("recovering endpoint has no ownership metadata".to_string())
    })?;
    let netns_name = record
        .netns
        .as_deref()
        .ok_or_else(|| RuntimeError::Network("recovering endpoint has no namespace".to_string()))?;
    network
        .install_endpoint(
            EndpointKey { address },
            EndpointValue {
                ifindex: ownership.host_ifindex.ok_or_else(|| {
                    RuntimeError::Network("recovering endpoint has no veth ifindex".to_string())
                })?,
                mac: netns_interface_mac(netns_name, "eth0")?,
                flags: 0,
            },
        )
        .map_err(|error| RuntimeError::Network(error.to_string()))?;
    install_ports_on_attached_network(network, address, &record.ports)
}

fn install_ports_on_attached_network(
    network: &mut EbpfNetwork,
    endpoint_address: [u8; 4],
    port_mappings: &[PortMappingRecord],
) -> Result<(), RuntimeError> {
    for mapping in port_mappings {
        network
            .install_port(
                PortKey {
                    protocol: protocol_number(&mapping.protocol)?,
                    host_port: mapping.host_port,
                },
                PortValue {
                    endpoint_address,
                    endpoint_port: mapping.container_port,
                },
            )
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_ebpf_ownership(
    preparation: &SharedEbpfPreparation,
    container_id: &str,
    host_veth: &str,
    source_cidr: &str,
    bridge: &str,
    bridge_ifindex: u32,
    host_ifindex: u32,
    namespace_identity: KernelObjectIdentityRecord,
    filters: Vec<EbpfFilterOwnershipRecord>,
    pins: Vec<EbpfPinOwnershipRecord>,
) -> Result<NetworkOwnershipRecord, RuntimeError> {
    Ok(NetworkOwnershipRecord {
        schema_version: 2,
        owner_id: container_id.to_string(),
        network_id: Some(preparation.network_id.clone()),
        host_interface: host_veth.to_string(),
        host_ifindex: Some(host_ifindex),
        namespace_identity: Some(namespace_identity),
        managed_interface: Some(preparation.route.interface.clone()),
        managed_ifindex: Some(preparation.route.ifindex),
        loopback_ifindex: Some(preparation.loopback_ifindex),
        bridge_ifindex: Some(bridge_ifindex),
        source_cidr: Some(source_cidr.to_string()),
        bridge: Some(bridge.to_string()),
        firewall_id: None,
        firewall_marker: None,
        firewall_expected_state: None,
        ebpf_pin_path: Some(
            Path::new(FERRO_NETWORK_ROOT)
                .join(&preparation.network_id)
                .display()
                .to_string(),
        ),
        external_ipv4: Some(Ipv4Addr::from(preparation.route.address).to_string()),
        next_hop_mac: Some(format_mac(preparation.route.next_hop_mac)),
        snat_port_start: Some(preparation.snat_port_start),
        snat_port_end: Some(preparation.snat_port_end),
        object_sha256: Some(hex::encode(embedded_object_sha256())),
        object_abi: Some(
            embedded_object_abi().map_err(|error| RuntimeError::Network(error.to_string()))?,
        ),
        ebpf_filters: filters,
        ebpf_pins: pins,
    })
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn kernel_path_identity(path: &Path) -> Result<KernelObjectIdentityRecord, RuntimeError> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(KernelObjectIdentityRecord {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[derive(Debug, Clone)]
struct EbpfExternalRoute {
    interface: String,
    address: [u8; 4],
    ifindex: u32,
    next_hop_mac: [u8; 6],
}

fn ebpf_external_route() -> Result<EbpfExternalRoute, RuntimeError> {
    let output = run_cmd_capture(&[
        "ip".to_string(),
        "-4".to_string(),
        "route".to_string(),
        "get".to_string(),
        "1.1.1.1".to_string(),
    ])?;
    let fields = output.split_whitespace().collect::<Vec<_>>();
    let field_after = |name: &str| {
        fields
            .iter()
            .position(|field| *field == name)
            .and_then(|index| fields.get(index + 1).copied())
    };
    let interface = std::env::var("FERROCRATE_EBPF_EXTERNAL_INTERFACE")
        .ok()
        .or_else(|| field_after("dev").map(str::to_string))
        .ok_or_else(|| RuntimeError::Network("eBPF route has no external interface".to_string()))?;
    let address = std::env::var("FERROCRATE_EBPF_EXTERNAL_IPV4")
        .ok()
        .or_else(|| field_after("src").map(str::to_string))
        .ok_or_else(|| RuntimeError::Network("eBPF route has no external source IPv4".to_string()))?
        .parse::<Ipv4Addr>()
        .map_err(|_| RuntimeError::Network("invalid eBPF external IPv4".to_string()))?
        .octets();
    let next_hop_mac = if let Ok(mac) = std::env::var("FERROCRATE_EBPF_NEXT_HOP_MAC") {
        parse_mac(&mac)?
    } else {
        let gateway = field_after("via").ok_or_else(|| {
            RuntimeError::Network(
                "eBPF default route has no next hop; set FERROCRATE_EBPF_NEXT_HOP_MAC".to_string(),
            )
        })?;
        let neighbor = run_cmd_capture(&[
            "ip".to_string(),
            "neigh".to_string(),
            "show".to_string(),
            "to".to_string(),
            gateway.to_string(),
            "dev".to_string(),
            interface.clone(),
        ])?;
        let neighbor_fields = neighbor.split_whitespace().collect::<Vec<_>>();
        let index = neighbor_fields
            .iter()
            .position(|field| *field == "lladdr")
            .ok_or_else(|| {
                RuntimeError::Network(format!(
                    "eBPF next-hop MAC for {gateway} is unresolved; populate the neighbor entry or set FERROCRATE_EBPF_NEXT_HOP_MAC"
                ))
            })?;
        parse_mac(neighbor_fields.get(index + 1).copied().unwrap_or_default())?
    };
    Ok(EbpfExternalRoute {
        ifindex: interface_ifindex(&interface)?,
        interface,
        address,
        next_hop_mac,
    })
}

fn interface_ifindex(interface: &str) -> Result<u32, RuntimeError> {
    ferro_net::validate::validate_interface_name(interface)
        .map_err(|error| RuntimeError::Network(error.to_string()))?;
    fs::read_to_string(Path::new("/sys/class/net").join(interface).join("ifindex"))?
        .trim()
        .parse::<u32>()
        .map_err(|_| RuntimeError::Network(format!("invalid ifindex for {interface}")))
}

fn netns_interface_mac(netns_name: &str, interface: &str) -> Result<[u8; 6], RuntimeError> {
    let output = run_cmd_capture(&ip_netns_exec(
        netns_name,
        &["cat", &format!("/sys/class/net/{interface}/address")],
    ))?;
    parse_mac(output.trim())
}

fn parse_mac(value: &str) -> Result<[u8; 6], RuntimeError> {
    let octets = value
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeError::Network(format!("invalid MAC address `{value}`")))?;
    octets
        .try_into()
        .map_err(|_| RuntimeError::Network(format!("invalid MAC address `{value}`")))
}

fn protocol_number(protocol: &str) -> Result<u8, RuntimeError> {
    match protocol.to_ascii_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        _ => Err(RuntimeError::Network(format!(
            "unsupported eBPF port protocol `{protocol}`"
        ))),
    }
}

fn ebpf_snat_range() -> Result<(u16, u16), RuntimeError> {
    let value = std::env::var("FERROCRATE_EBPF_SNAT_PORT_RANGE")
        .unwrap_or_else(|_| "50000-50031".to_string());
    let (start, end) = value.split_once('-').ok_or_else(|| {
        RuntimeError::Network("FERROCRATE_EBPF_SNAT_PORT_RANGE must be START-END".to_string())
    })?;
    let start = start
        .parse::<u16>()
        .map_err(|_| RuntimeError::Network("invalid eBPF SNAT range start".to_string()))?;
    let end = end
        .parse::<u16>()
        .map_err(|_| RuntimeError::Network("invalid eBPF SNAT range end".to_string()))?;
    Ok((start, end))
}

fn shared_tc_filter_snapshot(
    external_interface: &str,
) -> Result<Vec<EbpfFilterOwnershipRecord>, RuntimeError> {
    let mut filters = tc_filter_snapshot(external_interface, "ingress")?;
    filters.extend(tc_filter_snapshot(external_interface, "egress")?);
    filters.extend(tc_filter_snapshot("lo", "ingress")?);
    filters.extend(tc_filter_snapshot("lo", "egress")?);
    Ok(filters)
}

fn tc_filter_snapshot(
    interface: &str,
    direction: &str,
) -> Result<Vec<EbpfFilterOwnershipRecord>, RuntimeError> {
    let command = [
        "tc".to_string(),
        "-j".to_string(),
        "filter".to_string(),
        "show".to_string(),
        "dev".to_string(),
        interface.to_string(),
        direction.to_string(),
    ];
    let output = match run_cmd_capture(&command) {
        Ok(output) => output,
        Err(error) if error.to_string().contains("Parent Qdisc doesn't exist") => {
            return Ok(Vec::new())
        }
        Err(error) => return Err(error),
    };
    let filters = serde_json::from_str::<Vec<serde_json::Value>>(&output)
        .map_err(|error| RuntimeError::Network(format!("invalid tc filter JSON: {error}")))?;
    let mut owned = Vec::new();
    for filter in filters {
        if filter.get("kind").and_then(serde_json::Value::as_str) != Some("bpf") {
            continue;
        }
        let Some(priority) = filter.get("pref").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let Some(options) = filter.get("options") else {
            continue;
        };
        let name = options
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !matches!(name, "ferro_ingress" | "ferro_egress") {
            continue;
        }
        let handle = options
            .get("handle")
            .map(|value| match value {
                serde_json::Value::String(value) => value.clone(),
                value => value.to_string(),
            })
            .ok_or_else(|| RuntimeError::Network("owned tc filter has no handle".to_string()))?;
        let program_id = options
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .map(u32::try_from)
            .transpose()
            .map_err(|_| {
                RuntimeError::Network("owned tc program id is out of range".to_string())
            })?;
        let program_tag = options
            .get("tag")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if program_id.is_none() || program_tag.as_deref().is_none_or(str::is_empty) {
            return Err(RuntimeError::Network(
                "owned tc filter has no BPF program identity".to_string(),
            ));
        }
        owned.push(EbpfFilterOwnershipRecord {
            interface: Some(interface.to_string()),
            interface_ifindex: Some(interface_ifindex(interface)?),
            direction: direction.to_string(),
            priority: u32::try_from(priority).map_err(|_| {
                RuntimeError::Network("owned tc filter priority is out of range".to_string())
            })?,
            handle,
            program_id,
            program_tag,
        });
    }
    Ok(owned)
}

fn capture_ebpf_pins(root: &Path) -> Result<Vec<EbpfPinOwnershipRecord>, RuntimeError> {
    fn visit(
        root: &Path,
        path: &Path,
        records: &mut Vec<EbpfPinOwnershipRecord>,
    ) -> Result<(), RuntimeError> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(RuntimeError::Network(format!(
                "foreign symlink in eBPF ownership tree: {}",
                path.display()
            )));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| RuntimeError::Network("eBPF pin escaped ownership root".to_string()))?;
        records.push(EbpfPinOwnershipRecord {
            relative_path: relative.display().to_string(),
            device: metadata.dev(),
            inode: metadata.ino(),
            directory: metadata.is_dir(),
            map_id: if !metadata.is_dir()
                && relative
                    .components()
                    .next()
                    .is_some_and(|component| component.as_os_str() == "maps")
            {
                Some(
                    EbpfNetwork::pinned_map_id(path)
                        .map_err(|error| RuntimeError::Network(error.to_string()))?,
                )
            } else {
                None
            },
        });
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                visit(root, &entry?.path(), records)?;
            }
        }
        Ok(())
    }

    let mut records = Vec::new();
    visit(root, root, &mut records)?;
    Ok(records)
}

fn ensure_bridge_backend_root(
    is_root: bool,
    requested_backend: NetworkBackend,
) -> Result<(), RuntimeError> {
    if is_root {
        return Ok(());
    }
    Err(RuntimeError::Network(format!(
        "rootless bridge backend setup requires root; requested backend {requested_backend} cannot be established"
    )))
}

fn validate_port_mapping_conflicts(
    store: &LocalContainerStore,
    requested: &[crate::container_store::PortMappingRecord],
) -> Result<(), RuntimeError> {
    if requested.is_empty() {
        return Ok(());
    }
    let records = store.list()?;
    for existing in records {
        if existing.status != "running" {
            continue;
        }
        for left in &existing.ports {
            for right in requested {
                if left.host_port == right.host_port
                    && left.protocol.eq_ignore_ascii_case(&right.protocol)
                {
                    return Err(RuntimeError::Network(format!(
                        "host port {} / {} already mapped by container {}",
                        right.host_port, right.protocol, existing.id
                    )));
                }
            }
        }
    }
    Ok(())
}

fn ebpf_config_from_ownership(
    ownership: &NetworkOwnershipRecord,
) -> Result<EbpfNetworkConfig, RuntimeError> {
    if ownership.schema_version != 2 {
        return Err(RuntimeError::Network(
            "unsupported eBPF ownership schema".to_string(),
        ));
    }
    let network_id = ownership
        .network_id
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Network("eBPF network identity is missing".to_string()))?;
    let interface = ownership
        .managed_interface
        .clone()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Network("eBPF managed interface is missing".to_string()))?;
    let external_ifindex = ownership
        .managed_ifindex
        .ok_or_else(|| RuntimeError::Network("eBPF external ifindex is missing".to_string()))?;
    let loopback_ifindex = ownership
        .loopback_ifindex
        .ok_or_else(|| RuntimeError::Network("eBPF loopback ifindex is missing".to_string()))?;
    let external_ipv4 = ownership
        .external_ipv4
        .as_deref()
        .ok_or_else(|| RuntimeError::Network("eBPF external IPv4 is missing".to_string()))?
        .parse::<Ipv4Addr>()
        .map_err(|_| RuntimeError::Network("invalid persisted eBPF external IPv4".to_string()))?
        .octets();
    let next_hop_mac = parse_mac(
        ownership
            .next_hop_mac
            .as_deref()
            .ok_or_else(|| RuntimeError::Network("eBPF next-hop MAC is missing".to_string()))?,
    )?;
    let snat_port_start = ownership
        .snat_port_start
        .ok_or_else(|| RuntimeError::Network("eBPF SNAT range start is missing".to_string()))?;
    let snat_port_end = ownership
        .snat_port_end
        .ok_or_else(|| RuntimeError::Network("eBPF SNAT range end is missing".to_string()))?;
    if snat_port_start == 0 || snat_port_start > snat_port_end {
        return Err(RuntimeError::Network(
            "invalid persisted eBPF SNAT range".to_string(),
        ));
    }
    let object_hash = hex::decode(
        ownership
            .object_sha256
            .as_deref()
            .ok_or_else(|| RuntimeError::Network("eBPF object hash is missing".to_string()))?,
    )
    .map_err(|_| RuntimeError::Network("invalid persisted eBPF object hash".to_string()))?;
    let expected_object_sha256: [u8; 32] = object_hash.try_into().map_err(|_| {
        RuntimeError::Network("invalid persisted eBPF object hash length".to_string())
    })?;
    if expected_object_sha256 != embedded_object_sha256()
        || ownership.object_abi
            != Some(
                embedded_object_abi().map_err(|error| RuntimeError::Network(error.to_string()))?,
            )
    {
        return Err(RuntimeError::Network(
            "persisted eBPF object identity is incompatible with this runtime".to_string(),
        ));
    }
    Ok(EbpfNetworkConfig {
        network_id,
        interface,
        external_ipv4,
        external_ifindex,
        loopback_ifindex,
        next_hop_mac,
        snat_port_start,
        snat_port_end,
        expected_object_sha256,
    })
}

fn verify_recovery_host_contract(config: &EbpfNetworkConfig) -> Result<(), RuntimeError> {
    let route = ebpf_external_route()?;
    let snat = ebpf_snat_range()?;
    if route.interface != config.interface
        || route.ifindex != config.external_ifindex
        || route.address != config.external_ipv4
        || route.next_hop_mac != config.next_hop_mac
        || snat != (config.snat_port_start, config.snat_port_end)
    {
        return Err(RuntimeError::Network(
            "persisted eBPF host route or SNAT reservation no longer matches the host".to_string(),
        ));
    }
    Ok(())
}

fn verify_container_kernel_ownership(
    netns_name: Option<&str>,
    ownership: &NetworkOwnershipRecord,
    require_present: bool,
) -> Result<(), RuntimeError> {
    let expected_host_ifindex = ownership.host_ifindex.ok_or_else(|| {
        RuntimeError::Network("network ownership has no host-veth ifindex".to_string())
    })?;
    let host_path = Path::new("/sys/class/net").join(&ownership.host_interface);
    if host_path.exists() {
        if interface_ifindex(&ownership.host_interface)? != expected_host_ifindex {
            return Err(RuntimeError::Network(
                "owned host veth was replaced".to_string(),
            ));
        }
    } else if require_present {
        return Err(RuntimeError::Network(
            "owned host veth is missing".to_string(),
        ));
    }

    let expected_namespace = ownership.namespace_identity.ok_or_else(|| {
        RuntimeError::Network("network ownership has no namespace identity".to_string())
    })?;
    let netns_name = netns_name.ok_or_else(|| {
        RuntimeError::Network("network ownership has no namespace name".to_string())
    })?;
    let netns_path = Path::new("/var/run/netns").join(netns_name);
    match fs::symlink_metadata(&netns_path) {
        Ok(metadata) => verify_kernel_identity(
            KernelIdentity {
                device: expected_namespace.device,
                inode: expected_namespace.inode,
            },
            Some(KernelIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }),
        )
        .map(|_| ()),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !require_present => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(RuntimeError::Network(
            "owned network namespace is missing".to_string(),
        )),
        Err(error) => Err(error.into()),
    }?;

    if let (Some(bridge), Some(expected)) = (&ownership.bridge, ownership.bridge_ifindex) {
        let path = Path::new("/sys/class/net").join(bridge);
        if path.exists() && interface_ifindex(bridge)? != expected {
            return Err(RuntimeError::Network(
                "owned bridge was replaced".to_string(),
            ));
        }
        if require_present && !path.exists() {
            return Err(RuntimeError::Network("owned bridge is missing".to_string()));
        }
    }
    if let (Some(interface), Some(expected)) =
        (&ownership.managed_interface, ownership.managed_ifindex)
    {
        let path = Path::new("/sys/class/net").join(interface);
        if path.exists() && interface_ifindex(interface)? != expected {
            return Err(RuntimeError::Network(
                "managed network interface was replaced".to_string(),
            ));
        }
        if require_present && !path.exists() {
            return Err(RuntimeError::Network(
                "managed network interface is missing".to_string(),
            ));
        }
    }
    Ok(())
}

fn verify_firewall_ownership_fields(
    backend: NetworkBackend,
    ownership: &NetworkOwnershipRecord,
) -> Result<(), RuntimeError> {
    let firewall_id = ownership
        .firewall_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Network("firewall ownership id is missing".to_string()))?;
    let marker = ownership
        .firewall_marker
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| RuntimeError::Network("firewall ownership marker is missing".to_string()))?;
    if backend == NetworkBackend::Ebpf
        || ownership.schema_version != 2
        || marker != format!("ferrocrate:{}", firewall_id.to_ascii_lowercase())
        || ownership
            .firewall_expected_state
            .as_deref()
            .is_none_or(str::is_empty)
    {
        return Err(RuntimeError::Network(
            "malformed or foreign firewall ownership metadata".to_string(),
        ));
    }
    Ok(())
}

fn normalize_owned_firewall_state(state: &str) -> String {
    state
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.split(" # handle ").next().unwrap_or(line))
        .map(|line| {
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            let mut result = Vec::new();
            let mut index = 0usize;
            while index < tokens.len() {
                let token = tokens[index];
                if token.starts_with('[') && token.ends_with(']') && token.contains(':') {
                    index += 1;
                    continue;
                }
                if token == "counter"
                    && tokens.get(index + 1) == Some(&"packets")
                    && tokens.get(index + 3) == Some(&"bytes")
                {
                    result.push("counter".to_string());
                    index += 5;
                    continue;
                }
                result.push(token.trim_matches('"').to_string());
                index += 1;
            }
            result.join(" ")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn verify_resumable_firewall_state(expected: &str, live: &str) -> Result<(), RuntimeError> {
    let expected = expected.lines().collect::<BTreeSet<_>>();
    for line in live.lines() {
        if !expected.contains(line) {
            return Err(RuntimeError::Network(format!(
                "owned firewall object contains foreign or replaced state: {line}"
            )));
        }
    }
    Ok(())
}

fn capture_firewall_owned_state(
    backend: NetworkBackend,
    firewall_id: &str,
) -> Result<Option<String>, RuntimeError> {
    let raw = match backend {
        NetworkBackend::Iptables => {
            let output = run_cmd_capture(&["iptables-save".to_string()])?;
            let owned = output
                .lines()
                .filter(|line| line.contains(firewall_id))
                .collect::<Vec<_>>()
                .join("\n");
            if owned.is_empty() {
                return Ok(None);
            }
            owned
        }
        NetworkBackend::Nftables => {
            let output = Command::new("nft")
                .args(["list", "table", "ip", firewall_id])
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stderr.contains("No such file or directory") || stderr.contains("does not exist")
                {
                    return Ok(None);
                }
                return Err(RuntimeError::Network(format!(
                    "capture owned nftables table: {}",
                    stderr.trim()
                )));
            }
            String::from_utf8(output.stdout).map_err(|error| {
                RuntimeError::Network(format!("owned nftables state is not UTF-8: {error}"))
            })?
        }
        NetworkBackend::Ebpf => {
            return Err(RuntimeError::Network(
                "eBPF backend cannot own firewall state".to_string(),
            ))
        }
    };
    Ok(Some(normalize_owned_firewall_state(&raw)))
}

fn verify_firewall_ownership(
    record: &ContainerRecord,
    ownership: &NetworkOwnershipRecord,
) -> Result<(), RuntimeError> {
    let backend = record
        .network_backend
        .as_deref()
        .ok_or_else(|| RuntimeError::Network("firewall backend is missing".to_string()))?
        .parse::<NetworkBackend>()
        .map_err(|error| RuntimeError::Network(format!("malformed persisted backend: {error}")))?;
    verify_firewall_ownership_fields(backend, ownership)?;
    let container_ip = record
        .ip_address
        .as_deref()
        .ok_or_else(|| RuntimeError::Network("firewall endpoint IPv4 is missing".to_string()))?;
    let source_cidr = ownership
        .source_cidr
        .as_deref()
        .ok_or_else(|| RuntimeError::Network("firewall source CIDR is missing".to_string()))?;
    let bridge = ownership
        .bridge
        .as_deref()
        .ok_or_else(|| RuntimeError::Network("firewall bridge is missing".to_string()))?;
    let plan = build_network_plan(
        backend,
        &record.id,
        &record.ports,
        container_ip,
        source_cidr,
        bridge,
    )?;
    if plan.firewall_id() != ownership.firewall_id.as_deref() {
        return Err(RuntimeError::Network(
            "persisted firewall plan does not match its owner inputs".to_string(),
        ));
    }
    let firewall_id = ownership.firewall_id.as_deref().unwrap_or_default();
    let marker = ownership.firewall_marker.as_deref().unwrap_or_default();
    let output = capture_firewall_owned_state(backend, firewall_id)?
        .ok_or_else(|| RuntimeError::Network("owned firewall object is missing".to_string()))?;
    if !output.contains(marker)
        || ownership.firewall_expected_state.as_deref() != Some(output.as_str())
    {
        return Err(RuntimeError::Network(
            "owned firewall object is missing or was replaced".to_string(),
        ));
    }
    Ok(())
}

fn legacy_port_mappings(record: &ContainerRecord) -> Vec<ferro_net::portmap::PortMapping> {
    record
        .ports
        .iter()
        .map(|mapping| ferro_net::portmap::PortMapping {
            host_port: mapping.host_port,
            container_port: mapping.container_port,
            protocol: mapping.protocol.clone(),
        })
        .collect()
}

fn legacy_firewall_commands(record: &ContainerRecord) -> Result<Vec<Vec<String>>, RuntimeError> {
    let container_ip = record.ip_address.as_deref().ok_or_else(|| {
        RuntimeError::Network("legacy bridge record has no endpoint IPv4".to_string())
    })?;
    let mut commands = Vec::new();
    for mapping in legacy_port_mappings(record) {
        commands.push(ferro_net::portmap::build_iptables_prerouting_cmd(
            &mapping,
            container_ip,
        )?);
        commands.push(ferro_net::portmap::build_iptables_output_dnat_cmd(
            &mapping,
            container_ip,
        )?);
        commands.push(ferro_net::portmap::build_iptables_forward_cmd(
            &mapping,
            container_ip,
        )?);
    }
    let bridge = bridge_config()?;
    commands.push(ferro_net::portmap::build_iptables_masquerade_cmd(
        &bridge.cidr,
        &bridge.name,
    )?);
    Ok(commands)
}

fn iptables_save_rule(command: &[String]) -> Option<String> {
    let append = command.iter().position(|part| part == "-A")?;
    Some(command[append..].join(" "))
}

fn legacy_firewall_rules_proven(record: &ContainerRecord) -> Result<bool, RuntimeError> {
    if record.network_name.as_deref() != Some("bridge") || record.ports.is_empty() {
        return Ok(false);
    }
    let output = run_cmd_capture(&["iptables-save".to_string()])?;
    Ok(legacy_firewall_commands(record)?
        .iter()
        .filter_map(|command| iptables_save_rule(command))
        .all(|rule| output.lines().any(|line| line == rule)))
}

fn cleanup_proven_legacy_rules(
    record: &ContainerRecord,
    all_records: &[ContainerRecord],
) -> Result<(), RuntimeError> {
    let mut commands = legacy_firewall_commands(record)?;
    let keep_global_masquerade = all_records.iter().any(|candidate| {
        candidate.id != record.id
            && candidate.network_name.as_deref() == Some("bridge")
            && candidate.network_ownership.is_none()
    });
    if keep_global_masquerade {
        commands.pop();
    }
    for mut command in commands.into_iter().rev() {
        let action = command
            .iter()
            .position(|part| part == "-A")
            .ok_or_else(|| {
                RuntimeError::Network("malformed proven legacy firewall command".to_string())
            })?;
        command[action] = "-D".to_string();
        run_cmd_allow_missing(&command)?;
    }
    Ok(())
}

fn cleanup_network(
    record: &ContainerRecord,
    all_records: &[ContainerRecord],
) -> Result<(), RuntimeError> {
    if let Some(overlay_id) = record.managed_overlay.as_deref() {
        let socket = std::env::var("FERROCRATE_AGENT_SOCKET")
            .unwrap_or_else(|_| "/run/ferrocrate/agent.sock".to_string());
        let request = ManagedOverlayRequest::DetachContainer {
            container_id: record.id.clone(),
            now_unix: crate::container_store::now_unix() as i64,
        };
        let response = ManagedOverlayClient::new(socket)
            .request(&request)
            .map_err(|error| {
                RuntimeError::Network(format!(
                    "managed overlay detach unavailable for {overlay_id}: {error}"
                ))
            })?;
        if !matches!(response, ManagedOverlayResponse::Detached { .. }) {
            return Err(RuntimeError::Network(
                "managed overlay agent rejected detach".to_string(),
            ));
        }
        if let Some(host_veth) = record.managed_host_veth.as_deref() {
            run_cmd_allow_missing(&[
                "ip".into(),
                "link".into(),
                "delete".into(),
                host_veth.into(),
            ])?;
        }
        if let Some(netns_name) = record.netns.as_deref() {
            run_cmd_allow_missing(&netns::build_ip_netns_del_cmd(netns_name)?)?;
        }
        return Ok(());
    }
    if record.network_backend.is_none() && record.network_ownership.is_none() {
        let proven = legacy_firewall_rules_proven(record)?;
        match classify_legacy_network_record(record.network_name.as_deref(), proven)? {
            LegacyNetworkAction::NotManagedBridge => {
                if record.netns.is_some() {
                    return Err(RuntimeError::Network(format!(
                        "legacy container {} has a namespace name but no kernel identity; retain the record and remove the namespace manually",
                        record.id
                    )));
                }
            }
            LegacyNetworkAction::CleanupProvenRules => {
                cleanup_proven_legacy_rules(record, all_records)?;
                return Err(RuntimeError::Network(format!(
                    "legacy rules for container {} were removed, but namespace/veth identity was not recorded; remove those resources manually before retrying record removal",
                    record.id
                )));
            }
        }
    } else if record.network_backend.is_none() || record.network_ownership.is_none() {
        return Err(RuntimeError::Network(format!(
            "container {} has malformed partial network ownership; restore or remove the record fields before cleanup",
            record.id
        )));
    }
    let backend = record
        .network_backend
        .as_deref()
        .map(str::parse::<NetworkBackend>)
        .transpose()
        .map_err(|error| RuntimeError::Network(format!("malformed persisted backend: {error}")))?;
    let remove_shared_ebpf = record
        .network_ownership
        .as_ref()
        .and_then(|ownership| ownership.network_id.as_deref())
        .map(|network_id| {
            !all_records.iter().any(|candidate| {
                candidate.id != record.id
                    && candidate.network_backend.as_deref() == Some("ebpf")
                    && candidate
                        .network_ownership
                        .as_ref()
                        .and_then(|ownership| ownership.network_id.as_deref())
                        == Some(network_id)
            })
        })
        .unwrap_or(true);
    cleanup_network_resources(
        &record.id,
        record.netns.as_deref(),
        record.ip_address.as_deref(),
        &record.ports,
        backend,
        record.network_ownership.as_ref(),
        remove_shared_ebpf,
    )
}

fn cleanup_network_resources(
    container_id: &str,
    netns_name: Option<&str>,
    container_ip: Option<&str>,
    port_mappings: &[PortMappingRecord],
    backend: Option<NetworkBackend>,
    ownership: Option<&NetworkOwnershipRecord>,
    remove_shared_ebpf: bool,
) -> Result<(), RuntimeError> {
    match (backend, ownership) {
        (None, None) => {}
        (Some(backend), Some(ownership)) => {
            validate_network_ownership(container_id, backend, ownership)?;
            verify_container_kernel_ownership(netns_name, ownership, false)?;
            match backend {
                NetworkBackend::Ebpf => {
                    if Path::new(ownership.ebpf_pin_path.as_deref().unwrap_or_default()).exists() {
                        let verified =
                            verify_ebpf_record_mutation_ownership(ownership, remove_shared_ebpf)?;
                        cleanup_ebpf_container_records(
                            container_ip,
                            port_mappings,
                            &verified,
                            ownership,
                        )?;
                    }
                    if remove_shared_ebpf {
                        cleanup_owned_ebpf(ownership)?;
                    }
                }
                NetworkBackend::Iptables | NetworkBackend::Nftables => {
                    verify_firewall_ownership_fields(backend, ownership)?;
                    let container_ip = container_ip.ok_or_else(|| {
                        RuntimeError::Network("firewall ownership has no container IP".to_string())
                    })?;
                    let source_cidr = ownership.source_cidr.as_deref().ok_or_else(|| {
                        RuntimeError::Network("firewall ownership has no source CIDR".to_string())
                    })?;
                    let bridge = ownership.bridge.as_deref().ok_or_else(|| {
                        RuntimeError::Network("firewall ownership has no bridge".to_string())
                    })?;
                    let plan = build_network_plan(
                        backend,
                        container_id,
                        port_mappings,
                        container_ip,
                        source_cidr,
                        bridge,
                    )?;
                    if ownership.firewall_id.as_deref() != plan.firewall_id() {
                        return Err(RuntimeError::Network(
                            "foreign firewall ownership metadata".to_string(),
                        ));
                    }
                    let mut runner = HostFirewallCommandRunner;
                    cleanup_firewall_plan_with(
                        backend,
                        &plan,
                        ownership
                            .firewall_expected_state
                            .as_deref()
                            .unwrap_or_default(),
                        &mut runner,
                    )?;
                }
            }
        }
        _ => {
            return Err(RuntimeError::Network(
                "malformed network ownership metadata".to_string(),
            ))
        }
    }

    if let Some(netns_name) = netns_name {
        let command = netns::build_ip_netns_del_cmd(netns_name)?;
        run_cmd_allow_missing(&command)?;
    }
    if let Some(ownership) = ownership {
        run_cmd_allow_missing(&[
            "ip".to_string(),
            "link".to_string(),
            "delete".to_string(),
            ownership.host_interface.clone(),
        ])?;
    }
    Ok(())
}

fn cleanup_ebpf_container_records(
    container_ip: Option<&str>,
    port_mappings: &[PortMappingRecord],
    verified: &VerifiedPinnedNetwork,
    ownership: &NetworkOwnershipRecord,
) -> Result<(), RuntimeError> {
    let address = container_ip
        .ok_or_else(|| RuntimeError::Network("eBPF ownership has no endpoint IPv4".to_string()))?
        .parse::<Ipv4Addr>()
        .map_err(|_| RuntimeError::Network("eBPF ownership has invalid endpoint IPv4".to_string()))?
        .octets();
    for mapping in port_mappings {
        verify_ebpf_classifier_ownership(ownership)?;
        verified
            .remove_port(PortKey {
                protocol: protocol_number(&mapping.protocol)?,
                host_port: mapping.host_port,
            })
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
    }
    verify_ebpf_classifier_ownership(ownership)?;
    verified
        .remove_endpoint(EndpointKey { address })
        .map_err(|error| RuntimeError::Network(error.to_string()))
}

fn verify_ebpf_record_mutation_ownership(
    ownership: &NetworkOwnershipRecord,
    allow_missing_owned_filters: bool,
) -> Result<VerifiedPinnedNetwork, RuntimeError> {
    let network_id = ownership.network_id.as_deref().ok_or_else(|| {
        RuntimeError::Network("eBPF ownership has no bridge network identity".to_string())
    })?;
    let root = PathBuf::from(
        ownership
            .ebpf_pin_path
            .as_deref()
            .ok_or_else(|| RuntimeError::Network("eBPF ownership has no pin path".to_string()))?,
    );
    let current_pins = capture_ebpf_pins(&root)?;
    if current_pins.len() != ownership.ebpf_pins.len()
        || current_pins
            .iter()
            .any(|pin| !ownership.ebpf_pins.contains(pin))
    {
        return Err(RuntimeError::Network(
            "eBPF pin tree is incomplete, replaced, or foreign".to_string(),
        ));
    }
    verify_ebpf_classifier_ownership_with(ownership, !allow_missing_owned_filters)?;
    let identity = PinnedNetworkIdentity {
        root,
        objects: ownership
            .ebpf_pins
            .iter()
            .map(|pin| PinnedObjectIdentity {
                relative_path: pin.relative_path.clone(),
                device: pin.device,
                inode: pin.inode,
                directory: pin.directory,
                map_id: pin.map_id,
            })
            .collect(),
    };
    EbpfNetwork::verify_pinned_network(network_id, identity)
        .map_err(|error| RuntimeError::Network(error.to_string()))
}

fn verify_ebpf_classifier_ownership(
    ownership: &NetworkOwnershipRecord,
) -> Result<(), RuntimeError> {
    verify_ebpf_classifier_ownership_with(ownership, true)
}

fn verify_ebpf_classifier_ownership_with(
    ownership: &NetworkOwnershipRecord,
    require_all: bool,
) -> Result<(), RuntimeError> {
    let interface = ownership.managed_interface.as_deref().ok_or_else(|| {
        RuntimeError::Network("eBPF ownership has no managed interface".to_string())
    })?;
    let observed_filters = shared_tc_filter_snapshot(interface)?;
    for expected in &ownership.ebpf_filters {
        if observed_filters.contains(expected) {
            continue;
        }
        if observed_filters
            .iter()
            .any(|candidate| same_filter_slot(expected, candidate))
        {
            return Err(RuntimeError::Network(
                "eBPF classifier ownership was replaced".to_string(),
            ));
        }
        if require_all {
            return Err(RuntimeError::Network(
                "eBPF classifier ownership is incomplete".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_network_ownership(
    container_id: &str,
    backend: NetworkBackend,
    ownership: &NetworkOwnershipRecord,
) -> Result<(), RuntimeError> {
    if ownership.schema_version != 2 || ownership.network_id.as_deref().is_none_or(str::is_empty) {
        return Err(RuntimeError::Network(
            "malformed network ownership schema or network identity".to_string(),
        ));
    }
    let expected_host = format!("veth{}", short_id(container_id, 8));
    let expected_host = &expected_host[..expected_host.len().min(15)];
    if ownership.owner_id != container_id || ownership.host_interface != expected_host {
        return Err(RuntimeError::Network(
            "foreign network ownership metadata".to_string(),
        ));
    }
    match backend {
        NetworkBackend::Ebpf
            if ownership.firewall_id.is_some()
                || ownership.ebpf_pin_path.as_deref()
                    != Some(
                        Path::new(FERRO_NETWORK_ROOT)
                            .join(ownership.network_id.as_deref().unwrap_or_default())
                            .to_string_lossy()
                            .as_ref(),
                    ) =>
        {
            Err(RuntimeError::Network(
                "foreign eBPF ownership metadata".to_string(),
            ))
        }
        NetworkBackend::Iptables | NetworkBackend::Nftables
            if ownership.ebpf_pin_path.is_some()
                || !ownership.ebpf_filters.is_empty()
                || !ownership.ebpf_pins.is_empty() =>
        {
            Err(RuntimeError::Network(
                "foreign firewall ownership metadata".to_string(),
            ))
        }
        _ => Ok(()),
    }
}

fn cleanup_owned_ebpf(ownership: &NetworkOwnershipRecord) -> Result<(), RuntimeError> {
    let interface = ownership.managed_interface.as_deref().ok_or_else(|| {
        RuntimeError::Network("eBPF ownership has no managed interface".to_string())
    })?;
    ferro_net::validate::validate_interface_name(interface)
        .map_err(|error| RuntimeError::Network(error.to_string()))?;
    if ownership.ebpf_filters.len() != 4 || ownership.ebpf_pins.is_empty() {
        return Err(RuntimeError::Network(
            "malformed eBPF ownership metadata".to_string(),
        ));
    }
    verify_owned_ebpf_pins_before_cleanup(ownership)?;
    let mut interfaces = Vec::<(String, u32)>::new();
    for filter in &ownership.ebpf_filters {
        let name = filter.interface.clone().filter(|value| !value.is_empty());
        let ifindex = filter.interface_ifindex;
        let (Some(name), Some(ifindex)) = (name, ifindex) else {
            return Err(RuntimeError::Network(
                "malformed eBPF filter interface identity".to_string(),
            ));
        };
        if let Some((_, current)) = interfaces.iter().find(|(value, _)| value == &name) {
            if *current != ifindex {
                return Err(RuntimeError::Network(
                    "conflicting eBPF filter interface identities".to_string(),
                ));
            }
        } else {
            interfaces.push((name, ifindex));
        }
    }
    let mut observed = Vec::new();
    for (name, expected_ifindex) in &interfaces {
        let path = Path::new("/sys/class/net").join(name);
        if !path.exists() {
            continue;
        }
        if interface_ifindex(name)? != *expected_ifindex {
            return Err(RuntimeError::Network(
                "owned eBPF filter interface was replaced".to_string(),
            ));
        }
        observed.extend(tc_filter_snapshot(name, "ingress")?);
        observed.extend(tc_filter_snapshot(name, "egress")?);
    }
    let mut present_filters = Vec::new();
    for expected in &ownership.ebpf_filters {
        if observed.contains(expected) {
            present_filters.push(expected);
        } else if observed
            .iter()
            .any(|candidate| same_filter_slot(expected, candidate))
        {
            return Err(RuntimeError::Network(
                "owned eBPF filter was replaced".to_string(),
            ));
        }
    }
    for filter in present_filters {
        if !matches!(filter.direction.as_str(), "ingress" | "egress")
            || filter.priority == 0
            || filter.handle.is_empty()
            || filter.interface.as_deref().is_none_or(str::is_empty)
            || filter.interface_ifindex.is_none()
            || filter.program_id.is_none()
            || filter.program_tag.as_deref().is_none_or(str::is_empty)
            || !filter
                .handle
                .chars()
                .all(|character| character.is_ascii_hexdigit() || character == 'x')
        {
            return Err(RuntimeError::Network(
                "malformed eBPF filter ownership".to_string(),
            ));
        }
        run_cmd_allow_missing(&[
            "tc".to_string(),
            "filter".to_string(),
            "delete".to_string(),
            "dev".to_string(),
            filter.interface.clone().unwrap_or_default(),
            filter.direction.clone(),
            "pref".to_string(),
            filter.priority.to_string(),
            "handle".to_string(),
            filter.handle.clone(),
            "bpf".to_string(),
        ])?;
    }
    cleanup_owned_ebpf_pins(ownership)
}

fn verify_owned_ebpf_pins_before_cleanup(
    ownership: &NetworkOwnershipRecord,
) -> Result<(), RuntimeError> {
    let root = PathBuf::from(
        ownership
            .ebpf_pin_path
            .as_deref()
            .ok_or_else(|| RuntimeError::Network("eBPF ownership has no pin path".to_string()))?,
    );
    if !root.exists() {
        return Ok(());
    }
    let observed = capture_ebpf_pins(&root)?;
    for pin in observed {
        let Some(expected) = ownership
            .ebpf_pins
            .iter()
            .find(|expected| expected.relative_path == pin.relative_path)
        else {
            return Err(RuntimeError::Network(format!(
                "foreign entry in owned eBPF pin tree: {}",
                pin.relative_path
            )));
        };
        if expected != &pin {
            return Err(RuntimeError::Network(format!(
                "owned eBPF pin was replaced: {}",
                pin.relative_path
            )));
        }
    }
    Ok(())
}

fn cleanup_owned_ebpf_pins(ownership: &NetworkOwnershipRecord) -> Result<(), RuntimeError> {
    let root = PathBuf::from(
        ownership
            .ebpf_pin_path
            .as_deref()
            .ok_or_else(|| RuntimeError::Network("eBPF ownership has no pin path".to_string()))?,
    );
    let mut pins = ownership.ebpf_pins.clone();
    pins.sort_by(|left, right| {
        Path::new(&right.relative_path)
            .components()
            .count()
            .cmp(&Path::new(&left.relative_path).components().count())
            .then_with(|| left.directory.cmp(&right.directory))
    });
    for pin in pins {
        let relative = Path::new(&pin.relative_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
                && !pin.relative_path.is_empty()
        {
            return Err(RuntimeError::Network(
                "malformed eBPF pin ownership path".to_string(),
            ));
        }
        let path = root.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || metadata.dev() != pin.device
            || metadata.ino() != pin.inode
            || metadata.is_dir() != pin.directory
        {
            return Err(RuntimeError::Network(format!(
                "owned eBPF pin was replaced: {}",
                path.display()
            )));
        }
        let result = if pin.directory {
            fs::remove_dir(&path)
        } else {
            fs::remove_file(&path)
        };
        match result {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {
                return Err(RuntimeError::Network(format!(
                    "foreign entry in owned eBPF pin directory: {}",
                    path.display()
                )))
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn start_slirp4netns(pid: u32) -> Result<(), RuntimeError> {
    let tap_name = format!("tap{pid}");
    let tap_name = if tap_name.len() > 15 {
        tap_name[..15].to_string()
    } else {
        tap_name
    };
    let config = RootlessNetConfig {
        tap_name,
        cidr: "10.0.2.0/24".to_string(),
    };
    let cmd = match build_slirp4netns_cmd(pid, &config) {
        Ok(c) => c,
        Err(e) => {
            return Err(RuntimeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("slirp4netns config: {}", e),
            )))
        }
    };
    if cmd.is_empty() {
        return Ok(());
    }
    let (bin, rest) = parse_cmd_args(&cmd)?;
    Command::new(bin)
        .args(rest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

fn rootless_netns_enabled() -> bool {
    std::env::var("FERROCRATE_ROOTLESS_NETNS")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn seccomp_enabled() -> bool {
    std::env::var("FERROCRATE_SECCOMP")
        .map(|val| !(val == "0" || val.eq_ignore_ascii_case("false")))
        .unwrap_or(true)
}

#[allow(dead_code)]
fn seccomp_strict_mode() -> bool {
    !seccomp_permissive_mode()
}

fn seccomp_permissive_mode() -> bool {
    std::env::var("FERROCRATE_SECCOMP_PERMISSIVE")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Resolves the seccomp profile to apply.
///
/// If `ai_config` is `Some` with `authority = Guest`, returns the guest restricted
/// profile. Otherwise falls back to `load_seccomp_profile()` (default or env-override).
fn resolve_seccomp_profile(
    ai_config: Option<&AiRuntimeConfig>,
) -> Result<Option<SeccompProfile>, RuntimeError> {
    if let Some(ai) = ai_config {
        if let Some(profile) = crate::ai_runtime::seccomp_profile_for_authority(&ai.authority)
            .map_err(|err| RuntimeError::InvalidCommand(format!("ai_runtime seccomp: {err}")))?
        {
            return Ok(Some(profile));
        }
    }
    load_seccomp_profile()
}

fn load_seccomp_profile() -> Result<Option<SeccompProfile>, RuntimeError> {
    if !seccomp_enabled() {
        return Ok(None);
    }
    if let Ok(raw_path) = std::env::var("FERROCRATE_SECCOMP_PROFILE") {
        let path = PathBuf::from(raw_path.trim());
        let metadata = fs::metadata(&path).map_err(|err| {
            RuntimeError::InvalidCommand(format!("seccomp profile {}: {}", path.display(), err))
        })?;
        const MAX_SECCOMP_PROFILE_BYTES: u64 = 1024 * 1024;
        if metadata.len() > MAX_SECCOMP_PROFILE_BYTES {
            return Err(RuntimeError::InvalidCommand(format!(
                "seccomp profile {} exceeds {} bytes",
                path.display(),
                MAX_SECCOMP_PROFILE_BYTES
            )));
        }
        let raw = fs::read_to_string(&path).map_err(|err| {
            RuntimeError::InvalidCommand(format!("seccomp profile {}: {}", path.display(), err))
        })?;
        let profile = parse_seccomp_profile(&raw)
            .map_err(|err| RuntimeError::InvalidCommand(format!("seccomp profile: {err}")))?;
        return Ok(Some(profile));
    }
    let profile = default_seccomp_profile()
        .map_err(|err| RuntimeError::InvalidCommand(format!("seccomp profile: {err}")))?;
    Ok(Some(profile))
}

fn apparmor_enabled() -> bool {
    std::env::var("FERROCRATE_APPARMOR")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn selinux_enabled() -> bool {
    std::env::var("FERROCRATE_SELINUX")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn mac_permissive_mode() -> bool {
    std::env::var("FERROCRATE_MAC_PERMISSIVE")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn mac_enforcement_result(feature: &str, detail: &str) -> Result<(), RuntimeError> {
    if mac_permissive_mode() {
        log::warn!("{feature}: {detail} (permissive mode)");
        return Ok(());
    }
    Err(RuntimeError::InvalidCommand(format!("{feature}: {detail}")))
}

fn validate_selinux_type(selinux_type: &str) -> Result<(), RuntimeError> {
    if selinux_type
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        return Err(RuntimeError::InvalidCommand(
            "selinux type contains invalid characters".to_string(),
        ));
    }
    Ok(())
}

/// SEC-05: Execute command with timeout to prevent blocking indefinitely
fn execute_with_timeout(
    binary: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<std::process::Output, RuntimeError> {
    use std::io::Read;
    use std::process::{Command, Stdio};

    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            // Process completed - collect output
            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| std::io::Error::other("failed to capture stdout"))?;
            let mut stderr = child
                .stderr
                .take()
                .ok_or_else(|| std::io::Error::other("failed to capture stderr"))?;

            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            stdout.read_to_end(&mut stdout_buf)?;
            stderr.read_to_end(&mut stderr_buf)?;

            return Ok(std::process::Output {
                status,
                stdout: stdout_buf,
                stderr: stderr_buf,
            });
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RuntimeError::Timeout(timeout));
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn command_available(bin: &str) -> bool {
    // SEC-05: Use timeout to prevent hanging on --version check
    execute_with_timeout(bin, &["--version"], Duration::from_secs(2)).is_ok()
}

fn apply_apparmor_if_enabled(
    runtime_dir: &Path,
    container_id: &str,
    cmd: &[String],
) -> Result<Vec<String>, RuntimeError> {
    if !apparmor_enabled() {
        return Ok(cmd.to_vec());
    }
    if cmd.is_empty() {
        return Ok(cmd.to_vec());
    }
    if !command_available("apparmor_parser") || !command_available("aa-exec") {
        mac_enforcement_result(
            "apparmor",
            "apparmor_parser and aa-exec are required when FERROCRATE_APPARMOR=1",
        )?;
        return Ok(cmd.to_vec());
    }
    let profile_name = format!("ferrocrate-{container_id}");
    let profile = generate_apparmor_profile(container_id)?;
    let profile_dir = runtime_dir.join("security").join("apparmor");
    fs::create_dir_all(&profile_dir)?;
    let profile_path = profile_dir.join(format!("{profile_name}.profile"));
    fs::write(&profile_path, profile)?;

    // SEC-05: Execute apparmor_parser with timeout to prevent blocking indefinitely
    let output = execute_with_timeout(
        "apparmor_parser",
        &["-r", &profile_path.to_string_lossy()],
        Duration::from_secs(10),
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        mac_enforcement_result(
            "apparmor",
            &format!("failed to load profile: {}", stderr.trim()),
        )?;
        return Ok(cmd.to_vec());
    }

    let mut wrapped = vec![
        "aa-exec".to_string(),
        "-p".to_string(),
        profile_name,
        "--".to_string(),
    ];
    wrapped.extend(cmd.iter().cloned());
    Ok(wrapped)
}

fn apply_selinux_if_enabled(cmd: &[String]) -> Result<Vec<String>, RuntimeError> {
    if !selinux_enabled() {
        return Ok(cmd.to_vec());
    }
    if cmd.is_empty() {
        return Ok(cmd.to_vec());
    }
    if !command_available("runcon") {
        mac_enforcement_result("selinux", "runcon is required when FERROCRATE_SELINUX=1")?;
        return Ok(cmd.to_vec());
    }
    let selinux_type =
        std::env::var("FERROCRATE_SELINUX_TYPE").unwrap_or_else(|_| "container_t".to_string());
    validate_selinux_type(&selinux_type)?;
    let mut wrapped = vec![
        "runcon".to_string(),
        "-t".to_string(),
        selinux_type,
        "--".to_string(),
    ];
    wrapped.extend(cmd.iter().cloned());
    Ok(wrapped)
}

fn update_container_hosts(
    runtime_dir: &Path,
    containers: &[ContainerRecord],
) -> Result<(), RuntimeError> {
    let mut entries: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in containers {
        if record.status != "running" && record.status != "paused" {
            continue;
        }
        let mut add_entry = |ip: &Option<String>| {
            if let Some(ip) = ip.as_ref() {
                let names = entries.entry(ip.clone()).or_default();
                names.insert(record.id.clone());
                if let Some(name) = record.name.as_ref() {
                    names.insert(name.clone());
                }
            }
        };
        add_entry(&record.ip_address);
        add_entry(&record.ipv6_address);
    }

    if entries.is_empty() {
        return Ok(());
    }

    let hosts_body = render_hosts(&entries);
    let resolv_body = ferro_net::dns::render_resolv_conf(&runtime_dns_config());
    for record in containers {
        if record.status != "running" && record.status != "paused" {
            continue;
        }
        if record.ip_address.is_none() && record.ipv6_address.is_none() {
            continue;
        }
        let hosts_path = runtime_dir
            .join("containers")
            .join(&record.id)
            .join("rootfs")
            .join("etc")
            .join("hosts");
        if let Some(parent) = hosts_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&hosts_path, &hosts_body)?;

        let resolv_path = runtime_dir
            .join("containers")
            .join(&record.id)
            .join("rootfs")
            .join("etc")
            .join("resolv.conf");
        if let Some(parent) = resolv_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&resolv_path, &resolv_body)?;
    }
    Ok(())
}

fn runtime_dns_config() -> ferro_net::dns::DnsConfig {
    let servers = std::env::var("FERROCRATE_DNS_SERVERS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|entries| !entries.is_empty())
        .unwrap_or_else(|| vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    let search = std::env::var("FERROCRATE_DNS_SEARCH")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["ferro.local".to_string()]);
    ferro_net::dns::DnsConfig { servers, search }
}

fn render_hosts(entries: &BTreeMap<String, BTreeSet<String>>) -> String {
    let mut lines = Vec::new();
    lines.push("127.0.0.1 localhost".to_string());
    lines.push("::1 localhost ip6-localhost ip6-loopback".to_string());
    for (ip, names) in entries {
        if names.is_empty() {
            continue;
        }
        let list = names.iter().cloned().collect::<Vec<_>>().join(" ");
        lines.push(format!("{ip} {list}"));
    }
    lines.join("\n") + "\n"
}

fn ip_netns_exec(netns_name: &str, args: &[&str]) -> Vec<String> {
    let mut out = vec![
        "ip".to_string(),
        "netns".to_string(),
        "exec".to_string(),
        netns_name.to_string(),
    ];
    out.extend(args.iter().map(|val| (*val).to_string()));
    out
}

const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

trait GlobalValueStore {
    fn read(&mut self) -> Result<String, RuntimeError>;
    fn write(&mut self, value: &str) -> Result<(), RuntimeError>;
}

struct FileGlobalValueStore<'a> {
    path: &'a Path,
}

impl GlobalValueStore for FileGlobalValueStore<'_> {
    fn read(&mut self) -> Result<String, RuntimeError> {
        Ok(fs::read_to_string(self.path)?.trim().to_string())
    }

    fn write(&mut self, value: &str) -> Result<(), RuntimeError> {
        fs::write(self.path, value)?;
        Ok(())
    }
}

fn acquire_ip_forwarding_with<S: GlobalValueStore>(
    store: &mut S,
) -> Result<Option<GlobalValueOwnership>, RuntimeError> {
    let current = store.read()?;
    match current.as_str() {
        "1" => Ok(None),
        "0" => {
            store.write("1")?;
            Ok(Some(GlobalValueOwnership {
                previous: "0".to_string(),
                expected: "1".to_string(),
            }))
        }
        _ => Err(RuntimeError::Network(format!(
            "refusing to change malformed ip_forward value {current:?}"
        ))),
    }
}

fn restore_ip_forwarding_with<S: GlobalValueStore>(
    ownership: &GlobalValueOwnership,
    store: &mut S,
) -> Result<(), RuntimeError> {
    if ownership.previous != "0" || ownership.expected != "1" {
        return Err(RuntimeError::Network(
            "malformed persisted ip_forward ownership".to_string(),
        ));
    }
    let current = store.read()?;
    if current == ownership.previous {
        return Ok(());
    }
    if current != ownership.expected {
        return Err(RuntimeError::Network(format!(
            "ip_forward changed to foreign value {current:?}; refusing restoration"
        )));
    }
    store.write(&ownership.previous)
}

fn ensure_ip_forwarding(rollback: &mut CreationRollback) -> Result<(), RuntimeError> {
    let mut store = FileGlobalValueStore {
        path: Path::new(IP_FORWARD_PATH),
    };
    if let Some(ownership) = acquire_ip_forwarding_with(&mut store)? {
        rollback.track_ip_forward(ownership)?;
    }
    Ok(())
}

fn restore_ip_forwarding(ownership: &GlobalValueOwnership) -> Result<(), RuntimeError> {
    let mut store = FileGlobalValueStore {
        path: Path::new(IP_FORWARD_PATH),
    };
    restore_ip_forwarding_with(ownership, &mut store)
}

/// Execute a command with logging and timeout.
///
/// This is the unified entry point for all shell-outs in runtime.rs.
/// - Logs the command at debug level
/// - Captures stderr for error messages
/// - 30s default timeout
fn run_cmd(args: &[String]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        return Ok(());
    }
    let cmd_str = args.join(" ");

    // Log command execution at debug level (visible with RUST_LOG=debug)
    log::debug!("[exec] {}", cmd_str);

    net_exec_cmd(args).map_err(|err| RuntimeError::Network(err.to_string()))
}

fn run_cmd_capture(args: &[String]) -> Result<String, RuntimeError> {
    if args.is_empty() {
        return Ok(String::new());
    }
    let (bin, rest) = parse_cmd_args(args)?;
    let cmd_str = args.join(" ");

    log::debug!("[exec] {}", cmd_str);

    let output = Command::new(bin).args(rest).output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    Err(RuntimeError::Network(format!(
        "{}: {}",
        cmd_str,
        stderr.trim()
    )))
}

/// Execute a command, allowing "already exists" errors (idempotent operations).
fn run_cmd_allow_missing(args: &[String]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        return Ok(());
    }
    let (bin, rest) = parse_cmd_args(args)?;
    let output = Command::new(bin).args(rest).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if [
        "No such file or directory",
        "No such table",
        "No such file",
        "Cannot find device",
        "Cannot find qdisc",
        "Cannot find filter",
        "does a matching rule exist",
        "No chain/target/match by that name",
    ]
    .iter()
    .any(|message| stderr.contains(message))
    {
        return Ok(());
    }
    Err(RuntimeError::Network(format!("{bin}: {}", stderr.trim())))
}

struct BridgeConfig {
    name: String,
    cidr: String,
    gateway: String,
    prefix: u8,
    ipv6_cidr: Option<String>,
    ipv6_gateway: Option<Ipv6Addr>,
    ipv6_prefix: Option<u8>,
}

fn bridge_config() -> Result<BridgeConfig, RuntimeError> {
    let name = std::env::var("FERROCRATE_BRIDGE_NAME").unwrap_or_else(|_| "ferro0".to_string());
    let cidr =
        std::env::var("FERROCRATE_BRIDGE_CIDR").unwrap_or_else(|_| "10.0.0.1/24".to_string());
    let ipv6_cidr = std::env::var("FERROCRATE_BRIDGE_IPV6_CIDR").ok();
    let mut parts = cidr.split('/');
    let gateway = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid bridge cidr".to_string()))?
        .to_string();
    let prefix = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid bridge cidr".to_string()))?
        .parse::<u8>()
        .map_err(|_| RuntimeError::Network("invalid bridge cidr".to_string()))?;
    let (ipv6_gateway, ipv6_prefix) = if let Some(cidr) = ipv6_cidr.as_deref() {
        let mut parts = cidr.split('/');
        let gateway = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid ipv6 cidr".to_string()))?;
        let prefix = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid ipv6 cidr".to_string()))?
            .parse::<u8>()
            .map_err(|_| RuntimeError::Network("invalid ipv6 cidr".to_string()))?;
        let gateway = gateway
            .parse::<Ipv6Addr>()
            .map_err(|_| RuntimeError::Network("invalid ipv6 gateway".to_string()))?;
        (Some(gateway), Some(prefix))
    } else {
        (None, None)
    };
    Ok(BridgeConfig {
        name,
        cidr,
        gateway,
        prefix,
        ipv6_cidr,
        ipv6_gateway,
        ipv6_prefix,
    })
}

fn allocate_container_ip(container_id: &str, gateway: &str) -> Result<String, RuntimeError> {
    let gateway_ip: Ipv4Addr = gateway
        .parse()
        .map_err(|_| RuntimeError::Network("invalid bridge gateway".to_string()))?;
    let mut octets = gateway_ip.octets();
    let hash = rvf_crypto::shake256_256(container_id.as_bytes());
    let byte = hash[0];
    let host = 2 + (byte % 200);
    octets[3] = host;
    Ok(Ipv4Addr::from(octets).to_string())
}

fn selected_network_name(network_mode: &str) -> Option<String> {
    if let Ok(name) = std::env::var("FERROCRATE_NETWORK_NAME") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    match network_mode {
        "bridge" => Some("bridge".to_string()),
        "host" => Some("host".to_string()),
        "none" => Some("none".to_string()),
        "wireguard" => Some("wireguard".to_string()),
        _ => None,
    }
}

struct RuntimeBackendProbe;

impl BackendProbe for RuntimeBackendProbe {
    fn command_exists(&self, command: &str) -> bool {
        command_available(command)
    }

    fn bpffs_mounted(&self) -> bool {
        fs::read_to_string("/proc/mounts")
            .ok()
            .map(|mounts| {
                mounts.lines().any(|line| {
                    let mut fields = line.split_whitespace();
                    let _source = fields.next();
                    fields.next() == Some("/sys/fs/bpf") && fields.next() == Some("bpf")
                })
            })
            .unwrap_or(false)
    }

    fn artifact_available(&self) -> bool {
        embedded_object_abi().is_ok()
    }
}

#[cfg(test)]
fn ebpf_artifact_available(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() == 0 {
        return false;
    }
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
}

fn resolve_network_backend(
    requested: NetworkBackend,
    probe: &dyn BackendProbe,
) -> Result<NetworkBackend, RuntimeError> {
    requested
        .ensure_available(probe)
        .map_err(|err| RuntimeError::Network(err.to_string()))?;
    Ok(requested)
}

fn allocate_container_ipv6(container_id: &str, gateway: &Ipv6Addr, prefix: u8) -> String {
    let prefix = prefix.min(128);
    let gateway_val = u128::from(*gateway);
    let host_bits = 128u8.saturating_sub(prefix);
    if host_bits == 0 {
        return gateway.to_string();
    }
    let hash = rvf_crypto::shake256_256(container_id.as_bytes());
    let mut hash_bytes = [0u8; 16];
    hash_bytes.copy_from_slice(&hash[..16]);
    let hash_num = u128::from_be_bytes(hash_bytes);
    let host_space = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let min_host = 2u128;
    let max_host = host_space.saturating_sub(1);
    let host = if max_host >= min_host {
        min_host + (hash_num % (max_host - min_host + 1))
    } else {
        1
    };
    let network_mask = if host_bits >= 128 { 0 } else { !host_space };
    let address = (gateway_val & network_mask) | host;
    Ipv6Addr::from(address).to_string()
}

fn bandwidth_limit() -> Option<String> {
    std::env::var("FERROCRATE_BANDWIDTH_LIMIT").ok()
}

struct WireGuardConfig {
    iface: String,
    ipv4_gateway: String,
    ipv4_prefix: u8,
    ipv6_gateway: Option<Ipv6Addr>,
    ipv6_prefix: Option<u8>,
}

#[derive(Debug)]
struct WireGuardPeerConfig {
    public_key: String,
    endpoint: String,
    allowed_ips: String,
}

fn wireguard_config() -> Result<WireGuardConfig, RuntimeError> {
    let iface = std::env::var("FERROCRATE_WG_IFACE").unwrap_or_else(|_| "wg0".to_string());
    if iface.trim().is_empty() {
        return Err(RuntimeError::Network(
            "invalid wireguard interface".to_string(),
        ));
    }
    let cidr =
        std::env::var("FERROCRATE_WG_IPV4_CIDR").unwrap_or_else(|_| "10.44.0.1/24".to_string());
    let mut parts = cidr.split('/');
    let ipv4_gateway = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv4 cidr".to_string()))?
        .to_string();
    let ipv4_prefix = parts
        .next()
        .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv4 cidr".to_string()))?
        .parse::<u8>()
        .map_err(|_| RuntimeError::Network("invalid wireguard ipv4 cidr".to_string()))?;
    let ipv6_cidr = std::env::var("FERROCRATE_WG_IPV6_CIDR").ok();
    let (ipv6_gateway, ipv6_prefix) = if let Some(cidr) = ipv6_cidr.as_deref() {
        let mut parts = cidr.split('/');
        let gateway = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv6 cidr".to_string()))?;
        let prefix = parts
            .next()
            .ok_or_else(|| RuntimeError::Network("invalid wireguard ipv6 cidr".to_string()))?
            .parse::<u8>()
            .map_err(|_| RuntimeError::Network("invalid wireguard ipv6 cidr".to_string()))?;
        let gateway = gateway
            .parse::<Ipv6Addr>()
            .map_err(|_| RuntimeError::Network("invalid wireguard ipv6 gateway".to_string()))?;
        (Some(gateway), Some(prefix))
    } else {
        (None, None)
    };
    Ok(WireGuardConfig {
        iface,
        ipv4_gateway,
        ipv4_prefix,
        ipv6_gateway,
        ipv6_prefix,
    })
}

fn wireguard_peer_config() -> Result<Option<WireGuardPeerConfig>, RuntimeError> {
    let Some(public_key) = std::env::var("FERROCRATE_WG_PEER_PUBLIC_KEY").ok() else {
        return Ok(None);
    };
    let endpoint = std::env::var("FERROCRATE_WG_PEER_ENDPOINT").map_err(|_| {
        RuntimeError::Network(
            "FERROCRATE_WG_PEER_ENDPOINT is required when peer public key is set".to_string(),
        )
    })?;
    let allowed_ips =
        std::env::var("FERROCRATE_WG_ALLOWED_IPS").unwrap_or_else(|_| "0.0.0.0/0".to_string());
    Ok(Some(WireGuardPeerConfig {
        public_key,
        endpoint,
        allowed_ips,
    }))
}

fn run_cmd_capture_stdout(args: &[String]) -> Result<String, RuntimeError> {
    let (bin, rest) = parse_cmd_args(args)?;
    let output = Command::new(bin).args(rest).output()?;
    if !output.status.success() {
        return Err(RuntimeError::Network(format!(
            "{}: {}",
            bin,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_cmd_with_stdin_capture_stdout(
    args: &[String],
    stdin_data: &str,
) -> Result<String, RuntimeError> {
    let (bin, rest) = parse_cmd_args(args)?;
    let mut child = Command::new(bin)
        .args(rest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(stdin_data.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(RuntimeError::Network(format!(
            "{}: {}",
            bin,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn wireguard_listen_port(container_id: &str) -> u16 {
    let base = std::env::var("FERROCRATE_WG_LISTEN_PORT_BASE")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(51820);
    let hash = rvf_crypto::shake256_256(container_id.as_bytes());
    let offset = (u16::from(hash[0]) << 8) | u16::from(hash[1]);
    base.saturating_add(offset % 1000)
}

fn setup_wireguard(
    netns_name: &str,
    container_id: &str,
) -> Result<(Option<String>, Option<String>), RuntimeError> {
    let cfg = wireguard_config()?;
    let peer = wireguard_peer_config()?;
    let ipv4 = allocate_container_ip(container_id, &cfg.ipv4_gateway)?;
    let ipv6 = if let Some((gateway, prefix)) = cfg.ipv6_gateway.as_ref().zip(cfg.ipv6_prefix) {
        let assigned = allocate_container_ipv6(container_id, gateway, prefix);
        Some(assigned)
    } else {
        None
    };
    let manager = WireGuardManager::new(Some(netns_name.to_string()));
    let key_path = if let Ok(path) = std::env::var("FERROCRATE_WG_PRIVATE_KEY_PATH") {
        PathBuf::from(path)
    } else if let Ok(key) = std::env::var("FERROCRATE_WG_PRIVATE_KEY") {
        manager
            .write_private_key(&cfg.iface, &key)
            .map_err(|error| RuntimeError::Network(error.to_string()))?
    } else {
        manager
            .generate_private_key(&cfg.iface)
            .map_err(|error| RuntimeError::Network(error.to_string()))?
    };
    let mut addresses = vec![format!("{ipv4}/{}", cfg.ipv4_prefix)
        .parse()
        .map_err(|_| RuntimeError::Network("invalid WireGuard IPv4 assignment".to_string()))?];
    if let Some(address) = &ipv6 {
        addresses.push(
            format!("{address}/{}", cfg.ipv6_prefix.unwrap_or_default())
                .parse()
                .map_err(|_| {
                    RuntimeError::Network("invalid WireGuard IPv6 assignment".to_string())
                })?,
        );
    }
    let peers = match peer {
        Some(peer) => {
            let allowed_ips = peer
                .allowed_ips
                .split(',')
                .map(str::trim)
                .map(str::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| RuntimeError::Network("invalid WireGuard allowed IPs".to_string()))?;
            vec![WireGuardPeer::new(
                container_id.to_string(),
                peer.public_key,
                peer.endpoint.parse().map_err(|_| {
                    RuntimeError::Network("invalid WireGuard peer endpoint".to_string())
                })?,
                allowed_ips,
            )]
        }
        None => Vec::new(),
    };
    let config = WireGuardInterfaceConfig {
        name: cfg.iface,
        private_key_path: key_path.clone(),
        listen_port: wireguard_listen_port(container_id),
        addresses,
    };
    let applied = manager.apply(&config, &peers);
    if std::env::var_os("FERROCRATE_WG_PRIVATE_KEY_PATH").is_none() {
        let _ = fs::remove_file(&key_path);
    }
    applied.map_err(|error| RuntimeError::Network(error.to_string()))?;
    Ok((Some(ipv4), ipv6))
}

fn apply_bandwidth_limit(link: &str, limit: &str) -> Result<(), RuntimeError> {
    if limit.trim().is_empty() {
        return Ok(());
    }
    if !command_available("tc") {
        return Err(RuntimeError::Network(
            "bandwidth limit requires tc command".to_string(),
        ));
    }
    let rate = validate_bandwidth_limit(limit)?;
    let cmd = vec![
        "tc".to_string(),
        "qdisc".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        link.to_string(),
        "root".to_string(),
        "tbf".to_string(),
        "rate".to_string(),
        rate.clone(),
        "burst".to_string(),
        "32kbit".to_string(),
        "latency".to_string(),
        "400ms".to_string(),
    ];
    run_cmd(&cmd)?;
    let verify = vec![
        "tc".to_string(),
        "qdisc".to_string(),
        "show".to_string(),
        "dev".to_string(),
        link.to_string(),
    ];
    let (bin, rest) = parse_cmd_args(&verify)?;
    let output = Command::new(bin).args(rest).output()?;
    if !output.status.success() {
        return Err(RuntimeError::Network(
            "failed to verify bandwidth limit".to_string(),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("tbf") {
        return Err(RuntimeError::Network(format!(
            "bandwidth limit verification failed for {link}"
        )));
    }
    Ok(())
}

fn validate_bandwidth_limit(limit: &str) -> Result<String, RuntimeError> {
    let value = limit.trim().to_ascii_lowercase();
    let units = ["kbit", "mbit", "gbit"];
    let unit = units
        .iter()
        .find(|unit| value.ends_with(*unit))
        .ok_or_else(|| {
            RuntimeError::Network("bandwidth limit must end with kbit, mbit, or gbit".to_string())
        })?;
    let digits = value.trim_end_matches(unit);
    if digits.is_empty() || digits.parse::<u64>().map(|v| v == 0).unwrap_or(true) {
        return Err(RuntimeError::Network(
            "bandwidth limit must be a positive integer with unit".to_string(),
        ));
    }
    Ok(value)
}

fn security_ebpf_monitor_enabled() -> bool {
    std::env::var("FERROCRATE_EBPF_SECURITY_MONITOR")
        .or_else(|_| std::env::var("FERROCRATE_SECURITY_EBPF_MONITOR"))
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn security_ebpf_events() -> Vec<String> {
    std::env::var("FERROCRATE_EBPF_SECURITY_EVENTS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|events| !events.is_empty())
        .unwrap_or_else(|| {
            vec![
                "execve".to_string(),
                "connect".to_string(),
                "open".to_string(),
                "ptrace".to_string(),
                "mount".to_string(),
                "unshare".to_string(),
            ]
        })
}

fn setup_security_ebpf_monitor(container_id: &str) -> Result<(), RuntimeError> {
    if !command_available("bpftool") {
        return Err(RuntimeError::Network(
            "security ebpf monitor requires bpftool".to_string(),
        ));
    }
    let object_path = std::env::var("FERROCRATE_EBPF_SECURITY_OBJECT")
        .unwrap_or_else(|_| "/usr/lib/ferrocrate/ferro-security.o".to_string());
    let pin_root = std::env::var("FERROCRATE_EBPF_SECURITY_PIN_ROOT")
        .unwrap_or_else(|_| format!("/sys/fs/bpf/ferrocrate-security-{container_id}"));
    let config = SecurityMonitorConfig {
        object_path,
        pin_root,
        events: security_ebpf_events(),
    };
    let installed =
        install_security_monitor(&config).map_err(|err| RuntimeError::Network(err.to_string()))?;
    log::info!(
        "security ebpf monitor active for container {} events={:?}",
        container_id,
        installed
    );
    Ok(())
}

fn short_id(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .rev()
        .take(max)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

fn should_restart(policy: &RestartPolicy, status: &str, exit_code: i32) -> bool {
    if status == "stopped" || status == "killed" {
        return false;
    }
    match policy {
        RestartPolicy::No => false,
        RestartPolicy::Always => true,
        RestartPolicy::UnlessStopped => true,
        RestartPolicy::OnFailure => exit_code != 0,
    }
}

fn update_pid_status(
    db: &sled::Db,
    id: &str,
    pid: u32,
    status: &str,
) -> Result<(), ContainerStoreError> {
    use sled::transaction::{ConflictableTransactionError, TransactionError};
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    tree.transaction(|tree| {
        let Some(bytes) = tree.get(id.as_bytes())? else {
            return Ok(());
        };
        let mut record = serde_json::from_slice::<ContainerRecord>(&bytes).map_err(|error| {
            ConflictableTransactionError::Abort(ContainerStoreError::Decode(error))
        })?;
        if record.pending_mutation.is_some() {
            return Err(ConflictableTransactionError::Abort(
                ContainerStoreError::MutationConflict,
            ));
        }
        record.pid = pid;
        record.status = status.to_string();
        let encoded = serde_json::to_vec(&record).map_err(|error| {
            ConflictableTransactionError::Abort(ContainerStoreError::Encode(error))
        })?;
        tree.insert(id.as_bytes(), encoded)?;
        Ok(())
    })
    .map_err(|error| match error {
        TransactionError::Abort(error) => error,
        TransactionError::Storage(error) => ContainerStoreError::Open(error),
    })?;
    tree.flush()?;
    Ok(())
}

fn update_exit(db: &sled::Db, id: &str, exit_code: i32) -> Result<String, ContainerStoreError> {
    use sled::transaction::{ConflictableTransactionError, TransactionError};
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    let status = tree
        .transaction(|tree| {
            let Some(bytes) = tree.get(id.as_bytes())? else {
                return Ok("exited".to_string());
            };
            let mut record =
                serde_json::from_slice::<ContainerRecord>(&bytes).map_err(|error| {
                    ConflictableTransactionError::Abort(ContainerStoreError::Decode(error))
                })?;
            if record.pending_mutation.is_some() {
                return Err(ConflictableTransactionError::Abort(
                    ContainerStoreError::MutationConflict,
                ));
            }
            record.last_exit_code = Some(exit_code);
            if record.status != "stopped" && record.status != "killed" {
                record.status = "exited".to_string();
            }
            let status = record.status.clone();
            let encoded = serde_json::to_vec(&record).map_err(|error| {
                ConflictableTransactionError::Abort(ContainerStoreError::Encode(error))
            })?;
            tree.insert(id.as_bytes(), encoded)?;
            Ok(status)
        })
        .map_err(|error| match error {
            TransactionError::Abort(error) => error,
            TransactionError::Storage(error) => ContainerStoreError::Open(error),
        })?;
    tree.flush()?;
    Ok(status)
}

fn update_health(
    db: &sled::Db,
    id: &str,
    status: &str,
    failures: u32,
    checked_at_unix: u64,
) -> Result<bool, ContainerStoreError> {
    let tree = db.open_tree(crate::container_store::CONTAINER_INDEX_TREE)?;
    let Some(bytes) = tree.get(id.as_bytes())? else {
        return Ok(false);
    };
    let mut record =
        serde_json::from_slice::<ContainerRecord>(&bytes).map_err(ContainerStoreError::Decode)?;
    record.health_status = status.to_string();
    record.health_failures = failures;
    record.health_checked_at_unix = Some(checked_at_unix);
    let encoded = serde_json::to_vec(&record)?;
    tree.insert(id.as_bytes(), encoded)?;
    tree.flush()?;
    Ok(true)
}

fn run_health_checks(
    store: sled::Db,
    id: String,
    pid: u32,
    config: HealthConfig,
    cancel: Arc<AtomicBool>,
) {
    // Cancellation-aware start period sleep
    if config.start_period_secs > 0 {
        let deadline = std::time::Instant::now() + Duration::from_secs(config.start_period_secs);
        while std::time::Instant::now() < deadline {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    let mut failures = 0_u32;
    loop {
        // Check for explicit cancellation
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Check if container still exists (handles removal during health check)
        let tree = match store.open_tree("containers") {
            Ok(t) => t,
            Err(_) => return, // Store error, exit
        };
        if !tree.contains_key(&id).unwrap_or(false) {
            return; // Container removed, exit
        }

        let result = if config.timeout_secs > 0 {
            exec_in_container_with_timeout(
                pid,
                &config.cmd,
                Duration::from_secs(config.timeout_secs),
            )
        } else {
            exec_in_container(pid, &config.cmd)
        };
        let now = now_unix();
        match result {
            Ok(exec) if exec.exit_code == 0 => {
                failures = 0;
                if let Err(e) = update_health(&store, &id, "healthy", failures, now) {
                    warn!("failed to update health for {id}: {e}");
                }
            }
            Ok(_) | Err(_) => {
                failures = failures.saturating_add(1);
                let status = if failures >= config.retries.max(1) {
                    "unhealthy"
                } else {
                    "starting"
                };
                match update_health(&store, &id, status, failures, now) {
                    Ok(true) => {}
                    Ok(false) => return, // Container gone
                    Err(_) => {}
                }
            }
        }

        // Cancellation-aware interval sleep
        let deadline = std::time::Instant::now() + Duration::from_secs(config.interval_secs);
        while std::time::Instant::now() < deadline {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}

// ============================================================================
// AI Resource Monitoring (Task 5.1 - Predictive OOM Prevention)
// ============================================================================

/// Check if AI features are enabled via environment variable.
///
/// Returns true if FERROCRATE_AI is set to "1" or "true".
/// When disabled, no AI-related threads are spawned for zero overhead.
fn is_ai_enabled() -> bool {
    std::env::var("FERROCRATE_AI")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Resource monitor thread for predictive OOM prevention (Task 5.1).
///
/// This function runs in a background thread, periodically reading cgroup v2
/// metrics and using the ResourcePredictor to predict OOM conditions.
///
/// # Arguments
/// * `store` - Container store for checking container existence
/// * `id` - Container ID to monitor
/// * `cgroup_root` - Path to cgroup v2 mount (typically /sys/fs/cgroup)
/// * `memory_limit` - Memory limit in bytes (0 = no limit)
/// * `cancel` - Cancellation token for graceful shutdown
///
/// # Behavior
/// - Samples metrics every 30 seconds
/// - Logs OOM predictions to stderr when detected
/// - Writes predictions to audit log with DecisionTrace
/// - Progressive rollout: v0.1 observe only, v0.2 suggestions, v0.3 auto-adjust
fn run_resource_monitor(
    store: sled::Db,
    id: String,
    cgroup_root: PathBuf,
    memory_limit: u64,
    cancel: Arc<AtomicBool>,
) {
    use std::time::Instant;

    // No limit = nothing to predict
    if memory_limit == 0 {
        return;
    }

    // Initialize predictor with memory limit
    let mut predictor =
        ferro_mind::ai::resource::ResourcePredictor::new(60).with_memory_limit(memory_limit);
    let ai_logger = ferro_mind::ai::audit::AuditLogger::from_env();

    let mut anomaly_detector = ferro_mind::ai::anomaly::NeuralAnomalyDetector::new(3, 0.5);
    let mut anomaly_training_samples: Vec<Vec<f32>> = Vec::new();
    let anomaly_train_after = 20usize; // Train after 20 samples of normal behavior

    let sample_interval = Duration::from_secs(30);
    let oom_horizon = Duration::from_secs(1200); // 20 minutes

    loop {
        // Check for explicit cancellation
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Check if container still exists
        let tree = match store.open_tree("containers") {
            Ok(t) => t,
            Err(_) => return,
        };
        if !tree.contains_key(&id).unwrap_or(false) {
            return; // Container removed
        }

        // Read cgroup metrics
        let cgroup_path = cgroup_root.join("ferrocrate").join(&id);
        if let Ok(metrics) = ferro_mind::ai::resource::read_cgroup_metrics(&cgroup_path) {
            // Create sample with current metrics
            let sample = ferro_mind::ai::resource::ResourceSample {
                cpu_percent: 0.0, // CPU percentage requires delta calculation
                memory_bytes: metrics.memory_current,
                pids_count: metrics.pids_current,
                timestamp: Instant::now(),
            };

            predictor.push(sample);

            // Build normalized feature vector for anomaly detection
            // Features: [cpu_norm, mem_norm, pids_norm] normalized 0-1
            let mem_norm = if memory_limit > 0 {
                metrics.memory_current as f32 / memory_limit as f32
            } else {
                0.0f32
            };
            let cpu_norm = (sample.cpu_percent / 100.0).clamp(0.0, 1.0);
            let pids_norm = (metrics.pids_current as f32 / 1000.0).clamp(0.0, 1.0);
            let features = vec![cpu_norm, mem_norm, pids_norm];

            // Accumulate training samples during initial "normal" phase
            if !anomaly_detector.is_trained() {
                anomaly_training_samples.push(features.clone());
                if anomaly_training_samples.len() >= anomaly_train_after {
                    anomaly_detector.train(&anomaly_training_samples, 50);
                    info!(container = %id, samples = anomaly_training_samples.len(), "anomaly detector trained");
                }
            } else {
                // Detect anomalies once trained
                let score = anomaly_detector.detect(&features);
                if score.is_anomalous() {
                    warn!(
                        container = %id,
                        score = format!("{:.3}", score.score),
                        threshold = format!("{:.3}", score.threshold),
                        "anomaly detected"
                    );
                }
            }

            let latest_prediction = predictor.predict();

            // Predict OOM
            if let Some(prediction) = predictor.predict_oom(oom_horizon) {
                let minutes = prediction.time_to_oom.as_secs() / 60;
                let current_mb = prediction.current_memory as f64 / 1024.0 / 1024.0;
                let limit_mb = prediction.memory_limit as f64 / 1024.0 / 1024.0;
                let confidence_pct = prediction.confidence * 100.0;

                // v0.1: Log via tracing (observe only)
                warn!(
                    container = %id,
                    current_mb = format!("{:.1}", current_mb),
                    limit_mb = format!("{:.1}", limit_mb),
                    minutes = minutes,
                    confidence = format!("{:.0}%", confidence_pct),
                    "memory projected to exceed limit"
                );

                // Log to audit log for AI explainability (AI-11)
                let _ = log_audit_event(
                    &PathBuf::from(std::env::var("FERROCRATE_RUNTIME_DIR")
                        .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string())),
                    make_audit_event(
                        "ai_oom_prediction",
                        "ferrocrate-ai",
                        Some(&id),
                        None,
                        None,
                        Some(&format!(
                            "current_memory={} memory_limit={} time_to_oom_secs={} confidence={:.2}",
                            prediction.current_memory, prediction.memory_limit,
                            prediction.time_to_oom.as_secs(), prediction.confidence
                        )),
                    ),
                );

                if let Some(logger) = ai_logger.as_ref() {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let mut trace = ferro_mind::ai::explain::DecisionTrace::new(
                        format!("oom-prediction-{id}-{ts}"),
                        format!(
                            "Container {id} predicted to exceed memory limit in {} seconds",
                            prediction.time_to_oom.as_secs()
                        ),
                    )
                    .with_evidence("container_id", id.clone())
                    .with_evidence(
                        "current_memory_bytes",
                        prediction.current_memory.to_string(),
                    )
                    .with_evidence("memory_limit_bytes", prediction.memory_limit.to_string())
                    .with_evidence(
                        "predicted_peak_bytes",
                        prediction.predicted_peak.to_string(),
                    )
                    .with_evidence(
                        "time_to_oom_secs",
                        prediction.time_to_oom.as_secs().to_string(),
                    )
                    .with_evidence("confidence", format!("{:.4}", prediction.confidence))
                    .with_evidence("current_pids", metrics.pids_current.to_string())
                    .with_evidence("memory_current_cgroup", metrics.memory_current.to_string());
                    if let Some(pred) = latest_prediction {
                        trace = trace
                            .with_evidence(
                                "predicted_cpu_percent",
                                format!("{:.2}", pred.cpu_percent),
                            )
                            .with_evidence("predicted_memory_bytes", pred.memory_bytes.to_string())
                            .with_evidence(
                                "memory_growth_rate_bytes_per_sec",
                                format!("{:.2}", pred.memory_growth_rate),
                            );
                    }
                    let _ = logger.log("ai_oom_prediction", &trace);
                }

                // v0.2: FERROCRATE_AI_SUGGEST=1 — print suggestions
                if std::env::var("FERROCRATE_AI_SUGGEST")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                {
                    info!(
                        container = %id,
                        suggested_limit_mb = (limit_mb * 1.5) as u64,
                        "suggestion: consider increasing memory limit with 'ferrocrate update --memory'"
                    );
                }

                // v0.3: FERROCRATE_AI_ACT=1 — auto-adjust cgroup limit (opt-in)
                if std::env::var("FERROCRATE_AI_ACT")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                {
                    let manager = CgroupV2Manager::new(&cgroup_root);
                    let new_limit = (memory_limit as f64 * 1.25) as u64; // 25% increase
                    let ceiling = std::env::var("FERROCRATE_AI_ACT_MEMORY_CEILING")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(u64::MAX);

                    let adjusted_limit = new_limit.min(ceiling);
                    match manager.adjust_memory_limit(&cgroup_path, adjusted_limit) {
                        Ok(()) => {
                            info!(
                                container = %id,
                                new_limit_mb = adjusted_limit / 1024 / 1024,
                                "increased memory limit"
                            );
                            predictor.set_memory_limit(adjusted_limit);
                        }
                        Err(e) => {
                            warn!(
                                container = %id,
                                error = %e,
                                "failed to adjust memory limit"
                            );
                        }
                    }
                }
            }
        }

        // Cancellation-aware sleep
        let sleep_start = std::time::Instant::now();
        while std::time::Instant::now().duration_since(sleep_start) < sample_interval {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ContainerRuntime, NetworkBackend};
    use crate::cgroups::{CpuMax, ResourceLimits};
    use crate::container_store::{now_unix, ContainerRecord, PortMappingRecord, RestartPolicy};
    use crate::image_manifest::OCI_IMAGE_MANIFEST_MEDIA_TYPE;
    use crate::image_store::LocalImageStore;
    use crate::image_tagging::canonicalize_reference;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CGROUP_ENV_LOCK: Mutex<()> = Mutex::new(());
    static RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Helper to acquire lock, recovering from poison (for test isolation)
    fn acquire_lock(lock: &Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
        lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Check if we can run container tests (requires root or capabilities)
    fn can_run_containers() -> bool {
        // Must be root to create namespaces and manage cgroups
        nix::unistd::Uid::effective().is_root()
    }

    #[test]
    fn run_starts_process_and_persists_record() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo hi && sleep 0.05".to_string(),
                ],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
            )
            .expect("run");

        let listed = runtime.list().expect("list");
        assert!(listed.iter().any(|c| c.id == record.id));
    }

    #[test]
    fn logs_returns_output() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
            )
            .expect("run");

        let logs = wait_for_logs(&runtime, &record.id).expect("logs");
        assert!(logs.contains("hi"));
    }

    #[test]
    fn run_uses_image_config_command_when_missing() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");
        write_image_config(
            temp.path(),
            r#"{"config":{"Entrypoint":["/bin/sh","-c"],"Cmd":["echo hi"]}}"#,
        );

        let record = runtime
            .run(
                "alpine:latest",
                &[],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
            )
            .expect("run");

        assert_eq!(
            record.command,
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hi".to_string()
            ]
        );
    }

    #[test]
    fn run_merges_env_and_respects_workdir_user() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");
        write_image_config(
            temp.path(),
            r#"{"config":{"Env":["A=1","B=2"],"WorkingDir":"/app","User":"1001:1002"}}"#,
        );
        let workdir_path = temp.path().join("workdir");
        std::fs::create_dir_all(&workdir_path).expect("workdir");
        let workdir = workdir_path.to_string_lossy().to_string();

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "echo hi".to_string()],
                &["A=override".to_string(), "C=3".to_string()],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                Some(&workdir),
                Some("1000:1000"),
                Some("named"),
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
            )
            .expect("run");

        assert!(record.env.contains(&"A=override".to_string()));
        assert!(record.env.contains(&"B=2".to_string()));
        assert!(record.env.contains(&"C=3".to_string()));
        assert_eq!(record.workdir.as_deref(), Some(workdir.as_str()));
        assert_eq!(record.user.as_deref(), Some("1000:1000"));
        assert_eq!(record.name.as_deref(), Some("named"));
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
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 1".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
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
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 1".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
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

    #[test]
    fn startup_reconcile_marks_stale_running_pid_exited() {
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let store =
            crate::container_store::LocalContainerStore::open(temp.path().join("containers.db"))
                .expect("store");

        let record = ContainerRecord {
            id: "stale-running".to_string(),
            name: None,
            pid: 999_999,
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string(), "1".to_string()],
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
        store.put(&record).expect("seed stale record");
        drop(store);

        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let reconciled = runtime.inspect("stale-running").expect("inspect");
        assert_eq!(reconciled.status, "exited");
        assert_eq!(reconciled.last_exit_code, Some(-1));
    }

    #[test]
    fn startup_reconcile_keeps_live_running_pid() {
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let store =
            crate::container_store::LocalContainerStore::open(temp.path().join("containers.db"))
                .expect("store");

        let record = ContainerRecord {
            id: "live-running".to_string(),
            name: None,
            pid: std::process::id(),
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string(), "1".to_string()],
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
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
            managed_overlay: None,
            managed_host_veth: None,
        };
        store.put(&record).expect("seed live record");
        drop(store);

        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        let reconciled = runtime.inspect("live-running").expect("inspect");
        assert_eq!(reconciled.status, "running");
        assert_eq!(reconciled.last_exit_code, None);
    }

    #[test]
    fn run_applies_cgroup_limits_when_set() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("cgroup");
        std::fs::create_dir_all(&root).expect("cgroup root");

        std::fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        std::fs::write(root.join("cgroup.subtree_control"), "").expect("subtree control");

        unsafe {
            std::env::set_var("FERROCRATE_CGROUP_ROOT", &root);
        }
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let limits = ResourceLimits {
            memory_max: Some(1024),
            cpu_max: Some(CpuMax {
                quota: 1000,
                period: 1000,
            }),
            pids_max: Some(8),
        };

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 0.05".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                Some(&limits),
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
            )
            .expect("run");

        let group = root.join("ferrocrate").join(&record.id);
        assert_eq!(
            std::fs::read_to_string(group.join("memory.max")).expect("memory.max"),
            "1024"
        );
        assert_eq!(
            std::fs::read_to_string(group.join("cpu.max")).expect("cpu.max"),
            "1000 1000"
        );
        assert_eq!(
            std::fs::read_to_string(group.join("pids.max")).expect("pids.max"),
            "8"
        );
        assert_eq!(
            std::fs::read_to_string(group.join("cgroup.procs")).expect("cgroup.procs"),
            record.pid.to_string()
        );

        unsafe {
            std::env::remove_var("FERROCRATE_CGROUP_ROOT");
        }
    }

    #[test]
    fn pause_and_resume_updates_status() {
        if !can_run_containers() {
            eprintln!("SKIP: requires root privileges for container operations");
            return;
        }
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let _runtime_guard = acquire_lock(&RUNTIME_TEST_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("cgroup");
        std::fs::create_dir_all(&root).expect("cgroup root");

        std::fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        std::fs::write(root.join("cgroup.subtree_control"), "").expect("subtree control");

        unsafe {
            std::env::set_var("FERROCRATE_CGROUP_ROOT", &root);
        }
        let runtime = ContainerRuntime::new(temp.path()).expect("runtime");
        seed_image_store(temp.path(), "alpine:latest");

        let record = runtime
            .run(
                "alpine:latest",
                &["sh".to_string(), "-c".to_string(), "sleep 0.1".to_string()],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                false,
                None,
                None,
                None,
                &[],
                "bridge",
                NetworkBackend::Ebpf,
                None,
            )
            .expect("run");

        runtime.pause(&record.id).expect("pause");
        let paused = runtime.inspect(&record.id).expect("inspect");
        assert_eq!(paused.status, "paused");

        runtime.resume(&record.id).expect("resume");
        let resumed = runtime.inspect(&record.id).expect("inspect");
        assert_eq!(resumed.status, "running");

        unsafe {
            std::env::remove_var("FERROCRATE_CGROUP_ROOT");
        }
    }

    #[test]
    fn runtime_dns_config_defaults() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_DNS_SERVERS");
            std::env::remove_var("FERROCRATE_DNS_SEARCH");
        }
        let cfg = super::runtime_dns_config();
        assert_eq!(cfg.servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(cfg.search, vec!["ferro.local"]);
    }

    #[test]
    fn normalized_run_request_retains_fd_backed_mount_and_security_facts() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let request = super::normalize_run_request(
            &[caps::Capability::CAP_NET_BIND_SERVICE],
            &[crate::mounts::BindMount {
                source,
                target: "data".into(),
                read_only: true,
            }],
            &[crate::mounts::TmpfsMount {
                target: "tmp".into(),
                size: Some("64m".into()),
            }],
            true,
            true,
            "bridge",
            ferro_net::NetworkBackend::Iptables,
            &[],
        )
        .unwrap();
        assert!(request.bind_mounts[0].source.starts_with("/proc/self/fd/"));
        assert_eq!(request.facts.mounts.len(), 2);
        assert_ne!(request.facts.mounts[0].target_digest, [0; 32]);
        assert_ne!(
            request.facts.mounts[0].target_digest,
            request.facts.mounts[1].target_digest
        );
        assert!(request.facts.readonly_rootfs);
        assert!(request.facts.no_new_privileges);
        assert!(request
            .facts
            .network_ids
            .iter()
            .any(|id| id == "mode:bridge"));
        assert_eq!(request.facts.capabilities, ["CAP_NET_BIND_SERVICE"]);
    }

    #[test]
    fn normalized_run_request_rejects_unsafe_mount_targets() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        for target in ["/escape", "../escape", "safe/../escape", "safe/\nsecret"] {
            let result = super::normalize_run_request(
                &[],
                &[crate::mounts::BindMount {
                    source: source.clone(),
                    target: target.into(),
                    read_only: false,
                }],
                &[],
                false,
                false,
                "none",
                ferro_net::NetworkBackend::Iptables,
                &[],
            );
            assert!(result.is_err(), "accepted target {target:?}");
        }
    }

    #[test]
    fn runtime_dns_config_respects_env() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_DNS_SERVERS", "9.9.9.9,1.0.0.1");
            std::env::set_var("FERROCRATE_DNS_SEARCH", "svc.local,cluster.local");
        }
        let cfg = super::runtime_dns_config();
        assert_eq!(cfg.servers, vec!["9.9.9.9", "1.0.0.1"]);
        assert_eq!(cfg.search, vec!["svc.local", "cluster.local"]);
        unsafe {
            std::env::remove_var("FERROCRATE_DNS_SERVERS");
            std::env::remove_var("FERROCRATE_DNS_SEARCH");
        }
    }

    fn fixture_network_mapping() -> Vec<PortMappingRecord> {
        vec![PortMappingRecord {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        }]
    }

    #[test]
    fn ebpf_plan_contains_no_netfilter_commands() {
        let plan = super::build_network_plan(
            NetworkBackend::Ebpf,
            "fixture-container",
            &fixture_network_mapping(),
            "10.0.0.2",
            "10.0.0.0/24",
            "ferro0",
        )
        .expect("eBPF plan");

        assert!(plan.commands().iter().all(|command| {
            !matches!(
                command.first().map(String::as_str),
                Some("iptables" | "nft")
            )
        }));
    }

    #[test]
    fn iptables_plan_contains_only_iptables_firewall_commands() {
        let plan = super::build_network_plan(
            NetworkBackend::Iptables,
            "fixture-container",
            &fixture_network_mapping(),
            "10.0.0.2",
            "10.0.0.0/24",
            "ferro0",
        )
        .expect("iptables plan");

        assert!(plan
            .commands()
            .iter()
            .all(|command| command.first().map(String::as_str) == Some("iptables")));
    }

    #[test]
    fn nftables_plan_contains_only_nft_firewall_commands() {
        let plan = super::build_network_plan(
            NetworkBackend::Nftables,
            "fixture-container",
            &fixture_network_mapping(),
            "10.0.0.2",
            "10.0.0.0/24",
            "ferro0",
        )
        .expect("nftables plan");

        assert!(plan
            .commands()
            .iter()
            .all(|command| command.first().map(String::as_str) == Some("nft")));
    }

    fn fixture_ebpf_ownership() -> crate::container_store::NetworkOwnershipRecord {
        crate::container_store::NetworkOwnershipRecord {
            schema_version: 2,
            owner_id: "fixture-container".to_string(),
            network_id: Some("bridge-fixture".to_string()),
            host_interface: "vethfixture".to_string(),
            host_ifindex: Some(41),
            namespace_identity: Some(crate::container_store::KernelObjectIdentityRecord {
                device: 7,
                inode: 11,
            }),
            managed_interface: Some("eth-fixture".to_string()),
            managed_ifindex: Some(17),
            loopback_ifindex: Some(1),
            bridge_ifindex: Some(9),
            source_cidr: Some("10.0.0.0/24".to_string()),
            bridge: Some("ferro0".to_string()),
            firewall_id: None,
            firewall_marker: None,
            firewall_expected_state: None,
            ebpf_pin_path: Some("/sys/fs/bpf/ferrocrate/bridge-fixture".to_string()),
            external_ipv4: Some("203.0.113.8".to_string()),
            next_hop_mac: Some("02:aa:bb:cc:dd:ee".to_string()),
            snat_port_start: Some(50_000),
            snat_port_end: Some(50_031),
            object_sha256: Some(hex::encode(super::embedded_object_sha256())),
            object_abi: Some(super::embedded_object_abi().unwrap()),
            ebpf_filters: Vec::new(),
            ebpf_pins: Vec::new(),
        }
    }

    fn fixture_container_record(id: &str, status: &str) -> ContainerRecord {
        ContainerRecord {
            id: id.to_string(),
            name: None,
            pid: 999_999,
            image: "fixture:latest".to_string(),
            command: vec!["true".to_string()],
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
            stdout_path: "/tmp/fixture.stdout".to_string(),
            stderr_path: "/tmp/fixture.stderr".to_string(),
            status: status.to_string(),
            netns: None,
            network_name: Some("bridge".to_string()),
            ip_address: Some("10.44.1.2".to_string()),
            ipv6_address: None,
            ports: Vec::new(),
            network_backend: None,
            network_ownership: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
            managed_overlay: None,
            managed_host_veth: None,
        }
    }

    #[derive(Default)]
    struct FakeGlobalValueStore {
        value: String,
        writes: Vec<String>,
    }

    impl super::GlobalValueStore for FakeGlobalValueStore {
        fn read(&mut self) -> Result<String, super::RuntimeError> {
            Ok(self.value.clone())
        }

        fn write(&mut self, value: &str) -> Result<(), super::RuntimeError> {
            self.value = value.to_string();
            self.writes.push(value.to_string());
            Ok(())
        }
    }

    #[test]
    fn network_backend_ip_forward_restores_only_its_owned_transition() {
        let mut store = FakeGlobalValueStore {
            value: "0".to_string(),
            ..FakeGlobalValueStore::default()
        };
        let ownership = super::acquire_ip_forwarding_with(&mut store)
            .unwrap()
            .expect("0 to 1 transition is owned");
        assert_eq!(store.value, "1");
        super::restore_ip_forwarding_with(&ownership, &mut store).unwrap();
        assert_eq!(store.value, "0");
        assert_eq!(store.writes, vec!["1", "0"]);

        let mut already_enabled = FakeGlobalValueStore {
            value: "1".to_string(),
            ..FakeGlobalValueStore::default()
        };
        assert!(super::acquire_ip_forwarding_with(&mut already_enabled)
            .unwrap()
            .is_none());
        assert!(already_enabled.writes.is_empty());
    }

    #[test]
    fn network_backend_ip_forward_foreign_replacement_is_never_overwritten() {
        let mut store = FakeGlobalValueStore {
            value: "0".to_string(),
            ..FakeGlobalValueStore::default()
        };
        let ownership = super::acquire_ip_forwarding_with(&mut store)
            .unwrap()
            .unwrap();
        store.value = "2".to_string();
        assert!(super::restore_ip_forwarding_with(&ownership, &mut store).is_err());
        assert_eq!(store.value, "2");
        assert_eq!(store.writes, vec!["1"]);
    }

    #[test]
    fn network_backend_pending_cleanup_journal_is_consumed_behaviorally() {
        let temp = tempfile::tempdir().unwrap();
        let container_dir = temp.path().join("containers").join("pending-owner");
        std::fs::create_dir_all(&container_dir).unwrap();
        let pending = super::PendingNetworkCleanup {
            schema_version: 1,
            container_id: "pending-owner".to_string(),
            netns_name: None,
            namespace_identity: None,
            host_veth: None,
            container_ip: None,
            port_mappings: Vec::new(),
            network_backend: None,
            network_ownership: None,
            network_persisted: false,
            shared_network_created: false,
            bridge_created: None,
            ip_forward: None,
            pending_firewall_cleanup: Vec::new(),
        };
        std::fs::write(
            container_dir.join("network-cleanup-pending.json"),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
        let store =
            crate::container_store::LocalContainerStore::open(temp.path().join("containers.db"))
                .unwrap();

        let authorization =
            crate::authorization::runtime::RuntimeAuthorization::compatibility_with_id([1; 16]);
        super::recover_pending_network_cleanups(temp.path(), &store, temp.path(), &authorization)
            .unwrap();
        assert!(!container_dir.exists());
    }

    #[test]
    fn network_backend_restart_reconciles_stopped_record_before_process_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = ContainerRuntime::new(temp.path()).unwrap();
        let record = fixture_container_record("stopped-owned", "stopped");
        runtime.store.put(&record).unwrap();

        let error = runtime
            .restart("stopped-owned", std::time::Duration::from_millis(1))
            .unwrap_err();
        assert!(error.to_string().contains("ownership"));
        assert_eq!(runtime.inspect("stopped-owned").unwrap().status, "stopped");
    }

    #[test]
    fn network_backend_startup_reconciles_running_and_paused_records() {
        for status in ["running", "paused"] {
            let temp = tempfile::tempdir().unwrap();
            let store = crate::container_store::LocalContainerStore::open(
                temp.path().join("containers.db"),
            )
            .unwrap();
            store
                .put(&fixture_container_record(status, status))
                .unwrap();
            drop(store);
            let error = match ContainerRuntime::new(temp.path()) {
                Ok(_) => panic!("{status} malformed network unexpectedly reconciled"),
                Err(error) => error,
            };
            assert!(
                error.to_string().contains("ownership"),
                "status {status}: {error}"
            );
        }
    }

    #[test]
    fn network_backend_legacy_nonbridge_namespace_is_retained_without_identity() {
        let mut record = fixture_container_record("legacy-none", "stopped");
        record.network_name = Some("none".to_string());
        record.netns = Some("must-not-delete-by-name".to_string());

        let error = super::cleanup_network(&record, std::slice::from_ref(&record)).unwrap_err();
        assert!(error.to_string().contains("no kernel identity"));
        assert_eq!(record.netns.as_deref(), Some("must-not-delete-by-name"));
    }

    #[derive(Default)]
    struct FakeFirewallRunner {
        live: Vec<Vec<String>>,
        calls: Vec<Vec<String>>,
        fail_setup_at: Option<usize>,
        fail_cleanup_at: Option<usize>,
        setup_attempts: usize,
        cleanup_attempts: usize,
    }

    impl super::FirewallCommandRunner for FakeFirewallRunner {
        fn run(&mut self, command: &[String]) -> Result<(), super::RuntimeError> {
            self.calls.push(command.to_vec());
            let action = command.get(3).map(String::as_str);
            if matches!(action, Some("-N" | "-A")) {
                let attempt = self.setup_attempts;
                self.setup_attempts += 1;
                if self.fail_setup_at == Some(attempt) {
                    return Err(super::RuntimeError::Network(
                        "injected setup failure".to_string(),
                    ));
                }
            }
            match action {
                Some("-N") => {
                    if self.live.iter().any(|existing| {
                        existing.get(1) == command.get(1)
                            && existing.get(2) == command.get(2)
                            && existing.get(4) == command.get(4)
                    }) {
                        return Err(super::RuntimeError::Network(
                            "foreign chain already exists".to_string(),
                        ));
                    }
                    self.live.push(command.to_vec());
                }
                Some("-A") => self.live.push(command.to_vec()),
                Some("-X" | "-D") => {
                    let setup_action = if action == Some("-X") { "-N" } else { "-A" };
                    let mut setup = command.to_vec();
                    setup[3] = setup_action.to_string();
                    if let Some(index) = self.live.iter().position(|existing| existing == &setup) {
                        self.live.remove(index);
                    }
                }
                Some("-F") => {
                    self.live.retain(|existing| {
                        existing.get(1) != command.get(1)
                            || existing.get(2) != command.get(2)
                            || existing.get(3).map(String::as_str) != Some("-A")
                            || existing.get(4) != command.get(4)
                    });
                }
                _ => {}
            }
            Ok(())
        }

        fn run_cleanup(&mut self, command: &[String]) -> Result<(), super::RuntimeError> {
            let attempt = self.cleanup_attempts;
            self.cleanup_attempts += 1;
            if self.fail_cleanup_at == Some(attempt) {
                return Err(super::RuntimeError::Network(
                    "injected cleanup failure".to_string(),
                ));
            }
            self.run(command)
        }

        fn capture(
            &mut self,
            _backend: NetworkBackend,
            firewall_id: &str,
        ) -> Result<Option<String>, super::RuntimeError> {
            let state = self
                .live
                .iter()
                .filter(|command| {
                    command
                        .iter()
                        .any(|argument| argument.contains(firewall_id))
                })
                .map(|command| command.join(" "))
                .collect::<Vec<_>>()
                .join("\n");
            Ok((!state.is_empty()).then_some(state))
        }
    }

    fn fixture_firewall_plan() -> ferro_net::portmap::NetworkPlan {
        super::build_network_plan(
            NetworkBackend::Iptables,
            "transaction-owner",
            &fixture_network_mapping(),
            "10.0.0.2",
            "10.0.0.0/24",
            "ferro0",
        )
        .unwrap()
    }

    #[test]
    fn network_backend_firewall_setup_captures_canonical_marker_behaviorally() {
        let plan = fixture_firewall_plan();
        let mut runner = FakeFirewallRunner::default();
        let mut acquired = Vec::new();
        let captured = super::apply_and_capture_network_plan_with(
            NetworkBackend::Iptables,
            &plan,
            &mut acquired,
            &mut runner,
        )
        .unwrap();

        assert!(captured.contains(&plan.ownership_marker().unwrap()));
        assert_eq!(acquired.len(), plan.commands().len());
        assert_eq!(runner.live.len(), plan.commands().len());
    }

    #[test]
    fn network_backend_foreign_first_chain_failure_performs_zero_cleanup() {
        let plan = fixture_firewall_plan();
        let foreign = plan.commands()[0].clone();
        let mut runner = FakeFirewallRunner {
            live: vec![foreign.clone()],
            ..FakeFirewallRunner::default()
        };
        let mut acquired = Vec::new();
        let error = super::apply_and_capture_network_plan_with(
            NetworkBackend::Iptables,
            &plan,
            &mut acquired,
            &mut runner,
        )
        .unwrap_err();

        assert!(error.to_string().contains("foreign chain"));
        assert!(acquired.is_empty());
        assert_eq!(runner.live, vec![foreign]);
        assert!(runner
            .calls
            .iter()
            .all(|command| command[3] != "-X" && command[3] != "-D"));
    }

    #[test]
    fn network_backend_firewall_failure_rolls_back_only_acquired_objects_in_reverse() {
        let plan = fixture_firewall_plan();
        let mut runner = FakeFirewallRunner {
            fail_setup_at: Some(3),
            ..FakeFirewallRunner::default()
        };
        let mut acquired = Vec::new();
        assert!(super::apply_and_capture_network_plan_with(
            NetworkBackend::Iptables,
            &plan,
            &mut acquired,
            &mut runner,
        )
        .is_err());
        assert_eq!(acquired.len(), 3);

        let expected = acquired.iter().rev().cloned().collect::<Vec<_>>();
        let mut observed = Vec::new();
        while let Some(command) = acquired.pop() {
            observed.push(command.clone());
            super::FirewallCommandRunner::run(&mut runner, &command).unwrap();
        }
        assert_eq!(observed, expected);
        assert!(runner.live.is_empty());
    }

    #[test]
    fn network_backend_firewall_cleanup_retry_resumes_after_each_owned_deletion() {
        let plan = fixture_firewall_plan();
        let mut runner = FakeFirewallRunner::default();
        let mut acquired = Vec::new();
        let expected = super::apply_and_capture_network_plan_with(
            NetworkBackend::Iptables,
            &plan,
            &mut acquired,
            &mut runner,
        )
        .unwrap();
        let initial = runner.live.len();
        runner.calls.clear();
        runner.fail_cleanup_at = Some(2);

        assert!(super::cleanup_firewall_plan_with(
            NetworkBackend::Iptables,
            &plan,
            &expected,
            &mut runner,
        )
        .is_err());
        assert_eq!(runner.live.len(), initial - 2);

        runner.fail_cleanup_at = None;
        runner.cleanup_attempts = 0;
        super::cleanup_firewall_plan_with(NetworkBackend::Iptables, &plan, &expected, &mut runner)
            .unwrap();
        assert!(runner.live.is_empty());
    }

    #[test]
    fn network_backend_firewall_replacement_produces_zero_cleanup_mutations() {
        let plan = fixture_firewall_plan();
        let mut runner = FakeFirewallRunner::default();
        let mut acquired = Vec::new();
        let expected = super::apply_and_capture_network_plan_with(
            NetworkBackend::Iptables,
            &plan,
            &mut acquired,
            &mut runner,
        )
        .unwrap();
        runner.live[0].push("foreign-replacement".to_string());
        runner.calls.clear();

        assert!(super::cleanup_firewall_plan_with(
            NetworkBackend::Iptables,
            &plan,
            &expected,
            &mut runner,
        )
        .is_err());
        assert!(runner.calls.is_empty());
    }

    #[test]
    fn network_backend_restart_config_requires_complete_compatible_metadata() {
        let ownership = fixture_ebpf_ownership();
        let config = super::ebpf_config_from_ownership(&ownership).unwrap();
        assert_eq!(config.network_id, "bridge-fixture");
        assert_eq!(config.external_ifindex, 17);
        assert_eq!(
            config.snat_port_start..=config.snat_port_end,
            50_000..=50_031
        );

        let mut malformed = ownership.clone();
        malformed.next_hop_mac = None;
        assert!(super::ebpf_config_from_ownership(&malformed).is_err());

        let mut foreign = ownership;
        foreign.object_sha256 = Some("00".repeat(32));
        assert!(super::ebpf_config_from_ownership(&foreign).is_err());
    }

    #[test]
    fn network_backend_pin_cleanup_preflight_accepts_missing_and_rejects_replacement() {
        use std::os::unix::fs::MetadataExt as _;

        let temp = tempfile::tempdir().unwrap();
        let map = temp.path().join("owned-map");
        std::fs::write(&map, b"owned").unwrap();
        let root_metadata = std::fs::symlink_metadata(temp.path()).unwrap();
        let map_metadata = std::fs::symlink_metadata(&map).unwrap();
        let mut ownership = fixture_ebpf_ownership();
        ownership.ebpf_pin_path = Some(temp.path().display().to_string());
        ownership.ebpf_pins = vec![
            crate::container_store::EbpfPinOwnershipRecord {
                relative_path: String::new(),
                device: root_metadata.dev(),
                inode: root_metadata.ino(),
                directory: true,
                map_id: None,
            },
            crate::container_store::EbpfPinOwnershipRecord {
                relative_path: "owned-map".to_string(),
                device: map_metadata.dev(),
                inode: map_metadata.ino(),
                directory: false,
                map_id: None,
            },
        ];
        super::verify_owned_ebpf_pins_before_cleanup(&ownership).unwrap();
        let replacement_dir = tempfile::tempdir().unwrap();
        let replacement = replacement_dir.path().join("replacement");
        std::fs::write(&replacement, b"replacement").unwrap();
        std::fs::remove_file(&map).unwrap();
        super::verify_owned_ebpf_pins_before_cleanup(&ownership).unwrap();
        std::fs::rename(replacement, &map).unwrap();
        assert!(super::verify_owned_ebpf_pins_before_cleanup(&ownership).is_err());
    }

    #[test]
    fn network_backend_filter_identity_includes_interface_and_program() {
        let owned = crate::container_store::EbpfFilterOwnershipRecord {
            interface: Some("lo".to_string()),
            interface_ifindex: Some(1),
            direction: "ingress".to_string(),
            priority: 49_152,
            handle: "0x1".to_string(),
            program_id: Some(71),
            program_tag: Some("aabbccdd".to_string()),
        };
        let mut replacement = owned.clone();
        replacement.program_id = Some(72);
        assert_ne!(owned, replacement);
        replacement = owned.clone();
        replacement.interface_ifindex = Some(2);
        assert_ne!(owned, replacement);
    }

    #[test]
    fn network_backend_firewall_snapshot_normalizes_only_volatile_state() {
        let first = r#":fc_owned - [1:2]
-A fc_owned -j ACCEPT
counter packets 4 bytes 88 comment \"ferrocrate:fc_owned\" # handle 7"#;
        let counters_changed = r#":fc_owned - [9:10]
-A fc_owned -j ACCEPT
counter packets 99 bytes 1234 comment \"ferrocrate:fc_owned\" # handle 55"#;
        let content_changed = r#":fc_owned - [9:10]
-A fc_owned -j DROP
counter packets 99 bytes 1234 comment \"ferrocrate:fc_owned\" # handle 55"#;
        assert_eq!(
            super::normalize_owned_firewall_state(first),
            super::normalize_owned_firewall_state(counters_changed)
        );
        assert_ne!(
            super::normalize_owned_firewall_state(first),
            super::normalize_owned_firewall_state(content_changed)
        );
    }

    #[test]
    fn network_backend_shared_ebpf_identity_is_bridge_scoped() {
        let first = super::bridge_network_id("ferro0", "10.0.0.1/24");
        let second = super::bridge_network_id("ferro0", "10.0.0.1/24");
        let different = super::bridge_network_id("ferro1", "10.1.0.1/24");

        assert_eq!(first, second);
        assert_ne!(first, different);
        assert!(!first.contains("container-a"));
    }

    #[test]
    fn network_backend_reuses_one_ebpf_load_per_network() {
        assert_eq!(
            super::shared_ebpf_action("bridge-a", std::iter::empty::<&str>()),
            super::SharedEbpfAction::PrepareAndAttach
        );
        assert_eq!(
            super::shared_ebpf_action("bridge-a", ["bridge-a", "bridge-a"]),
            super::SharedEbpfAction::VerifyAndReuse
        );
    }

    #[test]
    fn network_backend_transaction_rolls_back_every_partial_boundary() {
        use super::NetworkMutationKind::{BackendRecords, Bridge, Namespace, Shaping, Veth};
        let mutations = [Bridge, Namespace, Veth, BackendRecords, Shaping];

        for completed in 1..=mutations.len() {
            let mut journal = super::NetworkMutationJournal::default();
            for mutation in mutations.iter().take(completed) {
                journal.record(*mutation);
            }
            let expected = mutations[..completed]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(journal.rollback_order(), expected);
        }
    }

    #[test]
    fn network_backend_recovery_reloads_only_completely_missing_owned_state() {
        use super::{NetworkRecoveryAction, ObservedNetworkState};
        assert_eq!(
            super::plan_network_recovery(ObservedNetworkState::Complete).unwrap(),
            NetworkRecoveryAction::VerifyAndReuse
        );
        assert_eq!(
            super::plan_network_recovery(ObservedNetworkState::CompletelyMissing).unwrap(),
            NetworkRecoveryAction::ReloadShared
        );
        assert!(super::plan_network_recovery(ObservedNetworkState::PartialOrReplaced).is_err());
    }

    #[test]
    fn network_backend_identity_cleanup_distinguishes_missing_and_foreign() {
        let expected = super::KernelIdentity {
            device: 7,
            inode: 11,
        };
        assert_eq!(
            super::verify_kernel_identity(expected, None).unwrap(),
            super::OwnedResourceState::Missing
        );
        assert!(super::verify_kernel_identity(
            expected,
            Some(super::KernelIdentity {
                device: 7,
                inode: 12,
            })
        )
        .is_err());
    }

    #[test]
    fn network_backend_legacy_bridge_records_never_silently_clean() {
        assert_eq!(
            super::classify_legacy_network_record(Some("host"), false).unwrap(),
            super::LegacyNetworkAction::NotManagedBridge
        );
        assert_eq!(
            super::classify_legacy_network_record(Some("bridge"), true).unwrap(),
            super::LegacyNetworkAction::CleanupProvenRules
        );
        assert!(super::classify_legacy_network_record(Some("bridge"), false).is_err());
    }

    #[test]
    fn ebpf_backend_unavailable_fails_without_fallback() {
        struct UnavailableProbe;

        impl ferro_net::BackendProbe for UnavailableProbe {
            fn command_exists(&self, _: &str) -> bool {
                false
            }

            fn bpffs_mounted(&self) -> bool {
                false
            }

            fn artifact_available(&self) -> bool {
                false
            }
        }

        let err =
            super::resolve_network_backend(ferro_net::NetworkBackend::Ebpf, &UnavailableProbe)
                .expect_err("eBPF must not fall back");
        assert!(err.to_string().contains("eBPF backend unavailable"));
    }

    #[test]
    fn non_root_bridge_backend_fails_closed() {
        let err = super::ensure_bridge_backend_root(false, NetworkBackend::Ebpf)
            .expect_err("rootless bridge backend setup must fail");
        assert!(err
            .to_string()
            .contains("rootless bridge backend setup requires root"));
    }

    #[test]
    fn ebpf_artifact_requires_regular_nonempty_elf_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing.o");
        assert!(!super::ebpf_artifact_available(&missing));

        let directory = temp.path().join("directory.o");
        std::fs::create_dir(&directory).expect("directory");
        assert!(!super::ebpf_artifact_available(&directory));

        let empty = temp.path().join("empty.o");
        std::fs::write(&empty, []).expect("empty artifact");
        assert!(!super::ebpf_artifact_available(&empty));

        let invalid = temp.path().join("invalid.o");
        std::fs::write(&invalid, b"not an ELF file").expect("invalid artifact");
        assert!(!super::ebpf_artifact_available(&invalid));

        let elf = temp.path().join("valid.o");
        std::fs::write(&elf, b"\x7fELF").expect("ELF artifact");
        assert!(super::ebpf_artifact_available(&elf));
    }

    #[test]
    fn wireguard_config_defaults() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_WG_IFACE");
            std::env::remove_var("FERROCRATE_WG_IPV4_CIDR");
            std::env::remove_var("FERROCRATE_WG_IPV6_CIDR");
        }
        let cfg = super::wireguard_config().expect("wireguard config");
        assert_eq!(cfg.iface, "wg0");
        assert_eq!(cfg.ipv4_gateway, "10.44.0.1");
        assert_eq!(cfg.ipv4_prefix, 24);
        assert!(cfg.ipv6_gateway.is_none());
        assert!(cfg.ipv6_prefix.is_none());
    }

    #[test]
    fn wireguard_config_respects_env() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_WG_IFACE", "wg-app");
            std::env::set_var("FERROCRATE_WG_IPV4_CIDR", "10.55.0.1/16");
            std::env::set_var("FERROCRATE_WG_IPV6_CIDR", "fd00:55::1/64");
        }
        let cfg = super::wireguard_config().expect("wireguard config");
        assert_eq!(cfg.iface, "wg-app");
        assert_eq!(cfg.ipv4_gateway, "10.55.0.1");
        assert_eq!(cfg.ipv4_prefix, 16);
        assert_eq!(
            cfg.ipv6_gateway.map(|ip| ip.to_string()),
            Some("fd00:55::1".to_string())
        );
        assert_eq!(cfg.ipv6_prefix, Some(64));
        unsafe {
            std::env::remove_var("FERROCRATE_WG_IFACE");
            std::env::remove_var("FERROCRATE_WG_IPV4_CIDR");
            std::env::remove_var("FERROCRATE_WG_IPV6_CIDR");
        }
    }

    #[test]
    fn port_mapping_conflicts_are_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = crate::container_store::LocalContainerStore::open(temp.path()).expect("store");
        let existing = ContainerRecord {
            id: "c-existing".to_string(),
            name: None,
            pid: 1234,
            image: "alpine:latest".to_string(),
            command: vec!["sleep".to_string(), "1".to_string()],
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
            netns: Some("ferro-existing".to_string()),
            network_name: Some("bridge".to_string()),
            ip_address: Some("10.0.0.2".to_string()),
            ipv6_address: None,
            ports: vec![PortMappingRecord {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            }],
            network_backend: None,
            network_ownership: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
            managed_overlay: None,
            managed_host_veth: None,
        };
        store.put(&existing).expect("put existing");

        let requested = vec![PortMappingRecord {
            host_port: 8080,
            container_port: 8080,
            protocol: "tcp".to_string(),
        }];
        let err = super::validate_port_mapping_conflicts(&store, &requested).expect_err("conflict");
        assert!(err.to_string().contains("already mapped"));
    }

    #[test]
    fn allocated_ipv6_stays_within_prefix() {
        let gateway = "fd00:10::1".parse::<std::net::Ipv6Addr>().expect("ipv6");
        let assigned = super::allocate_container_ipv6("abc123", &gateway, 64)
            .parse::<std::net::Ipv6Addr>()
            .expect("assigned ipv6");
        let gateway_u = u128::from(gateway);
        let assigned_u = u128::from(assigned);
        let host_mask = (1u128 << (128 - 64)) - 1;
        let network_mask = !host_mask;
        assert_eq!(gateway_u & network_mask, assigned_u & network_mask);
        assert_ne!(assigned, gateway);
    }

    #[test]
    fn allocated_ipv6_is_deterministic_for_container_id() {
        let gateway = "fd00:20::1".parse::<std::net::Ipv6Addr>().expect("ipv6");
        let first = super::allocate_container_ipv6("cid-1", &gateway, 64);
        let second = super::allocate_container_ipv6("cid-1", &gateway, 64);
        let third = super::allocate_container_ipv6("cid-2", &gateway, 64);
        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn bandwidth_limit_validation_accepts_supported_units() {
        assert_eq!(
            super::validate_bandwidth_limit("100mbit").expect("valid"),
            "100mbit"
        );
        assert_eq!(
            super::validate_bandwidth_limit("42KBIT").expect("valid"),
            "42kbit"
        );
    }

    #[test]
    fn bandwidth_limit_validation_rejects_invalid_values() {
        let err = super::validate_bandwidth_limit("0mbit").expect_err("invalid");
        assert!(err.to_string().contains("positive integer"));
        let err = super::validate_bandwidth_limit("100").expect_err("missing unit");
        assert!(err.to_string().contains("must end with"));
    }

    #[test]
    fn seccomp_profile_is_enabled_by_default() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP");
        }
        let profile = super::load_seccomp_profile().expect("seccomp profile");
        assert!(profile.is_some());
    }

    #[test]
    fn seccomp_profile_can_be_disabled_explicitly() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_SECCOMP", "0");
            std::env::remove_var("FERROCRATE_SECCOMP_PROFILE");
        }
        let profile = super::load_seccomp_profile().expect("seccomp profile");
        assert!(profile.is_none());
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP");
        }
    }

    #[test]
    fn seccomp_profile_can_load_custom_file() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let profile_path = temp.path().join("seccomp.json");
        std::fs::write(
            &profile_path,
            crate::seccomp::default_seccomp_profile_json(),
        )
        .expect("write profile");
        unsafe {
            std::env::set_var("FERROCRATE_SECCOMP_PROFILE", profile_path.as_os_str());
            std::env::remove_var("FERROCRATE_SECCOMP");
        }
        let profile = super::load_seccomp_profile().expect("seccomp profile");
        assert!(profile.is_some());
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP_PROFILE");
        }
    }

    #[test]
    fn seccomp_profile_rejects_oversized_custom_file() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let temp = tempfile::tempdir().expect("tempdir");
        let profile_path = temp.path().join("seccomp.json");
        let oversized = vec![b'a'; (1024 * 1024) + 1];
        std::fs::write(&profile_path, oversized).expect("write profile");
        unsafe {
            std::env::set_var("FERROCRATE_SECCOMP_PROFILE", profile_path.as_os_str());
            std::env::remove_var("FERROCRATE_SECCOMP");
        }
        let err = super::load_seccomp_profile().expect_err("oversized should fail");
        assert!(err.to_string().contains("exceeds"));
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP_PROFILE");
        }
    }

    #[test]
    fn seccomp_strict_mode_defaults_to_true() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP_PERMISSIVE");
        }
        assert!(super::seccomp_strict_mode());
    }

    #[test]
    fn seccomp_permissive_mode_relaxes_strict_default() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_SECCOMP_PERMISSIVE", "1");
        }
        assert!(!super::seccomp_strict_mode());
        unsafe {
            std::env::remove_var("FERROCRATE_SECCOMP_PERMISSIVE");
        }
    }

    #[test]
    fn security_ebpf_events_default_and_env_override() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_EBPF_SECURITY_EVENTS");
        }
        assert_eq!(
            super::security_ebpf_events(),
            vec!["execve", "connect", "open", "ptrace", "mount", "unshare"]
        );
        unsafe {
            std::env::set_var("FERROCRATE_EBPF_SECURITY_EVENTS", "execve,connect, open");
        }
        assert_eq!(
            super::security_ebpf_events(),
            vec!["execve", "connect", "open"]
        );
        unsafe {
            std::env::remove_var("FERROCRATE_EBPF_SECURITY_EVENTS");
        }
    }

    #[test]
    fn wireguard_peer_config_requires_endpoint_when_key_present() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::set_var("FERROCRATE_WG_PEER_PUBLIC_KEY", "peer-key");
            std::env::remove_var("FERROCRATE_WG_PEER_ENDPOINT");
        }
        let err = super::wireguard_peer_config().expect_err("missing endpoint");
        assert!(err.to_string().contains("PEER_ENDPOINT"));
        unsafe {
            std::env::remove_var("FERROCRATE_WG_PEER_PUBLIC_KEY");
        }
    }

    #[test]
    fn wireguard_listen_port_is_deterministic() {
        let first = super::wireguard_listen_port("container-a");
        let second = super::wireguard_listen_port("container-a");
        let third = super::wireguard_listen_port("container-b");
        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    #[test]
    fn mac_permissive_mode_respects_env() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe {
            std::env::remove_var("FERROCRATE_MAC_PERMISSIVE");
        }
        assert!(!super::mac_permissive_mode());
        unsafe {
            std::env::set_var("FERROCRATE_MAC_PERMISSIVE", "1");
        }
        assert!(super::mac_permissive_mode());
        unsafe {
            std::env::remove_var("FERROCRATE_MAC_PERMISSIVE");
        }
    }

    #[test]
    fn selinux_type_validation_rejects_invalid_chars() {
        let err = super::validate_selinux_type("container_t;bad").expect_err("invalid type");
        assert!(err.to_string().contains("invalid characters"));
        super::validate_selinux_type("container_t").expect("valid type");
    }

    fn seed_image_store(runtime_dir: &std::path::Path, image: &str) {
        let store = LocalImageStore::open(runtime_dir.join("images")).expect("store");
        let canonical = canonicalize_reference(image).expect("canonical");
        let manifest_json = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1},"layers":[]}"#;
        store
            .put_reference(
                &canonical,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                manifest_json,
            )
            .expect("seed manifest");
    }

    fn write_image_config(runtime_dir: &std::path::Path, json: &str) {
        let config_root = runtime_dir.join("images").join("configs");
        std::fs::create_dir_all(&config_root).expect("configs dir");
        let config_path = config_root
            .join("sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        std::fs::write(config_path, json).expect("write config");
    }
}
