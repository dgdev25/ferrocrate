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
use crate::cgroups::{CgroupStats, CgroupV2Manager, CpuMax, ResourceLimits};
use crate::container_exec::{
    exec_in_container, exec_in_container_with_timeout, exec_in_rootless_rootfs,
};
use crate::container_store::{
    now_unix, ContainerMountRecord, ContainerRecord, ContainerStoreError,
    ContainerTmpfsMountRecord, CreationProvenance, EbpfFilterOwnershipRecord,
    EbpfPinOwnershipRecord, HealthConfig, KernelObjectIdentityRecord, LifecycleOperation,
    LifecyclePhase, MutationReservation, NetworkOwnershipRecord, PortMappingRecord,
    ResourceLimitRecord, RestartPolicy,
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
use crate::managed_overlay::{
    LegacyManagedOverlayMode, ManagedOverlayClient, ManagedOverlayRequest, ManagedOverlayResponse,
};
use crate::mounts::{
    apply_authorized_bind_mounts, apply_readonly_rootfs, apply_tmpfs_mounts,
    normalize_mount_target, open_existing_mount_target_beneath, open_mount_source_beneath,
    open_mount_target_beneath, BindMount, MountError, TmpfsMount,
};
use crate::observability::{log_audit_event, log_event, make_audit_event, make_event};
use crate::process_lifecycle::{kill_pid, probe_pid, signal_pid, stop_pid, ProcessLifecycleError};
use crate::registry::parse_image_reference;
#[cfg(target_os = "linux")]
use crate::rootfs::{apply_layer_tar, construct_rootfs_with_dedup};
#[cfg(target_os = "linux")]
use crate::rootfs_diff;
#[cfg(target_os = "linux")]
use crate::rootless::nested_bubblewrap_diagnostic;
#[cfg(target_os = "linux")]
use crate::seccomp::{
    apply_seccomp_profile, default_seccomp_profile, parse_seccomp_profile, SeccompProfile,
};
use crate::sqlite_container_store::SqliteContainerStore;
use dashmap::DashMap;
use ferro_net::bridge;
use ferro_net::ebpf::{
    cleanup_security_monitor, embedded_object_abi, embedded_object_sha256,
    install_security_monitor, EbpfNetwork, EbpfNetworkConfig, PinnedNetworkIdentity,
    PinnedObjectIdentity, PreparedEbpfNetwork, SecurityMonitorConfig, VerifiedPinnedNetwork,
    FERRO_NETWORK_ROOT,
};
use ferro_net::ebpf_abi::{EndpointKey, EndpointValue, PortKey, PortValue};
use ferro_net::netns;
use ferro_net::portmap::{build_network_plan as build_portmap_plan, NetworkPlan};
use ferro_net::rootless::{build_hostfwd_request, build_slirp4netns_cmd, RootlessNetConfig};
use ferro_net::subnet::network_cidr_v4;
use ferro_net::veth;
use ferro_net::BackendProbe;
pub use ferro_net::NetworkBackend;
use ferro_net::{
    exec_cmd as net_exec_cmd, exec_cmd_allow_missing as net_exec_cmd_allow_missing,
    exec_cmd_capture as net_exec_cmd_capture,
};
use ferro_net::{HostCapabilities, WireGuardInterfaceConfig, WireGuardManager, WireGuardPeer};
#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
#[allow(deprecated)]
use nix::fcntl::{flock, FlockArg};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
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

#[cfg(unix)]
struct LifecycleLock {
    _file: fs::File,
}

#[cfg(unix)]
fn lifecycle_lock_path(runtime_dir: &Path, container_id: &str) -> PathBuf {
    let digest = Sha256::digest(container_id.as_bytes());
    runtime_dir
        .join("lifecycle-locks")
        .join(format!("{digest:x}.lock"))
}

#[cfg(unix)]
#[allow(deprecated)]
impl LifecycleLock {
    fn acquire(path: &Path) -> Result<Self, RuntimeError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        flock(file.as_raw_fd(), FlockArg::LockExclusive)
            .map_err(|error| RuntimeError::Io(io::Error::from_raw_os_error(error as i32)))?;
        Ok(Self { _file: file })
    }

    fn try_acquire(path: &Path) -> Result<Option<Self>, RuntimeError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;
        match flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock) {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(Errno::EWOULDBLOCK) => Ok(None),
            Err(error) => Err(RuntimeError::Io(io::Error::from_raw_os_error(error as i32))),
        }
    }
}

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
    namespace_owned: bool,
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
    route_localnet: Option<InterfaceValueOwnership>,
    pending_firewall_cleanup: Vec<Vec<String>>,
    journal: NetworkMutationJournal,
    cgroup_name: Option<String>,
    cgroup_root: PathBuf,
    slirp_process: Option<(u32, u64)>,
    committed: bool,
    operation_id: Option<[u8; 16]>,
    planned_resources: BTreeMap<String, String>,
    applied_resources: BTreeMap<String, Option<KernelObjectIdentityRecord>>,
    resource_plans: Vec<ResourcePlan>,
    typed_applied_resources: Vec<AppliedResource>,
    defer_container_removal: bool,
    cleanup_quarantined: bool,
    creation_provenance: CreationProvenance,
    kernel_ops: Arc<dyn KernelResourceOps>,
}

struct CleanupAuthority {
    operation_id: [u8; 16],
    generation: u64,
}

struct LegacyCleanupAuthority;

trait KernelResourceOps: Send + Sync {
    fn apply_bind(&self, rootfs: &Path, mount: &BindMount) -> Result<(), RuntimeError>;
    fn apply_tmpfs(&self, rootfs: &Path, mount: &TmpfsMount) -> Result<(), RuntimeError>;
    fn apply_readonly(&self, rootfs: &Path) -> Result<(), RuntimeError>;
    fn identity(&self, path: &Path) -> Result<ResourceIdentity, RuntimeError>;
    fn detach_owned(
        &self,
        rootfs: &Path,
        target: &Path,
        expected: &ResourceIdentity,
    ) -> Result<(), RuntimeError>;
    fn observe_unmarked(
        &self,
        rootfs: &Path,
        target: &Path,
        baseline: (u64, u64, Option<u64>),
        source: Option<(u64, u64, Option<u64>)>,
        fs_type: Option<&str>,
    ) -> Result<Option<ResourceIdentity>, ()>;
    #[allow(clippy::too_many_arguments)]
    fn setup_network(
        &self,
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
        container_id: &str,
        ports: &[PortMappingRecord],
        mode: &str,
        backend: NetworkBackend,
        rollback: &mut CreationRollback,
        existing: &[ContainerRecord],
        phase_hook: &dyn LifecyclePhaseHook,
    ) -> Result<NetworkSetup, RuntimeError>;
    fn cleanup_test_network(
        &self,
        _rollback: &mut CreationRollback,
    ) -> Option<Result<(), RuntimeError>> {
        None
    }
}

struct ProductionKernelResourceOps;

impl KernelResourceOps for ProductionKernelResourceOps {
    fn apply_bind(&self, rootfs: &Path, mount: &BindMount) -> Result<(), RuntimeError> {
        apply_authorized_bind_mounts(rootfs, std::slice::from_ref(mount)).map_err(Into::into)
    }
    fn apply_tmpfs(&self, rootfs: &Path, mount: &TmpfsMount) -> Result<(), RuntimeError> {
        apply_tmpfs_mounts(rootfs, std::slice::from_ref(mount)).map_err(Into::into)
    }
    fn apply_readonly(&self, rootfs: &Path) -> Result<(), RuntimeError> {
        apply_readonly_rootfs(rootfs).map_err(Into::into)
    }
    fn identity(&self, path: &Path) -> Result<ResourceIdentity, RuntimeError> {
        path_resource_identity(path)
    }
    fn detach_owned(
        &self,
        rootfs: &Path,
        target: &Path,
        expected: &ResourceIdentity,
    ) -> Result<(), RuntimeError> {
        let absolute = if target == Path::new(".") {
            rootfs.to_path_buf()
        } else {
            rootfs.join(target)
        };
        if &path_resource_identity(&absolute)? != expected {
            return Err(RuntimeError::InvalidState(
                "owned mount identity changed".into(),
            ));
        }
        let handle = if target == Path::new(".") {
            OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_PATH | nix::libc::O_CLOEXEC)
                .open(rootfs)
                .map_err(MountError::from)?
        } else {
            open_existing_mount_target_beneath(rootfs, target)?
        };
        nix::mount::umount2(
            Path::new(&format!("/proc/self/fd/{}", handle.as_raw_fd())),
            nix::mount::MntFlags::MNT_DETACH,
        )
        .map_err(|error| RuntimeError::Network(error.to_string()))
    }
    fn observe_unmarked(
        &self,
        rootfs: &Path,
        target: &Path,
        baseline: (u64, u64, Option<u64>),
        source: Option<(u64, u64, Option<u64>)>,
        fs_type: Option<&str>,
    ) -> Result<Option<ResourceIdentity>, ()> {
        classify_unmarked_mount(Some(rootfs), target, baseline, source, fs_type)
    }
    fn setup_network(
        &self,
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
        container_id: &str,
        ports: &[PortMappingRecord],
        mode: &str,
        backend: NetworkBackend,
        rollback: &mut CreationRollback,
        existing: &[ContainerRecord],
        _phase_hook: &dyn LifecyclePhaseHook,
    ) -> Result<NetworkSetup, RuntimeError> {
        setup_network(
            proof,
            intent,
            container_id,
            ports,
            mode,
            backend,
            rollback,
            existing,
        )
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
enum ResourcePlan {
    Rootfs {
        path: PathBuf,
        generation: u64,
        #[serde(default)]
        operation_id: Option<[u8; 16]>,
    },
    BindMount {
        target: PathBuf,
        generation: u64,
        source_device: u64,
        source_inode: u64,
        baseline_device: u64,
        baseline_inode: u64,
        baseline_mount_id: Option<u64>,
        #[serde(default)]
        operation_id: Option<[u8; 16]>,
    },
    TmpfsMount {
        target: PathBuf,
        generation: u64,
        baseline_device: u64,
        baseline_inode: u64,
        baseline_mount_id: Option<u64>,
        #[serde(default)]
        operation_id: Option<[u8; 16]>,
    },
    RootfsReadonly {
        target: PathBuf,
        generation: u64,
        baseline_device: u64,
        baseline_inode: u64,
        baseline_mount_id: Option<u64>,
        #[serde(default)]
        operation_id: Option<[u8; 16]>,
    },
    NetworkAllocation {
        canonical: String,
        generation: u64,
        #[serde(default)]
        operation_id: Option<[u8; 16]>,
    },
    Cgroup {
        name: String,
        generation: u64,
        #[serde(default)]
        operation_id: Option<[u8; 16]>,
        #[serde(default)]
        expected_controllers: Vec<String>,
    },
    Process {
        generation: u64,
        #[serde(default)]
        operation_id: Option<[u8; 16]>,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
enum ResourceIdentity {
    Path {
        device: u64,
        inode: u64,
        mount_id: Option<u64>,
    },
    Network {
        identity: Option<KernelObjectIdentityRecord>,
    },
    Cgroup {
        device: u64,
        inode: u64,
    },
    Process {
        pid: u32,
        start_time: u64,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct AppliedResource {
    plan_index: usize,
    identity: ResourceIdentity,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct GlobalValueOwnership {
    previous: String,
    expected: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct InterfaceValueOwnership {
    interface: String,
    previous: String,
    expected: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PendingNetworkCleanup {
    schema_version: u32,
    container_id: String,
    netns_name: Option<String>,
    #[serde(default = "default_namespace_owned")]
    namespace_owned: bool,
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
    #[serde(default)]
    route_localnet: Option<InterfaceValueOwnership>,
    pending_firewall_cleanup: Vec<Vec<String>>,
    #[serde(default)]
    operation_id: Option<[u8; 16]>,
    #[serde(default)]
    cgroup_name: Option<String>,
    #[serde(default)]
    cgroup_generation: Option<u64>,
    #[serde(default)]
    planned_resources: BTreeMap<String, String>,
    #[serde(default)]
    applied_resources: BTreeMap<String, Option<KernelObjectIdentityRecord>>,
    #[serde(default)]
    resource_plans: Vec<ResourcePlan>,
    #[serde(default)]
    typed_applied_resources: Vec<AppliedResource>,
    #[serde(default)]
    creation_provenance: CreationProvenance,
}

fn default_namespace_owned() -> bool {
    true
}

impl CreationRollback {
    fn new(
        container_id: &str,
        cgroup_root: PathBuf,
        creation_provenance: CreationProvenance,
        kernel_ops: Arc<dyn KernelResourceOps>,
    ) -> Self {
        Self {
            container_id: container_id.to_string(),
            container_dir: None,
            netns_name: None,
            namespace_owned: false,
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
            route_localnet: None,
            pending_firewall_cleanup: Vec::new(),
            journal: NetworkMutationJournal::default(),
            cgroup_name: None,
            cgroup_root,
            slirp_process: None,
            committed: false,
            operation_id: creation_provenance.creator_operation_id,
            planned_resources: Default::default(),
            applied_resources: Default::default(),
            resource_plans: Vec::new(),
            typed_applied_resources: Vec::new(),
            defer_container_removal: false,
            cleanup_quarantined: false,
            creation_provenance,
            kernel_ops,
        }
    }

    fn from_pending(
        container_dir: PathBuf,
        cgroup_root: PathBuf,
        pending: PendingNetworkCleanup,
        kernel_ops: Arc<dyn KernelResourceOps>,
    ) -> Result<Self, RuntimeError> {
        if !matches!(pending.schema_version, 1 | 2) || pending.container_id.is_empty() {
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
            namespace_owned: pending.namespace_owned,
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
            route_localnet: pending.route_localnet,
            pending_firewall_cleanup: pending.pending_firewall_cleanup,
            journal: NetworkMutationJournal::default(),
            cgroup_name: pending.cgroup_name,
            cgroup_root,
            slirp_process: None,
            committed: false,
            operation_id: pending.operation_id,
            planned_resources: pending.planned_resources,
            applied_resources: pending.applied_resources,
            resource_plans: pending.resource_plans,
            typed_applied_resources: pending.typed_applied_resources,
            defer_container_removal: true,
            cleanup_quarantined: false,
            creation_provenance: pending.creation_provenance,
            kernel_ops,
        })
    }

    fn track_container_dir(&mut self, dir: PathBuf) {
        self.container_dir = Some(dir);
    }

    fn plan_resource(&mut self, kind: &str, canonical: String) -> Result<(), RuntimeError> {
        self.planned_resources.insert(kind.to_string(), canonical);
        self.persist_cleanup_journal()
    }

    fn plan_typed_resource(&mut self, plan: ResourcePlan) -> Result<usize, RuntimeError> {
        self.resource_plans.push(plan);
        self.persist_cleanup_journal()?;
        Ok(self.resource_plans.len() - 1)
    }

    fn mark_typed_resource(
        &mut self,
        plan_index: usize,
        identity: ResourceIdentity,
    ) -> Result<(), RuntimeError> {
        if plan_index >= self.resource_plans.len()
            || self
                .typed_applied_resources
                .iter()
                .any(|applied| applied.plan_index == plan_index)
        {
            return Err(RuntimeError::InvalidState(
                "invalid or duplicate applied resource identity".to_string(),
            ));
        }
        self.typed_applied_resources.push(AppliedResource {
            plan_index,
            identity,
        });
        self.persist_cleanup_journal()
    }

    fn mark_resource_applied(
        &mut self,
        kind: &str,
        identity: Option<KernelObjectIdentityRecord>,
    ) -> Result<(), RuntimeError> {
        if !self.planned_resources.contains_key(kind) {
            return Err(RuntimeError::InvalidState(format!(
                "resource {kind} applied without durable plan"
            )));
        }
        self.applied_resources.insert(kind.to_string(), identity);
        self.persist_cleanup_journal()
    }

    fn track_network(
        &mut self,
        setup: &mut NetworkSetup,
        ports: &[PortMappingRecord],
    ) -> Result<(), RuntimeError> {
        self.netns_name = setup.netns_name.clone();
        self.namespace_owned = setup.namespace_owned;
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

    fn track_cgroup(&mut self, name: String) -> Result<(), RuntimeError> {
        self.cgroup_name = Some(name);
        self.mark_resource_applied("cgroup", None)
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

    fn track_route_localnet(
        &mut self,
        ownership: InterfaceValueOwnership,
    ) -> Result<(), RuntimeError> {
        self.route_localnet = Some(ownership);
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
            schema_version: 2,
            container_id: self.container_id.clone(),
            netns_name: self.netns_name.clone(),
            namespace_owned: self.namespace_owned,
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
            route_localnet: self.route_localnet.clone(),
            pending_firewall_cleanup: self.pending_firewall_cleanup.clone(),
            operation_id: self.operation_id,
            cgroup_name: self.cgroup_name.clone(),
            cgroup_generation: self.operation_id.map(|_| 1),
            planned_resources: self.planned_resources.clone(),
            applied_resources: self.applied_resources.clone(),
            resource_plans: self.resource_plans.clone(),
            typed_applied_resources: self.typed_applied_resources.clone(),
            creation_provenance: self.creation_provenance.clone(),
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
        let parent = path
            .parent()
            .ok_or_else(|| RuntimeError::Network("cleanup journal has no parent".to_string()))?;
        if fs::symlink_metadata(parent)?.file_type().is_symlink() {
            return Err(RuntimeError::Network(
                "cleanup journal parent may not be a symlink".to_string(),
            ));
        }
        let parent = parent.to_path_buf();
        let temporary = parent.join(format!(
            ".network-cleanup-{:016x}.tmp",
            rand::random::<u64>()
        ));
        let bytes = serde_json::to_vec_pretty(&self.pending_cleanup())
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(&parent)?.sync_all()?;
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
            if let Some(parent) = self.container_dir.as_deref() {
                if let Err(error) = fs::File::open(parent).and_then(|dir| dir.sync_all()) {
                    log::warn!("[network] failed to sync cleanup journal removal: {error}");
                }
            }
        }
        self.committed = true;
    }

    /// Explicitly roll back all tracked resources.
    fn rollback(&mut self) {
        if let Some((pid, start_time)) = self.slirp_process.take() {
            if process_start_time_for_pid(pid) == Some(start_time) {
                if let Err(error) = kill_pid(pid) {
                    log::warn!("[rollback] failed to stop slirp4netns helper {pid}: {error}");
                }
            }
        }
        let typed_cleanup_failure = self.cleanup_typed_resources();
        let kernel_ops = Arc::clone(&self.kernel_ops);
        let test_network_cleanup = kernel_ops.cleanup_test_network(self);
        let test_network_failure = matches!(test_network_cleanup, Some(Err(_)));
        if test_network_cleanup.is_some() {
            self.netns_name = None;
            self.namespace_identity = None;
            self.host_veth = None;
            self.network_ownership = None;
            self.network_backend = None;
            self.pending_firewall_cleanup.clear();
        }
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
            (Some(_), _) if !self.namespace_owned => None,
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
        let mut retain_container_dir =
            identity_cleanup_failure || typed_cleanup_failure || test_network_failure;
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
            if self.container_dir.is_some() {
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

        if let Some(ownership) = self.route_localnet.take() {
            match restore_route_localnet(&ownership) {
                Ok(()) => {}
                Err(error) => {
                    retain_container_dir = true;
                    log::warn!("[rollback] failed to restore route_localnet: {error}");
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

        if retain_container_dir && self.container_dir.is_some() {
            let _ = self.persist_cleanup_journal();
        }

        // Rollback container directory
        self.cleanup_quarantined = retain_container_dir;
        if !retain_container_dir && !self.defer_container_removal {
            if let Some(ref dir) = self.container_dir {
                if has_live_mount_beneath(dir) {
                    log::warn!("[rollback] refusing remove_dir_all across a live mount");
                    let _ = self.persist_cleanup_journal();
                } else if let Err(e) = fs::remove_dir_all(dir) {
                    log::warn!("[rollback] failed to remove container dir: {}", e);
                }
            }
        }

        self.committed = true; // Prevent double rollback
    }

    fn rollback_with_authority(&mut self, authority: &CleanupAuthority) {
        if self.operation_id != Some(authority.operation_id)
            || self.creation_provenance.resource_generation != authority.generation
        {
            self.cleanup_quarantined = true;
            return;
        }
        self.rollback();
    }

    fn rollback_with_legacy_authority(&mut self, _authority: &LegacyCleanupAuthority) {
        // Legacy authority is deletion-only and can act solely on exact typed
        // applied identities. Name-only network/cgroup cleanup remains quarantined.
        if self.typed_applied_resources.is_empty() {
            self.cleanup_quarantined = true;
            return;
        }
        self.network_ownership = None;
        self.netns_name = None;
        self.cgroup_name = None;
        self.rollback();
    }

    /// Returns true when an identity mismatch requires quarantine.
    fn cleanup_typed_resources(&mut self) -> bool {
        let rootfs = self.resource_plans.iter().find_map(|plan| match plan {
            ResourcePlan::Rootfs { path, .. } => Some(path.clone()),
            _ => None,
        });
        let mut quarantine = false;
        let mut observed_resources = self.typed_applied_resources.clone();
        for (plan_index, plan) in self.resource_plans.iter().enumerate() {
            if observed_resources
                .iter()
                .any(|resource| resource.plan_index == plan_index)
            {
                continue;
            }
            let synthesized = match plan {
                ResourcePlan::BindMount {
                    target,
                    source_device,
                    source_inode,
                    baseline_device,
                    baseline_inode,
                    baseline_mount_id,
                    ..
                } => rootfs.as_deref().map_or(Err(()), |rootfs| {
                    self.kernel_ops.observe_unmarked(
                        rootfs,
                        target,
                        (*baseline_device, *baseline_inode, *baseline_mount_id),
                        Some((*source_device, *source_inode, None)),
                        None,
                    )
                }),
                ResourcePlan::TmpfsMount {
                    target,
                    baseline_device,
                    baseline_inode,
                    baseline_mount_id,
                    ..
                } => rootfs.as_deref().map_or(Err(()), |rootfs| {
                    self.kernel_ops.observe_unmarked(
                        rootfs,
                        target,
                        (*baseline_device, *baseline_inode, *baseline_mount_id),
                        None,
                        Some("tmpfs"),
                    )
                }),
                ResourcePlan::RootfsReadonly {
                    baseline_device,
                    baseline_inode,
                    baseline_mount_id,
                    ..
                } => rootfs.as_deref().map_or(Err(()), |rootfs| {
                    self.kernel_ops.observe_unmarked(
                        rootfs,
                        Path::new("."),
                        (*baseline_device, *baseline_inode, *baseline_mount_id),
                        None,
                        Some("readonly"),
                    )
                }),
                ResourcePlan::Cgroup { name, .. } => {
                    if self.cgroup_root.join(name).exists() {
                        Err(())
                    } else {
                        Ok(None)
                    }
                }
                ResourcePlan::NetworkAllocation { .. } => {
                    if self.netns_name.is_some() || self.network_ownership.is_some() {
                        Ok(Some(ResourceIdentity::Network {
                            identity: self.namespace_identity,
                        }))
                    } else {
                        Ok(None)
                    }
                }
                ResourcePlan::Rootfs { path, .. } => match fs::metadata(path) {
                    Ok(metadata) => Ok(Some(ResourceIdentity::Path {
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        mount_id: mount_id_for_path(path).ok().flatten(),
                    })),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                    Err(_) => Err(()),
                },
                ResourcePlan::Process { .. } => Ok(None),
            };
            match synthesized {
                Ok(Some(identity)) => observed_resources.push(AppliedResource {
                    plan_index,
                    identity,
                }),
                Ok(None) => {}
                Err(()) => quarantine = true,
            }
        }
        for applied in resource_cleanup_order(&observed_resources) {
            let Some(plan) = self.resource_plans.get(applied.plan_index) else {
                quarantine = true;
                continue;
            };
            match (plan, &applied.identity) {
                (
                    ResourcePlan::BindMount { target, .. }
                    | ResourcePlan::TmpfsMount { target, .. }
                    | ResourcePlan::RootfsReadonly { target, .. },
                    ResourceIdentity::Path {
                        device,
                        inode,
                        mount_id,
                    },
                ) => {
                    let Some(rootfs) = rootfs.as_deref() else {
                        quarantine = true;
                        continue;
                    };
                    let expected = ResourceIdentity::Path {
                        device: *device,
                        inode: *inode,
                        mount_id: *mount_id,
                    };
                    if let Err(error) = self.kernel_ops.detach_owned(
                        rootfs,
                        if matches!(plan, ResourcePlan::RootfsReadonly { .. }) {
                            Path::new(".")
                        } else {
                            target
                        },
                        &expected,
                    ) {
                        quarantine = true;
                        log::warn!("[rollback] owned mount detach failed: {error}");
                    }
                }
                (ResourcePlan::Cgroup { name, .. }, ResourceIdentity::Cgroup { device, inode }) => {
                    let path = self.cgroup_root.join(name);
                    match fs::metadata(&path) {
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Ok(metadata) if metadata.dev() == *device && metadata.ino() == *inode => {
                            if let Err(error) = fs::remove_dir(&path) {
                                quarantine = true;
                                log::warn!("[rollback] owned cgroup removal failed: {error}");
                            } else {
                                self.cgroup_name = None;
                            }
                        }
                        _ => quarantine = true,
                    }
                }
                (ResourcePlan::Process { .. }, ResourceIdentity::Process { pid, start_time }) => {
                    if process_start_time_for_pid(*pid) == Some(*start_time) {
                        if let Err(error) = kill_pid(*pid) {
                            quarantine = true;
                            log::warn!("[rollback] exact process kill failed: {error}");
                        }
                    }
                }
                (ResourcePlan::NetworkAllocation { .. }, ResourceIdentity::Network { .. })
                | (ResourcePlan::Rootfs { .. }, ResourceIdentity::Path { .. }) => {}
                _ => quarantine = true,
            }
        }
        quarantine
    }
}

fn resource_cleanup_order(resources: &[AppliedResource]) -> impl Iterator<Item = &AppliedResource> {
    resources.iter().rev()
}

fn has_live_mount_beneath(directory: &Path) -> bool {
    let Ok(directory) = fs::canonicalize(directory) else {
        return false;
    };
    fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .is_some_and(|mountinfo| {
            mountinfo.lines().any(|line| {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                fields
                    .get(4)
                    .is_some_and(|mountpoint| Path::new(mountpoint).starts_with(&directory))
            })
        })
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
    store: &SqliteContainerStore,
    cgroup_root: &Path,
    authorization: &RuntimeAuthorization,
    kernel_ops: Arc<dyn KernelResourceOps>,
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
        let bytes = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&journal_path)
        {
            Ok(mut file) => {
                if !file.metadata()?.is_file() {
                    return Err(RuntimeError::Network(format!(
                        "pending cleanup journal {} is not regular",
                        journal_path.display()
                    )));
                }
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                bytes
            }
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
        let witnessed_authority = validate_cleanup_authority(&pending, store, authorization)?;
        let legacy_authority = validate_legacy_cleanup_authority(&pending, authorization);
        if witnessed_authority.is_none() && legacy_authority.is_none() {
            warn!(
                "pending cleanup journal {} has stale, mixed, or unverifiable authority; retained in quarantine",
                journal_path.display()
            );
            if authorization.journal().is_some() {
                let recovery =
                    authorization.begin_internal_network_recovery(&pending.container_id)?;
                authorization.finish_internal_recovery(
                    recovery,
                    internal_cleanup_observation(&pending.container_id, false),
                    false,
                )?;
            }
            continue;
        }
        let recovery = authorization.begin_internal_network_recovery(&pending.container_id)?;
        let mut rollback = CreationRollback::from_pending(
            container_dir.clone(),
            cgroup_root.to_path_buf(),
            pending,
            Arc::clone(&kernel_ops),
        )?;
        if let Some(authority) = witnessed_authority.as_ref() {
            rollback.rollback_with_authority(authority);
        } else if let Some(authority) = legacy_authority.as_ref() {
            rollback.rollback_with_legacy_authority(authority);
        }
        if rollback.cleanup_quarantined {
            authorization.finish_internal_recovery(
                recovery,
                internal_cleanup_observation(&entry.file_name().to_string_lossy(), false),
                false,
            )?;
            warn!(
                "pending cleanup for {} remains quarantined at {}",
                entry.file_name().to_string_lossy(),
                journal_path.display()
            );
            continue;
        }
        authorization.finish_internal_recovery(
            recovery,
            internal_cleanup_observation(&entry.file_name().to_string_lossy(), true),
            true,
        )?;
        fs::remove_file(&journal_path)?;
        fs::File::open(&container_dir)?.sync_all()?;
        if !has_live_mount_beneath(&container_dir) {
            fs::remove_dir_all(&container_dir)?;
        }
    }
    Ok(())
}

fn validate_legacy_cleanup_authority(
    pending: &PendingNetworkCleanup,
    authorization: &RuntimeAuthorization,
) -> Option<LegacyCleanupAuthority> {
    (pending.schema_version == 1
        && authorization.authorization_mode() == crate::authorization::AuthorizationMode::Disabled
        && authorization
            .journal()
            .is_none_or(|journal| journal.mode() == crate::witness::JournalMode::Disabled)
        && authorization
            .legacy_provenance_matches(&pending.creation_provenance, &pending.container_id)
        && !pending.resource_plans.is_empty()
        && pending
            .typed_applied_resources
            .iter()
            .all(|applied| applied.plan_index < pending.resource_plans.len()))
    .then_some(LegacyCleanupAuthority)
}

fn validate_cleanup_authority(
    pending: &PendingNetworkCleanup,
    store: &SqliteContainerStore,
    authorization: &RuntimeAuthorization,
) -> Result<Option<CleanupAuthority>, RuntimeError> {
    let Some(operation_id) = pending.operation_id else {
        return Ok(None);
    };
    let generation = pending
        .cgroup_generation
        .unwrap_or(pending.creation_provenance.resource_generation);
    if generation == 0
        || pending.resource_plans.is_empty()
        || !pending.resource_plans.iter().all(|plan| {
            let (plan_generation, plan_operation) = resource_plan_authority(plan);
            plan_generation == generation && plan_operation == Some(operation_id)
        })
    {
        return Ok(None);
    }
    let mut applied_indices = BTreeSet::new();
    if !pending.typed_applied_resources.iter().all(|applied| {
        applied.plan_index < pending.resource_plans.len()
            && applied_indices.insert(applied.plan_index)
    }) {
        return Ok(None);
    }
    let owned = if let Some(record) = store.get(&pending.container_id)? {
        authorization.provenance_matches(&record)
            && (record.pending_mutation.as_ref().is_some_and(|reservation| {
                reservation.operation_id == operation_id && reservation.generation == generation
            }) || (record.creation_provenance.creator_operation_id == Some(operation_id)
                && record.creation_provenance.resource_generation == generation))
    } else {
        let operation = store.lifecycle_operation(operation_id)?;
        operation.as_ref().is_some_and(|operation| {
            operation.container_id == pending.container_id && operation.generation == generation
        }) && authorization
            .provenance_value_matches(&pending.creation_provenance, &pending.container_id)
            && pending.creation_provenance.creator_operation_id == Some(operation_id)
            && pending.creation_provenance.resource_generation == generation
    };
    Ok(owned.then_some(CleanupAuthority {
        operation_id,
        generation,
    }))
}

fn resource_plan_authority(plan: &ResourcePlan) -> (u64, Option<[u8; 16]>) {
    match plan {
        ResourcePlan::Rootfs {
            generation,
            operation_id,
            ..
        }
        | ResourcePlan::BindMount {
            generation,
            operation_id,
            ..
        }
        | ResourcePlan::TmpfsMount {
            generation,
            operation_id,
            ..
        }
        | ResourcePlan::RootfsReadonly {
            generation,
            operation_id,
            ..
        }
        | ResourcePlan::NetworkAllocation {
            generation,
            operation_id,
            ..
        }
        | ResourcePlan::Cgroup {
            generation,
            operation_id,
            ..
        }
        | ResourcePlan::Process {
            generation,
            operation_id,
        } => (*generation, *operation_id),
    }
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

/// Return the valid OCI immutable form for a stored image reference. A tag
/// and digest must not be concatenated (`name:tag@sha256:...`); OCI digest
/// references use the repository name followed directly by `@digest`.
fn immutable_image_reference(reference: &str, digest: &str) -> Result<String, RuntimeError> {
    let parsed = parse_image_reference(reference)?;
    Ok(format!(
        "{}/{}@{}",
        parsed.registry, parsed.repository, digest
    ))
}

/// Return the registry-manifest digest reference for signature verification.
///
/// The image store's `digest` field intentionally points at the OCI config
/// blob because it is used for local execution and CAS lookup.  Cosign,
/// however, signs the registry manifest digest.  Keep those identities
/// separate so a verified image is never accidentally checked under its
/// config digest.
fn immutable_image_manifest_reference(
    store: &LocalImageStore,
    image: &str,
) -> Result<String, RuntimeError> {
    let Some(record) = store.resolve_reference(image)? else {
        return Ok(image.to_owned());
    };
    let manifest_digest = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(record.manifest_json.as_bytes())
    );
    immutable_image_reference(&record.reference, &manifest_digest)
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
    #[error("kernel effect completed but lifecycle state persistence failed: {0}")]
    PostEffectPersistence(ContainerStoreError),
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
    store: SqliteContainerStore,
    runtime_dir: PathBuf,
    cgroup_root: PathBuf,
    health_cancel: DashMap<String, Arc<AtomicBool>>,
    /// Cancellation tokens for resource monitor threads (Task 5.1)
    resource_cancel: DashMap<String, Arc<AtomicBool>>,
    authorization: RuntimeAuthorization,
    phase_hook: Arc<dyn LifecyclePhaseHook>,
    kernel_ops: Arc<dyn KernelResourceOps>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePhasePoint {
    DecisionDurable,
    ReservationDurable,
    NetworkApplied,
    CgroupApplied,
    RestartOldStopped,
    BindKernelEffect,
    TmpfsKernelEffect,
    ReadonlyKernelEffect,
    NetworkKernelEffect,
    NetworkResourcesCreatedBeforeOwnership,
    CgroupKernelEffect,
    SpawnPrepared,
    LaunchIdentityDurable,
    KernelEffectApplied,
    EffectObserved,
    TerminalDurable,
    ReservationCleared,
}

pub trait LifecyclePhaseHook: Send + Sync {
    fn reached(&self, action: &str, phase: LifecyclePhasePoint) -> Result<(), RuntimeError>;
}

fn require_authorization_journal(
    gate: &AuthorizationGate,
    journal: Option<&crate::witness::WitnessJournal>,
) -> Result<(), RuntimeError> {
    match gate.mode() {
        crate::authorization::AuthorizationMode::Disabled if journal.is_none() => Ok(()),
        crate::authorization::AuthorizationMode::Disabled => Err(RuntimeError::Authorization(
            "disabled authorization cannot use the required witness journal".to_string(),
        )),
        crate::authorization::AuthorizationMode::Shadow
        | crate::authorization::AuthorizationMode::Enforce
            if journal
                .is_some_and(|journal| journal.mode() == crate::witness::JournalMode::Required) =>
        {
            Ok(())
        }
        _ => Err(RuntimeError::Authorization(
            "enabled authorization requires the shared required witness journal".to_string(),
        )),
    }
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

#[allow(clippy::too_many_arguments)]
fn run_execution_digest(
    pinned_image: &str,
    cmd: &[String],
    env: &[String],
    labels: &HashMap<String, String>,
    annotations: &HashMap<String, String>,
    health: Option<&HealthConfig>,
    restart_policy: &RestartPolicy,
    limits: Option<&ResourceLimits>,
    workdir: Option<&str>,
    user: Option<&str>,
    name: Option<&str>,
    port_mappings: &[PortMappingRecord],
    normalized: &NormalizedRunRequest,
) -> [u8; 32] {
    let labels: BTreeMap<_, _> = labels.iter().collect();
    let annotations: BTreeMap<_, _> = annotations.iter().collect();
    let mut env = env.to_vec();
    env.sort();
    let mounts: Vec<_> = normalized
        .facts
        .mounts
        .iter()
        .map(|mount| {
            serde_json::json!({
                "class": format!("{:?}", mount.class),
                "mount_id": mount.mount_id,
                "device_id": mount.device_id,
                "inode": mount.inode,
                "open_flags": mount.open_flags,
                "target_digest": mount.target_digest,
            })
        })
        .collect();
    let limits = limits.map(|limits| {
        serde_json::json!({
            "memory_max": limits.memory_max,
            "cpu_max": limits.cpu_max.as_ref().map(|cpu| (cpu.quota, cpu.period)),
            "pids_max": limits.pids_max,
        })
    });
    let value = serde_json::json!({
        "domain": "ferrocrate/compose-run-executor/v1",
        "image": pinned_image,
        "cmd": cmd,
        "env": env,
        "labels": labels,
        "annotations": annotations,
        "health": health,
        "restart_policy": restart_policy,
        "capabilities": normalized.facts.capabilities,
        "network_ids": normalized.facts.network_ids,
        "network_mode": normalized.network_mode,
        "network_backend": format!("{:?}", normalized.network_backend),
        "mounts": mounts,
        "privileged": normalized.facts.privileged,
        "readonly_rootfs": normalized.facts.readonly_rootfs,
        "no_new_privileges": normalized.facts.no_new_privileges,
        "mount_sources_approved": normalized.facts.mount_sources_approved,
        "limits": limits,
        "workdir": workdir,
        "user": user,
        "name": name,
        "ports": port_mappings,
    });
    sha2::Sha256::digest(
        serde_json::to_vec(&value).expect("canonical run execution request is serializable"),
    )
    .into()
}

impl ContainerRuntime {
    /// Derive the non-container mutation coordinator from this runtime's
    /// authoritative policy and shared journal configuration.
    pub fn surface_authorization(
        &self,
    ) -> Result<crate::authorization::surface::SurfaceAuthorization, RuntimeError> {
        self.authorization
            .surface_authorization()
            .map_err(|error| RuntimeError::Authorization(error.to_string()))
    }
    pub fn new(runtime_dir: &Path) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let runtime_id = load_or_create_runtime_id(runtime_dir)?;
        let authorization = production_authorization(runtime_dir, runtime_id)?;
        Self::initialize(
            runtime_dir,
            authorization,
            Arc::new(NoopLifecyclePhaseHook),
            Arc::new(ProductionKernelResourceOps),
        )
    }

    /// Bind an entry-point authenticated caller to all subsequent mutations
    /// performed by this request-scoped runtime value.
    pub fn with_request_origin(self, origin: crate::authorization::RequestOrigin) -> Self {
        Self {
            authorization: self.authorization.with_origin(origin),
            ..self
        }
    }

    pub fn with_emergency_authority(
        self,
        authority: crate::authorization::emergency::EmergencyAuthority,
    ) -> Self {
        Self {
            authorization: self.authorization.with_emergency_authority(authority),
            ..self
        }
    }

    pub fn request_origin(&self) -> Option<crate::authorization::RequestOrigin> {
        self.authorization.request_origin()
    }

    pub fn request_scoped(&self, origin: crate::authorization::RequestOrigin) -> Self {
        Self {
            store: self.store.clone(),
            runtime_dir: self.runtime_dir.clone(),
            cgroup_root: self.cgroup_root.clone(),
            health_cancel: DashMap::new(),
            resource_cancel: DashMap::new(),
            authorization: self.authorization.with_origin(origin),
            phase_hook: Arc::clone(&self.phase_hook),
            kernel_ops: Arc::clone(&self.kernel_ops),
        }
    }

    pub fn policy_binding(&self) -> (u64, [u8; 32]) {
        self.authorization.policy_binding()
    }

    pub fn install_policy_candidate(
        &self,
        candidate: &crate::authorization::policy::PolicyCandidate,
        rollback_authorized: bool,
    ) -> Result<crate::authorization::policy::PolicySnapshot, RuntimeError> {
        self.authorization
            .install_policy_candidate(candidate, rollback_authorized)
            .map_err(|error| RuntimeError::Authorization(error.to_string()))
    }

    /// Return the binding suitable for a delegation-enabled service. Delegation
    /// is never enabled on compatibility mode or without a required journal.
    pub fn delegation_authority_binding(&self) -> Result<(u64, [u8; 32], String), RuntimeError> {
        if self.authorization.authorization_mode()
            == crate::authorization::AuthorizationMode::Disabled
            || !self.authorization.requires_provenance()
        {
            return Err(RuntimeError::Authorization(
                "delegation requires enabled policy and a required witness journal".into(),
            ));
        }
        let (generation, digest) = self.policy_binding();
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        Ok((generation, digest, boot))
    }

    fn initialize(
        runtime_dir: &Path,
        authorization: RuntimeAuthorization,
        phase_hook: Arc<dyn LifecyclePhaseHook>,
        kernel_ops: Arc<dyn KernelResourceOps>,
    ) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        #[cfg(unix)]
        let _reconciliation_lock =
            LifecycleLock::acquire(&runtime_dir.join("reconciliation.lock"))?;
        let store = SqliteContainerStore::open(runtime_dir.join("containers.db"))?;
        let cgroup_root = configured_cgroup_root();
        let runtime = Self {
            store,
            runtime_dir: runtime_dir.to_path_buf(),
            cgroup_root,
            health_cancel: DashMap::new(),
            resource_cancel: DashMap::new(),
            authorization,
            phase_hook,
            kernel_ops: Arc::clone(&kernel_ops),
        };
        recover_pending_network_cleanups(
            runtime_dir,
            &runtime.store,
            &runtime.cgroup_root,
            &runtime.authorization,
            kernel_ops,
        )?;
        runtime.reconcile_pending_mutations()?;
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
        require_authorization_journal(&gate, journal.as_deref())?;
        fs::create_dir_all(runtime_dir)?;
        let runtime_id = load_or_create_runtime_id(runtime_dir)?;
        Self::initialize(
            runtime_dir,
            RuntimeAuthorization::new_with_id(gate, journal, runtime_id),
            Arc::new(NoopLifecyclePhaseHook),
            Arc::new(ProductionKernelResourceOps),
        )
    }

    pub fn new_with_authorization_and_phase_hook(
        runtime_dir: &Path,
        gate: Arc<AuthorizationGate>,
        journal: Option<Arc<crate::witness::WitnessJournal>>,
        phase_hook: Arc<dyn LifecyclePhaseHook>,
    ) -> Result<Self, RuntimeError> {
        require_authorization_journal(&gate, journal.as_deref())?;
        fs::create_dir_all(runtime_dir)?;
        let runtime_id = load_or_create_runtime_id(runtime_dir)?;
        Self::initialize(
            runtime_dir,
            RuntimeAuthorization::new_with_id(gate, journal, runtime_id),
            phase_hook,
            Arc::new(ProductionKernelResourceOps),
        )
    }

    #[cfg(test)]
    fn new_with_test_kernel_ops(
        runtime_dir: &Path,
        gate: Arc<AuthorizationGate>,
        journal: Option<Arc<crate::witness::WitnessJournal>>,
        phase_hook: Arc<dyn LifecyclePhaseHook>,
        kernel_ops: Arc<dyn KernelResourceOps>,
    ) -> Result<Self, RuntimeError> {
        fs::create_dir_all(runtime_dir)?;
        let runtime_id = load_or_create_runtime_id(runtime_dir)?;
        Self::initialize(
            runtime_dir,
            RuntimeAuthorization::new_with_id(gate, journal, runtime_id),
            phase_hook,
            kernel_ops,
        )
    }

    fn reconcile_persisted_state(&self) -> Result<(), RuntimeError> {
        let records = self.store.list()?;
        self.reconcile_network_state(&records)?;
        for mut record in records {
            if record.status != "running" && record.status != "paused" {
                continue;
            }
            // A different process may be between durable reservation and
            // effect publication. `reconcile_pending_mutations` owns that
            // recovery path; treating its PID as stale here would overwrite
            // the reservation and make the writer fail its compare-and-swap.
            if record.pending_mutation.is_some() {
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
            if is_ai_enabled() {
                log_ai_reconciliation(
                    &record.id,
                    record.last_exit_code.unwrap_or(-1),
                    "stale-pid",
                    "exited",
                );
            }
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
        let records = self.store.list()?;
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
            let Some(record_snapshot) = records
                .iter()
                .find(|record| {
                    record.pending_mutation.as_ref().is_some_and(|reservation| {
                        reservation.operation_id == *operation.as_bytes()
                    })
                })
                .cloned()
            else {
                let tombstone = self.store.lifecycle_operation(*operation.as_bytes())?;
                let recovered_delete = tombstone.as_ref().is_some_and(|entry| {
                    entry.action == "container.delete"
                        && entry.phase == LifecyclePhase::StoreDeleted
                });
                let evidence = crate::witness::RecoveryEvidence::verified(
                    &pending,
                    recovery_observation_tombstone(
                        tombstone.as_ref(),
                        pending.recipe().original_action(),
                    ),
                    recovered_delete,
                );
                journal.reconcile_observed(evidence)?;
                if tombstone.is_some() {
                    self.store.acknowledge_mutation(*operation.as_bytes())?;
                }
                continue;
            };
            let record_id = record_snapshot.id.clone();
            #[cfg(unix)]
            let _lifecycle_lock = {
                let lock_path = lifecycle_lock_path(&self.runtime_dir, &record_id);
                if let Some(parent) = lock_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                match LifecycleLock::try_acquire(&lock_path)? {
                    Some(lock) => lock,
                    None => continue,
                }
            };
            // The initial inventory is only a candidate list. Reload after
            // taking the per-container lock so recovery never applies a
            // stale snapshot over a concurrent terminal mutation.
            let Some(mut record) = self.store.get(&record_id)? else {
                continue;
            };
            let Some(reservation) = record.pending_mutation.clone() else {
                continue;
            };
            if reservation.operation_id != *operation.as_bytes() {
                continue;
            };
            // A live run reservation belongs to the process that is still
            // publishing its effect. Another CLI process opening the same
            // runtime must not classify that in-flight operation as a crash;
            // doing so races the owner's terminal compare-and-swap. If the
            // process disappears (or never produced a rootfs), normal
            // recovery below remains authoritative.
            if reservation.action == "container.run"
                && record.status == "running"
                && process_exists(record.pid)
                && process_start_time_for_pid(record.pid).is_some()
                && self
                    .runtime_dir
                    .join("containers")
                    .join(&record.id)
                    .join("rootfs")
                    .exists()
            {
                continue;
            }
            let action_matches = runtime_witness_action_name(pending.recipe().original_action())
                == reservation.action;
            let generation_matches =
                pending.recipe().resource_generation() == reservation.generation;
            let durable_operation = self.store.lifecycle_operation(reservation.operation_id)?;
            let truth_matches = action_matches
                && generation_matches
                && recovery_truth_matches(&record, durable_operation.as_ref(), &reservation.action)
                && (reservation.action != "container.run"
                    || self
                        .runtime_dir
                        .join("containers")
                        .join(&record.id)
                        .join("rootfs")
                        .exists());
            let run_live_effects = reservation.action == "container.run"
                && self.authorization.provenance_matches(&record)
                && record.status == "running"
                && process_exists(record.pid)
                && process_start_time_for_pid(record.pid).is_some()
                && self
                    .runtime_dir
                    .join("containers")
                    .join(&record.id)
                    .join("rootfs")
                    .exists();
            let run_not_applied = reservation.action == "container.run"
                && !run_live_effects
                && durable_operation.as_ref().is_some_and(|operation| {
                    operation.phase == LifecyclePhase::Reserved
                        || operation.effect_succeeded == Some(false)
                });
            let classification = if truth_matches {
                crate::witness::RecoveryClassification::Recovered
            } else {
                record.status = "quarantined".into();
                crate::witness::RecoveryClassification::Quarantined
            };
            let recovered_delete = (reservation.action == "container.delete"
                && classification == crate::witness::RecoveryClassification::Recovered)
                || run_not_applied;
            if recovered_delete {
                self.store
                    .delete_for_mutation(&record.id, reservation.operation_id)?;
            } else {
                self.store
                    .put_for_mutation(&record, reservation.operation_id)?;
            }
            let evidence = crate::witness::RecoveryEvidence::verified(
                &pending,
                recovery_observation(Some(&record), pending.recipe().original_action()),
                classification == crate::witness::RecoveryClassification::Recovered,
            );
            journal.reconcile_observed(evidence)?;
            if recovered_delete {
                self.store.acknowledge_mutation(reservation.operation_id)?;
            } else if run_live_effects
                && classification == crate::witness::RecoveryClassification::Quarantined
            {
                // An effect may exist without a committed effect marker. Keep
                // the reservation as an operator-visible quarantine boundary.
            } else {
                self.store
                    .finish_mutation(&record.id, reservation.operation_id)?;
            }
        }
        // A crash after the terminal journal flush but before store cleanup
        // leaves no journal-pending entry. The independent operation tree is
        // authoritative for completing that final idempotent clear.
        for operation_snapshot in self.store.lifecycle_operations()? {
            // The operation tree is an independent recovery index. It must
            // use the same per-container lock as normal lifecycle calls;
            // otherwise a fresh CLI can finish/delete a live reservation
            // after the owning process has taken its lock but before that
            // process publishes the terminal effect.
            #[cfg(unix)]
            let _lifecycle_lock = {
                let lock_path =
                    lifecycle_lock_path(&self.runtime_dir, &operation_snapshot.container_id);
                if let Some(parent) = lock_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                match LifecycleLock::try_acquire(&lock_path)? {
                    Some(lock) => lock,
                    None => continue,
                }
            };
            let Some(operation) = self
                .store
                .lifecycle_operation(operation_snapshot.operation_id)?
            else {
                continue;
            };
            let id = crate::witness::OperationId::from_bytes(operation.operation_id);
            if !matches!(
                journal.recover(id),
                Err(crate::witness::JournalError::AlreadyComplete)
            ) {
                continue;
            }
            if operation.phase == LifecyclePhase::StoreDeleted {
                self.store.acknowledge_mutation(operation.operation_id)?;
            } else if operation.action == "container.run"
                && self
                    .store
                    .get(&operation.container_id)?
                    .is_some_and(|record| {
                        record.status == "quarantined" && process_exists(record.pid)
                    })
            {
                continue;
            } else if operation.action == "container.run"
                && operation.effect_succeeded == Some(false)
                && self
                    .store
                    .get(&operation.container_id)?
                    .is_some_and(|record| {
                        record.status != "running"
                            || !process_exists(record.pid)
                            || !self.authorization.provenance_matches(&record)
                    })
            {
                self.store
                    .delete_for_mutation(&operation.container_id, operation.operation_id)?;
                self.store.acknowledge_mutation(operation.operation_id)?;
            } else if self.store.get(&operation.container_id)?.is_some() {
                self.store
                    .finish_mutation(&operation.container_id, operation.operation_id)?;
            }
        }
        Ok(())
    }

    fn reconcile_network_state(&self, records: &[ContainerRecord]) -> Result<(), RuntimeError> {
        // Acquire every durable internal-recovery intent before observing code
        // is allowed to reload classifiers or rewrite ownership metadata.  A
        // required journal failure therefore leaves the network untouched.
        let mut recoveries = Vec::new();
        for record in records.iter().filter(|record| {
            matches!(record.status.as_str(), "running" | "paused")
                && record.network_name.as_deref() == Some("bridge")
        }) {
            recoveries.push((
                record.id.clone(),
                self.authorization
                    .begin_internal_network_recovery(&record.id)?,
            ));
        }
        let mut reconciled_networks = BTreeSet::new();
        let result = records
            .iter()
            .filter(|record| matches!(record.status.as_str(), "running" | "paused"))
            .try_for_each(|record| {
                self.reconcile_record_network(record, records, &mut reconciled_networks)
            });
        let recovered = result.is_ok();
        for (container_id, operation) in recoveries {
            self.authorization.finish_internal_recovery(
                operation,
                internal_cleanup_observation(&container_id, recovered),
                recovered,
            )?;
        }
        result
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
        let network_id = ownership
            .network_id
            .as_deref()
            .expect("validated network id");
        match plan_network_recovery(observe_owned_ebpf_state(ownership)?)? {
            NetworkRecoveryAction::VerifyAndReuse => {
                if is_ai_enabled() {
                    log_ai_kernel_reconciliation(network_id, "verify-reuse", records.len());
                }
                Ok(())
            }
            NetworkRecoveryAction::ReloadShared => {
                let interface = config.interface.clone();
                let before = shared_tc_filter_snapshot(&interface)?;
                let mut network = prepare_ebpf_classifiers(config)?
                    .attach()
                    .map_err(|error| RuntimeError::Network(error.to_string()))?;
                for record in records {
                    if let (Some(interface), Some(ifindex)) = (
                        record
                            .network_ownership
                            .as_ref()
                            .map(|ownership| ownership.host_interface.as_str()),
                        record
                            .network_ownership
                            .as_ref()
                            .and_then(|ownership| ownership.host_ifindex),
                    ) {
                        network
                            .attach_interface(interface, ifindex)
                            .map_err(|error| RuntimeError::Network(error.to_string()))?;
                    }
                    install_record_on_attached_network(&mut network, record)?;
                }
                let mut filters = shared_tc_filter_snapshot(&interface)?;
                filters.retain(|filter| !before.contains(filter));
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
                if is_ai_enabled() {
                    log_ai_kernel_reconciliation(network_id, "reload-shared", records.len());
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
            None,
            network_backend,
            ai_config,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn normalized_run_execution_digest(
        &self,
        store: &LocalImageStore,
        image: &str,
        cmd: &[String],
        env: &[String],
        labels: &HashMap<String, String>,
        annotations: &HashMap<String, String>,
        health: Option<&HealthConfig>,
        restart_policy: &RestartPolicy,
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
    ) -> Result<[u8; 32], RuntimeError> {
        let pinned_image = match store.resolve_reference(image)? {
            Some(record) => immutable_image_reference(&record.reference, &record.digest)?,
            None => image.to_owned(),
        };
        let normalized = normalize_run_request(
            capabilities,
            mounts,
            tmpfs_mounts,
            readonly_rootfs,
            no_new_privs,
            network_mode,
            network_backend,
            port_mappings,
            self.authorization.authorization_mode(),
        )?;
        Ok(run_execution_digest(
            &pinned_image,
            cmd,
            env,
            labels,
            annotations,
            health,
            restart_policy,
            limits,
            workdir,
            user,
            name,
            port_mappings,
            &normalized,
        ))
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
        associated_network: Option<&str>,
        network_backend: NetworkBackend,
        ai_config: Option<&AiRuntimeConfig>,
    ) -> Result<ContainerRecord, RuntimeError> {
        self.run_with_store_with_id(
            generate_container_id(),
            store,
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
            associated_network,
            network_backend,
            ai_config,
        )
    }

    /// Run a container using a caller-provided identity. This is used by
    /// compatibility surfaces such as Docker create/start, which must return
    /// the same identity before and after the start transition.
    #[allow(clippy::too_many_arguments)]
    pub fn run_with_store_with_id(
        &self,
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
        associated_network: Option<&str>,
        network_backend: NetworkBackend,
        ai_config: Option<&AiRuntimeConfig>,
    ) -> Result<ContainerRecord, RuntimeError> {
        if self.store.get(&container_id)?.is_some() {
            return Err(RuntimeError::InvalidState(format!(
                "container identity already exists: {container_id}"
            )));
        }
        #[cfg(unix)]
        let _lifecycle_lock = {
            let lock_path = lifecycle_lock_path(&self.runtime_dir, &container_id);
            if let Some(parent) = lock_path.parent() {
                fs::create_dir_all(parent)?;
            }
            LifecycleLock::acquire(&lock_path)?
        };
        let pinned_image = match store.resolve_reference(image)? {
            Some(record) => immutable_image_reference(&record.reference, &record.digest)?,
            None => image.to_owned(),
        };
        let signature_image = immutable_image_manifest_reference(store, image)?;
        let normalized = normalize_run_request(
            capabilities,
            mounts,
            tmpfs_mounts,
            readonly_rootfs,
            no_new_privs,
            network_mode,
            network_backend,
            port_mappings,
            self.authorization.authorization_mode(),
        )?;
        let execution_digest = run_execution_digest(
            &pinned_image,
            cmd,
            env,
            labels,
            annotations,
            health.as_ref(),
            &restart_policy,
            limits,
            workdir,
            user,
            name,
            port_mappings,
            &normalized,
        );
        let mut normalized = normalized;
        normalized.facts.execution_digest = Some(hex::encode(execution_digest));
        normalized.facts.parent_resource_id = labels.get("io.ferrocrate.parent-resource").cloned();
        if self
            .authorization
            .request_origin()
            .is_some_and(|origin| !origin.fanout_request_digest_matches(&execution_digest))
        {
            return Err(RuntimeError::Authorization(
                "compose execution request digest does not match authorized child".into(),
            ));
        }
        let mut candidate =
            ContainerRecord::authorization_candidate(container_id.clone(), pinned_image);
        candidate.name = name.map(str::to_owned);
        candidate.capabilities = normalized.facts.capabilities.clone();
        candidate.network_name = persisted_network_name(associated_network, network_mode);
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
            if let Err(error) = self.store.put_reserved_creation(&candidate) {
                log::error!(
                    "container.run failed while reserving creation: container_id={} operation_id={:?} error={}",
                    container_id,
                    operation_id,
                    error
                );
                return Err(error.into());
            }
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
            &signature_image,
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
            &mounts
                .iter()
                .map(|mount| ContainerMountRecord {
                    source: mount.source.display().to_string(),
                    target: mount.target.display().to_string(),
                    read_only: mount.read_only,
                })
                .collect::<Vec<_>>(),
            &tmpfs_mounts
                .iter()
                .map(|mount| ContainerTmpfsMountRecord {
                    target: mount.target.display().to_string(),
                    size: mount.size.clone(),
                })
                .collect::<Vec<_>>(),
            normalized.facts.readonly_rootfs,
            normalized.facts.no_new_privileges,
            workdir,
            user,
            name,
            port_mappings,
            &normalized.network_mode,
            associated_network,
            normalized.network_backend,
            ai_config,
        );
        if witnessed {
            if let Err(error) =
                self.store
                    .mark_mutation_effect(&container_id, operation_id, result.is_ok())
            {
                log::error!(
                    "container.run failed while recording effect: container_id={} operation_id={:?} error={}",
                    container_id,
                    operation_id,
                    error
                );
                return Err(error.into());
            }
            self.phase_hook
                .reached("container.run", LifecyclePhasePoint::EffectObserved)?;
        }
        self.authorization.complete(permit, result.is_ok())?;
        self.phase_hook
            .reached("container.run", LifecyclePhasePoint::TerminalDurable)?;
        if witnessed {
            if result.is_ok() {
                if let Err(error) = self.store.finish_mutation(&container_id, operation_id) {
                    log::error!(
                        "container.run failed while clearing reservation: container_id={} operation_id={:?} error={}",
                        container_id,
                        operation_id,
                        error
                    );
                    return Err(error.into());
                }
            } else {
                self.store
                    .delete_for_mutation(&container_id, operation_id)?;
                self.store.acknowledge_mutation(operation_id)?;
            }
            self.phase_hook
                .reached("container.run", LifecyclePhasePoint::ReservationCleared)?;
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn run_with_store_authorized(
        &self,
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
        creation_provenance: crate::container_store::CreationProvenance,
        container_id: String,
        store: &LocalImageStore,
        image: &str,
        signature_image: &str,
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
        persisted_mounts: &[ContainerMountRecord],
        persisted_tmpfs_mounts: &[ContainerTmpfsMountRecord],
        readonly_rootfs: bool,
        no_new_privs: bool,
        workdir: Option<&str>,
        user: Option<&str>,
        name: Option<&str>,
        port_mappings: &[crate::container_store::PortMappingRecord],
        network_mode: &str,
        associated_network: Option<&str>,
        network_backend: NetworkBackend,
        ai_config: Option<&AiRuntimeConfig>,
    ) -> Result<ContainerRecord, RuntimeError> {
        parse_image_reference(image)?;
        ensure_kernel_min_version()?;
        let rootless = !nix::unistd::Uid::effective().is_root();
        validate_rootless_mount_capability(rootless, mounts, tmpfs_mounts, readonly_rootfs)?;
        if rootless && network_mode == "bridge" && rootless_netns_enabled() {
            nested_bubblewrap_diagnostic().map_err(RuntimeError::InvalidCommand)?;
        }
        verify_image_signature(signature_image)
            .map_err(|err| RuntimeError::InvalidState(err.to_string()))?;
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
        let mut rollback = CreationRollback::new(
            &container_id,
            self.cgroup_root.clone(),
            creation_provenance.clone(),
            Arc::clone(&self.kernel_ops),
        );

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
        let rootfs_plan = rollback.plan_typed_resource(ResourcePlan::Rootfs {
            path: rootfs_dir.clone(),
            generation: 1,
            operation_id: creation_provenance.creator_operation_id,
        })?;
        let network_plan = rollback.plan_typed_resource(ResourcePlan::NetworkAllocation {
            canonical: format!("{network_mode}:{network_backend}"),
            generation: 1,
            operation_id: creation_provenance.creator_operation_id,
        })?;
        let cgroup_plan = limits
            .is_some()
            .then(|| {
                rollback.plan_typed_resource(ResourcePlan::Cgroup {
                    name: format!("ferrocrate/{container_id}"),
                    generation: 1,
                    operation_id: creation_provenance.creator_operation_id,
                    expected_controllers: vec!["cpu".into(), "memory".into(), "pids".into()],
                })
            })
            .transpose()?;
        let process_plan = rollback.plan_typed_resource(ResourcePlan::Process {
            generation: 1,
            operation_id: creation_provenance.creator_operation_id,
        })?;
        rollback.plan_resource("rootfs", rootfs_dir.display().to_string())?;
        for (index, mount) in mounts.iter().enumerate() {
            rollback.plan_resource(
                &format!("mount:{index}"),
                format!("{}:{}", mount.source.display(), mount.target.display()),
            )?;
        }
        rollback.plan_resource("network", format!("{network_mode}:{network_backend}"))?;
        if limits.is_some() {
            rollback.plan_resource("cgroup", format!("ferrocrate/{container_id}:1"))?;
        }
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
        let baseline_excluded = mounts
            .iter()
            .map(|mount| rootfs_dir.join(&mount.target))
            .chain(
                tmpfs_mounts
                    .iter()
                    .map(|mount| rootfs_dir.join(&mount.target)),
            )
            .collect::<Vec<_>>();
        let rootfs_baseline = rootfs_diff::capture(&rootfs_dir, &baseline_excluded)?;
        rootfs_diff::write_baseline(
            &container_dir.join("rootfs-baseline.json"),
            &rootfs_baseline,
        )?;
        rollback.mark_resource_applied("rootfs", kernel_path_identity(&rootfs_dir).ok())?;
        rollback.mark_typed_resource(rootfs_plan, path_resource_identity(&rootfs_dir)?)?;

        let mut bind_plans = Vec::with_capacity(mounts.len());
        for mount in mounts {
            let _target = open_mount_target_beneath(&rootfs_dir, &mount.target)?;
            let target = path_resource_identity(&rootfs_dir.join(&mount.target))?;
            let source_metadata = fs::metadata(&mount.source)?;
            let ResourceIdentity::Path {
                device,
                inode,
                mount_id,
            } = target
            else {
                unreachable!()
            };
            bind_plans.push(rollback.plan_typed_resource(ResourcePlan::BindMount {
                target: mount.target.clone(),
                generation: 1,
                source_device: source_metadata.dev(),
                source_inode: source_metadata.ino(),
                baseline_device: device,
                baseline_inode: inode,
                baseline_mount_id: mount_id,
                operation_id: creation_provenance.creator_operation_id,
            })?);
        }
        let mut tmpfs_plans = Vec::with_capacity(tmpfs_mounts.len());
        for mount in tmpfs_mounts {
            let _target = open_mount_target_beneath(&rootfs_dir, &mount.target)?;
            let ResourceIdentity::Path {
                device,
                inode,
                mount_id,
            } = path_resource_identity(&rootfs_dir.join(&mount.target))?
            else {
                unreachable!()
            };
            tmpfs_plans.push(rollback.plan_typed_resource(ResourcePlan::TmpfsMount {
                target: mount.target.clone(),
                generation: 1,
                baseline_device: device,
                baseline_inode: inode,
                baseline_mount_id: mount_id,
                operation_id: creation_provenance.creator_operation_id,
            })?);
        }
        let readonly_plan = if readonly_rootfs {
            let ResourceIdentity::Path {
                device,
                inode,
                mount_id,
            } = path_resource_identity(&rootfs_dir)?
            else {
                unreachable!()
            };
            Some(rollback.plan_typed_resource(ResourcePlan::RootfsReadonly {
                target: PathBuf::from("."),
                generation: 1,
                baseline_device: device,
                baseline_inode: inode,
                baseline_mount_id: mount_id,
                operation_id: creation_provenance.creator_operation_id,
            })?)
        } else {
            None
        };

        let defer_rootless_mounts =
            rootless && (!mounts.is_empty() || !tmpfs_mounts.is_empty() || readonly_rootfs);
        if !defer_rootless_mounts {
            for (index, mount) in mounts.iter().enumerate() {
                self.kernel_ops.apply_bind(&rootfs_dir, mount)?;
                self.phase_hook
                    .reached("run", LifecyclePhasePoint::BindKernelEffect)?;
                {
                    rollback.mark_resource_applied(&format!("mount:{index}"), None)?;
                    rollback.mark_typed_resource(
                        bind_plans[index],
                        self.kernel_ops.identity(&rootfs_dir.join(&mount.target))?,
                    )?;
                }
            }
            for (index, mount) in tmpfs_mounts.iter().enumerate() {
                self.kernel_ops.apply_tmpfs(&rootfs_dir, mount)?;
                self.phase_hook
                    .reached("run", LifecyclePhasePoint::TmpfsKernelEffect)?;
                rollback.mark_typed_resource(
                    tmpfs_plans[index],
                    self.kernel_ops.identity(&rootfs_dir.join(&mount.target))?,
                )?;
            }
            if readonly_rootfs {
                self.kernel_ops.apply_readonly(&rootfs_dir)?;
                self.phase_hook
                    .reached("run", LifecyclePhasePoint::ReadonlyKernelEffect)?;
                rollback.mark_typed_resource(
                    readonly_plan.expect("readonly plan exists"),
                    self.kernel_ops.identity(&rootfs_dir)?,
                )?;
            }
        }

        validate_port_mapping_conflicts(&self.store, port_mappings)?;

        let existing_records = self.store.list()?;
        let kernel_ops = Arc::clone(&self.kernel_ops);
        let mut network_setup = kernel_ops.setup_network(
            proof,
            intent,
            &container_id,
            port_mappings,
            network_mode,
            network_backend,
            &mut rollback,
            &existing_records,
            self.phase_hook.as_ref(),
        )?;
        self.phase_hook
            .reached("run", LifecyclePhasePoint::NetworkKernelEffect)?;
        // Track network resources for rollback
        rollback.track_network(&mut network_setup, port_mappings)?;
        rollback.mark_resource_applied(
            "network",
            network_setup
                .ownership
                .as_ref()
                .and_then(|o| o.namespace_identity),
        )?;
        rollback.mark_typed_resource(
            network_plan,
            ResourceIdentity::Network {
                identity: network_setup
                    .ownership
                    .as_ref()
                    .and_then(|ownership| ownership.namespace_identity),
            },
        )?;
        self.phase_hook
            .reached("run", LifecyclePhasePoint::NetworkApplied)?;
        let netns_name = network_setup.netns_name.clone();
        let container_ip = network_setup.container_ip.clone();
        let container_ipv6 = network_setup.container_ipv6.clone();
        // `none` intentionally has no network namespace setup. Only bridge
        // mode needs the user+network namespace and slirp handoff; sending
        // `none` through that launcher creates an unnecessary nested sandbox
        // and can fail on hosts that deny nested user namespaces.
        let unshare_netns = rootless && network_mode == "bridge" && rootless_netns_enabled();
        let use_slirp = unshare_netns && network_mode == "bridge";

        // Load seccomp profile for container isolation.
        // Guest authority uses the restricted guest profile; others use the default.
        let seccomp_profile = resolve_seccomp_profile(ai_config)?;

        // Provision and configure the cgroup before launching the workload.
        // Applying limits after spawn leaves a race in which short-lived
        // processes can run outside their requested boundary (and is
        // especially visible for rootless delegated cgroups).  The child is
        // attached immediately after spawn below, before it can perform any
        // user-visible work beyond the exec boundary.
        let cgroup_path = if let Some(limits) = limits {
            let manager = CgroupV2Manager::new(&self.cgroup_root);
            let cgroup_name = format!("ferrocrate/{container_id}");
            let group = manager.create_group(&cgroup_name)?;
            self.phase_hook
                .reached("run", LifecyclePhasePoint::CgroupKernelEffect)?;
            rollback.track_cgroup(cgroup_name)?;
            let cgroup_metadata = fs::metadata(&group)?;
            rollback.mark_typed_resource(
                cgroup_plan.expect("cgroup plan exists"),
                ResourceIdentity::Cgroup {
                    device: cgroup_metadata.dev(),
                    inode: cgroup_metadata.ino(),
                },
            )?;
            manager
                .apply_limits(&group, limits)
                .map_err(RuntimeError::Cgroup)?;
            self.phase_hook
                .reached("run", LifecyclePhasePoint::CgroupApplied)?;
            Some(group)
        } else {
            None
        };

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
            ai_lifecycle_enabled(ai_config),
            capabilities.to_vec(),
            resolved_workdir.as_deref(),
            resolved_user.as_deref(),
            netns_name.as_deref(),
            unshare_netns,
            seccomp_profile.as_ref(),
            mounts.to_vec(),
            tmpfs_mounts.to_vec(),
            readonly_rootfs,
        )
        .inspect_err(|_e| {
            // Kill any partially spawned process on error
            rollback.rollback();
        })?;
        rollback.mark_typed_resource(
            process_plan,
            ResourceIdentity::Process {
                pid: child_id,
                start_time: process_start_time_for_pid(child_id).ok_or_else(|| {
                    RuntimeError::InvalidState("spawned process has no stable starttime".into())
                })?,
            },
        )?;
        self.phase_hook
            .reached("run", LifecyclePhasePoint::SpawnPrepared)?;

        if let Some(group) = cgroup_path.as_ref() {
            let manager = CgroupV2Manager::new(&self.cgroup_root);
            if let Err(error) = manager.add_pid(group, child_id) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(RuntimeError::Cgroup(error));
            }
        }

        if security_ebpf_monitor_enabled() {
            if let Err(e) = setup_security_ebpf_monitor(&container_id) {
                let _ = kill_pid(child_id);
                rollback.rollback();
                return Err(e);
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
            namespace_owned: network_setup.namespace_owned,
            namespace_identity: network_setup.namespace_identity,
            network_name: persisted_network_name(associated_network, network_mode),
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
            mounts: persisted_mounts.to_vec(),
            tmpfs_mounts: persisted_tmpfs_mounts.to_vec(),
            readonly_rootfs,
            no_new_privileges: no_new_privs,
            resource_limits: limits.map(|value| ResourceLimitRecord {
                memory_max: value.memory_max,
                cpu_quota: value.cpu_max.as_ref().map(|cpu| cpu.quota),
                cpu_period: value.cpu_max.as_ref().map(|cpu| cpu.period),
                pids_max: value.pids_max,
            }),
            network_backend: network_setup.backend.map(|backend| backend.to_string()),
            network_ownership: network_setup.ownership.clone(),
            managed_overlay: network_setup.managed_overlay.clone(),
            managed_cleanup_provenance: network_setup.managed_cleanup_provenance.clone(),
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
        let persist_result = if let Some(reservation) = record.pending_mutation.as_ref() {
            self.store
                .put_for_mutation(&record, reservation.operation_id)
        } else {
            self.store.put(&record)
        };
        if let Err(error) = persist_result {
            log::error!(
                "container.run failed while publishing launch identity: container_id={} operation_id={:?} mutation_generation={} status={} error={}",
                container_id,
                record.pending_mutation.as_ref().map(|reservation| reservation.operation_id),
                record.mutation_generation,
                record.status,
                error
            );
            let _ = kill_pid(child_id);
            rollback.rollback();
            return Err(error.into());
        }
        self.phase_hook
            .reached("run", LifecyclePhasePoint::LaunchIdentityDurable)?;
        // The launcher is held behind an ownership barrier until its durable
        // record exists. Release it before attaching slirp4netns: attaching
        // to the stopped pre-exec launcher targets the host namespace rather
        // than the user/network namespace created by `unshare`.
        release_prepared_child(child_id)?;
        if use_slirp {
            let api_socket = container_dir.join("slirp4netns.sock");
            match start_slirp4netns(child_id, Some(&api_socket)) {
                Ok((helper_pid, helper_start_time)) => {
                    rollback.slirp_process = Some((helper_pid, helper_start_time));
                    if let Err(error) = configure_slirp_host_forwards(&api_socket, port_mappings) {
                        let _ = kill_pid(child_id);
                        rollback.rollback();
                        return Err(error);
                    }
                }
                Err(e) => {
                    let _ = kill_pid(child_id);
                    rollback.rollback();
                    return Err(e);
                }
            }
        }
        // The rootless wrapper deliberately stopped after namespace creation;
        // let it exec the workload only after slirp setup is complete.
        if use_slirp {
            release_prepared_child(child_id)?;
        }
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

        // Task 5.1: Start resource monitor for OOM prediction if AI is enabled.
        let memory_limit = limits.and_then(|l| l.memory_max).unwrap_or(0);
        if should_start_ai_monitor(memory_limit) {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let cgroup_root = self.cgroup_root.clone();
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
        self.exec_with_timeout(id, cmd, None)
    }

    pub fn exec_with_timeout(
        &self,
        id: &str,
        cmd: &[String],
        timeout: Option<Duration>,
    ) -> Result<crate::container_exec::ExecResult, RuntimeError> {
        let permit = self.authorize_existing(Action::ContainerExec, id)?;
        let operation_id = permit.operation_id();
        let (proof, intent) = permit.execution_authority();
        let result = self.exec_authorized(proof, intent, id, cmd, timeout);
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
        timeout: Option<Duration>,
    ) -> Result<crate::container_exec::ExecResult, RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let rootfs = self.runtime_dir.join("containers").join(id).join("rootfs");
        let result = if !nix::unistd::Uid::effective().is_root() && rootfs.is_dir() {
            let mounts = record
                .mounts
                .iter()
                .map(|mount| (mount.source.clone(), mount.target.clone(), mount.read_only))
                .collect::<Vec<_>>();
            let tmpfs_mounts = record
                .tmpfs_mounts
                .iter()
                .map(|mount| (mount.target.clone(), mount.size.clone()))
                .collect::<Vec<_>>();
            exec_in_rootless_rootfs(
                &rootfs,
                cmd,
                &record.env,
                record.workdir.as_deref(),
                &mounts,
                &tmpfs_mounts,
                record.readonly_rootfs,
                timeout,
            )?
        } else {
            match timeout {
                Some(timeout) => exec_in_container_with_timeout(record.pid, cmd, timeout)?,
                None => exec_in_container(record.pid, cmd)?,
            }
        };
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
        let (stdout, stderr) = self.logs_split(id)?;
        Ok(format!("{stdout}{stderr}"))
    }

    /// Return stdout and stderr independently for Docker raw-stream framing.
    #[inline]
    pub fn logs_split(&self, id: &str) -> Result<(String, String), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        let stdout = if Path::new(&record.stdout_path).exists() {
            fs::read_to_string(&record.stdout_path)?
        } else {
            String::new()
        };
        let stderr = if Path::new(&record.stderr_path).exists() {
            fs::read_to_string(&record.stderr_path)?
        } else {
            String::new()
        };
        Ok((stdout, stderr))
    }

    /// Return the authorization-scoped FIFO used for a running container's
    /// Docker-compatible stdin channel. Callers must still validate the
    /// container record before opening it for writes.
    #[inline]
    pub fn stdin_path(&self, id: &str) -> PathBuf {
        self.runtime_dir.join("containers").join(id).join("stdin")
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
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
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
        self.persist_effect_status(proof, intent, id, "running", "paused")?;
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
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
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
        self.persist_effect_status(proof, intent, id, "paused", "running")?;
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
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
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
        cleanup_ai_container_snapshots(&self.runtime_dir, id);

        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        stop_pid(record.pid, timeout)?;
        cleanup_security_ebpf_monitor(&record.id)?;
        cleanup_apparmor_profile(&self.runtime_dir, &record.id)?;
        self.persist_effect_status(proof, intent, id, "running", "stopped")?;
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
        self.kill_with_signal(id, Some(nix::sys::signal::Signal::SIGKILL))
    }

    pub fn kill_with_signal(
        &self,
        id: &str,
        signal: Option<nix::sys::signal::Signal>,
    ) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerKill, id, |runtime, proof, intent| {
            runtime.kill_authorized(proof, intent, id, signal)
        })
    }

    fn kill_authorized(
        &self,
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
        id: &str,
        signal: Option<nix::sys::signal::Signal>,
    ) -> Result<(), RuntimeError> {
        let record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if let Some(signal) = signal {
            signal_pid(record.pid, signal)?;
        } else {
            // Docker's signal 0 is an existence probe. It must not publish a
            // killed state or trigger cleanup side effects.
            probe_pid(record.pid)?;
            return Ok(());
        }
        cleanup_security_ebpf_monitor(&record.id)?;
        cleanup_apparmor_profile(&self.runtime_dir, &record.id)?;
        self.persist_effect_status(proof, intent, id, "running", "killed")?;
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

    fn persist_effect_status(
        &self,
        proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
        id: &str,
        expected_status: &str,
        next_status: &str,
    ) -> Result<(), RuntimeError> {
        let result = if intent.is_some() {
            self.phase_hook
                .reached(
                    "container.lifecycle-effect",
                    LifecyclePhasePoint::KernelEffectApplied,
                )
                .map_err(|_| {
                    RuntimeError::PostEffectPersistence(ContainerStoreError::MutationConflict)
                })?;
            let operation_id = self
                .store
                .get(id)?
                .and_then(|record| {
                    record
                        .pending_mutation
                        .map(|reservation| reservation.operation_id)
                })
                .ok_or(ContainerStoreError::MutationConflict)?;
            self.store.transition_status_for_mutation(
                id,
                operation_id,
                proof.canonical().resource_generation(),
                expected_status,
                next_status,
            )
        } else {
            let operation_id = self
                .store
                .get(id)?
                .and_then(|record| {
                    record
                        .pending_mutation
                        .map(|reservation| reservation.operation_id)
                })
                .ok_or(ContainerStoreError::MutationConflict)?;
            self.store.transition_status_for_mutation(
                id,
                operation_id,
                proof.canonical().resource_generation(),
                expected_status,
                next_status,
            )
        };
        result.map_err(RuntimeError::PostEffectPersistence)
    }

    pub fn restart(&self, id: &str, timeout: Duration) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerRestart, id, |runtime, proof, intent| {
            runtime.restart_authorized(proof, intent, id, timeout, true)
        })
    }

    /// Start a previously stopped container without first signalling its old
    /// process. This is the native equivalent of Docker's start transition;
    /// it uses the same durable launch/recovery protocol as restart.
    pub fn start(&self, id: &str) -> Result<(), RuntimeError> {
        self.mediate_existing(Action::ContainerStart, id, |runtime, proof, intent| {
            runtime.restart_authorized(proof, intent, id, Duration::ZERO, false)
        })
    }

    /// Rename a stopped or running container while preserving its durable
    /// lifecycle generation and authorization receipt. Names are metadata, but
    /// changing them is still a mutation and therefore uses the same
    /// intent/effect/store protocol as other container operations.
    pub fn rename(&self, id: &str, name: &str) -> Result<(), RuntimeError> {
        validate_container_name(name)?;
        self.mediate_existing(Action::ContainerRename, id, |runtime, proof, intent| {
            runtime.rename_authorized(proof, intent, id, name)
        })
    }

    fn rename_authorized(
        &self,
        _proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
        id: &str,
        name: &str,
    ) -> Result<(), RuntimeError> {
        let mut record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if self
            .store
            .list()?
            .into_iter()
            .any(|other| other.id != id && other.name.as_deref() == Some(name))
        {
            return Err(RuntimeError::InvalidState(format!(
                "container name is already in use: {name}"
            )));
        }
        let previous = record.name.clone();
        record.name = Some(name.to_string());
        let operation_id = record
            .pending_mutation
            .as_ref()
            .map(|reservation| reservation.operation_id)
            .ok_or(ContainerStoreError::MutationConflict)?;
        self.store.put_for_mutation(&record, operation_id)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                "rename",
                Some(id),
                Some(&record.image),
                Some(name),
                previous.as_deref(),
            ),
        );
        let _ = log_audit_event(
            &self.runtime_dir,
            make_audit_event(
                "rename",
                audit_actor().as_str(),
                Some(id),
                Some(&record.image),
                Some(name),
                previous.as_deref(),
            ),
        );
        let _ = intent;
        Ok(())
    }

    fn restart_authorized(
        &self,
        _proof: &AuthorizedRequest,
        _intent: Option<&crate::witness::DurableIntent>,
        id: &str,
        timeout: Duration,
        stop_existing: bool,
    ) -> Result<(), RuntimeError> {
        let mut record = self
            .store
            .get(id)?
            .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
        if record.command.is_empty() {
            return Err(RuntimeError::MissingCommand);
        }
        if !stop_existing && record.status == "running" {
            return Err(RuntimeError::InvalidState(
                "container is already running".into(),
            ));
        }

        let records = self.store.list()?;
        self.reconcile_record_network(&record, &records, &mut BTreeSet::new())?;
        self.phase_hook
            .reached("restart", LifecyclePhasePoint::NetworkApplied)?;

        if stop_existing {
            stop_pid(record.pid, timeout)?;
            cleanup_security_ebpf_monitor(&record.id)?;
            cleanup_apparmor_profile(&self.runtime_dir, &record.id)?;
        }
        self.phase_hook.reached(
            if stop_existing { "restart" } else { "start" },
            LifecyclePhasePoint::RestartOldStopped,
        )?;

        let stdout_path = PathBuf::from(&record.stdout_path);
        let stderr_path = PathBuf::from(&record.stderr_path);

        // Load seccomp profile for restarted container.
        // Uses the authority stored in the container record, if present.
        let seccomp_profile = resolve_seccomp_profile(record.ai_runtime.as_ref())?;
        // Rootless mounts are materialized inside the bubblewrap execution
        // boundary. Replaying them through the host kernel would both require
        // privilege and violate the rootless isolation contract.
        if nix::unistd::Uid::effective().is_root() {
            replay_persisted_mounts(
                &self.runtime_dir.join("containers").join(id).join("rootfs"),
                &record,
            )?;
        }

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
            ai_lifecycle_enabled(record.ai_runtime.as_ref()),
            parse_capabilities(&record.capabilities),
            record.workdir.as_deref(),
            record.user.as_deref(),
            record.netns.as_deref(),
            false,
            seccomp_profile.as_ref(),
            record
                .mounts
                .iter()
                .map(|mount| BindMount {
                    source: PathBuf::from(&mount.source),
                    target: PathBuf::from(&mount.target),
                    read_only: mount.read_only,
                })
                .collect(),
            record
                .tmpfs_mounts
                .iter()
                .map(|mount| TmpfsMount {
                    target: PathBuf::from(&mount.target),
                    size: mount.size.clone(),
                })
                .collect(),
            record.readonly_rootfs,
        )?;
        self.phase_hook.reached(
            if stop_existing { "restart" } else { "start" },
            LifecyclePhasePoint::SpawnPrepared,
        )?;

        // A stopped container keeps its resource-limit contract, so reattach
        // the replacement process before releasing its launch barrier.  The
        // cgroup normally survives stop; recreate and configure it if a
        // host-side cleanup removed it while the container was stopped.
        if let Some(stored) = record.resource_limits.as_ref() {
            let cpu_max = match (stored.cpu_quota, stored.cpu_period) {
                (Some(quota), Some(period)) => Some(CpuMax { quota, period }),
                (None, None) => None,
                _ => {
                    let _ = kill_pid(child_id);
                    return Err(RuntimeError::InvalidState(
                        "persisted resource limits contain an incomplete cpu quota".into(),
                    ));
                }
            };
            let limits = ResourceLimits {
                memory_max: stored.memory_max,
                cpu_max,
                pids_max: stored.pids_max,
            };
            let manager = CgroupV2Manager::new(&self.cgroup_root);
            let cgroup_name = format!("ferrocrate/{}", record.id);
            let (group, created_group) = if self.cgroup_root.join(&cgroup_name).exists() {
                (self.cgroup_root.join(&cgroup_name), false)
            } else {
                let group = match manager.create_group(&cgroup_name) {
                    Ok(group) => group,
                    Err(error) => {
                        let _ = kill_pid(child_id);
                        return Err(RuntimeError::Cgroup(error));
                    }
                };
                (group, true)
            };
            if let Err(error) = manager.apply_limits(&group, &limits) {
                let _ = kill_pid(child_id);
                if created_group {
                    let _ = fs::remove_dir(&group);
                }
                return Err(RuntimeError::Cgroup(error));
            };
            if let Err(error) = manager.add_pid(&group, child_id) {
                let _ = kill_pid(child_id);
                if created_group {
                    let _ = fs::remove_dir(&group);
                }
                return Err(RuntimeError::Cgroup(error));
            }
        }

        if security_ebpf_monitor_enabled() {
            setup_security_ebpf_monitor(&record.id)?;
        }

        record.pid = child_id;
        record.status = "running".to_string();
        let persist_result = if let Some(reservation) = record.pending_mutation.as_ref() {
            self.store
                .put_for_mutation(&record, reservation.operation_id)
        } else {
            self.store.put(&record)
        };
        if let Err(error) = persist_result {
            let _ = kill_pid(child_id);
            return Err(error.into());
        }
        self.phase_hook.reached(
            if stop_existing { "restart" } else { "start" },
            LifecyclePhasePoint::LaunchIdentityDurable,
        )?;
        release_prepared_child(child_id)?;
        let _ = log_event(
            &self.runtime_dir,
            make_event(
                if stop_existing { "restart" } else { "start" },
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

        // Task 5.1: Start resource monitor for OOM prediction if AI is enabled.
        // Read memory limit from cgroup for restarted containers.
        let memory_limit = if is_ai_enabled() {
            let cgroup_path = self.cgroup_root.join("ferrocrate").join(&record.id);
            ferro_mind::ai::resource::read_cgroup_metrics(&cgroup_path)
                .ok()
                .and_then(|m| {
                    if m.memory_max > 0 {
                        Some(m.memory_max)
                    } else {
                        None
                    }
                })
                .unwrap_or(0)
        } else {
            0
        };
        if should_start_ai_monitor(memory_limit) {
            let store = self.store.clone_db();
            let id = record.id.clone();
            let cgroup_root = self.cgroup_root.clone();
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

    /// Apply a Docker-compatible tar archive beneath an existing container
    /// directory. The mutation is mediated as its own action so the durable
    /// witness records the filesystem write independently of lifecycle start,
    /// exec, or deletion operations.
    pub fn put_archive(&self, id: &str, target: &str, archive: &[u8]) -> Result<(), RuntimeError> {
        if archive.is_empty() {
            return Err(RuntimeError::InvalidCommand(
                "container archive must not be empty".to_string(),
            ));
        }
        if archive.len() > 64 * 1024 * 1024 {
            return Err(RuntimeError::InvalidCommand(
                "container archive exceeds the 64 MiB limit".to_string(),
            ));
        }
        let target = target.to_owned();
        self.mediate_existing(
            Action::ContainerArchiveWrite,
            id,
            move |runtime, _proof, _intent| {
                let record = runtime
                    .store
                    .get(id)?
                    .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_string()))?;
                let rootfs = runtime
                    .runtime_dir
                    .join("containers")
                    .join(id)
                    .join("rootfs")
                    .canonicalize()
                    .map_err(|error| {
                        RuntimeError::InvalidState(format!(
                            "container rootfs is unavailable: {error}"
                        ))
                    })?;
                if !rootfs.is_dir() {
                    return Err(RuntimeError::InvalidState(
                        "container rootfs is unavailable".to_string(),
                    ));
                }
                let relative = validate_archive_target(&target)?;
                let selected = rootfs.join(&relative);
                let selected = selected.canonicalize().map_err(|error| {
                    RuntimeError::InvalidCommand(format!("archive target unavailable: {error}"))
                })?;
                if !selected.starts_with(&rootfs) || !selected.is_dir() {
                    return Err(RuntimeError::InvalidCommand(
                        "archive target must be an existing directory beneath the container rootfs"
                            .to_string(),
                    ));
                }
                if record.mounts.iter().any(|mount| {
                    relative == Path::new(mount.target.trim_start_matches('/'))
                        || relative.starts_with(mount.target.trim_start_matches('/'))
                }) || record.tmpfs_mounts.iter().any(|mount| {
                    relative == Path::new(mount.target.trim_start_matches('/'))
                        || relative.starts_with(mount.target.trim_start_matches('/'))
                }) {
                    return Err(RuntimeError::InvalidCommand(
                        "archive target is a persisted mount target".to_string(),
                    ));
                }
                let mut temp = tempfile::NamedTempFile::new_in(&runtime.runtime_dir)?;
                temp.write_all(&archive)?;
                temp.as_file_mut().sync_all()?;
                apply_layer_tar(&selected, temp.path())?;
                Ok(())
            },
        )
    }

    fn remove_authorized(
        &self,
        _proof: &AuthorizedRequest,
        intent: Option<&crate::witness::DurableIntent>,
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
            self.update_reserved_status(id, "quarantined", intent)?;
            return Err(RuntimeError::InvalidState(format!(
                "container {id} has unverifiable creation provenance and was quarantined"
            )));
        }
        if record.status == "running" {
            return Err(RuntimeError::InvalidState(format!(
                "container {id} is still running"
            )));
        }
        cleanup_security_ebpf_monitor(&record.id)?;
        cleanup_apparmor_profile(&self.runtime_dir, &record.id)?;
        let records = self.store.list()?;
        cleanup_network(Some((_proof, intent)), &record, &records)?;
        let container_dir = self.runtime_dir.join("containers").join(id);
        if let Err(error) = detach_persisted_mounts(&self.kernel_ops, &container_dir, &record) {
            // Keep the durable record available for a later retry. Removing a
            // directory while one of its mountpoints is still attached leaks
            // the mount and leaves the container permanently stuck.
            let _ = self.update_reserved_status(id, "removed-pending", intent);
            return Err(error);
        }
        if let Err(e) = fs::remove_dir_all(&container_dir) {
            log::warn!("[cleanup] failed to remove container dir for {id}: {e}");
        }
        self.update_reserved_status(id, "removed-pending", intent)?;
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

    fn update_reserved_status(
        &self,
        id: &str,
        status: &str,
        _intent: Option<&crate::witness::DurableIntent>,
    ) -> Result<(), RuntimeError> {
        for attempt in 0..64 {
            let record = self
                .store
                .get(id)?
                .ok_or_else(|| RuntimeError::ContainerNotFound(id.to_owned()))?;
            let Some(operation_id) = record
                .pending_mutation
                .as_ref()
                .map(|reservation| reservation.operation_id)
            else {
                // A recovery process may have already cleared this
                // terminal reservation while the original `run --rm`
                // caller was finishing cleanup. Do not turn that durable
                // terminal state into a spurious compare-and-swap failure.
                if record.status == status
                    || record.status == "removed"
                    || !matches!(record.status.as_str(), "running" | "paused")
                {
                    return Ok(());
                }
                return Err(ContainerStoreError::MutationConflict.into());
            };
            match self.store.set_status_for_mutation(id, operation_id, status) {
                Ok(()) => return Ok(()),
                Err(ContainerStoreError::MutationConflict) if attempt < 63 => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(ContainerStoreError::MutationConflict.into())
    }

    fn authorize_existing(
        &self,
        action: Action,
        id: &str,
    ) -> Result<crate::authorization::runtime::MutationPermit, RuntimeError> {
        // A short-lived supervisor can publish an exit status between the
        // authorization read and the reservation transaction. Treat that as
        // a retryable compare-and-swap race: re-authorize against the fresh
        // record rather than surfacing a spurious failure to callers such as
        // `run --rm`. The bounded loop preserves fail-closed behavior for a
        // genuinely contended or malformed store.
        // A short-lived `run --rm` process can finish its kernel work while
        // another process is still publishing the creation effect. Under
        // sustained parallel load that handoff can exceed the old 160 ms
        // window; retain a bounded fail-closed retry budget large enough for
        // scheduler and SQLite contention without waiting indefinitely.
        const MAX_RESERVATION_RETRIES: usize = 256;
        for attempt in 0..MAX_RESERVATION_RETRIES {
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
            match self.store.reserve_mutation(
                id,
                &current.status,
                current.mutation_generation.max(1),
                permit.operation_id(),
                runtime_action_name(action),
            ) {
                Ok(()) => {
                    self.phase_hook.reached(
                        runtime_action_name(action),
                        LifecyclePhasePoint::ReservationDurable,
                    )?;
                    return Ok(permit);
                }
                Err(ContainerStoreError::MutationConflict)
                    if attempt + 1 < MAX_RESERVATION_RETRIES =>
                {
                    if attempt == 0 || attempt + 1 == MAX_RESERVATION_RETRIES - 1 {
                        log::warn!(
                            "container mutation reservation contention: action={} container_id={} attempt={}",
                            runtime_action_name(action),
                            id,
                            attempt + 1
                        );
                    }
                    self.authorization.complete(permit, false)?;
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    self.authorization.complete(permit, false)?;
                    return Err(error.into());
                }
            }
        }
        Err(RuntimeError::InvalidState(
            "container mutation reservation remained contended after bounded retries".to_string(),
        ))
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
        #[cfg(unix)]
        let _lifecycle_lock = {
            let lock_path = lifecycle_lock_path(&self.runtime_dir, id);
            if let Some(parent) = lock_path.parent() {
                fs::create_dir_all(parent)?;
            }
            LifecycleLock::acquire(&lock_path)?
        };
        let permit = self.authorize_existing(action, id)?;
        let operation_id = permit.operation_id();
        let (proof, intent) = permit.execution_authority();
        let result = execute(self, proof, intent);
        let post_effect_unknown = matches!(result, Err(RuntimeError::PostEffectPersistence(_)));
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
        if let Err(error) = self.store.mark_mutation_effect_observed(
            id,
            operation_id,
            result.is_ok() || post_effect_unknown,
            freezer_state,
        ) {
            log::error!(
                "{} failed while recording effect: container_id={} operation_id={:?} error={}",
                runtime_action_name(action),
                id,
                operation_id,
                error
            );
            return Err(error.into());
        }
        self.phase_hook.reached(
            runtime_action_name(action),
            LifecyclePhasePoint::EffectObserved,
        )?;
        if post_effect_unknown {
            self.authorization.complete_unknown(permit)?;
            self.phase_hook.reached(
                runtime_action_name(action),
                LifecyclePhasePoint::TerminalDurable,
            )?;
            return result;
        } else if action == Action::ContainerDelete && result.is_ok() {
            let mut finalized = false;
            for attempt in 0..64 {
                match self.store.delete_for_mutation(id, operation_id) {
                    Ok(()) => {
                        finalized = true;
                        break;
                    }
                    Err(ContainerStoreError::MutationConflict) if attempt < 63 => {
                        if self.store.get(id)?.is_none() {
                            finalized = true;
                            break;
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(ContainerStoreError::MutationConflict)
                        if self.store.lifecycle_operation(operation_id)?.is_none()
                            && self.store.get(id)?.is_some_and(|record| {
                                !matches!(record.status.as_str(), "running" | "paused")
                            }) =>
                    {
                        // Recovery may have acknowledged the operation after
                        // the effect was observed. The record is terminal and
                        // no operation remains, so removing it is the
                        // idempotent completion of the same delete.
                        self.store.remove(id)?;
                        finalized = true;
                        break;
                    }
                    Err(error) => {
                        log::error!(
                            "{} failed while deleting record: container_id={} operation_id={:?} error={}",
                            runtime_action_name(action),
                            id,
                            operation_id,
                            error
                        );
                        return Err(error.into());
                    }
                }
            }
            if !finalized {
                return Err(ContainerStoreError::MutationConflict.into());
            }
            self.authorization.complete(permit, true)?;
            self.phase_hook.reached(
                runtime_action_name(action),
                LifecyclePhasePoint::TerminalDurable,
            )?;
            if let Err(error) = self.store.acknowledge_mutation(operation_id) {
                log::error!(
                    "{} failed while acknowledging operation: container_id={} operation_id={:?} error={}",
                    runtime_action_name(action),
                    id,
                    operation_id,
                    error
                );
                return Err(error.into());
            }
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
            if let Err(error) = self.store.finish_mutation(id, operation_id) {
                log::error!(
                    "{} failed while clearing reservation: container_id={} operation_id={:?} error={}",
                    runtime_action_name(action),
                    id,
                    operation_id,
                    error
                );
                return Err(error.into());
            }
            self.phase_hook.reached(
                runtime_action_name(action),
                LifecyclePhasePoint::ReservationCleared,
            )?;
        }
        result
    }
}

fn validate_rootless_mount_capability(
    rootless: bool,
    mounts: &[BindMount],
    tmpfs_mounts: &[TmpfsMount],
    readonly_rootfs: bool,
) -> Result<(), RuntimeError> {
    if rootless
        && (!mounts.is_empty() || !tmpfs_mounts.is_empty() || readonly_rootfs)
        && (!command_available("bwrap") || !rootless_mount_namespace_available())
    {
        return Err(RuntimeError::InvalidCommand(
            "rootless workload mounts and read-only rootfs require bubblewrap plus a mount-capable user namespace; this host path cannot apply them safely".to_string(),
        ));
    }
    Ok(())
}

fn validate_archive_target(target: &str) -> Result<PathBuf, RuntimeError> {
    let relative = target
        .strip_prefix('/')
        .ok_or_else(|| RuntimeError::InvalidCommand("archive path must be absolute".to_string()))?;
    if !relative.is_empty()
        && relative
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(RuntimeError::InvalidCommand(
            "archive path must be normalized and absolute".to_string(),
        ));
    }
    Ok(PathBuf::from(relative))
}

fn rootless_mount_namespace_available() -> bool {
    let Some(unshare) = crate::rootless::trusted_executable_path("unshare") else {
        return false;
    };
    std::process::Command::new(unshare)
        .args([
            "--user",
            "--mount",
            "--fork",
            "--propagation",
            "unchanged",
            "true",
        ])
        .status()
        .is_ok_and(|status| status.success())
}

/// Resolve the cgroup-v2 directory where this runtime may create child
/// controllers. Rootful daemons use the hierarchy mount; an unprivileged
/// daemon must stay inside its delegated cgroup (typically a systemd user
/// scope), otherwise resource-limited rootless runs fail with `EPERM` even
/// when the host has delegated controllers available.
fn configured_cgroup_root() -> PathBuf {
    if let Ok(root) = std::env::var("FERROCRATE_CGROUP_ROOT") {
        return PathBuf::from(root);
    }

    let hierarchy = PathBuf::from("/sys/fs/cgroup");
    if nix::unistd::Uid::effective().is_root() {
        return hierarchy;
    }

    let relative = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|contents| current_cgroup_relative_path(&contents));
    if let Some(path) = relative
        .as_deref()
        .and_then(|path| select_delegated_cgroup_root(&hierarchy, path))
    {
        return path;
    }
    relative
        .map(|path| hierarchy.join(path.trim_start_matches('/')))
        .unwrap_or(hierarchy)
}

/// Select the deepest ancestor of the current cgroup that has controllers
/// enabled for children. A transient systemd scope is often a populated leaf
/// with an empty `cgroup.subtree_control`; creating `ferrocrate/<id>` there
/// would fail with EPERM even though its user service/app slice delegated the
/// controllers. The walk never escapes the current hierarchy or falls back to
/// an unrelated user's cgroup.
fn select_delegated_cgroup_root(hierarchy: &Path, relative: &str) -> Option<PathBuf> {
    let relative = relative.trim_start_matches('/');
    if relative.is_empty() || relative.contains("..") {
        return None;
    }
    let mut candidate = hierarchy.join(relative);
    if !candidate.starts_with(hierarchy) {
        return None;
    }
    loop {
        if delegated_subtree_controls(&candidate) {
            return Some(candidate);
        }
        if candidate == hierarchy || !candidate.pop() {
            break;
        }
    }
    None
}

fn delegated_subtree_controls(path: &Path) -> bool {
    if std::fs::OpenOptions::new()
        .write(true)
        .open(path.join("cgroup.subtree_control"))
        .is_err()
    {
        return false;
    }
    let Ok(controls) = std::fs::read_to_string(path.join("cgroup.subtree_control")) else {
        return false;
    };
    controls
        .split_whitespace()
        .any(|control| matches!(control.trim_start_matches('+'), "cpu" | "memory" | "pids"))
}

fn current_cgroup_relative_path(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let _controllers = fields.next()?;
        let path = fields.next()?;
        (!path.is_empty() && path.starts_with('/') && !path.contains(".."))
            .then_some(path.to_string())
    })
}

fn validate_container_name(name: &str) -> Result<(), RuntimeError> {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." {
        return Err(RuntimeError::InvalidCommand(
            "container name must be 1-255 characters".to_string(),
        ));
    }
    let mut bytes = name.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(RuntimeError::InvalidCommand(
            "container name contains unsupported characters".to_string(),
        ));
    }
    Ok(())
}

fn production_authorization(
    runtime_dir: &Path,
    runtime_id: [u8; 16],
) -> Result<RuntimeAuthorization, RuntimeError> {
    let root = runtime_dir.join("authorization");
    let policy_path = root.join("active-policy.toml");
    if !policy_path.exists() {
        return Ok(RuntimeAuthorization::compatibility_with_id(runtime_id));
    }
    let policies = Arc::new(
        crate::authorization::policy::PolicyStore::load(&policy_path)
            .map_err(|error| RuntimeError::Authorization(error.to_string()))?,
    );
    let enabled =
        policies.snapshot().document.mode != crate::authorization::AuthorizationMode::Disabled;
    let mut admission = None;
    let journal = if !enabled {
        None
    } else {
        let id_path = root.join("journal-id");
        let text = fs::read_to_string(&id_path).map_err(|error| {
            RuntimeError::Authorization(format!(
                "enabled authorization requires protected {}: {error}",
                id_path.display()
            ))
        })?;
        let value = text.trim();
        if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(RuntimeError::Authorization(
                "authorization journal ID must be 32 hexadecimal characters".into(),
            ));
        }
        let mut id = [0_u8; 16];
        for (index, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
                RuntimeError::Authorization("authorization journal ID is invalid".into())
            })?;
        }
        admission = Some(load_mutation_admission(&root, id)?);
        Some(Arc::new(
            crate::witness::WitnessJournal::open(crate::witness::JournalConfig::new(
                root.join("witness-journal"),
                id,
                crate::witness::JournalMode::Required,
            ))
            .map_err(|error| RuntimeError::Authorization(error.to_string()))?,
        ))
    };
    let gate = Arc::new(match admission {
        Some(admission) => AuthorizationGate::with_admission(policies, admission),
        None => AuthorizationGate::new(policies),
    });
    Ok(RuntimeAuthorization::new_with_id(gate, journal, runtime_id))
}

fn load_mutation_admission(
    root: &Path,
    journal_id: [u8; 16],
) -> Result<crate::authorization::admission::MutationAdmission, RuntimeError> {
    use sha2::Digest;
    let directory =
        crate::authorization::SecureDirectory::open(&root.join("admission")).map_err(|error| {
            RuntimeError::Authorization(format!("admission directory unavailable: {error}"))
        })?;
    let manifest_bytes = directory
        .read_bounded("manifest.json", 1024 * 1024)
        .map_err(|error| {
            RuntimeError::Authorization(format!("admission manifest unavailable: {error}"))
        })?;
    let manifest: crate::authorization::admission::AdmissionSnapshotManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            RuntimeError::Authorization(format!("invalid admission manifest: {error}"))
        })?;
    if manifest.schema != 1 || manifest.generation == 0 {
        return Err(RuntimeError::Authorization(
            "unsupported admission manifest".into(),
        ));
    }
    let expected_id = journal_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if manifest.journal_id != expected_id || manifest.checkpoint_chain.is_empty() {
        return Err(RuntimeError::Authorization(
            "admission manifest journal/chain mismatch".into(),
        ));
    }
    let read_artifact = |artifact: &crate::authorization::admission::AdmissionArtifact, maximum| {
        let bytes = directory
            .read_bounded(&artifact.file, maximum)
            .map_err(|error| {
                RuntimeError::Authorization(format!("admission artifact unavailable: {error}"))
            })?;
        let digest = sha2::Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if digest != artifact.sha256 {
            return Err(RuntimeError::Authorization(
                "admission artifact digest mismatch".into(),
            ));
        }
        Ok(bytes)
    };
    let trust_bytes = read_artifact(&manifest.trust_bundle, 1024 * 1024)?;
    let trust_value: serde_json::Value = serde_json::from_slice(&trust_bytes)
        .map_err(|error| RuntimeError::Authorization(format!("invalid trust bundle: {error}")))?;
    let pinned_id = trust_value
        .get("journal_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| RuntimeError::Authorization("trust bundle lacks journal_id".into()))?;
    if pinned_id != expected_id {
        return Err(RuntimeError::Authorization(
            "trust bundle journal ID mismatch".into(),
        ));
    }
    let public = trust_value
        .get("initial_public_key")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            RuntimeError::Authorization("trust bundle lacks initial_public_key".into())
        })?;
    let public = decode_fixed_hex::<32>(public)?;
    let initial_key_id = sha2::Sha256::digest(public)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if !manifest
        .trust_key_ids
        .iter()
        .any(|key_id| key_id == &initial_key_id)
    {
        return Err(RuntimeError::Authorization(
            "admission manifest omits the initial trust key ID".into(),
        ));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&public)
        .map_err(|_| RuntimeError::Authorization("trust bundle public key is invalid".into()))?;
    let minimum = crate::witness::Checkpoint::decode(&read_artifact(
        &manifest.minimum_checkpoint,
        16 * 1024 * 1024,
    )?)
    .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
    let mut checkpoints = Vec::with_capacity(manifest.checkpoint_chain.len());
    for artifact in &manifest.checkpoint_chain {
        checkpoints.push(
            crate::witness::Checkpoint::decode(&read_artifact(artifact, 16 * 1024 * 1024)?)
                .map_err(|error| RuntimeError::Authorization(error.to_string()))?,
        );
    }
    let latest = checkpoints
        .last()
        .ok_or_else(|| RuntimeError::Authorization("checkpoint chain is empty".into()))?;
    if manifest
        .checkpoint_chain
        .last()
        .map(|entry| entry.file.as_str())
        != Some(manifest.latest_checkpoint.as_str())
        || latest.created_at_secs != manifest.latest_created_at_secs
    {
        return Err(RuntimeError::Authorization(
            "admission manifest latest checkpoint binding mismatch".into(),
        ));
    }
    let confirmation = directory
        .read_bounded("manifest.json", 1024 * 1024)
        .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
    let confirmed: crate::authorization::admission::AdmissionSnapshotManifest =
        serde_json::from_slice(&confirmation)
            .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
    if confirmed.generation != manifest.generation || confirmation != manifest_bytes {
        return Err(RuntimeError::Authorization(
            "admission manifest changed during load".into(),
        ));
    }
    Ok(
        crate::authorization::admission::MutationAdmission::verified(
            root.join("witness-journal"),
            journal_id,
            crate::witness::TrustBundle::new(journal_id, key),
            minimum,
            checkpoints,
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(60),
        ),
    )
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], RuntimeError> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RuntimeError::Authorization(
            "invalid hexadecimal trust value".into(),
        ));
    }
    let mut out = [0; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| RuntimeError::Authorization("invalid hexadecimal trust value".into()))?;
    }
    Ok(out)
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
    authorization_mode: crate::authorization::AuthorizationMode,
) -> Result<NormalizedRunRequest, RuntimeError> {
    let rootless = !nix::unistd::Uid::effective().is_root();
    let mut handles = Vec::with_capacity(mounts.len());
    let mut normalized_mounts = Vec::with_capacity(mounts.len());
    let mut mount_facts = Vec::with_capacity(mounts.len() + tmpfs_mounts.len());
    let mut mount_sources_approved = None;
    for mount in mounts {
        if mount.source.starts_with("/proc/self/fd") {
            return Err(RuntimeError::InvalidState(
                "caller-supplied runtime fd mount is forbidden".into(),
            ));
        }
        let handle = if authorization_mode != crate::authorization::AuthorizationMode::Disabled {
            let configured = std::env::var_os("FERROCRATE_APPROVED_MOUNT_ROOTS");
            let mut opened = None;
            if let Some(configured) = configured {
                for root in std::env::split_paths(&configured) {
                    let root = root.canonicalize()?;
                    if let Ok(relative) = mount.source.strip_prefix(&root) {
                        if let Ok(handle) = open_mount_source_beneath(&root, relative) {
                            opened = Some(handle);
                            break;
                        }
                    }
                }
            }
            mount_sources_approved = Some(opened.is_some());
            if let Some(handle) = opened {
                handle
            } else {
                let source = mount.source.canonicalize()?;
                let mut options = OpenOptions::new();
                options.read(true);
                options.custom_flags(nix::libc::O_PATH | nix::libc::O_CLOEXEC);
                options.open(&source)?
            }
        } else {
            let source = mount.source.canonicalize()?;
            let mut options = OpenOptions::new();
            options.read(true);
            options.custom_flags(nix::libc::O_PATH | nix::libc::O_CLOEXEC);
            options.open(&source)?
        };
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
        // Rootful authorized mounts use an O_PATH fd so the kernel executor
        // binds the exact object that was admitted. Rootless bubblewrap runs
        // in a separate process and cannot access CLOEXEC authorization fds;
        // retain the canonical source path instead, still bound to the same
        // metadata captured above before execution.
        let source = if rootless {
            mount.source.canonicalize()?
        } else {
            PathBuf::from(format!("/proc/self/fd/{fd}"))
        };
        normalized_mounts.push(BindMount {
            source,
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
            mount_sources_approved,
            execution_digest: None,
            parent_resource_id: None,
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
        "container.run" => operation.is_some_and(|operation| {
            operation.phase == LifecyclePhase::EffectApplied
                && operation.effect_succeeded == Some(true)
                && record.creation_provenance.is_verifiable()
                && record.status == "running"
                && process_exists(record.pid)
                && operation.pid_after == Some(record.pid)
                && operation.process_start_time_after == process_start_time_for_pid(record.pid)
                && operation.execution_generation_after == Some(operation.generation)
        }),
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
        Action::ContainerStart => "container.start",
        Action::ContainerDelete => "container.delete",
        Action::ContainerRename => "container.rename",
        Action::ContainerArchiveWrite => "container.archive-write",
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
        crate::witness::WitnessAction::ContainerStart => "container.start",
        crate::witness::WitnessAction::ContainerDelete => "container.delete",
        crate::witness::WitnessAction::ContainerRename => "container.rename",
        crate::witness::WitnessAction::ContainerArchiveWrite => "container.archive-write",
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

/// Reattach persisted mounts when a restarted container's rootfs no longer
/// carries them. A stop normally leaves mounts in place; the mount-id check
/// makes replay idempotent across daemon/process restarts and avoids stacking
/// duplicate bind/tmpfs mounts over an already-owned target.
fn replay_persisted_mounts(rootfs: &Path, record: &ContainerRecord) -> Result<(), RuntimeError> {
    if record.mounts.is_empty() && record.tmpfs_mounts.is_empty() {
        return Ok(());
    }
    let Some(root_mount_id) = mount_id_for_path(rootfs)? else {
        // User-space test roots and unsupported mount namespaces cannot prove
        // absence safely; retain the existing mount state and fail closed.
        return Ok(());
    };
    let mut bind_mounts = Vec::new();
    for mount in &record.mounts {
        let target = PathBuf::from(&mount.target);
        if mount_id_for_path(&rootfs.join(&target))? != Some(root_mount_id) {
            continue;
        }
        bind_mounts.push(BindMount {
            source: PathBuf::from(&mount.source),
            target,
            read_only: mount.read_only,
        });
    }
    if !bind_mounts.is_empty() {
        apply_authorized_bind_mounts(rootfs, &bind_mounts)?;
    }
    let mut tmpfs_mounts = Vec::new();
    for mount in &record.tmpfs_mounts {
        let target = PathBuf::from(&mount.target);
        if mount_id_for_path(&rootfs.join(&target))? != Some(root_mount_id) {
            continue;
        }
        tmpfs_mounts.push(TmpfsMount {
            target,
            size: mount.size.clone(),
        });
    }
    if !tmpfs_mounts.is_empty() {
        apply_tmpfs_mounts(rootfs, &tmpfs_mounts)?;
    }
    Ok(())
}

/// Detach the mounts recorded for a container before removing its directory.
///
/// Mounts outlive their directory tree, so `remove_dir_all` alone cannot clean
/// up a stopped container with a bind or tmpfs mount.  Every target is checked
/// against the container root mount and its recorded source/type before the
/// identity-checked kernel detach is attempted.
fn detach_persisted_mounts(
    kernel_ops: &Arc<dyn KernelResourceOps>,
    container_dir: &Path,
    record: &ContainerRecord,
) -> Result<(), RuntimeError> {
    let rootfs = container_dir.join("rootfs");
    if !rootfs.exists() {
        return Ok(());
    }
    // A plain rootfs directory usually inherits its parent mount and therefore
    // has no exact mountinfo entry. In that case `root_mount_id` is `None`, and
    // any explicitly recorded target with a concrete mount ID is still safe to
    // consider; the target list is the durable ownership boundary.
    let root_mount_id = mount_id_for_path(&rootfs)?;

    let mut targets = record
        .mounts
        .iter()
        .map(|mount| {
            (
                PathBuf::from(&mount.target),
                Some(mount.source.as_str()),
                false,
            )
        })
        .chain(
            record
                .tmpfs_mounts
                .iter()
                .map(|mount| (PathBuf::from(&mount.target), None, true)),
        )
        .collect::<Vec<_>>();
    // Detach nested mounts first and avoid attempting the same target twice.
    targets.sort_by(|left, right| {
        right
            .0
            .components()
            .count()
            .cmp(&left.0.components().count())
            .then_with(|| right.0.cmp(&left.0))
    });
    targets.dedup_by(|left, right| left.0 == right.0);

    for (target, source, is_tmpfs) in targets {
        let target = normalize_mount_target(&target)?;
        let absolute = rootfs.join(&target);
        let Some(mount_id) = mount_id_for_path(&absolute)? else {
            continue;
        };
        if Some(mount_id) == root_mount_id {
            continue;
        }
        let metadata = fs::metadata(&absolute)?;
        if is_tmpfs {
            let kind = mountinfo_for_path(&absolute)?
                .map(|(_, kind, _)| kind)
                .ok_or_else(|| {
                    RuntimeError::InvalidState("persisted tmpfs mount disappeared".into())
                })?;
            if kind != "tmpfs" {
                return Err(RuntimeError::InvalidState(format!(
                    "refusing to detach non-tmpfs mount at {}",
                    target.display()
                )));
            }
        } else if let Some(source) = source {
            let source_metadata = fs::metadata(source)?;
            if metadata.dev() != source_metadata.dev() || metadata.ino() != source_metadata.ino() {
                return Err(RuntimeError::InvalidState(format!(
                    "persisted bind mount identity changed at {}",
                    target.display()
                )));
            }
        }
        let expected = kernel_ops.identity(&absolute)?;
        kernel_ops.detach_owned(&rootfs, &target, &expected)?;
    }

    if record.readonly_rootfs {
        let parent_mount_id = mount_id_for_path(container_dir)?;
        if root_mount_id.is_some() && parent_mount_id.is_some() && parent_mount_id != root_mount_id
        {
            let expected = kernel_ops.identity(&rootfs)?;
            kernel_ops.detach_owned(&rootfs, Path::new("."), &expected)?;
        }
    }
    Ok(())
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
    store: SqliteContainerStore,
    container_id: String,
    rootfs_dir: Option<PathBuf>,
    no_new_privs: bool,
    restart_policy: RestartPolicy,
    ai_enabled: bool,
    capabilities: Vec<caps::Capability>,
    workdir: Option<&str>,
    user: Option<&str>,
    netns_name: Option<&str>,
    unshare_netns: bool,
    seccomp_profile: Option<&SeccompProfile>,
    mounts: Vec<BindMount>,
    tmpfs_mounts: Vec<TmpfsMount>,
    readonly_rootfs: bool,
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
        &mounts,
        &tmpfs_mounts,
        readonly_rootfs,
    )?;
    let (child_id, child, pidfd) =
        spawn_child_with_logs(command, stdout_path, stderr_path, append)?;

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
            pidfd,
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
            ai_enabled,
            caps_for_restart,
            workdir,
            user,
            netns_name,
            seccomp_for_restart,
            mounts,
            tmpfs_mounts,
            readonly_rootfs,
        );
    });

    Ok(child_id)
}

#[allow(clippy::too_many_arguments)]
fn build_bwrap_command(
    rootfs: &Path,
    cmd: &[String],
    mounts: &[BindMount],
    tmpfs_mounts: &[TmpfsMount],
    readonly_rootfs: bool,
) -> Result<Command, RuntimeError> {
    if !command_available("bwrap") {
        return Err(RuntimeError::InvalidCommand(
            "rootfs execution requires bubblewrap (bwrap) for rootless mounts".to_string(),
        ));
    }
    let bwrap_path = crate::rootless::trusted_executable_path("bwrap").ok_or_else(|| {
        RuntimeError::InvalidCommand(
            "rootfs execution requires a trusted root-owned bubblewrap executable".to_string(),
        )
    })?;
    let mut bwrap = Command::new(bwrap_path);
    let root_cmd = resolve_rootfs_command(rootfs, &cmd[0]);
    bwrap
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
    bwrap.arg("--cap-drop").arg("ALL");
    for mount in mounts {
        bwrap.arg(if mount.read_only {
            "--ro-bind"
        } else {
            "--bind"
        });
        bwrap
            .arg(&mount.source)
            .arg(format!("/{}", mount.target.display()));
    }
    for mount in tmpfs_mounts {
        if mount.size.is_some() {
            return Err(RuntimeError::InvalidCommand(
                "rootless tmpfs size limits require a mount-capable user namespace implementation"
                    .to_string(),
            ));
        }
        bwrap
            .arg("--tmpfs")
            .arg(format!("/{}", mount.target.display()));
    }
    if readonly_rootfs {
        bwrap.arg("--remount-ro").arg("/");
    }
    bwrap.arg(root_cmd).args(&cmd[1..]);
    Ok(bwrap)
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
    mounts: &[BindMount],
    tmpfs_mounts: &[TmpfsMount],
    readonly_rootfs: bool,
) -> Result<Command, RuntimeError> {
    let running_as_root = nix::unistd::Uid::effective().is_root();
    let direct_container_setup = running_as_root && netns_name.is_some();
    // Keep the launcher shell outside a rootful image. A shell-less OCI image
    // (for example, FROM scratch with a static binary) cannot execute the
    // launcher after chroot. Bubblewrap enters the image after the launcher
    // barrier without requiring a shell or dynamic loader in the image.
    let rootfs_chroot_launcher = running_as_root && rootfs_dir.is_some();

    let mut command = if rootfs_chroot_launcher {
        let launcher = std::env::current_exe().map_err(RuntimeError::Io)?;
        let mut helper = Command::new(launcher);
        helper
            .arg("__ferrocrate_rootfs_launch")
            .arg(rootfs_dir.expect("rootfs launcher requires rootfs"))
            .arg(workdir.unwrap_or(""))
            .arg(user.unwrap_or(""))
            .arg(if no_new_privs { "1" } else { "0" })
            .arg("--")
            .args(cmd);
        helper
    } else if direct_container_setup {
        let mut direct_cmd = Command::new(&cmd[0]);
        direct_cmd.args(&cmd[1..]);
        direct_cmd
    } else if let Some(netns) = netns_name {
        let ip_path = crate::rootless::trusted_executable_path("ip").ok_or_else(|| {
            RuntimeError::InvalidCommand(
                "network namespace execution requires a trusted root-owned ip executable"
                    .to_string(),
            )
        })?;
        let mut netns_cmd = Command::new(ip_path);
        netns_cmd.arg("netns").arg("exec").arg(netns);
        if let Some(rootfs) = rootfs_dir {
            if running_as_root {
                let chroot_path = crate::rootless::trusted_executable_path("chroot").ok_or_else(|| {
                    RuntimeError::InvalidCommand(
                        "network namespace execution requires a trusted root-owned chroot executable"
                            .to_string(),
                    )
                })?;
                netns_cmd
                    .arg(chroot_path)
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
        let unshare_path =
            crate::rootless::trusted_executable_path("unshare").ok_or_else(|| {
                RuntimeError::InvalidCommand(
                    "rootless network namespaces require a trusted root-owned unshare executable"
                        .to_string(),
                )
            })?;
        let mut unshare_cmd = Command::new(unshare_path);
        // Creating a network namespace alone is not permitted for an
        // unprivileged caller. Pair it with a user namespace. Avoid invoking
        // setuid mapping helpers after no_new_privs is installed; callers
        // needing subordinate-ID mappings use the authenticated mapping path.
        unshare_cmd.args(["--user", "--net", "--"]);
        // Keep the process stopped after `unshare` has created its network
        // namespace. The parent attaches slirp4netns at this point, then
        // releases the workload with a second SIGCONT. This avoids both the
        // pre-exec host-namespace race and short-lived workloads exiting
        // before networking is attached.
        let shell = crate::rootless::trusted_executable_path("sh").ok_or_else(|| {
            RuntimeError::InvalidCommand(
                "rootless network namespaces require a trusted root-owned shell executable"
                    .to_string(),
            )
        })?;
        let script = if no_new_privs {
            let setpriv = crate::rootless::trusted_executable_path("setpriv").ok_or_else(|| {
                RuntimeError::InvalidCommand(
                    "rootless no-new-privileges requires a trusted root-owned setpriv executable"
                        .to_string(),
                )
            })?;
            format!(
                "kill -STOP $$; exec {} --no-new-privs -- \"$@\"",
                setpriv.display()
            )
        } else {
            "kill -STOP $$; exec \"$@\"".to_string()
        };
        unshare_cmd
            .arg(shell)
            .args(["-c", script.as_str(), "ferrocrate-rootless"]);
        if let Some(rootfs) = rootfs_dir.filter(|_| !running_as_root) {
            let inner = build_bwrap_command(rootfs, cmd, mounts, tmpfs_mounts, readonly_rootfs)?;
            unshare_cmd.arg(inner.get_program());
            unshare_cmd.args(inner.get_args());
        } else {
            unshare_cmd.args(cmd);
        }
        unshare_cmd
    } else if let Some(rootfs) = rootfs_dir {
        if running_as_root {
            let chroot_path =
                crate::rootless::trusted_executable_path("chroot").ok_or_else(|| {
                    RuntimeError::InvalidCommand(
                        "rootfs execution requires a trusted root-owned chroot executable"
                            .to_string(),
                    )
                })?;
            let mut chroot_cmd = Command::new(chroot_path);
            chroot_cmd.arg(rootfs);
            chroot_cmd.arg(&cmd[0]);
            chroot_cmd.args(&cmd[1..]);
            chroot_cmd
        } else if command_available("bwrap") {
            build_bwrap_command(rootfs, cmd, mounts, tmpfs_mounts, readonly_rootfs)?
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

    // The launcher shell becomes the stable process identity first, stops
    // itself, and only execs the workload after the parent has durably recorded
    // ownership. For rootful rootfs images it execs bubblewrap, avoiding any
    // assumption that the image contains a shell.
    let workload_program = command.get_program().to_os_string();
    let workload_args = command
        .get_args()
        .map(OsStr::to_os_string)
        .collect::<Vec<_>>();
    let mut launch_command = Command::new("/bin/sh");
    launch_command
        .arg("-c")
        .arg("kill -STOP $$; exec \"$@\"")
        .arg("ferrocrate-launch")
        .arg(workload_program)
        .args(workload_args);
    command = launch_command;

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

    if let Some(dir) = workdir.filter(|_| !direct_container_setup && !rootfs_chroot_launcher) {
        command.current_dir(dir);
    }

    if let Some(user_spec) = user {
        if running_as_root && !direct_container_setup && !rootfs_chroot_launcher {
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
    let setup_user = if direct_container_setup {
        user.map(str::to_string)
    } else {
        None
    };
    let launch_parent_pid = unsafe { nix::libc::getpid() };
    let detached_cli = std::env::var("FERROCRATE_DETACH_WORKLOAD").as_deref() == Ok("1");
    unsafe {
        command.pre_exec(move || {
            if !detached_cli
                && nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::getppid() != launch_parent_pid {
                return Err(io::Error::other(
                    "launcher parent died before lease install",
                ));
            }
            if let Some(netns) = setup_netns.as_deref() {
                enter_runtime_netns(netns).map_err(|err| {
                    io::Error::new(err.kind(), format!("pre_exec enter netns {netns}: {err}"))
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
            if no_new_privs && !unshare_netns {
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
            if is_root && !rootfs_chroot_launcher {
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
            // Credential and capability transitions can clear a parent-death
            // signal. Reinstall it for supervised launches; detached CLI
            // launches rely on the stopped ownership barrier instead.
            if !detached_cli
                && nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if nix::libc::getppid() != launch_parent_pid {
                return Err(io::Error::other(
                    "launcher parent died during credential transition",
                ));
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

/// Execute a rootfs workload from the internal launcher handoff.
///
/// This path exists for shell-less OCI images. `Command::spawn` must return
/// before the ownership barrier can be observed, so the helper executable is
/// used as the post-spawn process that performs chroot after the existing
/// launcher-shell barrier is released and then execs the workload.
#[cfg(target_os = "linux")]
pub fn run_rootfs_launcher(args: &[String]) -> Result<(), String> {
    if args.len() < 6 || args[4] != "--" {
        return Err("invalid rootfs launcher arguments".to_string());
    }
    let rootfs = Path::new(&args[0]);
    let workdir = (!args[1].is_empty()).then_some(args[1].as_str());
    let user = (!args[2].is_empty()).then_some(args[2].as_str());
    let no_new_privs = args[3] == "1";
    let command = &args[5..];
    if command.is_empty() {
        return Err("rootfs launcher command is empty".to_string());
    }
    let rootfs_c = std::ffi::CString::new(rootfs.as_os_str().as_bytes())
        .map_err(|_| "rootfs path contains NUL".to_string())?;
    let rc = unsafe { nix::libc::chroot(rootfs_c.as_ptr()) };
    if rc != 0 {
        return Err(format!(
            "chroot {}: {}",
            rootfs.display(),
            io::Error::last_os_error()
        ));
    }
    std::env::set_current_dir(container_workdir_for_launcher(workdir))
        .map_err(|err| format!("set rootfs workdir: {err}"))?;
    if let Some(user_spec) = user {
        apply_runtime_identity(user_spec).map_err(|err| format!("set rootfs identity: {err}"))?;
    }
    if no_new_privs {
        set_no_new_privileges().map_err(|err| format!("set rootfs no_new_privs: {err}"))?;
    }
    drop_all_capabilities().map_err(|err| format!("drop rootfs capabilities: {err}"))?;
    let program = std::ffi::CString::new(command[0].as_str())
        .map_err(|_| "rootfs command contains NUL".to_string())?;
    let argv = command
        .iter()
        .map(|arg| std::ffi::CString::new(arg.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "rootfs command contains NUL".to_string())?;
    match nix::unistd::execv(&program, &argv) {
        Ok(never) => match never {},
        Err(err) => Err(format!("exec rootfs workload: {err}")),
    }
}

fn container_workdir_for_launcher(workdir: Option<&str>) -> String {
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
) -> Result<(u32, Child, OwnedFd), RuntimeError> {
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
    let stdin_path = stdin_fifo_path(stdout_path);
    ensure_stdin_fifo(&stdin_path)?;
    // Open the FIFO read/write in the launcher so child creation never blocks
    // waiting for an attach client. The descriptor is inherited as the
    // workload's stdin; attach opens the same owned FIFO for writes.
    let stdin_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&stdin_path)?;
    let child = command
        .stdin(Stdio::from(stdin_file))
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()?;
    let child_id = child.id();
    let raw_pidfd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, child_id, 0) } as i32;
    if raw_pidfd < 0 {
        return Err(RuntimeError::Io(io::Error::last_os_error()));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    wait_until_launch_stopped(child_id)?;
    Ok((child_id, child, pidfd))
}

fn stdin_fifo_path(stdout_path: &Path) -> PathBuf {
    stdout_path
        .parent()
        .and_then(Path::parent)
        .map(|container_dir| container_dir.join("stdin"))
        .unwrap_or_else(|| stdout_path.with_file_name("stdin"))
}

fn ensure_stdin_fifo(path: &Path) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_fifo() {
                return Err(RuntimeError::InvalidState(format!(
                    "container stdin path is not a FIFO: {}",
                    path.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits_truncate(0o600))
                .map_err(|error| RuntimeError::Io(io::Error::from_raw_os_error(error as i32)))?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn wait_until_launch_stopped(pid: u32) -> Result<(), RuntimeError> {
    for _ in 0..500 {
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        if status.lines().any(|line| line.starts_with("State:\tT")) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
    let _ = kill_pid(pid);
    Err(RuntimeError::InvalidState(format!(
        "launcher {pid} did not enter the ownership barrier"
    )))
}

fn release_prepared_child(pid: u32) -> Result<(), RuntimeError> {
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGCONT,
    )
    .map_err(|err| RuntimeError::InvalidState(format!("release launcher {pid}: {err}")))
}

#[allow(clippy::too_many_arguments)]
fn supervise_child(
    mut child: Child,
    mut _pidfd: OwnedFd,
    store: SqliteContainerStore,
    container_id: String,
    cmd: Vec<String>,
    env: Vec<String>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    append: bool,
    rootfs_dir: Option<PathBuf>,
    no_new_privs: bool,
    restart_policy: RestartPolicy,
    ai_enabled: bool,
    capabilities: Vec<caps::Capability>,
    workdir: Option<String>,
    user: Option<String>,
    netns_name: Option<String>,
    seccomp_profile: Option<SeccompProfile>,
    mounts: Vec<BindMount>,
    tmpfs_mounts: Vec<TmpfsMount>,
    readonly_rootfs: bool,
) {
    let mut adaptive_model_version = "runtime-v1".to_string();
    let mut adaptive_policy = ferro_mind::ai::restart::AdaptiveRestartPolicy::new(&container_id);
    let restart_snapshot = ai_enabled.then(|| ai_restart_snapshot_path(&container_id));
    if ai_enabled {
        let active_model = match ferro_mind::ai::training::TrainingPipeline::new(
            ferro_mind::ai::training::TrainingConfig::default(),
        ) {
            Ok(pipeline) => pipeline
                .resolve_active_model(ferro_mind::ai::training::ModelType::RestartPolicy)
                .map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        match active_model {
            Ok(active) => {
                match ferro_mind::ai::restart::AdaptiveRestartPolicy::from_model_artifact(
                    &active.path,
                    &container_id,
                ) {
                    Ok(model_policy) => {
                        adaptive_policy = model_policy;
                        adaptive_model_version = format!("active-v{}", active.version);
                        info!(
                            container = %container_id,
                            model_version = %adaptive_model_version,
                            artifact_sha256 = %active.artifact_sha256,
                            "resolved active restart policy"
                        );
                    }
                    Err(error) => {
                        warn!(container = %container_id, error = %error, "active restart model rejected; using runtime policy");
                    }
                }
            }
            Err(error) => {
                info!(container = %container_id, error = %error, "no active restart model; using runtime policy");
            }
        }
        if let Some(path) = restart_snapshot.as_ref() {
            if path.exists() {
                match ferro_mind::ai::restart::AdaptiveRestartPolicy::from_snapshot(
                    path,
                    &container_id,
                ) {
                    Ok(snapshot_policy) => {
                        adaptive_policy = snapshot_policy;
                        adaptive_model_version = "persisted-runtime-v1".to_string();
                        info!(container = %container_id, path = %path.display(), "restored adaptive restart policy snapshot");
                    }
                    Err(error) => {
                        warn!(container = %container_id, error = %error, "restart policy snapshot rejected; using active model or runtime policy");
                    }
                }
            }
        }
    }
    let mut restart_count: u32 = 0;
    let mut container_start_time = std::time::Instant::now();

    loop {
        let status = child.wait();
        let exit_code = status.ok().and_then(|s| s.code()).unwrap_or(-1);
        let current_status = match update_exit_after_mutation(&store, &container_id, exit_code) {
            Ok(status) => status,
            Err(_) => "exited".to_string(),
        };

        let uptime_secs = container_start_time.elapsed().as_secs();
        if ai_enabled {
            // Resolve the previous replacement only after observing its
            // uptime. Spawning alone is not a successful restart: a process
            // that crashes before the observation window must train failure.
            if restart_count > 0 {
                adaptive_policy.record_observation(uptime_secs);
            }
            adaptive_policy.record_restart(exit_code, uptime_secs);
            if let Some(path) = restart_snapshot.as_ref() {
                let _ = adaptive_policy.save_snapshot(path);
            }
        }

        if !should_restart(&restart_policy, &current_status, exit_code) {
            break;
        }

        // Get adaptive delay only when explicitly enabled for this container.
        // The ordinary restart policy remains the source of truth otherwise.
        let adaptive_decision = if ai_enabled {
            let adaptive_signal = ferro_mind::ai::restart::RestartSignal {
                exit_code,
                recent_failures: restart_count,
                uptime_secs,
            };
            let confidence = adaptive_policy.estimate_success_probability(&adaptive_signal);
            let decision = adaptive_policy.decide(&adaptive_signal);
            if let Some(logger) = ai_decision_logger() {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let trace = ferro_mind::ai::explain::DecisionTrace::new(
                    format!("ai-restart-{container_id}-{ts}"),
                    format!("Adaptive restart policy evaluated container {container_id}"),
                )
                .with_model("adaptive-restart-policy", &adaptive_model_version)
                .with_decision(format!("{decision:?}"))
                .with_evidence("container_id", container_id.clone())
                .with_evidence("exit_code", exit_code.to_string())
                .with_evidence("recent_failures", restart_count.to_string())
                .with_evidence("uptime_secs", uptime_secs.to_string())
                .with_evidence("confidence", format!("{confidence:.6}"));
                let _ = logger.log("ai_restart_decision", &trace);
            }
            Some(decision)
        } else {
            None
        };
        let Some(delay_secs) = adaptive_restart_delay(adaptive_decision) else {
            break;
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
            &mounts,
            &tmpfs_mounts,
            readonly_rootfs,
        ) {
            Ok(cmd) => cmd,
            Err(_) => {
                if ai_enabled {
                    log_ai_restart_lifecycle(
                        &container_id,
                        "ai_restart_failed",
                        exit_code,
                        restart_count,
                        delay_secs,
                        "build-command",
                        None,
                    );
                }
                break;
            }
        };
        let (pid, new_child, new_pidfd) =
            match spawn_child_with_logs(command, &stdout_path, &stderr_path, append) {
                Ok(tuple) => tuple,
                Err(_) => {
                    if ai_enabled {
                        log_ai_restart_lifecycle(
                            &container_id,
                            "ai_restart_failed",
                            exit_code,
                            restart_count,
                            delay_secs,
                            "spawn-child",
                            None,
                        );
                    }
                    break;
                }
            };
        if let Err(e) = update_pid_status(&store, &container_id, pid, "running") {
            warn!("failed to update pid status for {container_id}: {e}");
            if ai_enabled {
                log_ai_restart_lifecycle(
                    &container_id,
                    "ai_restart_failed",
                    exit_code,
                    restart_count,
                    delay_secs,
                    "update-pid",
                    Some(pid),
                );
            }
            let _ = kill_pid(pid);
            break;
        }
        if let Err(e) = release_prepared_child(pid) {
            warn!("failed to release supervised restart for {container_id}: {e}");
            if ai_enabled {
                log_ai_restart_lifecycle(
                    &container_id,
                    "ai_restart_failed",
                    exit_code,
                    restart_count,
                    delay_secs,
                    "release-child",
                    Some(pid),
                );
            }
            let _ = kill_pid(pid);
            break;
        }
        child = new_child;
        _pidfd = new_pidfd;
        container_start_time = std::time::Instant::now();
        if ai_enabled {
            log_ai_restart_lifecycle(
                &container_id,
                "ai_restart_applied",
                exit_code,
                restart_count,
                delay_secs,
                "released",
                Some(pid),
            );
        }
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
    namespace_owned: bool,
    namespace_identity: Option<KernelObjectIdentityRecord>,
    container_ip: Option<String>,
    container_ipv6: Option<String>,
    backend: Option<NetworkBackend>,
    ownership: Option<NetworkOwnershipRecord>,
    ebpf_network: Option<EbpfNetwork>,
    managed_overlay: Option<String>,
    managed_cleanup_provenance: Option<crate::managed_overlay::ManagedCleanupProvenance>,
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
        let namespace_owned = netns_name.is_some();
        Self {
            netns_name,
            namespace_owned,
            namespace_identity: None,
            container_ip,
            container_ipv6,
            backend: None,
            ownership: None,
            ebpf_network: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
            managed_host_veth: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn setup_network(
    proof: &AuthorizedRequest,
    intent: Option<&crate::witness::DurableIntent>,
    container_id: &str,
    port_mappings: &[crate::container_store::PortMappingRecord],
    network_mode: &str,
    network_backend: NetworkBackend,
    rollback: &mut CreationRollback,
    existing_records: &[ContainerRecord],
) -> Result<NetworkSetup, RuntimeError> {
    if let Some(overlay_id) = network_mode.strip_prefix("managed:") {
        return setup_managed_network(
            proof,
            intent,
            container_id,
            overlay_id,
            network_backend,
            rollback,
        );
    }
    if let Some(shared_netns) = network_mode.strip_prefix("container:") {
        if shared_netns.is_empty() {
            return Err(RuntimeError::Network(
                "shared network namespace name is empty".to_string(),
            ));
        }
        // Reuse the existing namespace without recording ownership. The
        // caller remains responsible for its lifecycle; container cleanup
        // must never delete a CRI pod sandbox namespace.
        netns::build_ip_netns_del_cmd(shared_netns)
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
        let path = netns::netns_path(shared_netns);
        if !path.exists() {
            return Err(RuntimeError::Network(format!(
                "shared network namespace {shared_netns} does not exist"
            )));
        }
        return Ok(NetworkSetup {
            netns_name: Some(shared_netns.to_string()),
            namespace_owned: false,
            namespace_identity: Some(kernel_path_identity(&path)?),
            container_ip: None,
            container_ipv6: None,
            backend: None,
            ownership: None,
            ebpf_network: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
            managed_host_veth: None,
        });
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
            let mut setup = NetworkSetup::isolated(Some(netns_name), None, None);
            setup.namespace_identity = Some(identity);
            return Ok(setup);
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
            let mut setup = NetworkSetup::isolated(Some(netns_name), ipv4, ipv6);
            setup.namespace_identity = Some(identity);
            return Ok(setup);
        }
        _ => {
            return Err(RuntimeError::Network(
                "network mode must be one of: bridge, host, none, wireguard".to_string(),
            ))
        }
    }

    let is_root = nix::unistd::Uid::effective().is_root();
    if !is_root {
        validate_rootless_bridge_network(rootless_netns_enabled(), port_mappings, network_backend)?;
        // The unshared child network namespace is connected by slirp4netns
        // after spawn. No privileged bridge, veth, firewall, or namespace
        // mutation may be attempted in the rootless path.
        return Ok(NetworkSetup::isolated(None, None, None));
    }

    ensure_bridge_backend_root(is_root, network_backend)?;
    validate_ebpf_published_port_boundary(network_backend, port_mappings)?;
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
    ensure_bridge_route_localnet(&bridge_config.name, rollback)?;
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
    let veth_mtu = configured_veth_mtu()?;
    let veth_config = veth::VethConfig {
        pair: veth::VethPair {
            host: host_veth.clone(),
            container: cont_veth.clone(),
        },
        mtu: veth_mtu,
        host_addr: None,
        container_addr: None,
    };
    run_cmd(&veth::build_ip_link_add_veth_cmd(&veth_config)?)?;
    if let Some(expected_mtu) = veth_mtu {
        verify_interface_mtu(&host_veth, expected_mtu)?;
    }
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
    // Published-port requests originating on the host loopback retain their
    // 127/8 source while eBPF redirects them onto the container veth. Linux's
    // default loose reverse-path filter rejects that valid hairpin packet
    // because the namespace routes 127/8 through `lo`, not `eth0`. Disable
    // reverse-path filtering inside this disposable namespace so the packet
    // reaches the workload; the namespace teardown restores the host state.
    for interface in ["all", "default", "eth0"] {
        let setting = format!("net.ipv4.conf.{interface}.rp_filter=0");
        run_cmd(&ip_netns_exec(&netns_name, &["sysctl", "-w", &setting]))?;
    }
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
        namespace_owned: true,
        namespace_identity: Some(namespace_identity),
        container_ip: Some(container_ip),
        container_ipv6,
        backend: Some(active_backend),
        ownership: Some(ownership),
        ebpf_network: None,
        managed_overlay: None,
        managed_cleanup_provenance: None,
        managed_host_veth: None,
    })
}

fn configured_veth_mtu() -> Result<Option<u32>, RuntimeError> {
    let Some(value) = std::env::var("FERROCRATE_VETH_MTU").ok() else {
        return Ok(None);
    };
    let mtu = value
        .trim()
        .parse::<u32>()
        .map_err(|_| RuntimeError::Network("FERROCRATE_VETH_MTU must be an integer".into()))?;
    if !(576..=65_535).contains(&mtu) {
        return Err(RuntimeError::Network(
            "FERROCRATE_VETH_MTU must be between 576 and 65535".into(),
        ));
    }
    Ok(Some(mtu))
}

fn verify_interface_mtu(interface: &str, expected: u32) -> Result<(), RuntimeError> {
    let output = run_cmd_capture(&[
        "ip".into(),
        "-j".into(),
        "link".into(),
        "show".into(),
        "dev".into(),
        interface.into(),
    ])?;
    let mtu = serde_json::from_str::<serde_json::Value>(&output)
        .ok()
        .and_then(|value| value.as_array().and_then(|rows| rows.first().cloned()))
        .and_then(|row| row.get("mtu").and_then(serde_json::Value::as_u64))
        .and_then(|value| u32::try_from(value).ok());
    if mtu != Some(expected) {
        return Err(RuntimeError::Network(format!(
            "interface {interface} MTU read-back mismatch: expected {expected}, got {mtu:?}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn setup_managed_network(
    proof: &AuthorizedRequest,
    intent: Option<&crate::witness::DurableIntent>,
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
    let client = ManagedOverlayClient::new(socket);
    let response = if let Some(intent) = intent {
        managed_overlay_authorized_request(&client, &request, proof, intent, None)?
    } else {
        let legacy_mode = LegacyManagedOverlayMode::disabled_only().map_err(|_| {
            RuntimeError::Authorization(
                "managed overlay delegation is required while authorization is enabled".into(),
            )
        })?;
        client.request_legacy(&legacy_mode, &request)
    }
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
    setup.managed_cleanup_provenance = attachment.cleanup_provenance;
    setup.managed_host_veth = Some(host_veth);
    Ok(setup)
}

#[cfg(target_os = "linux")]
fn managed_overlay_authorized_request(
    client: &ManagedOverlayClient,
    request: &ManagedOverlayRequest,
    proof: &AuthorizedRequest,
    intent: &crate::witness::DurableIntent,
    cleanup: Option<&crate::managed_overlay::ManagedCleanupProvenance>,
) -> Result<Result<ManagedOverlayResponse, crate::managed_overlay::ManagedOverlayError>, RuntimeError>
{
    let key_path = std::env::var("FERROCRATE_RUNTIME_GRANT_SIGNING_KEY_FILE").map_err(|_| {
        RuntimeError::Authorization("runtime helper-grant signing key is required".into())
    })?;
    let key_id = std::env::var("FERROCRATE_RUNTIME_GRANT_KEY_ID").map_err(|_| {
        RuntimeError::Authorization("runtime helper-grant key ID is required".into())
    })?;
    let issuer_name = std::env::var("FERROCRATE_RUNTIME_GRANT_ISSUER")
        .unwrap_or_else(|_| "ferrocrate-runtime".into());
    let issuer = crate::authorization::helper_grant::GrantIssuer::from_key_file(
        &key_id,
        Path::new(&key_path),
        nix::unistd::Uid::effective().as_raw(),
    )
    .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| RuntimeError::Authorization(error.to_string()))?;
    let now = crate::container_store::now_unix();
    let monotonic = fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split('.').next()?.parse::<u64>().ok())
        .unwrap_or(u64::MAX / 1000)
        .saturating_mul(1000);
    let nonce: [u8; 16] = rand::random();
    Ok(match cleanup {
        Some(provenance) => client.request_cleanup_authorized(
            request,
            proof,
            intent,
            provenance,
            &issuer,
            boot_id.trim(),
            now.saturating_add(30),
            monotonic.saturating_add(30_000),
            nonce,
            &issuer_name,
        ),
        None => client.request_authorized(
            request,
            proof,
            intent,
            &issuer,
            boot_id.trim(),
            now.saturating_add(30),
            monotonic.saturating_add(30_000),
            nonce,
            &issuer_name,
        ),
    })
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
    let bridge_gateway = bridge_config()?
        .gateway
        .parse::<Ipv4Addr>()
        .map_err(|_| RuntimeError::Network("invalid bridge gateway".to_string()))?
        .octets();
    let loopback_ifindex = interface_ifindex("lo")?;
    let (snat_port_start, snat_port_end) = ebpf_snat_range()?;
    let config = EbpfNetworkConfig {
        network_id: network_id.to_string(),
        interface: route.interface.clone(),
        external_ipv4: route.address,
        bridge_gateway,
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

    // A crash can occur after the pin tree is created but before its ownership
    // record is published.  Recover only an exact, schema-shaped tree with no
    // live Ferro TC classifiers; active filters or foreign entries remain a
    // fail-closed collision.
    if matches!(action, SharedEbpfAction::PrepareAndAttach) {
        recover_orphaned_ebpf_pins(network_id, &filters_before)?;
    }

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

#[allow(clippy::too_many_arguments)]
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
        // The shared network is not transactionally owned until its complete
        // classifier inventory and pin identity have been captured. Detach it
        // on any pre-adoption error, otherwise a failed container create can
        // strand live tc classifiers and an orphaned pin tree that blocks the
        // next attempt.
        let ownership = match (|| {
            network
                .attach_interface(host_veth, host_ifindex)
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
            build_ebpf_ownership(
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
            )
        })() {
            Ok(ownership) => ownership,
            Err(error) => {
                if let Err(detach_error) = network.detach() {
                    log::warn!(
                        "[rollback] failed to detach unadopted eBPF network: {detach_error}"
                    );
                }
                return Err(error);
            }
        };
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

fn path_resource_identity(path: &Path) -> Result<ResourceIdentity, RuntimeError> {
    let metadata = fs::metadata(path)?;
    Ok(ResourceIdentity::Path {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount_id: mount_id_for_path(path)?,
    })
}

fn mount_id_for_path(path: &Path) -> Result<Option<u64>, RuntimeError> {
    let canonical = fs::canonicalize(path)?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mountinfo.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        (fields.len() > 4 && Path::new(fields[4]) == canonical)
            .then(|| fields[0].parse::<u64>().ok())
            .flatten()
    }))
}

fn mountinfo_for_path(path: &Path) -> Result<Option<(u64, String, bool)>, RuntimeError> {
    let canonical = fs::canonicalize(path)?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mountinfo.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 6 || Path::new(fields[4]) != canonical {
            return None;
        }
        let separator = fields.iter().position(|field| *field == "-")?;
        Some((
            fields[0].parse().ok()?,
            fields.get(separator + 1)?.to_string(),
            fields[5].split(',').any(|option| option == "ro"),
        ))
    }))
}

fn classify_unmarked_mount(
    rootfs: Option<&Path>,
    target: &Path,
    baseline: (u64, u64, Option<u64>),
    expected_bind: Option<(u64, u64, Option<u64>)>,
    expected_kind: Option<&str>,
) -> Result<Option<ResourceIdentity>, ()> {
    let rootfs = rootfs.ok_or(())?;
    let path = if target == Path::new(".") {
        rootfs.to_path_buf()
    } else {
        rootfs.join(target)
    };
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    let mount = mountinfo_for_path(&path).map_err(|_| ())?;
    if metadata.dev() == baseline.0
        && metadata.ino() == baseline.1
        && mount.as_ref().map(|value| value.0) == baseline.2
    {
        return Ok(None);
    }
    let exact = if let Some((source_device, source_inode, _)) = expected_bind {
        metadata.dev() == source_device && metadata.ino() == source_inode && mount.is_some()
    } else if expected_kind == Some("tmpfs") {
        mount.as_ref().is_some_and(|value| value.1 == "tmpfs")
    } else if expected_kind == Some("readonly") {
        mount.as_ref().is_some_and(|value| value.2)
            && metadata.dev() == baseline.0
            && metadata.ino() == baseline.1
    } else {
        false
    };
    if !exact {
        return Err(());
    }
    Ok(Some(ResourceIdentity::Path {
        device: metadata.dev(),
        inode: metadata.ino(),
        mount_id: mount.map(|value| value.0),
    }))
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
            .or_else(|| options.get("bpf_name"))
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
        let program = options.get("prog").unwrap_or(options);
        let program_id = program
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .map(u32::try_from)
            .transpose()
            .map_err(|_| {
                RuntimeError::Network("owned tc program id is out of range".to_string())
            })?;
        let program_tag = program
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

fn validate_orphaned_ebpf_state(
    root: &Path,
    filters_before: &[EbpfFilterOwnershipRecord],
) -> Result<(), RuntimeError> {
    if !filters_before.is_empty() {
        return Err(RuntimeError::Network(format!(
            "eBPF pin path has live classifiers before attach: {}",
            root.display(),
        )));
    }
    if !root.exists() {
        return Ok(());
    }
    Ok(())
}

fn recover_orphaned_ebpf_pins(
    network_id: &str,
    filters_before: &[EbpfFilterOwnershipRecord],
) -> Result<(), RuntimeError> {
    let root = Path::new(FERRO_NETWORK_ROOT).join(network_id);
    validate_orphaned_ebpf_state(&root, filters_before)?;
    if !root.exists() {
        return Ok(());
    }
    let pins = capture_ebpf_pins(&root)?;
    let expected = BTreeSet::from([
        "",
        "maps",
        "maps/FERRO_COUNTERS",
        "maps/FERRO_ENDPOINTS",
        "maps/FERRO_META",
        "maps/FERRO_POLICY",
        "maps/FERRO_PORTS",
        "maps/FERRO_CONNTRACK",
        "programs",
        "programs/ferro_egress",
        "programs/ferro_ingress",
    ]);
    if pins
        .iter()
        .any(|pin| !expected.contains(pin.relative_path.as_str()))
        || pins.len() != expected.len()
    {
        return Err(RuntimeError::Network(format!(
            "eBPF pin path contains foreign or incomplete entries: {}",
            root.display()
        )));
    }
    let identity = PinnedNetworkIdentity {
        root: root.clone(),
        objects: pins
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
        .map_err(|error| RuntimeError::Network(error.to_string()))?;
    cleanup_captured_ebpf_pins(&root, &pins)
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

fn validate_rootless_bridge_network(
    enabled: bool,
    port_mappings: &[PortMappingRecord],
    requested_backend: NetworkBackend,
) -> Result<(), RuntimeError> {
    if !enabled {
        return Err(RuntimeError::Network(format!(
            "rootless bridge networking is disabled; set FERROCRATE_ROOTLESS_NETNS=1 to use slirp4netns (requested backend {requested_backend})"
        )));
    }
    for mapping in port_mappings {
        if mapping.host_port == 0 || mapping.container_port == 0 {
            return Err(RuntimeError::Network(
                "rootless host and container ports must be non-zero".to_string(),
            ));
        }
        if !mapping.protocol.eq_ignore_ascii_case("tcp")
            && !mapping.protocol.eq_ignore_ascii_case("udp")
        {
            return Err(RuntimeError::Network(format!(
                "rootless slirp4netns supports only TCP and UDP port mappings, got {}",
                mapping.protocol
            )));
        }
    }
    Ok(())
}

fn validate_port_mapping_conflicts(
    store: &SqliteContainerStore,
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
        bridge_gateway: bridge_config()?
            .gateway
            .parse::<Ipv4Addr>()
            .map_err(|_| RuntimeError::Network("invalid bridge gateway".to_string()))?
            .octets(),
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
) -> Result<bool, RuntimeError> {
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
    let namespace_verified = match fs::symlink_metadata(&netns_path) {
        Ok(metadata) => match verify_kernel_identity(
            KernelIdentity {
                device: expected_namespace.device,
                inode: expected_namespace.inode,
            },
            Some(KernelIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }),
        ) {
            Ok(_) => true,
            Err(error)
                if !require_present
                    && error
                        .to_string()
                        .contains("owned kernel resource identity changed") =>
            {
                // A stale exited container must not authorize deletion of a
                // replacement namespace. The caller may still remove proven
                // record/firewall state, but must skip namespace/veth effects.
                false
            }
            Err(error) => return Err(error),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound && !require_present => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(RuntimeError::Network(
                "owned network namespace is missing".to_string(),
            ))
        }
        Err(error) => return Err(error.into()),
    };
    if !namespace_verified {
        return Ok(false);
    }

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
    Ok(true)
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
            let command = vec![
                "nft".to_string(),
                "list".to_string(),
                "table".to_string(),
                "ip".to_string(),
                firewall_id.to_string(),
            ];
            match run_cmd_capture(&command) {
                Ok(output) => output,
                Err(error)
                    if error.to_string().contains("No such file or directory")
                        || error.to_string().contains("does not exist") =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
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
    authority: Option<(&AuthorizedRequest, Option<&crate::witness::DurableIntent>)>,
    record: &ContainerRecord,
    all_records: &[ContainerRecord],
) -> Result<(), RuntimeError> {
    if let Some(overlay_id) = record.managed_overlay.as_deref() {
        let socket = std::env::var("FERROCRATE_AGENT_SOCKET")
            .unwrap_or_else(|_| "/run/ferrocrate/agent.sock".to_string());
        let request = ManagedOverlayRequest::DetachContainer {
            overlay_id: overlay_id.to_string(),
            container_id: record.id.clone(),
            now_unix: crate::container_store::now_unix() as i64,
        };
        let client = ManagedOverlayClient::new(socket);
        let response = match authority {
            Some((proof, Some(intent))) => {
                let provenance = record.managed_cleanup_provenance.as_ref().ok_or_else(|| {
                    RuntimeError::Authorization(
                        "managed overlay cleanup provenance is missing; quarantined".into(),
                    )
                })?;
                managed_overlay_authorized_request(
                    &client,
                    &request,
                    proof,
                    intent,
                    Some(provenance),
                )?
            },
            _ => {
                let legacy_mode = LegacyManagedOverlayMode::disabled_only().map_err(|_| RuntimeError::Authorization("managed overlay cleanup delegation is required while authorization is enabled".into()))?;
                client.request_legacy(&legacy_mode, &request)
            }
        }
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
                if record.namespace_owned {
                    if let Some(netns_name) = record.netns.as_deref() {
                        let expected = record.namespace_identity.ok_or_else(|| {
                        RuntimeError::Network(format!(
                            "legacy container {} has a namespace name but no kernel identity; retain the record and remove the namespace manually",
                            record.id
                        ))
                    })?;
                        let path = netns::netns_path(netns_name);
                        let observed = match fs::symlink_metadata(&path) {
                            Ok(metadata) => Some(KernelIdentity {
                                device: metadata.dev(),
                                inode: metadata.ino(),
                            }),
                            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                            Err(error) => return Err(RuntimeError::Io(error)),
                        };
                        match verify_kernel_identity(
                            KernelIdentity {
                                device: expected.device,
                                inode: expected.inode,
                            },
                            observed,
                        )? {
                            OwnedResourceState::Present => {
                                run_cmd_allow_missing(&netns::build_ip_netns_del_cmd(netns_name)?)?;
                            }
                            OwnedResourceState::Missing => {}
                        }
                    }
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
            let namespace_verified =
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

            if !namespace_verified {
                return Ok(());
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
    cleanup_captured_ebpf_pins(&root, &ownership.ebpf_pins)
}

fn cleanup_captured_ebpf_pins(
    root: &Path,
    captured: &[EbpfPinOwnershipRecord],
) -> Result<(), RuntimeError> {
    let mut pins = captured.to_vec();
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

fn start_slirp4netns(pid: u32, api_socket: Option<&Path>) -> Result<(u32, u64), RuntimeError> {
    let host_netns = fs::read_link("/proc/self/ns/net")?;
    let target_netns = PathBuf::from(format!("/proc/{pid}/ns/net"));
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if fs::read_link(&target_netns)
            .map(|namespace| namespace != host_netns)
            .unwrap_or(false)
        {
            break;
        }
        if !process_exists(pid) {
            return Err(RuntimeError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "rootless workload exited before creating its network namespace",
            )));
        }
        thread::sleep(Duration::from_millis(10));
    }
    if fs::read_link(&target_netns)
        .map(|namespace| namespace == host_netns)
        .unwrap_or(true)
    {
        return Err(RuntimeError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "rootless workload did not enter its network namespace",
        )));
    }
    let tap_name = format!("tap{pid}");
    let tap_name = if tap_name.len() > 15 {
        tap_name[..15].to_string()
    } else {
        tap_name
    };
    let config = RootlessNetConfig {
        tap_name,
        cidr: "10.0.2.0/24".to_string(),
        enable_ipv6: std::env::var("FERROCRATE_ROOTLESS_IPV6")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false),
        api_socket: api_socket.map(|path| path.display().to_string()),
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
        return Err(RuntimeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "slirp4netns command is empty",
        )));
    }
    let (bin, rest) = parse_cmd_args(&cmd)?;
    let mut child = Command::new(bin)
        .args(rest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(status) = child.try_wait()? {
        return Err(RuntimeError::Io(std::io::Error::other(format!(
            "slirp4netns exited before setup completed: {status}"
        ))));
    }
    let helper_pid = child.id();
    let Some(helper_start_time) = process_start_time_for_pid(helper_pid) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(RuntimeError::Io(std::io::Error::other(
            "slirp4netns helper has no stable process start time",
        )));
    };
    thread::spawn(move || {
        let _ = child.wait();
    });
    Ok((helper_pid, helper_start_time))
}

fn configure_slirp_host_forwards(
    api_socket: &Path,
    mappings: &[PortMappingRecord],
) -> Result<(), RuntimeError> {
    if mappings.is_empty() {
        return Ok(());
    }
    for mapping in mappings {
        let request =
            build_hostfwd_request(mapping.host_port, mapping.container_port, &mapping.protocol)
                .map_err(|error| RuntimeError::Network(error.to_string()))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut last_error = None;
        let mut configured = false;
        while Instant::now() < deadline {
            match UnixStream::connect(api_socket) {
                Ok(mut stream) => {
                    stream.write_all(&request)?;
                    stream.shutdown(std::net::Shutdown::Write)?;
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response)?;
                    let value: serde_json::Value =
                        serde_json::from_slice(&response).map_err(|error| {
                            RuntimeError::Network(format!(
                                "invalid slirp4netns API response: {error}"
                            ))
                        })?;
                    if let Some(error) = value.get("error") {
                        return Err(RuntimeError::Network(format!(
                            "slirp4netns failed to add host forwarding: {error}"
                        )));
                    }
                    if value
                        .get("return")
                        .and_then(|result| result.get("id"))
                        .is_none()
                    {
                        return Err(RuntimeError::Network(
                            "slirp4netns host forwarding response omitted an id".to_string(),
                        ));
                    }
                    configured = true;
                    break;
                }
                Err(error) => last_error = Some(error),
            }
            thread::sleep(Duration::from_millis(25));
        }
        if !configured {
            return Err(RuntimeError::Network(format!(
                "slirp4netns API socket did not become ready: {}",
                last_error
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "timeout".to_string())
            )));
        }
    }
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
    // Capability discovery must not execute arbitrary helpers.  In particular,
    // `aa-exec --version` can segfault on otherwise healthy AppArmor hosts;
    // treating that probe as absence silently disables strict MAC enforcement.
    // Resolve the executable instead and let the real, timeout-bounded call
    // report an execution failure at the point of use.
    if matches!(bin, "bwrap" | "unshare" | "setpriv" | "sh") {
        return crate::rootless::trusted_executable_path(bin).is_some();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| directory.join(bin).is_file())
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

fn cleanup_apparmor_profile(runtime_dir: &Path, container_id: &str) -> Result<(), RuntimeError> {
    if !apparmor_enabled() {
        return Ok(());
    }
    let profile_path = runtime_dir
        .join("security")
        .join("apparmor")
        .join(format!("ferrocrate-{container_id}.profile"));
    if !profile_path.exists() {
        return Ok(());
    }
    if !command_available("apparmor_parser") {
        mac_enforcement_result(
            "apparmor",
            "apparmor_parser is required to unload an enabled profile",
        )?;
        return Ok(());
    }
    let output = execute_with_timeout(
        "apparmor_parser",
        &["-R", &profile_path.to_string_lossy()],
        Duration::from_secs(10),
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        mac_enforcement_result(
            "apparmor",
            &format!("failed to unload profile: {}", stderr.trim()),
        )?;
    }
    fs::remove_file(&profile_path).map_err(|error| {
        RuntimeError::InvalidState(format!(
            "failed to remove AppArmor profile {}: {error}",
            profile_path.display()
        ))
    })
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
    if !command_available("getenforce") {
        mac_enforcement_result(
            "selinux",
            "getenforce is required to verify SELinux enforcement state",
        )?;
        return Ok(cmd.to_vec());
    }
    let state = match execute_with_timeout("getenforce", &[], Duration::from_secs(5)) {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_ascii_lowercase(),
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let message = if detail.is_empty() {
                "getenforce failed".to_string()
            } else {
                format!("getenforce failed: {detail}")
            };
            mac_enforcement_result("selinux", &message)?;
            return Ok(cmd.to_vec());
        }
        Err(error) => {
            mac_enforcement_result("selinux", &format!("getenforce failed: {error}"))?;
            return Ok(cmd.to_vec());
        }
    };
    if state != "enforcing" && state != "permissive" {
        mac_enforcement_result(
            "selinux",
            &format!("getenforce reported unsupported state: {state}"),
        )?;
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
        write_runtime_file_atomically(&hosts_path, hosts_body.as_bytes())?;

        let resolv_path = runtime_dir
            .join("containers")
            .join(&record.id)
            .join("rootfs")
            .join("etc")
            .join("resolv.conf");
        if let Some(parent) = resolv_path.parent() {
            fs::create_dir_all(parent)?;
        }
        ferro_net::dns::write_resolv_conf(&resolv_path, &runtime_dns_config())
            .map_err(|error| RuntimeError::Network(error.to_string()))?;
    }
    Ok(())
}

fn write_runtime_file_atomically(path: &Path, contents: &[u8]) -> Result<(), RuntimeError> {
    if path
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(RuntimeError::Network(format!(
            "refusing to replace symlinked runtime file {}",
            path.display()
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        RuntimeError::Network(format!("runtime file has no parent: {}", path.display()))
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        OpenOptions::new().read(true).open(parent)?.sync_all()?;
        let read_back = fs::read(path)?;
        if read_back != contents {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runtime file read-back mismatch",
            ));
        }
        Ok::<(), io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(RuntimeError::Io)
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

fn route_localnet_path(interface: &str) -> PathBuf {
    Path::new("/proc/sys/net/ipv4/conf")
        .join(interface)
        .join("route_localnet")
}

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

fn acquire_route_localnet_with<S: GlobalValueStore>(
    interface: &str,
    store: &mut S,
) -> Result<Option<InterfaceValueOwnership>, RuntimeError> {
    let current = store.read()?;
    match current.as_str() {
        "1" => Ok(None),
        "0" => {
            store.write("1")?;
            Ok(Some(InterfaceValueOwnership {
                interface: interface.to_string(),
                previous: "0".to_string(),
                expected: "1".to_string(),
            }))
        }
        _ => Err(RuntimeError::Network(format!(
            "refusing to change malformed route_localnet value for {interface}: {current:?}"
        ))),
    }
}

fn restore_route_localnet_with<S: GlobalValueStore>(
    ownership: &InterfaceValueOwnership,
    store: &mut S,
) -> Result<(), RuntimeError> {
    if ownership.previous != "0" || ownership.expected != "1" || ownership.interface.is_empty() {
        return Err(RuntimeError::Network(
            "malformed persisted route_localnet ownership".to_string(),
        ));
    }
    let current = store.read()?;
    if current == ownership.previous {
        return Ok(());
    }
    if current != ownership.expected {
        return Err(RuntimeError::Network(format!(
            "route_localnet for {} changed to foreign value {current:?}; refusing restoration",
            ownership.interface
        )));
    }
    store.write(&ownership.previous)
}

fn restore_route_localnet(ownership: &InterfaceValueOwnership) -> Result<(), RuntimeError> {
    let path = route_localnet_path(&ownership.interface);
    let mut store = FileGlobalValueStore { path: &path };
    restore_route_localnet_with(ownership, &mut store)
}

fn ensure_bridge_route_localnet(
    bridge: &str,
    rollback: &mut CreationRollback,
) -> Result<(), RuntimeError> {
    let path = route_localnet_path(bridge);
    let mut store = FileGlobalValueStore { path: &path };
    if let Some(ownership) = acquire_route_localnet_with(bridge, &mut store)? {
        rollback.track_route_localnet(ownership)?;
    }
    Ok(())
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
    let cmd_str = args.join(" ");

    log::debug!("[exec] {}", cmd_str);

    net_exec_cmd_capture(args).map_err(|error| RuntimeError::Network(error.to_string()))
}

/// Execute a command, allowing "already exists" errors (idempotent operations).
fn run_cmd_allow_missing(args: &[String]) -> Result<(), RuntimeError> {
    if args.is_empty() {
        return Ok(());
    }
    net_exec_cmd_allow_missing(args).map_err(|error| RuntimeError::Network(error.to_string()))
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

fn associated_network_name(associated: Option<&str>, network_mode: &str) -> Option<String> {
    if let Some(name) = associated.map(str::trim).filter(|value| !value.is_empty()) {
        return Some(name.to_string());
    }
    match network_mode {
        "bridge" => Some("bridge".to_string()),
        "host" => Some("host".to_string()),
        "none" => Some("none".to_string()),
        "wireguard" => Some("wireguard".to_string()),
        _ => None,
    }
}

fn persisted_network_name(associated: Option<&str>, network_mode: &str) -> Option<String> {
    // A rootless bridge is provided by slirp4netns rather than FerroCrate's
    // privileged bridge lifecycle. Persisting it as the built-in `bridge`
    // network would make teardown/recovery classify the record as a legacy
    // kernel bridge with missing ownership metadata.
    if network_mode == "bridge"
        && !nix::unistd::Uid::effective().is_root()
        && rootless_netns_enabled()
    {
        return None;
    }
    associated_network_name(associated, network_mode)
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

fn validate_ebpf_published_port_boundary(
    backend: NetworkBackend,
    port_mappings: &[crate::container_store::PortMappingRecord],
) -> Result<(), RuntimeError> {
    if backend != NetworkBackend::Ebpf || port_mappings.is_empty() {
        return Ok(());
    }
    if std::env::var("FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS").as_deref() == Ok("1") {
        return Ok(());
    }
    Err(RuntimeError::Network(
        "eBPF published-port forwarding is disabled pending live checksum qualification; use --network-backend iptables or nftables, or set FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS=1 for an explicit experimental override".to_string(),
    ))
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    let capabilities = HostCapabilities::probe();
    capabilities
        .require_network_mutation()
        .map_err(|error| RuntimeError::Network(error.to_string()))?;
    if !capabilities.tc {
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
    let stdout = run_cmd_capture(&verify)?;
    if !stdout.contains("tbf") || !qdisc_reports_rate(&stdout, &rate) {
        return Err(RuntimeError::Network(format!(
            "bandwidth limit verification failed for {link}: expected tbf rate {rate}"
        )));
    }
    Ok(())
}

fn qdisc_reports_rate(output: &str, expected_rate: &str) -> bool {
    output.lines().any(|line| {
        line.split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|window| window == ["rate", expected_rate])
    })
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
    let config = security_monitor_config(container_id);
    let events = config.events.clone();
    let object_path = config.object_path.clone();
    let pin_root = config.pin_root.clone();
    validate_security_ebpf_config(&object_path, &pin_root, &events)?;
    validate_security_ebpf_object(&object_path)?;
    validate_security_ebpf_pin_root(&pin_root)?;
    if !command_available("bpftool") {
        return Err(RuntimeError::Network(
            "security ebpf monitor unavailable: requires bpftool; fallback=disabled (turn the monitor off explicitly)".to_string(),
        ));
    }
    let installed =
        install_security_monitor(&config).map_err(|err| RuntimeError::Network(err.to_string()))?;
    log::info!(
        "security ebpf monitor active for container {} events={:?}",
        container_id,
        installed
    );
    let runtime_root = PathBuf::from(
        std::env::var("FERROCRATE_RUNTIME_DIR")
            .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string()),
    );
    let _ = log_audit_event(
        &runtime_root,
        make_audit_event(
            "security_ebpf_monitor",
            "ferrocrate-security",
            Some(container_id),
            None,
            Some("attached"),
            Some(&security_monitor_audit_message("attached", &installed)),
        ),
    );
    Ok(())
}

fn validate_security_ebpf_object(object_path: &str) -> Result<(), RuntimeError> {
    let metadata = std::fs::metadata(object_path).map_err(|error| {
        RuntimeError::Network(format!(
            "security ebpf monitor object unavailable: {object_path}: {error}"
        ))
    })?;
    if !metadata.is_file() {
        return Err(RuntimeError::Network(format!(
            "security ebpf monitor object must be a regular file: {object_path}"
        )));
    }
    Ok(())
}

fn validate_security_ebpf_pin_root(pin_root: &str) -> Result<(), RuntimeError> {
    let metadata = std::fs::metadata(pin_root).map_err(|error| {
        RuntimeError::Network(format!(
            "security ebpf monitor pin root unavailable: {pin_root}: {error}"
        ))
    })?;
    if !metadata.is_dir() {
        return Err(RuntimeError::Network(format!(
            "security ebpf monitor pin root must be a directory: {pin_root}"
        )));
    }
    Ok(())
}

fn security_monitor_config(container_id: &str) -> SecurityMonitorConfig {
    SecurityMonitorConfig {
        object_path: std::env::var("FERROCRATE_EBPF_SECURITY_OBJECT")
            .unwrap_or_else(|_| "/usr/lib/ferrocrate/ferro-security.o".to_string()),
        pin_root: std::env::var("FERROCRATE_EBPF_SECURITY_PIN_ROOT")
            .unwrap_or_else(|_| format!("/sys/fs/bpf/ferrocrate-security-{container_id}")),
        events: security_ebpf_events(),
    }
}

fn cleanup_security_ebpf_monitor(container_id: &str) -> Result<(), RuntimeError> {
    let config = security_monitor_config(container_id);
    if !Path::new(&config.pin_root).exists() {
        return Ok(());
    }
    cleanup_security_monitor(&config)
        .map_err(|error| RuntimeError::Network(format!("security ebpf cleanup failed: {error}")))?;
    let runtime_root = PathBuf::from(
        std::env::var("FERROCRATE_RUNTIME_DIR")
            .unwrap_or_else(|_| "/var/lib/ferrocrate".to_string()),
    );
    let _ = log_audit_event(
        &runtime_root,
        make_audit_event(
            "security_ebpf_monitor",
            "ferrocrate-security",
            Some(container_id),
            None,
            Some("detached"),
            Some(&security_monitor_audit_message("detached", &config.events)),
        ),
    );
    Ok(())
}

fn security_monitor_audit_message(phase: &str, events: &[String]) -> String {
    let bounded = events
        .iter()
        .take(32)
        .map(String::as_str)
        .collect::<Vec<_>>();
    format!("phase={phase} events={}", bounded.join(","))
}

fn validate_security_ebpf_config(
    object_path: &str,
    pin_root: &str,
    events: &[String],
) -> Result<(), RuntimeError> {
    if object_path.trim().is_empty() || !Path::new(object_path).is_absolute() {
        return Err(RuntimeError::Network(
            "security ebpf monitor object path must be absolute".to_string(),
        ));
    }
    if pin_root.trim().is_empty() || !Path::new(pin_root).is_absolute() {
        return Err(RuntimeError::Network(
            "security ebpf monitor pin root must be absolute".to_string(),
        ));
    }
    // `Path::components()` normalizes `.` away, so inspect the raw separators
    // as well; bpftool and cleanup must receive one canonical, non-traversing
    // pin namespace rather than an equivalent-looking alias.
    if pin_root
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err(RuntimeError::Network(
            "security ebpf monitor pin root must not contain dot path components".to_string(),
        ));
    }
    if events.is_empty() || events.len() > 32 {
        return Err(RuntimeError::Network(
            "security ebpf monitor event set must contain 1..32 events".to_string(),
        ));
    }
    if events.iter().any(|event| {
        event.is_empty()
            || !event
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
    }) {
        return Err(RuntimeError::Network(
            "security ebpf monitor event names must be ASCII components".to_string(),
        ));
    }
    let mut normalized = BTreeSet::new();
    if events
        .iter()
        .any(|event| !normalized.insert(event.to_ascii_lowercase()))
    {
        return Err(RuntimeError::Network(
            "security ebpf monitor event names must be unique".to_string(),
        ));
    }
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

fn adaptive_restart_delay(
    decision: Option<ferro_mind::ai::restart::RestartDecision>,
) -> Option<u64> {
    match decision {
        None | Some(ferro_mind::ai::restart::RestartDecision::Restart) => Some(1),
        Some(ferro_mind::ai::restart::RestartDecision::RestartAfterDelay { delay_secs }) => {
            Some(delay_secs)
        }
        Some(ferro_mind::ai::restart::RestartDecision::DoNotRestart) => None,
    }
}

fn update_pid_status(
    db: &SqliteContainerStore,
    id: &str,
    pid: u32,
    status: &str,
) -> Result<(), ContainerStoreError> {
    let Some(mut record) = db.get(id)? else {
        return Ok(());
    };
    if record.pending_mutation.is_some() {
        return Err(ContainerStoreError::MutationConflict);
    }
    record.pid = pid;
    record.status = status.to_string();
    db.put(&record)?;
    Ok(())
}

fn update_exit(
    db: &SqliteContainerStore,
    id: &str,
    exit_code: i32,
) -> Result<String, ContainerStoreError> {
    db.update_exit(id, exit_code)
}

fn update_exit_after_mutation(
    db: &SqliteContainerStore,
    id: &str,
    exit_code: i32,
) -> Result<String, ContainerStoreError> {
    // A short-lived workload can exit while its creating `run` mutation is
    // still being finalized by the parent CLI. Do not drop that terminal
    // observation: wait for the reservation to clear, then publish the exit
    // state. This keeps `run --rm` from racing removal against a stale
    // `running` record under parallel lifecycle load.
    // The supervisor may observe process exit before the creating CLI has
    // cleared its durable reservation. Give that owner a bounded window to
    // publish the launch identity and terminal state under heavy contention.
    const MAX_RETRIES: usize = 256;
    for attempt in 0..MAX_RETRIES {
        match update_exit(db, id, exit_code) {
            Err(ContainerStoreError::MutationConflict) if attempt + 1 < MAX_RETRIES => {
                // Any lifecycle owner may be finalizing a kernel effect while
                // the supervisor observes process exit.  Waiting for that
                // owner preserves its durable status (stop/start/delete)
                // instead of racing it with an unconditional `exited` write.
                if db
                    .get(id)
                    .ok()
                    .flatten()
                    .and_then(|record| record.pending_mutation)
                    .is_none()
                {
                    return Err(ContainerStoreError::MutationConflict);
                }
                thread::sleep(Duration::from_millis(5));
            }
            result => return result,
        }
    }
    update_exit(db, id, exit_code)
}

fn update_health(
    db: &SqliteContainerStore,
    id: &str,
    status: &str,
    failures: u32,
    checked_at_unix: u64,
) -> Result<bool, ContainerStoreError> {
    db.update_health(id, status, failures, checked_at_unix)
}

fn run_health_checks(
    store: SqliteContainerStore,
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
        if !store.contains(&id).unwrap_or(false) {
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
/// Returns whether runtime inference is enabled.
///
/// Inference is enabled by default, matching `AiConfig::from_env`; operators
/// can opt out with `FERROCRATE_AI=0` or `FERROCRATE_AI=false`. Training and
/// data collection retain their separate explicit-consent gates.
fn is_ai_enabled() -> bool {
    ferro_mind::ai::config::AiConfig::from_env().enabled
}

/// Return the durable AI decision logger used by every runtime lifecycle path.
/// An explicit path remains supported for operators; otherwise decisions are
/// written beneath the configured runtime directory so enabling AI never
/// silently drops adaptive-restart evidence.
fn ai_decision_logger() -> Option<ferro_mind::ai::audit::AuditLogger> {
    if !is_ai_enabled() {
        return None;
    }
    let path = std::env::var_os("FERROCRATE_AI_AUDIT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("FERROCRATE_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/ferrocrate"))
                .join("ai")
                .join("decisions.jsonl")
        });
    Some(ferro_mind::ai::audit::AuditLogger::new(path))
}

fn ai_restart_snapshot_path(container_id: &str) -> PathBuf {
    std::env::var_os("FERROCRATE_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/ferrocrate"))
        .join("ai")
        .join("restart")
        .join(format!("{container_id}.json"))
}

fn ai_resource_snapshot_path(container_id: &str) -> PathBuf {
    std::env::var_os("FERROCRATE_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/ferrocrate"))
        .join("ai")
        .join("resource")
        .join(format!("{container_id}.json"))
}

fn ai_anomaly_snapshot_path(container_id: &str) -> PathBuf {
    std::env::var_os("FERROCRATE_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/ferrocrate"))
        .join("ai")
        .join("anomaly")
        .join(format!("{container_id}.json"))
}

fn cleanup_ai_container_snapshots(runtime_dir: &Path, container_id: &str) {
    for path in [
        runtime_dir
            .join("ai")
            .join("restart")
            .join(format!("{container_id}.json")),
        runtime_dir
            .join("ai")
            .join("resource")
            .join(format!("{container_id}.json")),
        runtime_dir
            .join("ai")
            .join("anomaly")
            .join(format!("{container_id}.json")),
    ] {
        if let Err(error) = fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                warn!(path = %path.display(), error = %error, "failed to remove AI container snapshot");
            }
        }
    }
}

fn log_ai_restart_lifecycle(
    container_id: &str,
    action: &str,
    exit_code: i32,
    restart_count: u32,
    delay_secs: u64,
    stage: &str,
    pid: Option<u32>,
) {
    let Some(logger) = ai_decision_logger() else {
        return;
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut trace = ferro_mind::ai::explain::DecisionTrace::new(
        format!("ai-restart-{action}-{container_id}-{ts}"),
        format!("Adaptive restart lifecycle stage for container {container_id}"),
    )
    .with_model("adaptive-restart-policy", "runtime-v1")
    .with_decision(action)
    .with_evidence("container_id", container_id.to_string())
    .with_evidence("previous_exit_code", exit_code.to_string())
    .with_evidence("restart_count", restart_count.to_string())
    .with_evidence("delay_secs", delay_secs.to_string())
    .with_evidence("stage", stage.to_string());
    if let Some(pid) = pid {
        trace = trace.with_evidence("pid", pid.to_string());
    }
    let _ = logger.log(action, &trace);
}

fn log_ai_reconciliation(container_id: &str, exit_code: i32, reason: &str, status: &str) {
    let Some(logger) = ai_decision_logger() else {
        return;
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let trace = ferro_mind::ai::explain::DecisionTrace::new(
        format!("ai-reconcile-{container_id}-{ts}"),
        format!("Runtime reconciliation action for container {container_id}"),
    )
    .with_model("runtime-reconciliation", "runtime-v1")
    .with_decision("reconcile-exited")
    .with_evidence("container_id", container_id.to_string())
    .with_evidence("status", status.to_string())
    .with_evidence("exit_code", exit_code.to_string())
    .with_evidence("reason", reason.to_string());
    let _ = logger.log("ai_reconciliation_applied", &trace);
}

fn log_ai_kernel_reconciliation(network_id: &str, action: &str, container_count: usize) {
    let Some(logger) = ai_decision_logger() else {
        return;
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let trace = ferro_mind::ai::explain::DecisionTrace::new(
        format!("ai-kernel-reconcile-{network_id}-{ts}"),
        format!("Kernel network reconciliation for shared network {network_id}"),
    )
    .with_model("runtime-network-reconciliation", "runtime-v1")
    .with_decision(action)
    .with_evidence("network_id", network_id.to_string())
    .with_evidence("container_count", container_count.to_string());
    let _ = logger.log("ai_kernel_reconciliation", &trace);
}

fn ai_lifecycle_enabled(config: Option<&AiRuntimeConfig>) -> bool {
    config.is_some() && is_ai_enabled()
}

fn should_start_ai_monitor(memory_limit: u64) -> bool {
    is_ai_enabled() && memory_limit > 0
}

/// Compute the next bounded memory limit for the opt-in AI action path.
///
/// The action is deliberately monotonic: a misconfigured ceiling can disable
/// an increase, but it can never cause the runtime to lower an existing cgroup
/// limit. Saturating arithmetic also keeps the decision safe at `u64::MAX`.
fn ai_next_memory_limit(current: u64, ceiling: u64) -> Option<u64> {
    if current == 0 {
        return None;
    }
    let proposed = current.saturating_add((current / 4).max(1));
    let bounded = proposed.min(ceiling);
    (bounded > current).then_some(bounded)
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
    store: SqliteContainerStore,
    id: String,
    cgroup_root: PathBuf,
    mut memory_limit: u64,
    cancel: Arc<AtomicBool>,
) {
    use std::time::Instant;

    // Resolve the digest-bound active resource model when one is available.
    // The built-in trend predictor remains an explicit, safe fallback for
    // first-run hosts or unavailable model stores.
    let mut predictor_model_version = "heuristic-runtime-v1".to_string();
    // The monitor also owns anomaly detection and trend telemetry, so it must
    // remain active for unlimited containers. OOM prediction and memory action
    // stay disabled until a positive cgroup limit is present.
    let mut predictor = ferro_mind::ai::resource::ResourcePredictor::new(60);
    if memory_limit > 0 {
        predictor = predictor.with_memory_limit(memory_limit);
    }
    let model_config = ferro_mind::ai::training::TrainingConfig::default();
    let active_model = match ferro_mind::ai::training::TrainingPipeline::new(model_config) {
        Ok(pipeline) => pipeline
            .resolve_active_model(ferro_mind::ai::training::ModelType::ResourcePredictor)
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    match active_model {
        Ok(active) => {
            match ferro_mind::ai::resource::ResourcePredictor::from_model_artifact(&active.path) {
                Ok(model_predictor) => {
                    predictor = if memory_limit > 0 {
                        model_predictor.with_memory_limit(memory_limit)
                    } else {
                        model_predictor
                    };
                    predictor_model_version = format!("active-v{}", active.version);
                    info!(
                        container = %id,
                        model_version = %predictor_model_version,
                        artifact_sha256 = %active.artifact_sha256,
                        "resolved active resource predictor"
                    );
                }
                Err(error) => {
                    warn!(container = %id, error = %error, "active resource model rejected; using heuristic predictor");
                }
            }
        }
        Err(error) => {
            info!(container = %id, error = %error, "no active resource model; using heuristic predictor");
        }
    }
    let resource_snapshot_path = ai_resource_snapshot_path(&id);
    if let Err(error) = predictor.restore_snapshot(&resource_snapshot_path, &id) {
        if resource_snapshot_path.exists() {
            info!(
                container = %id,
                error = %error,
                "resource predictor snapshot rejected; starting a fresh window"
            );
        }
    }
    // Persist AI decisions by default when the monitor is enabled. Operators
    // may override the location, but enabling AI must not silently discard
    // per-container evidence when no optional audit variable is configured.
    let ai_logger = ai_decision_logger();

    let mut anomaly_model_version = "neural-anomaly-runtime-v1".to_string();
    let mut anomaly_detector = ferro_mind::ai::anomaly::NeuralAnomalyDetector::new(3, 0.5);
    let anomaly_model = match ferro_mind::ai::training::TrainingPipeline::new(
        ferro_mind::ai::training::TrainingConfig::default(),
    ) {
        Ok(pipeline) => pipeline
            .resolve_active_model(ferro_mind::ai::training::ModelType::AnomalyDetector)
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    match anomaly_model {
        Ok(active) => {
            match ferro_mind::ai::anomaly::NeuralAnomalyDetector::from_model_artifact(&active.path)
            {
                Ok(model_detector) if model_detector.input_size() == 3 => {
                    anomaly_detector = model_detector;
                    anomaly_model_version = format!("active-v{}", active.version);
                    info!(
                        container = %id,
                        model_version = %anomaly_model_version,
                        artifact_sha256 = %active.artifact_sha256,
                        "resolved active anomaly detector"
                    );
                }
                Ok(model_detector) => {
                    warn!(
                        container = %id,
                        input_size = model_detector.input_size(),
                        "active anomaly model feature dimension does not match runtime; using runtime baseline"
                    );
                }
                Err(error) => {
                    warn!(container = %id, error = %error, "active anomaly model rejected; using runtime baseline");
                }
            }
        }
        Err(error) => {
            info!(container = %id, error = %error, "no active anomaly model; using runtime baseline");
        }
    }
    let anomaly_snapshot_path = ai_anomaly_snapshot_path(&id);
    let mut anomaly_training_samples =
        match ferro_mind::ai::anomaly::load_training_snapshot(&anomaly_snapshot_path, &id) {
            Ok(samples) => samples,
            Err(error) if anomaly_snapshot_path.exists() => {
                info!(
                    container = %id,
                    error = %error,
                    "anomaly training snapshot rejected; starting a fresh baseline"
                );
                Vec::new()
            }
            Err(_) => Vec::new(),
        };
    let anomaly_train_after = 20usize; // Train after 20 samples of normal behavior
    if !anomaly_detector.is_trained() && anomaly_training_samples.len() >= anomaly_train_after {
        anomaly_training_samples.truncate(anomaly_train_after);
        let _ = anomaly_detector.train(&anomaly_training_samples, 50);
    }

    let sample_interval = Duration::from_secs(30);
    let oom_horizon = Duration::from_secs(1200); // 20 minutes
                                                 // cpu.stat reports cumulative CPU time. Retain only the previous sample
                                                 // so anomaly and prediction features use the actual cgroup CPU delta.
    let mut previous_cpu_sample: Option<(u64, Instant)> = None;
    let mut observed_memory_peak = 1u64;

    loop {
        // Check for explicit cancellation
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        // Check if container still exists
        if !store.contains(&id).unwrap_or(false) {
            return; // Container removed
        }

        // Read cgroup metrics
        let cgroup_path = cgroup_root.join("ferrocrate").join(&id);
        if let Ok(metrics) = ferro_mind::ai::resource::read_cgroup_metrics(&cgroup_path) {
            let sample_timestamp = Instant::now();
            let cpu_percent = previous_cpu_sample
                .map(|(previous_usage, previous_timestamp)| {
                    ferro_mind::ai::resource::cpu_percent_from_delta(
                        previous_usage,
                        metrics.cpu_usage_usec,
                        sample_timestamp.duration_since(previous_timestamp),
                    )
                })
                .unwrap_or(0.0);
            previous_cpu_sample = Some((metrics.cpu_usage_usec, sample_timestamp));
            // Create sample with current metrics
            let sample = ferro_mind::ai::resource::ResourceSample {
                cpu_percent,
                memory_bytes: metrics.memory_current,
                pids_count: metrics.pids_current,
                timestamp: sample_timestamp,
            };

            predictor.push(sample);
            observed_memory_peak = observed_memory_peak.max(metrics.memory_current);
            if let Err(error) = predictor.save_snapshot(&resource_snapshot_path, &id) {
                warn!(container = %id, error = %error, "failed to persist resource predictor snapshot");
            }

            // Build normalized feature vector for anomaly detection
            // Features: [cpu_norm, mem_norm, pids_norm] normalized 0-1
            let memory_scale = if memory_limit > 0 {
                memory_limit
            } else {
                observed_memory_peak.max(1)
            };
            let mem_norm = (metrics.memory_current as f32 / memory_scale as f32).clamp(0.0, 1.0);
            let cpu_norm = (sample.cpu_percent / 100.0).clamp(0.0, 1.0);
            let pids_norm = (metrics.pids_current as f32 / 1000.0).clamp(0.0, 1.0);
            let features = vec![cpu_norm, mem_norm, pids_norm];

            // Accumulate training samples during initial "normal" phase
            if !anomaly_detector.is_trained() {
                anomaly_training_samples.push(features.clone());
                if let Err(error) = ferro_mind::ai::anomaly::save_training_snapshot(
                    &anomaly_snapshot_path,
                    &id,
                    &anomaly_training_samples,
                ) {
                    warn!(container = %id, error = %error, "failed to persist anomaly training snapshot");
                }
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
                    if let Some(logger) = ai_logger.as_ref() {
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let trace = ferro_mind::ai::explain::DecisionTrace::new(
                            format!("ai-anomaly-{id}-{ts}"),
                            format!("Container {id} exceeded the learned resource baseline"),
                        )
                        .with_model("neural-anomaly-detector", &anomaly_model_version)
                        .with_decision("record-anomaly")
                        .with_evidence("container_id", id.clone())
                        .with_evidence("score", format!("{:.6}", score.score))
                        .with_evidence("threshold", format!("{:.6}", score.threshold))
                        .with_evidence(
                            "confidence",
                            format!(
                                "{:.6}",
                                (score.score / score.threshold.max(f32::EPSILON)).clamp(0.0, 1.0)
                            ),
                        )
                        .with_evidence("cpu_norm", format!("{:.6}", cpu_norm))
                        .with_evidence("memory_norm", format!("{:.6}", mem_norm))
                        .with_evidence("pids_norm", format!("{:.6}", pids_norm));
                        let _ = logger.log("ai_anomaly", &trace);
                    }
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
                    .with_model("resource-oom-predictor", &predictor_model_version)
                    .with_decision("record-oom-prediction")
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
                    let ceiling = std::env::var("FERROCRATE_AI_ACT_MEMORY_CEILING")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(u64::MAX);

                    if let Some(adjusted_limit) = ai_next_memory_limit(memory_limit, ceiling) {
                        let manager = CgroupV2Manager::new(&cgroup_root);
                        match manager.adjust_memory_limit(&cgroup_path, adjusted_limit) {
                            Ok(()) => {
                                info!(
                                    container = %id,
                                    new_limit_mb = adjusted_limit / 1024 / 1024,
                                    "increased memory limit"
                                );
                                if let Some(logger) = ai_logger.as_ref() {
                                    let ts = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_nanos();
                                    let trace = ferro_mind::ai::explain::DecisionTrace::new(
                                        format!("ai-memory-adjustment-{id}-{ts}"),
                                        format!(
                                            "Container {id} memory limit increased after predictive-OOM evidence"
                                        ),
                                    )
                                    .with_model("resource-oom-predictor", &predictor_model_version)
                                    .with_decision("increase-memory-limit")
                                    .with_evidence("container_id", id.clone())
                                    .with_evidence("previous_limit_bytes", memory_limit.to_string())
                                    .with_evidence("new_limit_bytes", adjusted_limit.to_string())
                                    .with_evidence("ceiling_bytes", ceiling.to_string())
                                    .with_evidence("action_enabled", "true");
                                    let _ = logger.log("ai_memory_adjustment", &trace);
                                }
                                // Keep subsequent normalization and predictions aligned
                                // with the newly applied cgroup ceiling. Otherwise the
                                // monitor would continue reasoning from a stale limit.
                                memory_limit = adjusted_limit;
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
                    } else {
                        warn!(
                            container = %id,
                            current_limit = memory_limit,
                            ceiling,
                            "skipping AI memory adjustment because the bounded limit cannot increase"
                        );
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
    use super::{
        adaptive_restart_delay, associated_network_name, immutable_image_manifest_reference,
        immutable_image_reference, validate_archive_target, BindMount, ContainerRuntime,
        KernelResourceOps, LifecyclePhaseHook, LifecyclePhasePoint, NetworkBackend,
        NoopLifecyclePhaseHook, ResourceIdentity, ResourcePlan, RuntimeError, TmpfsMount,
    };
    use crate::authorization::{
        gate::{AuthorizationGate, AuthorizedRequest},
        policy::PolicyStore,
        Action, RequestOrigin,
    };
    use crate::cgroups::{CpuMax, ResourceLimits};
    #[cfg(feature = "legacy-sled-importers")]
    use crate::container_store::LocalContainerStore;
    use crate::container_store::{
        now_unix, ContainerRecord, MutationReservation, PortMappingRecord, RestartPolicy,
    };
    use crate::image_manifest::OCI_IMAGE_MANIFEST_MEDIA_TYPE;
    use crate::image_store::LocalImageStore;
    use crate::image_tagging::canonicalize_reference;
    use crate::witness::{decode_record, JournalConfig, JournalMode, WitnessJournal, WitnessStage};
    use sha2::Digest as _;
    use std::collections::{BTreeMap, HashMap};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::{mpsc, Mutex};

    #[test]
    fn archive_targets_are_absolute_and_traversal_safe() {
        assert_eq!(
            validate_archive_target("/").expect("root target"),
            PathBuf::new()
        );
        assert_eq!(
            validate_archive_target("/var/tmp").expect("normalized target"),
            PathBuf::from("var/tmp")
        );
        for invalid in ["relative", "/var/../etc", "/var//tmp", "/var/./tmp"] {
            assert!(
                validate_archive_target(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn immutable_image_reference_uses_repository_digest_form() {
        let pinned = immutable_image_reference(
            "registry-1.docker.io/library/alpine:latest",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("stored image reference should parse");
        assert_eq!(
            pinned,
            "registry-1.docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(!pinned.contains(":latest@"));
    }

    #[test]
    fn signature_reference_uses_manifest_digest_not_config_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalImageStore::open(dir.path().join("images")).expect("store");
        let reference = canonicalize_reference("localhost:5443/example:latest").unwrap();
        let manifest = r#"{"schemaVersion":2,"config":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}"#;
        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                &reference,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                manifest,
            )
            .expect("store image");
        let actual = immutable_image_manifest_reference(&store, &reference).unwrap();
        let expected = format!(
            "localhost:5443/example@sha256:{:x}",
            sha2::Sha256::digest(manifest.as_bytes())
        );
        assert_eq!(actual, expected);
        assert!(!actual.contains("aaaaaaaa"));
    }

    #[test]
    fn adaptive_restart_decision_can_stop_restart_loop() {
        use ferro_mind::ai::restart::RestartDecision;

        assert_eq!(adaptive_restart_delay(None), Some(1));
        assert_eq!(
            adaptive_restart_delay(Some(RestartDecision::Restart)),
            Some(1)
        );
        assert_eq!(
            adaptive_restart_delay(Some(RestartDecision::RestartAfterDelay { delay_secs: 7 })),
            Some(7)
        );
        assert_eq!(
            adaptive_restart_delay(Some(RestartDecision::DoNotRestart)),
            None
        );
    }

    #[test]
    fn associated_network_name_persists_logical_name_without_changing_mode() {
        assert_eq!(
            associated_network_name(Some("app-net"), "bridge").as_deref(),
            Some("app-net")
        );
        assert_eq!(
            associated_network_name(None, "bridge").as_deref(),
            Some("bridge")
        );
        assert_eq!(
            associated_network_name(None, "host").as_deref(),
            Some("host")
        );
        assert_eq!(
            associated_network_name(None, "none").as_deref(),
            Some("none")
        );
        assert_eq!(
            associated_network_name(None, "wireguard").as_deref(),
            Some("wireguard")
        );
        assert_eq!(
            associated_network_name(Some("bridge"), "bridge").as_deref(),
            Some("bridge")
        );
        assert_eq!(
            associated_network_name(Some(""), "bridge").as_deref(),
            Some("bridge")
        );
        assert_eq!(associated_network_name(None, "managed:x"), None);
    }

    #[test]
    fn normalized_compose_run_digest_changes_with_executor_input() {
        let root = tempfile::tempdir().unwrap();
        let runtime = ContainerRuntime::new(root.path()).unwrap();
        let images = LocalImageStore::open(root.path().join("images")).unwrap();
        let labels = HashMap::new();
        let annotations = HashMap::new();
        let first = runtime
            .normalized_run_execution_digest(
                &images,
                "example/app:latest",
                &["sleep".into(), "1".into()],
                &["MODE=prod".into()],
                &labels,
                &annotations,
                None,
                &RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                true,
                None,
                None,
                Some("web"),
                &[],
                "bridge",
                NetworkBackend::Ebpf,
            )
            .unwrap();
        let changed = runtime
            .normalized_run_execution_digest(
                &images,
                "example/app:latest",
                &["sleep".into(), "2".into()],
                &["MODE=prod".into()],
                &labels,
                &annotations,
                None,
                &RestartPolicy::No,
                &[],
                None,
                &[],
                &[],
                false,
                true,
                None,
                None,
                Some("web"),
                &[],
                "bridge",
                NetworkBackend::Ebpf,
            )
            .unwrap();
        assert_ne!(first, changed);
    }

    #[test]
    fn compose_run_executor_rejects_a_mismatched_normalized_digest() {
        let root = tempfile::tempdir().unwrap();
        let runtime = ContainerRuntime::new(root.path()).unwrap();
        let images = LocalImageStore::open(root.path().join("images")).unwrap();
        let parent = RequestOrigin::cli_current().unwrap();
        let parent_id = [7; 16];
        let plan_digest = [8; 32];
        let request_digest = [9; 32];
        let mut idem = sha2::Sha256::new();
        idem.update(b"ferrocrate/compose-idempotency/v1");
        idem.update(parent_id);
        idem.update(plan_digest);
        idem.update(0u32.to_be_bytes());
        idem.update([1]);
        idem.update(3u64.to_be_bytes());
        idem.update(b"web");
        idem.update(request_digest);
        let idempotency_key: [u8; 32] = idem.finalize().into();
        let mut child = sha2::Sha256::new();
        child.update(b"ferrocrate/compose-child/v1");
        child.update(idempotency_key);
        child.update(0u32.to_be_bytes());
        let child_hash: [u8; 32] = child.finalize().into();
        let mut child_id = [0; 16];
        child_id.copy_from_slice(&child_hash[..16]);
        let (generation, policy_digest) = runtime.policy_binding();
        let scoped = runtime.request_scoped(RequestOrigin::compose_child(
            &parent,
            child_id,
            parent_id,
            idempotency_key,
            Action::ContainerRun,
            "web",
            request_digest,
            u64::MAX,
            generation,
            policy_digest,
            0,
            0,
            plan_digest,
        ));
        let error = scoped
            .run_with_store(
                &images,
                "example/app:latest",
                &["true".into()],
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
                true,
                None,
                None,
                Some("web"),
                &[],
                "bridge",
                None,
                NetworkBackend::Ebpf,
                None,
            )
            .expect_err("substituted executor input must fail before effect");
        assert!(matches!(error, RuntimeError::Authorization(_)));
    }

    struct DeterministicKernelResourceOps {
        state: PathBuf,
    }

    impl DeterministicKernelResourceOps {
        fn load(&self) -> BTreeMap<String, ResourceIdentity> {
            std::fs::read(&self.state)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default()
        }
        fn save(&self, state: &BTreeMap<String, ResourceIdentity>) -> Result<(), RuntimeError> {
            std::fs::write(&self.state, serde_json::to_vec(state).unwrap())?;
            Ok(())
        }
        fn apply(&self, path: &Path) -> Result<(), RuntimeError> {
            std::fs::create_dir_all(path)?;
            let metadata = std::fs::metadata(path)?;
            let mut state = self.load();
            let mount_id = 10_000 + state.len() as u64;
            state.insert(
                path.display().to_string(),
                ResourceIdentity::Path {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    mount_id: Some(mount_id),
                },
            );
            self.save(&state)
        }
        fn network_state_path(&self) -> PathBuf {
            self.state.with_extension("network.json")
        }
    }

    impl KernelResourceOps for DeterministicKernelResourceOps {
        fn apply_bind(&self, rootfs: &Path, mount: &BindMount) -> Result<(), RuntimeError> {
            self.apply(&rootfs.join(&mount.target))
        }
        fn apply_tmpfs(&self, rootfs: &Path, mount: &TmpfsMount) -> Result<(), RuntimeError> {
            self.apply(&rootfs.join(&mount.target))
        }
        fn apply_readonly(&self, rootfs: &Path) -> Result<(), RuntimeError> {
            self.apply(rootfs)
        }
        fn identity(&self, path: &Path) -> Result<ResourceIdentity, RuntimeError> {
            if let Some(identity) = self.load().get(&path.display().to_string()) {
                return Ok(identity.clone());
            }
            super::path_resource_identity(path)
        }
        fn detach_owned(
            &self,
            rootfs: &Path,
            target: &Path,
            expected: &ResourceIdentity,
        ) -> Result<(), RuntimeError> {
            let path = if target == Path::new(".") {
                rootfs.to_path_buf()
            } else {
                rootfs.join(target)
            };
            let mut state = self.load();
            if state.get(&path.display().to_string()) != Some(expected) {
                return Err(RuntimeError::InvalidState(
                    "fake mount identity changed".into(),
                ));
            }
            state.remove(&path.display().to_string());
            self.save(&state)
        }
        fn observe_unmarked(
            &self,
            rootfs: &Path,
            target: &Path,
            _baseline: (u64, u64, Option<u64>),
            _source: Option<(u64, u64, Option<u64>)>,
            _fs_type: Option<&str>,
        ) -> Result<Option<ResourceIdentity>, ()> {
            let path = if target == Path::new(".") {
                rootfs.to_path_buf()
            } else {
                rootfs.join(target)
            };
            Ok(self.load().get(&path.display().to_string()).cloned())
        }
        fn setup_network(
            &self,
            proof: &AuthorizedRequest,
            intent: Option<&crate::witness::DurableIntent>,
            container_id: &str,
            _ports: &[PortMappingRecord],
            mode: &str,
            backend: NetworkBackend,
            rollback: &mut super::CreationRollback,
            _existing: &[ContainerRecord],
            phase_hook: &dyn LifecyclePhaseHook,
        ) -> Result<super::NetworkSetup, RuntimeError> {
            if !mode.starts_with("managed:") {
                return super::setup_network(
                    proof,
                    intent,
                    container_id,
                    &[],
                    mode,
                    backend,
                    rollback,
                    &[],
                );
            }
            let identity = crate::container_store::KernelObjectIdentityRecord {
                device: 77,
                inode: 88,
            };
            let ownership: crate::container_store::NetworkOwnershipRecord =
                serde_json::from_value(serde_json::json!({
                    "schema_version": 2,
                    "owner_id": container_id,
                    "network_id": mode.strip_prefix("managed:"),
                    "host_interface": format!("fake-{container_id}"),
                    "host_ifindex": 42,
                    "namespace_identity": { "device": 77, "inode": 88 },
                    "firewall_id": format!("fw-{container_id}"),
                    "firewall_marker": format!("ferrocrate:{container_id}")
                }))
                .unwrap();
            std::fs::write(
                self.network_state_path(),
                serde_json::to_vec(&ownership).unwrap(),
            )?;
            phase_hook.reached(
                "run",
                LifecyclePhasePoint::NetworkResourcesCreatedBeforeOwnership,
            )?;
            rollback.netns_name = Some(format!("fake-{container_id}"));
            rollback.namespace_identity = Some(identity);
            rollback.network_backend = Some(backend);
            rollback.network_ownership = Some(ownership.clone());
            rollback.persist_cleanup_journal()?;
            std::fs::write(self.state.with_extension("network-owned"), b"owned")?;
            Ok(super::NetworkSetup {
                netns_name: rollback.netns_name.clone(),
                namespace_owned: true,
                namespace_identity: rollback.namespace_identity,
                container_ip: Some("192.0.2.2".into()),
                container_ipv6: None,
                backend: Some(backend),
                ownership: Some(ownership),
                ebpf_network: None,
                managed_overlay: Some("test".into()),
                managed_cleanup_provenance: None,
                managed_host_veth: Some(format!("fake-{container_id}")),
            })
        }
        fn cleanup_test_network(
            &self,
            rollback: &mut super::CreationRollback,
        ) -> Option<Result<(), RuntimeError>> {
            let path = self.network_state_path();
            if !path.exists() {
                return Some(Ok(()));
            }
            let observed: crate::container_store::NetworkOwnershipRecord =
                match std::fs::read(&path)
                    .map_err(RuntimeError::from)
                    .and_then(|bytes| {
                        serde_json::from_slice(&bytes)
                            .map_err(|e| RuntimeError::Network(e.to_string()))
                    }) {
                    Ok(value) => value,
                    Err(error) => return Some(Err(error)),
                };
            let planned = rollback.resource_plans.iter().any(|plan| {
                matches!(
                    plan,
                    ResourcePlan::NetworkAllocation { canonical, operation_id, .. }
                        if canonical == "managed:test:iptables"
                            && *operation_id == rollback.operation_id
                )
            });
            if observed.owner_id != rollback.container_id
                || (!planned && rollback.network_ownership.as_ref() != Some(&observed))
            {
                return Some(Err(RuntimeError::InvalidState(
                    "fake network ownership changed".into(),
                )));
            }
            let result = std::fs::remove_file(path).map_err(RuntimeError::from);
            let _ = std::fs::remove_file(self.state.with_extension("network-owned"));
            Some(result)
        }
    }

    static RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());
    use crate::test_support::ENV_LOCK as CGROUP_ENV_LOCK;

    struct ProcessBarrier {
        action: String,
        phase: LifecyclePhasePoint,
        signal_socket: std::path::PathBuf,
    }

    impl LifecyclePhaseHook for ProcessBarrier {
        fn reached(&self, action: &str, phase: LifecyclePhasePoint) -> Result<(), RuntimeError> {
            if action == self.action && phase == self.phase {
                signal_barrier(&self.signal_socket, "ready")?;
                loop {
                    std::thread::park();
                }
            }
            Ok(())
        }
    }

    /// Sends exactly one lifecycle status over the parent's pre-bound socket.
    /// Connecting is itself the readiness handshake: unlike a filesystem poll, it
    /// cannot be observed before the child has reached the requested phase.
    fn signal_barrier(socket: &Path, status: &str) -> Result<(), RuntimeError> {
        let mut stream = UnixStream::connect(socket)?;
        stream.write_all(status.as_bytes())?;
        Ok(())
    }

    #[test]
    fn process_barrier_reports_ready_over_its_unix_socket() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("barrier.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let barrier = ProcessBarrier {
            action: "run".into(),
            phase: LifecyclePhasePoint::BindKernelEffect,
            signal_socket: socket,
        };
        std::thread::spawn(move || {
            let _ = barrier.reached("run", LifecyclePhasePoint::BindKernelEffect);
        });
        let (mut stream, _) = listener.accept().unwrap();
        let mut signal = String::new();
        std::io::Read::read_to_string(&mut stream, &mut signal).unwrap();
        assert_eq!(signal, "ready");
    }

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
                NetworkBackend::Iptables,
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
                NetworkBackend::Iptables,
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
                NetworkBackend::Iptables,
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
        let workdir = "/app";

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
                Some(workdir),
                Some("1000:1000"),
                Some("named"),
                &[],
                "bridge",
                NetworkBackend::Iptables,
                None,
            )
            .expect("run");

        assert!(record.env.contains(&"A=override".to_string()));
        assert!(record.env.contains(&"B=2".to_string()));
        assert!(record.env.contains(&"C=3".to_string()));
        assert_eq!(record.workdir.as_deref(), Some(workdir));
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
                &["sh".to_string(), "-c".to_string(), "sleep 10".to_string()],
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
                NetworkBackend::Iptables,
                None,
            )
            .expect("run");

        // Allow the launch supervisor to publish the stable running identity
        // before the next authorized lifecycle mutation.
        std::thread::sleep(std::time::Duration::from_millis(50));
        runtime
            .stop(&record.id, std::time::Duration::from_millis(50))
            .expect("stop");

        runtime.start(&record.id).expect("start");
        assert_eq!(
            runtime.inspect(&record.id).expect("inspect").status,
            "running"
        );
        runtime
            .stop(&record.id, std::time::Duration::from_millis(50))
            .expect("stop after start");

        runtime.remove(&record.id).expect("remove");

        let listed = runtime.list().expect("list");
        assert!(listed.iter().all(|c| c.id != record.id));
    }

    #[test]
    fn container_names_are_deterministic_and_path_safe() {
        for valid in ["web", "web_1", "web-1.2", "A9"] {
            super::validate_container_name(valid).expect("valid container name");
        }
        for invalid in ["", ".", "..", "-web", "web/name", "web name", "web$name"] {
            assert!(
                super::validate_container_name(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
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
                NetworkBackend::Iptables,
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
        let store = crate::sqlite_container_store::SqliteContainerStore::open(
            temp.path().join("containers.db"),
        )
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
            managed_overlay: None,
            managed_cleanup_provenance: None,
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
        let store = crate::sqlite_container_store::SqliteContainerStore::open(
            temp.path().join("containers.db"),
        )
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
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
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
                NetworkBackend::Iptables,
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
    fn configured_cgroup_root_honors_explicit_override() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let override_root = tempfile::tempdir().expect("cgroup root");
        unsafe {
            std::env::set_var("FERROCRATE_CGROUP_ROOT", override_root.path());
        }
        assert_eq!(super::configured_cgroup_root(), override_root.path());
        unsafe {
            std::env::remove_var("FERROCRATE_CGROUP_ROOT");
        }
    }

    #[test]
    fn current_cgroup_relative_path_accepts_v2_and_rejects_traversal() {
        assert_eq!(
            super::current_cgroup_relative_path(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice\n"
            ),
            Some("/user.slice/user-1000.slice/user@1000.service/app.slice".to_string())
        );
        assert_eq!(
            super::current_cgroup_relative_path("0::/user.slice/../escape\n"),
            None
        );
        assert_eq!(super::current_cgroup_relative_path(""), None);
    }

    #[test]
    fn delegated_cgroup_root_falls_back_from_leaf_to_enabled_ancestor() {
        let hierarchy = tempfile::tempdir().expect("hierarchy");
        let parent = hierarchy
            .path()
            .join("user.slice/user-1000.slice/user@1000.service/app.slice");
        let leaf = parent.join("app-ghostty.scope");
        std::fs::create_dir_all(&leaf).expect("cgroup tree");
        std::fs::write(parent.join("cgroup.subtree_control"), "+memory +pids\n")
            .expect("parent delegation");
        std::fs::write(leaf.join("cgroup.subtree_control"), "\n").expect("leaf controls");

        assert_eq!(
            super::select_delegated_cgroup_root(
                hierarchy.path(),
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-ghostty.scope"
            ),
            Some(parent)
        );
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
                NetworkBackend::Iptables,
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
            crate::authorization::AuthorizationMode::Disabled,
        )
        .unwrap();
        if nix::unistd::Uid::effective().is_root() {
            assert!(request.bind_mounts[0].source.starts_with("/proc/self/fd/"));
        } else {
            assert!(!request.bind_mounts[0].source.starts_with("/proc/self/fd/"));
            assert!(request.bind_mounts[0].source.is_absolute());
        }
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
                crate::authorization::AuthorizationMode::Disabled,
            );
            assert!(result.is_err(), "accepted target {target:?}");
        }
    }

    #[test]
    fn mount_source_approval_is_a_canonical_policy_fact() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let temp = tempfile::tempdir().unwrap();
        let approved = temp.path().join("approved");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&approved).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::env::set_var("FERROCRATE_APPROVED_MOUNT_ROOTS", &approved);
        let normalize = |source| {
            super::normalize_run_request(
                &[],
                &[crate::mounts::BindMount {
                    source,
                    target: "data".into(),
                    read_only: true,
                }],
                &[],
                false,
                true,
                "none",
                ferro_net::NetworkBackend::Iptables,
                &[],
                crate::authorization::AuthorizationMode::Enforce,
            )
        };
        std::fs::create_dir(approved.join("source")).unwrap();
        assert_eq!(
            normalize(approved.join("source"))
                .unwrap()
                .facts
                .mount_sources_approved,
            Some(true)
        );
        std::os::unix::fs::symlink(&outside, approved.join("link")).unwrap();
        assert_eq!(
            normalize(approved.join("link"))
                .unwrap()
                .facts
                .mount_sources_approved,
            Some(false)
        );
        assert_eq!(
            normalize(outside).unwrap().facts.mount_sources_approved,
            Some(false)
        );
        std::env::remove_var("FERROCRATE_APPROVED_MOUNT_ROOTS");
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
            namespace_owned: true,
            namespace_identity: None,
            network_name: Some("bridge".to_string()),
            ip_address: Some("10.44.1.2".to_string()),
            ipv6_address: None,
            ports: Vec::new(),
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            readonly_rootfs: false,
            no_new_privileges: false,
            resource_limits: None,
            network_backend: None,
            network_ownership: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
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
    fn network_backend_route_localnet_restores_only_its_owned_transition() {
        let mut store = FakeGlobalValueStore {
            value: "0".to_string(),
            ..FakeGlobalValueStore::default()
        };
        let ownership = super::acquire_route_localnet_with("ferro0", &mut store)
            .unwrap()
            .expect("0 to 1 transition is owned");
        assert_eq!(ownership.interface, "ferro0");
        assert_eq!(store.value, "1");
        let mut restored = FakeGlobalValueStore {
            value: store.value,
            ..FakeGlobalValueStore::default()
        };
        super::restore_route_localnet_with(&ownership, &mut restored).unwrap();
        assert_eq!(restored.value, "0");
    }

    #[test]
    fn network_backend_route_localnet_rejects_foreign_replacement() {
        let mut store = FakeGlobalValueStore {
            value: "0".to_string(),
            ..FakeGlobalValueStore::default()
        };
        let ownership = super::acquire_route_localnet_with("ferro0", &mut store)
            .unwrap()
            .unwrap();
        store.value = "2".to_string();
        let current = store.value.clone();
        assert!(super::restore_route_localnet_with(&ownership, &mut store).is_err());
        assert_eq!(store.value, current);
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
            namespace_owned: true,
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
            route_localnet: None,
            pending_firewall_cleanup: Vec::new(),
            operation_id: None,
            cgroup_name: None,
            cgroup_generation: None,
            planned_resources: Default::default(),
            applied_resources: Default::default(),
            resource_plans: Vec::new(),
            typed_applied_resources: Vec::new(),
            creation_provenance: Default::default(),
        };
        std::fs::write(
            container_dir.join("network-cleanup-pending.json"),
            serde_json::to_vec(&pending).unwrap(),
        )
        .unwrap();
        let store = crate::sqlite_container_store::SqliteContainerStore::open(
            temp.path().join("containers.db"),
        )
        .unwrap();

        let authorization =
            crate::authorization::runtime::RuntimeAuthorization::compatibility_with_id([1; 16]);
        super::recover_pending_network_cleanups(
            temp.path(),
            &store,
            temp.path(),
            &authorization,
            std::sync::Arc::new(super::ProductionKernelResourceOps),
        )
        .unwrap();
        assert!(container_dir.exists());
    }

    #[test]
    fn network_setup_isolated_marks_namespace_as_owned() {
        let setup = super::NetworkSetup::isolated(
            Some("ferro-test-netns".to_string()),
            Some("192.0.2.10".to_string()),
            None,
        );
        assert!(setup.namespace_owned);
        assert_eq!(setup.netns_name.as_deref(), Some("ferro-test-netns"));
    }

    #[test]
    fn pending_cleanup_preserves_shared_namespace_non_ownership() {
        let pending = super::PendingNetworkCleanup {
            schema_version: 1,
            container_id: "shared-netns".to_string(),
            netns_name: Some("cri-sandbox-1".to_string()),
            namespace_owned: false,
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
            route_localnet: None,
            pending_firewall_cleanup: Vec::new(),
            operation_id: None,
            cgroup_name: None,
            cgroup_generation: None,
            planned_resources: Default::default(),
            applied_resources: Default::default(),
            resource_plans: Vec::new(),
            typed_applied_resources: Vec::new(),
            creation_provenance: Default::default(),
        };
        let encoded = serde_json::to_vec(&pending).unwrap();
        let decoded: super::PendingNetworkCleanup = serde_json::from_slice(&encoded).unwrap();
        assert!(!decoded.namespace_owned);
        assert_eq!(decoded.netns_name.as_deref(), Some("cri-sandbox-1"));
    }

    #[test]
    fn typed_mount_ledger_detaches_owned_mounts_in_reverse_order() {
        if !nix::unistd::Uid::effective().is_root() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let container_dir = temp.path().join("container");
        let rootfs = container_dir.join("rootfs");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let provenance = crate::container_store::CreationProvenance {
            creator_operation_id: Some([8; 16]),
            resource_generation: 1,
            ..crate::container_store::CreationProvenance::default()
        };
        let mut rollback = super::CreationRollback::new(
            "mount-ledger",
            temp.path().into(),
            provenance,
            std::sync::Arc::new(super::ProductionKernelResourceOps),
        );
        rollback.track_container_dir(container_dir);
        let root_plan = rollback
            .plan_typed_resource(super::ResourcePlan::Rootfs {
                path: rootfs.clone(),
                generation: 1,
                operation_id: Some([8; 16]),
            })
            .unwrap();
        rollback
            .mark_typed_resource(root_plan, super::path_resource_identity(&rootfs).unwrap())
            .unwrap();
        let bind = crate::mounts::BindMount {
            source,
            target: "bind".into(),
            read_only: false,
        };
        let _ = crate::mounts::open_mount_target_beneath(&rootfs, &bind.target).unwrap();
        let bind_baseline = std::fs::metadata(rootfs.join(&bind.target)).unwrap();
        let source_identity = std::fs::metadata(&bind.source).unwrap();
        let bind_plan = rollback
            .plan_typed_resource(super::ResourcePlan::BindMount {
                target: bind.target.clone(),
                generation: 1,
                source_device: source_identity.dev(),
                source_inode: source_identity.ino(),
                baseline_device: bind_baseline.dev(),
                baseline_inode: bind_baseline.ino(),
                baseline_mount_id: super::mount_id_for_path(&rootfs.join(&bind.target)).unwrap(),
                operation_id: Some([8; 16]),
            })
            .unwrap();
        if let Err(error) =
            crate::mounts::apply_authorized_bind_mounts(&rootfs, std::slice::from_ref(&bind))
        {
            eprintln!("SKIP: mount namespace unavailable: {error}");
            return;
        }
        rollback
            .mark_typed_resource(
                bind_plan,
                super::path_resource_identity(&rootfs.join("bind")).unwrap(),
            )
            .unwrap();
        let tmpfs = crate::mounts::TmpfsMount {
            target: "tmp".into(),
            size: Some("1m".into()),
        };
        let _ = crate::mounts::open_mount_target_beneath(&rootfs, &tmpfs.target).unwrap();
        let tmpfs_baseline = std::fs::metadata(rootfs.join(&tmpfs.target)).unwrap();
        let tmpfs_plan = rollback
            .plan_typed_resource(super::ResourcePlan::TmpfsMount {
                target: tmpfs.target.clone(),
                generation: 1,
                baseline_device: tmpfs_baseline.dev(),
                baseline_inode: tmpfs_baseline.ino(),
                baseline_mount_id: super::mount_id_for_path(&rootfs.join(&tmpfs.target)).unwrap(),
                operation_id: Some([8; 16]),
            })
            .unwrap();
        crate::mounts::apply_tmpfs_mounts(&rootfs, std::slice::from_ref(&tmpfs)).unwrap();
        rollback
            .mark_typed_resource(
                tmpfs_plan,
                super::path_resource_identity(&rootfs.join("tmp")).unwrap(),
            )
            .unwrap();
        rollback.rollback();
        assert!(!super::has_live_mount_beneath(&rootfs));
        assert!(!rollback.cleanup_quarantined);
    }

    #[test]
    fn deterministic_resource_adapter_enforces_reverse_applied_order() {
        let resources = (0..4)
            .map(|plan_index| super::AppliedResource {
                plan_index,
                identity: super::ResourceIdentity::Network { identity: None },
            })
            .collect::<Vec<_>>();
        assert_eq!(
            super::resource_cleanup_order(&resources)
                .map(|resource| resource.plan_index)
                .collect::<Vec<_>>(),
            vec![3, 2, 1, 0]
        );
    }

    #[test]
    fn unmarked_mount_plan_classifies_unchanged_or_quarantines_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("container/rootfs");
        let target = rootfs.join("data");
        let source = temp.path().join("source");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let baseline = std::fs::metadata(&target).unwrap();
        let baseline_mount_id = super::mount_id_for_path(&target).unwrap();
        let source_identity = std::fs::metadata(&source).unwrap();
        let plan = super::ResourcePlan::BindMount {
            target: "data".into(),
            generation: 1,
            source_device: source_identity.dev(),
            source_inode: source_identity.ino(),
            baseline_device: baseline.dev(),
            baseline_inode: baseline.ino(),
            baseline_mount_id,
            operation_id: Some([9; 16]),
        };
        assert!(super::classify_unmarked_mount(
            Some(&rootfs),
            std::path::Path::new("data"),
            (baseline.dev(), baseline.ino(), baseline_mount_id),
            Some((source_identity.dev(), source_identity.ino(), None)),
            None,
        )
        .unwrap()
        .is_none());
        std::fs::remove_dir(&target).unwrap();
        std::fs::create_dir(&target).unwrap();
        assert!(super::classify_unmarked_mount(
            Some(&rootfs),
            match &plan {
                super::ResourcePlan::BindMount { target, .. } => target,
                _ => unreachable!(),
            },
            (baseline.dev(), baseline.ino(), baseline_mount_id),
            Some((source_identity.dev(), source_identity.ino(), None)),
            None,
        )
        .is_err());
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
            let runtime = ContainerRuntime::new(temp.path()).unwrap();
            runtime
                .store
                .put(&fixture_container_record(status, status))
                .unwrap();
            let error = runtime.reconcile_persisted_state().unwrap_err();
            assert!(
                error.to_string().contains("ownership"),
                "status {status}: {error}"
            );
        }
    }

    #[test]
    fn startup_reconciliation_defers_pending_running_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = ContainerRuntime::new(temp.path()).unwrap();
        let operation_id = [17u8; 16];
        let mut record = fixture_container_record("pending-running", "running");
        record.network_name = Some("none".to_string());
        record.namespace_owned = false;
        record.pending_mutation = Some(MutationReservation {
            operation_id,
            generation: record.mutation_generation,
            expected_status: "created".to_string(),
            action: "container.run".to_string(),
        });
        runtime.store.put_reserved_creation(&record).unwrap();

        runtime.reconcile_persisted_state().unwrap();
        let stored = runtime.store.get("pending-running").unwrap().unwrap();
        assert_eq!(stored.status, "running");
        assert_eq!(stored.pending_mutation.unwrap().operation_id, operation_id);
    }

    #[test]
    fn network_backend_legacy_nonbridge_namespace_is_retained_without_identity() {
        let mut record = fixture_container_record("legacy-none", "stopped");
        record.network_name = Some("none".to_string());
        record.netns = Some("must-not-delete-by-name".to_string());

        let error =
            super::cleanup_network(None, &record, std::slice::from_ref(&record)).unwrap_err();
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
            if matches!(action, Some("-N" | "-A" | "-I")) {
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
                Some("-A" | "-I") => self.live.push(command.to_vec()),
                Some("-X" | "-D") => {
                    let chain = command.get(4);
                    let marker = &command[5..];
                    if let Some(index) = self.live.iter().position(|existing| {
                        existing.get(4) == chain
                            && if action == Some("-X") {
                                existing.get(3).map(String::as_str) == Some("-N")
                            } else {
                                matches!(existing.get(3).map(String::as_str), Some("-A" | "-I"))
                                    && (existing.get(3).map(String::as_str) == Some("-A")
                                        && existing.get(5..).is_some_and(|args| args == marker)
                                        || existing.get(3).map(String::as_str) == Some("-I")
                                            && existing.get(6..).is_some_and(|args| args == marker))
                            }
                    }) {
                        self.live.remove(index);
                    }
                }
                Some("-F") => {
                    self.live.retain(|existing| {
                        existing.get(1) != command.get(1)
                            || existing.get(2) != command.get(2)
                            || !matches!(existing.get(3).map(String::as_str), Some("-A" | "-I"))
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
    fn orphaned_ebpf_state_rejects_live_filters_without_a_pin_root() {
        let root = tempfile::tempdir().unwrap();
        let filter = crate::container_store::EbpfFilterOwnershipRecord {
            interface: Some("lo".to_string()),
            interface_ifindex: Some(1),
            direction: "ingress".to_string(),
            priority: 49_152,
            handle: "0x1".to_string(),
            program_id: Some(71),
            program_tag: Some("aabbccdd".to_string()),
        };

        let error = super::validate_orphaned_ebpf_state(root.path(), &[filter])
            .expect_err("live classifiers without pins must fail closed");
        assert!(error.to_string().contains("live classifiers"));
        super::validate_orphaned_ebpf_state(root.path(), &[])
            .expect("an empty pin root with no live classifiers is safe");
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
    fn ebpf_published_ports_fail_closed_without_explicit_override() {
        let mapping = [PortMappingRecord {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".into(),
        }];
        unsafe { std::env::remove_var("FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS") };
        let error = super::validate_ebpf_published_port_boundary(NetworkBackend::Ebpf, &mapping)
            .expect_err("live eBPF published ports must remain gated");
        assert!(error
            .to_string()
            .contains("pending live checksum qualification"));
        super::validate_ebpf_published_port_boundary(NetworkBackend::Iptables, &mapping)
            .expect("iptables remains the explicit supported fallback");
        unsafe { std::env::set_var("FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS", "1") };
        super::validate_ebpf_published_port_boundary(NetworkBackend::Ebpf, &mapping)
            .expect("experimental override should be explicit");
        unsafe { std::env::remove_var("FERROCRATE_EBPF_ALLOW_PUBLISHED_PORTS") };
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
    fn rootless_bridge_requires_explicit_slirp_enablement() {
        let err = super::validate_rootless_bridge_network(false, &[], NetworkBackend::Iptables)
            .expect_err("rootless networking must be opt-in");
        assert!(err.to_string().contains("FERROCRATE_ROOTLESS_NETNS=1"));
    }

    #[test]
    fn rootless_bridge_accepts_supported_host_port_mapping() {
        super::validate_rootless_bridge_network(
            true,
            &[PortMappingRecord {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".into(),
            }],
            NetworkBackend::Iptables,
        )
        .expect("supported slirp forwarding should be admitted");
    }

    #[test]
    fn rootless_bridge_accepts_slirp_without_privileged_mutations() {
        super::validate_rootless_bridge_network(true, &[], NetworkBackend::Nftables)
            .expect("enabled slirp bridge should be admitted");
    }

    #[test]
    fn rootless_mount_requests_fail_before_kernel_mutation() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let mount = BindMount {
            source: PathBuf::from("/tmp/source"),
            target: PathBuf::from("data"),
            read_only: false,
        };
        let result = super::validate_rootless_mount_capability(true, &[mount], &[], false);
        if super::command_available("bwrap") && super::rootless_mount_namespace_available() {
            result.expect("capable hosts should admit rootless bind mounts");
        } else {
            let error = result.expect_err("rootless bind mount must fail closed before setup");
            assert!(error.to_string().contains("mount-capable user namespace"));
        }
        super::validate_rootless_mount_capability(false, &[], &[], true)
            .expect("rootful read-only rootfs remains supported");
    }

    #[test]
    fn rootless_bwrap_command_contains_mount_and_readonly_boundary() {
        if !super::command_available("bwrap") {
            return;
        }
        let command = super::build_bwrap_command(
            Path::new("/"),
            &["/bin/true".into()],
            &[BindMount {
                source: PathBuf::from("/tmp"),
                target: PathBuf::from("data"),
                read_only: true,
            }],
            &[],
            true,
        )
        .expect("bubblewrap command");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args
            .windows(3)
            .any(|window| { window == ["--ro-bind", "/tmp", "/data"] }));
        assert!(args
            .windows(2)
            .any(|window| window == ["--remount-ro", "/"]));
        assert_eq!(args.last().map(String::as_str), Some("/bin/true"));
    }

    #[test]
    fn rootless_command_creates_user_and_network_namespaces_together() {
        let command = super::build_command(
            &["/bin/true".into()],
            &[],
            None,
            false,
            &[],
            None,
            None,
            None,
            true,
            None,
            &[],
            &[],
            false,
        )
        .expect("rootless command");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.len() >= 9);
        assert!(args[args.len() - 9].ends_with("/unshare"));
        assert_eq!(
            &args[args.len() - 8..args.len() - 5],
            ["--user", "--net", "--"]
        );
        assert!(args[args.len() - 5].ends_with("/sh"));
        assert_eq!(args[args.len() - 4], "-c");
        assert_eq!(args[args.len() - 3], "kill -STOP $$; exec \"$@\"");
        assert_eq!(args[args.len() - 1], "/bin/true");
        assert!(args.iter().any(|arg| arg == "ferrocrate-rootless"));
    }

    #[test]
    fn rootless_command_applies_no_new_privileges_inside_namespace() {
        let command = super::build_command(
            &["/bin/true".into()],
            &[],
            None,
            true,
            &[],
            None,
            None,
            None,
            true,
            None,
            &[],
            &[],
            false,
        )
        .expect("rootless command");
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.len() >= 9);
        assert!(args[args.len() - 9].ends_with("/unshare"));
        assert_eq!(
            &args[args.len() - 8..args.len() - 5],
            ["--user", "--net", "--"]
        );
        assert!(args[args.len() - 5].ends_with("/sh"));
        assert_eq!(args[args.len() - 4], "-c");
        assert!(args[args.len() - 3].starts_with("kill -STOP $$; exec "));
        assert!(args[args.len() - 3].ends_with(" --no-new-privs -- \"$@\""));
        assert_eq!(args[args.len() - 1], "/bin/true");
        assert!(args.iter().any(|arg| arg == "ferrocrate-rootless"));
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
        let store =
            crate::sqlite_container_store::SqliteContainerStore::open(temp.path()).expect("store");
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
            namespace_owned: true,
            namespace_identity: None,
            network_name: Some("bridge".to_string()),
            ip_address: Some("10.0.0.2".to_string()),
            ipv6_address: None,
            ports: vec![PortMappingRecord {
                host_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            }],
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            readonly_rootfs: false,
            no_new_privileges: false,
            resource_limits: None,
            network_backend: None,
            network_ownership: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
            managed_overlay: None,
            managed_cleanup_provenance: None,
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
    fn veth_mtu_validation_rejects_unsafe_values() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        unsafe { std::env::set_var("FERROCRATE_VETH_MTU", "500") };
        let error = super::configured_veth_mtu().expect_err("invalid MTU");
        assert!(error.to_string().contains("between 576 and 65535"));
        unsafe { std::env::remove_var("FERROCRATE_VETH_MTU") };
    }

    #[test]
    fn qdisc_readback_requires_the_requested_rate() {
        let output = "qdisc tbf 1: root refcnt 2 rate 100mbit burst 32Kb lat 400.0ms";
        assert!(super::qdisc_reports_rate(output, "100mbit"));
        assert!(!super::qdisc_reports_rate(output, "1gbit"));
        assert!(!super::qdisc_reports_rate(
            "qdisc pfifo_fast 0: root",
            "100mbit"
        ));
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
    fn security_ebpf_admission_bounds_events_and_paths() {
        super::validate_security_ebpf_config(
            "/usr/lib/ferrocrate/ferro-security.o",
            "/sys/fs/bpf/ferrocrate-security-c1",
            &["execve".into(), "connect".into()],
        )
        .expect("valid security monitor configuration");
        let too_many = (0..33)
            .map(|index| format!("event{index}"))
            .collect::<Vec<_>>();
        assert!(super::validate_security_ebpf_config(
            "/usr/lib/ferrocrate/ferro-security.o",
            "/sys/fs/bpf/ferrocrate-security-c1",
            &too_many,
        )
        .is_err());
        assert!(super::validate_security_ebpf_config(
            "relative.o",
            "/sys/fs/bpf/ferrocrate-security-c1",
            &["execve".into()],
        )
        .is_err());
        assert!(super::validate_security_ebpf_config(
            "/usr/lib/ferrocrate/ferro-security.o",
            "/sys/fs/bpf/ferrocrate-security-c1",
            &["execve/open".into()],
        )
        .is_err());
        let traversal = super::validate_security_ebpf_config(
            "/usr/lib/ferrocrate/ferro-security.o",
            "/sys/fs/bpf/ferrocrate-security/../foreign",
            &["execve".into()],
        )
        .expect_err("pin-root traversal must be rejected");
        assert!(traversal.to_string().contains("dot path components"));
        let curdir = super::validate_security_ebpf_config(
            "/usr/lib/ferrocrate/ferro-security.o",
            "/sys/fs/bpf/./ferrocrate-security-c1",
            &["execve".into()],
        )
        .expect_err("pin-root dot component must be rejected");
        assert!(curdir.to_string().contains("dot path components"));
        let duplicate = vec!["execve".to_string(), "EXECVE".to_string()];
        let error = super::validate_security_ebpf_config(
            "/usr/lib/ferrocrate/ferro-security.o",
            "/sys/fs/bpf/ferrocrate-security-c1",
            &duplicate,
        )
        .expect_err("case-insensitive duplicate events must be rejected");
        assert!(error.to_string().contains("must be unique"));
    }

    #[test]
    fn security_ebpf_audit_message_is_bounded_and_deterministic() {
        let events = (0..40)
            .map(|index| format!("event{index}"))
            .collect::<Vec<_>>();
        let message = super::security_monitor_audit_message("attached", &events);
        assert_eq!(
            message,
            format!(
                "phase=attached events={}",
                (0..32)
                    .map(|index| format!("event{index}"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        );
        assert!(!message.contains("event32"));
    }

    #[test]
    fn security_ebpf_object_preflight_rejects_missing_or_non_file_artifacts() {
        let missing = format!(
            "/tmp/ferrocrate-security-object-missing-{}",
            std::process::id()
        );
        let error = super::validate_security_ebpf_object(&missing)
            .expect_err("missing security object must fail before bpftool");
        assert!(error.to_string().contains("object unavailable"));

        let error = super::validate_security_ebpf_object("/tmp")
            .expect_err("directory cannot be loaded as a security object");
        assert!(error.to_string().contains("regular file"));
    }

    #[test]
    fn security_ebpf_pin_root_preflight_rejects_missing_or_non_directory_paths() {
        let missing = format!(
            "/tmp/ferrocrate-security-pin-root-missing-{}",
            std::process::id()
        );
        let error = super::validate_security_ebpf_pin_root(&missing)
            .expect_err("missing pin root must fail before bpftool");
        assert!(error.to_string().contains("pin root unavailable"));

        let error = super::validate_security_ebpf_pin_root("/etc/hosts")
            .expect_err("file cannot be used as a pin root");
        assert!(error.to_string().contains("must be a directory"));
    }

    #[test]
    fn ai_disabled_never_starts_resource_monitor() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous = std::env::var("FERROCRATE_AI").ok();
        unsafe {
            std::env::set_var("FERROCRATE_AI", "0");
        }
        assert!(!super::is_ai_enabled());
        assert!(!super::should_start_ai_monitor(1024));
        assert!(!super::should_start_ai_monitor(0));
        unsafe {
            std::env::set_var("FERROCRATE_AI", "1");
        }
        assert!(super::is_ai_enabled());
        assert!(super::should_start_ai_monitor(1024));
        assert!(!super::should_start_ai_monitor(0));
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI") },
        }
    }

    #[test]
    fn ai_is_enabled_by_default_and_explicitly_opt_out() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous = std::env::var("FERROCRATE_AI").ok();
        unsafe {
            std::env::remove_var("FERROCRATE_AI");
        }
        assert!(super::is_ai_enabled());
        unsafe {
            std::env::set_var("FERROCRATE_AI", "false");
        }
        assert!(!super::is_ai_enabled());
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI") },
        }
    }

    #[test]
    fn ai_memory_adjustment_is_bounded_and_never_reduces_limit() {
        assert_eq!(super::ai_next_memory_limit(100, 200), Some(125));
        assert_eq!(super::ai_next_memory_limit(100, 110), Some(110));
        assert_eq!(super::ai_next_memory_limit(100, 99), None);
        assert_eq!(super::ai_next_memory_limit(0, u64::MAX), None);
        assert_eq!(super::ai_next_memory_limit(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn ai_runtime_decision_fixtures_emit_explainable_audit_records() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let temp = tempfile::tempdir().expect("audit tempdir");
        let audit_path = temp.path().join("decisions.jsonl");
        let previous_enabled = std::env::var("FERROCRATE_AI").ok();
        let previous_path = std::env::var("FERROCRATE_AI_AUDIT_LOG").ok();
        unsafe {
            std::env::set_var("FERROCRATE_AI", "1");
            std::env::set_var("FERROCRATE_AI_AUDIT_LOG", &audit_path);
        }

        super::log_ai_restart_lifecycle(
            "fixture-container",
            "ai_restart_applied",
            137,
            2,
            3,
            "observed",
            Some(42),
        );
        super::log_ai_reconciliation("fixture-container", 137, "stale-pid", "exited");
        super::log_ai_kernel_reconciliation("fixture-network", "verify-reuse", 2);

        let entries = std::fs::read_to_string(&audit_path)
            .expect("audit records")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid audit JSON"))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["action"], "ai_restart_applied");
        assert_eq!(entries[0]["model"], "adaptive-restart-policy");
        assert_eq!(entries[0]["model_version"], "runtime-v1");
        assert_eq!(entries[0]["evidence"]["container_id"], "fixture-container");
        assert_eq!(entries[0]["evidence"]["stage"], "observed");
        assert_eq!(entries[1]["action"], "ai_reconciliation_applied");
        assert_eq!(entries[1]["evidence"]["reason"], "stale-pid");
        assert_eq!(entries[2]["action"], "ai_kernel_reconciliation");
        assert_eq!(entries[2]["evidence"]["network_id"], "fixture-network");
        assert_eq!(entries[2]["evidence"]["container_count"], "2");

        match previous_enabled {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI") },
        }
        match previous_path {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI_AUDIT_LOG", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI_AUDIT_LOG") },
        }
    }

    #[test]
    fn ai_disabled_environment_overrides_explicit_runtime_config() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous = std::env::var("FERROCRATE_AI").ok();
        let config = crate::ai_runtime::AiRuntimeConfig::default();
        unsafe {
            std::env::set_var("FERROCRATE_AI", "0");
        }
        assert!(!super::ai_lifecycle_enabled(Some(&config)));
        unsafe {
            std::env::set_var("FERROCRATE_AI", "1");
        }
        assert!(super::ai_lifecycle_enabled(Some(&config)));
        assert!(!super::ai_lifecycle_enabled(None));
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI") },
        }
    }

    #[test]
    fn ai_lifecycle_enablement_matches_inference_for_non_boolean_opt_in_values() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous = std::env::var("FERROCRATE_AI").ok();
        let config = crate::ai_runtime::AiRuntimeConfig::default();
        unsafe {
            std::env::set_var("FERROCRATE_AI", "yes");
        }
        assert!(super::is_ai_enabled());
        assert!(super::ai_lifecycle_enabled(Some(&config)));
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI") },
        }
    }

    #[test]
    fn ai_snapshot_cleanup_removes_all_per_container_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        for kind in ["restart", "resource", "anomaly"] {
            let folder = dir.path().join("ai").join(kind);
            std::fs::create_dir_all(&folder).expect("folder");
            std::fs::write(folder.join("container-a.json"), b"snapshot").expect("snapshot");
        }
        super::cleanup_ai_container_snapshots(dir.path(), "container-a");
        for kind in ["restart", "resource", "anomaly"] {
            assert!(!dir
                .path()
                .join("ai")
                .join(kind)
                .join("container-a.json")
                .exists());
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
    fn apparmor_strict_mode_fails_closed_when_tools_are_missing() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("FERROCRATE_APPARMOR", "1");
            std::env::remove_var("FERROCRATE_MAC_PERMISSIVE");
            std::env::set_var("PATH", "");
        }
        let root = tempfile::tempdir().expect("runtime dir");
        let error = super::apply_apparmor_if_enabled(root.path(), "strict-mac", &["true".into()])
            .expect_err("strict AppArmor must fail without tools");
        assert!(error.to_string().contains("apparmor_parser"));
        unsafe {
            std::env::remove_var("FERROCRATE_APPARMOR");
            if let Some(path) = previous_path {
                std::env::set_var("PATH", path);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }

    #[test]
    fn command_capability_probe_resolves_without_executing_version_flag() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("PATH", "/usr/bin:/bin");
        }
        assert!(super::command_available("true"));
        assert!(!super::command_available(
            "ferrocrate-command-does-not-exist"
        ));
        unsafe {
            if let Some(path) = previous_path {
                std::env::set_var("PATH", path);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }

    #[test]
    fn selinux_strict_mode_fails_closed_when_runcon_is_missing() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous_path = std::env::var_os("PATH");
        unsafe {
            std::env::set_var("FERROCRATE_SELINUX", "1");
            std::env::remove_var("FERROCRATE_MAC_PERMISSIVE");
            std::env::set_var("PATH", "");
        }
        let error = super::apply_selinux_if_enabled(&["true".into()])
            .expect_err("strict SELinux must fail without runcon");
        assert!(error.to_string().contains("runcon"));
        unsafe {
            std::env::remove_var("FERROCRATE_SELINUX");
            if let Some(path) = previous_path {
                std::env::set_var("PATH", path);
            } else {
                std::env::remove_var("PATH");
            }
        }
    }

    #[test]
    fn selinux_strict_mode_fails_closed_when_enforcement_is_unknown() {
        let _guard = acquire_lock(&CGROUP_ENV_LOCK);
        let previous_path = std::env::var_os("PATH");
        let tools = tempfile::tempdir().expect("SELinux tool directory");
        let runcon = tools.path().join("runcon");
        let getenforce = tools.path().join("getenforce");
        std::fs::write(&runcon, b"#!/bin/sh\nexec \"$@\"\n").expect("runcon fixture");
        std::fs::write(&getenforce, b"#!/bin/sh\nprintf 'Unknown\\n'\n")
            .expect("getenforce fixture");
        for path in [&runcon, &getenforce] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("tool permissions");
        }
        unsafe {
            std::env::set_var("FERROCRATE_SELINUX", "1");
            std::env::remove_var("FERROCRATE_MAC_PERMISSIVE");
            std::env::set_var("PATH", tools.path());
        }
        let error = super::apply_selinux_if_enabled(&["true".into()])
            .expect_err("unknown SELinux state must fail closed");
        assert!(error.to_string().contains("unsupported state"));
        unsafe {
            std::env::remove_var("FERROCRATE_SELINUX");
            if let Some(path) = previous_path {
                std::env::set_var("PATH", path);
            } else {
                std::env::remove_var("PATH");
            }
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
        // Rootful lifecycle tests execute inside a chroot.  An empty manifest
        // would therefore fail with ENOENT before exercising the runtime path.
        // Use the host's static BusyBox binary as a tiny, deterministic test
        // rootfs and expose it as both `busybox` and `/bin/sh`.
        let busybox = ["/usr/bin/busybox", "/bin/busybox"]
            .into_iter()
            .map(std::path::Path::new)
            .find(|path| path.is_file())
            .expect("static busybox is required for rootful runtime fixtures");
        let layer_bytes = {
            let mut builder = tar::Builder::new(std::io::Cursor::new(Vec::new()));
            let data = std::fs::read(busybox).expect("read busybox");
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "bin/busybox", std::io::Cursor::new(data))
                .expect("append busybox");
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::symlink());
            link.set_link_name("busybox").expect("busybox link");
            link.set_mode(0o777);
            link.set_size(0);
            link.set_cksum();
            builder
                .append_data(&mut link, "bin/sh", std::io::Cursor::new(Vec::new()))
                .expect("append shell link");
            for applet in ["sleep", "echo", "touch"] {
                let mut link = tar::Header::new_gnu();
                link.set_entry_type(tar::EntryType::symlink());
                link.set_link_name("busybox").expect("busybox applet link");
                link.set_mode(0o777);
                link.set_size(0);
                link.set_cksum();
                builder
                    .append_data(
                        &mut link,
                        format!("bin/{applet}"),
                        std::io::Cursor::new(Vec::new()),
                    )
                    .expect("append busybox applet link");
            }
            let mut app = tar::Header::new_gnu();
            app.set_entry_type(tar::EntryType::dir());
            app.set_mode(0o755);
            app.set_size(0);
            app.set_cksum();
            builder
                .append_data(&mut app, "app", std::io::Cursor::new(Vec::new()))
                .expect("append app directory");
            builder.finish().expect("finish rootfs layer");
            builder
                .into_inner()
                .expect("read rootfs layer")
                .into_inner()
        };
        use sha2::{Digest, Sha256};
        let digest = format!("sha256:{:x}", Sha256::digest(&layer_bytes));
        let blob_root = runtime_dir.join("images").join("blobs");
        std::fs::create_dir_all(&blob_root).expect("blob root");
        std::fs::write(blob_root.join(digest.replace(':', "_")), &layer_bytes)
            .expect("write rootfs layer");
        let manifest_json = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{digest}","size":{}}}]}}"#,
            layer_bytes.len()
        );
        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                &canonical,
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                &manifest_json,
            )
            .expect("seed manifest");
    }

    fn write_image_config(runtime_dir: &std::path::Path, json: &str) {
        let config_root = runtime_dir.join("images").join("configs");
        std::fs::create_dir_all(&config_root).expect("configs dir");
        use sha2::{Digest, Sha256};
        let digest = format!("sha256:{:x}", Sha256::digest(json.as_bytes()));
        std::fs::write(config_root.join(digest.replace(':', "_")), json).expect("write config");

        // Keep the fixture manifest's config descriptor honest so normal
        // digest verification can discover this config during `run`.
        let store = LocalImageStore::open(runtime_dir.join("images")).expect("store");
        let canonical = canonicalize_reference("alpine:latest").expect("canonical");
        let record = store
            .resolve_reference(&canonical)
            .expect("resolve manifest")
            .expect("seed manifest");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&record.manifest_json).expect("manifest json");
        manifest["config"]["digest"] = serde_json::Value::String(digest);
        manifest["config"]["size"] = serde_json::Value::from(json.len());
        let manifest_json = serde_json::to_string(&manifest).expect("manifest json");
        store
            .put_reference(
                &crate::authorization::surface::SurfaceMutationAuthority::for_test(),
                &canonical,
                &record.digest,
                &record.manifest_media_type,
                &manifest_json,
            )
            .expect("update manifest");
    }

    #[test]
    fn supervised_launch_blocks_workload_until_parent_release() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("workload-ran");
        let stdout = root.path().join("stdout");
        let stderr = root.path().join("stderr");
        let command = super::build_command(
            &["/usr/bin/touch".into(), marker.display().to_string()],
            &[],
            None,
            false,
            &[],
            None,
            None,
            None,
            false,
            None,
            &[],
            &[],
            false,
        )
        .unwrap();
        let (pid, mut child, _pidfd) =
            super::spawn_child_with_logs(command, &stdout, &stderr, false).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        assert!(
            !marker.exists(),
            "workload ran before durable launch release"
        );
        super::release_prepared_child(pid).unwrap();
        assert!(child.wait().unwrap().success());
        assert!(marker.exists());
    }

    fn assert_sigkill_before_release_leaves_no_workload(action: &str) {
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("pid");
        let marker = root.path().join("marker");
        let mut daemon = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("runtime::tests::supervised_launch_sigkill_helper")
            .arg("--nocapture")
            .env("FERRO_LAUNCH_HELPER_PID", &pid_file)
            .env("FERRO_LAUNCH_HELPER_MARKER", &marker)
            .env("FERRO_LAUNCH_HELPER_ACTION", action)
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if pid_file.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let workload_pid: u32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if action.ends_with("-user") {
            let status = std::fs::read_to_string(format!("/proc/{workload_pid}/status")).unwrap();
            assert!(
                status
                    .lines()
                    .any(|line| line == "Uid:\t65534\t65534\t65534\t65534"),
                "launcher did not cross the requested non-root credential transition"
            );
        }
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(daemon.id() as i32),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
        let _ = daemon.wait();
        for _ in 0..500 {
            if !std::path::Path::new(&format!("/proc/{workload_pid}")).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(!marker.exists(), "{action} workload crossed launch lease");
        assert!(!std::path::Path::new(&format!("/proc/{workload_pid}")).exists());
    }

    #[cfg(feature = "legacy-sled-importers")]
    fn assert_sigkill_after_identity_persist_is_recoverable(action: &str) {
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("pid");
        let marker = root.path().join("marker");
        let store_path = root.path().join("store");
        let mut daemon = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("runtime::tests::supervised_launch_sigkill_helper")
            .arg("--nocapture")
            .env("FERRO_LAUNCH_HELPER_PID", &pid_file)
            .env("FERRO_LAUNCH_HELPER_MARKER", &marker)
            .env("FERRO_LAUNCH_HELPER_ACTION", action)
            .env("FERRO_LAUNCH_HELPER_STORE", &store_path)
            .spawn()
            .unwrap();
        for _ in 0..500 {
            if pid_file.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let workload_pid: u32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(daemon.id() as i32),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
        let _ = daemon.wait();
        for _ in 0..500 {
            if !std::path::Path::new(&format!("/proc/{workload_pid}")).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let store = LocalContainerStore::open(&store_path).unwrap();
        let operation = store.lifecycle_operation([71; 16]).unwrap().unwrap();
        assert_eq!(operation.pid_after, Some(workload_pid));
        assert!(operation.process_start_time_after.is_some());
        assert!(!marker.exists());
        assert!(!std::path::Path::new(&format!("/proc/{workload_pid}")).exists());
    }

    #[cfg(feature = "legacy-sled-importers")]
    #[test]
    fn run_sigkill_before_durable_launch_release_has_no_orphan() {
        assert_sigkill_before_release_leaves_no_workload("run");
    }

    #[cfg(feature = "legacy-sled-importers")]
    #[test]
    fn restart_sigkill_before_durable_launch_release_has_no_replacement_orphan() {
        assert_sigkill_before_release_leaves_no_workload("restart");
    }

    #[test]
    fn non_root_user_transition_preserves_prepublication_barrier() {
        if !nix::unistd::Uid::effective().is_root() {
            return;
        }
        assert_sigkill_before_release_leaves_no_workload("run-user");
    }

    #[cfg(feature = "legacy-sled-importers")]
    #[test]
    fn run_sigkill_after_identity_persist_retains_recovery_identity() {
        assert_sigkill_after_identity_persist_is_recoverable("run");
    }

    #[cfg(feature = "legacy-sled-importers")]
    #[test]
    fn restart_sigkill_after_identity_persist_retains_replacement_identity() {
        assert_sigkill_after_identity_persist_is_recoverable("restart");
    }

    #[test]
    fn supervised_launch_sigkill_helper() {
        let Ok(pid_file) = std::env::var("FERRO_LAUNCH_HELPER_PID") else {
            return;
        };
        let marker = std::env::var("FERRO_LAUNCH_HELPER_MARKER").unwrap();
        let root = tempfile::tempdir().unwrap();
        let action = std::env::var("FERRO_LAUNCH_HELPER_ACTION").unwrap();
        let command = super::build_command(
            &["/usr/bin/touch".into(), marker],
            &[],
            None,
            false,
            &[],
            None,
            action.ends_with("-user").then_some("65534:65534"),
            None,
            false,
            None,
            &[],
            &[],
            false,
        )
        .unwrap();
        let (pid, _child, _pidfd) = super::spawn_child_with_logs(
            command,
            &root.path().join("stdout"),
            &root.path().join("stderr"),
            false,
        )
        .unwrap();
        #[cfg(feature = "legacy-sled-importers")]
        if let Ok(store_path) = std::env::var("FERRO_LAUNCH_HELPER_STORE") {
            let store = LocalContainerStore::open(store_path).unwrap();
            let mut record =
                ContainerRecord::authorization_candidate("launch-helper".into(), "image".into());
            record.pending_mutation = Some(MutationReservation {
                operation_id: [71; 16],
                generation: 1,
                expected_status: "created".into(),
                action: format!("container.{action}"),
            });
            store.put_reserved_creation(&record).unwrap();
            record.pid = pid;
            record.status = "running".into();
            store.put_for_mutation(&record, [71; 16]).unwrap();
        }
        std::fs::write(pid_file, pid.to_string()).unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    fn phase_from_name(name: &str) -> LifecyclePhasePoint {
        match name {
            "network-resources-before-ownership" => {
                LifecyclePhasePoint::NetworkResourcesCreatedBeforeOwnership
            }
            "network" => LifecyclePhasePoint::NetworkApplied,
            "cgroup" => LifecyclePhasePoint::CgroupApplied,
            "old-stopped" => LifecyclePhasePoint::RestartOldStopped,
            "bind-effect" => LifecyclePhasePoint::BindKernelEffect,
            "tmpfs-effect" => LifecyclePhasePoint::TmpfsKernelEffect,
            "readonly-effect" => LifecyclePhasePoint::ReadonlyKernelEffect,
            "network-effect" => LifecyclePhasePoint::NetworkKernelEffect,
            "cgroup-effect" => LifecyclePhasePoint::CgroupKernelEffect,
            "spawn" => LifecyclePhasePoint::SpawnPrepared,
            "identity" => LifecyclePhasePoint::LaunchIdentityDurable,
            _ => panic!("unknown phase {name}"),
        }
    }

    #[test]
    fn public_lifecycle_sigkill_barrier_helper() {
        let Ok(root) = std::env::var("FERRO_PUBLIC_BARRIER_ROOT") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let action = std::env::var("FERRO_PUBLIC_BARRIER_ACTION").unwrap();
        let phase = phase_from_name(&std::env::var("FERRO_PUBLIC_BARRIER_PHASE").unwrap());
        let signal_socket =
            std::path::PathBuf::from(std::env::var("FERRO_PUBLIC_BARRIER_SIGNAL").unwrap());
        let cgroup = root.join("cgroup");
        std::fs::create_dir_all(&cgroup).unwrap();
        std::fs::write(cgroup.join("cgroup.controllers"), "cpu memory pids").unwrap();
        std::fs::write(cgroup.join("cgroup.subtree_control"), "").unwrap();
        unsafe { std::env::set_var("FERROCRATE_CGROUP_ROOT", &cgroup) };
        let policy = root.join("policy.toml");
        std::fs::write(
            &policy,
            "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        seed_image_store(&root, "alpine:latest");
        let gate = std::sync::Arc::new(AuthorizationGate::new(std::sync::Arc::new(
            PolicyStore::load(&policy).unwrap(),
        )));
        let journal = Some(std::sync::Arc::new(
            WitnessJournal::open(JournalConfig::new(
                root.join("witness"),
                [93; 16],
                JournalMode::Required,
            ))
            .unwrap(),
        ));
        let runtime = ContainerRuntime::new_with_test_kernel_ops(
            &root,
            gate,
            journal,
            std::sync::Arc::new(ProcessBarrier {
                action: action.clone(),
                phase,
                signal_socket: signal_socket.clone(),
            }),
            std::sync::Arc::new(DeterministicKernelResourceOps {
                state: root.join("fake-kernel.json"),
            }),
        )
        .unwrap();
        if action == "run" {
            let limits = ResourceLimits {
                // A 1 KiB real cgroup ceiling can make the launch shell fail
                // before pidfd acquisition; use a small but viable fixture
                // limit so the barrier tests exercise lifecycle recovery.
                memory_max: Some(16 * 1024 * 1024),
                cpu_max: None,
                pids_max: Some(8),
            };
            let source = root.join("mount-source");
            std::fs::create_dir_all(&source).unwrap();
            let mounts = [BindMount {
                source,
                target: PathBuf::from("bind-target"),
                read_only: false,
            }];
            let tmpfs = [TmpfsMount {
                target: PathBuf::from("tmp-target"),
                size: Some("1m".into()),
            }];
            let (run_mounts, run_tmpfs, run_readonly) = if nix::unistd::Uid::effective().is_root()
                && phase != LifecyclePhasePoint::SpawnPrepared
            {
                (&mounts[..], &tmpfs[..], true)
            } else {
                (&[][..], &[][..], false)
            };
            // Keep the child alive long enough for every pre-publication
            // barrier (including `spawn`) to be observable. The assertion is
            // about preventing post-SIGKILL workload execution, so a sleeper
            // is a better fixture than a short-lived marker command.
            let workload_command = "exec /bin/busybox sleep 60".to_string();
            let result = runtime.run(
                "alpine:latest",
                &["sh".into(), "-c".into(), workload_command],
                &[],
                &HashMap::new(),
                &HashMap::new(),
                None,
                RestartPolicy::No,
                &[],
                Some(&limits),
                run_mounts,
                run_tmpfs,
                run_readonly,
                false,
                None,
                None,
                None,
                &[],
                "managed:test",
                NetworkBackend::Iptables,
                None,
            );
            if let Err(error) = result {
                let _ = signal_barrier(&signal_socket, &format!("error:{error}"));
            }
        } else {
            let mut old = std::process::Command::new("sleep")
                .arg("60")
                .spawn()
                .unwrap();
            let container_id = "00112233445566778899aabbccddeeff";
            let container_dir = root.join("containers").join(container_id);
            let rootfs = container_dir.join("rootfs");
            std::fs::create_dir_all(rootfs.join("bin")).unwrap();
            std::fs::copy("/usr/bin/busybox", rootfs.join("bin/busybox")).unwrap();
            std::os::unix::fs::symlink("busybox", rootfs.join("bin/sh")).unwrap();
            std::os::unix::fs::symlink("busybox", rootfs.join("bin/sleep")).unwrap();
            let mut record = ContainerRecord::authorization_candidate(
                container_id.into(),
                "alpine:latest".into(),
            );
            record.pid = old.id();
            record.status = "running".into();
            record.command = vec!["/bin/busybox".into(), "sleep".into(), "60".into()];
            record.stdout_path = container_dir.join("stdout").display().to_string();
            record.stderr_path = container_dir.join("stderr").display().to_string();
            runtime.store.put(&record).unwrap();
            if let Err(error) = runtime.restart(container_id, std::time::Duration::from_millis(10))
            {
                let _ = signal_barrier(&signal_socket, &format!("error:{error}"));
            }
            let _ = old.kill();
            let _ = old.wait();
        }
    }

    #[test]
    fn public_run_and_restart_survive_real_sigkill_at_resource_and_launch_barriers() {
        let _env_guard = acquire_lock(&CGROUP_ENV_LOCK);
        let _guard = acquire_lock(&RUNTIME_TEST_LOCK);
        for action in ["run", "restart"] {
            let phases: &[&str] = if action == "run" {
                if nix::unistd::Uid::effective().is_root() {
                    &[
                        "bind-effect",
                        "tmpfs-effect",
                        "readonly-effect",
                        "network-effect",
                        "network-resources-before-ownership",
                        "network",
                        "cgroup-effect",
                        "cgroup",
                        "spawn",
                        "identity",
                    ]
                } else {
                    // Rootless mount admission is intentionally fail-closed
                    // until a mount-capable user namespace is available.
                    &[
                        "network-effect",
                        "network-resources-before-ownership",
                        "network",
                        "cgroup-effect",
                        "cgroup",
                        "spawn",
                        "identity",
                    ]
                }
            } else {
                &["network", "old-stopped", "spawn", "identity"]
            };
            for phase in phases {
                let root = tempfile::tempdir().unwrap();
                let signal_socket = root.path().join("barrier.sock");
                let listener = UnixListener::bind(&signal_socket).unwrap();
                let (signal_tx, signal_rx) = mpsc::channel();
                std::thread::spawn(move || {
                    let result = listener.accept().and_then(|(mut stream, _)| {
                        let mut signal = String::new();
                        stream.read_to_string(&mut signal)?;
                        Ok(signal)
                    });
                    let _ = signal_tx.send(result.map_err(|error| error.to_string()));
                });
                let marker = if nix::unistd::Uid::effective().is_root() && action == "run" {
                    root.path().join("mount-source/workload-marker")
                } else {
                    root.path().join("workload-marker")
                };
                let mut daemon = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--exact")
                    .arg("runtime::tests::public_lifecycle_sigkill_barrier_helper")
                    .arg("--nocapture")
                    .env("FERRO_PUBLIC_BARRIER_ROOT", root.path())
                    .env("FERRO_PUBLIC_BARRIER_ACTION", action)
                    .env("FERRO_PUBLIC_BARRIER_PHASE", phase)
                    .env("FERRO_PUBLIC_BARRIER_SIGNAL", &signal_socket)
                    .env("FERRO_PUBLIC_BARRIER_MARKER", &marker)
                    // This child exercises recovery boundaries, not image-signature
                    // verification. Pin the inherited process environment so parallel
                    // signature-verification tests cannot make it fail before ready.
                    .env("FERROCRATE_SIGNATURE_VERIFY", "0")
                    .spawn()
                    .unwrap();
                let signal = signal_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap_or_else(|error| {
                        panic!("{action} did not report {phase} readiness: {error}")
                    })
                    .unwrap_or_else(|error| {
                        panic!("{action} {phase} readiness transport failed: {error}")
                    });
                // Some kernels reject pidfd acquisition for a child created
                // under the synthetic test cgroup (EINVAL). Preserve this as
                // an explicit host capability boundary; all other failures
                // remain hard test failures.
                if signal == "error:io error: Invalid argument (os error 22)" && action == "run" {
                    continue;
                }
                assert_eq!(
                    signal, "ready",
                    "{action} {phase} child failed before barrier: {signal}"
                );
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(daemon.id() as i32),
                    nix::sys::signal::Signal::SIGKILL,
                )
                .unwrap();
                let _ = daemon.wait();
                let ownership_published = root.path().join("fake-kernel.network-owned").exists();
                if action == "run" && *phase == "network-resources-before-ownership" {
                    assert!(
                        !ownership_published,
                        "inner barrier published ownership early"
                    );
                    assert!(
                        root.path().join("fake-kernel.network.json").exists(),
                        "inner barrier did not create network resources"
                    );
                }
                if action == "run" && *phase == "network-effect" {
                    assert!(
                        ownership_published,
                        "outer barrier lacked durable ownership"
                    );
                }
                let policy = root.path().join("policy.toml");
                let gate = std::sync::Arc::new(AuthorizationGate::new(std::sync::Arc::new(
                    PolicyStore::load(&policy).unwrap(),
                )));
                let journal = std::sync::Arc::new(
                    WitnessJournal::open(JournalConfig::new(
                        root.path().join("witness"),
                        [93; 16],
                        JournalMode::Required,
                    ))
                    .unwrap(),
                );
                let reopened = ContainerRuntime::new_with_test_kernel_ops(
                    root.path(),
                    gate,
                    Some(journal.clone()),
                    std::sync::Arc::new(NoopLifecyclePhaseHook),
                    std::sync::Arc::new(DeterministicKernelResourceOps {
                        state: root.path().join("fake-kernel.json"),
                    }),
                )
                .unwrap();
                let fake_state: BTreeMap<String, ResourceIdentity> =
                    std::fs::read(root.path().join("fake-kernel.json"))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                        .unwrap_or_default();
                assert!(
                    fake_state.is_empty(),
                    "{action} {phase} leaked fake mount state"
                );
                assert!(
                    !root.path().join("fake-kernel.network.json").exists(),
                    "{action} {phase} leaked fake network state"
                );
                assert!(!marker.exists(), "{action} {phase} replayed workload");
                for record in reopened.list().unwrap() {
                    assert!(record.pending_mutation.is_none(), "{action} {phase}");
                    if action == "run" || matches!(*phase, "old-stopped" | "spawn" | "identity") {
                        assert!(
                            !super::process_exists(record.pid),
                            "{action} {phase} orphan"
                        );
                    } else {
                        let _ = super::kill_pid(record.pid);
                    }
                }
                let decoded = journal
                    .records()
                    .unwrap()
                    .iter()
                    .map(|bytes| decode_record(bytes).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(
                    decoded
                        .iter()
                        .filter(|record| record.stage() == WitnessStage::Recovery)
                        .count(),
                    if action == "run" { 2 } else { 1 },
                    "{action} {phase} recovery uniqueness"
                );
            }
        }
    }
}
