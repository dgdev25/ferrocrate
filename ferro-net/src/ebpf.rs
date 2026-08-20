use std::collections::VecDeque;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aya::maps::{Map, MapData, RingBuf};
use aya::programs::{links::FdLink, TracePoint};
use aya::Ebpf;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ebpf_abi::{
    EndpointKey, EndpointValue, MetaConfig, PolicyKey, PolicyValue, PortKey, PortValue,
    COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME, META_FLAG_SNAT_RANGE_RESERVED, PORTS_MAP_NAME,
    PROGRAM_ABI_VERSION,
};
use crate::ebpf_loader::{
    sha256, validate_embedded_object, AyaKernel, KernelAdapter, KernelLoadPlan, KernelPreflight,
};
use crate::executor::{exec_cmd_capture, ExecError};

pub const BPFFS_ROOT: &str = "/sys/fs/bpf";
pub const FERRO_NETWORK_ROOT: &str = "/sys/fs/bpf/ferrocrate";
pub const INGRESS_CLASSIFIER: &str = "ferro_ingress";
pub const EGRESS_CLASSIFIER: &str = "ferro_egress";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfNetworkConfig {
    pub network_id: String,
    pub interface: String,
    pub external_ipv4: [u8; 4],
    pub bridge_gateway: [u8; 4],
    pub external_ifindex: u32,
    pub loopback_ifindex: u32,
    pub next_hop_mac: [u8; 6],
    pub snat_port_start: u16,
    pub snat_port_end: u16,
    pub expected_object_sha256: [u8; 32],
}

impl EbpfNetworkConfig {
    pub fn pin_path(&self) -> Result<PathBuf, EbpfError> {
        validate_network_id(&self.network_id)?;
        Ok(Path::new(FERRO_NETWORK_ROOT).join(&self.network_id))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EbpfMetrics {
    pub ingress_packets: u64,
    pub egress_packets: u64,
    pub redirects: u64,
    pub passes: u64,
    pub drops: u64,
    pub nat_translations: u64,
    pub policy_denials: u64,
    pub map_errors: u64,
    pub snat_exhaustions: u64,
    pub snat_config_errors: u64,
}

impl From<[u64; COUNTER_MAX_ENTRIES as usize]> for EbpfMetrics {
    fn from(counters: [u64; COUNTER_MAX_ENTRIES as usize]) -> Self {
        Self {
            ingress_packets: counters[0],
            egress_packets: counters[1],
            redirects: counters[2],
            passes: counters[3],
            drops: counters[4],
            nat_translations: counters[5],
            policy_denials: counters[6],
            map_errors: counters[7],
            snat_exhaustions: counters[8],
            snat_config_errors: counters[9],
        }
    }
}

#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("invalid eBPF network id `{network_id}`")]
    InvalidNetworkId { network_id: String },
    #[error("invalid eBPF network configuration: {reason}")]
    InvalidConfig { reason: String },
    #[error("embedded eBPF object SHA-256 does not match the configured digest")]
    ObjectHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("embedded eBPF object format is invalid: {reason}")]
    ObjectFormat { reason: String },
    #[error("could not read /proc/sys/net/ipv4/ip_local_reserved_ports: {reason}")]
    ReservedPortsRead { reason: String },
    #[error("invalid ip_local_reserved_ports value `{token}`")]
    ReservedPortsInvalid { token: String },
    #[error("SNAT range {start}-{end} is not completely reserved")]
    SnatRangeNotReserved { start: u16, end: u16 },
    #[error("eBPF ABI mismatch: expected {expected}, found {actual}")]
    AbiMismatch { expected: u32, actual: u32 },
    #[error("required eBPF map `{map}` is missing")]
    MissingMap { map: &'static str },
    #[error("unexpected eBPF map `{map}`")]
    UnexpectedMap { map: String },
    #[error("eBPF map `{map}` has the wrong type or dimensions")]
    MapSchemaMismatch {
        map: String,
        expected: String,
        actual: String,
    },
    #[error("required classifier `{classifier}` is missing")]
    MissingClassifier { classifier: &'static str },
    #[error("unexpected classifier `{classifier}`")]
    UnexpectedClassifier { classifier: String },
    #[error("bpffs is unavailable: {reason}")]
    BpffsUnavailable { reason: String },
    #[error("pin path is outside ferro ownership: {path}")]
    InvalidPinPath { path: PathBuf },
    #[error("pin path already exists and is not owned by this transaction: {path}")]
    PinPathExists { path: PathBuf },
    #[error("bpffs directory policy failed for `{path}`: {reason}")]
    DirectoryPolicy { path: String, reason: String },
    #[error("owned bpffs directory is not empty: {path}")]
    DirectoryNotEmpty { path: String },
    #[error("owned bpffs entry was replaced; refusing to delete `{entry}`")]
    OwnershipChanged { entry: String },
    #[error("interface `{interface}` has ifindex {actual}, expected {expected}")]
    InterfaceMismatch {
        interface: String,
        expected: u32,
        actual: u32,
    },
    #[error("TC is unavailable for `{interface}`: {reason}")]
    TcUnavailable { interface: String, reason: String },
    #[error("failed to load the embedded eBPF object with Aya: {reason}")]
    ObjectLoad { reason: String },
    #[error("failed to load classifier `{classifier}`: {reason}")]
    ProgramLoad { classifier: String, reason: String },
    #[error("failed to pin `{item}`: {reason}")]
    Pin { item: String, reason: String },
    #[error("failed to attach classifier `{classifier}`: {reason}")]
    Attach { classifier: String, reason: String },
    #[error("map `{map}` is at capacity")]
    MapCapacity { map: &'static str },
    #[error("failed to {operation} map `{map}`: {reason}")]
    MapOperation {
        operation: &'static str,
        map: &'static str,
        reason: String,
    },
    #[error("failed to read eBPF metrics: {reason}")]
    Metrics { reason: String },
    #[error("eBPF network is detached")]
    Detached,
    #[error("invalid eBPF adapter lifecycle state: {reason}")]
    InvalidAdapterState { reason: String },
    #[error("failed to detach eBPF network: {reason}")]
    Detach { reason: String },
    #[error("{primary}; rollback also failed: {rollback}")]
    Rollback { primary: String, rollback: String },
}

pub struct EbpfNetwork {
    kernel: Box<dyn KernelAdapter>,
    detached: bool,
}

pub struct PreparedEbpfNetwork {
    kernel: Box<dyn KernelAdapter>,
    config: EbpfNetworkConfig,
    additional_interfaces: Vec<(String, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedObjectIdentity {
    pub relative_path: String,
    pub device: u64,
    pub inode: u64,
    pub directory: bool,
    pub map_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedNetworkIdentity {
    pub root: PathBuf,
    pub objects: Vec<PinnedObjectIdentity>,
}

#[derive(Debug, Clone)]
pub struct VerifiedPinnedNetwork {
    network_id: String,
    identity: PinnedNetworkIdentity,
}

impl fmt::Debug for PreparedEbpfNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEbpfNetwork")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EbpfNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EbpfNetwork")
            .field("detached", &self.detached)
            .finish_non_exhaustive()
    }
}

impl EbpfNetwork {
    pub fn load(config: EbpfNetworkConfig) -> Result<Self, EbpfError> {
        Self::prepare(config)?.attach()
    }

    /// Attach the loaded classifiers to a per-container veth. The veth is
    /// lifecycle-owned and disappears with the container, so it is not added
    /// to the shared network's persisted filter inventory.
    pub fn attach_interface(
        &mut self,
        interface: &str,
        expected_ifindex: u32,
    ) -> Result<(), EbpfError> {
        validate_network_id(interface)?;
        self.active_kernel()?
            .attach_ingress_interface(interface, expected_ifindex)
    }

    pub fn prepare(config: EbpfNetworkConfig) -> Result<PreparedEbpfNetwork, EbpfError> {
        Self::prepare_with(AyaKernel::new(), config)
    }

    #[cfg(test)]
    fn load_with<K>(kernel: K, config: EbpfNetworkConfig) -> Result<Self, EbpfError>
    where
        K: KernelAdapter + 'static,
    {
        Self::prepare_with(kernel, config)?.attach()
    }

    fn prepare_with<K>(
        kernel: K,
        config: EbpfNetworkConfig,
    ) -> Result<PreparedEbpfNetwork, EbpfError>
    where
        K: KernelAdapter + 'static,
    {
        Self::prepare_with_object(kernel, config, crate::ebpf_loader::embedded_object())
    }

    fn prepare_with_object<K>(
        mut kernel: K,
        config: EbpfNetworkConfig,
        object: &'static [u8],
    ) -> Result<PreparedEbpfNetwork, EbpfError>
    where
        K: KernelAdapter + 'static,
    {
        validate_config(&config)?;
        config.pin_path()?;
        let actual_hash = sha256(object);
        if actual_hash != config.expected_object_sha256 {
            return Err(EbpfError::ObjectHashMismatch {
                expected: config.expected_object_sha256,
                actual: actual_hash,
            });
        }
        validate_embedded_object(object)?;

        let reserved = kernel.reserved_ports()?;
        prove_reserved_range(&reserved, config.snat_port_start, config.snat_port_end)?;

        let preflight = KernelPreflight {
            object,
            expected_object_sha256: config.expected_object_sha256,
            network_id: &config.network_id,
            interface: &config.interface,
            external_ifindex: config.external_ifindex,
        };
        kernel.preflight(&preflight)?;

        Ok(PreparedEbpfNetwork {
            kernel: Box::new(kernel),
            config,
            additional_interfaces: Vec::new(),
        })
    }

    pub fn persist(mut self) -> Result<(), EbpfError> {
        self.active_kernel()?.persist()?;
        self.detached = true;
        Ok(())
    }

    pub fn pinned_map_id(path: &Path) -> Result<u32, EbpfError> {
        let map = aya::maps::MapData::from_pin(path).map_err(|error| EbpfError::MapOperation {
            operation: "open pinned identity",
            map: "pinned map",
            reason: error.to_string(),
        })?;
        map.info()
            .map(|info| info.id())
            .map_err(|error| EbpfError::MapOperation {
                operation: "read pinned identity",
                map: "pinned map",
                reason: error.to_string(),
            })
    }

    pub fn verify_pinned_network(
        network_id: &str,
        identity: PinnedNetworkIdentity,
    ) -> Result<VerifiedPinnedNetwork, EbpfError> {
        let expected_root = Path::new(FERRO_NETWORK_ROOT).join(network_id);
        if identity.root != expected_root {
            return Err(EbpfError::MapOperation {
                operation: "verify pinned ownership",
                map: "pin tree",
                reason: "pin root does not match the network identity".to_string(),
            });
        }
        verify_pinned_tree(&identity)?;
        Ok(VerifiedPinnedNetwork {
            network_id: network_id.to_string(),
            identity,
        })
    }

    fn commit_prepared(
        mut kernel: Box<dyn KernelAdapter>,
        config: EbpfNetworkConfig,
        additional_interfaces: Vec<(String, u32)>,
    ) -> Result<Self, EbpfError> {
        let metadata = MetaConfig {
            abi_version: PROGRAM_ABI_VERSION,
            external_ipv4: config.external_ipv4,
            bridge_gateway: config.bridge_gateway,
            external_ifindex: config.external_ifindex,
            loopback_ifindex: config.loopback_ifindex,
            next_hop_mac: config.next_hop_mac,
            snat_port_start: config.snat_port_start,
            snat_port_end: config.snat_port_end,
            flags: META_FLAG_SNAT_RANGE_RESERVED,
        }
        .encode();
        let plan = KernelLoadPlan {
            network_id: &config.network_id,
            interface: &config.interface,
            metadata,
        };
        if let Err(error) = kernel.commit(&plan) {
            return Err(rollback_error(kernel.as_mut(), error));
        }
        for (interface, expected_ifindex) in additional_interfaces {
            if let Err(error) = kernel.attach_interface(&interface, expected_ifindex) {
                return Err(rollback_error(kernel.as_mut(), error));
            }
        }

        Ok(Self {
            kernel,
            detached: false,
        })
    }

    pub fn install_endpoint(
        &mut self,
        key: EndpointKey,
        value: EndpointValue,
    ) -> Result<(), EbpfError> {
        self.active_kernel()?.install_endpoint(key, value)
    }

    pub fn remove_endpoint(&mut self, key: EndpointKey) -> Result<(), EbpfError> {
        self.active_kernel()?.remove_endpoint(key)
    }

    pub fn install_port(&mut self, key: PortKey, value: PortValue) -> Result<(), EbpfError> {
        self.active_kernel()?.install_port(key, value)
    }

    pub fn remove_port(&mut self, key: PortKey) -> Result<(), EbpfError> {
        self.active_kernel()?.remove_port(key)
    }

    pub fn set_policy(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), EbpfError> {
        self.active_kernel()?.set_policy(key, value)
    }

    pub fn metrics(&mut self) -> Result<EbpfMetrics, EbpfError> {
        self.active_kernel()?.counters().map(Into::into)
    }

    pub fn detach(&mut self) -> Result<(), EbpfError> {
        if self.detached {
            return Ok(());
        }
        self.kernel.detach()?;
        self.detached = true;
        Ok(())
    }

    fn active_kernel(&mut self) -> Result<&mut dyn KernelAdapter, EbpfError> {
        if self.detached {
            Err(EbpfError::Detached)
        } else {
            Ok(self.kernel.as_mut())
        }
    }
}

impl VerifiedPinnedNetwork {
    pub fn install_endpoint(
        &self,
        key: EndpointKey,
        value: EndpointValue,
    ) -> Result<(), EbpfError> {
        verify_pinned_tree(&self.identity)?;
        update_verified_hash::<4, 12>(
            &self.network_id,
            &self.identity,
            ENDPOINTS_MAP_NAME,
            key.encode(),
            value.encode(),
        )
    }

    pub fn install_port(&self, key: PortKey, value: PortValue) -> Result<(), EbpfError> {
        verify_pinned_tree(&self.identity)?;
        update_verified_hash::<4, 8>(
            &self.network_id,
            &self.identity,
            PORTS_MAP_NAME,
            key.encode(),
            value.encode(),
        )
    }

    pub fn remove_endpoint(&self, key: EndpointKey) -> Result<(), EbpfError> {
        verify_pinned_tree(&self.identity)?;
        delete_verified_hash::<4, 12>(
            &self.network_id,
            &self.identity,
            ENDPOINTS_MAP_NAME,
            key.encode(),
        )
    }

    pub fn remove_port(&self, key: PortKey) -> Result<(), EbpfError> {
        verify_pinned_tree(&self.identity)?;
        delete_verified_hash::<4, 8>(
            &self.network_id,
            &self.identity,
            PORTS_MAP_NAME,
            key.encode(),
        )
    }
}

fn verified_map_data(
    network_id: &str,
    identity: &PinnedNetworkIdentity,
    map_name: &'static str,
) -> Result<aya::maps::MapData, EbpfError> {
    let relative = format!("maps/{map_name}");
    let expected = identity
        .objects
        .iter()
        .find(|item| item.relative_path == relative && !item.directory)
        .ok_or_else(|| EbpfError::MapOperation {
            operation: "verify pinned ownership",
            map: map_name,
            reason: "persisted map identity is missing".to_string(),
        })?;
    let expected_map_id = expected.map_id.ok_or_else(|| EbpfError::MapOperation {
        operation: "verify pinned ownership",
        map: map_name,
        reason: "persisted map id is missing".to_string(),
    })?;
    let path = pinned_map_path(network_id, map_name)?;
    let data = aya::maps::MapData::from_pin(&path).map_err(|error| EbpfError::MapOperation {
        operation: "open verified pinned map",
        map: map_name,
        reason: error.to_string(),
    })?;
    let actual_map_id =
        data.info()
            .map(|info| info.id())
            .map_err(|error| EbpfError::MapOperation {
                operation: "read verified pinned map identity",
                map: map_name,
                reason: error.to_string(),
            })?;
    if actual_map_id != expected_map_id {
        return Err(EbpfError::MapOperation {
            operation: "verify pinned ownership",
            map: map_name,
            reason: format!("map id changed from {expected_map_id} to {actual_map_id}"),
        });
    }
    Ok(data)
}

fn update_verified_hash<const K: usize, const V: usize>(
    network_id: &str,
    identity: &PinnedNetworkIdentity,
    map_name: &'static str,
    key: [u8; K],
    value: [u8; V],
) -> Result<(), EbpfError> {
    let map_data = aya::maps::Map::HashMap(verified_map_data(network_id, identity, map_name)?);
    let mut map =
        aya::maps::HashMap::<_, [u8; K], [u8; V]>::try_from(map_data).map_err(|error| {
            EbpfError::MapOperation {
                operation: "reopen verified pinned map",
                map: map_name,
                reason: error.to_string(),
            }
        })?;
    map.insert(key, value, 0)
        .map_err(|error| EbpfError::MapOperation {
            operation: "update verified pinned key",
            map: map_name,
            reason: error.to_string(),
        })
}

fn verify_pinned_tree(identity: &PinnedNetworkIdentity) -> Result<(), EbpfError> {
    fn visit(
        root: &Path,
        path: &Path,
        observed: &mut Vec<PinnedObjectIdentity>,
    ) -> Result<(), EbpfError> {
        use std::os::unix::fs::MetadataExt as _;
        let metadata =
            std::fs::symlink_metadata(path).map_err(|error| EbpfError::MapOperation {
                operation: "verify pinned ownership",
                map: "pin tree",
                reason: error.to_string(),
            })?;
        if metadata.file_type().is_symlink() {
            return Err(EbpfError::MapOperation {
                operation: "verify pinned ownership",
                map: "pin tree",
                reason: format!("symlink in pin tree: {}", path.display()),
            });
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|error| EbpfError::MapOperation {
                operation: "verify pinned ownership",
                map: "pin tree",
                reason: error.to_string(),
            })?;
        let persisted = PinnedObjectIdentity {
            relative_path: relative.display().to_string(),
            device: metadata.dev(),
            inode: metadata.ino(),
            directory: metadata.is_dir(),
            map_id: None,
        };
        observed.push(persisted);
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|error| EbpfError::MapOperation {
                operation: "verify pinned ownership",
                map: "pin tree",
                reason: error.to_string(),
            })? {
                let entry = entry.map_err(|error| EbpfError::MapOperation {
                    operation: "verify pinned ownership",
                    map: "pin tree",
                    reason: error.to_string(),
                })?;
                visit(root, &entry.path(), observed)?;
            }
        }
        Ok(())
    }

    let mut observed = Vec::new();
    visit(&identity.root, &identity.root, &mut observed)?;
    if observed.len() != identity.objects.len() {
        return Err(EbpfError::MapOperation {
            operation: "verify pinned ownership",
            map: "pin tree",
            reason: "pin tree entry count changed".to_string(),
        });
    }
    for current in observed {
        let expected = identity
            .objects
            .iter()
            .find(|item| item.relative_path == current.relative_path)
            .ok_or_else(|| EbpfError::MapOperation {
                operation: "verify pinned ownership",
                map: "pin tree",
                reason: format!("foreign pin entry: {}", current.relative_path),
            })?;
        if expected.device != current.device
            || expected.inode != current.inode
            || expected.directory != current.directory
        {
            return Err(EbpfError::MapOperation {
                operation: "verify pinned ownership",
                map: "pin tree",
                reason: format!("pin identity changed: {}", current.relative_path),
            });
        }
    }
    Ok(())
}

fn delete_verified_hash<const K: usize, const V: usize>(
    network_id: &str,
    identity: &PinnedNetworkIdentity,
    map_name: &'static str,
    key: [u8; K],
) -> Result<(), EbpfError> {
    let map_data = aya::maps::Map::HashMap(verified_map_data(network_id, identity, map_name)?);
    let mut map =
        aya::maps::HashMap::<_, [u8; K], [u8; V]>::try_from(map_data).map_err(|error| {
            EbpfError::MapOperation {
                operation: "reopen verified pinned map",
                map: map_name,
                reason: error.to_string(),
            }
        })?;
    match map.remove(&key) {
        Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
        Err(error) => Err(EbpfError::MapOperation {
            operation: "delete verified pinned key",
            map: map_name,
            reason: error.to_string(),
        }),
    }
}

impl PreparedEbpfNetwork {
    pub fn config(&self) -> &EbpfNetworkConfig {
        &self.config
    }

    pub fn prepare_interface(
        &mut self,
        interface: &str,
        expected_ifindex: u32,
    ) -> Result<(), EbpfError> {
        validate_network_id(interface)?;
        if interface == self.config.interface
            || self
                .additional_interfaces
                .iter()
                .any(|(value, _)| value == interface)
        {
            return Err(EbpfError::InvalidAdapterState {
                reason: format!("classifier interface {interface} is duplicated"),
            });
        }
        self.kernel
            .preflight_interface(interface, expected_ifindex)?;
        self.additional_interfaces
            .push((interface.to_string(), expected_ifindex));
        Ok(())
    }

    /// Attach the already-loaded classifiers to a newly created per-container
    /// interface. The interface is owned by the container lifecycle and is
    /// removed with its veth, so it is intentionally not part of the shared
    /// network's persisted filter set.
    pub fn attach_interface(
        &mut self,
        interface: &str,
        expected_ifindex: u32,
    ) -> Result<(), EbpfError> {
        validate_network_id(interface)?;
        if interface == self.config.interface {
            return Err(EbpfError::InvalidAdapterState {
                reason: format!("classifier interface {interface} is duplicated"),
            });
        }
        self.kernel
            .preflight_interface(interface, expected_ifindex)?;
        self.kernel
            .attach_interface(interface, expected_ifindex)
            .map_err(|error| EbpfError::Attach {
                classifier: "ferro_ingress/ferro_egress".to_string(),
                reason: error.to_string(),
            })
    }

    pub fn attach(self) -> Result<EbpfNetwork, EbpfError> {
        EbpfNetwork::commit_prepared(self.kernel, self.config, self.additional_interfaces)
    }
}

fn pinned_map_path(network_id: &str, map_name: &str) -> Result<PathBuf, EbpfError> {
    validate_network_id(network_id)?;
    Ok(Path::new(FERRO_NETWORK_ROOT)
        .join(network_id)
        .join("maps")
        .join(map_name))
}

#[cfg(test)]
fn hex_bytes(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
fn build_pinned_map_update_command(
    network_id: &str,
    map_name: &'static str,
    key: &[u8],
    value: &[u8],
) -> Result<Vec<String>, EbpfError> {
    let path = pinned_map_path(network_id, map_name)?;
    let mut command = vec![
        "bpftool".to_string(),
        "map".to_string(),
        "update".to_string(),
        "pinned".to_string(),
        path.display().to_string(),
        "key".to_string(),
        "hex".to_string(),
    ];
    command.extend(hex_bytes(key));
    command.extend(["value".to_string(), "hex".to_string()]);
    command.extend(hex_bytes(value));
    command.push("any".to_string());
    Ok(command)
}

#[cfg(test)]
fn build_pinned_map_delete_command(
    network_id: &str,
    map_name: &'static str,
    key: &[u8],
) -> Result<Vec<String>, EbpfError> {
    let path = pinned_map_path(network_id, map_name)?;
    let mut command = vec![
        "bpftool".to_string(),
        "map".to_string(),
        "delete".to_string(),
        "pinned".to_string(),
        path.display().to_string(),
        "key".to_string(),
        "hex".to_string(),
    ];
    command.extend(hex_bytes(key));
    Ok(command)
}

impl Drop for EbpfNetwork {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

pub fn embedded_object_sha256() -> [u8; 32] {
    sha256(crate::ebpf_loader::embedded_object())
}

pub fn embedded_object_abi() -> Result<u32, EbpfError> {
    Ok(validate_embedded_object(crate::ebpf_loader::embedded_object())?.program_abi)
}

/// Return the packaged security-monitor eBPF object bytes produced by the
/// pinned Aya build. The runtime installer may publish these bytes to its
/// configured system object path before loading the tracepoint program.
pub fn embedded_security_object() -> &'static [u8] {
    include_bytes!(env!("FERRO_SECURITY_EBPF_OBJECT"))
}

fn validate_config(config: &EbpfNetworkConfig) -> Result<(), EbpfError> {
    validate_network_id(&config.network_id)?;
    if config.interface.is_empty()
        || config.interface.len() > 15
        || config.interface == "."
        || config.interface == ".."
        || config
            .interface
            .bytes()
            .any(|byte| byte == 0 || byte == b'/')
    {
        return Err(EbpfError::InvalidConfig {
            reason: format!("invalid interface name `{}`", config.interface),
        });
    }
    if config.external_ifindex == 0 {
        return Err(EbpfError::InvalidConfig {
            reason: "external ifindex must be nonzero".to_string(),
        });
    }
    if config.snat_port_start == 0 || config.snat_port_start > config.snat_port_end {
        return Err(EbpfError::InvalidConfig {
            reason: "SNAT range must be a nonzero inclusive range".to_string(),
        });
    }
    if u32::from(config.snat_port_end) - u32::from(config.snat_port_start) + 1 < 4 {
        return Err(EbpfError::InvalidConfig {
            reason: "SNAT range must contain at least four ports".to_string(),
        });
    }
    Ok(())
}

fn validate_network_id(network_id: &str) -> Result<(), EbpfError> {
    if network_id.is_empty()
        || network_id.len() > 63
        || network_id == "."
        || network_id == ".."
        || !network_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(EbpfError::InvalidNetworkId {
            network_id: network_id.to_string(),
        });
    }
    Ok(())
}

fn prove_reserved_range(contents: &str, start: u16, end: u16) -> Result<(), EbpfError> {
    let mut intervals = Vec::new();
    for raw_token in contents.trim().split(',') {
        let token = raw_token.trim();
        if token.is_empty() {
            continue;
        }
        let (first, last) = match token.split_once('-') {
            Some((first, last)) => (parse_port(first, token)?, parse_port(last, token)?),
            None => {
                let port = parse_port(token, token)?;
                (port, port)
            }
        };
        if first > last {
            return Err(EbpfError::ReservedPortsInvalid {
                token: token.to_string(),
            });
        }
        intervals.push((first, last));
    }
    intervals.sort_unstable();

    let mut next = u32::from(start);
    for (first, last) in intervals {
        let first = u32::from(first);
        let last = u32::from(last);
        if last < next {
            continue;
        }
        if first > next {
            break;
        }
        next = next.max(last + 1);
        if next > u32::from(end) {
            return Ok(());
        }
    }
    Err(EbpfError::SnatRangeNotReserved { start, end })
}

fn parse_port(value: &str, token: &str) -> Result<u16, EbpfError> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| EbpfError::ReservedPortsInvalid {
            token: token.to_string(),
        })
}

fn rollback_error(kernel: &mut dyn KernelAdapter, primary: EbpfError) -> EbpfError {
    match kernel.rollback() {
        Ok(()) => primary,
        Err(rollback) => EbpfError::Rollback {
            primary: primary.to_string(),
            rollback: rollback.to_string(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProgram {
    pub name: String,
    pub object_path: String,
    pub section: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityMonitorConfig {
    pub object_path: String,
    pub pin_root: String,
    pub events: Vec<String>,
}

/// Stable map name exported by the packaged security-monitor object.
pub const SECURITY_MONITOR_RING_MAP_NAME: &str = "FERRO_SECURITY_EVENTS";

/// Maximum number of decoded security-monitor events retained in memory.
/// Kernel delivery must never be able to grow a daemon process without bound.
pub const SECURITY_MONITOR_MAX_BUFFER_EVENTS: usize = 1024;
const SECURITY_MONITOR_MAX_PAYLOAD_BYTES: usize = 4096;
/// Fixed wire width emitted by the security-monitor eBPF ring buffer.
///
/// The producer uses a deliberately simple native-independent layout: a
/// NUL-padded UTF-8 event name, little-endian pid/uid/timestamp fields, and a
/// NUL-padded UTF-8 payload. Keeping the record fixed-width lets the consumer
/// reject truncated or oversized kernel data before it reaches the durable
/// receipt sink.
pub const SECURITY_MONITOR_EVENT_NAME_BYTES: usize = 32;
pub const SECURITY_MONITOR_EVENT_PAYLOAD_BYTES: usize = 256;
pub const SECURITY_MONITOR_EVENT_WIRE_BYTES: usize =
    SECURITY_MONITOR_EVENT_NAME_BYTES + 4 + 4 + 8 + SECURITY_MONITOR_EVENT_PAYLOAD_BYTES;
/// Receipts are durable, but the monitor must not turn an unbounded event
/// stream into unbounded disk usage. Operators can rotate this file between
/// runs after exporting the records they need.
pub const SECURITY_MONITOR_MAX_RECEIPT_BYTES: u64 = 8 * 1024 * 1024;
const SECURITY_MONITOR_RECEIPT_SCHEMA: &str = "ferrocrate/security-monitor-receipt/v1";

/// Stable, bounded representation of one syscall tracepoint notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityMonitorEvent {
    pub event: String,
    pub pid: u32,
    pub uid: u32,
    pub timestamp_ns: u64,
    pub payload: String,
}

impl SecurityMonitorEvent {
    pub fn new(
        event: &str,
        pid: u32,
        uid: u32,
        timestamp_ns: u64,
        payload: impl Into<String>,
    ) -> Result<Self, ExecError> {
        let event = sanitize_event(event)?;
        let payload = payload.into();
        if payload.len() > SECURITY_MONITOR_MAX_PAYLOAD_BYTES {
            return Err(ExecError::CommandFailed {
                cmd: format!("event={event}"),
                stderr: "security monitor payload exceeds bounded size".to_string(),
            });
        }
        Ok(Self {
            event,
            pid,
            uid,
            timestamp_ns,
            payload,
        })
    }

    /// Decode one bounded record from the security-monitor ring-buffer ABI.
    ///
    /// This function is independent of Aya's map handle so admission and
    /// buffering can be tested without a privileged BPF filesystem. The caller
    /// must pass exactly one complete wire record.
    pub fn decode_kernel_record(bytes: &[u8]) -> Result<Self, ExecError> {
        if bytes.len() != SECURITY_MONITOR_EVENT_WIRE_BYTES {
            return Err(ExecError::CommandFailed {
                cmd: "decode security monitor ring-buffer record".to_string(),
                stderr: format!(
                    "record has {} bytes; expected {}",
                    bytes.len(),
                    SECURITY_MONITOR_EVENT_WIRE_BYTES
                ),
            });
        }
        let name = decode_nul_padded(&bytes[..SECURITY_MONITOR_EVENT_NAME_BYTES], "event name")?;
        let pid_offset = SECURITY_MONITOR_EVENT_NAME_BYTES;
        let pid =
            u32::from_le_bytes(bytes[pid_offset..pid_offset + 4].try_into().map_err(|_| {
                ExecError::CommandFailed {
                    cmd: "decode security monitor ring-buffer record".to_string(),
                    stderr: "pid field is truncated".to_string(),
                }
            })?);
        let uid_offset = pid_offset + 4;
        let uid =
            u32::from_le_bytes(bytes[uid_offset..uid_offset + 4].try_into().map_err(|_| {
                ExecError::CommandFailed {
                    cmd: "decode security monitor ring-buffer record".to_string(),
                    stderr: "uid field is truncated".to_string(),
                }
            })?);
        let timestamp_offset = uid_offset + 4;
        let timestamp_ns = u64::from_le_bytes(
            bytes[timestamp_offset..timestamp_offset + 8]
                .try_into()
                .map_err(|_| ExecError::CommandFailed {
                    cmd: "decode security monitor ring-buffer record".to_string(),
                    stderr: "timestamp field is truncated".to_string(),
                })?,
        );
        let payload_offset = timestamp_offset + 8;
        let payload = decode_nul_padded(
            &bytes[payload_offset..payload_offset + SECURITY_MONITOR_EVENT_PAYLOAD_BYTES],
            "event payload",
        )?;
        Self::new(&name, pid, uid, timestamp_ns, payload)
    }
}

fn decode_nul_padded(bytes: &[u8], field: &str) -> Result<String, ExecError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = std::str::from_utf8(&bytes[..end]).map_err(|_| ExecError::CommandFailed {
        cmd: "decode security monitor ring-buffer record".to_string(),
        stderr: format!("{field} is not valid UTF-8"),
    })?;
    if value.chars().any(char::is_control) {
        return Err(ExecError::CommandFailed {
            cmd: "decode security monitor ring-buffer record".to_string(),
            stderr: format!("{field} contains control characters"),
        });
    }
    Ok(value.to_string())
}

/// Fixed-capacity event queue for the eventual ring-buffer consumer.
/// Overflow drops the oldest record and increments a visible counter.
#[derive(Debug, Default)]
pub struct SecurityMonitorBuffer {
    events: VecDeque<SecurityMonitorEvent>,
    dropped: u64,
}

/// Userspace handle for a pinned security-monitor eBPF ring buffer.
///
/// The map is opened by file descriptor through Aya; no shell command is
/// involved. Callers can poll with drain_to, then persist decoded events using
/// the existing receipt writer.
pub struct SecurityMonitorRingBuffer {
    ring: RingBuf<MapData>,
}

impl SecurityMonitorRingBuffer {
    /// Open an already-pinned ring-buffer map.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExecError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(ExecError::CommandFailed {
                cmd: "open security monitor ring buffer".to_string(),
                stderr: "ring-buffer pin path must be absolute".to_string(),
            });
        }
        let map = MapData::from_pin(path).map_err(|error| ExecError::CommandFailed {
            cmd: format!("open security monitor ring buffer {}", path.display()),
            stderr: error.to_string(),
        })?;
        let ring = Map::from_map_data(map)
            .and_then(RingBuf::try_from)
            .map_err(|error| ExecError::CommandFailed {
                cmd: format!("open security monitor ring buffer {}", path.display()),
                stderr: error.to_string(),
            })?;
        Ok(Self { ring })
    }

    /// Drain all currently available records into the bounded event buffer.
    pub fn drain_to(&mut self, buffer: &mut SecurityMonitorBuffer) -> Result<usize, ExecError> {
        let mut drained = 0;
        while let Some(record) = self.ring.next() {
            let event = SecurityMonitorEvent::decode_kernel_record(&record)?;
            buffer.push(event);
            drained += 1;
        }
        Ok(drained)
    }
}

impl SecurityMonitorBuffer {
    pub fn push(&mut self, event: SecurityMonitorEvent) {
        if self.events.len() == SECURITY_MONITOR_MAX_BUFFER_EVENTS {
            self.events.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.events.push_back(event);
    }

    /// Decode and queue one kernel ring-buffer record. Invalid records never
    /// alter queue length or drop accounting.
    pub fn ingest_kernel_record(&mut self, bytes: &[u8]) -> Result<(), ExecError> {
        let event = SecurityMonitorEvent::decode_kernel_record(bytes)?;
        self.push(event);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<SecurityMonitorEvent> {
        self.events.pop_front()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Persist queued events in FIFO order, retaining an event in memory until
    /// its receipt has been durably written. This makes a failed write
    /// retryable instead of silently losing the kernel notification.
    pub fn drain_to(
        &mut self,
        sink: &mut SecurityMonitorReceiptWriter,
    ) -> Result<usize, ExecError> {
        let mut drained = 0;
        while let Some(event) = self.events.front().cloned() {
            sink.append(&event)?;
            self.events.pop_front();
            drained += 1;
        }
        Ok(drained)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SecurityMonitorReceipt {
    schema: String,
    sequence: u64,
    event: SecurityMonitorEvent,
}

/// Durable, bounded JSONL sink for decoded kernel-monitor events.
///
/// The sink validates existing records before accepting new ones, resumes the
/// sequence monotonically after a daemon restart, writes mode-0600 files, and
/// calls `sync_data` for every receipt. It deliberately rejects a full file so
/// callers can surface backpressure instead of silently dropping evidence.
#[derive(Debug)]
pub struct SecurityMonitorReceiptWriter {
    file: File,
    path: PathBuf,
    next_sequence: u64,
}

impl SecurityMonitorReceiptWriter {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ExecError> {
        let path = path.as_ref().to_path_buf();
        if !path.is_absolute() {
            return Err(receipt_error(&path, "receipt path must be absolute"));
        }
        let parent = path.parent().ok_or_else(|| {
            receipt_error(&path, "receipt path must have an existing parent directory")
        })?;
        let metadata = std::fs::metadata(parent).map_err(|source| ExecError::Io {
            cmd: format!("open security monitor receipt {}", path.display()),
            source,
        })?;
        if !metadata.is_dir() {
            return Err(receipt_error(&path, "receipt parent must be a directory"));
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|source| ExecError::Io {
                cmd: format!("open security monitor receipt {}", path.display()),
                source,
            })?;
        let length = file
            .metadata()
            .map_err(|source| ExecError::Io {
                cmd: format!("stat security monitor receipt {}", path.display()),
                source,
            })?
            .len();
        if length > SECURITY_MONITOR_MAX_RECEIPT_BYTES {
            return Err(receipt_error(&path, "receipt file exceeds bounded size"));
        }
        let mut next_sequence = 0;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| ExecError::Io {
                cmd: format!("read security monitor receipt {}", path.display()),
                source,
            })?;
        for line in BufReader::new(&file).lines() {
            let line = line.map_err(|source| ExecError::Io {
                cmd: format!("read security monitor receipt {}", path.display()),
                source,
            })?;
            let receipt: SecurityMonitorReceipt =
                serde_json::from_str(&line).map_err(|error| ExecError::CommandFailed {
                    cmd: format!("read security monitor receipt {}", path.display()),
                    stderr: format!("invalid receipt: {error}"),
                })?;
            if receipt.schema != SECURITY_MONITOR_RECEIPT_SCHEMA {
                return Err(receipt_error(&path, "receipt schema is unsupported"));
            }
            next_sequence = next_sequence.max(
                receipt
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| receipt_error(&path, "receipt sequence exhausted"))?,
            );
        }
        file.seek(SeekFrom::End(0))
            .map_err(|source| ExecError::Io {
                cmd: format!("append security monitor receipt {}", path.display()),
                source,
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                |source| ExecError::Io {
                    cmd: format!("protect security monitor receipt {}", path.display()),
                    source,
                },
            )?;
        }
        Ok(Self {
            file,
            path,
            next_sequence,
        })
    }

    pub fn append(&mut self, event: &SecurityMonitorEvent) -> Result<u64, ExecError> {
        let receipt = SecurityMonitorReceipt {
            schema: SECURITY_MONITOR_RECEIPT_SCHEMA.to_string(),
            sequence: self.next_sequence,
            event: event.clone(),
        };
        let mut encoded =
            serde_json::to_vec(&receipt).map_err(|error| ExecError::CommandFailed {
                cmd: format!("write security monitor receipt {}", self.path.display()),
                stderr: error.to_string(),
            })?;
        encoded.push(b'\n');
        let current = self
            .file
            .metadata()
            .map_err(|source| ExecError::Io {
                cmd: format!("stat security monitor receipt {}", self.path.display()),
                source,
            })?
            .len();
        if current.saturating_add(encoded.len() as u64) > SECURITY_MONITOR_MAX_RECEIPT_BYTES {
            return Err(receipt_error(&self.path, "receipt capacity exhausted"));
        }
        self.file
            .write_all(&encoded)
            .map_err(|source| ExecError::Io {
                cmd: format!("write security monitor receipt {}", self.path.display()),
                source,
            })?;
        self.file.sync_data().map_err(|source| ExecError::Io {
            cmd: format!("sync security monitor receipt {}", self.path.display()),
            source,
        })?;
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(sequence)
    }
}

fn receipt_error(path: &Path, stderr: &str) -> ExecError {
    ExecError::CommandFailed {
        cmd: format!("security monitor receipt {}", path.display()),
        stderr: stderr.to_string(),
    }
}

pub fn build_bpftool_load_cmd(program: &EbpfProgram, pin_path: &str) -> Vec<String> {
    vec![
        "bpftool".into(),
        "prog".into(),
        "load".into(),
        program.object_path.clone(),
        pin_path.into(),
        "type".into(),
        program.section.clone(),
    ]
}

/// Build the typed `bpftool prog load` command for a security monitor program
/// and explicitly pin its ring-buffer map.  Explicit map pinning is required
/// because the userspace Aya consumer opens the map by path; relying on
/// bpftool's implicit map lifetime would leave no durable hand-off between
/// the loader and consumer.
pub fn build_bpftool_load_with_map_cmd(
    program: &EbpfProgram,
    pin_path: &str,
    map_pin_root: &str,
) -> Vec<String> {
    let mut command = build_bpftool_load_cmd(program, pin_path);
    command.extend(["pinmaps".to_string(), map_pin_root.to_string()]);
    command
}

/// Return the per-event ring-buffer map pin path used by the security
/// monitor.  Each loaded tracepoint program owns one map instance, so event
/// names are part of the path and cannot collide during multi-event setup.
pub fn security_monitor_ring_map_path(pin_root: &str, event: &str) -> String {
    let _ = event;
    format!("{pin_root}/{SECURITY_MONITOR_RING_MAP_NAME}")
}

pub fn build_tc_attach_cmd(iface: &str, pin_path: &str, direction: &str) -> Vec<String> {
    vec![
        "tc".into(),
        "filter".into(),
        "add".into(),
        "dev".into(),
        iface.into(),
        direction.into(),
        "bpf".into(),
        "da".into(),
        "pinned".into(),
        pin_path.into(),
    ]
}

pub fn build_xdp_attach_cmd(iface: &str, pin_path: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        iface.into(),
        "xdp".into(),
        "pinned".into(),
        pin_path.into(),
    ]
}

pub fn build_tracepoint_attach_cmd(pin_path: &str, category: &str, event: &str) -> Vec<String> {
    vec![
        "bpftool".into(),
        "prog".into(),
        "attach".into(),
        "pinned".into(),
        pin_path.into(),
        "tracepoint".into(),
        category.into(),
        event.into(),
    ]
}

pub fn install_security_monitor(config: &SecurityMonitorConfig) -> Result<Vec<String>, ExecError> {
    let events = normalize_security_events(&config.events)?;
    let mut installed = Vec::new();
    for normalized in events {
        let pin_path = format!("{}/{}", config.pin_root, normalized);
        let map_pin_path = security_monitor_ring_map_path(&config.pin_root, &normalized);
        let link_pin_path = format!("{pin_path}-link");
        let mut ebpf =
            Ebpf::load_file(&config.object_path).map_err(|error| ExecError::CommandFailed {
                cmd: format!("load security monitor object {}", config.object_path),
                stderr: error.to_string(),
            })?;
        {
            let program = ebpf
                .program_mut("ferro_security_tracepoint")
                .ok_or_else(|| ExecError::CommandFailed {
                    cmd: format!("load security monitor object {}", config.object_path),
                    stderr: "missing ferro_security_tracepoint program".to_string(),
                })?;
            let program_result: Result<&mut TracePoint, _> = program.try_into();
            let program = program_result.map_err(|error| ExecError::CommandFailed {
                cmd: format!("load security monitor object {}", config.object_path),
                stderr: error.to_string(),
            })?;
            program.load().map_err(|error| ExecError::CommandFailed {
                cmd: format!("load security monitor event {normalized}"),
                stderr: error.to_string(),
            })?;
            program
                .pin(&pin_path)
                .map_err(|error| ExecError::CommandFailed {
                    cmd: format!("pin security monitor event {normalized}"),
                    stderr: error.to_string(),
                })?;
        }
        ebpf.map_mut(SECURITY_MONITOR_RING_MAP_NAME)
            .ok_or_else(|| ExecError::CommandFailed {
                cmd: format!("load security monitor event {normalized}"),
                stderr: format!("missing {SECURITY_MONITOR_RING_MAP_NAME} map"),
            })?
            .pin(&map_pin_path)
            .map_err(|error| ExecError::CommandFailed {
                cmd: format!("pin security monitor map {normalized}"),
                stderr: error.to_string(),
            })?;
        let program = ebpf
            .program_mut("ferro_security_tracepoint")
            .ok_or_else(|| ExecError::CommandFailed {
                cmd: format!("load security monitor object {}", config.object_path),
                stderr: "missing ferro_security_tracepoint program".to_string(),
            })?;
        let program_result: Result<&mut TracePoint, _> = program.try_into();
        let program = program_result.map_err(|error| ExecError::CommandFailed {
            cmd: format!("load security monitor object {}", config.object_path),
            stderr: error.to_string(),
        })?;
        let link_id = program
            .attach("syscalls", &format!("sys_enter_{normalized}"))
            .map_err(|error| ExecError::CommandFailed {
                cmd: format!("attach security monitor event {normalized}"),
                stderr: error.to_string(),
            })?;
        let link = program
            .take_link(link_id)
            .map_err(|error| ExecError::CommandFailed {
                cmd: format!("retain security monitor event {normalized}"),
                stderr: error.to_string(),
            })?;
        let fd_link = FdLink::try_from(link).map_err(|error| ExecError::CommandFailed {
            cmd: format!("retain security monitor event {normalized}"),
            stderr: error.to_string(),
        })?;
        fd_link
            .pin(&link_pin_path)
            .map_err(|error| ExecError::CommandFailed {
                cmd: format!("pin security monitor link {normalized}"),
                stderr: error.to_string(),
            })?;
        installed.push(normalized.clone());
        if let Err(error) = exec_cmd_capture(&[
            "bpftool".to_string(),
            "prog".to_string(),
            "show".to_string(),
            "pinned".to_string(),
            pin_path,
        ]) {
            cleanup_security_monitor_paths(&config.pin_root, &installed)?;
            return Err(error);
        }
    }
    Ok(installed)
}

/// Detach and remove all pinned security-monitor programs for the selected
/// events. Cleanup is idempotent and uses only typed argv execution; callers
/// use it during rollback and normal container teardown.
pub fn cleanup_security_monitor(config: &SecurityMonitorConfig) -> Result<(), ExecError> {
    let events = normalize_security_events(&config.events)?;
    cleanup_security_monitor_paths(&config.pin_root, &events)
}

fn cleanup_security_monitor_paths(pin_root: &str, events: &[String]) -> Result<(), ExecError> {
    let mut first_error = None;
    for event in events {
        let pin_path = format!("{pin_root}/{event}");
        for path in [
            pin_path.clone(),
            format!("{pin_path}-link"),
            security_monitor_ring_map_path(pin_root, event),
        ] {
            if let Err(error) = std::fs::remove_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    first_error.get_or_insert(ExecError::Io {
                        cmd: format!("remove pinned security monitor {path}"),
                        source: error,
                    });
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn normalize_security_events(events: &[String]) -> Result<Vec<String>, ExecError> {
    const MAX_SECURITY_EVENTS: usize = 32;
    let source = if events.is_empty() {
        default_security_events()
            .iter()
            .map(|event| (*event).to_string())
            .collect::<Vec<_>>()
    } else {
        events.to_vec()
    };
    if source.len() > MAX_SECURITY_EVENTS {
        return Err(ExecError::CommandFailed {
            cmd: format!("events={}", source.len()),
            stderr: "too many security monitor events".to_string(),
        });
    }
    let mut normalized = Vec::with_capacity(source.len());
    for event in source {
        let event = sanitize_event(&event)?;
        if normalized.iter().any(|existing| existing == &event) {
            return Err(ExecError::CommandFailed {
                cmd: format!("event={event}"),
                stderr: "duplicate security monitor event".to_string(),
            });
        }
        normalized.push(event);
    }
    Ok(normalized)
}

fn sanitize_event(event: &str) -> Result<String, ExecError> {
    let normalized = event.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(ExecError::CommandFailed {
            cmd: format!("event={event}"),
            stderr: "invalid security monitor event".to_string(),
        });
    }
    Ok(normalized)
}

fn default_security_events() -> &'static [&'static str] {
    &["execve", "connect", "open", "ptrace", "mount", "unshare"]
}

#[cfg(test)]
mod lifecycle_tests {
    use std::sync::{Arc, Mutex};

    use super::{
        build_bpftool_load_with_map_cmd, build_pinned_map_delete_command,
        build_pinned_map_update_command, embedded_object_sha256, hex_bytes,
        normalize_security_events, EbpfError, EbpfNetwork, EbpfNetworkConfig,
        SecurityMonitorBuffer, SecurityMonitorEvent, SecurityMonitorReceiptWriter,
        SecurityMonitorRingBuffer, EGRESS_CLASSIFIER, INGRESS_CLASSIFIER,
        SECURITY_MONITOR_EVENT_NAME_BYTES, SECURITY_MONITOR_EVENT_PAYLOAD_BYTES,
        SECURITY_MONITOR_EVENT_WIRE_BYTES, SECURITY_MONITOR_MAX_BUFFER_EVENTS,
    };
    use crate::ebpf_abi::{
        EndpointKey, EndpointValue, MetaConfig, PolicyKey, PolicyValue, PortKey, PortValue,
        COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME, META_FLAG_SNAT_RANGE_RESERVED, META_VALUE_LEN,
        PORTS_MAP_NAME, PROGRAM_ABI_VERSION,
    };
    use crate::ebpf_loader::{KernelAdapter, KernelLoadPlan, KernelPreflight};

    #[derive(Debug, Default)]
    struct FakeState {
        events: Vec<String>,
        network_preflights: Vec<String>,
        interface_preflights: Vec<(String, u32)>,
        interface_attaches: Vec<(String, u32)>,
        metadata: Option<[u8; META_VALUE_LEN]>,
        endpoints: Vec<(EndpointKey, EndpointValue)>,
        ports: Vec<(PortKey, PortValue)>,
        policies: Vec<(PolicyKey, PolicyValue)>,
        rollback_count: usize,
        detach_count: usize,
    }

    #[test]
    fn security_monitor_normalizes_before_execution_and_rejects_duplicates() {
        let events = normalize_security_events(&[" Execve ".to_string(), "connect".to_string()])
            .expect("valid events");
        assert_eq!(events, vec!["execve", "connect"]);
        let error = normalize_security_events(&["open".to_string(), "OPEN".to_string()])
            .expect_err("duplicate normalized event");
        assert!(error
            .to_string()
            .contains("duplicate security monitor event"));
        let error = normalize_security_events(&["execve".to_string(), "bad/name".to_string()])
            .expect_err("invalid later event");
        assert!(error.to_string().contains("invalid security monitor event"));
    }

    #[test]
    fn security_monitor_rejects_unbounded_event_configuration() {
        let events = (0..33)
            .map(|index| format!("event_{index}"))
            .collect::<Vec<_>>();
        let error = normalize_security_events(&events).expect_err("event list must be bounded");
        assert!(error
            .to_string()
            .contains("too many security monitor events"));
    }

    #[test]
    fn security_monitor_event_schema_is_normalized_and_payload_bounded() {
        let event =
            SecurityMonitorEvent::new(" Execve ", 42, 1000, 7, "ok").expect("valid bounded event");
        assert_eq!(event.event, "execve");
        assert_eq!(event.pid, 42);
        let oversized = "x".repeat(4097);
        let error = SecurityMonitorEvent::new("open", 1, 1, 1, oversized)
            .expect_err("oversized payload must fail closed");
        assert!(error.to_string().contains("payload exceeds bounded size"));
    }

    #[test]
    fn security_monitor_decodes_fixed_wire_record_and_ingests_it() {
        let mut bytes = vec![0_u8; SECURITY_MONITOR_EVENT_WIRE_BYTES];
        bytes[..4].copy_from_slice(b"open");
        let pid_offset = SECURITY_MONITOR_EVENT_NAME_BYTES;
        bytes[pid_offset..pid_offset + 4].copy_from_slice(&42_u32.to_le_bytes());
        bytes[pid_offset + 4..pid_offset + 8].copy_from_slice(&1000_u32.to_le_bytes());
        bytes[pid_offset + 8..pid_offset + 16].copy_from_slice(&7_u64.to_le_bytes());
        let payload_offset = pid_offset + 16;
        bytes[payload_offset..payload_offset + 7].copy_from_slice(b"allowed");
        let event = SecurityMonitorEvent::decode_kernel_record(&bytes).expect("decode");
        assert_eq!(event.event, "open");
        assert_eq!(event.pid, 42);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.timestamp_ns, 7);
        assert_eq!(event.payload, "allowed");

        let mut buffer = SecurityMonitorBuffer::default();
        buffer.ingest_kernel_record(&bytes).expect("ingest");
        assert_eq!(buffer.len(), 1);
        assert_eq!(buffer.dropped(), 0);
        assert_eq!(buffer.pop().expect("event"), event);
    }

    #[test]
    fn security_monitor_rejects_malformed_wire_records_before_queue_mutation() {
        let mut buffer = SecurityMonitorBuffer::default();
        let error = buffer
            .ingest_kernel_record(&[0_u8; SECURITY_MONITOR_EVENT_WIRE_BYTES - 1])
            .expect_err("truncated record");
        assert!(error.to_string().contains("expected"));
        assert!(buffer.is_empty());

        let mut bytes = vec![0_u8; SECURITY_MONITOR_EVENT_WIRE_BYTES];
        bytes[..SECURITY_MONITOR_EVENT_NAME_BYTES].fill(0xff);
        let error = buffer
            .ingest_kernel_record(&bytes)
            .expect_err("invalid UTF-8");
        assert!(error.to_string().contains("UTF-8"));
        assert!(buffer.is_empty());

        bytes.fill(0);
        let payload_offset = SECURITY_MONITOR_EVENT_NAME_BYTES + 16;
        bytes[..4].copy_from_slice(b"open");
        bytes[payload_offset..payload_offset + SECURITY_MONITOR_EVENT_PAYLOAD_BYTES].fill(0);
        bytes[payload_offset] = 1;
        let error = buffer
            .ingest_kernel_record(&bytes)
            .expect_err("control payload");
        assert!(error.to_string().contains("control"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn security_monitor_ring_buffer_rejects_relative_pin_paths_before_kernel_access() {
        let error = match SecurityMonitorRingBuffer::open("security-monitor-events") {
            Ok(_) => panic!("relative pin path must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("absolute"));
    }

    #[test]
    fn security_monitor_load_pins_ring_map_with_stable_per_event_path() {
        let program = super::EbpfProgram {
            name: "ferro_security_open".to_string(),
            object_path: "/usr/lib/ferrocrate/ferro-security.o".to_string(),
            section: "tracepoint".to_string(),
        };
        let command = build_bpftool_load_with_map_cmd(
            &program,
            "/sys/fs/bpf/ferrocrate-security/open",
            "/sys/fs/bpf/ferrocrate-security",
        );
        assert_eq!(
            command,
            vec![
                "bpftool",
                "prog",
                "load",
                "/usr/lib/ferrocrate/ferro-security.o",
                "/sys/fs/bpf/ferrocrate-security/open",
                "type",
                "tracepoint",
                "pinmaps",
                "/sys/fs/bpf/ferrocrate-security",
            ]
        );
        assert_eq!(
            super::security_monitor_ring_map_path("/sys/fs/bpf/ferrocrate-security", "open"),
            "/sys/fs/bpf/ferrocrate-security/FERRO_SECURITY_EVENTS"
        );
    }

    #[test]
    fn security_monitor_buffer_drops_oldest_with_visible_count() {
        let mut buffer = SecurityMonitorBuffer::default();
        for pid in 0..=SECURITY_MONITOR_MAX_BUFFER_EVENTS as u32 {
            buffer.push(SecurityMonitorEvent::new("open", pid, 1000, pid as u64, "x").unwrap());
        }
        assert_eq!(buffer.len(), SECURITY_MONITOR_MAX_BUFFER_EVENTS);
        assert_eq!(buffer.dropped(), 1);
        assert_eq!(buffer.pop().unwrap().pid, 1);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn security_monitor_receipts_are_durable_bounded_and_restart_safe() {
        let temp = tempfile::tempdir().expect("receipt directory");
        let path = temp.path().join("security-monitor.jsonl");
        let event = SecurityMonitorEvent::new("open", 42, 1000, 7, "payload").unwrap();
        let mut buffer = SecurityMonitorBuffer::default();
        buffer.push(event.clone());
        let mut writer = SecurityMonitorReceiptWriter::open(&path).unwrap();
        assert_eq!(buffer.drain_to(&mut writer).unwrap(), 1);
        assert!(buffer.is_empty());
        assert_eq!(writer.append(&event).unwrap(), 1);

        let mut restarted = SecurityMonitorReceiptWriter::open(&path).unwrap();
        assert_eq!(restarted.append(&event).unwrap(), 2);
        let lines = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["schema"], "ferrocrate/security-monitor-receipt/v1");
        assert_eq!(lines[0]["sequence"], 0);
        assert_eq!(lines[2]["sequence"], 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn security_monitor_receipts_reject_relative_and_malformed_files() {
        let relative = SecurityMonitorReceiptWriter::open("security-monitor.jsonl")
            .expect_err("relative receipt path must fail closed");
        assert!(relative.to_string().contains("must be absolute"));
        let temp = tempfile::tempdir().expect("receipt directory");
        let path = temp.path().join("security-monitor.jsonl");
        std::fs::write(&path, b"not-json\n").unwrap();
        let malformed = SecurityMonitorReceiptWriter::open(&path)
            .expect_err("malformed receipt must fail closed");
        assert!(malformed.to_string().contains("invalid receipt"));
    }

    struct FakeKernel {
        state: Arc<Mutex<FakeState>>,
        reserved_ports: String,
        fail_egress_attach: bool,
        replacement_ifindex_at_attach: Option<u32>,
    }

    impl FakeKernel {
        fn valid() -> (Self, Arc<Mutex<FakeState>>) {
            let state = Arc::new(Mutex::new(FakeState::default()));
            (
                Self {
                    state: Arc::clone(&state),
                    reserved_ports: "1-1024,50000-50031".to_string(),
                    fail_egress_attach: false,
                    replacement_ifindex_at_attach: None,
                },
                state,
            )
        }
    }

    impl KernelAdapter for FakeKernel {
        fn reserved_ports(&mut self) -> Result<String, EbpfError> {
            self.state
                .lock()
                .unwrap()
                .events
                .push("reserved".to_string());
            Ok(self.reserved_ports.clone())
        }

        fn preflight(&mut self, request: &KernelPreflight<'_>) -> Result<(), EbpfError> {
            assert_eq!(request.expected_object_sha256, embedded_object_sha256());
            let mut state = self.state.lock().unwrap();
            state
                .network_preflights
                .push(request.network_id.to_string());
            state.events.push("preflight".to_string());
            Ok(())
        }

        fn preflight_interface(
            &mut self,
            interface: &str,
            expected_ifindex: u32,
        ) -> Result<(), EbpfError> {
            let mut state = self.state.lock().unwrap();
            state
                .interface_preflights
                .push((interface.to_string(), expected_ifindex));
            state
                .events
                .push(format!("preflight-interface:{interface}"));
            Ok(())
        }

        fn commit(&mut self, plan: &KernelLoadPlan<'_>) -> Result<(), EbpfError> {
            let mut state = self.state.lock().unwrap();
            state.metadata = Some(plan.metadata);
            state.events.push(format!("attach:{INGRESS_CLASSIFIER}"));
            if self.fail_egress_attach {
                return Err(EbpfError::Attach {
                    classifier: EGRESS_CLASSIFIER.to_string(),
                    reason: "injected".to_string(),
                });
            }
            state.events.push(format!("attach:{EGRESS_CLASSIFIER}"));
            Ok(())
        }

        fn attach_interface(
            &mut self,
            interface: &str,
            expected_ifindex: u32,
        ) -> Result<(), EbpfError> {
            if let Some(actual) = self.replacement_ifindex_at_attach {
                return Err(EbpfError::InterfaceMismatch {
                    interface: interface.to_string(),
                    expected: expected_ifindex,
                    actual,
                });
            }
            let mut state = self.state.lock().unwrap();
            state
                .interface_attaches
                .push((interface.to_string(), expected_ifindex));
            state.events.push(format!("attach-interface:{interface}"));
            Ok(())
        }

        fn install_endpoint(
            &mut self,
            key: EndpointKey,
            value: EndpointValue,
        ) -> Result<(), EbpfError> {
            self.state.lock().unwrap().endpoints.push((key, value));
            Ok(())
        }

        fn remove_endpoint(&mut self, _key: EndpointKey) -> Result<(), EbpfError> {
            Ok(())
        }

        fn install_port(&mut self, key: PortKey, value: PortValue) -> Result<(), EbpfError> {
            self.state.lock().unwrap().ports.push((key, value));
            Ok(())
        }

        fn remove_port(&mut self, _key: PortKey) -> Result<(), EbpfError> {
            Ok(())
        }

        fn set_policy(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), EbpfError> {
            self.state.lock().unwrap().policies.push((key, value));
            Ok(())
        }

        fn counters(&mut self) -> Result<[u64; COUNTER_MAX_ENTRIES as usize], EbpfError> {
            Ok([0; COUNTER_MAX_ENTRIES as usize])
        }

        fn rollback(&mut self) -> Result<(), EbpfError> {
            self.state.lock().unwrap().rollback_count += 1;
            Ok(())
        }

        fn detach(&mut self) -> Result<(), EbpfError> {
            self.state.lock().unwrap().detach_count += 1;
            Ok(())
        }
    }

    fn config() -> EbpfNetworkConfig {
        EbpfNetworkConfig {
            network_id: "test-network".to_string(),
            interface: "eth-test0".to_string(),
            external_ipv4: [203, 0, 113, 8],
            bridge_gateway: [10, 0, 0, 1],
            external_ifindex: 17,
            loopback_ifindex: 1,
            next_hop_mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            snat_port_start: 50_000,
            snat_port_end: 50_031,
            expected_object_sha256: embedded_object_sha256(),
        }
    }

    #[test]
    fn network_backend_typed_pinned_record_commands_preserve_schema_bytes() {
        let endpoint_key = EndpointKey {
            address: [10, 44, 1, 2],
        };
        let endpoint_value = EndpointValue {
            ifindex: 23,
            mac: [2, 0, 0, 0, 0, 23],
            flags: 1,
        };
        let update = build_pinned_map_update_command(
            "shared-bridge",
            ENDPOINTS_MAP_NAME,
            &endpoint_key.encode(),
            &endpoint_value.encode(),
        )
        .unwrap();
        assert_eq!(
            &update[..7],
            [
                "bpftool",
                "map",
                "update",
                "pinned",
                "/sys/fs/bpf/ferrocrate/shared-bridge/maps/FERRO_ENDPOINTS",
                "key",
                "hex",
            ]
        );
        let key_hex = hex_bytes(&endpoint_key.encode());
        assert_eq!(&update[7..7 + key_hex.len()], key_hex);
        assert!(update.ends_with(&["any".to_string()]));

        let port_key = PortKey {
            protocol: 6,
            host_port: 45_123,
        };
        let delete =
            build_pinned_map_delete_command("shared-bridge", PORTS_MAP_NAME, &port_key.encode())
                .unwrap();
        assert_eq!(delete[2], "delete");
        assert_eq!(
            delete[4],
            "/sys/fs/bpf/ferrocrate/shared-bridge/maps/FERRO_PORTS"
        );
        assert_eq!(&delete[7..], hex_bytes(&port_key.encode()));
        assert!(build_pinned_map_delete_command("../foreign", PORTS_MAP_NAME, &[0]).is_err());
    }

    #[test]
    fn network_backend_additional_classifier_is_preflighted_and_unique() {
        let (kernel, state) = FakeKernel::valid();
        let mut prepared = EbpfNetwork::prepare_with(kernel, config()).unwrap();
        prepared.prepare_interface("lo", 1).unwrap();
        assert!(prepared.prepare_interface("lo", 1).is_err());
        prepared.attach().unwrap();
        let state = state.lock().unwrap();
        let events = &state.events;
        let preflight = events
            .iter()
            .position(|event| event == "preflight-interface:lo")
            .unwrap();
        let attach = events
            .iter()
            .position(|event| event == "attach-interface:lo")
            .unwrap();
        assert!(preflight < attach);
        assert_eq!(state.interface_preflights, vec![("lo".to_string(), 1)]);
        assert_eq!(state.interface_attaches, vec![("lo".to_string(), 1)]);
    }

    #[test]
    fn network_backend_additional_ifindex_replacement_fails_before_attach_mutation() {
        let (mut kernel, state) = FakeKernel::valid();
        kernel.replacement_ifindex_at_attach = Some(99);
        let mut prepared = EbpfNetwork::prepare_with(kernel, config()).unwrap();
        prepared.prepare_interface("lo", 1).unwrap();

        assert!(matches!(
            prepared.attach(),
            Err(EbpfError::InterfaceMismatch {
                expected: 1,
                actual: 99,
                ..
            })
        ));
        let state = state.lock().unwrap();
        assert_eq!(state.interface_preflights, vec![("lo".to_string(), 1)]);
        assert!(state.interface_attaches.is_empty());
        assert_eq!(state.rollback_count, 1);
    }

    #[test]
    fn network_backend_one_load_shares_classifiers_and_maps_for_multiple_endpoints() {
        let (kernel, state) = FakeKernel::valid();
        let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();
        for suffix in [2u8, 3] {
            let address = [10, 44, 1, suffix];
            network
                .install_endpoint(
                    EndpointKey { address },
                    EndpointValue {
                        ifindex: u32::from(suffix) + 20,
                        mac: [2, 0, 0, 0, 0, suffix],
                        flags: 0,
                    },
                )
                .unwrap();
            network
                .install_port(
                    PortKey {
                        protocol: 6,
                        host_port: 8_000 + u16::from(suffix),
                    },
                    PortValue {
                        endpoint_address: address,
                        endpoint_port: 80,
                    },
                )
                .unwrap();
        }
        let state = state.lock().unwrap();
        assert_eq!(state.network_preflights, vec!["test-network"]);
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| event.starts_with("attach:"))
                .count(),
            2
        );
        assert_eq!(state.endpoints.len(), 2);
        assert_eq!(state.ports.len(), 2);
    }

    #[test]
    fn network_backend_distinct_bridge_networks_share_host_attach_points_without_rejection() {
        let shared = Arc::new(Mutex::new(FakeState::default()));
        for network_id in ["bridge-a", "bridge-b"] {
            let kernel = FakeKernel {
                state: Arc::clone(&shared),
                reserved_ports: "1-1024,50000-50031".to_string(),
                fail_egress_attach: false,
                replacement_ifindex_at_attach: None,
            };
            let mut network_config = config();
            network_config.network_id = network_id.to_string();
            let mut prepared = EbpfNetwork::prepare_with(kernel, network_config).unwrap();
            prepared.prepare_interface("lo", 1).unwrap();
            prepared.attach().unwrap().persist().unwrap();
        }
        let state = shared.lock().unwrap();
        assert_eq!(state.network_preflights, vec!["bridge-a", "bridge-b"]);
        assert_eq!(state.interface_attaches.len(), 2);
        assert_eq!(
            state
                .events
                .iter()
                .filter(|event| event.starts_with("attach:"))
                .count(),
            4
        );
    }

    #[test]
    fn successful_load_commits_coherent_metadata_and_typed_updates() {
        let (kernel, state) = FakeKernel::valid();
        let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();
        let endpoint = (
            EndpointKey {
                address: [10, 44, 1, 2],
            },
            EndpointValue {
                ifindex: 23,
                mac: [2, 0, 0, 0, 0, 23],
                flags: 1,
            },
        );
        let port = (
            PortKey {
                protocol: 6,
                host_port: 8080,
            },
            PortValue {
                endpoint_address: [10, 44, 1, 2],
                endpoint_port: 80,
            },
        );
        let policy = (
            PolicyKey {
                endpoint_address: [10, 44, 1, 2],
                protocol: 6,
                direction: 1,
                port: 443,
            },
            PolicyValue {
                action: 1,
                log: true,
            },
        );

        network.install_endpoint(endpoint.0, endpoint.1).unwrap();
        network.install_port(port.0, port.1).unwrap();
        network.set_policy(policy.0, policy.1).unwrap();

        let locked = state.lock().unwrap();
        let metadata = MetaConfig::decode(locked.metadata.unwrap());
        assert_eq!(metadata.abi_version, PROGRAM_ABI_VERSION);
        assert_eq!(metadata.flags, META_FLAG_SNAT_RANGE_RESERVED);
        assert_eq!(locked.endpoints, vec![endpoint]);
        assert_eq!(locked.ports, vec![port]);
        assert_eq!(locked.policies, vec![policy]);
    }

    #[test]
    fn incomplete_reservation_fails_before_kernel_preflight() {
        let (mut kernel, state) = FakeKernel::valid();
        kernel.reserved_ports = "50000-50015".to_string();

        assert!(matches!(
            EbpfNetwork::load_with(kernel, config()),
            Err(EbpfError::SnatRangeNotReserved { .. })
        ));
        assert_eq!(state.lock().unwrap().events, vec!["reserved"]);
    }

    #[test]
    fn failed_second_attach_rolls_back_and_detach_is_idempotent() {
        let (mut failing, failed_state) = FakeKernel::valid();
        failing.fail_egress_attach = true;
        assert!(matches!(
            EbpfNetwork::load_with(failing, config()),
            Err(EbpfError::Attach { .. })
        ));
        assert_eq!(failed_state.lock().unwrap().rollback_count, 1);

        let (kernel, detached_state) = FakeKernel::valid();
        let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();
        network.detach().unwrap();
        network.detach().unwrap();
        assert_eq!(detached_state.lock().unwrap().detach_count, 1);
    }

    #[test]
    fn prepare_is_mutation_free_until_attach() {
        let (kernel, state) = FakeKernel::valid();
        let prepared = EbpfNetwork::prepare_with(kernel, config()).unwrap();
        assert!(state
            .lock()
            .unwrap()
            .events
            .iter()
            .all(|event| !event.starts_with("attach:")));

        let _network = prepared.attach().unwrap();
        assert_eq!(
            state
                .lock()
                .unwrap()
                .events
                .iter()
                .filter(|event| event.starts_with("attach:"))
                .count(),
            2
        );
    }

    #[test]
    fn persistent_transfer_disarms_drop_cleanup() {
        let (kernel, state) = FakeKernel::valid();
        let network = EbpfNetwork::prepare_with(kernel, config())
            .unwrap()
            .attach()
            .unwrap();
        network.persist().unwrap();
        assert_eq!(state.lock().unwrap().detach_count, 0);
    }
}
