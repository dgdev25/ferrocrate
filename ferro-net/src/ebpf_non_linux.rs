//! Explicit non-Linux eBPF boundary.
//!
//! Ferrocrate's TC/Aya implementation is Linux-specific. Keeping the public
//! types available on other targets lets the CLI and higher-level crates
//! compile and report a precise capability error instead of pulling Linux file
//! descriptor APIs into a foreign build.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ebpf_abi::{EndpointKey, EndpointValue, PolicyKey, PolicyValue, PortKey, PortValue};
use crate::executor::ExecError;

pub const BPFFS_ROOT: &str = "/sys/fs/bpf";
pub const FERRO_NETWORK_ROOT: &str = "/sys/fs/bpf/ferrocrate";
pub const INGRESS_CLASSIFIER: &str = "ferro_ingress";
pub const EGRESS_CLASSIFIER: &str = "ferro_egress";
pub const SECURITY_MONITOR_RING_MAP_NAME: &str = "FERRO_SECURITY_EVENTS";
pub const SECURITY_MONITOR_MAX_BUFFER_EVENTS: usize = 1024;
pub const SECURITY_MONITOR_EVENT_NAME_BYTES: usize = 32;
pub const SECURITY_MONITOR_EVENT_PAYLOAD_BYTES: usize = 256;
pub const SECURITY_MONITOR_EVENT_WIRE_BYTES: usize =
    SECURITY_MONITOR_EVENT_NAME_BYTES + 4 + 4 + 8 + SECURITY_MONITOR_EVENT_PAYLOAD_BYTES;
pub const SECURITY_MONITOR_MAX_RECEIPT_BYTES: u64 = 8 * 1024 * 1024;

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

#[derive(Debug, Error)]
pub enum EbpfError {
    #[error("eBPF networking is unavailable on this target: {reason}")]
    Unsupported { reason: &'static str },
    #[error("invalid eBPF network id `{network_id}`")]
    InvalidNetworkId { network_id: String },
}

fn unsupported() -> EbpfError {
    EbpfError::Unsupported {
        reason: "TC/Aya eBPF networking requires a Linux kernel",
    }
}

pub struct EbpfNetwork;
pub struct PreparedEbpfNetwork {
    config: EbpfNetworkConfig,
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
    _network_id: String,
    _identity: PinnedNetworkIdentity,
}

impl EbpfNetwork {
    pub fn load(_: EbpfNetworkConfig) -> Result<Self, EbpfError> {
        Err(unsupported())
    }
    pub fn prepare(_: EbpfNetworkConfig) -> Result<PreparedEbpfNetwork, EbpfError> {
        Err(unsupported())
    }
    pub fn attach_interface(&mut self, _: &str, _: u32) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn pinned_map_id(_: &Path) -> Result<u32, EbpfError> {
        Err(unsupported())
    }
    pub fn verify_pinned_network(
        _: &str,
        _: PinnedNetworkIdentity,
    ) -> Result<VerifiedPinnedNetwork, EbpfError> {
        Err(unsupported())
    }
    pub fn install_endpoint(&mut self, _: EndpointKey, _: EndpointValue) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn remove_endpoint(&mut self, _: EndpointKey) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn install_port(&mut self, _: PortKey, _: PortValue) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn remove_port(&mut self, _: PortKey) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn set_policy(&mut self, _: PolicyKey, _: PolicyValue) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn metrics(&mut self) -> Result<EbpfMetrics, EbpfError> {
        Err(unsupported())
    }
    pub fn detach(&mut self) -> Result<(), EbpfError> {
        Ok(())
    }
}

impl PreparedEbpfNetwork {
    pub fn config(&self) -> &EbpfNetworkConfig {
        &self.config
    }
    pub fn prepare_interface(&mut self, _: &str, _: u32) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn attach_interface(&mut self, _: &str, _: u32) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn attach(self) -> Result<EbpfNetwork, EbpfError> {
        Err(unsupported())
    }
}

impl VerifiedPinnedNetwork {
    pub fn install_endpoint(&self, _: EndpointKey, _: EndpointValue) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn install_port(&self, _: PortKey, _: PortValue) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn remove_endpoint(&self, _: EndpointKey) -> Result<(), EbpfError> {
        Err(unsupported())
    }
    pub fn remove_port(&self, _: PortKey) -> Result<(), EbpfError> {
        Err(unsupported())
    }
}

pub fn embedded_object_sha256() -> [u8; 32] {
    [0; 32]
}
pub fn embedded_object_abi() -> Result<u32, EbpfError> {
    Err(unsupported())
}
pub fn embedded_security_object() -> &'static [u8] {
    &[]
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
        Ok(Self {
            event: event.to_string(),
            pid,
            uid,
            timestamp_ns,
            payload: payload.into(),
        })
    }
    pub fn decode_kernel_record(_: &[u8]) -> Result<Self, ExecError> {
        Err(ExecError::CommandFailed {
            cmd: "decode security monitor ring-buffer record".into(),
            stderr: "eBPF networking is unavailable on this target".into(),
        })
    }
}

#[derive(Debug, Default)]
pub struct SecurityMonitorBuffer {
    events: Vec<SecurityMonitorEvent>,
    dropped: u64,
}
impl SecurityMonitorBuffer {
    pub fn push(&mut self, event: SecurityMonitorEvent) {
        if self.events.len() == SECURITY_MONITOR_MAX_BUFFER_EVENTS {
            self.events.remove(0);
            self.dropped += 1;
        }
        self.events.push(event);
    }
    pub fn ingest_kernel_record(&mut self, bytes: &[u8]) -> Result<(), ExecError> {
        self.push(SecurityMonitorEvent::decode_kernel_record(bytes)?);
        Ok(())
    }
    pub fn pop(&mut self) -> Option<SecurityMonitorEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
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
}

pub struct SecurityMonitorRingBuffer;
impl SecurityMonitorRingBuffer {
    pub fn open(_: impl AsRef<Path>) -> Result<Self, ExecError> {
        Err(unsupported_exec())
    }
    pub fn drain_to(&mut self, _: &mut SecurityMonitorBuffer) -> Result<usize, ExecError> {
        Err(unsupported_exec())
    }
}

#[derive(Debug)]
pub struct SecurityMonitorReceiptWriter;
impl SecurityMonitorReceiptWriter {
    pub fn open(_: impl AsRef<Path>) -> Result<Self, ExecError> {
        Err(unsupported_exec())
    }
    pub fn append(&mut self, _: &SecurityMonitorEvent) -> Result<u64, ExecError> {
        Err(unsupported_exec())
    }
}

fn unsupported_exec() -> ExecError {
    ExecError::CommandFailed {
        cmd: "security monitor".into(),
        stderr: unsupported().to_string(),
    }
}

pub fn build_bpftool_load_cmd(_: &EbpfProgram, _: &str) -> Vec<String> {
    Vec::new()
}
pub fn build_bpftool_load_with_map_cmd(_: &EbpfProgram, _: &str, _: &str) -> Vec<String> {
    Vec::new()
}
pub fn security_monitor_ring_map_path(pin_root: &str, event: &str) -> String {
    format!("{pin_root}/{event}-events")
}
pub fn build_tc_attach_cmd(_: &str, _: &str, _: &str) -> Vec<String> {
    Vec::new()
}
pub fn build_xdp_attach_cmd(_: &str, _: &str) -> Vec<String> {
    Vec::new()
}
pub fn build_tracepoint_attach_cmd(_: &str, _: &str, _: &str) -> Vec<String> {
    Vec::new()
}
pub fn install_security_monitor(_: &SecurityMonitorConfig) -> Result<Vec<String>, ExecError> {
    Err(unsupported_exec())
}
pub fn cleanup_security_monitor(_: &SecurityMonitorConfig) -> Result<(), ExecError> {
    Ok(())
}

fn validate_network_id(network_id: &str) -> Result<(), EbpfError> {
    if network_id.is_empty()
        || network_id == "."
        || network_id == ".."
        || network_id.contains('/')
        || network_id.contains('\0')
    {
        return Err(EbpfError::InvalidNetworkId {
            network_id: network_id.to_string(),
        });
    }
    Ok(())
}
