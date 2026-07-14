use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::ebpf_abi::{
    EndpointKey, EndpointValue, MetaConfig, PolicyKey, PolicyValue, PortKey, PortValue,
    COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME, META_FLAG_SNAT_RANGE_RESERVED, POLICY_MAP_NAME,
    PORTS_MAP_NAME, PROGRAM_ABI_VERSION,
};
use crate::ebpf_loader::{
    sha256, AyaKernel, KernelAdapter, KernelLoadPlan, KernelPreflight, MapMetadata, ObjectMetadata,
};
use crate::ebpf_maps::expected_map_metadata;
use crate::executor::{exec_cmd, exec_cmd_capture, ExecError};

pub const BPFFS_ROOT: &str = "/sys/fs/bpf";
pub const FERRO_NETWORK_ROOT: &str = "/sys/fs/bpf/ferro/networks";
pub const INGRESS_CLASSIFIER: &str = "ferro_ingress";
pub const EGRESS_CLASSIFIER: &str = "ferro_egress";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfNetworkConfig {
    pub network_id: String,
    pub interface: String,
    pub external_ipv4: [u8; 4],
    pub external_ifindex: u32,
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
        expected: MapMetadata,
        actual: MapMetadata,
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
    #[error("failed to detach eBPF network: {reason}")]
    Detach { reason: String },
    #[error("{primary}; rollback also failed: {rollback}")]
    Rollback { primary: String, rollback: String },
}

pub struct EbpfNetwork {
    kernel: Box<dyn KernelAdapter>,
    detached: bool,
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
        Self::load_with(AyaKernel::new(), config)
    }

    pub fn load_with<K>(mut kernel: K, config: EbpfNetworkConfig) -> Result<Self, EbpfError>
    where
        K: KernelAdapter + 'static,
    {
        validate_config(&config)?;
        let pin_path = config.pin_path()?;
        let object = crate::ebpf_loader::embedded_object();
        let actual_hash = sha256(object);
        if actual_hash != config.expected_object_sha256 {
            return Err(EbpfError::ObjectHashMismatch {
                expected: config.expected_object_sha256,
                actual: actual_hash,
            });
        }

        let reserved = kernel.reserved_ports()?;
        prove_reserved_range(&reserved, config.snat_port_start, config.snat_port_end)?;

        let preflight = KernelPreflight {
            object,
            interface: &config.interface,
            external_ifindex: config.external_ifindex,
            pin_path: &pin_path,
        };
        let metadata = kernel.preflight(&preflight)?;
        if let Err(error) = validate_object_metadata(&metadata) {
            return Err(rollback_error(&mut kernel, error));
        }

        let metadata = MetaConfig {
            abi_version: PROGRAM_ABI_VERSION,
            external_ipv4: config.external_ipv4,
            external_ifindex: config.external_ifindex,
            next_hop_mac: config.next_hop_mac,
            snat_port_start: config.snat_port_start,
            snat_port_end: config.snat_port_end,
            flags: META_FLAG_SNAT_RANGE_RESERVED,
        }
        .encode();
        let plan = KernelLoadPlan {
            interface: &config.interface,
            pin_path: &pin_path,
            metadata,
        };
        if let Err(error) = kernel.commit(&plan) {
            return Err(rollback_error(&mut kernel, error));
        }

        Ok(Self {
            kernel: Box::new(kernel),
            detached: false,
        })
    }

    pub fn install_endpoint(
        &mut self,
        key: EndpointKey,
        value: EndpointValue,
    ) -> Result<(), EbpfError> {
        self.active_kernel()?.map_insert(
            ENDPOINTS_MAP_NAME,
            &key.encode(),
            &value.encode(),
        )
    }

    pub fn remove_endpoint(&mut self, key: EndpointKey) -> Result<(), EbpfError> {
        self.active_kernel()?
            .map_remove(ENDPOINTS_MAP_NAME, &key.encode())
    }

    pub fn install_port(&mut self, key: PortKey, value: PortValue) -> Result<(), EbpfError> {
        self.active_kernel()?
            .map_insert(PORTS_MAP_NAME, &key.encode(), &value.encode())
    }

    pub fn remove_port(&mut self, key: PortKey) -> Result<(), EbpfError> {
        self.active_kernel()?
            .map_remove(PORTS_MAP_NAME, &key.encode())
    }

    pub fn set_policy(&mut self, key: PolicyKey, value: PolicyValue) -> Result<(), EbpfError> {
        self.active_kernel()?
            .map_insert(POLICY_MAP_NAME, &key.encode(), &value.encode())
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

impl Drop for EbpfNetwork {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

pub fn embedded_object_sha256() -> [u8; 32] {
    sha256(crate::ebpf_loader::embedded_object())
}

pub fn embedded_object_abi() -> Result<u32, EbpfError> {
    crate::ebpf_loader::object_abi(crate::ebpf_loader::embedded_object())
}

fn validate_config(config: &EbpfNetworkConfig) -> Result<(), EbpfError> {
    validate_network_id(&config.network_id)?;
    if config.interface.is_empty()
        || config.interface.len() > 15
        || config.interface == "."
        || config.interface == ".."
        || config.interface.bytes().any(|byte| byte == 0 || byte == b'/')
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

fn validate_object_metadata(metadata: &ObjectMetadata) -> Result<(), EbpfError> {
    if metadata.program_abi != PROGRAM_ABI_VERSION {
        return Err(EbpfError::AbiMismatch {
            expected: PROGRAM_ABI_VERSION,
            actual: metadata.program_abi,
        });
    }

    let expected_maps = expected_map_metadata();
    let mut actual_names = BTreeSet::new();
    for actual in &metadata.maps {
        if !actual_names.insert(actual.name.as_str()) {
            return Err(EbpfError::UnexpectedMap {
                map: actual.name.clone(),
            });
        }
        let Some(expected) = expected_maps.iter().find(|map| map.name == actual.name) else {
            return Err(EbpfError::UnexpectedMap {
                map: actual.name.clone(),
            });
        };
        if actual != expected {
            return Err(EbpfError::MapSchemaMismatch {
                map: actual.name.clone(),
                expected: expected.clone(),
                actual: actual.clone(),
            });
        }
    }
    for expected in &expected_maps {
        if !actual_names.contains(expected.name.as_str()) {
            let map = expected_maps
                .iter()
                .find_map(|candidate| {
                    (candidate.name == expected.name).then_some(candidate.name.as_str())
                })
                .expect("expected map name is present in the static schema");
            let map = match map {
                name if name == ENDPOINTS_MAP_NAME => ENDPOINTS_MAP_NAME,
                name if name == PORTS_MAP_NAME => PORTS_MAP_NAME,
                name if name == crate::ebpf_abi::CONNTRACK_MAP_NAME => {
                    crate::ebpf_abi::CONNTRACK_MAP_NAME
                }
                name if name == POLICY_MAP_NAME => POLICY_MAP_NAME,
                name if name == crate::ebpf_abi::COUNTERS_MAP_NAME => {
                    crate::ebpf_abi::COUNTERS_MAP_NAME
                }
                _ => crate::ebpf_abi::META_MAP_NAME,
            };
            return Err(EbpfError::MissingMap { map });
        }
    }

    let expected_classifiers = [INGRESS_CLASSIFIER, EGRESS_CLASSIFIER];
    let mut actual_classifiers = BTreeSet::new();
    for classifier in &metadata.classifiers {
        if !actual_classifiers.insert(classifier.as_str())
            || !expected_classifiers.contains(&classifier.as_str())
        {
            return Err(EbpfError::UnexpectedClassifier {
                classifier: classifier.clone(),
            });
        }
    }
    for classifier in expected_classifiers {
        if !actual_classifiers.contains(classifier) {
            return Err(EbpfError::MissingClassifier { classifier });
        }
    }
    Ok(())
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
    let events = if config.events.is_empty() {
        default_security_events()
            .iter()
            .map(|event| (*event).to_string())
            .collect::<Vec<_>>()
    } else {
        config.events.clone()
    };
    let mut installed = Vec::new();
    for event in events {
        let normalized = sanitize_event(&event)?;
        let pin_path = format!("{}/{}", config.pin_root, normalized);
        let program = EbpfProgram {
            name: format!("ferro_security_{normalized}"),
            object_path: config.object_path.clone(),
            section: "tracepoint".to_string(),
        };
        exec_cmd(&build_bpftool_load_cmd(&program, &pin_path))?;
        let tracepoint = format!("sys_enter_{normalized}");
        exec_cmd(&build_tracepoint_attach_cmd(
            &pin_path,
            "syscalls",
            &tracepoint,
        ))?;
        let _ = exec_cmd_capture(&[
            "bpftool".to_string(),
            "prog".to_string(),
            "show".to_string(),
            "pinned".to_string(),
            pin_path,
        ])?;
        installed.push(normalized);
    }
    Ok(installed)
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
