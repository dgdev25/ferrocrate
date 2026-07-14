use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::ebpf_abi::{
    EndpointKey, EndpointValue, MetaConfig, PolicyKey, PolicyValue, PortKey, PortValue,
    COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME, META_FLAG_SNAT_RANGE_RESERVED, PORTS_MAP_NAME,
    PROGRAM_ABI_VERSION,
};
use crate::ebpf_loader::{
    sha256, validate_embedded_object, AyaKernel, KernelAdapter, KernelLoadPlan, KernelPreflight,
};
use crate::executor::{exec_cmd, exec_cmd_capture, ExecError};

pub const BPFFS_ROOT: &str = "/sys/fs/bpf";
pub const FERRO_NETWORK_ROOT: &str = "/sys/fs/bpf/ferrocrate";
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
    additional_interfaces: Vec<String>,
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

    fn prepare_with<K>(kernel: K, config: EbpfNetworkConfig) -> Result<PreparedEbpfNetwork, EbpfError>
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

    pub fn install_pinned_endpoint(
        network_id: &str,
        key: EndpointKey,
        value: EndpointValue,
    ) -> Result<(), EbpfError> {
        update_pinned_map(network_id, ENDPOINTS_MAP_NAME, &key.encode(), &value.encode())
    }

    pub fn remove_pinned_endpoint(network_id: &str, key: EndpointKey) -> Result<(), EbpfError> {
        delete_pinned_map_key(network_id, ENDPOINTS_MAP_NAME, &key.encode())
    }

    pub fn install_pinned_port(
        network_id: &str,
        key: PortKey,
        value: PortValue,
    ) -> Result<(), EbpfError> {
        update_pinned_map(network_id, PORTS_MAP_NAME, &key.encode(), &value.encode())
    }

    pub fn remove_pinned_port(network_id: &str, key: PortKey) -> Result<(), EbpfError> {
        delete_pinned_map_key(network_id, PORTS_MAP_NAME, &key.encode())
    }

    fn commit_prepared(
        mut kernel: Box<dyn KernelAdapter>,
        config: EbpfNetworkConfig,
        additional_interfaces: Vec<String>,
    ) -> Result<Self, EbpfError> {
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
            network_id: &config.network_id,
            interface: &config.interface,
            metadata,
        };
        if let Err(error) = kernel.commit(&plan) {
            return Err(rollback_error(kernel.as_mut(), error));
        }
        for interface in additional_interfaces {
            if let Err(error) = kernel.attach_interface(&interface) {
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

impl PreparedEbpfNetwork {
    pub fn config(&self) -> &EbpfNetworkConfig {
        &self.config
    }

    pub fn prepare_interface(&mut self, interface: &str) -> Result<(), EbpfError> {
        validate_network_id(interface)?;
        if interface == self.config.interface
            || self.additional_interfaces.iter().any(|value| value == interface)
        {
            return Err(EbpfError::InvalidAdapterState {
                reason: format!("classifier interface {interface} is duplicated"),
            });
        }
        self.kernel.preflight_interface(interface)?;
        self.additional_interfaces.push(interface.to_string());
        Ok(())
    }

    pub fn attach(self) -> Result<EbpfNetwork, EbpfError> {
        EbpfNetwork::commit_prepared(
            self.kernel,
            self.config,
            self.additional_interfaces,
        )
    }
}

fn pinned_map_path(network_id: &str, map_name: &str) -> Result<PathBuf, EbpfError> {
    validate_network_id(network_id)?;
    Ok(Path::new(FERRO_NETWORK_ROOT)
        .join(network_id)
        .join("maps")
        .join(map_name))
}

fn hex_bytes(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn update_pinned_map(
    network_id: &str,
    map_name: &'static str,
    key: &[u8],
    value: &[u8],
) -> Result<(), EbpfError> {
    let command = build_pinned_map_update_command(network_id, map_name, key, value)?;
    exec_cmd(&command).map_err(|error| EbpfError::MapOperation {
        operation: "update pinned",
        map: map_name,
        reason: error.to_string(),
    })
}

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

fn delete_pinned_map_key(
    network_id: &str,
    map_name: &'static str,
    key: &[u8],
) -> Result<(), EbpfError> {
    let command = build_pinned_map_delete_command(network_id, map_name, key)?;
    match exec_cmd(&command) {
        Ok(()) => Ok(()),
        Err(error) if error.to_string().contains("No such file or directory") => Ok(()),
        Err(error) => Err(EbpfError::MapOperation {
            operation: "delete pinned",
            map: map_name,
            reason: error.to_string(),
        }),
    }
}

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

#[cfg(test)]
mod lifecycle_tests {
    use std::sync::{Arc, Mutex};

    use super::{
        build_pinned_map_delete_command, build_pinned_map_update_command,
        embedded_object_sha256, hex_bytes, EbpfError, EbpfNetwork, EbpfNetworkConfig,
        EGRESS_CLASSIFIER, INGRESS_CLASSIFIER,
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
        metadata: Option<[u8; META_VALUE_LEN]>,
        endpoints: Vec<(EndpointKey, EndpointValue)>,
        ports: Vec<(PortKey, PortValue)>,
        policies: Vec<(PolicyKey, PolicyValue)>,
        rollback_count: usize,
        detach_count: usize,
    }

    struct FakeKernel {
        state: Arc<Mutex<FakeState>>,
        reserved_ports: String,
        fail_egress_attach: bool,
    }

    impl FakeKernel {
        fn valid() -> (Self, Arc<Mutex<FakeState>>) {
            let state = Arc::new(Mutex::new(FakeState::default()));
            (
                Self {
                    state: Arc::clone(&state),
                    reserved_ports: "1-1024,50000-50031".to_string(),
                    fail_egress_attach: false,
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
            assert_eq!(request.network_id, "test-network");
            assert_eq!(request.expected_object_sha256, embedded_object_sha256());
            self.state
                .lock()
                .unwrap()
                .events
                .push("preflight".to_string());
            Ok(())
        }

        fn preflight_interface(&mut self, interface: &str) -> Result<(), EbpfError> {
            self.state
                .lock()
                .unwrap()
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

        fn attach_interface(&mut self, interface: &str) -> Result<(), EbpfError> {
            self.state
                .lock()
                .unwrap()
                .events
                .push(format!("attach-interface:{interface}"));
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
            external_ifindex: 17,
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
        let delete = build_pinned_map_delete_command(
            "shared-bridge",
            PORTS_MAP_NAME,
            &port_key.encode(),
        )
        .unwrap();
        assert_eq!(delete[2], "delete");
        assert_eq!(delete[4], "/sys/fs/bpf/ferrocrate/shared-bridge/maps/FERRO_PORTS");
        assert_eq!(&delete[7..], hex_bytes(&port_key.encode()));
        assert!(build_pinned_map_delete_command("../foreign", PORTS_MAP_NAME, &[0]).is_err());
    }

    #[test]
    fn network_backend_additional_classifier_is_preflighted_and_unique() {
        let (kernel, state) = FakeKernel::valid();
        let mut prepared = EbpfNetwork::prepare_with(kernel, config()).unwrap();
        prepared.prepare_interface("lo").unwrap();
        assert!(prepared.prepare_interface("lo").is_err());
        prepared.attach().unwrap();
        let events = &state.lock().unwrap().events;
        let preflight = events
            .iter()
            .position(|event| event == "preflight-interface:lo")
            .unwrap();
        let attach = events
            .iter()
            .position(|event| event == "attach-interface:lo")
            .unwrap();
        assert!(preflight < attach);
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
