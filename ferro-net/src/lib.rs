pub mod backend;
pub mod bridge;
pub mod dns;
pub mod ebpf;
pub mod ebpf_abi;
mod ebpf_loader;
pub mod ebpf_maps;
pub mod executor;
pub mod iptables;
pub mod netns;
pub mod nftables;
pub mod observability;
pub mod packet_rules;
pub mod portmap;
pub mod rootless;
pub mod sandbox;
pub mod subnet;
pub mod validate;
pub mod veth;
pub mod wireguard;

pub use dns::{render_resolv_conf, write_resolv_conf, DnsConfig, DnsError};

// Re-export executor types
pub use executor::{
    exec_cmd, exec_cmd_allow_missing, exec_cmd_capture, ExecError, HostCapabilities, Transaction,
};

// Re-export backend selection types
pub use backend::{BackendError, BackendProbe, NetworkBackend};

// Re-export validation types
pub use validate::ValidationError;

// Re-export bridge execution functions
pub use bridge::{
    create_bridge, destroy_bridge, observe_bridge_identity, BridgeConfig, BridgeObservation,
};
pub use observability::{format_backend_metrics, BackendMetrics};

// Re-export eBPF execution functions
pub use ebpf::{
    cleanup_security_monitor, embedded_object_abi, embedded_object_sha256,
    install_security_monitor, EbpfError, EbpfMetrics, EbpfNetwork, EbpfNetworkConfig,
    SecurityMonitorBuffer, SecurityMonitorConfig, SecurityMonitorEvent,
    SecurityMonitorReceiptWriter, SecurityMonitorRingBuffer, SECURITY_MONITOR_EVENT_NAME_BYTES,
    SECURITY_MONITOR_EVENT_PAYLOAD_BYTES, SECURITY_MONITOR_EVENT_WIRE_BYTES,
    SECURITY_MONITOR_RING_MAP_NAME,
};

// Re-export veth execution functions
pub use veth::{assign_ip, create_veth_pair, destroy_veth_pair, VethConfig, VethPair};

// Re-export netns execution functions
pub use netns::{
    create_netns, destroy_netns, enter_netns, loopback_is_up, move_to_netns, netns_path,
    set_loopback_up, NetnsError,
};
pub use wireguard::{
    WireGuardError, WireGuardInterfaceConfig, WireGuardManager, WireGuardPeer, WireGuardSnapshot,
};
