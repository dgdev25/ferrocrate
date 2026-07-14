pub mod backend;
pub mod bridge;
pub mod dns;
pub mod ebpf;
pub mod ebpf_abi;
pub mod ebpf_loader;
pub mod ebpf_maps;
pub mod executor;
pub mod iptables;
pub mod netns;
pub mod nftables;
pub mod observability;
pub mod packet_rules;
pub mod portmap;
pub mod rootless;
pub mod subnet;
pub mod validate;
pub mod veth;

// Re-export executor types
pub use executor::{exec_cmd, exec_cmd_capture, ExecError, Transaction};

// Re-export backend selection types
pub use backend::{BackendError, BackendProbe, NetworkBackend};

// Re-export validation types
pub use validate::ValidationError;

// Re-export bridge execution functions
pub use bridge::{create_bridge, destroy_bridge, BridgeConfig};

// Re-export eBPF execution functions
pub use ebpf::{
    embedded_object_abi, embedded_object_sha256, install_security_monitor, EbpfError, EbpfMetrics,
    EbpfNetwork, EbpfNetworkConfig, SecurityMonitorConfig,
};

// Re-export veth execution functions
pub use veth::{assign_ip, create_veth_pair, destroy_veth_pair, VethConfig, VethPair};

// Re-export netns execution functions
pub use netns::{create_netns, destroy_netns, enter_netns, move_to_netns, netns_path, NetnsError};
