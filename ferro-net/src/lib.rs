pub mod bridge;
pub mod dns;
pub mod ebpf;
pub mod ebpf_maps;
pub mod executor;
pub mod iptables;
pub mod netns;
pub mod nftables;
pub mod observability;
pub mod packet_rules;
pub mod portmap;
pub mod rootless;
pub mod validate;
pub mod veth;

// Re-export executor types
pub use executor::{ExecError, Transaction, exec_cmd, exec_cmd_capture};

// Re-export validation types
pub use validate::ValidationError;

// Re-export bridge execution functions
pub use bridge::{create_bridge, destroy_bridge, BridgeConfig};

// Re-export eBPF execution functions
pub use ebpf::{install_security_monitor, SecurityMonitorConfig};

// Re-export veth execution functions
pub use veth::{create_veth_pair, destroy_veth_pair, assign_ip, VethConfig, VethPair};

// Re-export netns execution functions
pub use netns::{create_netns, destroy_netns, move_to_netns, enter_netns, netns_path, NetnsError};
