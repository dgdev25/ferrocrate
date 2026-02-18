#![cfg(target_os = "linux")]

use ferro_net::bridge::build_ip_link_add_bridge_cmd;
use ferro_net::dns::{render_resolv_conf, DnsConfig};
use ferro_net::netns::build_ip_netns_add_cmd;
use ferro_net::portmap::{build_iptables_forward_cmd, PortMapping};
use ferro_net::veth::{build_ip_link_add_veth_cmd, VethConfig, VethPair};

#[test]
fn network_config_builders_work() {
    assert_eq!(
        build_ip_link_add_bridge_cmd("ferro0").unwrap(),
        vec!["ip", "link", "add", "ferro0", "type", "bridge"]
    );

    let dns = DnsConfig {
        servers: vec!["1.1.1.1".to_string()],
        search: vec!["example.local".to_string()],
    };
    let resolv = render_resolv_conf(&dns);
    assert!(resolv.contains("nameserver 1.1.1.1"));

    assert_eq!(
        build_ip_netns_add_cmd("c1").unwrap(),
        vec!["ip", "netns", "add", "c1"]
    );

    let config = VethConfig {
        pair: VethPair {
            host: "veth0".to_string(),
            container: "veth1".to_string(),
        },
        mtu: None,
        host_addr: None,
        container_addr: None,
    };
    assert_eq!(
        build_ip_link_add_veth_cmd(&config).unwrap(),
        vec!["ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"]
    );

    let mapping = PortMapping {
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    };
    assert_eq!(
        build_iptables_forward_cmd(&mapping, "10.0.0.2").unwrap(),
        vec![
            "iptables", "-A", "FORWARD", "-p", "tcp", "-d", "10.0.0.2", "--dport", "80", "-j",
            "ACCEPT"
        ]
    );
}

#[test]
fn network_validators_reject_invalid_input() {
    // Shell injection in interface name
    assert!(build_ip_link_add_bridge_cmd("eth0;rm -rf /").is_err());
    // Empty interface name
    assert!(build_ip_link_add_bridge_cmd("").is_err());
    // Invalid netns name
    assert!(build_ip_netns_add_cmd("ns$(whoami)").is_err());

    // Invalid container port (0)
    let mapping = PortMapping {
        host_port: 8080,
        container_port: 0, // Invalid
        protocol: "tcp".to_string(),
    };
    assert!(build_iptables_forward_cmd(&mapping, "10.0.0.2").is_err());

    // Invalid protocol
    let mapping = PortMapping {
        host_port: 8080,
        container_port: 80,
        protocol: "invalid".to_string(),
    };
    assert!(build_iptables_forward_cmd(&mapping, "10.0.0.2").is_err());
}
