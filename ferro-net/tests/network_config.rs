use ferro_net::bridge::build_ip_link_add_bridge_cmd;
use ferro_net::dns::{DnsConfig, render_resolv_conf};
use ferro_net::netns::build_ip_netns_add_cmd;
use ferro_net::portmap::{PortMapping, build_iptables_forward_cmd};
use ferro_net::veth::{VethConfig, VethPair, build_ip_link_add_veth_cmd};

#[test]
fn network_config_builders_work() {
    assert_eq!(
        build_ip_link_add_bridge_cmd("ferro0"),
        vec!["ip", "link", "add", "ferro0", "type", "bridge"]
    );

    let dns = DnsConfig {
        servers: vec!["1.1.1.1".to_string()],
        search: vec!["example.local".to_string()],
    };
    let resolv = render_resolv_conf(&dns);
    assert!(resolv.contains("nameserver 1.1.1.1"));

    assert_eq!(
        build_ip_netns_add_cmd("c1"),
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
        build_ip_link_add_veth_cmd(&config),
        vec!["ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"]
    );

    let mapping = PortMapping {
        host_port: 8080,
        container_port: 80,
        protocol: "tcp".to_string(),
    };
    assert_eq!(
        build_iptables_forward_cmd(&mapping, "10.0.0.2"),
        vec![
            "iptables", "-A", "FORWARD", "-p", "tcp", "-d", "10.0.0.2", "--dport", "80",
            "-j", "ACCEPT"
        ]
    );
}
