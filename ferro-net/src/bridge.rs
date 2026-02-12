#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    pub name: String,
    pub cidr: String,
}

pub fn build_ip_link_add_bridge_cmd(name: &str) -> Vec<String> {
    vec!["ip".into(), "link".into(), "add".into(), name.into(), "type".into(), "bridge".into()]
}

pub fn build_ip_link_set_master_cmd(link: &str, bridge: &str) -> Vec<String> {
    vec!["ip".into(), "link".into(), "set".into(), link.into(), "master".into(), bridge.into()]
}

pub fn build_ip_addr_add_bridge_cmd(bridge: &str, cidr: &str) -> Vec<String> {
    vec!["ip".into(), "addr".into(), "add".into(), cidr.into(), "dev".into(), bridge.into()]
}

pub fn build_ip_addr_add_ipv6_bridge_cmd(bridge: &str, cidr: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "-6".into(),
        "addr".into(),
        "add".into(),
        cidr.into(),
        "dev".into(),
        bridge.into(),
    ]
}

pub fn build_ip_link_set_up_cmd(link: &str) -> Vec<String> {
    vec!["ip".into(), "link".into(), "set".into(), link.into(), "up".into()]
}

#[cfg(test)]
mod tests {
    use super::{
        build_ip_addr_add_bridge_cmd,
        build_ip_addr_add_ipv6_bridge_cmd,
        build_ip_link_add_bridge_cmd,
        build_ip_link_set_master_cmd,
        build_ip_link_set_up_cmd,
    };

    #[test]
    fn builds_bridge_commands() {
        assert_eq!(
            build_ip_link_add_bridge_cmd("ferro0"),
            vec!["ip", "link", "add", "ferro0", "type", "bridge"]
        );
        assert_eq!(
            build_ip_addr_add_bridge_cmd("ferro0", "10.0.0.1/24"),
            vec!["ip", "addr", "add", "10.0.0.1/24", "dev", "ferro0"]
        );
        assert_eq!(
            build_ip_addr_add_ipv6_bridge_cmd("ferro0", "fd00::1/64"),
            vec!["ip", "-6", "addr", "add", "fd00::1/64", "dev", "ferro0"]
        );
        assert_eq!(
            build_ip_link_set_master_cmd("veth0", "ferro0"),
            vec!["ip", "link", "set", "veth0", "master", "ferro0"]
        );
        assert_eq!(
            build_ip_link_set_up_cmd("ferro0"),
            vec!["ip", "link", "set", "ferro0", "up"]
        );
    }
}
