use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethPair {
    pub host: String,
    pub container: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethConfig {
    pub pair: VethPair,
    pub mtu: Option<u32>,
    pub host_addr: Option<IpAddr>,
    pub container_addr: Option<IpAddr>,
}

pub fn build_ip_link_add_veth_cmd(config: &VethConfig) -> Vec<String> {
    let mut cmd = vec![
        "ip".into(),
        "link".into(),
        "add".into(),
        config.pair.host.clone(),
        "type".into(),
        "veth".into(),
        "peer".into(),
        "name".into(),
        config.pair.container.clone(),
    ];
    if let Some(mtu) = config.mtu {
        cmd.push("mtu".into());
        cmd.push(mtu.to_string());
    }
    cmd
}

pub fn build_ip_link_set_up_cmd(link: &str) -> Vec<String> {
    vec!["ip".into(), "link".into(), "set".into(), link.into(), "up".into()]
}

pub fn build_ip_addr_add_cmd(link: &str, addr: IpAddr, cidr: u8) -> Vec<String> {
    vec![
        "ip".into(),
        "addr".into(),
        "add".into(),
        format!("{addr}/{cidr}"),
        "dev".into(),
        link.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{VethConfig, VethPair, build_ip_addr_add_cmd, build_ip_link_add_veth_cmd, build_ip_link_set_up_cmd};
    use std::net::IpAddr;

    #[test]
    fn builds_veth_add_command() {
        let config = VethConfig {
            pair: VethPair {
                host: "veth-host".to_string(),
                container: "veth-cont".to_string(),
            },
            mtu: Some(1500),
            host_addr: None,
            container_addr: None,
        };

        assert_eq!(
            build_ip_link_add_veth_cmd(&config),
            vec![
                "ip", "link", "add", "veth-host", "type", "veth", "peer", "name",
                "veth-cont", "mtu", "1500"
            ]
        );
    }

    #[test]
    fn builds_link_up_and_addr_commands() {
        assert_eq!(
            build_ip_link_set_up_cmd("veth0"),
            vec!["ip", "link", "set", "veth0", "up"]
        );

        let cmd = build_ip_addr_add_cmd("veth0", "10.0.0.2".parse::<IpAddr>().unwrap(), 24);
        assert_eq!(
            cmd,
            vec!["ip", "addr", "add", "10.0.0.2/24", "dev", "veth0"]
        );
    }
}
