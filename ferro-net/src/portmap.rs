#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

pub fn build_iptables_prerouting_cmd(mapping: &PortMapping, container_ip: &str) -> Vec<String> {
    vec![
        "iptables".into(),
        "-t".into(),
        "nat".into(),
        "-A".into(),
        "PREROUTING".into(),
        "-p".into(),
        mapping.protocol.clone(),
        "--dport".into(),
        mapping.host_port.to_string(),
        "-j".into(),
        "DNAT".into(),
        "--to-destination".into(),
        format!("{container_ip}:{}", mapping.container_port),
    ]
}

pub fn build_iptables_forward_cmd(mapping: &PortMapping, container_ip: &str) -> Vec<String> {
    vec![
        "iptables".into(),
        "-A".into(),
        "FORWARD".into(),
        "-p".into(),
        mapping.protocol.clone(),
        "-d".into(),
        container_ip.into(),
        "--dport".into(),
        mapping.container_port.to_string(),
        "-j".into(),
        "ACCEPT".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{PortMapping, build_iptables_forward_cmd, build_iptables_prerouting_cmd};

    #[test]
    fn builds_portmap_commands() {
        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };

        let prerouting = build_iptables_prerouting_cmd(&mapping, "10.0.0.2");
        assert_eq!(
            prerouting,
            vec![
                "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport",
                "8080", "-j", "DNAT", "--to-destination", "10.0.0.2:80"
            ]
        );

        let forward = build_iptables_forward_cmd(&mapping, "10.0.0.2");
        assert_eq!(
            forward,
            vec![
                "iptables", "-A", "FORWARD", "-p", "tcp", "-d", "10.0.0.2", "--dport", "80",
                "-j", "ACCEPT"
            ]
        );
    }
}
