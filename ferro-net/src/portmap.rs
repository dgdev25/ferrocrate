use crate::validate::{validate_ip, validate_port, validate_protocol, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

pub fn build_iptables_prerouting_cmd(
    mapping: &PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_port(mapping.host_port)?;
    validate_port(mapping.container_port)?;
    validate_protocol(&mapping.protocol)?;
    validate_ip(container_ip)?;
    Ok(vec![
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
    ])
}

pub fn build_iptables_forward_cmd(
    mapping: &PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_port(mapping.container_port)?;
    validate_protocol(&mapping.protocol)?;
    validate_ip(container_ip)?;
    Ok(vec![
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
    ])
}

#[cfg(test)]
mod tests {
    use super::{build_iptables_forward_cmd, build_iptables_prerouting_cmd, PortMapping};

    #[test]
    fn builds_portmap_commands() {
        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };

        let prerouting = build_iptables_prerouting_cmd(&mapping, "10.0.0.2").unwrap();
        assert_eq!(
            prerouting,
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "DNAT",
                "--to-destination",
                "10.0.0.2:80"
            ]
        );

        let forward = build_iptables_forward_cmd(&mapping, "10.0.0.2").unwrap();
        assert_eq!(
            forward,
            vec![
                "iptables", "-A", "FORWARD", "-p", "tcp", "-d", "10.0.0.2", "--dport", "80", "-j",
                "ACCEPT"
            ]
        );
    }

    #[test]
    fn rejects_invalid_port_mappings() {
        let mapping = PortMapping {
            host_port: 0, // Invalid
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        assert!(build_iptables_prerouting_cmd(&mapping, "10.0.0.2").is_err());

        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "invalid".to_string(),
        };
        assert!(build_iptables_prerouting_cmd(&mapping, "10.0.0.2").is_err());

        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        assert!(build_iptables_prerouting_cmd(&mapping, "not-an-ip").is_err());
    }
}
