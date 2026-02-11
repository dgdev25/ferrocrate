#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketRule {
    pub protocol: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub action: String,
}

pub fn build_iptables_forward_rule(rule: &PacketRule) -> Vec<String> {
    let mut cmd = vec!["iptables".to_string(), "-A".to_string(), "FORWARD".to_string()];
    cmd.push("-p".to_string());
    cmd.push(rule.protocol.clone());
    if let Some(src) = &rule.source {
        cmd.push("-s".to_string());
        cmd.push(src.clone());
    }
    if let Some(dst) = &rule.destination {
        cmd.push("-d".to_string());
        cmd.push(dst.clone());
    }
    cmd.push("-j".to_string());
    cmd.push(rule.action.clone());
    cmd
}

#[cfg(test)]
mod tests {
    use super::{PacketRule, build_iptables_forward_rule};

    #[test]
    fn builds_forward_rule() {
        let rule = PacketRule {
            protocol: "tcp".to_string(),
            source: Some("10.0.0.0/24".to_string()),
            destination: Some("10.1.0.0/24".to_string()),
            action: "ACCEPT".to_string(),
        };

        assert_eq!(
            build_iptables_forward_rule(&rule),
            vec![
                "iptables", "-A", "FORWARD", "-p", "tcp", "-s", "10.0.0.0/24", "-d",
                "10.1.0.0/24", "-j", "ACCEPT"
            ]
        );
    }
}
