#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesRule {
    pub table: String,
    pub chain: String,
    pub args: Vec<String>,
}

pub fn build_iptables_cmd(rule: &IptablesRule) -> Vec<String> {
    let mut cmd = vec!["iptables".to_string()];
    cmd.push("-t".to_string());
    cmd.push(rule.table.clone());
    cmd.push("-A".to_string());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.args.clone());
    cmd
}

pub fn build_iptables_delete_cmd(rule: &IptablesRule) -> Vec<String> {
    let mut cmd = vec!["iptables".to_string()];
    cmd.push("-t".to_string());
    cmd.push(rule.table.clone());
    cmd.push("-D".to_string());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.args.clone());
    cmd
}

#[cfg(test)]
mod tests {
    use super::{IptablesRule, build_iptables_cmd, build_iptables_delete_cmd};

    #[test]
    fn builds_iptables_command() {
        let rule = IptablesRule {
            table: "nat".to_string(),
            chain: "PREROUTING".to_string(),
            args: vec!["-p".to_string(), "tcp".to_string(), "--dport".to_string(), "80".to_string()],
        };

        assert_eq!(
            build_iptables_cmd(&rule),
            vec!["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "80"]
        );

        assert_eq!(
            build_iptables_delete_cmd(&rule),
            vec!["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "80"]
        );
    }
}
