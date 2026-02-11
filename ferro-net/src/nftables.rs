#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRule {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub expr: Vec<String>,
}

pub fn build_nft_add_rule_cmd(rule: &NftRule) -> Vec<String> {
    let mut cmd = vec!["nft".to_string(), "add".to_string(), "rule".to_string()];
    cmd.push(rule.family.clone());
    cmd.push(rule.table.clone());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.expr.clone());
    cmd
}

pub fn build_nft_delete_rule_cmd(rule: &NftRule) -> Vec<String> {
    let mut cmd = vec!["nft".to_string(), "delete".to_string(), "rule".to_string()];
    cmd.push(rule.family.clone());
    cmd.push(rule.table.clone());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.expr.clone());
    cmd
}

#[cfg(test)]
mod tests {
    use super::{NftRule, build_nft_add_rule_cmd, build_nft_delete_rule_cmd};

    #[test]
    fn builds_nft_add_rule_command() {
        let rule = NftRule {
            family: "ip".to_string(),
            table: "nat".to_string(),
            chain: "prerouting".to_string(),
            expr: vec!["tcp".to_string(), "dport".to_string(), "80".to_string(), "dnat".to_string(), "to".to_string(), "10.0.0.2:80".to_string()],
        };

        assert_eq!(
            build_nft_add_rule_cmd(&rule),
            vec![
                "nft", "add", "rule", "ip", "nat", "prerouting", "tcp", "dport", "80", "dnat",
                "to", "10.0.0.2:80"
            ]
        );

        assert_eq!(
            build_nft_delete_rule_cmd(&rule),
            vec![
                "nft", "delete", "rule", "ip", "nat", "prerouting", "tcp", "dport", "80", "dnat",
                "to", "10.0.0.2:80"
            ]
        );
    }
}
