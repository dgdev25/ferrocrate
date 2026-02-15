use crate::validate::validate_nft_family;

/// Allowed nftables tables for security validation
const ALLOWED_TABLES: &[&str] = &["filter", "nat", "mangle", "raw", "security", "bridge"];

/// Allowed nftables chains for security validation
const ALLOWED_CHAINS: &[&str] = &[
    "input", "output", "forward",
    "prerouting", "postrouting",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftRule {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub expr: Vec<String>,
}

impl NftRule {
    /// Validate the rule for security - prevent injection attacks (SEC-03)
    pub fn validate(&self) -> Result<(), String> {
        // Validate family using validate module
        validate_nft_family(&self.family)
            .map_err(|e| format!("Invalid nftables family: {}", e))?;

        // Validate table name
        if !ALLOWED_TABLES.contains(&self.table.to_lowercase().as_str())
            && !self.table.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            return Err(format!("Invalid nftables table: {}", self.table));
        }

        // Validate chain name
        if !ALLOWED_CHAINS.contains(&self.chain.to_lowercase().as_str())
            && !self.chain.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            return Err(format!("Invalid nftables chain: {}", self.chain));
        }

        // Validate expr don't contain shell metacharacters
        for expr in &self.expr {
            if expr.contains('\0') || expr.contains('|') || expr.contains(';')
                || expr.contains('`') || expr.contains('$') || expr.contains('\n')
                || expr.contains('&') || expr.contains('(') || expr.contains(')')
            {
                return Err("Invalid characters in nftables expression".to_string());
            }
        }

        Ok(())
    }
}

pub fn build_nft_add_rule_cmd(rule: &NftRule) -> Result<Vec<String>, String> {
    // SEC-03: Call validation before command construction
    rule.validate()?;
    let mut cmd = vec!["nft".to_string(), "add".to_string(), "rule".to_string()];
    cmd.push(rule.family.clone());
    cmd.push(rule.table.clone());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.expr.clone());
    Ok(cmd)
}

pub fn build_nft_delete_rule_cmd(rule: &NftRule) -> Result<Vec<String>, String> {
    // SEC-03: Call validation before command construction
    rule.validate()?;
    let mut cmd = vec!["nft".to_string(), "delete".to_string(), "rule".to_string()];
    cmd.push(rule.family.clone());
    cmd.push(rule.table.clone());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.expr.clone());
    Ok(cmd)
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
            build_nft_add_rule_cmd(&rule).unwrap(),
            vec![
                "nft", "add", "rule", "ip", "nat", "prerouting", "tcp", "dport", "80", "dnat",
                "to", "10.0.0.2:80"
            ]
        );

        assert_eq!(
            build_nft_delete_rule_cmd(&rule).unwrap(),
            vec![
                "nft", "delete", "rule", "ip", "nat", "prerouting", "tcp", "dport", "80", "dnat",
                "to", "10.0.0.2:80"
            ]
        );
    }

    #[test]
    fn rejects_invalid_family() {
        let rule = NftRule {
            family: "invalid_family".to_string(),
            table: "nat".to_string(),
            chain: "prerouting".to_string(),
            expr: vec![],
        };
        assert!(build_nft_add_rule_cmd(&rule).is_err());
    }

    #[test]
    fn rejects_shell_injection_in_expr() {
        let rule = NftRule {
            family: "ip".to_string(),
            table: "nat".to_string(),
            chain: "prerouting".to_string(),
            expr: vec!["tcp; rm -rf /".to_string()],
        };
        assert!(build_nft_add_rule_cmd(&rule).is_err());
    }
}
