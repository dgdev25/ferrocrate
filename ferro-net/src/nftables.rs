use crate::executor::{exec_cmd, exec_cmd_capture, ExecError};
use crate::validate::validate_nft_family;

/// Allowed nftables tables for security validation
const ALLOWED_TABLES: &[&str] = &["filter", "nat", "mangle", "raw", "security", "bridge"];

/// Allowed nftables chains for security validation
const ALLOWED_CHAINS: &[&str] = &["input", "output", "forward", "prerouting", "postrouting"];

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
        validate_nft_family(&self.family).map_err(|e| format!("Invalid nftables family: {}", e))?;

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
            if expr.contains('\0')
                || expr.contains('|')
                || expr.contains(';')
                || expr.contains('`')
                || expr.contains('$')
                || expr.contains('\n')
                || expr.contains('&')
                || expr.contains('(')
                || expr.contains(')')
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

pub fn build_nft_list_chain_with_handles_cmd(rule: &NftRule) -> Result<Vec<String>, String> {
    // SEC-03: Call validation before command construction
    rule.validate()?;
    Ok(vec![
        "nft".to_string(),
        "-a".to_string(),
        "list".to_string(),
        "chain".to_string(),
        rule.family.clone(),
        rule.table.clone(),
        rule.chain.clone(),
    ])
}

pub fn build_nft_delete_rule_handle_cmd(
    rule: &NftRule,
    handle: u64,
) -> Result<Vec<String>, String> {
    // SEC-03: Call validation before command construction
    rule.validate()?;
    Ok(vec![
        "nft".to_string(),
        "delete".to_string(),
        "rule".to_string(),
        rule.family.clone(),
        rule.table.clone(),
        rule.chain.clone(),
        "handle".to_string(),
        handle.to_string(),
    ])
}

pub fn nft_rule_handles_from_list(output: &str, rule: &NftRule) -> Result<Vec<u64>, String> {
    rule.validate()?;
    let expected_expr = normalize_nft_expr(&rule.expr.join(" "));
    let mut handles = Vec::new();
    for line in output.lines() {
        let Some((rule_text, handle_text)) = line.split_once("# handle") else {
            continue;
        };
        if !normalize_nft_expr(rule_text).contains(&expected_expr) {
            continue;
        }
        let Some(raw_handle) = handle_text.split_whitespace().next() else {
            continue;
        };
        if let Ok(handle) = raw_handle.parse::<u64>() {
            handles.push(handle);
        }
    }
    Ok(handles)
}

fn normalize_nft_expr(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn apply_nft_rule(rule: &NftRule) -> Result<(), ExecError> {
    crate::executor::HostCapabilities::probe().require_network_mutation()?;
    let cmd = build_nft_add_rule_cmd(rule).map_err(|err| ExecError::CommandFailed {
        cmd: "nft add build".to_string(),
        stderr: err,
    })?;
    exec_cmd(&cmd)?;
    let list_cmd =
        build_nft_list_chain_with_handles_cmd(rule).map_err(|err| ExecError::CommandFailed {
            cmd: "nft list build".to_string(),
            stderr: err,
        })?;
    let output = exec_cmd_capture(&list_cmd)?;
    if nft_rule_handles_from_list(&output, rule)
        .map_err(|err| ExecError::CommandFailed {
            cmd: "nft handle parse".to_string(),
            stderr: err,
        })?
        .is_empty()
    {
        return Err(ExecError::CommandFailed {
            cmd: list_cmd.join(" "),
            stderr: "rule missing after insertion".into(),
        });
    }
    Ok(())
}

pub fn delete_nft_rule(rule: &NftRule) -> Result<(), ExecError> {
    crate::executor::HostCapabilities::probe().require_network_mutation()?;
    let list_cmd =
        build_nft_list_chain_with_handles_cmd(rule).map_err(|err| ExecError::CommandFailed {
            cmd: "nft list build".to_string(),
            stderr: err,
        })?;
    let output = exec_cmd_capture(&list_cmd)?;
    let handles =
        nft_rule_handles_from_list(&output, rule).map_err(|err| ExecError::CommandFailed {
            cmd: "nft handle parse".to_string(),
            stderr: err,
        })?;
    for handle in handles {
        let cmd = build_nft_delete_rule_handle_cmd(rule, handle).map_err(|err| {
            ExecError::CommandFailed {
                cmd: "nft delete build".to_string(),
                stderr: err,
            }
        })?;
        exec_cmd(&cmd)?;
    }
    let remaining = exec_cmd_capture(&list_cmd)?;
    if !nft_rule_handles_from_list(&remaining, rule)
        .map_err(|err| ExecError::CommandFailed {
            cmd: "nft handle parse".to_string(),
            stderr: err,
        })?
        .is_empty()
    {
        return Err(ExecError::CommandFailed {
            cmd: list_cmd.join(" "),
            stderr: "rule remained after deletion".into(),
        });
    }
    Ok(())
}

pub fn build_nft_delete_rule_cmd(rule: &NftRule) -> Result<Vec<String>, String> {
    rule.validate()?;
    Err("nft delete rule requires a handle; list the chain with -a first".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        build_nft_add_rule_cmd, build_nft_delete_rule_cmd, build_nft_delete_rule_handle_cmd,
        build_nft_list_chain_with_handles_cmd, nft_rule_handles_from_list, NftRule,
    };

    #[test]
    fn builds_nft_add_rule_command() {
        let rule = NftRule {
            family: "ip".to_string(),
            table: "nat".to_string(),
            chain: "prerouting".to_string(),
            expr: vec![
                "tcp".to_string(),
                "dport".to_string(),
                "80".to_string(),
                "dnat".to_string(),
                "to".to_string(),
                "10.0.0.2:80".to_string(),
            ],
        };

        assert_eq!(
            build_nft_add_rule_cmd(&rule).unwrap(),
            vec![
                "nft",
                "add",
                "rule",
                "ip",
                "nat",
                "prerouting",
                "tcp",
                "dport",
                "80",
                "dnat",
                "to",
                "10.0.0.2:80"
            ]
        );

        let err = build_nft_delete_rule_cmd(&rule).expect_err("delete requires handle");
        assert!(err.contains("requires a handle"));
    }

    #[test]
    fn builds_nft_handle_lookup_and_delete_commands() {
        let rule = NftRule {
            family: "ip".to_string(),
            table: "nat".to_string(),
            chain: "prerouting".to_string(),
            expr: vec![
                "tcp".to_string(),
                "dport".to_string(),
                "8080".to_string(),
                "dnat".to_string(),
                "to".to_string(),
                "10.0.0.2:80".to_string(),
            ],
        };

        assert_eq!(
            build_nft_list_chain_with_handles_cmd(&rule).unwrap(),
            vec!["nft", "-a", "list", "chain", "ip", "nat", "prerouting"]
        );
        assert_eq!(
            build_nft_delete_rule_handle_cmd(&rule, 42).unwrap(),
            vec![
                "nft",
                "delete",
                "rule",
                "ip",
                "nat",
                "prerouting",
                "handle",
                "42"
            ]
        );
    }

    #[test]
    fn parses_nft_rule_handles_from_annotated_chain_output() {
        let rule = NftRule {
            family: "ip".to_string(),
            table: "nat".to_string(),
            chain: "prerouting".to_string(),
            expr: vec![
                "tcp".to_string(),
                "dport".to_string(),
                "8080".to_string(),
                "dnat".to_string(),
                "to".to_string(),
                "10.0.0.2:80".to_string(),
            ],
        };
        let output = r#"
table ip nat {
	chain prerouting {
		type nat hook prerouting priority filter; policy accept;
		tcp dport 8080 dnat to 10.0.0.2:80 # handle 17
		tcp dport 9090 dnat to 10.0.0.3:90 # handle 18
		tcp dport 8080 dnat to 10.0.0.2:80 # handle 19
	}
}
"#;

        assert_eq!(
            nft_rule_handles_from_list(output, &rule).unwrap(),
            vec![17, 19]
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
