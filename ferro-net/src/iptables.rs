/// Allowed iptables tables for security validation
use crate::executor::{exec_cmd, ExecError};

const ALLOWED_TABLES: &[&str] = &["filter", "nat", "mangle", "raw", "security"];

/// Allowed iptables chains for security validation
const ALLOWED_CHAINS: &[&str] = &["INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IptablesRule {
    pub table: String,
    pub chain: String,
    pub args: Vec<String>,
}

impl IptablesRule {
    /// Validate the rule for security - prevent injection attacks
    pub fn validate(&self) -> Result<(), String> {
        // Validate table name
        if !ALLOWED_TABLES.contains(&self.table.as_str()) {
            return Err(format!("Invalid iptables table: {}", self.table));
        }

        // Validate chain name (must be alphanumeric or known chain)
        if !ALLOWED_CHAINS.contains(&self.chain.to_uppercase().as_str())
            && !self
                .chain
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(format!("Invalid iptables chain: {}", self.chain));
        }

        // Validate args don't contain shell metacharacters
        for arg in &self.args {
            if arg.contains('\0')
                || arg.contains('|')
                || arg.contains(';')
                || arg.contains('`')
                || arg.contains('$')
                || arg.contains('\n')
            {
                return Err("Invalid characters in iptables arguments".to_string());
            }
        }

        Ok(())
    }
}

pub fn build_iptables_cmd(rule: &IptablesRule) -> Result<Vec<String>, String> {
    rule.validate()?;
    let mut cmd = vec!["iptables".to_string()];
    cmd.push("-t".to_string());
    cmd.push(rule.table.clone());
    cmd.push("-A".to_string());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.args.clone());
    Ok(cmd)
}

pub fn build_iptables_delete_cmd(rule: &IptablesRule) -> Result<Vec<String>, String> {
    rule.validate()?;
    let mut cmd = vec!["iptables".to_string()];
    cmd.push("-t".to_string());
    cmd.push(rule.table.clone());
    cmd.push("-D".to_string());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.args.clone());
    Ok(cmd)
}

fn build_iptables_check_cmd(rule: &IptablesRule) -> Result<Vec<String>, String> {
    rule.validate()?;
    let mut cmd = vec!["iptables".to_string(), "-t".to_string(), rule.table.clone()];
    cmd.push("-C".to_string());
    cmd.push(rule.chain.clone());
    cmd.extend(rule.args.clone());
    Ok(cmd)
}

pub fn apply_iptables_rule(rule: &IptablesRule) -> Result<(), ExecError> {
    crate::executor::HostCapabilities::probe().require_network_mutation()?;
    let cmd = build_iptables_cmd(rule).map_err(|err| ExecError::CommandFailed {
        cmd: "iptables build".to_string(),
        stderr: err,
    })?;
    exec_cmd(&cmd)?;
    let check = build_iptables_check_cmd(rule).map_err(|err| ExecError::CommandFailed {
        cmd: "iptables check build".to_string(),
        stderr: err,
    })?;
    exec_cmd(&check)
}

pub fn delete_iptables_rule(rule: &IptablesRule) -> Result<(), ExecError> {
    crate::executor::HostCapabilities::probe().require_network_mutation()?;
    let cmd = build_iptables_delete_cmd(rule).map_err(|err| ExecError::CommandFailed {
        cmd: "iptables delete build".to_string(),
        stderr: err,
    })?;
    exec_cmd(&cmd)?;
    let check = build_iptables_check_cmd(rule).map_err(|err| ExecError::CommandFailed {
        cmd: "iptables check build".to_string(),
        stderr: err,
    })?;
    match exec_cmd(&check) {
        Err(ExecError::CommandFailed { .. }) => Ok(()),
        Ok(()) => Err(ExecError::CommandFailed {
            cmd: check.join(" "),
            stderr: "rule remained after deletion".into(),
        }),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_iptables_check_cmd, build_iptables_cmd, build_iptables_delete_cmd, IptablesRule,
    };

    #[test]
    fn builds_iptables_command() {
        let rule = IptablesRule {
            table: "nat".to_string(),
            chain: "PREROUTING".to_string(),
            args: vec![
                "-p".to_string(),
                "tcp".to_string(),
                "--dport".to_string(),
                "80".to_string(),
            ],
        };

        assert_eq!(
            build_iptables_cmd(&rule).unwrap(),
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                "80"
            ]
        );

        assert_eq!(
            build_iptables_delete_cmd(&rule).unwrap(),
            vec![
                "iptables",
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                "80"
            ]
        );
    }

    #[test]
    fn rejects_invalid_table() {
        let rule = IptablesRule {
            table: "invalid_table".to_string(),
            chain: "INPUT".to_string(),
            args: vec![],
        };
        assert!(build_iptables_cmd(&rule).is_err());
    }

    #[test]
    fn rejects_shell_injection_in_args() {
        let rule = IptablesRule {
            table: "filter".to_string(),
            chain: "INPUT".to_string(),
            args: vec!["-p".to_string(), "tcp; rm -rf /".to_string()],
        };
        assert!(build_iptables_cmd(&rule).is_err());
    }

    #[test]
    fn builds_exact_rule_check_command() {
        let rule = IptablesRule {
            table: "nat".into(),
            chain: "PREROUTING".into(),
            args: vec!["-p".into(), "tcp".into()],
        };
        assert_eq!(
            build_iptables_check_cmd(&rule).unwrap(),
            vec!["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "tcp"]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rule_application_and_deletion_fail_closed_without_root_privilege() {
        if nix::unistd::geteuid().as_raw() == 0 {
            // Running with privilege would reach the real firewall; skip.
            return;
        }
        let rule = IptablesRule {
            table: "filter".into(),
            chain: "INPUT".into(),
            args: vec!["-p".into(), "tcp".into()],
        };
        assert!(matches!(
            super::apply_iptables_rule(&rule),
            Err(crate::executor::ExecError::CapabilityRequired { capability })
                if capability == "root"
        ));
        assert!(matches!(
            super::delete_iptables_rule(&rule),
            Err(crate::executor::ExecError::CapabilityRequired { capability })
                if capability == "root"
        ));
    }
}
