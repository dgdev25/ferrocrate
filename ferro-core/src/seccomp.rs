use libseccomp::{
    ScmpAction, ScmpArch, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SeccompError {
    #[error("invalid seccomp profile JSON: {0}")]
    InvalidJson(String),
    #[error("failed to apply seccomp profile: {0}")]
    Apply(#[from] libseccomp::error::SeccompError),
    #[error("unknown syscall action: {0}")]
    UnknownAction(String),
    #[error("unknown syscall name: {0}")]
    UnknownSyscall(String),
    #[error("unknown architecture: {0}")]
    UnknownArch(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeccompProfile {
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    #[serde(rename = "defaultErrnoRet")]
    pub default_errno_ret: Option<i64>,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SyscallRule>,
}

impl SeccompProfile {
    /// SEC-06: Validate semantic correctness of seccomp profile
    pub fn validate(&self) -> Result<(), SeccompError> {
        // Validate default_action is a known SCMP_ACT_* constant
        if parse_action(&self.default_action).is_err() {
            return Err(SeccompError::UnknownAction(self.default_action.clone()));
        }

        // Validate architectures are known SCMP_ARCH_* constants
        for arch in &self.architectures {
            match arch.as_str() {
                "SCMP_ARCH_X86_64" | "SCMP_ARCH_X86" | "SCMP_ARCH_X32" | "SCMP_ARCH_ARM"
                | "SCMP_ARCH_AARCH64" | "SCMP_ARCH_MIPS" | "SCMP_ARCH_MIPS64" | "SCMP_ARCH_PPC"
                | "SCMP_ARCH_PPC64" | "SCMP_ARCH_PPC64LE" | "SCMP_ARCH_S390X" => {}
                _ => return Err(SeccompError::UnknownArch(arch.clone())),
            }
        }

        // Validate each syscall rule
        for rule in &self.syscalls {
            // Validate action
            parse_action(&rule.action)?;

            // Validate args[].index values are in range 0..5
            if let Some(args) = &rule.args {
                for arg in args {
                    if arg.index > 5 {
                        return Err(SeccompError::InvalidJson(format!(
                            "arg index {} out of range 0..5",
                            arg.index
                        )));
                    }
                }
            }
        }

        // Check for contradictory rules (same syscall with both ALLOW and KILL)
        let mut syscall_actions: std::collections::HashMap<&str, &str> =
            std::collections::HashMap::new();
        for rule in &self.syscalls {
            for name in &rule.names {
                if let Some(existing) = syscall_actions.get(name.as_str()) {
                    let is_kill =
                        *existing == "SCMP_ACT_KILL" || *existing == "SCMP_ACT_KILL_PROCESS";
                    let new_kill =
                        rule.action == "SCMP_ACT_KILL" || rule.action == "SCMP_ACT_KILL_PROCESS";
                    if (is_kill && rule.action == "SCMP_ACT_ALLOW")
                        || (new_kill && *existing == "SCMP_ACT_ALLOW")
                    {
                        return Err(SeccompError::InvalidJson(format!(
                            "contradictory rules for syscall {}: both KILL and ALLOW",
                            name
                        )));
                    }
                }
                syscall_actions.insert(name.as_str(), &rule.action);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyscallRule {
    pub names: Vec<String>,
    pub action: String,
    pub args: Option<Vec<SyscallArg>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyscallArg {
    pub index: u32,
    pub value: u64,
    #[serde(rename = "valueTwo")]
    pub value_two: Option<u64>,
    pub op: String,
}

pub fn parse_seccomp_profile(json: &str) -> Result<SeccompProfile, SeccompError> {
    let profile: SeccompProfile =
        serde_json::from_str(json).map_err(|e| SeccompError::InvalidJson(format!("{}", e)))?;
    // SEC-06: Validate semantic correctness immediately after parsing
    profile.validate()?;
    Ok(profile)
}

pub fn default_seccomp_profile_json() -> &'static str {
    include_str!("seccomp_default.json")
}

pub fn default_seccomp_profile() -> Result<SeccompProfile, SeccompError> {
    parse_seccomp_profile(default_seccomp_profile_json())
}

/// Converts a string action name to libseccomp action.
fn parse_action(action: &str) -> Result<ScmpAction, SeccompError> {
    match action {
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_PROCESS" => Ok(ScmpAction::KillProcess),
        "SCMP_ACT_KILL_THREAD" => Ok(ScmpAction::KillThread),
        "SCMP_ACT_TRAP" => Ok(ScmpAction::Trap),
        "SCMP_ACT_ERRNO" => Ok(ScmpAction::Errno(1)), // Default errno
        "SCMP_ACT_TRACE" => Ok(ScmpAction::Trace(0)),
        "SCMP_ACT_ALLOW" => Ok(ScmpAction::Allow),
        "SCMP_ACT_LOG" => Ok(ScmpAction::Log),
        _ => Err(SeccompError::UnknownAction(action.to_string())),
    }
}

/// Applies a seccomp profile to the current process.
///
/// # Safety
/// This function must be called AFTER fork but BEFORE exec in the child process.
/// It should also be called AFTER capability drops (seccomp is the last sandboxing step).
///
/// # Errors
/// Returns an error if:
/// - The profile contains unknown syscalls or actions
/// - The libseccomp library fails to apply the filter
pub fn apply_seccomp_profile(profile: &SeccompProfile) -> Result<(), SeccompError> {
    let default_action = parse_action(&profile.default_action)?;

    // Create the filter with the default action
    let mut filter = ScmpFilterContext::new_filter(default_action)?;

    // Add architecture rules
    for arch in &profile.architectures {
        let scmp_arch = match arch.as_str() {
            "SCMP_ARCH_X86_64" => ScmpArch::X8664,
            "SCMP_ARCH_X86" => ScmpArch::X86,
            "SCMP_ARCH_X32" => ScmpArch::X32,
            "SCMP_ARCH_ARM" => ScmpArch::Arm,
            "SCMP_ARCH_AARCH64" => ScmpArch::Aarch64,
            "SCMP_ARCH_MIPS" => ScmpArch::Mips,
            "SCMP_ARCH_MIPS64" => ScmpArch::Mips64,
            "SCMP_ARCH_PPC" => ScmpArch::Ppc,
            "SCMP_ARCH_PPC64" => ScmpArch::Ppc64,
            "SCMP_ARCH_PPC64LE" => ScmpArch::Ppc64Le,
            "SCMP_ARCH_S390X" => ScmpArch::S390X,
            _ => return Err(SeccompError::UnknownArch(arch.clone())),
        };
        filter.add_arch(scmp_arch)?;
    }

    // Add syscall rules
    for rule in &profile.syscalls {
        let action = parse_action(&rule.action)?;

        for syscall_name in &rule.names {
            // Get syscall number by name
            let syscall = ScmpSyscall::from_name(syscall_name)
                .map_err(|_| SeccompError::UnknownSyscall(syscall_name.clone()))?;

            // Handle argument rules if present
            if let Some(args) = &rule.args {
                for arg in args {
                    let cmp_op = match arg.op.as_str() {
                        "SCMP_CMP_NE" => ScmpCompareOp::NotEqual,
                        "SCMP_CMP_LT" => ScmpCompareOp::Less,
                        "SCMP_CMP_LE" => ScmpCompareOp::LessOrEqual,
                        "SCMP_CMP_EQ" => ScmpCompareOp::Equal,
                        "SCMP_CMP_GE" => ScmpCompareOp::GreaterEqual,
                        "SCMP_CMP_GT" => ScmpCompareOp::Greater,
                        "SCMP_CMP_MASKED_EQ" => {
                            // For masked equality, use the value as mask
                            let mask = arg.value;
                            filter.add_rule_conditional(
                                action,
                                syscall,
                                &[ScmpArgCompare::new(
                                    arg.index,
                                    ScmpCompareOp::MaskedEqual(mask),
                                    arg.value_two.unwrap_or(0),
                                )],
                            )?;
                            continue;
                        }
                        _ => {
                            return Err(SeccompError::UnknownAction(format!("cmp_op: {}", arg.op)))
                        }
                    };
                    filter.add_rule_conditional(
                        action,
                        syscall,
                        &[ScmpArgCompare::new(arg.index, cmp_op, arg.value)],
                    )?;
                }
            } else {
                // No argument rules - add simple rule
                filter.add_rule(action, syscall)?;
            }
        }
    }

    // Apply the filter
    filter.load()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{default_seccomp_profile, parse_seccomp_profile};

    #[test]
    fn loads_default_profile() {
        let profile = default_seccomp_profile().expect("default profile should parse");
        assert_eq!(profile.default_action, "SCMP_ACT_ERRNO");
        assert!(!profile.syscalls.is_empty());
    }

    #[test]
    fn rejects_invalid_profile_json() {
        let err = parse_seccomp_profile("{not-json").expect_err("invalid json");
        assert!(err.to_string().contains("invalid seccomp profile JSON"));
    }

    #[test]
    fn parses_known_actions() {
        use super::parse_action;
        assert!(parse_action("SCMP_ACT_ALLOW").is_ok());
        assert!(parse_action("SCMP_ACT_KILL_PROCESS").is_ok());
        assert!(parse_action("SCMP_ACT_ERRNO").is_ok());
        assert!(parse_action("unknown").is_err());
    }
}
