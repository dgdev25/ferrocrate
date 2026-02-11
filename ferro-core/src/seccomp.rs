use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SeccompError {
    #[error("invalid seccomp profile JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
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
    Ok(serde_json::from_str(json)?)
}

pub fn default_seccomp_profile_json() -> &'static str {
    include_str!("seccomp_default.json")
}

pub fn default_seccomp_profile() -> Result<SeccompProfile, SeccompError> {
    parse_seccomp_profile(default_seccomp_profile_json())
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
}
