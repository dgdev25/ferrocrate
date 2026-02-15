use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeConfigParseError {
    #[error("invalid OCI runtime config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported OCI runtime version: {0}")]
    InvalidOciVersion(String),
    #[error("missing required section: {0}")]
    MissingRequiredField(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(String),
}

/// Parse an OCI Runtime Spec `config.json` document.
pub fn parse_runtime_config(json: &str) -> Result<RuntimeConfig, RuntimeConfigParseError> {
    let cfg: RuntimeConfig = serde_json::from_str(json)?;
    cfg.validate()?;
    Ok(cfg)
}

/// Minimal-but-extensible representation of OCI Runtime Spec v1.2 `config.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    pub oci_version: String,
    pub process: Option<Process>,
    pub root: Option<Root>,
    pub hostname: Option<String>,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    pub linux: Option<Linux>,
    #[serde(default)]
    pub annotations: HashMap<String, String>,
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), RuntimeConfigParseError> {
        if !(self.oci_version.starts_with("1.0")
            || self.oci_version.starts_with("1.1")
            || self.oci_version.starts_with("1.2"))
        {
            return Err(RuntimeConfigParseError::InvalidOciVersion(
                self.oci_version.clone(),
            ));
        }
        let process = self
            .process
            .as_ref()
            .ok_or(RuntimeConfigParseError::MissingRequiredField("process"))?;
        if process.args.is_empty() {
            return Err(RuntimeConfigParseError::InvalidField(
                "process.args must not be empty".to_string(),
            ));
        }
        if let Some(cwd) = process.cwd.as_deref() {
            if !cwd.starts_with('/') {
                return Err(RuntimeConfigParseError::InvalidField(
                    "process.cwd must be absolute".to_string(),
                ));
            }
        }
        let root = self
            .root
            .as_ref()
            .ok_or(RuntimeConfigParseError::MissingRequiredField("root"))?;
        if root.path.trim().is_empty() {
            return Err(RuntimeConfigParseError::InvalidField(
                "root.path must not be empty".to_string(),
            ));
        }
        let mut seen_mounts = HashSet::new();
        for mount in &self.mounts {
            if !mount.destination.starts_with('/') {
                return Err(RuntimeConfigParseError::InvalidField(format!(
                    "mount destination must be absolute: {}",
                    mount.destination
                )));
            }
            if !seen_mounts.insert(mount.destination.as_str()) {
                return Err(RuntimeConfigParseError::InvalidField(format!(
                    "duplicate mount destination: {}",
                    mount.destination
                )));
            }
        }
        if let Some(linux) = self.linux.as_ref() {
            let mut ns_types = HashSet::new();
            for ns in &linux.namespaces {
                let kind = ns.namespace_type.as_str();
                let valid = matches!(
                    kind,
                    "pid" | "network" | "mount" | "ipc" | "uts" | "user" | "cgroup" | "time"
                );
                if !valid {
                    return Err(RuntimeConfigParseError::InvalidField(format!(
                        "unsupported linux namespace type: {kind}"
                    )));
                }
                if !ns_types.insert(kind) {
                    return Err(RuntimeConfigParseError::InvalidField(format!(
                        "duplicate linux namespace type: {kind}"
                    )));
                }
            }
            for map in linux.uid_mappings.iter().chain(linux.gid_mappings.iter()) {
                if map.size == 0 {
                    return Err(RuntimeConfigParseError::InvalidField(
                        "id mapping size must be > 0".to_string(),
                    ));
                }
            }
            if let Some(resources) = linux.resources.as_ref() {
                if let Some(memory) = resources.memory.as_ref() {
                    if memory.limit.map(|v| v < 0).unwrap_or(false)
                        || memory.reservation.map(|v| v < 0).unwrap_or(false)
                        || memory.swap.map(|v| v < 0).unwrap_or(false)
                    {
                        return Err(RuntimeConfigParseError::InvalidField(
                            "linux.resources.memory values must be >= 0".to_string(),
                        ));
                    }
                }
                if let Some(cpu) = resources.cpu.as_ref() {
                    if cpu.quota.map(|v| v < 0).unwrap_or(false) {
                        return Err(RuntimeConfigParseError::InvalidField(
                            "linux.resources.cpu.quota must be >= 0".to_string(),
                        ));
                    }
                }
                if let Some(pids) = resources.pids.as_ref() {
                    if pids.limit <= 0 {
                        return Err(RuntimeConfigParseError::InvalidField(
                            "linux.resources.pids.limit must be > 0".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    pub terminal: Option<bool>,
    pub user: Option<User>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
    #[serde(default)]
    pub no_new_privileges: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(default)]
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    #[serde(default)]
    pub bounding: Vec<String>,
    #[serde(default)]
    pub effective: Vec<String>,
    #[serde(default)]
    pub inheritable: Vec<String>,
    #[serde(default)]
    pub permitted: Vec<String>,
    #[serde(default)]
    pub ambient: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub path: String,
    pub readonly: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: Option<String>,
    pub source: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    #[serde(default)]
    pub namespaces: Vec<LinuxNamespace>,
    #[serde(default)]
    pub resources: Option<LinuxResources>,
    #[serde(default)]
    pub uid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub gid_mappings: Vec<IdMapping>,
    #[serde(default)]
    pub cgroups_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxNamespace {
    #[serde(rename = "type")]
    pub namespace_type: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxResources {
    pub memory: Option<LinuxMemory>,
    pub cpu: Option<LinuxCpu>,
    pub pids: Option<LinuxPids>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxMemory {
    pub limit: Option<i64>,
    pub reservation: Option<i64>,
    pub swap: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxCpu {
    pub shares: Option<u64>,
    pub quota: Option<i64>,
    pub period: Option<u64>,
    pub cpus: Option<String>,
    pub mems: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinuxPids {
    pub limit: i64,
}

#[cfg(test)]
mod tests {
    use super::parse_runtime_config;

    #[test]
    fn parses_minimal_oci_runtime_config() {
        let config = r#"
        {
          "ociVersion": "1.2.0",
          "process": {
            "terminal": false,
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/"
          },
          "root": {
            "path": "rootfs",
            "readonly": true
          },
          "mounts": [
            {
              "destination": "/proc",
              "type": "proc",
              "source": "proc"
            }
          ],
          "linux": {
            "namespaces": [
              {"type": "pid"},
              {"type": "network"},
              {"type": "mount"}
            ],
            "resources": {
              "memory": {"limit": 536870912},
              "cpu": {"shares": 1024},
              "pids": {"limit": 256}
            }
          },
          "annotations": {
            "org.opencontainers.image.ref.name": "test"
          }
        }
        "#;

        let parsed = parse_runtime_config(config).expect("config should parse");

        assert_eq!(parsed.oci_version, "1.2.0");
        assert_eq!(parsed.mounts.len(), 1);
        assert_eq!(
            parsed.linux.expect("linux section").namespaces.len(),
            3
        );
    }

    #[test]
    fn returns_error_for_invalid_json() {
        let invalid = r#"{"ociVersion": "1.2.0", "process": {"args": [}}"#;
        let result = parse_runtime_config(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_missing_required_sections() {
        let invalid = r#"{"ociVersion":"1.2.0"}"#;
        let err = parse_runtime_config(invalid).expect_err("missing process/root");
        assert!(err.to_string().contains("missing required section"));
    }

    #[test]
    fn rejects_relative_cwd_and_duplicate_mounts() {
        let invalid = r#"
        {
          "ociVersion":"1.2.0",
          "process":{"args":["/bin/sh"],"cwd":"tmp"},
          "root":{"path":"rootfs"},
          "mounts":[
            {"destination":"/proc","type":"proc","source":"proc"},
            {"destination":"/proc","type":"proc","source":"proc"}
          ]
        }
        "#;
        let err = parse_runtime_config(invalid).expect_err("invalid fields");
        assert!(err.to_string().contains("process.cwd"));
    }

    #[test]
    fn rejects_invalid_namespace_and_resource_limits() {
        let invalid = r#"
        {
          "ociVersion":"1.2.0",
          "process":{"args":["/bin/sh"],"cwd":"/"},
          "root":{"path":"rootfs"},
          "linux":{
            "namespaces":[{"type":"unknown"}],
            "resources":{"pids":{"limit":0}}
          }
        }
        "#;
        let err = parse_runtime_config(invalid).expect_err("invalid linux fields");
        assert!(
            err.to_string().contains("unsupported linux namespace type")
                || err.to_string().contains("pids.limit")
        );
    }
}
