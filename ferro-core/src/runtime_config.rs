use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeConfigParseError {
    #[error("invalid OCI runtime config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
}

/// Parse an OCI Runtime Spec `config.json` document.
pub fn parse_runtime_config(json: &str) -> Result<RuntimeConfig, RuntimeConfigParseError> {
    Ok(serde_json::from_str(json)?)
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
}
