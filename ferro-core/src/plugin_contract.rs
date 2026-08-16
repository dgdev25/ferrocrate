//! Versioned extension manifest validation.
//!
//! This module deliberately stops at admission: parsing a manifest is not
//! permission to execute a plugin. Runtime loading must consume the validated
//! identity, declared capabilities, and signature metadata through an
//! authorization-bound executor.

use serde::{Deserialize, Serialize};
use thiserror::Error;

const ALLOWED_PERMISSIONS: &[&str] = &[
    "read_logs",
    "write_logs",
    "read_volumes",
    "write_volumes",
    "read_networks",
    "write_networks",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    LogDriver,
    VolumeDriver,
    NetworkDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginManifest {
    pub api_version: String,
    pub name: String,
    pub version: String,
    pub kind: PluginKind,
    pub entrypoint: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Signature is opaque to admission; trust-bundle verification belongs to
    /// the deployment authority and must happen before execution.
    pub signature: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PluginManifestError {
    #[error("plugin manifest is invalid JSON: {0}")]
    Json(String),
    #[error("plugin manifest api_version must be 1")]
    ApiVersion,
    #[error("plugin manifest {field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("plugin manifest entrypoint must be an absolute path")]
    EntrypointNotAbsolute,
    #[error("plugin manifest entrypoint must not contain traversal")]
    EntrypointTraversal,
    #[error("plugin manifest permission is unsupported: {0}")]
    UnsupportedPermission(String),
}

pub fn validate_plugin_manifest(
    manifest: PluginManifest,
) -> Result<PluginManifest, PluginManifestError> {
    if manifest.api_version != "1" {
        return Err(PluginManifestError::ApiVersion);
    }
    for (field, value) in [
        ("name", manifest.name.as_str()),
        ("version", manifest.version.as_str()),
        ("signature", manifest.signature.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(PluginManifestError::EmptyField { field });
        }
    }
    if !manifest.entrypoint.starts_with('/') {
        return Err(PluginManifestError::EntrypointNotAbsolute);
    }
    if manifest.entrypoint == "/"
        || manifest.entrypoint.ends_with('/')
        || manifest
            .entrypoint
            .split('/')
            .any(|segment| segment == "..")
    {
        return Err(PluginManifestError::EntrypointTraversal);
    }
    for permission in &manifest.permissions {
        if !ALLOWED_PERMISSIONS.contains(&permission.as_str()) {
            return Err(PluginManifestError::UnsupportedPermission(
                permission.clone(),
            ));
        }
    }
    Ok(manifest)
}

pub fn parse_plugin_manifest(bytes: &[u8]) -> Result<PluginManifest, PluginManifestError> {
    let manifest = serde_json::from_slice(bytes)
        .map_err(|error| PluginManifestError::Json(error.to_string()))?;
    validate_plugin_manifest(manifest)
}

#[cfg(test)]
mod tests {
    use super::{parse_plugin_manifest, PluginKind, PluginManifestError};

    fn valid() -> &'static [u8] {
        br#"{
          "api_version":"1",
          "name":"audit-log",
          "version":"1.2.3",
          "kind":"log_driver",
          "entrypoint":"/usr/lib/ferrocrate/audit-log",
          "permissions":["write_logs"],
          "signature":"ed25519:abc"
        }"#
    }

    #[test]
    fn validates_versioned_manifest() {
        let manifest = parse_plugin_manifest(valid()).expect("manifest");
        assert_eq!(manifest.kind, PluginKind::LogDriver);
        assert_eq!(manifest.permissions, vec!["write_logs"]);
    }

    #[test]
    fn rejects_traversal_and_unknown_permissions() {
        let mut value: serde_json::Value = serde_json::from_slice(valid()).unwrap();
        value["entrypoint"] = serde_json::Value::String("/usr/../plugin".into());
        let error = parse_plugin_manifest(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(error, PluginManifestError::EntrypointTraversal);

        value["entrypoint"] = serde_json::Value::String("/usr/lib/plugin".into());
        value["permissions"] = serde_json::json!(["mount_host"]);
        let error = parse_plugin_manifest(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(
            error,
            PluginManifestError::UnsupportedPermission("mount_host".into())
        );
    }
}
