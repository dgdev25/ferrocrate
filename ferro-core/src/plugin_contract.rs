//! Versioned extension manifest validation.
//!
//! This module deliberately stops at admission: parsing a manifest is not
//! permission to execute a plugin. Runtime loading must consume the validated
//! identity, declared capabilities, and signature metadata through an
//! authorization-bound executor.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub const ALLOWED_PERMISSIONS: &[&str] = &[
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
    #[serde(default)]
    pub limits: PluginLimits,
    /// Signature is opaque to admission; trust-bundle verification belongs to
    /// the deployment authority and must happen before execution.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginLimits {
    #[serde(default = "default_memory_limit")]
    pub memory_bytes: u64,
    #[serde(default = "default_pid_limit")]
    pub pids: u32,
    #[serde(default = "default_timeout_limit")]
    pub timeout_secs: u64,
    #[serde(default = "default_output_limit")]
    pub max_output_bytes: u64,
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            memory_bytes: default_memory_limit(),
            pids: default_pid_limit(),
            timeout_secs: default_timeout_limit(),
            max_output_bytes: default_output_limit(),
        }
    }
}

fn default_memory_limit() -> u64 {
    256 * 1024 * 1024
}
fn default_pid_limit() -> u32 {
    64
}
fn default_timeout_limit() -> u64 {
    300
}
fn default_output_limit() -> u64 {
    16 * 1024 * 1024
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
    #[error("plugin manifest resource limits are invalid: {0}")]
    InvalidLimits(&'static str),
    #[error("plugin manifest signature must use ed25519:<128 hex characters>")]
    SignatureEncoding,
    #[error("plugin manifest signature verification failed")]
    SignatureInvalid,
    #[error("plugin manifest canonicalization failed: {0}")]
    Canonicalization(String),
    #[error("plugin trust root could not be read: {0}")]
    TrustRootIo(String),
    #[error("plugin trust root must be a regular owner-only file")]
    TrustRootPermissions,
    #[error("plugin trust root must contain exactly 32 raw bytes or 64 hex characters")]
    TrustRootEncoding,
    #[error("plugin trust root public key is invalid")]
    TrustRootKey,
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
    if manifest.limits.memory_bytes == 0 || manifest.limits.memory_bytes > 1024 * 1024 * 1024 {
        return Err(PluginManifestError::InvalidLimits("memory_bytes"));
    }
    if manifest.limits.pids == 0 || manifest.limits.pids > 65_536 {
        return Err(PluginManifestError::InvalidLimits("pids"));
    }
    if manifest.limits.timeout_secs == 0 || manifest.limits.timeout_secs > 86_400 {
        return Err(PluginManifestError::InvalidLimits("timeout_secs"));
    }
    if manifest.limits.max_output_bytes == 0
        || manifest.limits.max_output_bytes > 1024 * 1024 * 1024
    {
        return Err(PluginManifestError::InvalidLimits("max_output_bytes"));
    }
    Ok(manifest)
}

pub fn parse_plugin_manifest(bytes: &[u8]) -> Result<PluginManifest, PluginManifestError> {
    let manifest = serde_json::from_slice(bytes)
        .map_err(|error| PluginManifestError::Json(error.to_string()))?;
    validate_plugin_manifest(manifest)
}

/// Load the deployment-selected plugin trust root from an owner-only file.
///
/// Accepts either the raw 32-byte Ed25519 public key or its 64-character hex
/// encoding. Symlinks, group/world-readable files, oversized files, and keys
/// owned by another uid are rejected before parsing.
pub fn load_plugin_trust_root(path: &Path) -> Result<VerifyingKey, PluginManifestError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| PluginManifestError::TrustRootIo(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(PluginManifestError::TrustRootPermissions);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(PluginManifestError::TrustRootPermissions);
        }
    }
    if metadata.len() > 4096 {
        return Err(PluginManifestError::TrustRootEncoding);
    }
    let bytes =
        std::fs::read(path).map_err(|error| PluginManifestError::TrustRootIo(error.to_string()))?;
    let raw = if bytes.len() == 32 {
        bytes
    } else {
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| PluginManifestError::TrustRootEncoding)?
            .trim();
        let decoded = hex::decode(text).map_err(|_| PluginManifestError::TrustRootEncoding)?;
        if decoded.len() != 32 {
            return Err(PluginManifestError::TrustRootEncoding);
        }
        decoded
    };
    let key: [u8; 32] = raw
        .try_into()
        .map_err(|_| PluginManifestError::TrustRootEncoding)?;
    VerifyingKey::from_bytes(&key).map_err(|_| PluginManifestError::TrustRootKey)
}

/// Verify the detached Ed25519 signature over canonical JSON with the
/// manifest's signature field cleared. Trust-key selection remains the
/// deployment authority's responsibility.
pub fn verify_plugin_signature(
    manifest: &PluginManifest,
    key: &VerifyingKey,
) -> Result<(), PluginManifestError> {
    let encoded = manifest
        .signature
        .strip_prefix("ed25519:")
        .ok_or(PluginManifestError::SignatureEncoding)?;
    let bytes = hex::decode(encoded).map_err(|_| PluginManifestError::SignatureEncoding)?;
    let signature =
        Signature::from_slice(&bytes).map_err(|_| PluginManifestError::SignatureEncoding)?;
    let mut unsigned = manifest.clone();
    unsigned.signature.clear();
    let payload = serde_json::to_vec(&unsigned)
        .map_err(|error| PluginManifestError::Canonicalization(error.to_string()))?;
    key.verify(&payload, &signature)
        .map_err(|_| PluginManifestError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::{load_plugin_trust_root, parse_plugin_manifest, PluginKind, PluginManifestError};
    use ed25519_dalek::{Signer, SigningKey};

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
    fn validates_published_v1_sdk_fixture() {
        let manifest = parse_plugin_manifest(include_bytes!(
            "../../tests/fixtures/plugins/log-driver-v1.json"
        ))
        .expect("published plugin fixture");
        assert_eq!(manifest.api_version, "1");
        assert_eq!(manifest.name, "audit-log");
        assert_eq!(manifest.limits.pids, 16);
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

        value["permissions"] = serde_json::json!([]);
        value["limits"] = serde_json::json!({"memory_bytes": 0});
        let error = parse_plugin_manifest(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(error, PluginManifestError::InvalidLimits("memory_bytes"));
    }

    #[test]
    fn verifies_canonical_manifest_signature() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut unsigned_manifest = parse_plugin_manifest(valid()).unwrap();
        unsigned_manifest.signature.clear();
        let unsigned = serde_json::to_vec(&unsigned_manifest).unwrap();
        let signature = key.sign(&unsigned);
        unsigned_manifest.signature = format!("ed25519:{}", hex::encode(signature.to_bytes()));
        let manifest = unsigned_manifest;
        super::verify_plugin_signature(&manifest, &key.verifying_key()).expect("signature");

        let mut tampered = manifest.clone();
        tampered.name = "tampered".into();
        assert_eq!(
            super::verify_plugin_signature(&tampered, &key.verifying_key()).unwrap_err(),
            PluginManifestError::SignatureInvalid
        );
    }

    #[test]
    fn loads_owner_only_hex_trust_root_and_rejects_unsafe_files() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("plugin-root.pub");
        let key = SigningKey::from_bytes(&[9u8; 32]);
        std::fs::write(&path, hex::encode(key.verifying_key().to_bytes())).expect("write key");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure key");
        assert_eq!(
            load_plugin_trust_root(&path).expect("trust root"),
            key.verifying_key()
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("relax key");
        assert_eq!(
            load_plugin_trust_root(&path).unwrap_err(),
            PluginManifestError::TrustRootPermissions
        );
    }
}
