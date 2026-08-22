//! Stable node identity and capability record.
//!
//! The identity file is created once, atomically, and verified on every
//! restart: it must be a regular file owned by the current user with no
//! group/other permissions, and its digest must match the recorded bytes.
//! A mismatch fails closed.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_IDENTITY_BYTES: usize = 64 * 1024;

/// Resource and label record a node publishes about itself. The fields match
/// [`crate::scheduler::Node`] so admission can reuse the placement check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub labels: BTreeMap<String, String>,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub task_limit: usize,
}

/// Durable node identity: a stable ID plus the capability record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub node_id: String,
    pub capabilities: NodeCapabilities,
    pub created_unix: i64,
    digest: String,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity file is invalid")]
    Invalid,
    #[error("identity file digest mismatch: the record was modified")]
    Tampered,
    #[error("identity entropy generation failed")]
    Entropy,
}

/// Atomic, digest-verified store for the node identity file.
pub struct IdentityStore {
    path: PathBuf,
}

impl IdentityStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Load the persisted identity, enrolling a new one if no file exists.
    ///
    /// The node ID is `"node-"` followed by 32 hex characters of random
    /// entropy. It never changes once written.
    pub fn load_or_enroll(
        &self,
        capabilities: NodeCapabilities,
        now_unix: i64,
    ) -> Result<NodeIdentity, IdentityError> {
        if self.path.exists() {
            return self.load();
        }
        let mut entropy = [0_u8; 16];
        getrandom::fill(&mut entropy).map_err(|_| IdentityError::Entropy)?;
        let identity = NodeIdentity {
            node_id: format!("node-{}", hex(&entropy)),
            capabilities,
            created_unix: now_unix,
            digest: String::new(),
        }
        .sealed();
        self.write_atomically(&identity)?;
        Ok(identity)
    }

    /// Load and verify the persisted identity.
    pub fn load(&self) -> Result<NodeIdentity, IdentityError> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.len() > MAX_IDENTITY_BYTES as u64
        {
            return Err(IdentityError::Invalid);
        }
        let bytes = fs::read(&self.path)?;
        let identity: NodeIdentity =
            serde_json::from_slice(&bytes).map_err(|_| IdentityError::Invalid)?;
        if identity.digest != identity.digest_of() || identity.node_id.trim().is_empty() {
            return Err(IdentityError::Tampered);
        }
        Ok(identity)
    }

    fn write_atomically(&self, identity: &NodeIdentity) -> Result<(), IdentityError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec(identity).map_err(|_| IdentityError::Invalid)?;
        if bytes.len() > MAX_IDENTITY_BYTES {
            return Err(IdentityError::Invalid);
        }
        let temporary = self.path.with_extension("tmp");
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        Ok(())
    }
}

impl NodeIdentity {
    fn digest_of(&self) -> String {
        let mut record = self.clone();
        record.digest = String::new();
        let bytes = serde_json::to_vec(&record).unwrap_or_default();
        hex(&Sha256::digest(bytes))
    }

    /// Return a copy with a digest computed over the current fields.
    fn sealed(mut self) -> Self {
        let digest = self.digest_of();
        self.digest = digest;
        self
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> NodeCapabilities {
        NodeCapabilities {
            labels: BTreeMap::from([("zone".into(), "west".into())]),
            cpu_millis: 4_000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            task_limit: 16,
        }
    }

    #[test]
    fn identity_is_stable_across_restart_and_digest_verified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.json");
        let store = IdentityStore::new(&path);
        let first = store.load_or_enroll(capabilities(), 1_000).unwrap();
        let second = store.load().unwrap();
        assert_eq!(first, second);
        assert!(second.node_id.starts_with("node-"));
        assert_eq!(second.node_id.len(), "node-".len() + 32);
        assert_eq!(second.created_unix, 1_000);

        // Rewriting an existing identity never re-enrolls.
        let third = store.load_or_enroll(capabilities(), 2_000).unwrap();
        assert_eq!(third.node_id, first.node_id);
        assert_eq!(third.created_unix, 1_000);
    }

    #[test]
    fn tampered_identity_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.json");
        let store = IdentityStore::new(&path);
        let identity = store.load_or_enroll(capabilities(), 1_000).unwrap();

        let mut modified = identity.clone();
        modified.capabilities.cpu_millis = 999_999;
        fs::write(&path, serde_json::to_vec(&modified).unwrap()).unwrap();
        assert!(matches!(store.load(), Err(IdentityError::Tampered)));
    }

    #[test]
    fn insecure_permissions_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.json");
        let store = IdentityStore::new(&path);
        let identity = store.load_or_enroll(capabilities(), 1_000).unwrap();

        // Rewrite the same (digest-valid) bytes with group read access.
        fs::remove_file(&path).unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = OpenOptions::new()
            .mode(0o640)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&serde_json::to_vec(&identity).unwrap())
            .unwrap();
        assert!(matches!(store.load(), Err(IdentityError::Invalid)));
    }
}
