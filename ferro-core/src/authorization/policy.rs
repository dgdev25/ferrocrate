//! Secure loading and atomic replacement of native authorization policies.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::PolicyDocument;

/// Maximum accepted policy source size (1 MiB).
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
const POLICY_SCHEMA_VERSION: u32 = 1;

/// An immutable, digest-bound view of a validated policy.
#[derive(Clone, Debug)]
pub struct PolicySnapshot {
    pub generation: u64,
    pub digest: [u8; 32],
    pub document: Arc<PolicyDocument>,
}

/// A thread-safe store that replaces policies only after full validation.
#[derive(Debug)]
pub struct PolicyStore {
    active: RwLock<PolicySnapshot>,
}

/// Proof that the caller passed the separate policy-rollback authorization path.
///
/// Only the authorization module can mint this proof.
#[derive(Debug)]
pub struct PolicyRollbackAuthorization {
    actor: String,
}

impl PolicyRollbackAuthorization {
    #[allow(dead_code)]
    pub(crate) fn new(actor: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
        }
    }
}

/// Stable failures returned at the policy boundary.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy path is a symbolic link")]
    Symlink,
    #[error("policy must be a regular file")]
    NotRegularFile,
    #[error("policy owner {actual} does not match effective uid {expected}")]
    WrongOwner { expected: u32, actual: u32 },
    #[error("policy mode {mode:#o} permits modification by group or other users")]
    UnsafeMode { mode: u32 },
    #[error("policy exceeds the {maximum}-byte limit")]
    TooLarge { maximum: usize },
    #[error("policy TOML is invalid: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("policy source is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("unsupported policy schema version {0}")]
    UnsupportedSchema(u32),
    #[error("policy generation must be greater than zero")]
    InvalidGeneration,
    #[error(
        "policy generation rollback from {current} to {candidate} requires separate authorization"
    )]
    Rollback { current: u64, candidate: u64 },
    #[error("policy store lock is unavailable")]
    LockPoisoned,
    #[error("policy file operation failed: {0}")]
    Io(#[from] std::io::Error),
}

impl PolicyStore {
    /// Load and validate the initial policy snapshot.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let snapshot = load_snapshot(path.as_ref())?;
        Ok(Self {
            active: RwLock::new(snapshot),
        })
    }

    /// Clone the active immutable snapshot.
    pub fn snapshot(&self) -> PolicySnapshot {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Validate a complete candidate and atomically install it if monotonic.
    pub fn reload(
        &self,
        path: impl AsRef<Path>,
        _actor: &str,
    ) -> Result<PolicySnapshot, PolicyError> {
        self.replace(path.as_ref(), false)
    }

    /// Install a lower generation only from the separately authorized rollback path.
    pub fn reload_authorized_rollback(
        &self,
        path: impl AsRef<Path>,
        authorization: &PolicyRollbackAuthorization,
    ) -> Result<PolicySnapshot, PolicyError> {
        let _actor = &authorization.actor;
        self.replace(path.as_ref(), true)
    }

    fn replace(
        &self,
        path: &Path,
        rollback_authorized: bool,
    ) -> Result<PolicySnapshot, PolicyError> {
        let candidate = load_snapshot(path)?;
        let mut active = self.active.write().map_err(|_| PolicyError::LockPoisoned)?;
        if candidate.generation < active.generation && !rollback_authorized {
            return Err(PolicyError::Rollback {
                current: active.generation,
                candidate: candidate.generation,
            });
        }
        *active = candidate.clone();
        Ok(candidate)
    }
}

fn load_snapshot(path: &Path) -> Result<PolicySnapshot, PolicyError> {
    let mut file = open_without_following_symlinks(path)?;
    validate_metadata(&file)?;

    let mut source = Vec::new();
    file.by_ref()
        .take((MAX_POLICY_BYTES + 1) as u64)
        .read_to_end(&mut source)?;
    if source.len() > MAX_POLICY_BYTES {
        return Err(PolicyError::TooLarge {
            maximum: MAX_POLICY_BYTES,
        });
    }

    let document: PolicyDocument = toml::from_str(std::str::from_utf8(&source)?)?;
    validate_document(&document)?;
    let digest = Sha256::digest(&source).into();
    Ok(PolicySnapshot {
        generation: document.generation,
        digest,
        document: Arc::new(document),
    })
}

fn open_without_following_symlinks(path: &Path) -> Result<File, PolicyError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);

    options.open(path).map_err(|error| {
        #[cfg(unix)]
        if error.raw_os_error() == Some(nix::libc::ELOOP) {
            return PolicyError::Symlink;
        }
        PolicyError::Io(error)
    })
}

fn validate_metadata(file: &File) -> Result<(), PolicyError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(PolicyError::NotRegularFile);
    }

    #[cfg(unix)]
    {
        let expected = nix::unistd::geteuid().as_raw();
        let actual = metadata.uid();
        if actual != expected {
            return Err(PolicyError::WrongOwner { expected, actual });
        }
        let mode = metadata.mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(PolicyError::UnsafeMode { mode });
        }
    }

    if metadata.len() > MAX_POLICY_BYTES as u64 {
        return Err(PolicyError::TooLarge {
            maximum: MAX_POLICY_BYTES,
        });
    }
    Ok(())
}

fn validate_document(document: &PolicyDocument) -> Result<(), PolicyError> {
    if document.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::UnsupportedSchema(document.schema_version));
    }
    if document.generation == 0 {
        return Err(PolicyError::InvalidGeneration);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::{PolicyRollbackAuthorization, PolicyStore};

    #[test]
    fn separately_authorized_path_can_install_an_older_generation() {
        let dir = TempDir::new().expect("tempdir");
        let current = dir.path().join("current.toml");
        let rollback = dir.path().join("rollback.toml");
        fs::write(
            &current,
            "schema_version = 1\ngeneration = 2\nmode = \"enforce\"\n",
        )
        .expect("current policy");
        fs::write(
            &rollback,
            "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n",
        )
        .expect("rollback policy");
        for path in [&current, &rollback] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("policy mode");
        }
        let store = PolicyStore::load(&current).expect("load current");
        let authorization = PolicyRollbackAuthorization::new("host-administrator");

        let installed = store
            .reload_authorized_rollback(&rollback, &authorization)
            .expect("authorized rollback");

        assert_eq!(installed.generation, 1);
        assert_eq!(store.snapshot().generation, 1);
    }
}
