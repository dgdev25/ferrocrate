//! Secure loading and atomic replacement of native authorization policies.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, RwLock};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{PolicyDocument, ResolvedPrincipal, Role};

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

/// A fully validated policy and the exact bytes read from one protected file
/// descriptor. Callers authorize and install this value rather than reopening
/// a caller-controlled path after authorization.
#[derive(Clone, Debug)]
pub struct PolicyCandidate {
    snapshot: PolicySnapshot,
    source: Arc<[u8]>,
}

impl PolicyCandidate {
    pub fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }

    pub fn source_bytes(&self) -> &[u8] {
        &self.source
    }
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
    actor: ResolvedPrincipal,
}

impl PolicyRollbackAuthorization {
    #[allow(dead_code)] // Minted only by the authorization gate in a later task.
    pub(super) fn new(actor: ResolvedPrincipal) -> Self {
        Self { actor }
    }
}

/// Stable failures returned at the policy boundary.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy path is a symbolic link")]
    Symlink,
    #[error("policy must be a regular file")]
    NotRegularFile,
    #[error("policy must have exactly one filesystem link")]
    HardLinked,
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
    #[error("policy reload requires a resolved administrator principal")]
    UnauthorizedReload,
    #[error("policy store lock is unavailable")]
    LockPoisoned,
    #[error("policy file operation failed: {0}")]
    Io(#[from] std::io::Error),
}

impl PolicyStore {
    pub(crate) fn compatibility_disabled() -> Self {
        let document = PolicyDocument {
            schema_version: POLICY_SCHEMA_VERSION,
            generation: 1,
            mode: super::AuthorizationMode::Disabled,
        };
        let source = b"schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n";
        Self {
            active: RwLock::new(PolicySnapshot {
                generation: 1,
                digest: Sha256::digest(source).into(),
                document: Arc::new(document),
            }),
        }
    }

    /// Load and validate the initial policy snapshot.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let snapshot = Self::load_candidate(path)?.snapshot;
        Ok(Self {
            active: RwLock::new(snapshot),
        })
    }

    pub fn load_candidate(path: impl AsRef<Path>) -> Result<PolicyCandidate, PolicyError> {
        load_candidate(path.as_ref())
    }

    pub fn from_candidate(candidate: &PolicyCandidate) -> Self {
        Self {
            active: RwLock::new(candidate.snapshot.clone()),
        }
    }

    /// Atomically replace the in-memory snapshot with the exact candidate
    /// that was already authorized and durably installed by the caller.
    pub fn install_candidate(
        &self,
        candidate: &PolicyCandidate,
        rollback_authorized: bool,
    ) -> Result<PolicySnapshot, PolicyError> {
        let mut active = self.active.write().map_err(|_| PolicyError::LockPoisoned)?;
        if candidate.snapshot.generation < active.generation && !rollback_authorized {
            return Err(PolicyError::Rollback {
                current: active.generation,
                candidate: candidate.snapshot.generation,
            });
        }
        *active = candidate.snapshot.clone();
        Ok(active.clone())
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
        actor: &ResolvedPrincipal,
    ) -> Result<PolicySnapshot, PolicyError> {
        if actor.role() != Role::Administrator {
            return Err(PolicyError::UnauthorizedReload);
        }
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
        let candidate = load_candidate(path)?.snapshot;
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

fn load_candidate(path: &Path) -> Result<PolicyCandidate, PolicyError> {
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
    Ok(PolicyCandidate {
        snapshot: PolicySnapshot {
            generation: document.generation,
            digest,
            document: Arc::new(document),
        },
        source: source.into(),
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
        if metadata.nlink() != 1 {
            return Err(PolicyError::HardLinked);
        }
        validate_unix_owner_and_mode(
            nix::unistd::geteuid().as_raw(),
            metadata.uid(),
            metadata.mode(),
        )?;
    }

    if metadata.len() > MAX_POLICY_BYTES as u64 {
        return Err(PolicyError::TooLarge {
            maximum: MAX_POLICY_BYTES,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_owner_and_mode(
    expected_owner: u32,
    actual_owner: u32,
    raw_mode: u32,
) -> Result<(), PolicyError> {
    if actual_owner != expected_owner {
        return Err(PolicyError::WrongOwner {
            expected: expected_owner,
            actual: actual_owner,
        });
    }
    let mode = raw_mode & 0o777;
    if mode & 0o022 != 0 {
        return Err(PolicyError::UnsafeMode { mode });
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

    use super::{
        validate_unix_owner_and_mode, PolicyError, PolicyRollbackAuthorization, PolicyStore,
    };
    use crate::authorization::{ResolvedPrincipal, Role};

    #[test]
    fn mismatched_owner_is_rejected_deterministically() {
        let error =
            validate_unix_owner_and_mode(1000, 1001, 0o600).expect_err("mismatched uid must fail");

        assert!(matches!(
            error,
            PolicyError::WrongOwner {
                expected: 1000,
                actual: 1001
            }
        ));
    }

    #[test]
    fn reload_rejects_generation_rollback_and_keeps_the_active_snapshot() {
        let dir = TempDir::new().expect("tempdir");
        let current = dir.path().join("current.toml");
        let rollback = dir.path().join("rollback.toml");
        write_policy(&current, 2, "enforce");
        write_policy(&rollback, 1, "disabled");
        let store = PolicyStore::load(&current).expect("load current policy");
        let original_digest = store.snapshot().digest;
        let actor = ResolvedPrincipal::new("host-administrator", Role::Administrator);

        let error = store
            .reload(&rollback, &actor)
            .expect_err("rollback must fail");

        assert!(matches!(
            error,
            PolicyError::Rollback {
                current: 2,
                candidate: 1
            }
        ));
        let retained = store.snapshot();
        assert_eq!(retained.generation, 2);
        assert_eq!(retained.digest, original_digest);
        assert_eq!(
            retained.document.mode,
            super::super::AuthorizationMode::Enforce
        );
    }

    #[test]
    fn reload_rejects_a_resolved_non_administrator() {
        let dir = TempDir::new().expect("tempdir");
        let current = dir.path().join("current.toml");
        let candidate = dir.path().join("candidate.toml");
        write_policy(&current, 1, "enforce");
        write_policy(&candidate, 2, "disabled");
        let store = PolicyStore::load(&current).expect("load current policy");
        let actor = ResolvedPrincipal::new("developer", Role::Developer);

        let error = store
            .reload(&candidate, &actor)
            .expect_err("non-administrator reload must fail");

        assert!(matches!(error, PolicyError::UnauthorizedReload));
        assert_eq!(store.snapshot().generation, 1);
    }

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
        let actor = ResolvedPrincipal::new("host-administrator", Role::Administrator);
        let authorization = PolicyRollbackAuthorization::new(actor);

        let installed = store
            .reload_authorized_rollback(&rollback, &authorization)
            .expect("authorized rollback");

        assert_eq!(installed.generation, 1);
        assert_eq!(store.snapshot().generation, 1);
    }

    fn write_policy(path: &std::path::Path, generation: u64, mode: &str) {
        fs::write(
            path,
            format!("schema_version = 1\ngeneration = {generation}\nmode = \"{mode}\"\n"),
        )
        .expect("write policy");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("policy mode");
    }
}
