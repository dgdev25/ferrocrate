//! Deterministic rolling-update planning.
//!
//! This module produces an ordered, side-effect-free plan. Applying a plan
//! still belongs to the authorized controller/agent reconciliation path.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RolloutPolicy {
    /// Maximum number of replacements started in one step.
    pub max_surge: usize,
    /// Maximum number of obsolete instances stopped in one step.
    pub max_unavailable: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutStep {
    pub start: Vec<String>,
    pub stop: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutCheckpoint {
    pub generation: u64,
    pub step: usize,
    pub plan_digest: [u8; 32],
    pub completed_start: Vec<String>,
    pub completed_stop: Vec<String>,
}

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint is invalid")]
    Invalid,
    #[error("checkpoint exceeds the size limit")]
    Oversized,
    #[error("checkpoint serialization failed: {0}")]
    Codec(#[from] serde_json::Error),
}

pub struct CheckpointStore {
    path: PathBuf,
}

impl CheckpointStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn load(&self) -> Result<Option<RolloutCheckpoint>, CheckpointError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(CheckpointError::Invalid);
        }
        let bytes = fs::read(&self.path)?;
        if bytes.len() > 256 * 1024 {
            return Err(CheckpointError::Oversized);
        }
        let checkpoint: RolloutCheckpoint = serde_json::from_slice(&bytes)?;
        validate_checkpoint(&checkpoint)?;
        Ok(Some(checkpoint))
    }

    pub fn save(&self, checkpoint: &RolloutCheckpoint) -> Result<(), CheckpointError> {
        validate_checkpoint(checkpoint)?;
        let bytes = serde_json::to_vec(checkpoint)?;
        if bytes.len() > 256 * 1024 {
            return Err(CheckpointError::Oversized);
        }
        let parent = self.path.parent().ok_or(CheckpointError::Invalid)?;
        fs::create_dir_all(parent)?;
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
        sync_parent(parent)?;
        Ok(())
    }
}

fn validate_checkpoint(checkpoint: &RolloutCheckpoint) -> Result<(), CheckpointError> {
    if checkpoint.completed_start.len() > 65_536 || checkpoint.completed_stop.len() > 65_536 {
        return Err(CheckpointError::Invalid);
    }
    if checkpoint
        .completed_start
        .iter()
        .chain(checkpoint.completed_stop.iter())
        .any(|id| id.trim().is_empty())
    {
        return Err(CheckpointError::Invalid);
    }
    Ok(())
}

fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    OpenOptions::new().read(true).open(parent)?.sync_all()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RolloutError {
    #[error("instance id must not be empty")]
    EmptyId,
    #[error("instance ids must be unique")]
    DuplicateId,
    #[error("max_surge must be non-zero when starting replacements")]
    ZeroSurge,
    #[error("max_unavailable must be non-zero when stopping without a replacement")]
    ZeroUnavailable,
}

/// Build a stable replacement plan from current and desired instance IDs.
///
/// Replacement steps start new instances before stopping their old peers. The
/// planner batches starts and stops according to the supplied policy and never
/// mutates the input vectors. IDs are sorted, making output independent of
/// discovery order.
pub fn plan(
    current: &[String],
    desired: &[String],
    policy: RolloutPolicy,
) -> Result<Vec<RolloutStep>, RolloutError> {
    let current = unique_sorted(current)?;
    let desired = unique_sorted(desired)?;
    let current_set: BTreeSet<_> = current.iter().collect();
    let desired_set: BTreeSet<_> = desired.iter().collect();
    let mut starts: Vec<String> = desired_set
        .difference(&current_set)
        .map(|id| (*id).clone())
        .collect();
    let mut stops: Vec<String> = current_set
        .difference(&desired_set)
        .map(|id| (*id).clone())
        .collect();

    if starts.is_empty() && stops.is_empty() {
        return Ok(Vec::new());
    }
    if !starts.is_empty() && policy.max_surge == 0 {
        return Err(RolloutError::ZeroSurge);
    }
    if starts.is_empty() && !stops.is_empty() && policy.max_unavailable == 0 {
        return Err(RolloutError::ZeroUnavailable);
    }

    let mut steps = Vec::new();
    while !starts.is_empty() || !stops.is_empty() {
        let start_count = if starts.is_empty() {
            0
        } else {
            policy.max_surge.min(starts.len())
        };
        let stop_count = if stops.is_empty() {
            0
        } else if start_count > 0 {
            // A replacement can stop its old peer after the new instances have
            // started, even when max_unavailable is zero.
            policy.max_unavailable.max(1).min(stops.len())
        } else {
            policy.max_unavailable.min(stops.len())
        };
        let step_start = starts.drain(..start_count).collect();
        let step_stop = stops.drain(..stop_count).collect();
        steps.push(RolloutStep {
            start: step_start,
            stop: step_stop,
        });
    }
    Ok(steps)
}

fn unique_sorted(ids: &[String]) -> Result<Vec<String>, RolloutError> {
    let mut result = ids.to_vec();
    if result.iter().any(|id| id.trim().is_empty()) {
        return Err(RolloutError::EmptyId);
    }
    result.sort();
    if result.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RolloutError::DuplicateId);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn replacements_start_before_stopping_and_are_stable() {
        let policy = RolloutPolicy {
            max_surge: 1,
            max_unavailable: 0,
        };
        let forward = plan(&ids(&["old-b", "old-a"]), &ids(&["new-b", "new-a"]), policy).unwrap();
        let reverse = plan(&ids(&["old-a", "old-b"]), &ids(&["new-a", "new-b"]), policy).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward[0].start, ids(&["new-a"]));
        assert_eq!(forward[0].stop, ids(&["old-a"]));
        assert_eq!(forward[1].start, ids(&["new-b"]));
    }

    #[test]
    fn scale_down_requires_unavailability_budget() {
        let error = plan(
            &ids(&["a", "b"]),
            &ids(&["a"]),
            RolloutPolicy {
                max_surge: 1,
                max_unavailable: 0,
            },
        )
        .unwrap_err();
        assert_eq!(error, RolloutError::ZeroUnavailable);
    }

    #[test]
    fn duplicate_and_empty_ids_fail_closed() {
        assert_eq!(
            plan(
                &ids(&["a", "a"]),
                &[],
                RolloutPolicy {
                    max_surge: 1,
                    max_unavailable: 1
                }
            ),
            Err(RolloutError::DuplicateId)
        );
        assert_eq!(
            plan(
                &ids(&["a"]),
                &ids(&[""]),
                RolloutPolicy {
                    max_surge: 1,
                    max_unavailable: 1
                }
            ),
            Err(RolloutError::EmptyId)
        );
    }

    #[test]
    fn no_change_is_a_noop() {
        assert!(plan(
            &ids(&["a"]),
            &ids(&["a"]),
            RolloutPolicy {
                max_surge: 0,
                max_unavailable: 0
            }
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn checkpoint_store_round_trips_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let store = CheckpointStore::new(directory.path().join("rollout.json"));
        let checkpoint = RolloutCheckpoint {
            generation: 4,
            step: 2,
            plan_digest: [7; 32],
            completed_start: ids(&["new-a"]),
            completed_stop: ids(&["old-a"]),
        };
        store.save(&checkpoint).unwrap();
        assert_eq!(store.load().unwrap(), Some(checkpoint));
        let mode = std::fs::metadata(directory.path().join("rollout.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn checkpoint_store_rejects_symlinks_and_empty_ids() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.json");
        let link = directory.path().join("rollout.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            CheckpointStore::new(link).load(),
            Err(CheckpointError::Invalid)
        ));

        let invalid = RolloutCheckpoint {
            generation: 1,
            step: 0,
            plan_digest: [0; 32],
            completed_start: vec![String::new()],
            completed_stop: Vec::new(),
        };
        assert!(matches!(
            CheckpointStore::new(directory.path().join("invalid.json")).save(&invalid),
            Err(CheckpointError::Invalid)
        ));
    }
}
