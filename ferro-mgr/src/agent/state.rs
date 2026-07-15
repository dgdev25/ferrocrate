use std::{fs::{self, OpenOptions}, io::Write, os::unix::fs::PermissionsExt, path::PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentState {
    pub cluster_epoch: u64,
    pub applied_revision: u64,
    pub overlays: Vec<String>,
    pub lease_expiry: i64,
}

impl Default for AgentState {
    fn default() -> Self { Self { cluster_epoch: 0, applied_revision: 0, overlays: Vec::new(), lease_expiry: 0 } }
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state file is invalid")]
    Invalid,
}

pub struct StateStore { path: PathBuf }

impl StateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self { Self { path: path.into() } }

    pub fn load(&self) -> Result<AgentState, StateError> {
        if !self.path.exists() { return Ok(AgentState::default()); }
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 { return Err(StateError::Invalid); }
        serde_json::from_slice(&fs::read(&self.path)?).map_err(|_| StateError::Invalid)
    }

    pub fn save(&self, state: &AgentState) -> Result<(), StateError> {
        let parent = self.path.parent().ok_or(StateError::Invalid)?;
        fs::create_dir_all(parent)?;
        let temporary = self.path.with_extension("tmp");
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&serde_json::to_vec(state).map_err(|_| StateError::Invalid)?)?;
        file.sync_all()?;
        fs::rename(temporary, &self.path)?;
        Ok(())
    }
}
