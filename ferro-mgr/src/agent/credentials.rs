use std::{fs::{self, OpenOptions}, io::Write, os::unix::{fs::{MetadataExt, OpenOptionsExt}}, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("credential path is not a secure regular file")]
    InsecurePath,
    #[error("credential material is truncated")]
    Truncated,
    #[error("credential entropy generation failed")]
    Entropy,
}

pub struct CredentialStore { path: PathBuf }

impl CredentialStore {
    pub fn new(path: impl Into<PathBuf>) -> Self { Self { path: path.into() } }

    pub fn load_or_generate(&self) -> Result<Vec<u8>, CredentialError> {
        if self.path.exists() {
            self.validate_metadata()?;
            let bytes = fs::read(&self.path)?;
            if bytes.len() != 32 { return Err(CredentialError::Truncated); }
            return Ok(bytes);
        }
        let parent = self.path.parent().ok_or(CredentialError::InsecurePath)?;
        fs::create_dir_all(parent)?;
        let mut secret = vec![0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| CredentialError::Entropy)?;
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&self.path)?;
        file.write_all(&secret)?;
        file.sync_all()?;
        self.validate_metadata()?;
        Ok(secret)
    }

    fn validate_metadata(&self) -> Result<(), CredentialError> {
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file() || metadata.mode() & 0o077 != 0 || metadata.uid() != nix::unistd::geteuid().as_raw() { return Err(CredentialError::InsecurePath); }
        Ok(())
    }
}
