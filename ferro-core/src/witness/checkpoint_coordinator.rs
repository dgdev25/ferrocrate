use super::{
    checkpoint::MAX_CHECKPOINT_BYTES, Checkpoint, CheckpointError, CheckpointKind, WitnessJournal,
    WitnessRecord,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct CheckpointCoordinator {
    path: PathBuf,
    max_age: Duration,
    grace: Duration,
}

impl CheckpointCoordinator {
    pub fn new(path: impl AsRef<Path>, max_age: Duration, grace: Duration) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            max_age,
            grace,
        }
    }
    pub fn capture_and_publish(
        &self,
        journal: &WitnessJournal,
        now_secs: u64,
        key: &SigningKey,
    ) -> Result<Checkpoint, CheckpointError> {
        let cp = Checkpoint::sign(
            journal.flushed_head()?.into(),
            now_secs,
            key,
            CheckpointKind::Periodic,
        )?;
        self.publish(&cp)?;
        Ok(cp)
    }
    pub fn publish(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        let bytes = checkpoint.encode();
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::InvalidArtifact);
        }
        let parent = self.path.parent().ok_or(CheckpointError::InvalidArtifact)?;
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            File::open(parent.parent().unwrap_or(parent))?.sync_all()?;
        }
        let tmp = parent.join(format!(".checkpoint-{}.tmp", rand::random::<u64>()));
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        if let Err(error) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(error.into());
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub fn publish_and_bind(
        &self,
        journal: &WitnessJournal,
        checkpoint: &Checkpoint,
        record: WitnessRecord,
    ) -> Result<(), CheckpointError> {
        self.publish(checkpoint)?;
        let digest: [u8; 32] = Sha256::digest(checkpoint.encode()).into();
        journal.append_checkpoint_publication(digest, record)?;
        Ok(())
    }
    pub fn allows_user_mutation(&self, newest_checkpoint_secs: u64, now_secs: u64) -> bool {
        now_secs >= newest_checkpoint_secs
            && now_secs - newest_checkpoint_secs
                <= self.max_age.saturating_add(self.grace).as_secs()
    }
    pub const fn allows_reserved_cleanup(&self) -> bool {
        true
    }
}
