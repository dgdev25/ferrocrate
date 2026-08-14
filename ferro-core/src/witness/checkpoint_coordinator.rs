use super::{
    checkpoint::MAX_CHECKPOINT_BYTES, Checkpoint, CheckpointError, WitnessJournal, WitnessRecord,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "linux"))]
use std::fs::OpenOptions;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct CheckpointCoordinator {
    path: PathBuf,
    max_age: Duration,
    grace: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicationOutcome {
    Bound(Checkpoint),
    PendingBinding(PendingBinding),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingBinding {
    checkpoint: Checkpoint,
    event_id: [u8; 16],
    expected_epoch: u64,
    expected_sequence: u64,
}
impl PendingBinding {
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
}

impl CheckpointCoordinator {
    pub fn new(path: impl AsRef<Path>, max_age: Duration, grace: Duration) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            max_age,
            grace,
        }
    }
    pub fn capture_publish_bind<F>(
        &self,
        journal: &WitnessJournal,
        now_secs: u64,
        key: &SigningKey,
        predecessor: Option<&Checkpoint>,
        record: F,
    ) -> Result<PublicationOutcome, CheckpointError>
    where
        F: FnOnce(&Checkpoint) -> WitnessRecord,
    {
        let head = journal.flushed_head()?.into();
        let cp = match predecessor {
            Some(previous) => Checkpoint::sign_after(head, now_secs, previous, key)?,
            None => Checkpoint::sign(head, now_secs, key, super::CheckpointKind::Periodic)?,
        };
        self.publish(&cp)?;
        let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
        let prepared = prepare_binding(&cp, record(&cp), digest)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => PublicationOutcome::Bound(cp),
                Err(_) => PublicationOutcome::PendingBinding(pending(cp, &prepared)?),
            },
        )
    }
    pub fn capture_reset_publish_bind<F>(
        &self,
        journal: &WitnessJournal,
        now_secs: u64,
        new_key: &SigningKey,
        predecessor: &Checkpoint,
        record: F,
    ) -> Result<PublicationOutcome, CheckpointError>
    where
        F: FnOnce(&Checkpoint) -> WitnessRecord,
    {
        let current = journal.flushed_head()?;
        if current.epoch != predecessor.head.epoch {
            return Err(CheckpointError::Rollback);
        }
        let next_epoch = current
            .epoch
            .checked_add(1)
            .ok_or(CheckpointError::Rollback)?;
        let head = super::FlushedHead::new(
            current.journal_id,
            next_epoch,
            current.sequence,
            current.hash,
        );
        let cp = Checkpoint::trust_reset_after(head, now_secs, predecessor, new_key)?;
        self.publish(&cp)?;
        if journal.advance_epoch(current.epoch).is_err() {
            let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
            let prepared = prepare_binding(&cp, record(&cp), digest)?;
            return Ok(PublicationOutcome::PendingBinding(pending(cp, &prepared)?));
        }
        let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
        let prepared = prepare_binding(&cp, record(&cp), digest)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => PublicationOutcome::Bound(cp),
                Err(_) => PublicationOutcome::PendingBinding(pending(cp, &prepared)?),
            },
        )
    }
    pub fn capture_rotate_publish_bind<F>(
        &self,
        journal: &WitnessJournal,
        now_secs: u64,
        old_key: &SigningKey,
        new_key: &SigningKey,
        predecessor: &Checkpoint,
        record: F,
    ) -> Result<PublicationOutcome, CheckpointError>
    where
        F: FnOnce(&Checkpoint) -> WitnessRecord,
    {
        let head = journal.flushed_head()?.into();
        let cp = Checkpoint::rotate_after(head, now_secs, predecessor, old_key, new_key)?;
        self.publish(&cp)?;
        let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
        let prepared = prepare_binding(&cp, record(&cp), digest)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => PublicationOutcome::Bound(cp),
                Err(_) => PublicationOutcome::PendingBinding(pending(cp, &prepared)?),
            },
        )
    }
    pub(crate) fn publish(&self, checkpoint: &Checkpoint) -> Result<(), CheckpointError> {
        let bytes = checkpoint.encode();
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::InvalidArtifact);
        }
        let parent = self.path.parent().ok_or(CheckpointError::InvalidArtifact)?;
        validate_publication_dir(parent)?;
        #[cfg(target_os = "linux")]
        return publish_at(
            parent,
            self.path
                .file_name()
                .ok_or(CheckpointError::InvalidArtifact)?,
            &bytes,
        );
        #[cfg(not(target_os = "linux"))]
        {
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
    }
    pub fn reconcile_binding(
        &self,
        journal: &WitnessJournal,
        pending: &PendingBinding,
        record: WitnessRecord,
    ) -> Result<(), CheckpointError> {
        let current = journal.flushed_head()?;
        let checkpoint = &pending.checkpoint;
        if checkpoint.kind == super::CheckpointKind::TrustReset
            && current.epoch.checked_add(1) == Some(checkpoint.head.epoch)
        {
            journal.advance_epoch(current.epoch)?;
        }
        let digest: [u8; 32] = Sha256::digest(checkpoint.encode()).into();
        let prepared = prepare_binding(checkpoint, record, digest)?;
        if prepared.event_id != pending.event_id
            || prepared.epoch != pending.expected_epoch
            || prepared.sequence != pending.expected_sequence
        {
            return Err(CheckpointError::Rollback);
        }
        journal.append_checkpoint_publication(digest, prepared)?;
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

fn prepare_binding(
    checkpoint: &Checkpoint,
    mut record: WitnessRecord,
    digest: [u8; 32],
) -> Result<WitnessRecord, CheckpointError> {
    let sequence = checkpoint
        .head
        .sequence
        .checked_add(1)
        .ok_or(CheckpointError::Rollback)?;
    let identity: [u8; 32] = Sha256::digest(
        [
            b"FERROCRATE-CHECKPOINT-BINDING-V2".as_slice(),
            digest.as_slice(),
        ]
        .concat(),
    )
    .into();
    record.event_id.copy_from_slice(&identity[..16]);
    record.request_id.copy_from_slice(&identity[16..]);
    record.epoch = checkpoint.head.epoch;
    record.sequence = sequence;
    record.previous_hash = checkpoint.head.hash;
    Ok(record)
}
fn pending(
    checkpoint: Checkpoint,
    record: &WitnessRecord,
) -> Result<PendingBinding, CheckpointError> {
    Ok(PendingBinding {
        checkpoint,
        event_id: record.event_id,
        expected_epoch: record.epoch,
        expected_sequence: record.sequence,
    })
}

#[cfg(target_os = "linux")]
fn publish_at(
    parent: &Path,
    target: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<(), CheckpointError> {
    use nix::{
        fcntl::{open, openat, openat2, renameat, OFlag, OpenHow, ResolveFlag},
        sys::stat::Mode,
        unistd::{unlinkat, UnlinkatFlags},
    };
    let relative = parent
        .strip_prefix("/")
        .map_err(|_| CheckpointError::InvalidArtifact)?;
    let anchor = open(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
    let dir = openat2(&anchor, relative, how).map_err(std::io::Error::from)?;
    let tmp = format!(".checkpoint-{}.tmp", rand::random::<u64>());
    let fd = openat(
        &dir,
        tmp.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(std::io::Error::from)?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Err(error) = renameat(&dir, tmp.as_str(), &dir, target) {
        let _ = unlinkat(&dir, tmp.as_str(), UnlinkatFlags::NoRemoveDir);
        return Err(std::io::Error::from(error).into());
    }
    File::from(dir).sync_all()?;
    Ok(())
}

fn validate_publication_dir(path: &Path) -> Result<(), CheckpointError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CheckpointError::InvalidArtifact);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(CheckpointError::InvalidArtifact);
        }
    }
    Ok(())
}
