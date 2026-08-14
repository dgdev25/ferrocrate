use super::{
    checkpoint::MAX_CHECKPOINT_BYTES, decode_record, encode_record, Checkpoint, CheckpointError,
    JournalError, WitnessJournal, WitnessRecord,
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
    record_bytes: Vec<u8>,
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
        let pending = pending(cp.clone(), &prepared)?;
        self.persist_pending(&pending)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => {
                    self.clear_pending()?;
                    PublicationOutcome::Bound(cp)
                }
                Err(JournalError::Indeterminate { .. }) => {
                    PublicationOutcome::PendingBinding(pending)
                }
                Err(error) => return Err(error.into()),
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
            let pending = pending(cp, &prepared)?;
            self.persist_pending(&pending)?;
            return Ok(PublicationOutcome::PendingBinding(pending));
        }
        let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
        let prepared = prepare_binding(&cp, record(&cp), digest)?;
        let pending = pending(cp.clone(), &prepared)?;
        self.persist_pending(&pending)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => {
                    self.clear_pending()?;
                    PublicationOutcome::Bound(cp)
                }
                Err(JournalError::Indeterminate { .. }) => {
                    PublicationOutcome::PendingBinding(pending)
                }
                Err(error) => return Err(error.into()),
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
        let pending = pending(cp.clone(), &prepared)?;
        self.persist_pending(&pending)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => {
                    self.clear_pending()?;
                    PublicationOutcome::Bound(cp)
                }
                Err(JournalError::Indeterminate { .. }) => {
                    PublicationOutcome::PendingBinding(pending)
                }
                Err(error) => return Err(error.into()),
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
        if current.journal_id != checkpoint.head.journal_id {
            return Err(CheckpointError::Untrusted);
        }
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
        self.clear_pending()?;
        Ok(())
    }
    pub fn pending_binding(&self) -> Result<Option<PendingBinding>, CheckpointError> {
        let path = self.pending_path();
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let pending = decode_pending(&bytes)?;
        let artifact = fs::read(&self.path)?;
        if artifact != pending.checkpoint.encode() {
            return Err(CheckpointError::Rollback);
        }
        Ok(Some(pending))
    }
    pub fn reconcile_pending(&self, journal: &WitnessJournal) -> Result<(), CheckpointError> {
        let pending = self
            .pending_binding()?
            .ok_or(CheckpointError::InvalidArtifact)?;
        let decoded =
            decode_record(&pending.record_bytes).map_err(|_| CheckpointError::InvalidArtifact)?;
        let record = restore_record(decoded.record());
        self.reconcile_binding(journal, &pending, record)
    }
    fn pending_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".pending");
        PathBuf::from(name)
    }
    fn persist_pending(&self, pending: &PendingBinding) -> Result<(), CheckpointError> {
        atomic_write(&self.pending_path(), &encode_pending(pending))
    }
    fn clear_pending(&self) -> Result<(), CheckpointError> {
        match fs::remove_file(self.pending_path()) {
            Ok(()) => File::open(self.path.parent().ok_or(CheckpointError::InvalidArtifact)?)?
                .sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
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
    let journal_id = checkpoint.head.journal_id;
    Ok(PendingBinding {
        checkpoint,
        event_id: record.event_id,
        expected_epoch: record.epoch,
        expected_sequence: record.sequence,
        record_bytes: encode_record(journal_id, record)
            .map_err(|_| CheckpointError::InvalidArtifact)?
            .as_ref()
            .to_vec(),
    })
}

fn encode_pending(pending: &PendingBinding) -> Vec<u8> {
    let checkpoint = pending.checkpoint.encode();
    let mut out = b"FPEND001".to_vec();
    out.extend_from_slice(&(checkpoint.len() as u32).to_be_bytes());
    out.extend_from_slice(&(pending.record_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&checkpoint);
    out.extend_from_slice(&pending.record_bytes);
    let digest: [u8; 32] = Sha256::digest(&out).into();
    out.extend_from_slice(&digest);
    out
}
fn decode_pending(bytes: &[u8]) -> Result<PendingBinding, CheckpointError> {
    if bytes.len() < 48
        || &bytes[..8] != b"FPEND001"
        || bytes.len() > MAX_CHECKPOINT_BYTES + super::MAX_RECORD_BYTES + 48
    {
        return Err(CheckpointError::InvalidArtifact);
    }
    let cp_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let record_len = u32::from_be_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let end = 16usize
        .checked_add(cp_len)
        .and_then(|v| v.checked_add(record_len))
        .ok_or(CheckpointError::InvalidArtifact)?;
    if end + 32 != bytes.len() || Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
        return Err(CheckpointError::InvalidArtifact);
    }
    let checkpoint = Checkpoint::decode(&bytes[16..16 + cp_len])?;
    let record_bytes = bytes[16 + cp_len..end].to_vec();
    let decoded = decode_record(&record_bytes).map_err(|_| CheckpointError::InvalidArtifact)?;
    let record = restore_record(decoded.record());
    let expected = pending(checkpoint, &record)?;
    if expected.record_bytes != record_bytes {
        return Err(CheckpointError::InvalidArtifact);
    }
    Ok(expected)
}

fn restore_record(record: &super::ParsedRecord) -> WitnessRecord {
    WitnessRecord {
        epoch: record.epoch,
        sequence: record.sequence,
        previous_hash: record.previous_hash,
        event_id: record.event_id,
        request_id: record.request_id,
        runtime_instance_id: record.runtime_instance_id,
        boot_id: record.boot_id,
        principal: super::PrincipalSummary(record.principal_digest),
        invocation: record.invocation,
        action: record.action,
        resource_kind: record.resource_kind,
        resource: super::ResourceSummary(record.resource_digest),
        resource_generation: record.resource_generation,
        policy_version: record.policy_version,
        policy_digest: record.policy_digest,
        decision_id: record.decision_id,
        rule: record.rule,
        decision: record.decision,
        reason: record.reason,
        request_digest: record.request_digest,
        result_digest: record.result_digest,
        wall_time_ns: record.wall_time_ns,
        monotonic_ns: record.monotonic_ns,
        stage: record.stage,
        outcome: record.outcome,
        recovery_link: record.recovery_link,
        path_class: record.path_class,
        device_class: record.device_class,
        correlation_digest: record.correlation_digest,
    }
}
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CheckpointError> {
    let parent = path.parent().ok_or(CheckpointError::InvalidArtifact)?;
    validate_publication_dir(parent)?;
    let tmp = parent.join(format!(".pending-{}.tmp", rand::random::<u64>()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
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
