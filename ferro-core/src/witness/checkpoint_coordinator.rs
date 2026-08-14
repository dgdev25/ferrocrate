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
    io::{Read, Write},
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
    state: PendingState,
    recoverability: Recoverability,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingState {
    Prepared,
    Published,
    Bound,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recoverability {
    Retryable,
    Indeterminate,
}
impl PendingBinding {
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
    pub fn state(&self) -> PendingState {
        self.state
    }
    pub fn recoverability(&self) -> Recoverability {
        self.recoverability
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
        self.preflight()?;
        let head = journal.flushed_head()?.into();
        let cp = match predecessor {
            Some(previous) => Checkpoint::sign_after(head, now_secs, previous, key)?,
            None => Checkpoint::sign(head, now_secs, key, super::CheckpointKind::Periodic)?,
        };
        let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
        let prepared = prepare_binding(&cp, record(&cp), digest)?;
        let mut pending = pending(cp.clone(), &prepared)?;
        self.persist_pending(&pending)?;
        self.publish(&cp)?;
        pending.state = PendingState::Published;
        self.persist_pending_replace(&pending)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => {
                    pending.state = PendingState::Bound;
                    self.persist_pending_replace(&pending)?;
                    self.clear_pending()?;
                    PublicationOutcome::Bound(cp)
                }
                Err(JournalError::Indeterminate { .. }) => {
                    pending.recoverability = Recoverability::Indeterminate;
                    self.persist_pending_replace(&pending)?;
                    PublicationOutcome::PendingBinding(pending)
                }
                Err(error) => {
                    if nonretryable(&error) {
                        self.clear_pending()?;
                    }
                    return Err(error.into());
                }
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
        self.preflight()?;
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
        let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
        let prepared = prepare_binding(&cp, record(&cp), digest)?;
        let mut pending = pending(cp.clone(), &prepared)?;
        self.persist_pending(&pending)?;
        self.publish(&cp)?;
        pending.state = PendingState::Published;
        self.persist_pending_replace(&pending)?;
        journal.advance_epoch(current.epoch)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => {
                    pending.state = PendingState::Bound;
                    self.persist_pending_replace(&pending)?;
                    self.clear_pending()?;
                    PublicationOutcome::Bound(cp)
                }
                Err(JournalError::Indeterminate { .. }) => {
                    pending.recoverability = Recoverability::Indeterminate;
                    self.persist_pending_replace(&pending)?;
                    PublicationOutcome::PendingBinding(pending)
                }
                Err(error) => {
                    if nonretryable(&error) {
                        self.clear_pending()?;
                    }
                    return Err(error.into());
                }
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
        self.preflight()?;
        let head = journal.flushed_head()?.into();
        let cp = Checkpoint::rotate_after(head, now_secs, predecessor, old_key, new_key)?;
        let digest: [u8; 32] = Sha256::digest(cp.encode()).into();
        let prepared = prepare_binding(&cp, record(&cp), digest)?;
        let mut pending = pending(cp.clone(), &prepared)?;
        self.persist_pending(&pending)?;
        self.publish(&cp)?;
        pending.state = PendingState::Published;
        self.persist_pending_replace(&pending)?;
        Ok(
            match journal.append_checkpoint_publication(digest, prepared.clone()) {
                Ok(()) => {
                    pending.state = PendingState::Bound;
                    self.persist_pending_replace(&pending)?;
                    self.clear_pending()?;
                    PublicationOutcome::Bound(cp)
                }
                Err(JournalError::Indeterminate { .. }) => {
                    pending.recoverability = Recoverability::Indeterminate;
                    self.persist_pending_replace(&pending)?;
                    PublicationOutcome::PendingBinding(pending)
                }
                Err(error) => {
                    if nonretryable(&error) {
                        self.clear_pending()?;
                    }
                    return Err(error.into());
                }
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
        let mut bound = pending.clone();
        bound.state = PendingState::Bound;
        self.persist_pending_replace(&bound)?;
        self.clear_pending()?;
        Ok(())
    }
    pub fn pending_binding(&self) -> Result<Option<PendingBinding>, CheckpointError> {
        let path = self.pending_path();
        let bytes = match secure_read(&path, MAX_CHECKPOINT_BYTES + super::MAX_RECORD_BYTES + 50)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let pending = decode_pending(&bytes)?;
        match secure_read(&self.path, MAX_CHECKPOINT_BYTES)? {
            Some(artifact) if artifact == pending.checkpoint.encode() => {}
            None if pending.state == PendingState::Prepared => {}
            _ => return Err(CheckpointError::Rollback),
        }
        Ok(Some(pending))
    }
    pub fn reconcile_pending(&self, journal: &WitnessJournal) -> Result<(), CheckpointError> {
        let mut pending = self
            .pending_binding()?
            .ok_or(CheckpointError::InvalidArtifact)?;
        if pending.state == PendingState::Prepared {
            self.publish(&pending.checkpoint)?;
            pending.state = PendingState::Published;
            self.persist_pending_replace(&pending)?;
        }
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
        secure_write(&self.pending_path(), &encode_pending(pending), false)
    }
    fn persist_pending_replace(&self, pending: &PendingBinding) -> Result<(), CheckpointError> {
        secure_write(&self.pending_path(), &encode_pending(pending), true)
    }
    fn preflight(&self) -> Result<(), CheckpointError> {
        if self.pending_binding()?.is_some() {
            Err(CheckpointError::PendingExists)
        } else {
            Ok(())
        }
    }
    fn clear_pending(&self) -> Result<(), CheckpointError> {
        secure_unlink(&self.pending_path())
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

fn nonretryable(error: &JournalError) -> bool {
    matches!(
        error,
        JournalError::Disabled
            | JournalError::JournalMismatch
            | JournalError::UnsupportedVersion
            | JournalError::ProofMismatch
            | JournalError::BindingMismatch
            | JournalError::InvalidStage
            | JournalError::AlreadyComplete
            | JournalError::NotPending
    )
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
        state: PendingState::Prepared,
        recoverability: Recoverability::Retryable,
    })
}

fn encode_pending(pending: &PendingBinding) -> Vec<u8> {
    let checkpoint = pending.checkpoint.encode();
    let mut out = b"FPEND002".to_vec();
    out.push(match pending.state {
        PendingState::Prepared => 1,
        PendingState::Published => 2,
        PendingState::Bound => 3,
    });
    out.push(match pending.recoverability {
        Recoverability::Retryable => 1,
        Recoverability::Indeterminate => 2,
    });
    out.extend_from_slice(&(checkpoint.len() as u32).to_be_bytes());
    out.extend_from_slice(&(pending.record_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&checkpoint);
    out.extend_from_slice(&pending.record_bytes);
    let digest: [u8; 32] = Sha256::digest(&out).into();
    out.extend_from_slice(&digest);
    out
}
fn decode_pending(bytes: &[u8]) -> Result<PendingBinding, CheckpointError> {
    if bytes.len() < 50
        || &bytes[..8] != b"FPEND002"
        || bytes.len() > MAX_CHECKPOINT_BYTES + super::MAX_RECORD_BYTES + 50
    {
        return Err(CheckpointError::InvalidArtifact);
    }
    let state = match bytes[8] {
        1 => PendingState::Prepared,
        2 => PendingState::Published,
        3 => PendingState::Bound,
        _ => return Err(CheckpointError::InvalidArtifact),
    };
    let recoverability = match bytes[9] {
        1 => Recoverability::Retryable,
        2 => Recoverability::Indeterminate,
        _ => return Err(CheckpointError::InvalidArtifact),
    };
    let cp_len = u32::from_be_bytes(bytes[10..14].try_into().unwrap()) as usize;
    let record_len = u32::from_be_bytes(bytes[14..18].try_into().unwrap()) as usize;
    let end = 18usize
        .checked_add(cp_len)
        .and_then(|v| v.checked_add(record_len))
        .ok_or(CheckpointError::InvalidArtifact)?;
    if end + 32 != bytes.len() || Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
        return Err(CheckpointError::InvalidArtifact);
    }
    let checkpoint = Checkpoint::decode(&bytes[18..18 + cp_len])?;
    let record_bytes = bytes[18 + cp_len..end].to_vec();
    let decoded = decode_record(&record_bytes).map_err(|_| CheckpointError::InvalidArtifact)?;
    let record = restore_record(decoded.record());
    let mut expected = pending(checkpoint, &record)?;
    expected.state = state;
    expected.recoverability = recoverability;
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
#[cfg(not(target_os = "linux"))]
fn secure_write(path: &Path, bytes: &[u8], replace: bool) -> Result<(), CheckpointError> {
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
    if !replace && path.exists() {
        return Err(CheckpointError::PendingExists);
    }
    fs::rename(&tmp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn secure_read(path: &Path, bound: usize) -> Result<Option<Vec<u8>>, CheckpointError> {
    let mut file = match fs::OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take((bound + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(CheckpointError::InvalidArtifact);
    }
    Ok(Some(bytes))
}
#[cfg(not(target_os = "linux"))]
fn secure_unlink(path: &Path) -> Result<(), CheckpointError> {
    match fs::remove_file(path) {
        Ok(()) => {
            File::open(path.parent().ok_or(CheckpointError::InvalidArtifact)?)?.sync_all()?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(target_os = "linux")]
fn secure_dir(path: &Path) -> Result<std::os::fd::OwnedFd, CheckpointError> {
    use nix::fcntl::{open, openat2, OFlag, OpenHow, ResolveFlag};
    use nix::sys::stat::Mode;
    validate_publication_dir(path)?;
    let anchor = open(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| CheckpointError::InvalidArtifact)?;
    let how = OpenHow::new()
        .flags(OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
        .resolve(ResolveFlag::RESOLVE_BENEATH | ResolveFlag::RESOLVE_NO_SYMLINKS);
    openat2(&anchor, relative, how).map_err(|e| std::io::Error::from(e).into())
}
#[cfg(target_os = "linux")]
fn secure_read(path: &Path, bound: usize) -> Result<Option<Vec<u8>>, CheckpointError> {
    use nix::fcntl::{openat, OFlag};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::MetadataExt;
    let parent = path.parent().ok_or(CheckpointError::InvalidArtifact)?;
    let dir = secure_dir(parent)?;
    let fd = match openat(
        &dir,
        path.file_name().ok_or(CheckpointError::InvalidArtifact)?,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(e) => return Err(std::io::Error::from(e).into()),
    };
    let mut file = File::from(fd);
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.mode() & 0o777 != 0o600
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.nlink() != 1
    {
        return Err(CheckpointError::InvalidArtifact);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((bound + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > bound {
        return Err(CheckpointError::InvalidArtifact);
    }
    Ok(Some(bytes))
}
#[cfg(target_os = "linux")]
fn secure_write(path: &Path, bytes: &[u8], replace: bool) -> Result<(), CheckpointError> {
    use nix::fcntl::{openat, renameat, renameat2, OFlag, RenameFlags};
    use nix::sys::stat::Mode;
    use nix::unistd::{unlinkat, UnlinkatFlags};
    let parent = path.parent().ok_or(CheckpointError::InvalidArtifact)?;
    let dir = secure_dir(parent)?;
    let tmp = format!(".pending-{}.tmp", rand::random::<u64>());
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
    let target = path.file_name().ok_or(CheckpointError::InvalidArtifact)?;
    let result = if replace {
        renameat(&dir, tmp.as_str(), &dir, target)
    } else {
        renameat2(
            &dir,
            tmp.as_str(),
            &dir,
            target,
            RenameFlags::RENAME_NOREPLACE,
        )
    };
    if let Err(error) = result {
        let _ = unlinkat(&dir, tmp.as_str(), UnlinkatFlags::NoRemoveDir);
        return if error == nix::errno::Errno::EEXIST {
            Err(CheckpointError::PendingExists)
        } else {
            Err(std::io::Error::from(error).into())
        };
    }
    File::from(dir).sync_all()?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn secure_unlink(path: &Path) -> Result<(), CheckpointError> {
    use nix::unistd::{unlinkat, UnlinkatFlags};
    let parent = path.parent().ok_or(CheckpointError::InvalidArtifact)?;
    let dir = secure_dir(parent)?;
    match unlinkat(
        &dir,
        path.file_name().ok_or(CheckpointError::InvalidArtifact)?,
        UnlinkatFlags::NoRemoveDir,
    ) {
        Ok(()) => File::from(dir).sync_all().map_err(Into::into),
        Err(nix::errno::Errno::ENOENT) => Ok(()),
        Err(e) => Err(std::io::Error::from(e).into()),
    }
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
