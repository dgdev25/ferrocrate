use super::{JournalError, JournalHead, KeyId, VerificationReport, WitnessJournal};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

const DOMAIN: &[u8] = b"FERROCRATE-CHECKPOINT-V1";
const MAGIC: &[u8; 8] = b"FCHKPT01";
const MAX_CHECKPOINT_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushedHead {
    pub journal_id: [u8; 16],
    pub epoch: u64,
    pub sequence: u64,
    pub hash: [u8; 32],
}
impl FlushedHead {
    pub const fn new(journal_id: [u8; 16], epoch: u64, sequence: u64, hash: [u8; 32]) -> Self {
        Self {
            journal_id,
            epoch,
            sequence,
            hash,
        }
    }
}
impl From<JournalHead> for FlushedHead {
    fn from(h: JournalHead) -> Self {
        Self::new(h.journal_id, h.epoch, h.sequence, h.hash)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CheckpointKind {
    Periodic = 1,
    Rotation = 2,
    TrustReset = 3,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub head: FlushedHead,
    pub created_at_secs: u64,
    pub kind: CheckpointKind,
    pub key_id: KeyId,
    pub public_key: [u8; 32],
    pub previous_epoch: u64,
    pub signature: [u8; 64],
    pub secondary_signature: Option<[u8; 64]>,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint does not descend from explicit trust")]
    Untrusted,
    #[error("checkpoint regresses or conflicts with a pinned head")]
    Rollback,
    #[error("checkpoint artifact is invalid or exceeds its bound")]
    InvalidArtifact,
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal capture failed: {0}")]
    Journal(#[from] JournalError),
}

impl Checkpoint {
    pub fn sign(
        head: FlushedHead,
        created_at_secs: u64,
        key: &SigningKey,
        kind: CheckpointKind,
    ) -> Result<Self, CheckpointError> {
        if kind != CheckpointKind::Periodic {
            return Err(CheckpointError::InvalidArtifact);
        }
        Ok(Self::signed(
            head,
            created_at_secs,
            kind,
            key,
            key.verifying_key().to_bytes(),
            0,
            None,
        ))
    }
    pub fn rotate(
        head: FlushedHead,
        created_at_secs: u64,
        old: &SigningKey,
        new: &SigningKey,
    ) -> Result<Self, CheckpointError> {
        let mut cp = Self::signed(
            head,
            created_at_secs,
            CheckpointKind::Rotation,
            old,
            new.verifying_key().to_bytes(),
            0,
            None,
        );
        cp.secondary_signature = Some(new.sign(&cp.payload()).to_bytes());
        Ok(cp)
    }
    pub fn trust_reset(
        head: FlushedHead,
        created_at_secs: u64,
        new: &SigningKey,
        previous_epoch: u64,
    ) -> Result<Self, CheckpointError> {
        if head.epoch <= previous_epoch {
            return Err(CheckpointError::Rollback);
        }
        Ok(Self::signed(
            head,
            created_at_secs,
            CheckpointKind::TrustReset,
            new,
            new.verifying_key().to_bytes(),
            previous_epoch,
            None,
        ))
    }
    fn signed(
        head: FlushedHead,
        time: u64,
        kind: CheckpointKind,
        signer: &SigningKey,
        public_key: [u8; 32],
        previous_epoch: u64,
        secondary_signature: Option<[u8; 64]>,
    ) -> Self {
        let mut cp = Self {
            head,
            created_at_secs: time,
            kind,
            key_id: KeyId::from_public_key(&signer.verifying_key()),
            public_key,
            previous_epoch,
            signature: [0; 64],
            secondary_signature,
        };
        cp.signature = signer.sign(&cp.payload()).to_bytes();
        cp
    }
    fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(130);
        out.extend_from_slice(DOMAIN);
        out.push(1);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.head.journal_id);
        out.extend_from_slice(&self.head.epoch.to_be_bytes());
        out.extend_from_slice(&self.head.sequence.to_be_bytes());
        out.extend_from_slice(&self.head.hash);
        out.extend_from_slice(&self.created_at_secs.to_be_bytes());
        out.extend_from_slice(&self.previous_epoch.to_be_bytes());
        out.extend_from_slice(&self.key_id.0);
        out.extend_from_slice(&self.public_key);
        out
    }
    pub fn encode(&self) -> Vec<u8> {
        let payload = self.payload();
        let mut body = payload;
        body.extend_from_slice(&self.signature);
        body.push(u8::from(self.secondary_signature.is_some()));
        if let Some(sig) = self.secondary_signature {
            body.extend_from_slice(&sig);
        }
        let mut out = Vec::with_capacity(body.len() + 12);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() < 12 || bytes.len() > MAX_CHECKPOINT_BYTES || &bytes[..8] != MAGIC {
            return Err(CheckpointError::InvalidArtifact);
        }
        let declared = u32::from_be_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| CheckpointError::InvalidArtifact)?,
        ) as usize;
        if declared != bytes.len() - 12 {
            return Err(CheckpointError::InvalidArtifact);
        }
        let mut cursor = 12;
        if take(bytes, &mut cursor, DOMAIN.len())? != DOMAIN || take_u8(bytes, &mut cursor)? != 1 {
            return Err(CheckpointError::InvalidArtifact);
        }
        let kind = match take_u8(bytes, &mut cursor)? {
            1 => CheckpointKind::Periodic,
            2 => CheckpointKind::Rotation,
            3 => CheckpointKind::TrustReset,
            _ => return Err(CheckpointError::InvalidArtifact),
        };
        let journal_id = take_array::<16>(bytes, &mut cursor)?;
        let epoch = take_u64(bytes, &mut cursor)?;
        let sequence = take_u64(bytes, &mut cursor)?;
        let hash = take_array::<32>(bytes, &mut cursor)?;
        let created_at_secs = take_u64(bytes, &mut cursor)?;
        let previous_epoch = take_u64(bytes, &mut cursor)?;
        let key_id = KeyId(take_array::<32>(bytes, &mut cursor)?);
        let public_key = take_array::<32>(bytes, &mut cursor)?;
        let signature = take_array::<64>(bytes, &mut cursor)?;
        let secondary_signature = match take_u8(bytes, &mut cursor)? {
            0 => None,
            1 => Some(take_array::<64>(bytes, &mut cursor)?),
            _ => return Err(CheckpointError::InvalidArtifact),
        };
        if cursor != bytes.len() {
            return Err(CheckpointError::InvalidArtifact);
        }
        let checkpoint = Self {
            head: FlushedHead::new(journal_id, epoch, sequence, hash),
            created_at_secs,
            kind,
            key_id,
            public_key,
            previous_epoch,
            signature,
            secondary_signature,
        };
        if (kind == CheckpointKind::Rotation) != checkpoint.secondary_signature.is_some() {
            return Err(CheckpointError::InvalidArtifact);
        }
        Ok(checkpoint)
    }
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], CheckpointError> {
    let end = cursor
        .checked_add(length)
        .ok_or(CheckpointError::InvalidArtifact)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(CheckpointError::InvalidArtifact)?;
    *cursor = end;
    Ok(value)
}
fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, CheckpointError> {
    Ok(take(bytes, cursor, 1)?[0])
}
fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, CheckpointError> {
    Ok(u64::from_be_bytes(take_array::<8>(bytes, cursor)?))
}
fn take_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], CheckpointError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| CheckpointError::InvalidArtifact)
}

#[derive(Clone)]
pub struct TrustBundle {
    journal_id: [u8; 16],
    initial: VerifyingKey,
    minimum: Option<Checkpoint>,
    resets: HashMap<u64, VerifyingKey>,
}
impl TrustBundle {
    pub fn new(journal_id: [u8; 16], initial: VerifyingKey) -> Self {
        Self {
            journal_id,
            initial,
            minimum: None,
            resets: HashMap::new(),
        }
    }
    pub fn with_minimum(mut self, checkpoint: Checkpoint) -> Self {
        self.minimum = Some(checkpoint);
        self
    }
    pub fn allow_epoch_reset(mut self, epoch: u64, key: VerifyingKey) -> Self {
        self.resets.insert(epoch, key);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    Current,
    Stale,
    UnknownTail,
}

pub struct CheckpointVerifier {
    trust: TrustBundle,
}
impl CheckpointVerifier {
    pub fn new(trust: TrustBundle) -> Self {
        Self { trust }
    }
    pub fn verify(
        &self,
        checkpoints: &[Checkpoint],
        now_secs: u64,
        max_age: Duration,
    ) -> Result<VerificationReport, CheckpointError> {
        if let Some(minimum) = &self.trust.minimum {
            if minimum.head.journal_id != self.trust.journal_id
                || verify_signature(minimum, &self.trust.initial).is_err()
            {
                return Err(CheckpointError::Untrusted);
            }
        }
        let mut trusted = self.trust.initial;
        let mut last: Option<&Checkpoint> = None;
        let mut discontinuities = 0;
        for cp in checkpoints {
            if cp.head.journal_id != self.trust.journal_id {
                return Err(CheckpointError::Untrusted);
            }
            if let Some(prev) = last {
                if cp.head.epoch < prev.head.epoch
                    || (cp.head.epoch == prev.head.epoch
                        && (cp.head.sequence <= prev.head.sequence
                            || cp.created_at_secs < prev.created_at_secs))
                {
                    return Err(CheckpointError::Rollback);
                }
            }
            match cp.kind {
                CheckpointKind::Periodic => verify_signature(cp, &trusted)?,
                CheckpointKind::Rotation => {
                    verify_signature(cp, &trusted)?;
                    let next = VerifyingKey::from_bytes(&cp.public_key)
                        .map_err(|_| CheckpointError::Untrusted)?;
                    next.verify(
                        &cp.payload(),
                        &Signature::from_bytes(
                            &cp.secondary_signature.ok_or(CheckpointError::Untrusted)?,
                        ),
                    )
                    .map_err(|_| CheckpointError::Untrusted)?;
                    trusted = next;
                }
                CheckpointKind::TrustReset => {
                    let reset = self
                        .trust
                        .resets
                        .get(&cp.head.epoch)
                        .ok_or(CheckpointError::Untrusted)?;
                    if cp.previous_epoch >= cp.head.epoch || reset.to_bytes() != cp.public_key {
                        return Err(CheckpointError::Untrusted);
                    }
                    verify_signature(cp, reset)?;
                    trusted = *reset;
                    discontinuities += 1;
                }
            }
            last = Some(cp);
        }
        let complete = self.trust.minimum.as_ref().map(|minimum| {
            last.is_some_and(|cp| {
                cp.head.epoch > minimum.head.epoch
                    || (cp.head.epoch == minimum.head.epoch
                        && cp.head.sequence >= minimum.head.sequence
                        && (cp.head.sequence != minimum.head.sequence
                            || cp.head.hash == minimum.head.hash))
            })
        });
        if complete == Some(false) {
            return Err(CheckpointError::Rollback);
        }
        let fresh =
            last.is_some_and(|cp| now_secs.saturating_sub(cp.created_at_secs) <= max_age.as_secs());
        Ok(VerificationReport {
            integrity: true,
            lifecycle_consistent: true,
            completeness_through_checkpoint: complete,
            unknown_tail_freshness: fresh,
            records: 0,
            terminal_denied: 0,
            terminal_outcomes: 0,
            terminal_recoveries: 0,
            discontinuities,
        })
    }
}
fn verify_signature(cp: &Checkpoint, key: &VerifyingKey) -> Result<(), CheckpointError> {
    if cp.key_id != KeyId::from_public_key(key) {
        return Err(CheckpointError::Untrusted);
    }
    key.verify(&cp.payload(), &Signature::from_bytes(&cp.signature))
        .map_err(|_| CheckpointError::Untrusted)
}

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
        fs::create_dir_all(parent)?;
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
    pub fn allows_user_mutation(&self, newest_checkpoint_secs: u64, now_secs: u64) -> bool {
        now_secs.saturating_sub(newest_checkpoint_secs)
            <= self.max_age.saturating_add(self.grace).as_secs()
    }
    pub const fn allows_reserved_cleanup(&self) -> bool {
        true
    }
}
