use super::{JournalError, JournalHead, KeyId, VerificationReport};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Duration};

const DOMAIN: &[u8] = b"FERROCRATE-CHECKPOINT-V1";
const MAGIC: &[u8; 8] = b"FCHKPT01";
pub(super) const MAX_CHECKPOINT_BYTES: usize = 1024;

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
    pub first_sequence: u64,
    pub schema_version: u8,
    pub hash_algorithm: u8,
    pub created_at_secs: u64,
    pub kind: CheckpointKind,
    pub key_id: KeyId,
    pub public_key: [u8; 32],
    pub previous_epoch: u64,
    pub previous_checkpoint_digest: [u8; 32],
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
    pub fn rotate_after(
        head: FlushedHead,
        created_at_secs: u64,
        predecessor: &Self,
        old: &SigningKey,
        new: &SigningKey,
    ) -> Result<Self, CheckpointError> {
        let mut cp = Self::rotate(head, created_at_secs, old, new)?;
        cp.previous_checkpoint_digest = Sha256::digest(predecessor.encode()).into();
        cp.signature = old.sign(&cp.payload()).to_bytes();
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
    pub fn trust_reset_after(
        head: FlushedHead,
        created_at_secs: u64,
        predecessor: &Self,
        new: &SigningKey,
    ) -> Result<Self, CheckpointError> {
        let mut cp = Self::trust_reset(head, created_at_secs, new, predecessor.head.epoch)?;
        cp.previous_checkpoint_digest = Sha256::digest(predecessor.encode()).into();
        cp.signature = new.sign(&cp.payload()).to_bytes();
        Ok(cp)
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
            first_sequence: 1,
            schema_version: 1,
            hash_algorithm: 1,
            created_at_secs: time,
            kind,
            key_id: KeyId::from_public_key(&signer.verifying_key()),
            public_key,
            previous_epoch,
            previous_checkpoint_digest: [0; 32],
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
        out.push(self.schema_version);
        out.push(self.hash_algorithm);
        out.extend_from_slice(&self.head.journal_id);
        out.extend_from_slice(&self.head.epoch.to_be_bytes());
        out.extend_from_slice(&self.first_sequence.to_be_bytes());
        out.extend_from_slice(&self.head.sequence.to_be_bytes());
        out.extend_from_slice(&self.head.hash);
        out.extend_from_slice(&self.created_at_secs.to_be_bytes());
        out.extend_from_slice(&self.previous_epoch.to_be_bytes());
        out.extend_from_slice(&self.previous_checkpoint_digest);
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
        let schema_version = take_u8(bytes, &mut cursor)?;
        let hash_algorithm = take_u8(bytes, &mut cursor)?;
        if schema_version != 1 || hash_algorithm != 1 {
            return Err(CheckpointError::InvalidArtifact);
        }
        let journal_id = take_array::<16>(bytes, &mut cursor)?;
        let epoch = take_u64(bytes, &mut cursor)?;
        let first_sequence = take_u64(bytes, &mut cursor)?;
        let sequence = take_u64(bytes, &mut cursor)?;
        let hash = take_array::<32>(bytes, &mut cursor)?;
        let created_at_secs = take_u64(bytes, &mut cursor)?;
        let previous_epoch = take_u64(bytes, &mut cursor)?;
        let previous_checkpoint_digest = take_array::<32>(bytes, &mut cursor)?;
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
            first_sequence,
            schema_version,
            hash_algorithm,
            created_at_secs,
            kind,
            key_id,
            public_key,
            previous_epoch,
            previous_checkpoint_digest,
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
        evidence: &[Vec<u8>],
        checkpoints: &[Checkpoint],
        now_secs: u64,
        max_age: Duration,
    ) -> Result<VerificationReport, CheckpointError> {
        let mut trusted = self.trust.initial;
        let mut trusted_keys = HashMap::from([(KeyId::from_public_key(&trusted), trusted)]);
        let mut last: Option<&Checkpoint> = None;
        let mut discontinuities = 0;
        for cp in checkpoints {
            if cp.head.journal_id != self.trust.journal_id {
                return Err(CheckpointError::Untrusted);
            }
            if !super::checkpoint_evidence::is_bound(evidence, cp) {
                return Err(CheckpointError::Rollback);
            }
            if let Some(prev) = last {
                let expected_predecessor: [u8; 32] = Sha256::digest(prev.encode()).into();
                if (cp.kind != CheckpointKind::TrustReset && cp.head.epoch != prev.head.epoch)
                    || (cp.kind == CheckpointKind::TrustReset
                        && (cp.head.epoch != prev.head.epoch.saturating_add(1)
                            || cp.previous_epoch != prev.head.epoch))
                    || cp.previous_checkpoint_digest != expected_predecessor
                    || (cp.head.epoch == prev.head.epoch
                        && (cp.head.sequence < prev.head.sequence
                            || (cp.head.sequence == prev.head.sequence
                                && cp.head.hash != prev.head.hash)
                            || cp.created_at_secs < prev.created_at_secs))
                {
                    return Err(CheckpointError::Rollback);
                }
            } else if cp.kind == CheckpointKind::TrustReset
                || cp.previous_checkpoint_digest != [0; 32]
            {
                return Err(CheckpointError::Untrusted);
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
                    trusted_keys.insert(KeyId::from_public_key(&next), next);
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
                    trusted_keys.insert(KeyId::from_public_key(reset), *reset);
                    discontinuities += 1;
                }
            }
            last = Some(cp);
        }
        let complete = self.trust.minimum.as_ref().map(|minimum| {
            let minimum_signature_valid = trusted_keys
                .get(&minimum.key_id)
                .is_some_and(|key| verify_signature(minimum, key).is_ok());
            if minimum.head.journal_id != self.trust.journal_id
                || !minimum_signature_valid
                || !super::checkpoint_evidence::contains_head(evidence, minimum)
            {
                return false;
            }
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
        let last = last.ok_or(CheckpointError::Untrusted)?;
        if last.created_at_secs > now_secs {
            return Err(CheckpointError::InvalidArtifact);
        }
        let mut report = super::checkpoint_evidence::verify(evidence, last)?;
        report.completeness_through_checkpoint = complete.or(Some(true));
        report.unknown_tail_freshness = now_secs - last.created_at_secs <= max_age.as_secs();
        report.freshness = if report.unknown_tail_freshness {
            Freshness::Current
        } else {
            Freshness::Stale
        };
        report.discontinuities = discontinuities;
        Ok(report)
    }
}

fn verify_signature(cp: &Checkpoint, key: &VerifyingKey) -> Result<(), CheckpointError> {
    if cp.key_id != KeyId::from_public_key(key) {
        return Err(CheckpointError::Untrusted);
    }
    key.verify(&cp.payload(), &Signature::from_bytes(&cp.signature))
        .map_err(|_| CheckpointError::Untrusted)
}
