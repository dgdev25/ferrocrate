use super::{
    encode_record, hash_record, OperationId, PendingOperation, RecoveryRecipe, WitnessRecord,
    WitnessStage,
};
use sled::transaction::{ConflictableTransactionError, Transactional};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const HEAD_SEQUENCE: &[u8] = b"head-sequence";
const HEAD_HASH: &[u8] = b"head-hash";
const JOURNAL_ID: &[u8] = b"journal-id";
const RESERVE: &[u8] = b"cleanup-reserve";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalMode {
    Optional,
    Required,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlushBoundary {
    Reserve,
    Received,
    Decision,
    Outcome,
}

/// Deterministic fault seam. Public for integration qualification; production
/// callers should use [`WitnessJournal::open`].
#[derive(Clone, Default)]
pub struct JournalFaults(Arc<Mutex<HashSet<FlushBoundary>>>);

impl JournalFaults {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn fail_ambiguous_once(&self, boundary: FlushBoundary) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(boundary);
    }
    fn take(&self, boundary: FlushBoundary) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&boundary)
    }
}

#[derive(Clone, Debug)]
pub struct JournalConfig {
    root: PathBuf,
    journal_id: [u8; 16],
    mode: JournalMode,
    cleanup_reserve_bytes: u64,
}

impl JournalConfig {
    pub fn new(root: impl AsRef<Path>, journal_id: [u8; 16], mode: JournalMode) -> Self {
        Self {
            root: root.as_ref().to_owned(),
            journal_id,
            mode,
            cleanup_reserve_bytes: 64 * 1024,
        }
    }
    pub fn cleanup_reserve_bytes(mut self, bytes: u64) -> Self {
        self.cleanup_reserve_bytes = bytes;
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("witness journal is owned by another append coordinator")]
    Locked,
    #[error("configured journal identity does not match durable storage")]
    JournalMismatch,
    #[error("operation ID already exists")]
    DuplicateOperation,
    #[error("operation is not pending")]
    NotPending,
    #[error("operation already has a terminal outcome")]
    AlreadyComplete,
    #[error("witness durability is indeterminate; recover by operation ID")]
    Indeterminate { operation_id: OperationId },
    #[error("automated state changes stopped because cleanup reserve is not durable")]
    AutomationStopped,
    #[error("invalid witness stage for journal transition")]
    InvalidStage,
    #[error("corrupt witness journal metadata")]
    Corrupt,
    #[error("witness journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("witness journal storage failed: {0}")]
    Storage(#[from] sled::Error),
    #[error("witness record failed validation: {0}")]
    Record(#[from] super::WitnessError),
}

/// Proof that the decision and its pending recovery state received an explicit
/// successful storage flush. Deliberately neither `Clone` nor publicly constructible.
#[derive(Debug)]
pub struct DurableIntent {
    operation_id: OperationId,
    execution_generation: u64,
}

impl DurableIntent {
    /// The proof is intentionally affine and cannot be duplicated.
    /// ```compile_fail
    /// use ferro_core::witness::DurableIntent;
    /// fn duplicate(value: DurableIntent) { let _ = value.clone(); }
    /// ```
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn execution_generation(&self) -> u64 {
        self.execution_generation
    }
}

pub struct WitnessJournal {
    root: PathBuf,
    db: sled::Db,
    records: sled::Tree,
    operations: sled::Tree,
    pending: sled::Tree,
    meta: sled::Tree,
    journal_id: [u8; 16],
    _mode: JournalMode,
    _lock: File,
    coordinator: Mutex<()>,
    faults: JournalFaults,
}

impl WitnessJournal {
    pub fn open(config: JournalConfig) -> Result<Self, JournalError> {
        Self::open_with_faults(config, JournalFaults::new())
    }

    pub fn open_with_faults(
        config: JournalConfig,
        faults: JournalFaults,
    ) -> Result<Self, JournalError> {
        fs::create_dir_all(&config.root)?;
        let lock = lock_journal(&config.root, config.journal_id)?;
        let db = sled::open(config.root.join("witness.sled"))?;
        let journal = Self {
            root: config.root.clone(),
            records: db.open_tree("witness-records-v1")?,
            operations: db.open_tree("witness-operations-v1")?,
            pending: db.open_tree("witness-pending-v1")?,
            meta: db.open_tree("witness-meta-v1")?,
            db,
            journal_id: config.journal_id,
            _mode: config.mode,
            _lock: lock,
            coordinator: Mutex::new(()),
            faults,
        };
        journal.initialize(config.cleanup_reserve_bytes)?;
        Ok(journal)
    }

    fn initialize(&self, reserve_bytes: u64) -> Result<(), JournalError> {
        if let Some(id) = self.meta.get(JOURNAL_ID)? {
            if id.as_ref() != self.journal_id {
                return Err(JournalError::JournalMismatch);
            }
            if self.meta.get(RESERVE)?.is_none() {
                return Err(JournalError::AutomationStopped);
            }
            let reserve = self.reserve_file()?;
            if reserve.metadata()?.len() != reserve_bytes {
                return Err(JournalError::AutomationStopped);
            }
            return Ok(());
        }
        self.meta.insert(JOURNAL_ID, &self.journal_id)?;
        self.meta.insert(HEAD_SEQUENCE, &0_u64.to_be_bytes())?;
        self.meta.insert(HEAD_HASH, &[0_u8; 32])?;
        // Bounded preallocation is represented by durable quota metadata. Sled
        // owns physical allocation; cleanup consumption is accounted separately.
        self.meta.insert(RESERVE, &reserve_bytes.to_be_bytes())?;
        let mut reserve = self.reserve_file()?;
        reserve.set_len(0)?;
        let zeroes = [0_u8; 4096];
        let mut remaining = reserve_bytes;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(zeroes.len() as u64))
                .map_err(|_| JournalError::AutomationStopped)?;
            reserve.write_all(&zeroes[..count])?;
            remaining -= count as u64;
        }
        reserve.sync_all()?;
        self.db.flush()?;
        if self.faults.take(FlushBoundary::Reserve) {
            return Err(JournalError::AutomationStopped);
        }
        Ok(())
    }

    fn reserve_file(&self) -> Result<File, JournalError> {
        let path = self.root.join("witness.cleanup-reserve");
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?)
    }

    pub fn append_received(
        &self,
        id: OperationId,
        generation: u64,
        recipe: RecoveryRecipe,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        if record.stage != WitnessStage::RequestReceived {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        if self.operations.contains_key(id.0)? {
            return Err(JournalError::DuplicateOperation);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let pending_value = recipe.encode(generation);
        (&self.records, &self.operations, &self.pending, &self.meta)
            .transaction(|(records, operations, pending, meta)| {
                if operations.get(id.0)?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::DuplicateOperation,
                    ));
                }
                records.insert(&seq_key, bytes.as_ref())?;
                operations.insert(&id.0, &[1_u8][..])?;
                pending.insert(&id.0, &pending_value[..])?;
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        self.flush(FlushBoundary::Received, id).map(|_| ())
    }

    pub fn append_decision(
        &self,
        id: OperationId,
        mut record: WitnessRecord,
    ) -> Result<DurableIntent, JournalError> {
        if record.stage != WitnessStage::Decision {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        let pending = self.pending.get(id.0)?.ok_or(JournalError::NotPending)?;
        let (generation, _) = RecoveryRecipe::decode(&pending).ok_or(JournalError::Corrupt)?;
        let state = self.operations.get(id.0)?.ok_or(JournalError::NotPending)?;
        if state.as_ref() != [1] {
            return Err(JournalError::DuplicateOperation);
        }
        self.append_record_and_state(id, &mut record, 2)?;
        self.flush(FlushBoundary::Decision, id)?;
        Ok(DurableIntent {
            operation_id: id,
            execution_generation: generation,
        })
    }

    pub fn complete(
        &self,
        intent: DurableIntent,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        if record.stage != WitnessStage::Outcome && record.stage != WitnessStage::Recovery {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        let id = intent.operation_id;
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        (&self.records, &self.operations, &self.pending, &self.meta)
            .transaction(|(records, operations, pending, meta)| {
                if pending.get(id.0)?.is_none() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::AlreadyComplete,
                    ));
                }
                records.insert(&seq_key, bytes.as_ref())?;
                operations.insert(&id.0, &[3_u8][..])?;
                pending.remove(&id.0)?;
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        self.flush(FlushBoundary::Outcome, id).map(|_| ())
    }

    fn append_record_and_state(
        &self,
        id: OperationId,
        record: &mut WitnessRecord,
        state: u8,
    ) -> Result<(), JournalError> {
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, record)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        (&self.records, &self.operations, &self.meta)
            .transaction(|(records, operations, meta)| {
                records.insert(&seq_key, bytes.as_ref())?;
                operations.insert(&id.0, &[state][..])?;
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                Ok(())
            })
            .map_err(transaction_error)
    }

    pub fn pending(&self) -> Result<Vec<PendingOperation>, JournalError> {
        self.pending
            .iter()
            .map(|entry| {
                let (key, value) = entry?;
                let id = OperationId(key.as_ref().try_into().map_err(|_| JournalError::Corrupt)?);
                let (execution_generation, recipe) =
                    RecoveryRecipe::decode(&value).ok_or(JournalError::Corrupt)?;
                Ok(PendingOperation {
                    operation_id: id,
                    execution_generation,
                    recipe,
                })
            })
            .collect()
    }

    pub fn recover(&self, id: OperationId) -> Result<PendingOperation, JournalError> {
        let value = self
            .pending
            .get(id.0)?
            .ok_or_else(|| match self.operations.get(id.0) {
                Ok(Some(state)) if state.as_ref() == [3] => JournalError::AlreadyComplete,
                _ => JournalError::NotPending,
            })?;
        let (execution_generation, recipe) =
            RecoveryRecipe::decode(&value).ok_or(JournalError::Corrupt)?;
        Ok(PendingOperation {
            operation_id: id,
            execution_generation,
            recipe,
        })
    }

    fn head(&self) -> Result<(u64, [u8; 32]), JournalError> {
        let seq = self.meta.get(HEAD_SEQUENCE)?.ok_or(JournalError::Corrupt)?;
        let hash = self.meta.get(HEAD_HASH)?.ok_or(JournalError::Corrupt)?;
        Ok((
            u64::from_be_bytes(seq.as_ref().try_into().map_err(|_| JournalError::Corrupt)?),
            hash.as_ref()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        ))
    }

    fn flush(&self, boundary: FlushBoundary, id: OperationId) -> Result<(), JournalError> {
        self.db.flush()?;
        if self.faults.take(boundary) {
            Err(JournalError::Indeterminate { operation_id: id })
        } else {
            Ok(())
        }
    }
}

fn transaction_error(error: sled::transaction::TransactionError<JournalError>) -> JournalError {
    match error {
        sled::transaction::TransactionError::Abort(error) => error,
        sled::transaction::TransactionError::Storage(error) => JournalError::Storage(error),
    }
}

fn lock_journal(root: &Path, journal_id: [u8; 16]) -> Result<File, JournalError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("witness.lock"))?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => JournalError::Locked,
        std::fs::TryLockError::Error(error) => JournalError::Io(error),
    })?;
    let mut existing = Vec::new();
    file.read_to_end(&mut existing)?;
    if !existing.is_empty() && existing != journal_id {
        return Err(JournalError::JournalMismatch);
    }
    if existing.is_empty() {
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&journal_id)?;
        file.sync_all()?;
    }
    Ok(file)
}
