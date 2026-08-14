use super::{encode_record, hash_record, OperationId, RecoveryRecipe, WitnessRecord, WitnessStage};
use sled::transaction::{ConflictableTransactionError, Transactional};
mod inspect;
mod quota;
mod reconcile;
mod state;
mod storage;
mod types;
use state::{OperationState, ALLOWED, COMPLETE, RECEIVED, UNKNOWN};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{atomic::AtomicBool, Mutex},
};
use storage::{lock_journal, path_entry_exists, transaction_error};
pub use types::{
    DurableIntent, FaultPoint, FlushBoundary, JournalConfig, JournalError, JournalFaults,
    JournalMode,
};

const HEAD_SEQUENCE: &[u8] = b"head-sequence";
const HEAD_HASH: &[u8] = b"head-hash";
const JOURNAL_ID: &[u8] = b"journal-id";
const RESERVE: &[u8] = b"cleanup-reserve";
const RESERVE_TOTAL: &[u8] = b"cleanup-reserve-total";
const RESERVE_INFLIGHT: &[u8] = b"cleanup-reserve-inflight";
const AUTOMATION_STOPPED: &[u8] = b"automation-stopped";
const MAX_BYTES: &[u8] = b"max-journal-bytes";
const CURRENT_SEGMENT: &[u8] = b"current-segment";
const ROTATION_DEFERRED: &[u8] = b"rotation-deferred";
const EPOCH: &[u8] = b"epoch";

pub struct WitnessJournal {
    root: PathBuf,
    db: sled::Db,
    records: sled::Tree,
    operations: sled::Tree,
    events: sled::Tree,
    pending: sled::Tree,
    meta: sled::Tree,
    segments: sled::Tree,
    sealed_segments: sled::Tree,
    journal_id: [u8; 16],
    epoch: u64,
    max_bytes: u64,
    reserve_total: u64,
    segment_bytes: u64,
    mode: JournalMode,
    _lock: File,
    coordinator: Mutex<()>,
    faults: JournalFaults,
    automation_stopped: AtomicBool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalHead {
    pub journal_id: [u8; 16],
    pub epoch: u64,
    pub sequence: u64,
    pub hash: [u8; 32],
}

impl WitnessJournal {
    /// Flush all journal trees and capture the head while holding the sole
    /// append coordinator. Checkpoint signers must use this snapshot rather
    /// than separately reading sequence and hash metadata.
    pub fn flushed_head(&self) -> Result<JournalHead, JournalError> {
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.db.flush()?;
        let (sequence, hash) = self.head()?;
        Ok(JournalHead {
            journal_id: self.journal_id,
            epoch: self.epoch,
            sequence,
            hash,
        })
    }
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
            events: db.open_tree("witness-events-v1")?,
            pending: db.open_tree("witness-pending-v1")?,
            meta: db.open_tree("witness-meta-v1")?,
            segments: db.open_tree("witness-segments-v1")?,
            sealed_segments: db.open_tree("witness-sealed-segments-v1")?,
            db,
            journal_id: config.journal_id,
            epoch: 1,
            max_bytes: config.max_journal_bytes,
            reserve_total: config.cleanup_reserve_bytes,
            segment_bytes: config.segment_bytes,
            mode: config.mode,
            _lock: lock,
            coordinator: Mutex::new(()),
            faults,
            automation_stopped: AtomicBool::new(false),
        };
        journal.initialize(config.cleanup_reserve_bytes)?;
        Ok(journal)
    }
    fn initialize(&self, reserve_bytes: u64) -> Result<(), JournalError> {
        if path_entry_exists(&self.root.join("witness.automation-stopped"))
            || path_entry_exists(&self.root.join("witness.automation-stopped.tmp"))
        {
            self.automation_stopped
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(JournalError::AutomationStopped);
        }
        if let Some(id) = self.meta.get(JOURNAL_ID)? {
            if id.as_ref() != self.journal_id {
                return Err(JournalError::JournalMismatch);
            }
            if self.meta.get(RESERVE)?.is_none() {
                return Err(JournalError::AutomationStopped);
            }
            if self.meta.get(RESERVE_INFLIGHT)?.is_some() {
                return Err(JournalError::AutomationStopped);
            }
            if self.meta.get(AUTOMATION_STOPPED)?.is_some() {
                return Err(JournalError::AutomationStopped);
            }
            let epoch = self.meta.get(EPOCH)?.ok_or(JournalError::Corrupt)?;
            if epoch.as_ref() != self.epoch.to_be_bytes() {
                return Err(JournalError::Corrupt);
            }
            let stored_reserve = self
                .meta
                .get(RESERVE)?
                .ok_or(JournalError::AutomationStopped)?;
            let stored_reserve = u64::from_be_bytes(
                stored_reserve
                    .as_ref()
                    .try_into()
                    .map_err(|_| JournalError::AutomationStopped)?,
            );
            let total = self.meta.get(RESERVE_TOTAL)?.ok_or(JournalError::Corrupt)?;
            let total = u64::from_be_bytes(
                total
                    .as_ref()
                    .try_into()
                    .map_err(|_| JournalError::Corrupt)?,
            );
            let max = self.meta.get(MAX_BYTES)?.ok_or(JournalError::Corrupt)?;
            let max =
                u64::from_be_bytes(max.as_ref().try_into().map_err(|_| JournalError::Corrupt)?);
            if total != self.reserve_total || max != self.max_bytes {
                return Err(JournalError::Corrupt);
            }
            let reserve = self.reserve_file()?;
            if reserve.metadata()?.len() != stored_reserve {
                return Err(JournalError::AutomationStopped);
            }
            return Ok(());
        }
        self.meta.insert(JOURNAL_ID, &self.journal_id)?;
        self.meta.insert(HEAD_SEQUENCE, &0_u64.to_be_bytes())?;
        self.meta.insert(HEAD_HASH, &[0_u8; 32])?;
        self.meta.insert(EPOCH, &1_u64.to_be_bytes())?;
        self.meta.insert(RESERVE, &reserve_bytes.to_be_bytes())?;
        self.meta
            .insert(RESERVE_TOTAL, &reserve_bytes.to_be_bytes())?;
        self.meta.insert(MAX_BYTES, &self.max_bytes.to_be_bytes())?;
        self.meta.insert(CURRENT_SEGMENT, &0_u64.to_be_bytes())?;
        let mut genesis = [0_u8; 40];
        genesis[..8].copy_from_slice(&1_u64.to_be_bytes());
        self.segments
            .insert(0_u64.to_be_bytes(), genesis.as_slice())?;
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
        if self
            .faults
            .take(FaultPoint::AfterFlush(FlushBoundary::Reserve))
        {
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
        if recipe.precondition_digest() != &record.request_digest
            || recipe.resource_generation() != record.resource_generation
            || recipe.original_action() != record.action
            || recipe.resource_kind() != record.resource_kind
        {
            return Err(JournalError::BindingMismatch);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Received)?;
        if self.operations.contains_key(id.0)? {
            return Err(JournalError::DuplicateOperation);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        self.ensure_user_capacity(bytes.as_ref().len() as u64)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        let pending_value = recipe.encode(generation);
        let operation = OperationState::received(&record, generation).encode();
        (
            &self.records,
            &self.operations,
            &self.pending,
            &self.meta,
            &self.events,
        )
            .transaction(|(records, operations, pending, meta, events)| {
                if meta.get(HEAD_SEQUENCE)?.as_deref() != Some(expected_head.as_slice()) {
                    return Err(ConflictableTransactionError::Abort(JournalError::Corrupt));
                }
                if operations.get(id.0)?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::DuplicateOperation,
                    ));
                }
                if events.get(record.event_id)?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::DuplicateEvent,
                    ));
                }
                records.insert(&seq_key, bytes.as_ref())?;
                events.insert(&record.event_id, &seq_key)?;
                operations.insert(&id.0, operation.as_slice())?;
                pending.insert(&id.0, &pending_value[..])?;
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        self.flush(FlushBoundary::Received, id)?;
        self.post_ack_rotation();
        Ok(())
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
        self.preflight(FlushBoundary::Decision)?;
        let pending = self.pending.get(id.0)?.ok_or(JournalError::NotPending)?;
        let (generation, _) = RecoveryRecipe::decode(&pending).ok_or(JournalError::Corrupt)?;
        let mut state =
            OperationState::decode(&self.operations.get(id.0)?.ok_or(JournalError::NotPending)?)
                .ok_or(JournalError::Corrupt)?;
        if state.state != RECEIVED {
            return Err(JournalError::DuplicateOperation);
        }
        if !state.binding_matches(&record) {
            return Err(JournalError::BindingMismatch);
        }
        if record.decision != Some(true) {
            return Err(JournalError::InvalidStage);
        }
        let decision_id = record.decision_id.ok_or(JournalError::InvalidStage)?;
        let decision_digest = self.append_decision_record(id, &mut record, &mut state)?;
        self.flush(FlushBoundary::Decision, id)?;
        self.post_ack_rotation();
        Ok(DurableIntent {
            journal_id: self.journal_id,
            epoch: self.epoch,
            operation_id: id,
            execution_generation: generation,
            pending_generation: state.pending_generation,
            decision_id,
            decision_digest,
        })
    }

    pub fn deny(
        &self,
        id: OperationId,
        mut decision: WitnessRecord,
        mut denied: WitnessRecord,
    ) -> Result<(), JournalError> {
        if decision.stage != WitnessStage::Decision
            || decision.decision != Some(false)
            || denied.stage != WitnessStage::Denied
        {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Decision)?;
        let state =
            OperationState::decode(&self.operations.get(id.0)?.ok_or(JournalError::NotPending)?)
                .ok_or(JournalError::Corrupt)?;
        if state.state != RECEIVED
            || !state.binding_matches(&decision)
            || !state.binding_matches(&denied)
            || decision.decision_id != denied.decision_id
        {
            return Err(JournalError::BindingMismatch);
        }
        let (sequence, previous) = self.head()?;
        decision.sequence = sequence + 1;
        decision.previous_hash = previous;
        let decision_bytes = encode_record(self.journal_id, &decision)?;
        denied.sequence = sequence + 2;
        denied.previous_hash = hash_record(&decision_bytes);
        let denied_bytes = encode_record(self.journal_id, &denied)?;
        self.ensure_user_capacity(
            (decision_bytes.as_ref().len() + denied_bytes.as_ref().len()) as u64,
        )?;
        let terminal_hash = hash_record(&denied_bytes);
        let first_key = decision.sequence.to_be_bytes();
        let terminal_key = denied.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        let mut terminal = state;
        terminal.state = COMPLETE;
        terminal.pending_generation += 1;
        let terminal_state = terminal.encode();
        (
            &self.records,
            &self.operations,
            &self.pending,
            &self.meta,
            &self.events,
        )
            .transaction(|(records, operations, pending, meta, events)| {
                if meta.get(HEAD_SEQUENCE)?.as_deref() != Some(expected_head.as_slice()) {
                    return Err(ConflictableTransactionError::Abort(JournalError::Corrupt));
                }
                if events.get(decision.event_id)?.is_some()
                    || events.get(denied.event_id)?.is_some()
                    || decision.event_id == denied.event_id
                {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::DuplicateEvent,
                    ));
                }
                records.insert(&first_key, decision_bytes.as_ref())?;
                records.insert(&terminal_key, denied_bytes.as_ref())?;
                events.insert(&decision.event_id, &first_key)?;
                events.insert(&denied.event_id, &terminal_key)?;
                operations.insert(&id.0, terminal_state.as_slice())?;
                pending.remove(&id.0)?;
                meta.insert(HEAD_SEQUENCE, &terminal_key)?;
                meta.insert(HEAD_HASH, &terminal_hash)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        self.flush(FlushBoundary::Decision, id)?;
        self.post_ack_rotation();
        Ok(())
    }

    pub fn complete(
        &self,
        intent: DurableIntent,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        if record.stage != WitnessStage::Outcome {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Outcome)?;
        let id = intent.operation_id;
        if intent.journal_id != self.journal_id || intent.epoch != self.epoch {
            return Err(JournalError::ProofMismatch);
        }
        let state_bytes = self.operations.get(id.0)?.ok_or(JournalError::NotPending)?;
        let state = OperationState::decode(&state_bytes).ok_or(JournalError::Corrupt)?;
        if state.state != ALLOWED
            || state.execution_generation != intent.execution_generation
            || state.pending_generation != intent.pending_generation
            || state.decision_id != intent.decision_id
            || state.decision_digest != intent.decision_digest
        {
            return Err(JournalError::ProofMismatch);
        }
        if !state.terminal_matches(&record) {
            return Err(JournalError::BindingMismatch);
        }
        let forced_unknown = self
            .faults
            .take(FaultPoint::BeforeFlush(FlushBoundary::Outcome));
        if forced_unknown {
            record.outcome = super::WitnessOutcome::OutcomeUnknown;
            record.reason = Some(super::ReasonCode::ExecutionFailed);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        self.ensure_user_capacity(bytes.as_ref().len() as u64)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        (
            &self.records,
            &self.operations,
            &self.pending,
            &self.meta,
            &self.events,
        )
            .transaction(|(records, operations, pending, meta, events)| {
                if meta.get(HEAD_SEQUENCE)?.as_deref() != Some(expected_head.as_slice()) {
                    return Err(ConflictableTransactionError::Abort(JournalError::Corrupt));
                }
                if pending.get(id.0)?.is_none() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::AlreadyComplete,
                    ));
                }
                if events.get(record.event_id)?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::DuplicateEvent,
                    ));
                }
                records.insert(&seq_key, bytes.as_ref())?;
                events.insert(&record.event_id, &seq_key)?;
                let mut terminal = state.clone();
                let unknown = record.outcome == super::WitnessOutcome::OutcomeUnknown;
                terminal.state = if unknown { UNKNOWN } else { COMPLETE };
                terminal.unknown_event_id = if unknown { record.event_id } else { [0; 16] };
                terminal.pending_generation += 1;
                operations.insert(&id.0, terminal.encode())?;
                if !unknown {
                    pending.remove(&id.0)?;
                }
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        if forced_unknown {
            Err(JournalError::Indeterminate { operation_id: id })
        } else {
            self.flush(FlushBoundary::Outcome, id)?;
            self.post_ack_rotation();
            Ok(())
        }
    }

    fn append_decision_record(
        &self,
        id: OperationId,
        record: &mut WitnessRecord,
        state: &mut OperationState,
    ) -> Result<[u8; 32], JournalError> {
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, record)?;
        self.ensure_user_capacity(bytes.as_ref().len() as u64)?;
        let next_hash = hash_record(&bytes);
        state.state = ALLOWED;
        state.pending_generation += 1;
        state.decision_id = record.decision_id.ok_or(JournalError::InvalidStage)?;
        state.decision_digest = next_hash;
        let operation = state.encode();
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        (&self.records, &self.operations, &self.meta, &self.events)
            .transaction(|(records, operations, meta, events)| {
                if meta.get(HEAD_SEQUENCE)?.as_deref() != Some(expected_head.as_slice()) {
                    return Err(ConflictableTransactionError::Abort(JournalError::Corrupt));
                }
                if events.get(record.event_id)?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::DuplicateEvent,
                    ));
                }
                records.insert(&seq_key, bytes.as_ref())?;
                events.insert(&record.event_id, &seq_key)?;
                operations.insert(&id.0, operation.as_slice())?;
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        Ok(next_hash)
    }
}
