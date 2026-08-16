use super::{
    decode_record, encode_record, hash_record, OperationId, RecoveryRecipe, WitnessAction,
    WitnessOutcome, WitnessRecord, WitnessStage,
};
use sha2::Digest;
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
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
};
use storage::{lock_journal, path_entry_exists, JournalDb, JournalTree, SqliteJournalStore};
pub use types::{
    DurableIntent, FaultPoint, FlushBoundary, JournalConfig, JournalError, JournalFaults,
    JournalMode, RecoveryClassification,
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

#[cfg(test)]
type CheckpointLockHook = (
    std::sync::Arc<std::sync::Barrier>,
    std::sync::Arc<std::sync::Barrier>,
);
#[cfg(test)]
static CHECKPOINT_LOCK_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<CheckpointLockHook>>> =
    std::sync::OnceLock::new();
#[cfg(test)]
fn checkpoint_lock_hook() {
    let hook = CHECKPOINT_LOCK_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    if let Some((reached, release)) = hook {
        reached.wait();
        release.wait();
    }
}

pub struct WitnessJournal {
    root: PathBuf,
    db: JournalDb,
    records: JournalTree,
    operations: JournalTree,
    events: JournalTree,
    pending: JournalTree,
    meta: JournalTree,
    segments: JournalTree,
    sealed_segments: JournalTree,
    journal_id: [u8; 16],
    epoch: AtomicU64,
    max_bytes: u64,
    reserve_total: u64,
    segment_bytes: u64,
    mode: JournalMode,
    _lock: File,
    coordinator: Mutex<()>,
    faults: JournalFaults,
    automation_stopped: AtomicBool,
    mirror_sequence: AtomicU64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalHead {
    pub journal_id: [u8; 16],
    pub epoch: u64,
    pub sequence: u64,
    pub hash: [u8; 32],
}

impl WitnessJournal {
    pub const fn journal_id(&self) -> [u8; 16] {
        self.journal_id
    }
    pub const fn mode(&self) -> JournalMode {
        self.mode
    }
    pub(super) fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
    pub(super) fn checkpoint_preflight(&self) -> Result<(), JournalError> {
        if self.mode == JournalMode::Disabled {
            Err(JournalError::Disabled)
        } else {
            Ok(())
        }
    }
    pub(super) fn advance_epoch(&self, expected: u64) -> Result<u64, JournalError> {
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        if self.epoch.load(Ordering::Acquire) != expected {
            return Err(JournalError::ProofMismatch);
        }
        let next = expected.checked_add(1).ok_or(JournalError::Corrupt)?;
        self.meta.insert(EPOCH, &next.to_be_bytes())?;
        self.db.flush()?;
        self.epoch.store(next, Ordering::Release);
        Ok(next)
    }
    /// Flush all journal trees and capture the head while holding the sole
    /// append coordinator. Checkpoint signers must use this snapshot rather
    /// than separately reading sequence and hash metadata.
    pub fn flushed_head(&self) -> Result<JournalHead, JournalError> {
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.db.flush()?;
        let (sequence, hash) = self.head()?;
        Ok(JournalHead {
            journal_id: self.journal_id,
            epoch: self.epoch.load(Ordering::Acquire),
            sequence,
            hash,
        })
    }

    pub fn append_checkpoint_publication(
        &self,
        artifact_digest: [u8; 32],
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        if record.stage != WitnessStage::CheckpointPublished
            || record.action != WitnessAction::CheckpointPublish
            || record.outcome != WitnessOutcome::Succeeded
        {
            return Err(JournalError::InvalidStage);
        }
        record.result_digest = Some(artifact_digest);
        super::validation::validate_record(&record)?;
        #[cfg(test)]
        checkpoint_lock_hook();
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        if record.epoch != self.current_epoch() {
            return Err(JournalError::ProofMismatch);
        }
        if let Some(sequence) = self.events.get(record.event_id)? {
            let bytes = self.records.get(sequence)?.ok_or(JournalError::Corrupt)?;
            let existing = decode_record(&bytes)?;
            if existing.record().epoch == record.epoch
                && existing.record().stage == WitnessStage::CheckpointPublished
                && existing.record().result_digest == Some(artifact_digest)
            {
                return Ok(());
            }
            return Err(JournalError::DuplicateEvent);
        }
        self.preflight(FlushBoundary::Outcome)?;
        if self.faults.take(FaultPoint::CheckpointBindingRejected) {
            return Err(JournalError::BindingMismatch);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence.checked_add(1).ok_or(JournalError::Corrupt)?;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        self.ensure_user_capacity(bytes.as_ref().len() as u64)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        self.db.transaction(|transaction| {
            if transaction.get(self.meta.name(), HEAD_SEQUENCE)?.as_deref()
                != Some(expected_head.as_slice())
            {
                return Err(JournalError::Corrupt);
            }
            if transaction
                .get(self.events.name(), &record.event_id)?
                .is_some()
            {
                return Err(JournalError::DuplicateEvent);
            }
            transaction.put(self.records.name(), &seq_key, bytes.as_ref())?;
            transaction.put(self.events.name(), &record.event_id, &seq_key)?;
            transaction.put(self.meta.name(), HEAD_SEQUENCE, &seq_key)?;
            transaction.put(self.meta.name(), HEAD_HASH, &next_hash)?;
            Ok(())
        })?;
        self.flush(FlushBoundary::Outcome, OperationId(record.request_id))?;
        self.update_read_mirror_best_effort();
        Ok(())
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
        let legacy_path = config.root.join("witness.sled");
        let sqlite_path = config.root.join("witness.sqlite3");
        let ready_marker = config.root.join("witness.sqlite3.ready");
        const V1_TREES: [&[u8]; 7] = [
            b"witness-records-v1",
            b"witness-operations-v1",
            b"witness-events-v1",
            b"witness-pending-v1",
            b"witness-meta-v1",
            b"witness-segments-v1",
            b"witness-sealed-segments-v1",
        ];
        if ready_marker.exists() && !sqlite_path.exists() {
            return Err(JournalError::Corrupt);
        }
        if legacy_path.exists() && (!sqlite_path.exists() || !ready_marker.exists()) {
            let legacy = sled::open(&legacy_path)?;
            if legacy
                .tree_names()
                .iter()
                .any(|name| V1_TREES.contains(&name.as_ref()))
            {
                return Err(JournalError::UnsupportedVersion);
            }
            drop(legacy);
            SqliteJournalStore::migrate_from_sled(
                &legacy_path,
                &sqlite_path,
                &ready_marker,
                &[
                    "witness-records-v2",
                    "witness-operations-v2",
                    "witness-events-v2",
                    "witness-pending-v2",
                    "witness-meta-v2",
                    "witness-segments-v2",
                    "witness-sealed-segments-v2",
                ],
            )?;
        }
        let db = JournalDb::open(&sqlite_path)?;
        let journal = Self {
            root: config.root.clone(),
            records: db.open_tree("witness-records-v2"),
            operations: db.open_tree("witness-operations-v2"),
            events: db.open_tree("witness-events-v2"),
            pending: db.open_tree("witness-pending-v2"),
            meta: db.open_tree("witness-meta-v2"),
            segments: db.open_tree("witness-segments-v2"),
            sealed_segments: db.open_tree("witness-sealed-segments-v2"),
            db,
            journal_id: config.journal_id,
            epoch: AtomicU64::new(1),
            max_bytes: config.max_journal_bytes,
            reserve_total: config.cleanup_reserve_bytes,
            segment_bytes: config.segment_bytes,
            mode: config.mode,
            _lock: lock,
            coordinator: Mutex::new(()),
            faults,
            automation_stopped: AtomicBool::new(false),
            mirror_sequence: AtomicU64::new(0),
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
            let epoch = u64::from_be_bytes(
                epoch
                    .as_slice()
                    .try_into()
                    .map_err(|_| JournalError::Corrupt)?,
            );
            if epoch == 0 {
                return Err(JournalError::Corrupt);
            }
            self.epoch.store(epoch, Ordering::Release);
            let stored_reserve = self
                .meta
                .get(RESERVE)?
                .ok_or(JournalError::AutomationStopped)?;
            let stored_reserve = u64::from_be_bytes(
                stored_reserve
                    .as_slice()
                    .try_into()
                    .map_err(|_| JournalError::AutomationStopped)?,
            );
            let total = self.meta.get(RESERVE_TOTAL)?.ok_or(JournalError::Corrupt)?;
            let total = u64::from_be_bytes(
                total
                    .as_slice()
                    .try_into()
                    .map_err(|_| JournalError::Corrupt)?,
            );
            let max = self.meta.get(MAX_BYTES)?.ok_or(JournalError::Corrupt)?;
            let max = u64::from_be_bytes(
                max.as_slice()
                    .try_into()
                    .map_err(|_| JournalError::Corrupt)?,
            );
            if total != self.reserve_total || max != self.max_bytes {
                return Err(JournalError::Corrupt);
            }
            let reserve = self.reserve_file()?;
            if reserve.metadata()?.len() != stored_reserve {
                return Err(JournalError::AutomationStopped);
            }
            self.repair_read_mirror();
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
        self.repair_read_mirror();
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
        record.epoch = self.epoch.load(Ordering::Acquire);
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
        self.db.transaction(|transaction| {
            if transaction.get(self.meta.name(), HEAD_SEQUENCE)?.as_deref()
                != Some(expected_head.as_slice())
            {
                return Err(JournalError::Corrupt);
            }
            if transaction.get(self.operations.name(), &id.0)?.is_some() {
                return Err(JournalError::DuplicateOperation);
            }
            if transaction
                .get(self.events.name(), &record.event_id)?
                .is_some()
            {
                return Err(JournalError::DuplicateEvent);
            }
            transaction.put(self.records.name(), &seq_key, bytes.as_ref())?;
            transaction.put(self.events.name(), &record.event_id, &seq_key)?;
            transaction.put(self.operations.name(), &id.0, operation.as_slice())?;
            transaction.put(self.pending.name(), &id.0, &pending_value[..])?;
            transaction.put(self.meta.name(), HEAD_SEQUENCE, &seq_key)?;
            transaction.put(self.meta.name(), HEAD_HASH, &next_hash)?;
            Ok(())
        })?;
        self.flush(FlushBoundary::Received, id)?;
        crate::observability::authorization_metrics()
            .record(crate::observability::AuthorizationMetric::PendingIntent);
        self.update_read_mirror_best_effort();
        self.post_ack_rotation();
        Ok(())
    }

    pub fn append_decision(
        &self,
        id: OperationId,
        mut record: WitnessRecord,
    ) -> Result<DurableIntent, JournalError> {
        record.epoch = self.epoch.load(Ordering::Acquire);
        if record.stage != WitnessStage::Decision {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Decision)?;
        let pending = self.pending.get(id.0)?.ok_or(JournalError::NotPending)?;
        let (generation, recipe) = RecoveryRecipe::decode(&pending).ok_or(JournalError::Corrupt)?;
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
        self.update_read_mirror_best_effort();
        self.post_ack_rotation();
        Ok(DurableIntent {
            journal_id: self.journal_id,
            epoch: self.epoch.load(Ordering::Acquire),
            operation_id: id,
            execution_generation: generation,
            pending_generation: state.pending_generation,
            decision_id,
            decision_digest,
            request_digest: state.request_digest,
            precondition_digest: *recipe.precondition_digest(),
            recovery_recipe_digest: sha2::Sha256::digest(
                [
                    b"ferrocrate.recovery-recipe.v1\0".as_slice(),
                    pending.as_ref(),
                ]
                .concat(),
            )
            .into(),
        })
    }

    pub fn deny(
        &self,
        id: OperationId,
        mut decision: WitnessRecord,
        mut denied: WitnessRecord,
    ) -> Result<(), JournalError> {
        let epoch = self.epoch.load(Ordering::Acquire);
        decision.epoch = epoch;
        denied.epoch = epoch;
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
        self.db.transaction(|transaction| {
            if transaction.get(self.meta.name(), HEAD_SEQUENCE)?.as_deref()
                != Some(expected_head.as_slice())
            {
                return Err(JournalError::Corrupt);
            }
            if transaction
                .get(self.events.name(), &decision.event_id)?
                .is_some()
                || transaction
                    .get(self.events.name(), &denied.event_id)?
                    .is_some()
                || decision.event_id == denied.event_id
            {
                return Err(JournalError::DuplicateEvent);
            }
            transaction.put(self.records.name(), &first_key, decision_bytes.as_ref())?;
            transaction.put(self.records.name(), &terminal_key, denied_bytes.as_ref())?;
            transaction.put(self.events.name(), &decision.event_id, &first_key)?;
            transaction.put(self.events.name(), &denied.event_id, &terminal_key)?;
            transaction.put(self.operations.name(), &id.0, terminal_state.as_slice())?;
            transaction.remove(self.pending.name(), &id.0)?;
            transaction.put(self.meta.name(), HEAD_SEQUENCE, &terminal_key)?;
            transaction.put(self.meta.name(), HEAD_HASH, &terminal_hash)?;
            Ok(())
        })?;
        self.flush(FlushBoundary::Decision, id)?;
        self.update_read_mirror_best_effort();
        self.post_ack_rotation();
        Ok(())
    }

    pub fn complete(
        &self,
        intent: DurableIntent,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        record.epoch = self.epoch.load(Ordering::Acquire);
        if record.stage != WitnessStage::Outcome {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Outcome)?;
        let id = intent.operation_id;
        if intent.journal_id != self.journal_id
            || intent.epoch != self.epoch.load(Ordering::Acquire)
        {
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
            crate::observability::authorization_metrics().record(
                crate::observability::AuthorizationMetric::Recovery(
                    crate::observability::RecoveryMetric::OutcomeUnknown,
                ),
            );
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
        self.db.transaction(|transaction| {
            if transaction.get(self.meta.name(), HEAD_SEQUENCE)?.as_deref()
                != Some(expected_head.as_slice())
            {
                return Err(JournalError::Corrupt);
            }
            if transaction.get(self.pending.name(), &id.0)?.is_none() {
                return Err(JournalError::AlreadyComplete);
            }
            if transaction
                .get(self.events.name(), &record.event_id)?
                .is_some()
            {
                return Err(JournalError::DuplicateEvent);
            }
            transaction.put(self.records.name(), &seq_key, bytes.as_ref())?;
            transaction.put(self.events.name(), &record.event_id, &seq_key)?;
            let mut terminal = state.clone();
            let unknown = record.outcome == super::WitnessOutcome::OutcomeUnknown;
            terminal.state = if unknown { UNKNOWN } else { COMPLETE };
            terminal.unknown_event_id = if unknown { record.event_id } else { [0; 16] };
            terminal.pending_generation += 1;
            transaction.put(self.operations.name(), &id.0, &terminal.encode())?;
            if !unknown {
                transaction.remove(self.pending.name(), &id.0)?;
            }
            transaction.put(self.meta.name(), HEAD_SEQUENCE, &seq_key)?;
            transaction.put(self.meta.name(), HEAD_HASH, &next_hash)?;
            Ok(())
        })?;
        if forced_unknown {
            self.update_read_mirror_best_effort();
            Err(JournalError::Indeterminate { operation_id: id })
        } else {
            self.flush(FlushBoundary::Outcome, id)?;
            if record.outcome == super::WitnessOutcome::OutcomeUnknown {
                crate::observability::authorization_metrics().record(
                    crate::observability::AuthorizationMetric::Recovery(
                        crate::observability::RecoveryMetric::OutcomeUnknown,
                    ),
                );
            }
            self.update_read_mirror_best_effort();
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
        self.db.transaction(|transaction| {
            if transaction.get(self.meta.name(), HEAD_SEQUENCE)?.as_deref()
                != Some(expected_head.as_slice())
            {
                return Err(JournalError::Corrupt);
            }
            if transaction
                .get(self.events.name(), &record.event_id)?
                .is_some()
            {
                return Err(JournalError::DuplicateEvent);
            }
            transaction.put(self.records.name(), &seq_key, bytes.as_ref())?;
            transaction.put(self.events.name(), &record.event_id, &seq_key)?;
            transaction.put(self.operations.name(), &id.0, operation.as_slice())?;
            transaction.put(self.meta.name(), HEAD_SEQUENCE, &seq_key)?;
            transaction.put(self.meta.name(), HEAD_HASH, &next_hash)?;
            Ok(())
        })?;
        Ok(next_hash)
    }

    fn repair_read_mirror(&self) {
        if self.rebuild_read_mirror().is_err() {
            self.mark_reader_stale();
        }
    }

    fn rebuild_read_mirror(&self) -> Result<(), JournalError> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let has_segments = fs::read_dir(&self.root)?
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(super::reader::READER_SEGMENT_PREFIX)
            });
        if has_segments {
            let mut reader = super::WitnessReader::open_read_only(&self.root, self.journal_id)?;
            let mut last = 0;
            while let Some(bytes) = reader.next_record()? {
                last = decode_record(&bytes)?.sequence();
            }
            reader.finish()?;
            self.mirror_sequence.store(last, Ordering::Release);
            self.append_read_mirror()?;
            let _ = fs::remove_file(self.root.join("witness.reader-stale"));
            return Ok(());
        }

        let records = self.records()?;
        let temporary = self.root.join(".witness.readonly-v2.tmp");
        let target = self.root.join(super::reader::READER_FILE);
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(super::reader::READER_MAGIC)?;
        file.write_all(&self.journal_id)?;
        let mut last = 0;
        for bytes in &records {
            let decoded = decode_record(bytes)?;
            last = decoded.sequence();
            file.write_all(&decoded.sequence().to_be_bytes())?;
            file.write_all(&(bytes.len() as u32).to_be_bytes())?;
            file.write_all(bytes)?;
        }
        file.sync_all()?;
        fs::rename(&temporary, &target)?;
        File::open(&self.root)?.sync_all()?;
        self.mirror_sequence.store(last, Ordering::Release);
        let _ = fs::remove_file(self.root.join("witness.reader-stale"));
        Ok(())
    }

    fn update_read_mirror_best_effort(&self) {
        if self.append_read_mirror().is_err() {
            self.mark_reader_stale();
        }
    }

    fn append_read_mirror(&self) -> Result<(), JournalError> {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let first = self
            .mirror_sequence
            .load(Ordering::Acquire)
            .saturating_add(1);
        let (head, _) = self.head()?;
        if first > head {
            return Ok(());
        }
        let active = self.root.join(super::reader::READER_FILE);
        let mut options = OpenOptions::new();
        options.append(true);
        #[cfg(unix)]
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
        let mut file = options.open(&active)?;
        for sequence in first..=head {
            let bytes = self
                .records
                .get(sequence.to_be_bytes())?
                .ok_or(JournalError::Corrupt)?;
            let mut frame = Vec::with_capacity(12 + bytes.len());
            frame.extend_from_slice(&sequence.to_be_bytes());
            frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            frame.extend_from_slice(&bytes);
            if file.metadata()?.len() > 24
                && file.metadata()?.len().saturating_add(frame.len() as u64)
                    > read_mirror_segment_limit()
            {
                file.sync_all()?;
                drop(file);
                self.rotate_read_mirror(&active, sequence.saturating_sub(1))?;
                file = options.open(&active)?;
            }
            file.write_all(&frame)?;
        }
        file.sync_all()?;
        self.mirror_sequence.store(head, Ordering::Release);
        Ok(())
    }

    fn rotate_read_mirror(&self, active: &std::path::Path, last: u64) -> Result<(), JournalError> {
        use std::io::Read;
        #[cfg(unix)]
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut source = File::open(active)?;
        let mut header = [0_u8; 32];
        source.read_exact(&mut header)?;
        let first = u64::from_be_bytes(
            header[24..32]
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        if first == 0 || last < first {
            return Err(JournalError::Corrupt);
        }
        let segment = self.root.join(format!(
            "{}{first}-{last}",
            super::reader::READER_SEGMENT_PREFIX
        ));
        fs::rename(active, &segment)?;
        #[cfg(unix)]
        fs::set_permissions(&segment, fs::Permissions::from_mode(0o400))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut next = options.open(active)?;
        next.write_all(super::reader::READER_MAGIC)?;
        next.write_all(&self.journal_id)?;
        next.sync_all()?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn mark_reader_stale(&self) {
        let path = self.root.join("witness.reader-stale");
        if let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(&path) {
            let _ = file.write_all(b"reader mirror requires explicit maintenance repair\n");
            let _ = file.sync_all();
            let _ = File::open(&self.root).and_then(|directory| directory.sync_all());
        }
    }
}

#[cfg(not(test))]
const fn read_mirror_segment_limit() -> u64 {
    128 * 1024 * 1024
}

#[cfg(test)]
const fn read_mirror_segment_limit() -> u64 {
    4 * 1024
}

#[cfg(test)]
mod epoch_lock_tests {
    use super::*;
    use crate::witness::{Invocation, PrincipalSummary, ResourceSummary, WitnessResourceKind};
    use std::sync::{Arc, Barrier};

    fn publication() -> WitnessRecord {
        WitnessRecord {
            epoch: 1,
            sequence: 1,
            previous_hash: [0; 32],
            event_id: [1; 16],
            request_id: [2; 16],
            runtime_instance_id: [3; 16],
            boot_id: [4; 16],
            principal: PrincipalSummary::pseudonymize(&[5; 32], b"coordinator").unwrap(),
            invocation: Invocation::Manager,
            action: WitnessAction::CheckpointPublish,
            resource_kind: WitnessResourceKind::Administrative,
            resource: ResourceSummary::pseudonymize(&[6; 32], b"checkpoint").unwrap(),
            resource_generation: 1,
            policy_version: 0,
            policy_digest: [0; 32],
            decision_id: None,
            rule: None,
            decision: None,
            reason: None,
            request_digest: [7; 32],
            result_digest: Some([8; 32]),
            wall_time_ns: 0,
            monotonic_ns: 0,
            stage: WitnessStage::CheckpointPublished,
            outcome: WitnessOutcome::Succeeded,
            recovery_link: None,
            path_class: None,
            device_class: None,
            correlation_digest: None,
        }
    }

    #[test]
    fn read_mirror_failure_marks_stale_without_misreporting_durable_append() {
        let root = tempfile::tempdir().unwrap();
        let journal = WitnessJournal::open(JournalConfig::new(
            root.path(),
            [0x61; 16],
            JournalMode::Required,
        ))
        .unwrap();
        fs::remove_file(root.path().join(super::super::reader::READER_FILE)).unwrap();
        fs::create_dir(root.path().join(super::super::reader::READER_FILE)).unwrap();

        journal
            .append_checkpoint_publication([8; 32], publication())
            .unwrap();

        assert_eq!(journal.records().unwrap().len(), 1);
        assert!(root.path().join("witness.reader-stale").is_file());
    }

    #[test]
    fn read_only_mirror_rejects_a_broken_record_hash_chain() {
        let root = tempfile::tempdir().unwrap();
        let journal = WitnessJournal::open(JournalConfig::new(
            root.path(),
            [0x62; 16],
            JournalMode::Required,
        ))
        .unwrap();
        journal
            .append_checkpoint_publication([8; 32], publication())
            .unwrap();
        let mut second = publication();
        second.event_id = [9; 16];
        second.request_id = [10; 16];
        journal
            .append_checkpoint_publication([9; 32], second)
            .unwrap();

        let mirror = root.path().join(super::super::reader::READER_FILE);
        let mut bytes = fs::read(&mirror).unwrap();
        let first_len = u32::from_be_bytes(bytes[32..36].try_into().unwrap()) as usize;
        let second_record = 24 + 12 + first_len + 12;
        let previous_hash = second_record + 2 + 16 + 8 + 8;
        bytes[previous_hash] ^= 0x80;
        fs::write(&mirror, bytes).unwrap();

        let mut reader =
            super::super::WitnessReader::open_read_only(root.path(), [0x62; 16]).unwrap();
        assert!(reader.next_record().unwrap().is_some());
        assert!(matches!(reader.next_record(), Err(JournalError::Corrupt)));
    }

    #[test]
    fn read_mirror_rotates_bounded_segments_and_reader_rejects_a_gap() {
        let root = tempfile::tempdir().unwrap();
        let journal = WitnessJournal::open(JournalConfig::new(
            root.path(),
            [0x63; 16],
            JournalMode::Required,
        ))
        .unwrap();
        for index in 1_u8..=40 {
            let mut record = publication();
            record.event_id = [index; 16];
            record.request_id = [index.wrapping_add(80); 16];
            journal
                .append_checkpoint_publication([index; 32], record)
                .unwrap();
        }
        let segments: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(super::super::reader::READER_SEGMENT_PREFIX)
            })
            .collect();
        assert!(segments.len() > 1);
        assert!(segments
            .iter()
            .all(|entry| entry.metadata().unwrap().len() <= read_mirror_segment_limit()));
        let mut reader =
            super::super::WitnessReader::open_read_only(root.path(), [0x63; 16]).unwrap();
        assert_eq!(reader.records().count(), 40);
        reader.finish().unwrap();

        drop(journal);
        let reopened = WitnessJournal::open(JournalConfig::new(
            root.path(),
            [0x63; 16],
            JournalMode::Required,
        ))
        .unwrap();
        drop(reopened);

        fs::remove_file(segments.first().unwrap().path()).unwrap();
        let mut reader =
            super::super::WitnessReader::open_read_only(root.path(), [0x63; 16]).unwrap();
        let mut rejected = false;
        loop {
            match reader.next_record() {
                Err(JournalError::Corrupt) => {
                    rejected = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        assert!(rejected);
    }

    #[test]
    fn read_only_snapshot_remains_bounded_across_concurrent_rotation() {
        let root = tempfile::tempdir().unwrap();
        let journal = WitnessJournal::open(JournalConfig::new(
            root.path(),
            [0x64; 16],
            JournalMode::Required,
        ))
        .unwrap();
        let mut first = publication();
        first.event_id = [41; 16];
        first.request_id = [42; 16];
        journal
            .append_checkpoint_publication([41; 32], first)
            .unwrap();
        let mut reader =
            super::super::WitnessReader::open_read_only(root.path(), [0x64; 16]).unwrap();

        for index in 43_u8..=80 {
            let mut record = publication();
            record.event_id = [index; 16];
            record.request_id = [index.wrapping_add(90); 16];
            journal
                .append_checkpoint_publication([index; 32], record)
                .unwrap();
        }

        assert_eq!(reader.records().count(), 1);
        reader.finish().unwrap();
        let mut current =
            super::super::WitnessReader::open_read_only(root.path(), [0x64; 16]).unwrap();
        assert_eq!(current.records().count(), 39);
        current.finish().unwrap();
    }

    #[test]
    fn epoch_advance_wins_before_checkpoint_append_lock() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                dir.path(),
                [91; 16],
                JournalMode::Required,
            ))
            .unwrap(),
        );
        let reached = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *CHECKPOINT_LOCK_HOOK
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .unwrap() = Some((reached.clone(), release.clone()));
        let worker_journal = journal.clone();
        let worker = std::thread::spawn(move || {
            worker_journal.append_checkpoint_publication([8; 32], publication())
        });
        reached.wait();
        assert_eq!(journal.advance_epoch(1).unwrap(), 2);
        release.wait();
        assert!(matches!(
            worker.join().unwrap(),
            Err(JournalError::ProofMismatch)
        ));
        *CHECKPOINT_LOCK_HOOK.get().unwrap().lock().unwrap() = None;
        assert!(journal.records().unwrap().is_empty());
    }
}
