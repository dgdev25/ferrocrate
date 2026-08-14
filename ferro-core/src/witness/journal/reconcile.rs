use super::{
    state::{OperationState, ALLOWED, COMPLETE, UNKNOWN},
    transaction_error, FlushBoundary, JournalError, WitnessJournal, HEAD_HASH, HEAD_SEQUENCE,
    RESERVE,
};
use crate::witness::{encode_record, hash_record, OperationId, WitnessRecord, WitnessStage};
use sled::transaction::{ConflictableTransactionError, Transactional};
use std::sync::atomic::Ordering;

impl WitnessJournal {
    /// Record that an already-authorized execution generation may have changed
    /// external state after its terminal receipt could not be proven durable.
    /// This grants no authority to repeat the external action.
    pub fn record_outcome_unknown(
        &self,
        id: OperationId,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        if record.stage != WitnessStage::Outcome
            || record.outcome != crate::witness::WitnessOutcome::OutcomeUnknown
        {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Outcome)?;
        let mut state =
            OperationState::decode(&self.operations.get(id.0)?.ok_or(JournalError::NotPending)?)
                .ok_or(JournalError::Corrupt)?;
        if state.state == COMPLETE {
            self.flush(FlushBoundary::Outcome, id)?;
            return Err(JournalError::AlreadyComplete);
        }
        if state.state != ALLOWED || !state.terminal_matches(&record) {
            return Err(JournalError::BindingMismatch);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        self.ensure_user_capacity(bytes.as_ref().len() as u64)?;
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        state.state = UNKNOWN;
        state.unknown_event_id = record.event_id;
        state.pending_generation += 1;
        let state = state.encode();
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
                operations.insert(&id.0, state.as_slice())?;
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        self.flush(FlushBoundary::Outcome, id)?;
        self.post_ack_rotation();
        Ok(())
    }

    pub fn complete_recovery(
        &self,
        id: OperationId,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        if self.automation_stopped.load(Ordering::Acquire) {
            return Err(JournalError::AutomationStopped);
        }
        if record.stage != WitnessStage::Recovery {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        let state =
            OperationState::decode(&self.operations.get(id.0)?.ok_or(JournalError::NotPending)?)
                .ok_or(JournalError::Corrupt)?;
        if state.state != UNKNOWN
            || !state.terminal_matches(&record)
            || record.recovery_link != Some(state.unknown_event_id)
        {
            return Err(JournalError::BindingMismatch);
        }
        let (sequence, previous) = self.head()?;
        record.sequence = sequence + 1;
        record.previous_hash = previous;
        let bytes = encode_record(self.journal_id, &record)?;
        if self.events.contains_key(record.event_id)? {
            return Err(JournalError::DuplicateEvent);
        }
        let reserve_after = self.begin_cleanup_reservation(id, bytes.as_ref().len() as u64)?;
        if self
            .faults
            .take(super::FaultPoint::BeforeTransaction(FlushBoundary::Outcome))
            || self
                .faults
                .take(super::FaultPoint::Transaction(FlushBoundary::Outcome))
        {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
        let next_hash = hash_record(&bytes);
        let seq_key = record.sequence.to_be_bytes();
        let expected_head = sequence.to_be_bytes();
        let mut terminal = state;
        terminal.state = COMPLETE;
        terminal.pending_generation += 1;
        let terminal = terminal.encode();
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
                if events.get(record.event_id)?.is_some() {
                    return Err(ConflictableTransactionError::Abort(
                        JournalError::DuplicateEvent,
                    ));
                }
                records.insert(&seq_key, bytes.as_ref())?;
                events.insert(&record.event_id, &seq_key)?;
                operations.insert(&id.0, terminal.as_slice())?;
                pending.remove(&id.0)?;
                meta.insert(HEAD_SEQUENCE, &seq_key)?;
                meta.insert(HEAD_HASH, &next_hash)?;
                meta.insert(RESERVE, &reserve_after.to_be_bytes())?;
                Ok(())
            })
            .map_err(transaction_error)?;
        if self.flush(FlushBoundary::Outcome, id).is_err() {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
        self.finish_cleanup_reservation(reserve_after)?;
        self.post_ack_rotation();
        Ok(())
    }
}
