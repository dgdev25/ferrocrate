use super::{
    state::{OperationState, COMPLETE, UNKNOWN},
    transaction_error, FlushBoundary, JournalError, WitnessJournal, HEAD_HASH, HEAD_SEQUENCE,
    RESERVE, RESERVE_INFLIGHT,
};
use crate::witness::{encode_record, hash_record, OperationId, WitnessRecord, WitnessStage};
use sled::transaction::{ConflictableTransactionError, Transactional};

impl WitnessJournal {
    pub fn complete_recovery(
        &self,
        id: OperationId,
        mut record: WitnessRecord,
    ) -> Result<(), JournalError> {
        if record.stage != WitnessStage::Recovery {
            return Err(JournalError::InvalidStage);
        }
        let _guard = self.coordinator.lock().map_err(|_| JournalError::Corrupt)?;
        self.preflight(FlushBoundary::Outcome)?;
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
                meta.remove(RESERVE_INFLIGHT)?;
                Ok(())
            })
            .map_err(transaction_error)?;
        self.flush(FlushBoundary::Outcome, id)?;
        self.finish_cleanup_reservation(reserve_after)
    }
}
