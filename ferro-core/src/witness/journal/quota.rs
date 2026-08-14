use super::{FaultPoint, FlushBoundary, JournalError, WitnessJournal, RESERVE};

impl WitnessJournal {
    pub(super) fn ensure_user_capacity(&self, additional: u64) -> Result<(), JournalError> {
        let used = self.records.iter().try_fold(0_u64, |sum, entry| {
            let (_, bytes) = entry?;
            Ok::<_, sled::Error>(sum.saturating_add(bytes.len() as u64))
        })?;
        let user_limit = self
            .max_bytes
            .checked_sub(self.reserve_total)
            .ok_or(JournalError::QuotaExceeded)?;
        if used.saturating_add(additional) > user_limit {
            Err(JournalError::QuotaExceeded)
        } else {
            Ok(())
        }
    }

    pub(super) fn consume_cleanup_reserve(&self, bytes: u64) -> Result<(), JournalError> {
        let remaining = self
            .meta
            .get(RESERVE)?
            .ok_or(JournalError::AutomationStopped)?;
        let remaining = u64::from_be_bytes(
            remaining
                .as_ref()
                .try_into()
                .map_err(|_| JournalError::AutomationStopped)?,
        );
        let next = remaining
            .checked_sub(bytes)
            .ok_or(JournalError::AutomationStopped)?;
        let reserve = self.reserve_file()?;
        reserve.set_len(next)?;
        reserve.sync_all()?;
        self.meta.insert(RESERVE, &next.to_be_bytes())?;
        self.db
            .flush()
            .map_err(|_| JournalError::AutomationStopped)?;
        if self
            .faults
            .take(FaultPoint::AfterFlush(FlushBoundary::Reserve))
        {
            return Err(JournalError::AutomationStopped);
        }
        Ok(())
    }
}
