use super::{
    FaultPoint, FlushBoundary, JournalError, WitnessJournal, AUTOMATION_STOPPED, RESERVE,
    RESERVE_INFLIGHT,
};
use sled::transaction::Transactional;

impl WitnessJournal {
    pub(super) fn ensure_user_capacity(&self, additional: u64) -> Result<(), JournalError> {
        let used = self.records.iter().try_fold(0_u64, |sum, entry| {
            let (_, bytes) = entry?;
            Ok::<_, sled::Error>(sum.saturating_add(bytes.len() as u64))
        })?;
        self.prepare_segment(used, additional)?;
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

    pub(super) fn begin_cleanup_reservation(
        &self,
        id: crate::witness::OperationId,
        bytes: u64,
    ) -> Result<u64, JournalError> {
        if self.meta.get(RESERVE_INFLIGHT)?.is_some()
            || self.meta.get(AUTOMATION_STOPPED)?.is_some()
        {
            return Err(JournalError::AutomationStopped);
        }
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
        let used = self.records.iter().try_fold(0_u64, |sum, entry| {
            let (_, value) = entry?;
            Ok::<_, sled::Error>(sum.saturating_add(value.len() as u64))
        })?;
        self.prepare_segment(used, bytes)?;
        let Some(next) = remaining.checked_sub(bytes) else {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        };
        let mut reservation = [0_u8; 24];
        reservation[..16].copy_from_slice(id.as_bytes());
        reservation[16..].copy_from_slice(&bytes.to_be_bytes());
        self.meta.insert(RESERVE_INFLIGHT, &reservation)?;
        self.db
            .flush()
            .map_err(|_| JournalError::AutomationStopped)?;
        if self
            .faults
            .take(FaultPoint::AfterFlush(FlushBoundary::Reserve))
        {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
        Ok(next)
    }

    pub(super) fn finish_cleanup_reservation(&self, remaining: u64) -> Result<(), JournalError> {
        let reserve = self.reserve_file()?;
        if reserve
            .set_len(remaining)
            .and_then(|_| reserve.sync_all())
            .is_err()
        {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
        Ok(())
    }

    fn stop_automation(&self) {
        let _ = self.meta.insert(AUTOMATION_STOPPED, &[1_u8]);
        let _ = self.db.flush();
    }

    fn prepare_segment(&self, used: u64, additional: u64) -> Result<(), JournalError> {
        let start = self
            .meta
            .get(super::SEGMENT_START_BYTES)?
            .ok_or(JournalError::Corrupt)?;
        let start = u64::from_be_bytes(
            start
                .as_ref()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        if used.saturating_sub(start).saturating_add(additional) <= self.segment_bytes {
            return Ok(());
        }
        let current = self
            .meta
            .get(super::CURRENT_SEGMENT)?
            .ok_or(JournalError::Corrupt)?;
        let next = u64::from_be_bytes(
            current
                .as_ref()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        )
        .checked_add(1)
        .ok_or(JournalError::Corrupt)?;
        let (sequence, hash) = self.head()?;
        let mut handoff = [0_u8; 40];
        handoff[..8].copy_from_slice(&(sequence + 1).to_be_bytes());
        handoff[8..].copy_from_slice(&hash);
        (&self.segments, &self.meta)
            .transaction(|(segments, meta)| {
                if segments.get(next.to_be_bytes())?.is_some() {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        JournalError::Corrupt,
                    ));
                }
                segments.insert(&next.to_be_bytes(), handoff.as_slice())?;
                meta.insert(super::CURRENT_SEGMENT, &next.to_be_bytes())?;
                meta.insert(super::SEGMENT_START_BYTES, &used.to_be_bytes())?;
                Ok(())
            })
            .map_err(super::transaction_error)?;
        self.db.flush()?;
        Ok(())
    }
}
