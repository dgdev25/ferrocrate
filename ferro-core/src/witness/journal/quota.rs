use super::{
    FaultPoint, FlushBoundary, JournalError, WitnessJournal, AUTOMATION_STOPPED, RESERVE,
    RESERVE_INFLIGHT,
};
use sled::transaction::Transactional;
use std::sync::atomic::Ordering;

impl WitnessJournal {
    pub(super) fn ensure_user_capacity(&self, additional: u64) -> Result<(), JournalError> {
        let used = self.records.iter().try_fold(0_u64, |sum, entry| {
            let (_, bytes) = entry?;
            Ok::<_, sled::Error>(sum.saturating_add(bytes.len() as u64))
        })?;
        let sealed = self.sealed_segments.iter().try_fold(0_u64, |sum, entry| {
            let (_, value) = entry?;
            Ok::<_, sled::Error>(sum.saturating_add(value.len() as u64))
        })?;
        let user_limit = self
            .max_bytes
            .checked_sub(self.reserve_total)
            .ok_or(JournalError::QuotaExceeded)?;
        if used.saturating_add(sealed).saturating_add(additional) > user_limit {
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
        if self.automation_stopped.load(Ordering::Acquire)
            || self.meta.get(RESERVE_INFLIGHT)?.is_some()
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
        let Some(next) = remaining.checked_sub(bytes) else {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        };
        let mut reservation = [0_u8; 24];
        reservation[..16].copy_from_slice(id.as_bytes());
        reservation[16..].copy_from_slice(&bytes.to_be_bytes());
        self.meta.insert(RESERVE_INFLIGHT, &reservation)?;
        if self.db.flush().is_err() {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
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
        if self.meta.remove(RESERVE_INFLIGHT).is_err() || self.db.flush().is_err() {
            self.stop_automation();
            return Err(JournalError::AutomationStopped);
        }
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

    pub(super) fn stop_automation(&self) {
        self.automation_stopped.store(true, Ordering::Release);
        let _ = self.meta.insert(AUTOMATION_STOPPED, &[1_u8]);
        let _ = self.db.flush();
        let marker = self.root.join("witness.automation-stopped");
        if let Ok(file) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(marker)
        {
            let _ = file.sync_all();
        }
    }

    pub(super) fn seal_active_segment(&self) -> Result<(), JournalError> {
        let entries: Vec<_> = self.records.iter().collect::<Result<_, _>>()?;
        let used: u64 = entries.iter().map(|(_, value)| value.len() as u64).sum();
        if used <= self.segment_bytes {
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
        let current_id = u64::from_be_bytes(
            current
                .as_ref()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        );
        let (sequence, hash) = self.head()?;
        let mut handoff = [0_u8; 40];
        handoff[..8].copy_from_slice(&(sequence + 1).to_be_bytes());
        handoff[8..].copy_from_slice(&hash);
        let mut blob = Vec::new();
        for (key, value) in &entries {
            blob.extend_from_slice(key);
            blob.extend_from_slice(&(value.len() as u32).to_be_bytes());
            blob.extend_from_slice(value);
        }
        (
            &self.records,
            &self.segments,
            &self.sealed_segments,
            &self.meta,
        )
            .transaction(|(records, segments, sealed, meta)| {
                if segments.get(next.to_be_bytes())?.is_some() {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        JournalError::Corrupt,
                    ));
                }
                if sealed.get(current_id.to_be_bytes())?.is_some() {
                    return Err(sled::transaction::ConflictableTransactionError::Abort(
                        JournalError::Corrupt,
                    ));
                }
                sealed.insert(&current_id.to_be_bytes(), blob.as_slice())?;
                for (key, _) in &entries {
                    records.remove(key.as_ref())?;
                }
                segments.insert(&next.to_be_bytes(), handoff.as_slice())?;
                meta.insert(super::CURRENT_SEGMENT, &next.to_be_bytes())?;
                Ok(())
            })
            .map_err(super::transaction_error)?;
        self.db.flush()?;
        Ok(())
    }
}
