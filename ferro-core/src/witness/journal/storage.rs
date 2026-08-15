use super::{FaultPoint, FlushBoundary, JournalError, WitnessJournal};
use crate::observability::{authorization_metrics, AuthorizationMetric, JournalMetric};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    time::Duration,
};

// A journal that has just been dropped in this process can briefly retain its
// advisory OS lock while the file descriptor teardown completes. Retry only
// that close-to-reopen hand-off; a live competing writer still fails closed.
const LOCK_HANDOFF_RETRIES: usize = 16;
const LOCK_HANDOFF_DELAY: Duration = Duration::from_millis(1);

pub(super) fn transaction_error(
    error: sled::transaction::TransactionError<JournalError>,
) -> JournalError {
    authorization_metrics().record(AuthorizationMetric::Journal(JournalMetric::AppendFailure));
    match error {
        sled::transaction::TransactionError::Abort(error) => error,
        sled::transaction::TransactionError::Storage(error) => JournalError::Storage(error),
    }
}

pub(super) fn lock_journal(root: &Path, journal_id: [u8; 16]) -> Result<File, JournalError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join("witness.lock"))?;
    for attempt in 0..=LOCK_HANDOFF_RETRIES {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if attempt < LOCK_HANDOFF_RETRIES => {
                std::thread::sleep(LOCK_HANDOFF_DELAY);
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(JournalError::Locked),
            Err(std::fs::TryLockError::Error(error)) => return Err(JournalError::Io(error)),
        }
    }
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

pub(super) fn path_entry_exists(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

impl WitnessJournal {
    pub(super) fn head(&self) -> Result<(u64, [u8; 32]), JournalError> {
        let seq = self
            .meta
            .get(super::HEAD_SEQUENCE)?
            .ok_or(JournalError::Corrupt)?;
        let hash = self
            .meta
            .get(super::HEAD_HASH)?
            .ok_or(JournalError::Corrupt)?;
        Ok((
            u64::from_be_bytes(seq.as_ref().try_into().map_err(|_| JournalError::Corrupt)?),
            hash.as_ref()
                .try_into()
                .map_err(|_| JournalError::Corrupt)?,
        ))
    }

    pub(super) fn preflight(&self, boundary: FlushBoundary) -> Result<(), JournalError> {
        if self.mode == super::JournalMode::Disabled {
            return Err(JournalError::Disabled);
        }
        if self.faults.take(FaultPoint::BeforeTransaction(boundary))
            || self.faults.take(FaultPoint::Transaction(boundary))
        {
            authorization_metrics()
                .record(AuthorizationMetric::Journal(JournalMetric::AppendFailure));
            Err(JournalError::UnavailableBeforeVisibility)
        } else {
            Ok(())
        }
    }
    pub(super) fn flush(
        &self,
        boundary: FlushBoundary,
        id: crate::witness::OperationId,
    ) -> Result<(), JournalError> {
        if self.faults.take(FaultPoint::BeforeFlush(boundary)) {
            authorization_metrics()
                .record(AuthorizationMetric::Journal(JournalMetric::FlushFailure));
            return Err(JournalError::Indeterminate { operation_id: id });
        }
        if self.faults.take(FaultPoint::DuringFlush(boundary)) {
            authorization_metrics()
                .record(AuthorizationMetric::Journal(JournalMetric::FlushFailure));
            return Err(JournalError::Indeterminate { operation_id: id });
        }
        if self.db.flush().is_err() {
            authorization_metrics()
                .record(AuthorizationMetric::Journal(JournalMetric::FlushFailure));
            let _ = self.operations.get(id.0);
            return Err(JournalError::Indeterminate { operation_id: id });
        }
        if self.faults.take(FaultPoint::AfterFlush(boundary)) {
            authorization_metrics()
                .record(AuthorizationMetric::Journal(JournalMetric::FlushFailure));
            Err(JournalError::Indeterminate { operation_id: id })
        } else {
            Ok(())
        }
    }
}
