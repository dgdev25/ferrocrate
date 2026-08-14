use super::{FaultPoint, FlushBoundary, JournalError, WitnessJournal};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub(super) fn transaction_error(
    error: sled::transaction::TransactionError<JournalError>,
) -> JournalError {
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
        if self.faults.take(FaultPoint::BeforeTransaction(boundary))
            || self.faults.take(FaultPoint::Transaction(boundary))
        {
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
            return Err(JournalError::Indeterminate { operation_id: id });
        }
        if self.faults.take(FaultPoint::DuringFlush(boundary)) {
            let _ = self.db.flush();
            return Err(JournalError::Indeterminate { operation_id: id });
        }
        if self.db.flush().is_err() {
            let _ = self.operations.get(id.0);
            return Err(JournalError::Indeterminate { operation_id: id });
        }
        if self.faults.take(FaultPoint::AfterFlush(boundary)) {
            Err(JournalError::Indeterminate { operation_id: id })
        } else {
            Ok(())
        }
    }
}
