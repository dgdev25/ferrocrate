#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub restored_database_path: String,
    pub next_epoch: u64,
    pub rotate_issuing_ca: bool,
    pub expire_all_credentials: bool,
}

impl RecoveryPlan {
    pub fn restore_and_rekey(restored_database_path: impl Into<String>, current_epoch: u64) -> Self {
        Self {
            restored_database_path: restored_database_path.into(),
            next_epoch: current_epoch.saturating_add(1),
            rotate_issuing_ca: true,
            expire_all_credentials: true,
        }
    }
}

pub fn restore_backup(source: impl AsRef<Path>, destination: impl AsRef<Path>, reason: &str, now_unix_secs: i64) -> Result<RecoveryPlan, RecoveryError> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    if !source.is_file() { return Err(RecoveryError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "backup is not a regular file"))); }
    if destination.exists() { return Err(RecoveryError::DestinationExists); }
    let source_connection = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let temporary = destination.with_extension("restore.tmp");
    if temporary.exists() { return Err(RecoveryError::DestinationExists); }
    let escaped = temporary.to_string_lossy().replace('\'', "''");
    source_connection.execute_batch(&format!("VACUUM INTO '{}';", escaped))?;
    drop(source_connection);
    let restored = Connection::open(&temporary)?;
    let integrity: String = restored.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    drop(restored);
    if integrity != "ok" { let _ = fs::remove_file(&temporary); return Err(RecoveryError::Sql(rusqlite::Error::InvalidQuery)); }
    fs::rename(&temporary, destination)?;
    let store = ManagerStore::open(destination)?;
    let next_epoch = store.recover_after_restore(reason, now_unix_secs)?;
    Ok(RecoveryPlan { restored_database_path: destination.to_string_lossy().into_owned(), next_epoch, rotate_issuing_ca: true, expire_all_credentials: true })
}
use std::{fs, path::Path};

use rusqlite::{Connection, OpenFlags};
use thiserror::Error;

use crate::store::{ManagerStore, StoreError};

#[derive(Debug, Error)]
pub enum RecoveryError {
    #[error("backup file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("backup database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("destination database already exists")]
    DestinationExists,
    #[error(transparent)]
    Store(#[from] StoreError),
}
