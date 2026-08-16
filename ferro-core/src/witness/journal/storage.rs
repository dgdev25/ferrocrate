use super::{FaultPoint, FlushBoundary, JournalError, WitnessJournal};
use crate::observability::{authorization_metrics, AuthorizationMetric, JournalMetric};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::sync::{Arc, Mutex};
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

/// SQLite key/value storage used by the witness-journal cutover.
///
/// The journal deliberately keeps its existing tree names and byte keys. This
/// makes migration auditable and lets the operation layer retain its current
/// serialization while the remaining multi-tree transaction adapter is wired.
#[derive(Clone)]
pub(super) struct SqliteJournalStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteJournalStore {
    pub(super) fn open(path: &Path) -> Result<Self, JournalError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                 tree TEXT NOT NULL,
                 key BLOB NOT NULL,
                 value BLOB NOT NULL,
                 PRIMARY KEY (tree, key)
             );
             CREATE INDEX IF NOT EXISTS kv_tree_key ON kv(tree, key);",
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Copy a legacy sled tree set into SQLite in one durable transaction.
    /// The ready marker is created only after SQLite commits, so an interrupted
    /// copy can be retried without treating a partial database as authoritative.
    pub(super) fn migrate_from_sled(
        sled_path: &Path,
        sqlite_path: &Path,
        ready_marker: &Path,
        trees: &[&str],
    ) -> Result<(), JournalError> {
        if ready_marker.exists() {
            return if std::fs::read(ready_marker).ok().as_deref()
                == Some(b"witness-sqlite-ready-v1")
            {
                Ok(())
            } else {
                Err(JournalError::Corrupt)
            };
        }
        let legacy = sled::open(sled_path)?;
        let store = Self::open(sqlite_path)?;
        store.transaction(|transaction| {
            for tree_name in trees {
                let tree = legacy.open_tree(tree_name)?;
                for entry in tree.iter() {
                    let (key, value) = entry?;
                    transaction.put(tree_name, &key, &value)?;
                }
            }
            Ok(())
        })?;
        let temporary = ready_marker.with_extension("ready.tmp");
        let mut marker = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        marker.write_all(b"witness-sqlite-ready-v1")?;
        marker.sync_all()?;
        std::fs::rename(&temporary, ready_marker)?;
        if let Some(parent) = ready_marker.parent() {
            if let Ok(directory) = File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(())
    }

    pub(super) fn get(&self, tree: &str, key: &[u8]) -> Result<Option<Vec<u8>>, JournalError> {
        let connection = self.connection.lock().map_err(|_| JournalError::Corrupt)?;
        Ok(connection
            .query_row(
                "SELECT value FROM kv WHERE tree = ?1 AND key = ?2",
                params![tree, key],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(super) fn put(&self, tree: &str, key: &[u8], value: &[u8]) -> Result<(), JournalError> {
        let connection = self.connection.lock().map_err(|_| JournalError::Corrupt)?;
        connection.execute(
            "INSERT INTO kv(tree, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(tree, key) DO UPDATE SET value = excluded.value",
            params![tree, key, value],
        )?;
        Ok(())
    }

    pub(super) fn remove(&self, tree: &str, key: &[u8]) -> Result<(), JournalError> {
        let connection = self.connection.lock().map_err(|_| JournalError::Corrupt)?;
        connection.execute(
            "DELETE FROM kv WHERE tree = ?1 AND key = ?2",
            params![tree, key],
        )?;
        Ok(())
    }

    pub(super) fn scan(&self, tree: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>, JournalError> {
        let connection = self.connection.lock().map_err(|_| JournalError::Corrupt)?;
        let mut statement =
            connection.prepare("SELECT key, value FROM kv WHERE tree = ?1 ORDER BY key")?;
        let rows = statement.query_map(params![tree], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(JournalError::from)
    }

    /// Run one callback against a single SQLite transaction and connection.
    ///
    /// Keeping the connection borrowed for the complete callback prevents a
    /// tree operation from accidentally committing independently of its
    /// sibling updates.
    pub(super) fn transaction<T>(
        &self,
        callback: impl for<'tx> FnOnce(&SqliteTransaction<'tx>) -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        let mut connection = self.connection.lock().map_err(|_| JournalError::Corrupt)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let context = SqliteTransaction { transaction };
        match callback(&context) {
            Ok(value) => {
                context.transaction.commit()?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }
}

pub(super) struct SqliteTransaction<'tx> {
    transaction: rusqlite::Transaction<'tx>,
}

impl SqliteTransaction<'_> {
    pub(super) fn get(&self, tree: &str, key: &[u8]) -> Result<Option<Vec<u8>>, JournalError> {
        Ok(self
            .transaction
            .query_row(
                "SELECT value FROM kv WHERE tree = ?1 AND key = ?2",
                params![tree, key],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(super) fn put(&self, tree: &str, key: &[u8], value: &[u8]) -> Result<(), JournalError> {
        self.transaction.execute(
            "INSERT INTO kv(tree, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(tree, key) DO UPDATE SET value = excluded.value",
            params![tree, key, value],
        )?;
        Ok(())
    }

    pub(super) fn remove(&self, tree: &str, key: &[u8]) -> Result<(), JournalError> {
        self.transaction.execute(
            "DELETE FROM kv WHERE tree = ?1 AND key = ?2",
            params![tree, key],
        )?;
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct JournalTree {
    store: SqliteJournalStore,
    name: &'static str,
}

impl JournalTree {
    pub(super) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, JournalError> {
        self.store.get(self.name, key.as_ref())
    }

    pub(super) fn insert(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<Option<Vec<u8>>, JournalError> {
        let previous = self.get(key.as_ref())?;
        self.store.put(self.name, key.as_ref(), value.as_ref())?;
        Ok(previous)
    }

    pub(super) fn remove(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, JournalError> {
        let previous = self.get(key.as_ref())?;
        self.store.remove(self.name, key.as_ref())?;
        Ok(previous)
    }

    pub(super) fn contains_key(&self, key: impl AsRef<[u8]>) -> Result<bool, JournalError> {
        Ok(self.get(key)?.is_some())
    }

    pub(super) fn iter(&self) -> JournalTreeIter {
        JournalTreeIter {
            entries: Some(self.store.scan(self.name)),
        }
    }

    pub(super) fn len(&self) -> Result<usize, JournalError> {
        Ok(self.store.scan(self.name)?.len())
    }

    pub(super) fn name(&self) -> &'static str {
        self.name
    }
}

pub(super) struct JournalTreeIter {
    entries: Option<Result<Vec<(Vec<u8>, Vec<u8>)>, JournalError>>,
}

impl Iterator for JournalTreeIter {
    type Item = Result<(Vec<u8>, Vec<u8>), JournalError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.entries.as_mut()? {
            Ok(entries) if entries.is_empty() => {
                self.entries = None;
                None
            }
            Ok(entries) => Some(Ok(entries.remove(0))),
            Err(_) => match self.entries.take() {
                Some(Err(error)) => Some(Err(error)),
                _ => None,
            },
        }
    }
}

pub(super) struct JournalDb {
    store: SqliteJournalStore,
}

impl JournalDb {
    pub(super) fn open(path: &Path) -> Result<Self, JournalError> {
        Ok(Self {
            store: SqliteJournalStore::open(path)?,
        })
    }

    pub(super) fn open_tree(&self, name: &'static str) -> JournalTree {
        JournalTree {
            store: self.store.clone(),
            name,
        }
    }

    pub(super) fn transaction<T>(
        &self,
        callback: impl for<'tx> FnOnce(&SqliteTransaction<'tx>) -> Result<T, JournalError>,
    ) -> Result<T, JournalError> {
        self.store.transaction(callback)
    }

    pub(super) fn flush(&self) -> Result<(), JournalError> {
        Ok(())
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
            u64::from_be_bytes(
                seq.as_slice()
                    .try_into()
                    .map_err(|_| JournalError::Corrupt)?,
            ),
            hash.as_slice()
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

#[cfg(test)]
mod sqlite_tests {
    use super::SqliteJournalStore;
    use tempfile::tempdir;

    #[test]
    fn sqlite_store_reopens_with_byte_stable_tree_entries() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("witness.sqlite3");
        let store = SqliteJournalStore::open(&path).unwrap();
        store
            .put("witness-meta-v2", b"head", &[0, 1, 2, 3])
            .unwrap();
        store
            .put("witness-records-v2", &[0, 0, 0, 1], b"record")
            .unwrap();
        drop(store);

        let reopened = SqliteJournalStore::open(&path).unwrap();
        assert_eq!(
            reopened.get("witness-meta-v2", b"head").unwrap(),
            Some(vec![0, 1, 2, 3])
        );
        assert_eq!(
            reopened.scan("witness-records-v2").unwrap(),
            vec![(vec![0, 0, 0, 1], b"record".to_vec())]
        );
        reopened.remove("witness-meta-v2", b"head").unwrap();
        assert_eq!(reopened.get("witness-meta-v2", b"head").unwrap(), None);
    }

    #[test]
    fn sqlite_store_transaction_rolls_back_all_tree_updates_on_error() {
        let directory = tempdir().unwrap();
        let store = SqliteJournalStore::open(&directory.path().join("witness.sqlite3")).unwrap();
        let result = store.transaction(|transaction| {
            transaction.put("records", b"one", b"record")?;
            transaction.put("meta", b"head", b"1")?;
            assert_eq!(transaction.get("meta", b"head")?, Some(b"1".to_vec()));
            transaction.remove("meta", b"head")?;
            Err::<(), _>(super::JournalError::Corrupt)
        });
        assert!(matches!(result, Err(super::JournalError::Corrupt)));
        assert_eq!(store.get("records", b"one").unwrap(), None);
        assert_eq!(store.get("meta", b"head").unwrap(), None);
    }

    #[test]
    fn sqlite_store_migrates_legacy_trees_before_marking_ready() {
        let directory = tempdir().unwrap();
        let sled_path = directory.path().join("witness.sled");
        let sqlite_path = directory.path().join("witness.sqlite3");
        let marker_path = directory.path().join("witness.sqlite3.ready");
        let legacy = sled::open(&sled_path).unwrap();
        legacy
            .open_tree("witness-meta-v2")
            .unwrap()
            .insert(b"head", b"1")
            .unwrap();
        legacy
            .open_tree("witness-records-v2")
            .unwrap()
            .insert([0, 0, 0, 1], b"record")
            .unwrap();
        legacy.flush().unwrap();
        drop(legacy);

        SqliteJournalStore::migrate_from_sled(
            &sled_path,
            &sqlite_path,
            &marker_path,
            &["witness-meta-v2", "witness-records-v2"],
        )
        .unwrap();
        assert_eq!(
            std::fs::read(&marker_path).unwrap(),
            b"witness-sqlite-ready-v1"
        );
        let store = SqliteJournalStore::open(&sqlite_path).unwrap();
        assert_eq!(
            store.get("witness-meta-v2", b"head").unwrap(),
            Some(b"1".to_vec())
        );
        assert_eq!(store.scan("witness-records-v2").unwrap().len(), 1);
    }
}
