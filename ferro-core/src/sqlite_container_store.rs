//! SQLite-backed container and lifecycle store.
//!
//! This is the active runtime backend. The legacy sled store remains available
//! for explicit rollback/import tooling, but runtime state is published in one
//! SQLite transaction across container records and lifecycle operations.

use crate::container_store::{
    process_start_time, ContainerRecord, ContainerStoreError, LifecycleOperation, LifecyclePhase,
    MutationReservation,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CONTAINERS_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS containers (
    id TEXT PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL,
    name TEXT
);
CREATE TABLE IF NOT EXISTS lifecycle_operations (
    operation_id BLOB PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS container_name_claims (
    name TEXT PRIMARY KEY NOT NULL,
    container_id TEXT NOT NULL
);
"#;

#[derive(Clone)]
pub struct SqliteContainerStore {
    db: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl std::fmt::Debug for SqliteContainerStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteContainerStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteContainerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ContainerStoreError> {
        let requested = path.as_ref();
        let (sqlite_path, legacy_path) = if requested.is_dir() {
            (
                requested.join("containers.sqlite3"),
                Some(requested.to_path_buf()),
            )
        } else {
            (requested.to_path_buf(), None)
        };
        if let Some(parent) = sqlite_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Import a pre-existing sled directory once. The legacy source is
        // deliberately retained for rollback and audit comparison.
        if let Some(legacy_path) = legacy_path.as_ref() {
            let marker = legacy_path.join("containers.sqlite3.imported");
            if !sqlite_path.exists() && !marker.exists() && legacy_path.join("conf").exists() {
                return Err(ContainerStoreError::LegacyMigrationRequired);
            }
        }
        let mut connection = Connection::open(&sqlite_path)?;
        // Multiple CLI processes can start together during a parallel
        // workload. SQLite's default busy timeout is zero, so a concurrent
        // schema initialization would surface as a spurious `database is
        // locked` migration failure. Wait briefly for the initializer/writer
        // while retaining SQLite's transactional locking semantics.
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(CONTAINERS_SCHEMA)?;
        migrate_container_names(&mut connection)?;
        connection.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS containers_unique_name ON containers(name) WHERE name IS NOT NULL;",
        )?;
        // Keep the timeout in force after schema pragmas as well; SQLite
        // resets connection-level busy handlers when certain pragmas are
        // applied on older bundled builds.
        connection.execute_batch("PRAGMA busy_timeout = 5000;")?;
        let store = Self {
            db: Arc::new(Mutex::new(connection)),
            path: sqlite_path,
        };
        Ok(store)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, ContainerStoreError> {
        self.db.lock().map_err(|_| {
            ContainerStoreError::Lock("container SQLite connection lock poisoned".to_string())
        })
    }

    fn transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>) -> Result<T, ContainerStoreError>,
    ) -> Result<T, ContainerStoreError> {
        let mut connection = self.lock()?;
        // Acquire the write reservation before any reads. A deferred
        // transaction can deadlock when several lifecycle writers read the
        // same snapshot and then upgrade simultaneously, yielding an
        // immediate `database is locked` despite the busy timeout.
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = operation(&transaction)?;
        transaction.commit()?;
        Ok(value)
    }

    fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ContainerStoreError> {
        serde_json::to_vec(value).map_err(ContainerStoreError::Encode)
    }

    fn decode_record(payload: &[u8]) -> Result<ContainerRecord, ContainerStoreError> {
        serde_json::from_slice(payload).map_err(ContainerStoreError::Decode)
    }

    fn decode_operation(payload: &[u8]) -> Result<LifecycleOperation, ContainerStoreError> {
        serde_json::from_slice(payload).map_err(ContainerStoreError::Decode)
    }

    fn get_tx(
        transaction: &Transaction<'_>,
        id: &str,
    ) -> Result<Option<ContainerRecord>, ContainerStoreError> {
        let payload: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT payload FROM containers WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        payload.map(|bytes| Self::decode_record(&bytes)).transpose()
    }

    fn operation_tx(
        transaction: &Transaction<'_>,
        operation_id: [u8; 16],
    ) -> Result<Option<LifecycleOperation>, ContainerStoreError> {
        let payload: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT payload FROM lifecycle_operations WHERE operation_id = ?1",
                params![operation_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|bytes| Self::decode_operation(&bytes))
            .transpose()
    }

    fn claim_name_tx(
        transaction: &Transaction<'_>,
        name: &str,
        container_id: &str,
    ) -> Result<bool, ContainerStoreError> {
        let inserted = transaction.execute(
            "INSERT OR IGNORE INTO container_name_claims(name,container_id) VALUES (?1,?2)",
            params![name, container_id],
        )?;
        if inserted == 1 {
            return Ok(true);
        }
        let owner: String = transaction.query_row(
            "SELECT container_id FROM container_name_claims WHERE name=?1",
            params![name],
            |row| row.get(0),
        )?;
        if owner == container_id {
            Ok(false)
        } else {
            Err(ContainerStoreError::NameConflict {
                name: name.to_owned(),
                container_id: owner,
            })
        }
    }

    fn sync_record_name_tx(
        transaction: &Transaction<'_>,
        record: &ContainerRecord,
    ) -> Result<(), ContainerStoreError> {
        if let Some(name) = record.name.as_deref() {
            Self::claim_name_tx(transaction, name, &record.id)?;
        }
        transaction.execute(
            "DELETE FROM container_name_claims WHERE container_id=?1 AND (?2 IS NULL OR name<>?2)",
            params![record.id, record.name],
        )?;
        Ok(())
    }

    pub fn reserve_name(&self, name: &str, container_id: &str) -> Result<bool, ContainerStoreError> {
        self.transaction(|transaction| Self::claim_name_tx(transaction, name, container_id))
    }

    pub fn rename_reserved_name(
        &self,
        container_id: &str,
        name: &str,
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            Self::claim_name_tx(transaction, name, container_id)?;
            transaction.execute(
                "DELETE FROM container_name_claims WHERE container_id=?1 AND name<>?2",
                params![container_id, name],
            )?;
            Ok(())
        })
    }

    pub fn release_reserved_name(&self, container_id: &str) -> Result<(), ContainerStoreError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM container_name_claims WHERE container_id=?1",
            params![container_id],
        )?;
        Ok(())
    }

    pub fn put(&self, record: &ContainerRecord) -> Result<(), ContainerStoreError> {
        if record.pending_mutation.is_some() {
            return Err(ContainerStoreError::MutationConflict);
        }
        let encoded = Self::encode(record)?;
        self.transaction(|transaction| {
            if let Some(existing) = Self::get_tx(transaction, &record.id)? {
                if existing.pending_mutation.is_some() {
                    return Err(ContainerStoreError::MutationConflict);
                }
            }
            Self::sync_record_name_tx(transaction, record)?;
            transaction.execute(
                "INSERT INTO containers(id,payload,name) VALUES (?1,?2,?3)
                 ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,name=excluded.name",
                params![record.id, encoded, record.name],
            )?;
            Ok(())
        })
    }

    /// Replace a snapshot only when it is still current and no lifecycle
    /// mutation owns the row.
    pub(crate) fn put_if_generation_unreserved(
        &self,
        record: &ContainerRecord,
        expected_generation: u64,
    ) -> Result<(), ContainerStoreError> {
        let payload = Self::encode(record)?;
        self.transaction(|transaction| {
            let current =
                Self::get_tx(transaction, &record.id)?.ok_or(ContainerStoreError::MutationConflict)?;
            if current.mutation_generation != expected_generation
                || current.pending_mutation.is_some()
                || record.pending_mutation.is_some()
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            Self::sync_record_name_tx(transaction, record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2,name=?3 WHERE id=?1",
                params![record.id, payload, record.name],
            )?;
            Ok(())
        })
    }

    pub(crate) fn put_reserved_creation(
        &self,
        record: &ContainerRecord,
    ) -> Result<(), ContainerStoreError> {
        let reservation = record
            .pending_mutation
            .as_ref()
            .ok_or(ContainerStoreError::MutationConflict)?;
        let record_payload = Self::encode(record)?;
        let operation = lifecycle_operation(record, reservation.operation_id, &reservation.action);
        let operation_payload = Self::encode(&operation)?;
        self.transaction(|transaction| {
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT id FROM containers WHERE id=?1",
                    params![record.id],
                    |row| row.get(0),
                )
                .optional()?;
            let existing_operation: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT operation_id FROM lifecycle_operations WHERE operation_id=?1",
                    params![reservation.operation_id.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if existing.is_some() || existing_operation.is_some() {
                return Err(ContainerStoreError::MutationConflict);
            }
            Self::sync_record_name_tx(transaction, record)?;
            transaction.execute(
                "INSERT INTO containers(id,payload,name) VALUES (?1,?2,?3)",
                params![record.id, record_payload, record.name],
            )?;
            transaction.execute(
                "INSERT INTO lifecycle_operations(operation_id,payload) VALUES (?1,?2)",
                params![reservation.operation_id.as_slice(), operation_payload],
            )?;
            Ok(())
        })
    }

    pub(crate) fn put_for_mutation(
        &self,
        record: &ContainerRecord,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let record_payload = Self::encode(record)?;
        self.transaction(|transaction| {
            let current = Self::get_tx(transaction, &record.id)?
                .ok_or(ContainerStoreError::MutationConflict)?;
            let reservation = current
                .pending_mutation
                .as_ref()
                .ok_or(ContainerStoreError::MutationConflict)?;
            if reservation.operation_id != operation_id
                || reservation.generation != current.mutation_generation
                || record.pending_mutation.as_ref() != Some(reservation)
                || record.mutation_generation != current.mutation_generation
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            let mut operation = Self::operation_tx(transaction, operation_id)?
                .ok_or(ContainerStoreError::MutationConflict)?;
            operation.pid_after = Some(record.pid);
            operation.process_start_time_after = process_start_time(record.pid);
            operation.state_after = Some(record.status.clone());
            let operation_payload = Self::encode(&operation)?;
            Self::sync_record_name_tx(transaction, record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2,name=?3 WHERE id=?1",
                params![record.id, record_payload, record.name],
            )?;
            transaction.execute(
                "UPDATE lifecycle_operations SET payload=?2 WHERE operation_id=?1",
                params![operation_id.as_slice(), operation_payload],
            )?;
            Ok(())
        })
    }

    /// Atomically publish a status transition for an in-flight mutation.
    ///
    /// Callers must not read a record, change its status, and then invoke
    /// `put_for_mutation`: supervisors and health writers can legitimately
    /// update the same row between those two operations. Keeping the read,
    /// reservation check, and write in one immediate transaction removes that
    /// avoidable compare-and-swap race.
    pub(crate) fn set_status_for_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
        status: &str,
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let mut record =
                Self::get_tx(transaction, id)?.ok_or(ContainerStoreError::MutationConflict)?;
            let reservation = record
                .pending_mutation
                .as_ref()
                .ok_or(ContainerStoreError::MutationConflict)?;
            if reservation.operation_id != operation_id
                || reservation.generation != record.mutation_generation
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            let Some(mut operation) = Self::operation_tx(transaction, operation_id)? else {
                return Err(ContainerStoreError::MutationConflict);
            };
            if operation.container_id != id || operation.generation != record.mutation_generation {
                return Err(ContainerStoreError::MutationConflict);
            }
            record.status = status.to_owned();
            operation.state_after = Some(record.status.clone());
            operation.pid_after = Some(record.pid);
            operation.process_start_time_after = process_start_time(record.pid);
            let record_payload = Self::encode(&record)?;
            let operation_payload = Self::encode(&operation)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, record_payload],
            )?;
            transaction.execute(
                "UPDATE lifecycle_operations SET payload=?2 WHERE operation_id=?1",
                params![operation_id.as_slice(), operation_payload],
            )?;
            Ok(())
        })
    }

    pub fn get(&self, id: &str) -> Result<Option<ContainerRecord>, ContainerStoreError> {
        let connection = self.lock()?;
        let payload: Option<Vec<u8>> = connection
            .query_row(
                "SELECT payload FROM containers WHERE id=?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        payload.map(|bytes| Self::decode_record(&bytes)).transpose()
    }

    pub fn remove(&self, id: &str) -> Result<bool, ContainerStoreError> {
        self.transaction(|transaction| {
            let removed = transaction.execute("DELETE FROM containers WHERE id=?1", params![id])? > 0;
            transaction.execute(
                "DELETE FROM container_name_claims WHERE container_id=?1",
                params![id],
            )?;
            Ok(removed)
        })
    }

    pub fn list(&self) -> Result<Vec<ContainerRecord>, ContainerStoreError> {
        self.list_paginated(None, None)
    }

    pub fn list_paginated(
        &self,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<Vec<ContainerRecord>, ContainerStoreError> {
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100).min(1000);
        let connection = self.lock()?;
        let mut statement =
            connection.prepare("SELECT payload FROM containers ORDER BY id LIMIT ?1 OFFSET ?2")?;
        let rows = statement.query_map(params![limit as i64, offset as i64], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|row| {
            let payload = row?;
            Self::decode_record(&payload)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(ContainerStoreError::Sqlite)
    }

    pub fn update_status(&self, id: &str, status: &str) -> Result<(), ContainerStoreError> {
        if let Some(mut record) = self.get(id)? {
            record.status = status.to_string();
            self.put(&record)?;
        }
        Ok(())
    }

    pub(crate) fn transition_status_and_user_stopped_for_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
        expected_generation: u64,
        expected_status: &str,
        next_status: &str,
        user_stopped: Option<bool>,
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let mut record =
                Self::get_tx(transaction, id)?.ok_or(ContainerStoreError::MutationConflict)?;
            let reservation = record
                .pending_mutation
                .as_ref()
                .ok_or(ContainerStoreError::MutationConflict)?;
            if reservation.operation_id != operation_id
                || reservation.generation != expected_generation
                || reservation.expected_status != expected_status
                || record.mutation_generation != expected_generation
                || record.status != expected_status
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            record.status = next_status.to_string();
            if let Some(user_stopped) = user_stopped {
                record.user_stopped = user_stopped;
            }
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            Ok(())
        })
    }

    pub(crate) fn set_user_stopped_for_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
        expected_generation: u64,
        user_stopped: bool,
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let mut record =
                Self::get_tx(transaction, id)?.ok_or(ContainerStoreError::MutationConflict)?;
            let reservation = record
                .pending_mutation
                .as_ref()
                .ok_or(ContainerStoreError::MutationConflict)?;
            if reservation.operation_id != operation_id
                || reservation.generation != expected_generation
                || record.mutation_generation != expected_generation
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            record.user_stopped = user_stopped;
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            Ok(())
        })
    }

    pub(crate) fn reserve_mutation(
        &self,
        id: &str,
        expected_status: &str,
        expected_generation: u64,
        operation_id: [u8; 16],
        action: &str,
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let mut record =
                Self::get_tx(transaction, id)?.ok_or(ContainerStoreError::MutationConflict)?;
            if record.status != expected_status
                || record.mutation_generation != expected_generation
                || record.pending_mutation.is_some()
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            record.pending_mutation = Some(MutationReservation {
                operation_id,
                generation: expected_generation,
                expected_status: expected_status.to_string(),
                action: action.to_string(),
            });
            let operation = lifecycle_operation(&record, operation_id, action);
            let operation_payload = Self::encode(&operation)?;
            if transaction.execute(
                "INSERT OR IGNORE INTO lifecycle_operations(operation_id,payload) VALUES (?1,?2)",
                params![operation_id.as_slice(), operation_payload],
            )? != 1
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            Ok(())
        })
    }

    /// Restore a reservation erased by a legacy snapshot writer while
    /// retaining the already-durable lifecycle operation.
    pub(crate) fn re_reserve_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
        action: &str,
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let mut record =
                Self::get_tx(transaction, id)?.ok_or(ContainerStoreError::MutationConflict)?;
            if let Some(reservation) = record.pending_mutation.as_ref() {
                return if reservation.operation_id == operation_id {
                    Ok(())
                } else {
                    Err(ContainerStoreError::MutationConflict)
                };
            }
            let operation = Self::operation_tx(transaction, operation_id)?
                .ok_or(ContainerStoreError::MutationConflict)?;
            if operation.container_id != id || operation.generation != record.mutation_generation {
                return Err(ContainerStoreError::MutationConflict);
            }
            record.pending_mutation = Some(MutationReservation {
                operation_id,
                generation: record.mutation_generation,
                expected_status: record.status.clone(),
                action: action.to_owned(),
            });
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            Ok(())
        })
    }

    pub(crate) fn lifecycle_operation(
        &self,
        operation_id: [u8; 16],
    ) -> Result<Option<LifecycleOperation>, ContainerStoreError> {
        let connection = self.lock()?;
        let payload: Option<Vec<u8>> = connection
            .query_row(
                "SELECT payload FROM lifecycle_operations WHERE operation_id=?1",
                params![operation_id.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|bytes| Self::decode_operation(&bytes))
            .transpose()
    }

    pub(crate) fn lifecycle_operations(
        &self,
    ) -> Result<Vec<LifecycleOperation>, ContainerStoreError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare("SELECT payload FROM lifecycle_operations")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| {
            let payload = row?;
            Self::decode_operation(&payload)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(ContainerStoreError::Sqlite)
    }

    pub(crate) fn mark_mutation_effect_observed(
        &self,
        id: &str,
        operation_id: [u8; 16],
        succeeded: bool,
        freezer_state: Option<bool>,
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let record =
                Self::get_tx(transaction, id)?.ok_or(ContainerStoreError::MutationConflict)?;
            let Some(mut operation) = Self::operation_tx(transaction, operation_id)? else {
                // Another process may have durably completed and acknowledged
                // this terminal transition. Observation is idempotent in that
                // case; a present-but-mismatched reservation still fails
                // closed below.
                if record.pending_mutation.is_none() {
                    return Ok(());
                }
                return Err(ContainerStoreError::MutationConflict);
            };
            if record
                .pending_mutation
                .as_ref()
                .map(|value| value.operation_id)
                != Some(operation_id)
                || operation.container_id != id
                || operation.generation != record.mutation_generation
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            operation.phase = LifecyclePhase::EffectApplied;
            operation.pid_after = Some(record.pid);
            operation.process_start_time_after = process_start_time(record.pid);
            operation.state_after = Some(record.status);
            operation.freezer_state_after = freezer_state;
            operation.execution_generation_after =
                Some(if operation.action == "container.restart" && succeeded {
                    record.mutation_generation.saturating_add(1)
                } else {
                    record.mutation_generation
                });
            let mut digest = Sha256::new();
            digest.update(b"ferrocrate/lifecycle-result/v1");
            digest.update(operation_id);
            digest.update([u8::from(succeeded)]);
            operation.result_digest = Some(digest.finalize().into());
            operation.effect_succeeded = Some(succeeded);
            let payload = Self::encode(&operation)?;
            transaction.execute(
                "UPDATE lifecycle_operations SET payload=?2 WHERE operation_id=?1",
                params![operation_id.as_slice(), payload],
            )?;
            Ok(())
        })
    }

    pub(crate) fn mark_mutation_effect(
        &self,
        id: &str,
        operation_id: [u8; 16],
        succeeded: bool,
    ) -> Result<(), ContainerStoreError> {
        self.mark_mutation_effect_observed(id, operation_id, succeeded, None)
    }

    pub(crate) fn delete_for_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let record =
                Self::get_tx(transaction, id)?.ok_or(ContainerStoreError::MutationConflict)?;
            if record
                .pending_mutation
                .as_ref()
                .map(|value| value.operation_id)
                != Some(operation_id)
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            let mut operation = Self::operation_tx(transaction, operation_id)?
                .ok_or(ContainerStoreError::MutationConflict)?;
            operation.phase = LifecyclePhase::StoreDeleted;
            let payload = Self::encode(&operation)?;
            transaction.execute(
                "UPDATE lifecycle_operations SET payload=?2 WHERE operation_id=?1",
                params![operation_id.as_slice(), payload],
            )?;
            transaction.execute("DELETE FROM containers WHERE id=?1", params![id])?;
            transaction.execute(
                "DELETE FROM container_name_claims WHERE container_id=?1",
                params![id],
            )?;
            Ok(())
        })
    }

    pub(crate) fn acknowledge_mutation(
        &self,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM lifecycle_operations WHERE operation_id=?1",
            params![operation_id.as_slice()],
        )?;
        Ok(())
    }

    pub(crate) fn finish_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
    ) -> Result<(), ContainerStoreError> {
        self.transaction(|transaction| {
            let mut record = match Self::get_tx(transaction, id)? {
                Some(record) => record,
                None => return Ok(()),
            };
            let Some(reservation) = record.pending_mutation.as_ref() else {
                if Self::operation_tx(transaction, operation_id)?.is_none() {
                    return Ok(());
                }
                return Err(ContainerStoreError::MutationConflict);
            };
            if reservation.operation_id != operation_id
                || reservation.generation != record.mutation_generation
            {
                return Err(ContainerStoreError::MutationConflict);
            }
            record.pending_mutation = None;
            record.mutation_generation = record.mutation_generation.saturating_add(1);
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            transaction.execute(
                "DELETE FROM lifecycle_operations WHERE operation_id=?1",
                params![operation_id.as_slice()],
            )?;
            Ok(())
        })
    }

    /// Publish a process exit only if the record still belongs to the
    /// supervisor that observed it. Restart replaces the PID while the old
    /// supervisor may still be finishing its wait; without this compare the
    /// old process can overwrite the replacement's running/exit state.
    pub(crate) fn update_exit_for_pid(
        &self,
        id: &str,
        expected_pid: u32,
        exit_code: i32,
    ) -> Result<Option<String>, ContainerStoreError> {
        self.update_exit_for_process(id, expected_pid, None, exit_code)
    }

    pub(crate) fn update_exit_for_process(
        &self,
        id: &str,
        expected_pid: u32,
        expected_start_time: Option<u64>,
        exit_code: i32,
    ) -> Result<Option<String>, ContainerStoreError> {
        self.transaction(|transaction| {
            let Some(mut record) = Self::get_tx(transaction, id)? else {
                return Ok(None);
            };
            if record.pid != expected_pid
                || expected_start_time.is_some() && record.process_start_time != expected_start_time
            {
                return Ok(None);
            }
            if record.pending_mutation.is_some() {
                return Err(ContainerStoreError::MutationConflict);
            }
            record.last_exit_code = Some(exit_code);
            if record.status != "stopped" && record.status != "killed" {
                record.status = "exited".to_string();
            }
            let status = record.status.clone();
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            Ok(Some(status))
        })
    }

    /// Reset the durable consecutive-restart counter only when the record
    /// still belongs to the process whose healthy lifetime we observed.
    pub(crate) fn reset_restart_count_for_process(
        &self,
        id: &str,
        expected_pid: u32,
    ) -> Result<bool, ContainerStoreError> {
        self.transaction(|transaction| {
            let Some(mut record) = Self::get_tx(transaction, id)? else {
                return Ok(false);
            };
            if record.pid != expected_pid || record.pending_mutation.is_some() {
                return Ok(false);
            }
            record.restart_count = 0;
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            Ok(true)
        })
    }

    pub(crate) fn update_health(
        &self,
        id: &str,
        status: &str,
        failures: u32,
        checked_at_unix: u64,
        health_log: Vec<crate::container_store::HealthLogEntry>,
    ) -> Result<bool, ContainerStoreError> {
        self.transaction(|transaction| {
            let Some(mut record) = Self::get_tx(transaction, id)? else {
                return Ok(false);
            };
            if record.pending_mutation.is_some() {
                return Ok(false);
            }
            record.health_status = status.to_string();
            record.health_failures = failures;
            record.health_checked_at_unix = Some(checked_at_unix);
            record.health_log = health_log;
            let payload = Self::encode(&record)?;
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![id, payload],
            )?;
            Ok(true)
        })
    }

    pub(crate) fn contains(&self, id: &str) -> Result<bool, ContainerStoreError> {
        let connection = self.lock()?;
        Ok(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM containers WHERE id=?1)",
            params![id],
            |row| row.get(0),
        )?)
    }

    pub(crate) fn clone_db(&self) -> Self {
        self.clone()
    }
}

fn migrate_container_names(connection: &mut Connection) -> Result<(), ContainerStoreError> {
    let has_name_column = {
        let mut statement = connection.prepare("PRAGMA table_info(containers)")?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        columns
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|column| column == "name")
    };
    if !has_name_column {
        connection.execute("ALTER TABLE containers ADD COLUMN name TEXT", [])?;
    }

    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut records = {
        let mut statement = transaction.prepare("SELECT payload FROM containers")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|payload| SqliteContainerStore::decode_record(&payload))
            .collect::<Result<Vec<_>, _>>()?
    };
    let record_ids = records
        .iter()
        .map(|record| record.id.as_str())
        .collect::<HashSet<_>>();
    let mut occupied = records
        .iter()
        .filter_map(|record| record.name.clone())
        .collect::<HashSet<_>>();
    {
        let mut statement = transaction.prepare(
            "SELECT name,container_id FROM container_name_claims ORDER BY name,container_id",
        )?;
        let claims = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for claim in claims {
            let (name, owner) = claim?;
            if !record_ids.contains(owner.as_str()) {
                occupied.insert(name);
            }
        }
    }

    let mut groups = HashMap::<String, Vec<usize>>::new();
    for (index, record) in records.iter().enumerate() {
        if let Some(name) = record.name.as_ref() {
            groups.entry(name.clone()).or_default().push(index);
        }
    }
    for (name, mut indexes) in groups {
        if indexes.len() < 2 {
            continue;
        }
        indexes.sort_by(|left, right| {
            records[*left]
                .created_at_unix
                .cmp(&records[*right].created_at_unix)
                .then_with(|| records[*left].id.cmp(&records[*right].id))
        });
        for index in indexes.into_iter().skip(1) {
            let id = records[index].id.clone();
            let short_len = id.len().min(12);
            let base = format!("{name}-{}", &id[..short_len]);
            let mut replacement = base.clone();
            let mut discriminator = 2usize;
            while occupied.contains(&replacement) {
                replacement = format!("{base}-{discriminator}");
                discriminator += 1;
            }
            occupied.insert(replacement.clone());
            records[index].name = Some(replacement.clone());
            log::warn!(
                "duplicate container name repaired while opening store: original_name={} container_id={} replacement_name={}",
                name,
                id,
                replacement
            );
        }
    }

    for record in &records {
        transaction.execute(
            "DELETE FROM container_name_claims WHERE container_id=?1",
            params![record.id],
        )?;
    }
    for record in &records {
        let payload = SqliteContainerStore::encode(record)?;
        transaction.execute(
            "UPDATE containers SET payload=?2,name=?3 WHERE id=?1",
            params![record.id, payload, record.name],
        )?;
        if let Some(name) = record.name.as_deref() {
            transaction.execute(
                "INSERT INTO container_name_claims(name,container_id) VALUES (?1,?2)",
                params![name, record.id],
            )?;
        }
    }
    transaction.commit()?;
    Ok(())
}

fn lifecycle_operation(
    record: &ContainerRecord,
    operation_id: [u8; 16],
    action: &str,
) -> LifecycleOperation {
    let mut digest = Sha256::new();
    digest.update(b"ferrocrate/lifecycle-ownership/v1");
    digest.update(record.id.as_bytes());
    digest.update(
        record
            .creation_provenance
            .runtime_instance_id
            .unwrap_or_default(),
    );
    digest.update(record.creation_provenance.resource_generation.to_be_bytes());
    LifecycleOperation {
        operation_id,
        container_id: record.id.clone(),
        action: action.to_owned(),
        generation: record.mutation_generation,
        phase: LifecyclePhase::Reserved,
        pid: record.pid,
        process_start_time: process_start_time(record.pid),
        state: record.status.clone(),
        pid_after: None,
        process_start_time_after: None,
        state_after: None,
        freezer_state_after: None,
        ownership_digest: digest.finalize().into(),
        execution_generation_after: None,
        result_digest: None,
        effect_succeeded: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn record(id: &str) -> ContainerRecord {
        ContainerRecord::authorization_candidate(id.to_string(), "alpine:latest".to_string())
    }

    #[test]
    fn sqlite_store_round_trips_lifecycle_transaction() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SqliteContainerStore::open(temp.path()).expect("open");
        let mut value = record("container-1");
        value.pid = std::process::id();
        store.put(&value).expect("put");
        assert_eq!(store.list().expect("list").len(), 1);

        let operation_id = [7u8; 16];
        store
            .reserve_mutation("container-1", "created", 1, operation_id, "container.start")
            .expect("reserve");
        store
            .transition_status_and_user_stopped_for_mutation(
                "container-1",
                operation_id,
                1,
                "created",
                "running",
                None,
            )
            .expect("transition");
        store
            .mark_mutation_effect("container-1", operation_id, true)
            .expect("effect");
        store
            .finish_mutation("container-1", operation_id)
            .expect("finish");
        let stored = store.get("container-1").expect("get").expect("record");
        assert_eq!(stored.status, "running");
        assert!(stored.pending_mutation.is_none());
        assert_eq!(store.lifecycle_operations().expect("operations").len(), 0);
        // Terminal publication is safe to acknowledge again if another
        // process completed it between observation and cleanup.
        store
            .mark_mutation_effect("container-1", operation_id, true)
            .expect("idempotent effect");
        store
            .finish_mutation("container-1", operation_id)
            .expect("idempotent finish");
    }

    #[test]
    fn sqlite_store_round_trips_user_stop_intent_and_defaults_legacy_records() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SqliteContainerStore::open(temp.path()).expect("open");
        let mut stopped = record("operator-stopped");
        stopped.user_stopped = true;
        store.put(&stopped).expect("put stopped record");

        let restored = store
            .get("operator-stopped")
            .expect("get")
            .expect("stored record");
        assert!(restored.user_stopped);

        let legacy: ContainerRecord = serde_json::from_value(serde_json::json!({
            "id": "legacy-record",
            "pid": 0,
            "image": "alpine:latest",
            "command": [],
            "created_at_unix": 0,
            "stdout_path": "stdout.log",
            "stderr_path": "stderr.log",
            "status": "created"
        }))
        .expect("legacy record deserializes");
        assert!(!legacy.user_stopped);
    }

    #[test]
    fn status_publication_is_atomic_with_reservation_validation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = SqliteContainerStore::open(temp.path()).expect("open");
        store.put(&record("container-status")).expect("put");
        let operation_id = [19u8; 16];
        store
            .reserve_mutation(
                "container-status",
                "created",
                1,
                operation_id,
                "container.delete",
            )
            .expect("reserve");

        store
            .set_status_for_mutation("container-status", operation_id, "removed-pending")
            .expect("status");
        let stored = store.get("container-status").expect("get").expect("record");
        assert_eq!(stored.status, "removed-pending");
        let operation = store
            .lifecycle_operation(operation_id)
            .expect("operation")
            .expect("lifecycle operation");
        assert_eq!(operation.state_after.as_deref(), Some("removed-pending"));
    }

    #[test]
    fn concurrent_open_waits_for_schema_initialization() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("containers.db");
        let workers = (0..8)
            .map(|index| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let store = SqliteContainerStore::open(path).expect("open");
                    store
                        .put(&record(&format!("container-{index}")))
                        .expect("put");
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("worker");
        }
        let store = SqliteContainerStore::open(&path).expect("reopen");
        assert_eq!(store.list().expect("list").len(), 8);
    }

    #[test]
    fn sqlite_store_rejects_legacy_directory_by_default() {
        let temp = tempfile::tempdir().expect("legacy store");
        std::fs::create_dir_all(temp.path().join("conf")).expect("legacy marker");
        let error = match SqliteContainerStore::open(temp.path()) {
            Ok(_) => panic!("legacy boundary"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("legacy-sled-importers"));
    }

    #[test]
    fn concurrent_named_creates_have_exactly_one_winner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("containers.db");
        SqliteContainerStore::open(&path).expect("initialize schema");
        let barrier = Arc::new(Barrier::new(8));
        let workers = (0..8)
            .map(|index| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let store = SqliteContainerStore::open(path).expect("open");
                    let mut candidate = record(&format!("racer-{index}"));
                    candidate.name = Some("one-name".to_string());
                    barrier.wait();
                    store.put(&candidate)
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ContainerStoreError::NameConflict { name, .. }) if name == "one-name"))
                .count(),
            7
        );
    }

    #[test]
    fn opening_legacy_store_disambiguates_duplicate_names_deterministically() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("containers.db");
        let connection = Connection::open(&path).expect("legacy database");
        connection
            .execute_batch(
                "CREATE TABLE containers (id TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL);\
                 CREATE TABLE lifecycle_operations (operation_id BLOB PRIMARY KEY NOT NULL, payload BLOB NOT NULL);",
            )
            .expect("legacy schema");
        for (id, created_at) in [("bbbbbbbb2222", 20), ("aaaaaaaa1111", 10), ("cccccccc3333", 20)] {
            let mut value = record(id);
            value.name = Some("duplicate".to_string());
            value.created_at_unix = created_at;
            connection
                .execute(
                    "INSERT INTO containers(id,payload) VALUES (?1,?2)",
                    params![id, SqliteContainerStore::encode(&value).expect("encode")],
                )
                .expect("legacy row");
        }
        drop(connection);

        let store = SqliteContainerStore::open(&path).expect("migrate duplicates");
        let records = store.list().expect("list");
        let names = records
            .into_iter()
            .map(|record| (record.id, record.name.expect("name")))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(names["aaaaaaaa1111"], "duplicate");
        assert_eq!(names["bbbbbbbb2222"], "duplicate-bbbbbbbb2222");
        assert_eq!(names["cccccccc3333"], "duplicate-cccccccc3333");
    }
}
