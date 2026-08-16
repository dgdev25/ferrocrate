//! SQLite-backed container and lifecycle store.
//!
//! This is the active runtime backend. The legacy sled store remains available
//! for explicit rollback/import tooling, but runtime state is published in one
//! SQLite transaction across container records and lifecycle operations.

use crate::container_store::{
    process_start_time, ContainerRecord, ContainerStoreError, LifecycleOperation, LifecyclePhase,
    MutationReservation,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const CONTAINERS_SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS containers (
    id TEXT PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS lifecycle_operations (
    operation_id BLOB PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL
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
                let legacy = super::container_store::LocalContainerStore::open(&legacy_path)?;
                legacy.export_sqlite_snapshot(&sqlite_path)?;
                std::fs::write(marker, b"sqlite-v1\n")?;
            }
        }
        let connection = Connection::open(&sqlite_path)?;
        connection.execute_batch(CONTAINERS_SCHEMA)?;
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
        let transaction = connection.transaction()?;
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
            transaction.execute(
                "INSERT INTO containers(id,payload) VALUES (?1,?2)
                 ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                params![record.id, encoded],
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
            transaction.execute(
                "INSERT INTO containers(id,payload) VALUES (?1,?2)",
                params![record.id, record_payload],
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
            transaction.execute(
                "UPDATE containers SET payload=?2 WHERE id=?1",
                params![record.id, record_payload],
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
        let connection = self.lock()?;
        Ok(connection.execute("DELETE FROM containers WHERE id=?1", params![id])? > 0)
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

    pub(crate) fn transition_status_for_mutation(
        &self,
        id: &str,
        operation_id: [u8; 16],
        expected_generation: u64,
        expected_status: &str,
        next_status: &str,
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
            let mut operation = Self::operation_tx(transaction, operation_id)?
                .ok_or(ContainerStoreError::MutationConflict)?;
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
            let reservation = record
                .pending_mutation
                .as_ref()
                .ok_or(ContainerStoreError::MutationConflict)?;
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

    pub(crate) fn update_exit(
        &self,
        id: &str,
        exit_code: i32,
    ) -> Result<String, ContainerStoreError> {
        self.transaction(|transaction| {
            let Some(mut record) = Self::get_tx(transaction, id)? else {
                return Ok("exited".to_string());
            };
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
            Ok(status)
        })
    }

    pub(crate) fn update_health(
        &self,
        id: &str,
        status: &str,
        failures: u32,
        checked_at_unix: u64,
    ) -> Result<bool, ContainerStoreError> {
        self.transaction(|transaction| {
            let Some(mut record) = Self::get_tx(transaction, id)? else {
                return Ok(false);
            };
            record.health_status = status.to_string();
            record.health_failures = failures;
            record.health_checked_at_unix = Some(checked_at_unix);
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
    use crate::container_store::LocalContainerStore;

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
            .transition_status_for_mutation("container-1", operation_id, 1, "created", "running")
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
    }

    #[test]
    fn sqlite_store_imports_existing_legacy_sled_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let legacy = LocalContainerStore::open(temp.path()).expect("legacy");
        legacy.put(&record("legacy-1")).expect("legacy put");
        drop(legacy);
        let sqlite = SqliteContainerStore::open(temp.path()).expect("sqlite");
        assert!(sqlite.get("legacy-1").expect("get").is_some());
        assert!(temp.path().join("containers.sqlite3.imported").exists());
    }
}
