#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub restored_database_path: String,
    pub next_epoch: u64,
    pub rotate_issuing_ca: bool,
    pub expire_all_credentials: bool,
}

impl RecoveryPlan {
    pub fn restore_and_rekey(
        restored_database_path: impl Into<String>,
        current_epoch: u64,
    ) -> Self {
        Self {
            restored_database_path: restored_database_path.into(),
            next_epoch: current_epoch.saturating_add(1),
            rotate_issuing_ca: true,
            expire_all_credentials: true,
        }
    }
}

pub fn restore_backup(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    reason: &str,
    now_unix_secs: i64,
) -> Result<RecoveryPlan, RecoveryError> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    if !source.is_file() {
        return Err(RecoveryError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "backup is not a regular file",
        )));
    }
    if destination.exists() {
        return Err(RecoveryError::DestinationExists);
    }
    let source_connection = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let temporary = destination.with_extension("restore.tmp");
    if temporary.exists() {
        return Err(RecoveryError::DestinationExists);
    }
    let escaped = temporary.to_string_lossy().replace('\'', "''");
    source_connection.execute_batch(&format!("VACUUM INTO '{}';", escaped))?;
    drop(source_connection);
    let restored = Connection::open(&temporary)?;
    let integrity: String = restored.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    drop(restored);
    if integrity != "ok" {
        let _ = fs::remove_file(&temporary);
        return Err(RecoveryError::Sql(rusqlite::Error::InvalidQuery));
    }
    fs::rename(&temporary, destination)?;
    let store = ManagerStore::open(destination)?;
    let next_epoch = store.recover_after_restore(reason, now_unix_secs)?;
    Ok(RecoveryPlan {
        restored_database_path: destination.to_string_lossy().into_owned(),
        next_epoch,
        rotate_issuing_ca: true,
        expire_all_credentials: true,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Enrollment, ManagerStore, ScopedToken};
    use rusqlite::Connection;
    use tempfile::tempdir;

    #[test]
    fn restore_backup_rotates_epoch_and_revokes_credentials() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("manager.sqlite");
        let destination = temp.path().join("restored.sqlite");
        let store = ManagerStore::open(&source).expect("open source");
        store
            .create_token(ScopedToken {
                secret: [7; 32],
                expected_node: "node-a".into(),
                approved_endpoint: "10.0.0.2:51820".into(),
                overlay_scope: "overlay-a".into(),
                expires_at: 9_999,
            })
            .expect("create token");
        store
            .register_node(Enrollment {
                node_id: "node-a".into(),
                public_key: vec![1; 32],
                endpoint: "10.0.0.2:51820".into(),
            })
            .expect("register node");

        // Create a consistent, portable SQLite backup using the same primitive
        // used by the manager's operational backup tooling.
        let source_connection =
            Connection::open_with_flags(&source, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open backup source");
        let escaped = destination.to_string_lossy().replace('\'', "''");
        source_connection
            .execute_batch(&format!("VACUUM INTO '{}';", escaped))
            .expect("create backup");

        let plan = restore_backup(
            &destination,
            &temp.path().join("recovered.sqlite"),
            "lost host",
            1234,
        )
        .expect("restore backup");
        assert_eq!(plan.next_epoch, 2);
        assert!(plan.rotate_issuing_ca);
        assert!(plan.expire_all_credentials);

        let recovered = Connection::open(plan.restored_database_path).expect("open recovered");
        let epoch: u64 = recovered
            .query_row(
                "SELECT cluster_epoch FROM cluster_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("epoch");
        assert_eq!(epoch, 2);
        let revoked: Option<i64> = recovered
            .query_row(
                "SELECT revoked_at FROM nodes WHERE node_id = 'node-a'",
                [],
                |row| row.get(0),
            )
            .expect("revocation");
        assert_eq!(revoked, Some(1234));
        let token_expiry: i64 = recovered
            .query_row("SELECT expires_at FROM enrollment_tokens", [], |row| {
                row.get(0)
            })
            .expect("token expiry");
        assert_eq!(token_expiry, 1234);
        let audit_reason: String = recovered
            .query_row("SELECT reason FROM recovery_audit", [], |row| row.get(0))
            .expect("recovery audit");
        assert_eq!(audit_reason, "lost host");
    }

    #[test]
    fn restore_backup_rejects_existing_destination_without_mutation() {
        let temp = tempdir().expect("tempdir");
        let source = temp.path().join("source.sqlite");
        let destination = temp.path().join("destination.sqlite");
        ManagerStore::open(&source).expect("open source");
        Connection::open(&destination).expect("create destination");

        let error =
            restore_backup(&source, &destination, "test", 1).expect_err("existing destination");
        assert!(matches!(error, RecoveryError::DestinationExists));
    }
}
