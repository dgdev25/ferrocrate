mod migrations;
mod models;

pub use models::{Enrollment, Overlay, ScopedToken, Token};

use std::{net::Ipv4Addr, path::Path, sync::Mutex};

use ipnet::{IpNet, Ipv4Net};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_ALLOCATION_CANDIDATES: u64 = 65_536;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("enrollment token has already been consumed")]
    TokenConsumed,
    #[error("enrollment token has expired")]
    TokenExpired,
    #[error("enrollment token is not valid for this node or endpoint")]
    TokenScopeMismatch,
    #[error("unknown enrollment token")]
    TokenUnknown,
    #[error("overlay {0} does not exist")]
    OverlayUnknown(String),
    #[error("invalid network: {0}")]
    InvalidNetwork(String),
    #[error("no subnet is available for this overlay")]
    SubnetExhausted,
    #[error("store mutex was poisoned")]
    Poisoned,
}

pub struct ManagerStore {
    connection: Mutex<Connection>,
}

impl ManagerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;",
        )?;
        migrations::apply(&connection)?;
        Ok(Self { connection: Mutex::new(connection) })
    }

    pub fn transact<T>(&self, operation: impl FnOnce(&Transaction<'_>) -> Result<T, StoreError>) -> Result<T, StoreError> {
        let mut connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = operation(&transaction)?;
        transaction.commit()?;
        Ok(value)
    }

    pub fn create_token(&self, token: ScopedToken) -> Result<Token, StoreError> {
        let hash = token_hash(&token.secret);
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO enrollment_tokens (secret_hash, expected_node, approved_endpoint, overlay_scope, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![hash.as_slice(), token.expected_node, token.approved_endpoint, token.overlay_scope, token.expires_at],
            )?;
            Ok(Token { secret: token.secret, expires_at: token.expires_at })
        })
    }

    pub fn consume_token(&self, secret: &[u8; 32], now_unix_secs: i64) -> Result<(), StoreError> {
        let hash = token_hash(secret);
        self.transact(|tx| { consume_token_tx(tx, &hash, now_unix_secs).map(|_| ()) })
    }

    pub fn register_node_with_token(&self, secret: &[u8; 32], enrollment: Enrollment, now_unix_secs: i64) -> Result<(), StoreError> {
        let hash = token_hash(secret);
        self.transact(|tx| {
            let (expected_node, endpoint) = consume_token_tx(tx, &hash, now_unix_secs)?;
            if expected_node != enrollment.node_id || endpoint != enrollment.endpoint {
                return Err(StoreError::TokenScopeMismatch);
            }
            tx.execute(
                "INSERT INTO nodes (node_id, public_key, endpoint) VALUES (?1, ?2, ?3)",
                params![enrollment.node_id, enrollment.public_key, enrollment.endpoint],
            )?;
            Ok(())
        })
    }

    pub fn register_node(&self, enrollment: Enrollment) -> Result<(), StoreError> {
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO nodes (node_id, public_key, endpoint) VALUES (?1, ?2, ?3)",
                params![enrollment.node_id, enrollment.public_key, enrollment.endpoint],
            )?;
            Ok(())
        })
    }

    pub fn create_overlay(&self, overlay: Overlay) -> Result<(), StoreError> {
        let network = parse_v4(&overlay.cidr)?;
        self.transact(|tx| {
            let mut statement = tx.prepare("SELECT cidr FROM overlays")?;
            let existing = statement.query_map([], |row| row.get::<_, String>(0))?;
            for cidr in existing {
                let existing = parse_v4(&cidr?)?;
                if networks_overlap(network, existing) {
                    return Err(StoreError::InvalidNetwork("overlay ranges must not overlap".into()));
                }
            }
            tx.execute("INSERT INTO overlays (overlay_id, cidr) VALUES (?1, ?2)", params![overlay.id, overlay.cidr])?;
            Ok(())
        })
    }

    pub fn allocate_node_subnet(
        &self,
        overlay_id: &str,
        node_id: &str,
        prefix_len: u8,
        host_reserved: &[Ipv4Net],
    ) -> Result<Ipv4Net, StoreError> {
        self.transact(|tx| {
            let cidr: String = tx.query_row(
                "SELECT cidr FROM overlays WHERE overlay_id = ?1", params![overlay_id], |row| row.get(0),
            ).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { StoreError::OverlayUnknown(overlay_id.into()) } else { StoreError::Sql(error) })?;
            let overlay = parse_v4(&cidr)?;
            if prefix_len < overlay.prefix_len() || prefix_len > 30 {
                return Err(StoreError::InvalidNetwork("node subnet prefix must be within the IPv4 overlay and no longer than /30".into()));
            }
            let existing: Option<String> = tx.query_row(
                "SELECT cidr FROM node_subnets WHERE overlay_id = ?1 AND node_id = ?2",
                params![overlay_id, node_id], |row| row.get(0),
            ).ok();
            if let Some(cidr) = existing { return parse_v4(&cidr); }
            let used = {
                let mut statement = tx.prepare("SELECT cidr FROM node_subnets WHERE overlay_id = ?1")?;
                let rows = statement.query_map(params![overlay_id], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            let slots = 1_u64 << (prefix_len - overlay.prefix_len());
            let size = 1_u64 << (32 - prefix_len);
            let base = u32::from(overlay.network()) as u64;
            for slot in 0..slots.min(MAX_ALLOCATION_CANDIDATES) {
                let candidate = Ipv4Net::new(Ipv4Addr::from((base + slot * size) as u32), prefix_len)
                    .map_err(|error| StoreError::InvalidNetwork(error.to_string()))?;
                if host_reserved.iter().any(|reserved| networks_overlap(candidate, *reserved)) { continue; }
                if used.iter().any(|cidr| parse_v4(cidr).is_ok_and(|assigned| networks_overlap(candidate, assigned))) { continue; }
                tx.execute(
                    "INSERT INTO node_subnets (overlay_id, node_id, cidr) VALUES (?1, ?2, ?3)",
                    params![overlay_id, node_id, candidate.to_string()],
                )?;
                return Ok(candidate);
            }
            Err(StoreError::SubnetExhausted)
        })
    }

    pub fn append_revision(&self, overlay_id: &str, payload: &[u8]) -> Result<i64, StoreError> {
        self.transact(|tx| {
            let next: i64 = tx.query_row("SELECT COALESCE(MAX(revision), 0) + 1 FROM desired_revisions", [], |row| row.get(0))?;
            tx.execute("INSERT INTO desired_revisions (revision, overlay_id, payload) VALUES (?1, ?2, ?3)", params![next, overlay_id, payload])?;
            Ok(next)
        })
    }

    pub fn acknowledge_revision(&self, node_id: &str, revision: i64) -> Result<(), StoreError> {
        self.transact(|tx| {
            tx.execute(
                "INSERT INTO acknowledgements (node_id, revision) VALUES (?1, ?2)
                 ON CONFLICT(node_id, revision) DO NOTHING", params![node_id, revision],
            )?;
            Ok(())
        })
    }

    pub fn revoke_node(&self, node_id: &str, reason: &str) -> Result<(), StoreError> {
        self.transact(|tx| {
            tx.execute("UPDATE nodes SET revoked_at = unixepoch(), revocation_reason = ?2 WHERE node_id = ?1", params![node_id, reason])?;
            Ok(())
        })
    }

    pub fn node_count(&self) -> Result<u32, StoreError> {
        let connection = self.connection.lock().map_err(|_| StoreError::Poisoned)?;
        Ok(connection.query_row("SELECT COUNT(*) FROM nodes WHERE revoked_at IS NULL", [], |row| row.get(0))?)
    }
}

fn consume_token_tx(tx: &Transaction<'_>, hash: &[u8; 32], now_unix_secs: i64) -> Result<(String, String), StoreError> {
    let row = tx.query_row(
        "SELECT expected_node, approved_endpoint, expires_at, consumed_at FROM enrollment_tokens WHERE secret_hash = ?1",
        params![hash.as_slice()], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, Option<i64>>(3)?)),
    ).map_err(|error| if matches!(error, rusqlite::Error::QueryReturnedNoRows) { StoreError::TokenUnknown } else { StoreError::Sql(error) })?;
    if row.3.is_some() { return Err(StoreError::TokenConsumed); }
    if row.2 <= now_unix_secs { return Err(StoreError::TokenExpired); }
    tx.execute("UPDATE enrollment_tokens SET consumed_at = ?2 WHERE secret_hash = ?1 AND consumed_at IS NULL", params![hash.as_slice(), now_unix_secs])?;
    Ok((row.0, row.1))
}

fn token_hash(secret: &[u8; 32]) -> [u8; 32] { Sha256::digest(secret).into() }

fn parse_v4(cidr: &str) -> Result<Ipv4Net, StoreError> {
    cidr.parse::<IpNet>().map_err(|error| StoreError::InvalidNetwork(error.to_string())).and_then(|network| match network {
        IpNet::V4(network) => Ok(network),
        IpNet::V6(_) => Err(StoreError::InvalidNetwork("only IPv4 overlay ranges are currently supported".into())),
    })
}

fn networks_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}
