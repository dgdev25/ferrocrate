//! Trusted verification boundary for bounded CRI delegation capabilities.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection};
use std::sync::Mutex;
use thiserror::Error;

use super::{Action, ResolvedPrincipal, Role};

const MAX_TEXT_BYTES: usize = 512;
const MAX_SCOPE_ITEMS: usize = 64;
const MAX_CANONICAL_BYTES: usize = 64 * 1024;
const WIRE_DOMAIN: &[u8] = b"ferrocrate/cri-delegation/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriDelegationClaims {
    issuer: String,
    key_id: String,
    transport_subject: String,
    audience: String,
    delegated_principal: String,
    allowed_actions: Vec<Action>,
    allowed_resources: Vec<String>,
    nonce: String,
    deadline_unix_ms: u64,
    boot_id: String,
    policy_digest: [u8; 32],
}

impl CriDelegationClaims {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: impl Into<String>,
        key_id: impl Into<String>,
        transport_subject: impl Into<String>,
        audience: impl Into<String>,
        delegated_principal: impl Into<String>,
        allowed_actions: Vec<Action>,
        allowed_resources: Vec<String>,
        nonce: impl Into<String>,
        deadline_unix_ms: u64,
        boot_id: impl Into<String>,
        policy_digest: [u8; 32],
    ) -> Result<Self, DelegationError> {
        let value = Self {
            issuer: issuer.into(),
            key_id: key_id.into(),
            transport_subject: transport_subject.into(),
            audience: audience.into(),
            delegated_principal: delegated_principal.into(),
            allowed_actions,
            allowed_resources,
            nonce: nonce.into(),
            deadline_unix_ms,
            boot_id: boot_id.into(),
            policy_digest,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), DelegationError> {
        let strings = [
            &self.issuer,
            &self.key_id,
            &self.transport_subject,
            &self.audience,
            &self.delegated_principal,
            &self.nonce,
            &self.boot_id,
        ];
        if strings
            .iter()
            .any(|value| value.is_empty() || value.len() > MAX_TEXT_BYTES)
            || self.allowed_actions.is_empty()
            || self.allowed_actions.len() > MAX_SCOPE_ITEMS
            || self.allowed_resources.is_empty()
            || self.allowed_resources.len() > MAX_SCOPE_ITEMS
            || self
                .allowed_resources
                .iter()
                .any(|value| value.is_empty() || value.len() > MAX_TEXT_BYTES)
        {
            return Err(DelegationError::Bounds);
        }
        if self.signing_bytes().len() > MAX_CANONICAL_BYTES {
            return Err(DelegationError::Bounds);
        }
        Ok(())
    }

    /// Normative binary encoding: domain separator followed by big-endian
    /// length-prefixed UTF-8 fields and fixed-width integers/bytes.
    pub fn signing_bytes(&self) -> Vec<u8> {
        fn text(out: &mut Vec<u8>, value: &str) {
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        let mut out = WIRE_DOMAIN.to_vec();
        for value in [
            &self.issuer,
            &self.key_id,
            &self.transport_subject,
            &self.audience,
            &self.delegated_principal,
        ] {
            text(&mut out, value);
        }
        out.extend_from_slice(&(self.allowed_actions.len() as u32).to_be_bytes());
        for action in &self.allowed_actions {
            text(
                &mut out,
                &serde_json::to_string(action).expect("Action serialization is infallible"),
            );
        }
        out.extend_from_slice(&(self.allowed_resources.len() as u32).to_be_bytes());
        for resource in &self.allowed_resources {
            text(&mut out, resource);
        }
        text(&mut out, &self.nonce);
        out.extend_from_slice(&self.deadline_unix_ms.to_be_bytes());
        text(&mut out, &self.boot_id);
        out.extend_from_slice(&self.policy_digest);
        out
    }

    pub fn delegated_principal(&self) -> &str {
        &self.delegated_principal
    }

    /// Create a child claim whose authority is no broader than this claim.
    ///
    /// The child keeps the issuer, audience, transport binding, boot binding,
    /// and policy digest, while requiring a strictly new nonce, a no-later
    /// deadline, and action/resource sets that are subsets of the parent.
    /// Callers still sign the returned claims with the issuer key before
    /// putting them on the wire.
    pub fn attenuate(
        &self,
        allowed_actions: Vec<Action>,
        allowed_resources: Vec<String>,
        nonce: impl Into<String>,
        deadline_unix_ms: u64,
    ) -> Result<Self, DelegationError> {
        let nonce = nonce.into();
        if nonce == self.nonce
            || !allowed_actions
                .iter()
                .all(|action| self.allowed_actions.contains(action))
            || !allowed_resources
                .iter()
                .all(|resource| self.allowed_resources.contains(resource))
            || deadline_unix_ms > self.deadline_unix_ms
        {
            return Err(DelegationError::Attenuation);
        }
        Self::new(
            self.issuer.clone(),
            self.key_id.clone(),
            self.transport_subject.clone(),
            self.audience.clone(),
            self.delegated_principal.clone(),
            allowed_actions,
            allowed_resources,
            nonce,
            deadline_unix_ms,
            self.boot_id.clone(),
            self.policy_digest,
        )
    }

    fn replay_key(&self) -> Vec<u8> {
        let mut key = b"ferrocrate/cri-delegation-replay/v1\0".to_vec();
        for value in [&self.issuer, &self.key_id, &self.nonce] {
            key.extend_from_slice(&(value.len() as u32).to_be_bytes());
            key.extend_from_slice(value.as_bytes());
        }
        key
    }

    fn revocation_key(&self) -> Vec<u8> {
        let mut key = b"ferrocrate/cri-delegation-revocation/v1\0".to_vec();
        for value in [&self.issuer, &self.key_id, &self.nonce] {
            key.extend_from_slice(&(value.len() as u32).to_be_bytes());
            key.extend_from_slice(value.as_bytes());
        }
        key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationAssertion {
    claims: CriDelegationClaims,
    signature: [u8; 64],
}
impl DelegationAssertion {
    pub fn new(claims: CriDelegationClaims, signature: [u8; 64]) -> Result<Self, DelegationError> {
        claims.validate()?;
        Ok(Self { claims, signature })
    }
    pub fn claims(&self) -> &CriDelegationClaims {
        &self.claims
    }

    pub fn wire_bytes(&self) -> Vec<u8> {
        let canonical = self.claims.signing_bytes();
        let mut wire = Vec::with_capacity(4 + canonical.len() + self.signature.len());
        wire.extend_from_slice(&(canonical.len() as u32).to_be_bytes());
        wire.extend_from_slice(&canonical);
        wire.extend_from_slice(&self.signature);
        wire
    }

    pub fn from_wire_bytes(wire: &[u8]) -> Result<Self, DelegationError> {
        if wire.len() < 4 + WIRE_DOMAIN.len() + 64 || wire.len() > 4 + MAX_CANONICAL_BYTES + 64 {
            return Err(DelegationError::Malformed);
        }
        let canonical_len = usize::try_from(u32::from_be_bytes(
            wire[..4]
                .try_into()
                .map_err(|_| DelegationError::Malformed)?,
        ))
        .map_err(|_| DelegationError::Malformed)?;
        if canonical_len > MAX_CANONICAL_BYTES || wire.len() != 4 + canonical_len + 64 {
            return Err(DelegationError::Malformed);
        }
        let canonical = &wire[4..4 + canonical_len];
        let claims = parse_canonical_claims(canonical)?;
        if claims.signing_bytes() != canonical {
            return Err(DelegationError::Malformed);
        }
        let signature = wire[4 + canonical_len..]
            .try_into()
            .map_err(|_| DelegationError::Malformed)?;
        Self::new(claims, signature)
    }
}

fn parse_canonical_claims(bytes: &[u8]) -> Result<CriDelegationClaims, DelegationError> {
    struct Cursor<'a> {
        bytes: &'a [u8],
        position: usize,
    }
    impl<'a> Cursor<'a> {
        fn take(&mut self, count: usize) -> Result<&'a [u8], DelegationError> {
            let end = self
                .position
                .checked_add(count)
                .ok_or(DelegationError::Malformed)?;
            let value = self
                .bytes
                .get(self.position..end)
                .ok_or(DelegationError::Malformed)?;
            self.position = end;
            Ok(value)
        }
        fn u32(&mut self) -> Result<u32, DelegationError> {
            Ok(u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| DelegationError::Malformed)?,
            ))
        }
        fn text(&mut self) -> Result<String, DelegationError> {
            let length = usize::try_from(self.u32()?).map_err(|_| DelegationError::Malformed)?;
            if length == 0 || length > MAX_TEXT_BYTES {
                return Err(DelegationError::Bounds);
            }
            String::from_utf8(self.take(length)?.to_vec()).map_err(|_| DelegationError::Malformed)
        }
    }
    let mut cursor = Cursor { bytes, position: 0 };
    if cursor.take(WIRE_DOMAIN.len())? != WIRE_DOMAIN {
        return Err(DelegationError::Malformed);
    }
    let issuer = cursor.text()?;
    let key_id = cursor.text()?;
    let transport_subject = cursor.text()?;
    let audience = cursor.text()?;
    let delegated_principal = cursor.text()?;
    let action_count = usize::try_from(cursor.u32()?).map_err(|_| DelegationError::Malformed)?;
    if action_count == 0 || action_count > MAX_SCOPE_ITEMS {
        return Err(DelegationError::Bounds);
    }
    let mut allowed_actions = Vec::with_capacity(action_count);
    for _ in 0..action_count {
        allowed_actions
            .push(serde_json::from_str(&cursor.text()?).map_err(|_| DelegationError::Malformed)?);
    }
    let resource_count = usize::try_from(cursor.u32()?).map_err(|_| DelegationError::Malformed)?;
    if resource_count == 0 || resource_count > MAX_SCOPE_ITEMS {
        return Err(DelegationError::Bounds);
    }
    let mut allowed_resources = Vec::with_capacity(resource_count);
    for _ in 0..resource_count {
        allowed_resources.push(cursor.text()?);
    }
    let nonce = cursor.text()?;
    let deadline_unix_ms = u64::from_be_bytes(
        cursor
            .take(8)?
            .try_into()
            .map_err(|_| DelegationError::Malformed)?,
    );
    let boot_id = cursor.text()?;
    let policy_digest = cursor
        .take(32)?
        .try_into()
        .map_err(|_| DelegationError::Malformed)?;
    if cursor.position != bytes.len() {
        return Err(DelegationError::Malformed);
    }
    CriDelegationClaims::new(
        issuer,
        key_id,
        transport_subject,
        audience,
        delegated_principal,
        allowed_actions,
        allowed_resources,
        nonce,
        deadline_unix_ms,
        boot_id,
        policy_digest,
    )
}

#[derive(Clone)]
pub struct DelegationTrustKey {
    issuer: String,
    key_id: String,
    key: VerifyingKey,
    role: Role,
}
impl DelegationTrustKey {
    pub fn developer(
        issuer: impl Into<String>,
        key_id: impl Into<String>,
        key: VerifyingKey,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            key_id: key_id.into(),
            key,
            role: Role::Developer,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCriDelegation(ResolvedPrincipal);
impl VerifiedCriDelegation {
    pub fn principal(&self) -> &ResolvedPrincipal {
        &self.0
    }
    pub(crate) fn into_principal(self) -> ResolvedPrincipal {
        self.0
    }
}

pub struct CriDelegationVerifier {
    keys: HashMap<(String, String), (VerifyingKey, Role)>,
    audience: String,
    boot_id: String,
    policy_digest: [u8; 32],
    replay: Mutex<Connection>,
}

impl CriDelegationVerifier {
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn open(
        keys: Vec<DelegationTrustKey>,
        audience: impl Into<String>,
        boot_id: impl Into<String>,
        policy_digest: [u8; 32],
        replay_path: impl AsRef<Path>,
    ) -> Result<Self, DelegationError> {
        let keys = keys
            .into_iter()
            .map(|item| ((item.issuer, item.key_id), (item.key, item.role)))
            .collect();
        let legacy_path = replay_path.as_ref().to_path_buf();
        std::fs::create_dir_all(&legacy_path).map_err(|_| DelegationError::ReplayStore)?;
        let sqlite_path = PathBuf::from(format!("{}.sqlite", legacy_path.display()));
        if !sqlite_path.exists() && legacy_path.join("conf").exists() {
            return Err(DelegationError::ReplayMigrationRequired);
        }
        let replay = Connection::open(&sqlite_path).map_err(|_| DelegationError::ReplayStore)?;
        replay
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS delegation_replay (
                    replay_key BLOB PRIMARY KEY NOT NULL
                );
                CREATE TABLE IF NOT EXISTS delegation_revocations (
                    revocation_key BLOB PRIMARY KEY NOT NULL,
                    revoked_at_unix_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS delegation_key_revocations (
                    issuer TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    revoked_at_unix_ms INTEGER NOT NULL,
                    PRIMARY KEY (issuer, key_id)
                )",
            )
            .map_err(|_| DelegationError::ReplayStore)?;
        Ok(Self {
            keys,
            audience: audience.into(),
            boot_id: boot_id.into(),
            policy_digest,
            replay: Mutex::new(replay),
        })
    }

    /// Persist revocation of a signed claim without consuming its one-shot
    /// replay entry. Reopening the verifier retains the revocation decision.
    pub fn revoke(
        &self,
        assertion: &DelegationAssertion,
        now_unix_ms: u64,
    ) -> Result<(), DelegationError> {
        let claims = &assertion.claims;
        claims.validate()?;
        let (key, _) = self
            .keys
            .get(&(claims.issuer.clone(), claims.key_id.clone()))
            .ok_or(DelegationError::UntrustedKey)?;
        key.verify(
            &claims.signing_bytes(),
            &Signature::from_bytes(&assertion.signature),
        )
        .map_err(|_| DelegationError::Signature)?;
        let replay = self
            .replay
            .lock()
            .map_err(|_| DelegationError::ReplayStore)?;
        replay
            .execute(
                "INSERT OR IGNORE INTO delegation_revocations (revocation_key, revoked_at_unix_ms) VALUES (?1, ?2)",
                params![claims.revocation_key(), now_unix_ms],
            )
            .map_err(|_| DelegationError::ReplayStore)?;
        replay
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DelegationError::ReplayStore)
    }

    /// Retire a trusted issuer key. The decision is durable and applies to all
    /// claims signed by the key, including claims that have not been replayed.
    pub fn revoke_key(
        &self,
        issuer: &str,
        key_id: &str,
        now_unix_ms: u64,
    ) -> Result<(), DelegationError> {
        if issuer.is_empty() || key_id.is_empty() {
            return Err(DelegationError::Bounds);
        }
        if !self
            .keys
            .contains_key(&(issuer.to_string(), key_id.to_string()))
        {
            return Err(DelegationError::UntrustedKey);
        }
        let replay = self
            .replay
            .lock()
            .map_err(|_| DelegationError::ReplayStore)?;
        replay
            .execute(
                "INSERT OR IGNORE INTO delegation_key_revocations (issuer, key_id, revoked_at_unix_ms) VALUES (?1, ?2, ?3)",
                params![issuer, key_id, now_unix_ms],
            )
            .map_err(|_| DelegationError::ReplayStore)?;
        replay
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DelegationError::ReplayStore)
    }

    pub fn verify(
        &self,
        assertion: &DelegationAssertion,
        transport_subject: &str,
        action: Action,
        resource: &str,
        now_unix_ms: u64,
    ) -> Result<VerifiedCriDelegation, DelegationError> {
        let claims = &assertion.claims;
        claims.validate()?;
        let (key, role) = self
            .keys
            .get(&(claims.issuer.clone(), claims.key_id.clone()))
            .ok_or(DelegationError::UntrustedKey)?;
        let key_revoked: bool = self
            .replay
            .lock()
            .map_err(|_| DelegationError::ReplayStore)?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM delegation_key_revocations WHERE issuer = ?1 AND key_id = ?2)",
                params![claims.issuer, claims.key_id],
                |row| row.get(0),
            )
            .map_err(|_| DelegationError::ReplayStore)?;
        if key_revoked {
            return Err(DelegationError::KeyRevoked);
        }
        key.verify(
            &claims.signing_bytes(),
            &Signature::from_bytes(&assertion.signature),
        )
        .map_err(|_| DelegationError::Signature)?;
        let replay = self
            .replay
            .lock()
            .map_err(|_| DelegationError::ReplayStore)?;
        let revoked: bool = replay
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM delegation_revocations WHERE revocation_key = ?1)",
                params![claims.revocation_key()],
                |row| row.get(0),
            )
            .map_err(|_| DelegationError::ReplayStore)?;
        if revoked {
            return Err(DelegationError::Revoked);
        }
        if claims.deadline_unix_ms < now_unix_ms {
            return Err(DelegationError::Expired);
        }
        if claims.transport_subject != transport_subject
            || claims.audience != self.audience
            || claims.boot_id != self.boot_id
            || claims.policy_digest != self.policy_digest
            || !claims.allowed_actions.contains(&action)
            || !claims
                .allowed_resources
                .iter()
                .any(|allowed| allowed == resource)
        {
            return Err(DelegationError::Scope);
        }
        let replay_key = claims.replay_key();
        let inserted = replay
            .execute(
                "INSERT OR IGNORE INTO delegation_replay (replay_key) VALUES (?1)",
                params![replay_key],
            )
            .map_err(|_| DelegationError::ReplayStore)?;
        if inserted == 0 {
            return Err(DelegationError::Replay);
        }
        replay
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DelegationError::ReplayStore)?;
        Ok(VerifiedCriDelegation(ResolvedPrincipal::new(
            claims.delegated_principal.clone(),
            *role,
        )))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DelegationError {
    #[error("delegation wire value is malformed")]
    Malformed,
    #[error("delegation value exceeds its bound")]
    Bounds,
    #[error("delegation signing key is not trusted")]
    UntrustedKey,
    #[error("delegation signature is invalid")]
    Signature,
    #[error("delegation is expired")]
    Expired,
    #[error("delegation context or scope does not match")]
    Scope,
    #[error("delegated claim attempts to broaden or reuse its parent authority")]
    Attenuation,
    #[error("delegation was already used")]
    Replay,
    #[error("delegation was revoked")]
    Revoked,
    #[error("delegation signing key was revoked")]
    KeyRevoked,
    #[error("durable delegation replay store failed")]
    ReplayStore,
    #[error("legacy Sled delegation replay detected; the Sled importer was removed. See docs/architecture/legacy-sled-importers.md")]
    ReplayMigrationRequired,
}

#[cfg(test)]
mod tests {

    #[test]
    fn default_open_rejects_legacy_replay_directory() {
        let temp = tempfile::tempdir().expect("replay directory");
        std::fs::create_dir(temp.path().join("conf")).expect("legacy marker");
        let error = match super::CriDelegationVerifier::open(
            Vec::new(),
            "audience",
            "boot",
            [0; 32],
            temp.path(),
        ) {
            Ok(_) => panic!("legacy boundary"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("legacy-sled-importers"));
    }
}
