use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ferro_core::authorization::helper_grant::{
    signing_bytes, GrantAction, GrantClaims, GrantKind, GrantParameters, HelperGrant,
    GRANT_SCHEMA_VERSION, MAX_GRANT_BYTES,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GrantResult {
    pub request_id: String,
    pub nonce: [u8; 16],
    pub result_identity: String,
    pub outcome: String,
}

#[derive(Default, Deserialize, Serialize)]
struct LedgerState {
    consumed: BTreeMap<String, GrantOperation>,
    results: BTreeMap<String, GrantResult>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
enum GrantPhase {
    Pending,
    ConsumedBeforeEffect,
    Succeeded,
    Failed,
    OutcomeUnknown,
}

#[derive(Deserialize, Serialize)]
struct GrantOperation {
    claims: GrantClaims,
    phase: GrantPhase,
}

pub struct GrantLedger {
    path: Option<PathBuf>,
    _writer_lock: Option<std::fs::File>,
    state: LedgerState,
}
impl GrantLedger {
    pub fn memory() -> Self {
        Self {
            path: None,
            _writer_lock: None,
            state: LedgerState::default(),
        }
    }
    pub fn open(path: PathBuf) -> Result<Self, GrantError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = path.with_extension("lock");
        let writer_lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)?;
        writer_lock
            .try_lock_exclusive()
            .map_err(|_| GrantError::Locked)?;
        let state = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            LedgerState::default()
        };
        let mut ledger = Self {
            path: Some(path),
            _writer_lock: Some(writer_lock),
            state,
        };
        ledger.quarantine_unknown_after_restart()?;
        Ok(ledger)
    }
    fn consume(&mut self, grant: &HelperGrant) -> Result<(), GrantError> {
        let nonce = hex(&grant.claims.nonce);
        if self.state.consumed.contains_key(&nonce) {
            return Err(GrantError::Replay);
        }
        self.state.consumed.insert(
            nonce.clone(),
            GrantOperation {
                claims: grant.claims.clone(),
                phase: GrantPhase::Pending,
            },
        );
        self.persist()?;
        self.state
            .consumed
            .get_mut(&nonce)
            .expect("inserted nonce")
            .phase = GrantPhase::ConsumedBeforeEffect;
        self.persist()
    }
    fn result(&self, request_id: &str) -> Option<&GrantResult> {
        self.state.results.get(request_id)
    }
    fn record(&mut self, result: GrantResult, phase: GrantPhase) -> Result<(), GrantError> {
        if self
            .state
            .consumed
            .get(&hex(&result.nonce))
            .map(|operation| operation.claims.request_id.as_str())
            != Some(result.request_id.as_str())
        {
            return Err(GrantError::NotConsumed);
        }
        if let Some(old) = self.state.results.get(&result.request_id) {
            return if old == &result {
                Ok(())
            } else {
                Err(GrantError::ResultConflict)
            };
        }
        let nonce = hex(&result.nonce);
        self.state.results.insert(result.request_id.clone(), result);
        self.state
            .consumed
            .get_mut(&nonce)
            .expect("validated nonce")
            .phase = phase;
        self.persist()
    }
    fn validates_cleanup(&self, grant: &HelperGrant) -> bool {
        let Some(origin) = grant.claims.origin_request_id.as_deref() else {
            return false;
        };
        let Some(result) = self.state.results.get(origin) else {
            return false;
        };
        let source = self
            .state
            .consumed
            .values()
            .find(|operation| operation.claims.request_id == origin)
            .map(|operation| &operation.claims);
        let Some(source) = source else {
            return false;
        };
        let live: [u8; 32] = Sha256::digest(
            [
                b"ferrocrate.helper-live-identity.v1\0".as_slice(),
                result.result_identity.as_bytes(),
            ]
            .concat(),
        )
        .into();
        source.boot_id == grant.claims.boot_id
            && source.resource == grant.claims.resource
            && matches!(
                source.action,
                GrantAction::NetworkCreate | GrantAction::NetworkAttach
            )
            && grant.claims.live_identity_digest == Some(live)
    }
    fn mark_outcome_unknown(&mut self, nonce: [u8; 16]) -> Result<(), GrantError> {
        let operation = self
            .state
            .consumed
            .get_mut(&hex(&nonce))
            .ok_or(GrantError::NotConsumed)?;
        operation.phase = GrantPhase::OutcomeUnknown;
        self.persist()
    }
    fn quarantine_unknown_after_restart(&mut self) -> Result<(), GrantError> {
        let unknown = self
            .state
            .consumed
            .iter()
            .filter_map(|(nonce, operation)| {
                matches!(operation.phase, GrantPhase::OutcomeUnknown)
                    .then(|| (nonce.clone(), operation.claims.clone()))
            })
            .collect::<Vec<_>>();
        if unknown.is_empty() {
            return Ok(());
        }
        for (nonce, claims) in unknown {
            self.state
                .results
                .entry(claims.request_id.clone())
                .or_insert(GrantResult {
                    request_id: claims.request_id,
                    nonce: claims.nonce,
                    result_identity: format!(
                        "quarantine:{}:{:?}",
                        claims.resource.resource_uuid, claims.action
                    ),
                    outcome: "quarantined_after_unknown_effect".into(),
                });
            if let Some(operation) = self.state.consumed.get_mut(&nonce) {
                operation.phase = GrantPhase::Failed;
            }
        }
        self.persist()
    }
    fn persist(&self) -> Result<(), GrantError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&serde_json::to_vec(&self.state)?)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            OpenOptions::new().read(true).open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedGrant {
    request_id: String,
    nonce: [u8; 16],
}
impl ConsumedGrant {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}
impl ConsumedGrant {
    pub(crate) fn restored(request_id: &str, nonce: [u8; 16]) -> Self {
        Self {
            request_id: request_id.into(),
            nonce,
        }
    }
}

pub struct GrantKeyring {
    active: BTreeMap<String, VerifyingKey>,
}
impl GrantKeyring {
    pub fn new(key_id: impl Into<String>, key: VerifyingKey) -> Self {
        Self {
            active: BTreeMap::from([(key_id.into(), key)]),
        }
    }
    pub fn add_overlap(
        &mut self,
        key_id: impl Into<String>,
        key: VerifyingKey,
    ) -> Result<(), GrantError> {
        if self.active.insert(key_id.into(), key).is_some() {
            return Err(GrantError::WrongIssuer);
        }
        Ok(())
    }
    pub fn retire(&mut self, key_id: &str) -> Result<(), GrantError> {
        self.active
            .remove(key_id)
            .map(|_| ())
            .ok_or(GrantError::WrongIssuer)
    }
    fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.active.get(key_id)
    }
}

pub struct GrantVerifier {
    keys: GrantKeyring,
    issuer: String,
    boot_id: String,
    ledger: GrantLedger,
}
impl GrantVerifier {
    pub fn add_verification_key(
        &mut self,
        key_id: impl Into<String>,
        key: VerifyingKey,
    ) -> Result<(), GrantError> {
        self.keys.add_overlap(key_id, key)
    }
    pub fn retire_verification_key(&mut self, key_id: &str) -> Result<(), GrantError> {
        self.keys.retire(key_id)
    }
    pub fn new(
        key: VerifyingKey,
        issuer: impl Into<String>,
        key_id: impl Into<String>,
        boot_id: impl Into<String>,
        ledger: GrantLedger,
    ) -> Self {
        Self {
            keys: GrantKeyring::new(key_id, key),
            issuer: issuer.into(),
            boot_id: boot_id.into(),
            ledger,
        }
    }
    pub fn memory(
        key: VerifyingKey,
        issuer: impl Into<String>,
        boot_id: impl Into<String>,
    ) -> Self {
        Self::new(key, issuer, "key-1", boot_id, GrantLedger::memory())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        grant: &HelperGrant,
        action: GrantAction,
        uuid: &str,
        generation: u64,
        parameters: &GrantParameters,
        wall_now: u64,
        monotonic_now: u64,
    ) -> Result<(), GrantError> {
        if serde_json::to_vec(grant)?.len() > MAX_GRANT_BYTES {
            return Err(GrantError::Oversized);
        }
        if grant.claims.schema_version != GRANT_SCHEMA_VERSION || grant.claims.issuer != self.issuer
        {
            return Err(GrantError::WrongIssuer);
        }
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&grant.signature)
            .map_err(|_| GrantError::InvalidSignature)?;
        self.keys
            .get(&grant.claims.key_id)
            .ok_or(GrantError::WrongIssuer)?
            .verify(
                &signing_bytes(&grant.claims),
                &Signature::from_slice(&signature).map_err(|_| GrantError::InvalidSignature)?,
            )
            .map_err(|_| GrantError::InvalidSignature)?;
        if grant.claims.boot_id != self.boot_id {
            return Err(GrantError::WrongBoot);
        }
        if wall_now >= grant.claims.wall_deadline_secs
            || monotonic_now >= grant.claims.monotonic_deadline_millis
        {
            return Err(GrantError::Expired);
        }
        if grant.claims.kind == GrantKind::Cleanup && !action.is_cleanup() {
            return Err(GrantError::CleanupEscalation);
        }
        if grant.claims.action != action {
            return Err(GrantError::ActionMismatch);
        }
        if grant.claims.resource.resource_uuid != uuid
            || grant.claims.resource.generation != generation
        {
            return Err(GrantError::ResourceMismatch);
        }
        if grant.claims.parameter_digest != parameters.digest() {
            return Err(GrantError::ParameterMismatch);
        }
        if grant.claims.kind == GrantKind::Cleanup
            && (grant
                .claims
                .origin_request_id
                .as_deref()
                .is_none_or(str::is_empty)
                || grant
                    .claims
                    .live_identity_digest
                    .is_none_or(|v| v == [0; 32]))
        {
            return Err(GrantError::CleanupProvenance);
        }
        if grant.claims.kind == GrantKind::Cleanup && !self.ledger.validates_cleanup(grant) {
            return Err(GrantError::CleanupProvenance);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify_and_consume(
        &mut self,
        grant: &HelperGrant,
        action: GrantAction,
        uuid: &str,
        generation: u64,
        parameters: &GrantParameters,
        wall_now: u64,
        monotonic_now: u64,
    ) -> Result<ConsumedGrant, GrantError> {
        self.verify(
            grant,
            action,
            uuid,
            generation,
            parameters,
            wall_now,
            monotonic_now,
        )?;
        self.ledger.consume(grant)?;
        Ok(ConsumedGrant {
            request_id: grant.claims.request_id.clone(),
            nonce: grant.claims.nonce,
        })
    }
    pub fn record_result(
        &mut self,
        consumed: &ConsumedGrant,
        identity: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Result<(), GrantError> {
        self.ledger.record(
            GrantResult {
                request_id: consumed.request_id.clone(),
                nonce: consumed.nonce,
                result_identity: identity.into(),
                outcome: outcome.into(),
            },
            GrantPhase::Succeeded,
        )
    }
    pub fn record_failure(
        &mut self,
        consumed: &ConsumedGrant,
        identity: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Result<(), GrantError> {
        self.ledger.record(
            GrantResult {
                request_id: consumed.request_id.clone(),
                nonce: consumed.nonce,
                result_identity: identity.into(),
                outcome: outcome.into(),
            },
            GrantPhase::Failed,
        )
    }
    pub fn arm_effect(&mut self, consumed: &ConsumedGrant) -> Result<(), GrantError> {
        self.ledger.mark_outcome_unknown(consumed.nonce)
    }
    pub fn result(&self, request_id: &str) -> Option<&GrantResult> {
        self.ledger.result(request_id)
    }
}

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("grant ledger already has a writer")]
    Locked,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("wrong issuer or schema")]
    WrongIssuer,
    #[error("wrong boot")]
    WrongBoot,
    #[error("grant expired")]
    Expired,
    #[error("action mismatch")]
    ActionMismatch,
    #[error("cleanup authority escalation")]
    CleanupEscalation,
    #[error("resource mismatch")]
    ResourceMismatch,
    #[error("parameter or descriptor mismatch")]
    ParameterMismatch,
    #[error("cleanup provenance missing")]
    CleanupProvenance,
    #[error("grant replay")]
    Replay,
    #[error("result without consumed nonce")]
    NotConsumed,
    #[error("conflicting result identity")]
    ResultConflict,
    #[error("grant oversized")]
    Oversized,
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding: {0}")]
    Encoding(#[from] serde_json::Error),
}
impl PartialEq for GrantError {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
