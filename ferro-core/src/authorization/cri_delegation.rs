//! Trusted verification boundary for bounded CRI delegation capabilities.

use std::{collections::HashMap, path::Path};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
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

    fn replay_key(&self) -> Vec<u8> {
        let mut key = b"ferrocrate/cri-delegation-replay/v1\0".to_vec();
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
    replay: sled::Db,
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
        let replay = sled::open(replay_path).map_err(|_| DelegationError::ReplayStore)?;
        Ok(Self {
            keys,
            audience: audience.into(),
            boot_id: boot_id.into(),
            policy_digest,
            replay,
        })
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
        key.verify(
            &claims.signing_bytes(),
            &Signature::from_bytes(&assertion.signature),
        )
        .map_err(|_| DelegationError::Signature)?;
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
        if self
            .replay
            .compare_and_swap(replay_key, None as Option<&[u8]>, Some(&[1]))
            .map_err(|_| DelegationError::ReplayStore)?
            .is_err()
        {
            return Err(DelegationError::Replay);
        }
        self.replay
            .flush()
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
    #[error("delegation was already used")]
    Replay,
    #[error("durable delegation replay store failed")]
    ReplayStore,
}
