//! Signed, single-use capabilities for the privileged networking helper.

use super::helper_grant_encoding::{is_uuid, push_text};
pub use super::helper_grant_error::GrantBuildError;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{gate::AuthorizedRequest, Action};
use crate::witness::DurableIntent;

pub const GRANT_SCHEMA_VERSION: u16 = 1;
pub const MAX_GRANT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum GrantAction {
    NetworkCreate,
    NetworkDelete,
    NetworkAttach,
    NetworkDetach,
    NetworkInspect,
}

impl GrantAction {
    pub fn from_authorization(action: Action) -> Option<Self> {
        match action {
            Action::NetworkCreate => Some(Self::NetworkCreate),
            Action::NetworkDelete => Some(Self::NetworkDelete),
            Action::NetworkAttach => Some(Self::NetworkAttach),
            Action::NetworkDetach => Some(Self::NetworkDetach),
            _ => None,
        }
    }
    pub const fn is_cleanup(self) -> bool {
        matches!(self, Self::NetworkDelete | Self::NetworkDetach)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum GrantKind {
    Mutation,
    Cleanup,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBinding {
    pub resource_uuid: String,
    pub generation: u64,
}

impl ResourceBinding {
    pub fn new(resource_uuid: impl Into<String>, generation: u64) -> Result<Self, GrantBuildError> {
        let resource_uuid = resource_uuid.into();
        if !is_uuid(&resource_uuid) || generation == 0 {
            return Err(GrantBuildError::InvalidResource);
        }
        Ok(Self {
            resource_uuid: resource_uuid.to_ascii_lowercase(),
            generation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FdBinding {
    pub position: u16,
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantParameters {
    operation: String,
    pub(super) fields: Vec<(String, String)>,
    fds: Vec<FdBinding>,
}

impl GrantParameters {
    pub fn new(
        operation: impl Into<String>,
        mut fields: Vec<(String, String)>,
        mut fds: Vec<(u16, u64, u64)>,
    ) -> Result<Self, GrantBuildError> {
        let operation = operation.into();
        if operation.is_empty() || operation.len() > 64 || fields.len() > 128 || !fds.is_empty() {
            return Err(GrantBuildError::InvalidParameters);
        }
        fields.sort();
        if fields.windows(2).any(|v| v[0].0 == v[1].0)
            || fields
                .iter()
                .any(|(k, v)| k.is_empty() || k.len() > 64 || v.len() > 4096)
        {
            return Err(GrantBuildError::InvalidParameters);
        }
        fds.sort();
        Ok(Self {
            operation,
            fields,
            fds: fds
                .into_iter()
                .map(|(position, device, inode)| FdBinding {
                    position,
                    device,
                    inode,
                })
                .collect(),
        })
    }
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        push_text(&mut bytes, &self.operation);
        bytes.extend_from_slice(&(self.fields.len() as u16).to_be_bytes());
        for (key, value) in &self.fields {
            push_text(&mut bytes, key);
            push_text(&mut bytes, value);
        }
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        Sha256::digest([b"ferrocrate.helper-parameters.v1\0".as_slice(), &bytes].concat()).into()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClaims {
    pub schema_version: u16,
    pub request_id: String,
    pub action: GrantAction,
    pub resource: ResourceBinding,
    pub parameter_digest: [u8; 32],
    pub boot_id: String,
    pub wall_deadline_secs: u64,
    pub monotonic_deadline_millis: u64,
    pub nonce: [u8; 16],
    pub operation_id: [u8; 16],
    pub request_digest: [u8; 32],
    pub precondition_digest: [u8; 32],
    pub recovery_recipe_digest: [u8; 32],
    pub issuer: String,
    pub key_id: String,
    pub kind: GrantKind,
    pub origin_request_id: Option<String>,
    pub live_identity_digest: Option<[u8; 32]>,
}

impl GrantClaims {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request_id: impl Into<String>,
        action: GrantAction,
        resource: ResourceBinding,
        parameter_digest: [u8; 32],
        boot_id: impl Into<String>,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
        issuer: impl Into<String>,
        key_id: impl Into<String>,
        kind: GrantKind,
    ) -> Result<Self, GrantBuildError> {
        let value = Self {
            schema_version: GRANT_SCHEMA_VERSION,
            request_id: request_id.into(),
            action,
            resource,
            parameter_digest,
            boot_id: boot_id.into(),
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            operation_id: nonce,
            request_digest: parameter_digest,
            precondition_digest: parameter_digest,
            recovery_recipe_digest: parameter_digest,
            issuer: issuer.into(),
            key_id: key_id.into(),
            kind,
            origin_request_id: None,
            live_identity_digest: None,
        };
        if value.request_id.is_empty()
            || value.request_id.len() > 128
            || value.boot_id.is_empty()
            || value.issuer.is_empty()
            || value.key_id.is_empty()
            || nonce == [0; 16]
        {
            return Err(GrantBuildError::InvalidClaims);
        }
        Ok(value)
    }
    pub(crate) fn cleanup(
        mut self,
        origin_request_id: impl Into<String>,
        live_identity_digest: [u8; 32],
    ) -> Result<Self, GrantBuildError> {
        if !self.action.is_cleanup() || live_identity_digest == [0; 32] {
            return Err(GrantBuildError::InvalidCleanup);
        }
        self.kind = GrantKind::Cleanup;
        self.origin_request_id = Some(origin_request_id.into());
        self.live_identity_digest = Some(live_identity_digest);
        Ok(self)
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HelperGrant {
    pub claims: GrantClaims,
    pub signature: String,
}

pub struct VerifiedHelperGrant(HelperGrant);
impl VerifiedHelperGrant {
    pub fn verify(
        grant: HelperGrant,
        key: &VerifyingKey,
        issuer: &str,
        boot_id: &str,
    ) -> Result<Self, GrantBuildError> {
        if grant.claims.schema_version != GRANT_SCHEMA_VERSION
            || grant.claims.issuer != issuer
            || grant.claims.boot_id != boot_id
        {
            return Err(GrantBuildError::InvalidClaims);
        }
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&grant.signature)
            .map_err(|_| GrantBuildError::InvalidClaims)?;
        key.verify(
            &signing_bytes(&grant.claims),
            &Signature::from_slice(&signature).map_err(|_| GrantBuildError::InvalidClaims)?,
        )
        .map_err(|_| GrantBuildError::InvalidClaims)?;
        Ok(Self(grant))
    }
    pub fn claims(&self) -> &GrantClaims {
        &self.0.claims
    }
}

impl std::fmt::Debug for HelperGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperGrant")
            .field("request_id", &self.claims.request_id)
            .field("key_id", &self.claims.key_id)
            .field("signature", &"[redacted]")
            .finish()
    }
}

pub struct GrantIssuer {
    pub(super) key_id: String,
    key: SigningKey,
}
impl GrantIssuer {
    pub(crate) fn new(key_id: impl Into<String>, key: SigningKey) -> Self {
        Self {
            key_id: key_id.into(),
            key,
        }
    }
    #[cfg(unix)]
    pub fn from_key_file(
        key_id: impl Into<String>,
        path: &std::path::Path,
        expected_uid: u32,
    ) -> Result<Self, GrantBuildError> {
        use std::{
            io::Read,
            os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        };
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| GrantBuildError::KeyCustody)?;
        let metadata = file.metadata().map_err(|_| GrantBuildError::KeyCustody)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != expected_uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(GrantBuildError::KeyCustody);
        }
        let mut bytes = Vec::with_capacity(32);
        file.read_to_end(&mut bytes)
            .map_err(|_| GrantBuildError::KeyCustody)?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| GrantBuildError::KeyCustody)?;
        Ok(Self::new(key_id, SigningKey::from_bytes(&key)))
    }
    pub(crate) fn sign(&self, mut claims: GrantClaims) -> HelperGrant {
        claims.key_id.clone_from(&self.key_id);
        let signature = self.key.sign(&signing_bytes(&claims));
        HelperGrant {
            claims,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        }
    }
    /// Mints one controller-policy-approved overlay mutation. This deliberately
    /// excludes endpoint and inspection authority.
    #[allow(clippy::too_many_arguments)]
    pub fn for_controller_overlay(
        &self,
        request_id: &str,
        action: GrantAction,
        resource: ResourceBinding,
        parameters: &GrantParameters,
        boot_id: &str,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
        issuer: &str,
        policy_digest: [u8; 32],
    ) -> Result<HelperGrant, GrantBuildError> {
        if !matches!(
            action,
            GrantAction::NetworkCreate | GrantAction::NetworkDelete
        ) || policy_digest == [0; 32]
        {
            return Err(GrantBuildError::UnsupportedAction);
        }
        let mut claims = GrantClaims::new(
            request_id,
            action,
            resource,
            parameters.digest(),
            boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            issuer,
            &self.key_id,
            GrantKind::Mutation,
        )?;
        claims.request_digest = parameters.digest();
        claims.precondition_digest = policy_digest;
        claims.recovery_recipe_digest = policy_digest;
        Ok(self.sign(claims))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn for_authorized(
        &self,
        proof: &AuthorizedRequest,
        intent: &DurableIntent,
        parameters: &GrantParameters,
        boot_id: &str,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
        issuer: &str,
    ) -> Result<HelperGrant, GrantBuildError> {
        let action = GrantAction::from_authorization(proof.canonical().context().action())
            .ok_or(GrantBuildError::UnsupportedAction)?;
        let request_digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(proof.canonical().context())
                .map_err(|_| GrantBuildError::InvalidClaims)?,
        )
        .into();
        if intent.execution_generation() != proof.canonical().resource_generation()
            || intent.request_digest() != request_digest
        {
            return Err(GrantBuildError::IntentMismatch);
        }
        let resource = ResourceBinding::new(
            proof.canonical().resource_id(),
            proof.canonical().resource_generation(),
        )?;
        let mut claims = GrantClaims::new(
            proof.canonical().request_id(),
            action,
            resource,
            parameters.digest(),
            boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            issuer,
            &self.key_id,
            GrantKind::Mutation,
        )?;
        claims.operation_id = *intent.operation_id().as_bytes();
        claims.request_digest = request_digest;
        claims.precondition_digest = request_digest;
        claims.recovery_recipe_digest = intent.decision_digest();
        Ok(self.sign(claims))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn for_managed_overlay_parent(
        &self,
        proof: &AuthorizedRequest,
        intent: &DurableIntent,
        action: GrantAction,
        parameters: &GrantParameters,
        boot_id: &str,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
        issuer: &str,
    ) -> Result<HelperGrant, GrantBuildError> {
        let allowed = matches!(
            (proof.canonical().context().action(), action),
            (
                Action::ContainerCreate | Action::ContainerRun,
                GrantAction::NetworkAttach
            ) | (Action::ContainerDelete, GrantAction::NetworkDetach)
        );
        let request_digest: [u8; 32] = Sha256::digest(
            serde_json::to_vec(proof.canonical().context())
                .map_err(|_| GrantBuildError::InvalidClaims)?,
        )
        .into();
        if !allowed
            || intent.execution_generation() != proof.canonical().resource_generation()
            || intent.request_digest() != request_digest
        {
            return Err(GrantBuildError::IntentMismatch);
        }
        let overlay_id = parameters
            .field("overlay_id")
            .ok_or(GrantBuildError::IntentMismatch)?;
        if !proof
            .canonical()
            .context()
            .facts()
            .network_ids()
            .iter()
            .any(|id| id == overlay_id)
        {
            return Err(GrantBuildError::IntentMismatch);
        }
        let resource = ResourceBinding::new(
            proof.canonical().resource_id(),
            proof.canonical().resource_generation(),
        )?;
        let mut claims = GrantClaims::new(
            proof.canonical().request_id(),
            action,
            resource,
            parameters.digest(),
            boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            issuer,
            &self.key_id,
            GrantKind::Mutation,
        )?;
        claims.operation_id = *intent.operation_id().as_bytes();
        claims.request_digest = request_digest;
        claims.precondition_digest = request_digest;
        claims.recovery_recipe_digest = intent.decision_digest();
        Ok(self.sign(claims))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn delegate_child(
        &self,
        parent: &VerifiedHelperGrant,
        child_request_id: &str,
        action: GrantAction,
        resource: ResourceBinding,
        parameters: &GrantParameters,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
    ) -> Result<HelperGrant, GrantBuildError> {
        let parent_claims = parent.claims();
        if parent_claims.kind != GrantKind::Mutation
            || parent_claims.action != action
            || resource.resource_uuid != parent_claims.resource.resource_uuid
            || resource.generation != parent_claims.resource.generation
            || wall_deadline_secs > parent_claims.wall_deadline_secs
            || monotonic_deadline_millis > parent_claims.monotonic_deadline_millis
        {
            return Err(GrantBuildError::IntentMismatch);
        }
        let mut claims = GrantClaims::new(
            child_request_id,
            action,
            resource,
            parameters.digest(),
            &parent_claims.boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            &parent_claims.issuer,
            &self.key_id,
            GrantKind::Mutation,
        )?;
        claims.operation_id = parent_claims.operation_id;
        claims.request_digest = parent_claims.request_digest;
        claims.precondition_digest = parent_claims.precondition_digest;
        claims.recovery_recipe_digest = parent_claims.recovery_recipe_digest;
        Ok(self.sign(claims))
    }
}

pub use super::helper_grant_encoding::signing_bytes;
