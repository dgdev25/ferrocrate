//! Signed, single-use capabilities for the privileged networking helper.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{gate::AuthorizedRequest, Action};
use crate::witness::DurableIntent;

pub const GRANT_SCHEMA_VERSION: u16 = 1;
pub const MAX_GRANT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
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
    fields: Vec<(String, String)>,
    fds: Vec<FdBinding>,
}

impl GrantParameters {
    pub fn new(
        operation: impl Into<String>,
        mut fields: Vec<(String, String)>,
        mut fds: Vec<(u16, u64, u64)>,
    ) -> Result<Self, GrantBuildError> {
        let operation = operation.into();
        if operation.is_empty() || operation.len() > 64 || fields.len() > 128 || fds.len() > 32 {
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
        if fds.windows(2).any(|v| v[0].0 == v[1].0) {
            return Err(GrantBuildError::InvalidParameters);
        }
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
        let bytes = serde_json::to_vec(self).expect("bounded grant parameters serialize");
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
    pub issuer: String,
    pub key_id: String,
    pub kind: GrantKind,
    pub origin_request_id: Option<String>,
    pub live_identity_digest: Option<[u8; 32]>,
}

impl GrantClaims {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
    pub fn cleanup(
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
    key_id: String,
    key: SigningKey,
}
impl GrantIssuer {
    pub fn new(key_id: impl Into<String>, key: SigningKey) -> Self {
        Self {
            key_id: key_id.into(),
            key,
        }
    }
    pub fn sign(&self, mut claims: GrantClaims) -> HelperGrant {
        claims.key_id.clone_from(&self.key_id);
        let signature = self.key.sign(&signing_bytes(&claims));
        HelperGrant {
            claims,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        }
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
        let resource = ResourceBinding::new(
            proof.canonical().resource_id(),
            intent.execution_generation(),
        )?;
        Ok(self.sign(GrantClaims::new(
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
        )?))
    }
}

pub fn signing_bytes(claims: &GrantClaims) -> Vec<u8> {
    [
        b"ferrocrate.helper-grant.v1\0".as_slice(),
        serde_json::to_vec(claims)
            .expect("grant claims serialize")
            .as_slice(),
    ]
    .concat()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum GrantBuildError {
    #[error("invalid resource binding")]
    InvalidResource,
    #[error("invalid normalized parameters")]
    InvalidParameters,
    #[error("invalid grant claims")]
    InvalidClaims,
    #[error("invalid cleanup provenance")]
    InvalidCleanup,
    #[error("action cannot be delegated to helper")]
    UnsupportedAction,
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
