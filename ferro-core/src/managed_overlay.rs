use crate::{
    authorization::{
        gate::AuthorizedRequest,
        helper_grant::{GrantBuildError, GrantIssuer, GrantParameters, HelperGrant},
    },
    witness::DurableIntent,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedOverlayRef(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManagedOverlayError {
    #[error("managed overlay reference must use managed:<overlay-id>")]
    InvalidReference,
    #[error("managed overlay id is empty")]
    EmptyId,
    #[error("authorized helper grant could not be derived: {0}")]
    Grant(#[from] GrantBuildError),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedOverlayDelegation {
    pub parent: HelperGrant,
}

impl ManagedOverlayDelegation {
    pub fn new(parent: HelperGrant) -> Self {
        Self { parent }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegatedManagedOverlayRequest {
    pub request: ManagedOverlayRequest,
    pub delegation: ManagedOverlayDelegation,
}

pub const MANAGED_OVERLAY_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ManagedOverlayCompatibilityMode {
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyManagedOverlayRequest {
    pub schema_version: u16,
    pub mode: ManagedOverlayCompatibilityMode,
    pub request: ManagedOverlayRequest,
}

impl ManagedOverlayRef {
    pub fn parse(value: &str) -> Result<Self, ManagedOverlayError> {
        let id = value
            .strip_prefix("managed:")
            .ok_or(ManagedOverlayError::InvalidReference)?;
        if id.is_empty()
            || id.len() > 15
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(ManagedOverlayError::EmptyId);
        }
        Ok(Self(id.to_string()))
    }

    pub fn id(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedOverlayAttachment {
    pub overlay_id: String,
    pub container_id: String,
    pub bridge: String,
    pub netns: String,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub gateway: String,
    pub prefix: u8,
    pub mtu: u16,
    #[serde(default)]
    pub cleanup_provenance: Option<ManagedCleanupProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCleanupProvenance {
    pub origin_request_id: String,
    pub live_identity_digest: [u8; 32],
    pub resource_uuid: String,
    pub resource_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManagedOverlayRequest {
    AttachContainer {
        overlay_id: String,
        container_id: String,
        now_unix: i64,
    },
    DetachContainer {
        overlay_id: String,
        container_id: String,
        now_unix: i64,
    },
    InspectOverlay {
        overlay_id: String,
        now_unix: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManagedOverlayResponse {
    Attached(ManagedOverlayAttachment),
    Detached {
        released: bool,
    },
    Overlay {
        overlay_id: String,
        bridge: String,
        gateway: String,
        prefix: u8,
        mtu: u16,
    },
    Rejected {
        reason: String,
    },
}

#[cfg(unix)]
pub struct ManagedOverlayClient {
    socket: std::path::PathBuf,
    timeout: Duration,
}

/// Explicit compatibility authority for the pre-authorization agent protocol.
pub(crate) struct LegacyManagedOverlayMode(());

impl LegacyManagedOverlayMode {
    pub(crate) fn disabled_only() -> Result<Self, ManagedOverlayError> {
        let mode = std::env::var("FERROCRATE_AUTHORIZATION_MODE")
            .map_err(|_| ManagedOverlayError::Grant(GrantBuildError::IntentMismatch))?;
        let digest = std::env::var("FERROCRATE_AUTHORIZATION_POLICY_DIGEST")
            .ok()
            .map(|value| {
                use base64::Engine as _;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| ManagedOverlayError::Grant(GrantBuildError::IntentMismatch))?;
                bytes
                    .try_into()
                    .map_err(|_| ManagedOverlayError::Grant(GrantBuildError::IntentMismatch))
            })
            .transpose()?;
        let service = crate::authorization::AuthorizationServiceMode::parse(&mode, digest)
            .map_err(|_| ManagedOverlayError::Grant(GrantBuildError::IntentMismatch))?;
        if service.mode() == crate::authorization::AuthorizationMode::Disabled {
            Ok(Self(()))
        } else {
            Err(ManagedOverlayError::Grant(GrantBuildError::IntentMismatch))
        }
    }
}

#[cfg(unix)]
impl ManagedOverlayClient {
    pub fn new(socket: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: Duration::from_secs(5),
        }
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub(crate) fn request_legacy(
        &self,
        _mode: &LegacyManagedOverlayMode,
        request: &ManagedOverlayRequest,
    ) -> Result<ManagedOverlayResponse, ManagedOverlayError> {
        self.send(&LegacyManagedOverlayRequest {
            schema_version: MANAGED_OVERLAY_PROTOCOL_VERSION,
            mode: ManagedOverlayCompatibilityMode::Disabled,
            request: request.clone(),
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn request_authorized(
        &self,
        request: &ManagedOverlayRequest,
        proof: &AuthorizedRequest,
        intent: &DurableIntent,
        issuer: &GrantIssuer,
        boot_id: &str,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
        issuer_name: &str,
    ) -> Result<ManagedOverlayResponse, ManagedOverlayError> {
        let parameters = managed_parameters(request)?;
        let action = match request {
            ManagedOverlayRequest::AttachContainer { .. } => {
                crate::authorization::helper_grant::GrantAction::NetworkAttach
            }
            ManagedOverlayRequest::DetachContainer { .. } => {
                crate::authorization::helper_grant::GrantAction::NetworkDetach
            }
            ManagedOverlayRequest::InspectOverlay { .. } => {
                return Err(ManagedOverlayError::Grant(
                    GrantBuildError::UnsupportedAction,
                ))
            }
        };
        let grant = issuer.for_managed_overlay_parent(
            proof,
            intent,
            action,
            &parameters,
            boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            issuer_name,
        )?;
        self.send(&DelegatedManagedOverlayRequest {
            request: request.clone(),
            delegation: ManagedOverlayDelegation::new(grant),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_cleanup_authorized(
        &self,
        request: &ManagedOverlayRequest,
        proof: &AuthorizedRequest,
        intent: &DurableIntent,
        provenance: &ManagedCleanupProvenance,
        issuer: &GrantIssuer,
        boot_id: &str,
        wall_deadline_secs: u64,
        monotonic_deadline_millis: u64,
        nonce: [u8; 16],
        issuer_name: &str,
    ) -> Result<ManagedOverlayResponse, ManagedOverlayError> {
        if !matches!(request, ManagedOverlayRequest::DetachContainer { .. }) {
            return Err(ManagedOverlayError::Grant(
                GrantBuildError::UnsupportedAction,
            ));
        }
        let parameters = managed_parameters(request)?;
        let grant = issuer.for_managed_overlay_cleanup(
            proof,
            intent,
            &parameters,
            provenance,
            boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            issuer_name,
        )?;
        self.send(&DelegatedManagedOverlayRequest {
            request: request.clone(),
            delegation: ManagedOverlayDelegation::new(grant),
        })
    }
    fn send<T: Serialize + ?Sized>(
        &self,
        request: &T,
    ) -> Result<ManagedOverlayResponse, ManagedOverlayError> {
        let mut stream =
            UnixStream::connect(&self.socket).map_err(|_| ManagedOverlayError::InvalidReference)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| ManagedOverlayError::InvalidReference)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| ManagedOverlayError::InvalidReference)?;
        let body =
            serde_json::to_vec(request).map_err(|_| ManagedOverlayError::InvalidReference)?;
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .map_err(|_| ManagedOverlayError::InvalidReference)?;
        stream
            .write_all(&body)
            .map_err(|_| ManagedOverlayError::InvalidReference)?;
        let mut prefix = [0_u8; 4];
        stream
            .read_exact(&mut prefix)
            .map_err(|_| ManagedOverlayError::InvalidReference)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > 256 * 1024 {
            return Err(ManagedOverlayError::InvalidReference);
        }
        let mut response = vec![0_u8; length];
        stream
            .read_exact(&mut response)
            .map_err(|_| ManagedOverlayError::InvalidReference)?;
        serde_json::from_slice(&response).map_err(|_| ManagedOverlayError::InvalidReference)
    }
}

pub fn managed_parameters(
    request: &ManagedOverlayRequest,
) -> Result<GrantParameters, ManagedOverlayError> {
    let (operation, fields) = match request {
        ManagedOverlayRequest::AttachContainer {
            overlay_id,
            container_id,
            ..
        } => (
            "endpoint.attach",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("container_id".into(), container_id.clone()),
            ],
        ),
        ManagedOverlayRequest::DetachContainer { container_id, .. } => (
            "endpoint.detach",
            vec![("container_id".into(), container_id.clone())],
        ),
        ManagedOverlayRequest::InspectOverlay { overlay_id, .. } => (
            "overlay.inspect",
            vec![("overlay_id".into(), overlay_id.clone())],
        ),
    };
    Ok(GrantParameters::new(operation, fields, vec![])?)
}

#[cfg(test)]
mod tests {
    use super::{ManagedOverlayError, ManagedOverlayRef};

    #[test]
    fn parses_strict_managed_overlay_reference() {
        assert_eq!(
            ManagedOverlayRef::parse("managed:prod").unwrap().id(),
            "prod"
        );
        assert_eq!(
            ManagedOverlayRef::parse("bridge"),
            Err(ManagedOverlayError::InvalidReference)
        );
        assert_eq!(
            ManagedOverlayRef::parse("managed:"),
            Err(ManagedOverlayError::EmptyId)
        );
        assert_eq!(
            ManagedOverlayRef::parse("managed/unsafe"),
            Err(ManagedOverlayError::InvalidReference)
        );
    }
}
