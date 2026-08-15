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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManagedOverlayRequest {
    AttachContainer {
        overlay_id: String,
        container_id: String,
        now_unix: i64,
    },
    DetachContainer {
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
    pub fn request(
        &self,
        request: &ManagedOverlayRequest,
    ) -> Result<ManagedOverlayResponse, ManagedOverlayError> {
        self.send(request)
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
    ) -> Result<ManagedOverlayResponse, ManagedOverlayError> {
        let parameters = managed_parameters(request)?;
        let grant = issuer.for_authorized(
            proof,
            intent,
            &parameters,
            boot_id,
            wall_deadline_secs,
            monotonic_deadline_millis,
            nonce,
            "ferrocrate-runtime",
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
