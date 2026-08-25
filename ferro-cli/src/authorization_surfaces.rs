use ferro_core::authorization::{
    PeerAuthMode, PrincipalResolutionError, PrincipalResolver, RequestOrigin, TransportPrincipal,
};
use std::{collections::BTreeMap, os::unix::net::UnixStream};

/// Caller-provided identity-like values retained exclusively for diagnostics.
#[derive(Clone, Debug, Default)]
pub struct DockerTelemetry {
    headers: BTreeMap<String, String>,
    labels: BTreeMap<String, String>,
}
impl DockerTelemetry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }
    pub fn with_label(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(name.into(), value.into());
        self
    }
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
    pub fn label_value(&self, name: &str) -> Option<&str> {
        self.labels.get(name).map(String::as_str)
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header_value(name)
    }
}

pub struct DockerPeerIdentity {
    transport: TransportPrincipal,
    telemetry: DockerTelemetry,
}
impl DockerPeerIdentity {
    pub fn principal_id(&self) -> &str {
        self.transport.principal().id().as_str()
    }
    pub fn transport(&self) -> &TransportPrincipal {
        &self.transport
    }
    pub fn request_origin(&self) -> RequestOrigin {
        RequestOrigin::docker(&self.transport)
    }
    pub fn telemetry(&self) -> &DockerTelemetry {
        &self.telemetry
    }
}

/// Authenticate the accepted Unix peer before any HTTP body is decoded.
pub fn authenticate_docker_peer(
    stream: &UnixStream,
    telemetry: DockerTelemetry,
) -> Result<DockerPeerIdentity, PrincipalResolutionError> {
    PrincipalResolver::from_peer_credentials(stream).map(|transport| DockerPeerIdentity {
        transport,
        telemetry,
    })
}

pub fn authenticate_docker_peer_with_mode(
    stream: &UnixStream,
    telemetry: DockerTelemetry,
    mode: PeerAuthMode,
) -> Result<DockerPeerIdentity, PrincipalResolutionError> {
    PrincipalResolver::from_peer_credentials_with_mode(stream, mode).map(|transport| {
        DockerPeerIdentity {
            transport,
            telemetry,
        }
    })
}
