use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ferro_core::{
    authorization::helper_grant::{
        GrantAction, GrantIssuer, GrantKind, GrantParameters, HelperGrant, ResourceBinding,
        VerifiedHelperGrant,
    },
    managed_overlay::{managed_parameters, ManagedOverlayDelegation, ManagedOverlayRequest},
};
use prost::Message;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use super::delegation_ledger::ChildIdentity;
use super::reconcile::NetdClient;
use crate::proto::DesiredState;

const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct DesiredStateEnvelope<'a> {
    cluster_id: &'a str,
    node_id: &'a str,
    epoch: u64,
    revision: u64,
    lease_expires_unix_secs: u64,
    desired_state: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum NetdResponse {
    Applied,
    Removed,
    Attached,
    Detached,
    Snapshot {
        overlay_id: String,
        revision: u64,
    },
    Rejected {
        code: serde_json::Value,
        reason: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetdRequest {
    ApplyOverlay {
        overlay_id: String,
        peers: Vec<serde_json::Value>,
        routes: Vec<String>,
        addresses: Vec<String>,
    },
    RemoveOverlay {
        overlay_id: String,
    },
    AttachEndpoint {
        overlay_id: String,
        endpoint_id: String,
        netns: Option<String>,
    },
    DetachEndpoint {
        overlay_id: String,
        endpoint_id: String,
    },
    Inspect {
        overlay_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub cluster_id: String,
    pub node_id: String,
    pub epoch: u64,
    pub revision: u64,
    pub lease_expires_unix_secs: u64,
    pub request: NetdRequest,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantedEnvelope {
    pub envelope: SignedEnvelope,
    pub resource_uuid: String,
    pub resource_generation: u64,
    pub grant: HelperGrant,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DelegationError {
    #[error("parent delegation signature is invalid")]
    InvalidSignature,
    #[error("parent delegation is not bound to this request")]
    Binding,
    #[error("parent delegation is expired or from another boot")]
    Expired,
    #[error("secure randomness unavailable")]
    Random,
    #[error("unsupported delegated request")]
    Unsupported,
}

/// Verifies runtime authority and attenuates it to one exact netd mutation.
pub struct DelegationBridge {
    parent_key: VerifyingKey,
    parent_issuer: String,
    parent_key_id: String,
    boot_id: String,
    child_issuer: GrantIssuer,
    envelope_key: SigningKey,
    cluster_id: String,
    node_id: String,
    revision: u64,
}

impl DelegationBridge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_key: VerifyingKey,
        parent_issuer: impl Into<String>,
        parent_key_id: impl Into<String>,
        boot_id: impl Into<String>,
        child_issuer: GrantIssuer,
        envelope_key: SigningKey,
        cluster_id: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            parent_key,
            parent_issuer: parent_issuer.into(),
            parent_key_id: parent_key_id.into(),
            boot_id: boot_id.into(),
            child_issuer,
            envelope_key,
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
            revision: 0,
        }
    }

    pub fn validate_parent(
        &self,
        request: &ManagedOverlayRequest,
        delegation: &ManagedOverlayDelegation,
        action: GrantAction,
        now_unix: u64,
        now_monotonic_millis: u64,
    ) -> Result<(), DelegationError> {
        let parent = &delegation.parent;
        VerifiedHelperGrant::verify(
            parent.clone(),
            &self.parent_key,
            &self.parent_issuer,
            &self.boot_id,
        )
        .map_err(|_| DelegationError::InvalidSignature)?;
        if parent.claims.key_id != self.parent_key_id
            || parent.claims.action != action
            || parent.claims.kind != GrantKind::Mutation
            || parent.claims.parameter_digest
                != managed_parameters(request)
                    .map_err(|_| DelegationError::Binding)?
                    .digest()
        {
            return Err(DelegationError::Binding);
        }
        if now_unix > parent.claims.wall_deadline_secs
            || now_monotonic_millis > parent.claims.monotonic_deadline_millis
        {
            return Err(DelegationError::Expired);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn delegate_attach(
        &mut self,
        request: &ManagedOverlayRequest,
        delegation: &ManagedOverlayDelegation,
        endpoint_id: &str,
        netns: &str,
        now_unix: u64,
        now_monotonic_millis: u64,
        child: &ChildIdentity,
    ) -> Result<GrantedEnvelope, DelegationError> {
        let ManagedOverlayRequest::AttachContainer { overlay_id, .. } = request else {
            return Err(DelegationError::Unsupported);
        };
        let parent = &delegation.parent;
        let verified = VerifiedHelperGrant::verify(
            parent.clone(),
            &self.parent_key,
            &self.parent_issuer,
            &self.boot_id,
        )
        .map_err(|_| DelegationError::InvalidSignature)?;
        if parent.claims.key_id != self.parent_key_id
            || parent.claims.action != GrantAction::NetworkAttach
            || parent.claims.kind != GrantKind::Mutation
            || parent.claims.parameter_digest
                != managed_parameters(request)
                    .map_err(|_| DelegationError::Binding)?
                    .digest()
        {
            return Err(DelegationError::Binding);
        }
        if parent.claims.boot_id != self.boot_id
            || now_unix > parent.claims.wall_deadline_secs
            || now_monotonic_millis > parent.claims.monotonic_deadline_millis
        {
            return Err(DelegationError::Expired);
        }
        if child.nonce == [0; 16]
            || child.nonce == parent.claims.nonce
            || child.request_id.is_empty()
        {
            return Err(DelegationError::Random);
        }
        let child_request = NetdRequest::AttachEndpoint {
            overlay_id: overlay_id.clone(),
            endpoint_id: endpoint_id.into(),
            netns: Some(netns.into()),
        };
        let parameters = GrantParameters::new(
            "endpoint.attach",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("endpoint_id".into(), endpoint_id.into()),
                ("netns".into(), netns.into()),
            ],
            vec![],
        )
        .map_err(|_| DelegationError::Binding)?;
        let grant = self
            .child_issuer
            .delegate_child(
                &verified,
                &child.request_id,
                GrantAction::NetworkAttach,
                ResourceBinding::new(
                    parent.claims.resource.resource_uuid.clone(),
                    parent.claims.resource.generation,
                )
                .map_err(|_| DelegationError::Binding)?,
                &parameters,
                parent.claims.wall_deadline_secs,
                parent.claims.monotonic_deadline_millis,
                child.nonce,
            )
            .map_err(|_| DelegationError::Binding)?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DelegationError::Binding)?;
        let mut envelope = SignedEnvelope {
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id.clone(),
            epoch: 1,
            revision: self.revision,
            lease_expires_unix_secs: parent.claims.wall_deadline_secs,
            request: child_request,
            signature: String::new(),
        };
        envelope.signature = base64::engine::general_purpose::STANDARD.encode(
            self.envelope_key
                .sign(&serde_json::to_vec(&envelope).map_err(|_| DelegationError::Binding)?)
                .to_bytes(),
        );
        Ok(GrantedEnvelope {
            envelope,
            resource_uuid: parent.claims.resource.resource_uuid.clone(),
            resource_generation: parent.claims.resource.generation,
            grant,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn delegate_detach(
        &mut self,
        request: &ManagedOverlayRequest,
        delegation: &ManagedOverlayDelegation,
        endpoint_id: &str,
        now_unix: u64,
        now_monotonic_millis: u64,
        child: &ChildIdentity,
    ) -> Result<GrantedEnvelope, DelegationError> {
        let ManagedOverlayRequest::DetachContainer { overlay_id, .. } = request else {
            return Err(DelegationError::Unsupported);
        };
        let parent = &delegation.parent;
        let verified = VerifiedHelperGrant::verify(
            parent.clone(),
            &self.parent_key,
            &self.parent_issuer,
            &self.boot_id,
        )
        .map_err(|_| DelegationError::InvalidSignature)?;
        if parent.claims.key_id != self.parent_key_id
            || parent.claims.action != GrantAction::NetworkDetach
            || parent.claims.kind != GrantKind::Mutation
            || parent.claims.parameter_digest
                != managed_parameters(request)
                    .map_err(|_| DelegationError::Binding)?
                    .digest()
            || now_unix > parent.claims.wall_deadline_secs
            || now_monotonic_millis > parent.claims.monotonic_deadline_millis
        {
            return Err(DelegationError::Binding);
        }
        if child.nonce == [0; 16]
            || child.nonce == parent.claims.nonce
            || child.request_id.is_empty()
        {
            return Err(DelegationError::Random);
        }
        let child_request = NetdRequest::DetachEndpoint {
            overlay_id: overlay_id.clone(),
            endpoint_id: endpoint_id.into(),
        };
        let parameters = GrantParameters::new(
            "endpoint.detach",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("endpoint_id".into(), endpoint_id.into()),
            ],
            vec![],
        )
        .map_err(|_| DelegationError::Binding)?;
        let grant = self
            .child_issuer
            .delegate_child(
                &verified,
                &child.request_id,
                GrantAction::NetworkDetach,
                ResourceBinding::new(
                    parent.claims.resource.resource_uuid.clone(),
                    parent.claims.resource.generation,
                )
                .map_err(|_| DelegationError::Binding)?,
                &parameters,
                parent.claims.wall_deadline_secs,
                parent.claims.monotonic_deadline_millis,
                child.nonce,
            )
            .map_err(|_| DelegationError::Binding)?;
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(DelegationError::Binding)?;
        let mut envelope = SignedEnvelope {
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id.clone(),
            epoch: 1,
            revision: self.revision,
            lease_expires_unix_secs: parent.claims.wall_deadline_secs,
            request: child_request,
            signature: String::new(),
        };
        envelope.signature = base64::engine::general_purpose::STANDARD.encode(
            self.envelope_key
                .sign(&serde_json::to_vec(&envelope).map_err(|_| DelegationError::Binding)?)
                .to_bytes(),
        );
        Ok(GrantedEnvelope {
            envelope,
            resource_uuid: parent.claims.resource.resource_uuid.clone(),
            resource_generation: parent.claims.resource.generation,
            grant,
        })
    }
}

#[derive(Debug, Error)]
pub enum NetdClientError {
    #[error("netd connection failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("netd request serialization failed: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("netd response frame is invalid")]
    InvalidFrame,
    #[error("netd response exceeds the configured limit")]
    Oversized,
}

impl NetdClient for UnixNetdClient {
    fn apply(&self, desired_state: &DesiredState) -> Result<(), String> {
        let request = DesiredStateEnvelope {
            cluster_id: &desired_state.cluster_id,
            node_id: &self.node_id,
            epoch: desired_state.cluster_epoch,
            revision: desired_state.revision,
            lease_expires_unix_secs: desired_state.lease_expires_unix as u64,
            desired_state: desired_state.encode_to_vec(),
        };
        let response: NetdResponse = self.request(&request).map_err(|error| error.to_string())?;
        match response {
            NetdResponse::Applied => Ok(()),
            NetdResponse::Rejected { reason, .. } => Err(reason),
            _ => Err("netd returned an unexpected response".into()),
        }
    }

    fn apply_authorized(
        &self,
        _desired_state: &DesiredState,
        bundle: &super::desired_authorization::DesiredAuthorizationBundle,
    ) -> Result<(), String> {
        for operation in &bundle.operations {
            match self
                .request_granted(operation)
                .map_err(|error| error.to_string())?
            {
                NetdResponse::Applied | NetdResponse::Removed => {}
                NetdResponse::Rejected { reason, .. } => return Err(reason),
                _ => return Err("netd returned an unexpected response".into()),
            }
        }
        Ok(())
    }
}

pub struct UnixNetdClient {
    socket: PathBuf,
    timeout: Duration,
    node_id: String,
}

impl UnixNetdClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: Duration::from_secs(5),
            node_id: String::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = node_id.into();
        self
    }

    pub fn request<Request, Response>(&self, request: &Request) -> Result<Response, NetdClientError>
    where
        Request: Serialize,
        Response: DeserializeOwned,
    {
        let mut stream = UnixStream::connect(&self.socket)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let body = serde_json::to_vec(request)?;
        if body.len() > MAX_FRAME_BYTES {
            return Err(NetdClientError::Oversized);
        }
        stream.write_all(&(body.len() as u32).to_be_bytes())?;
        stream.write_all(&body)?;
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_FRAME_BYTES {
            return Err(NetdClientError::Oversized);
        }
        let mut response = vec![0_u8; length];
        stream.read_exact(&mut response)?;
        serde_json::from_slice(&response).map_err(NetdClientError::Encode)
    }

    pub fn request_granted(
        &self,
        request: &GrantedEnvelope,
    ) -> Result<NetdResponse, NetdClientError> {
        self.request(request)
    }
}

#[cfg(test)]
mod tests {
    use super::{DelegationBridge, NetdRequest, UnixNetdClient};
    use crate::agent::delegation_ledger::ChildIdentity;
    use base64::Engine;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use ferro_core::authorization::helper_grant::{
        signing_bytes, GrantAction, GrantClaims, GrantIssuer, GrantKind, GrantParameters,
        HelperGrant, ResourceBinding,
    };
    use ferro_core::managed_overlay::{ManagedOverlayDelegation, ManagedOverlayRequest};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize)]
    struct Request {
        value: u32,
    }
    #[derive(Deserialize, PartialEq, Debug)]
    struct Response {
        value: u32,
    }

    #[test]
    fn client_has_bounded_timeout_and_socket_path() {
        let client = UnixNetdClient::new("/run/ferrocrate/netd.sock")
            .with_node_id("node-a")
            .with_timeout(std::time::Duration::from_millis(50));
        assert_eq!(client.socket.to_string_lossy(), "/run/ferrocrate/netd.sock");
        assert_eq!(client.node_id, "node-a");
        let _ = Request { value: 1 };
        let _ = std::marker::PhantomData::<Response>;
    }

    #[test]
    fn bridge_verifies_parent_and_mints_exactly_one_bound_child() {
        let parent_key = SigningKey::from_bytes(&[11; 32]);
        let child_key = SigningKey::from_bytes(&[12; 32]);
        let envelope_key = SigningKey::from_bytes(&[21; 32]);
        let request = ManagedOverlayRequest::AttachContainer {
            overlay_id: "wg0".into(),
            container_id: "c1".into(),
            now_unix: 100,
        };
        let parameters = ferro_core::managed_overlay::managed_parameters(&request).unwrap();
        let claims = parent_claims("parent-1", parameters.digest(), 7, [3; 16]);
        let delegation = ManagedOverlayDelegation::new(sign_parent(&parent_key, claims));
        let mut bridge = DelegationBridge::new(
            parent_key.verifying_key(),
            "runtime",
            "parent-key",
            "boot-a",
            issuer_from_key("child-key", &child_key),
            envelope_key,
            "cluster",
            "node",
        );
        let child = bridge
            .delegate_attach(
                &request,
                &delegation,
                "ep1",
                "ferro-c1",
                100,
                9_000,
                &ChildIdentity {
                    request_id: "parent-1:child:1".into(),
                    nonce: [8; 16],
                },
            )
            .unwrap();
        assert!(
            matches!(child.envelope.request, NetdRequest::AttachEndpoint { ref overlay_id, ref endpoint_id, netns: Some(ref netns) } if overlay_id == "wg0" && endpoint_id == "ep1" && netns == "ferro-c1")
        );
        assert_eq!(child.resource_uuid, "123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(child.resource_generation, 7);
        assert_eq!(child.grant.claims.operation_id, [3; 16]);
        assert_ne!(child.grant.claims.request_id, "parent-1");
        assert_ne!(child.grant.claims.nonce, [3; 16]);
        let expected = GrantParameters::new(
            "endpoint.attach",
            vec![
                ("overlay_id".into(), "wg0".into()),
                ("endpoint_id".into(), "ep1".into()),
                ("netns".into(), "ferro-c1".into()),
            ],
            vec![],
        )
        .unwrap();
        assert_eq!(child.grant.claims.parameter_digest, expected.digest());
    }

    #[test]
    fn bridge_rejects_a_parent_bound_to_another_request() {
        let parent_key = SigningKey::from_bytes(&[13; 32]);
        let child_key = SigningKey::from_bytes(&[14; 32]);
        let envelope_key = SigningKey::from_bytes(&[22; 32]);
        let claims = parent_claims("parent-2", [9; 32], 1, [4; 16]);
        let delegation = ManagedOverlayDelegation::new(sign_parent(&parent_key, claims));
        let mut bridge = DelegationBridge::new(
            parent_key.verifying_key(),
            "runtime",
            "parent-key",
            "boot-a",
            issuer_from_key("child-key", &child_key),
            envelope_key,
            "cluster",
            "node",
        );
        let request = ManagedOverlayRequest::AttachContainer {
            overlay_id: "wg0".into(),
            container_id: "c1".into(),
            now_unix: 100,
        };
        assert!(bridge
            .delegate_attach(
                &request,
                &delegation,
                "ep1",
                "ferro-c1",
                100,
                9_000,
                &ChildIdentity {
                    request_id: "parent-2:child:1".into(),
                    nonce: [8; 16]
                }
            )
            .is_err());
    }

    fn parent_claims(
        request_id: &str,
        parameter_digest: [u8; 32],
        generation: u64,
        nonce: [u8; 16],
    ) -> GrantClaims {
        GrantClaims {
            schema_version: 1,
            request_id: request_id.into(),
            action: GrantAction::NetworkAttach,
            resource: ResourceBinding {
                resource_uuid: "123e4567-e89b-12d3-a456-426614174000".into(),
                generation,
            },
            parameter_digest,
            boot_id: "boot-a".into(),
            wall_deadline_secs: 110,
            monotonic_deadline_millis: 10_000,
            nonce,
            operation_id: nonce,
            request_digest: parameter_digest,
            precondition_digest: parameter_digest,
            recovery_recipe_digest: parameter_digest,
            issuer: "runtime".into(),
            key_id: "parent-key".into(),
            kind: GrantKind::Mutation,
            origin_request_id: None,
            live_identity_digest: None,
        }
    }
    fn sign_parent(key: &SigningKey, claims: GrantClaims) -> HelperGrant {
        HelperGrant {
            signature: base64::engine::general_purpose::STANDARD
                .encode(key.sign(&signing_bytes(&claims)).to_bytes()),
            claims,
        }
    }
    fn issuer_from_key(key_id: &str, key: &SigningKey) -> GrantIssuer {
        use std::os::unix::{fs::MetadataExt, fs::PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grant.key");
        std::fs::write(&path, key.to_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let uid = std::fs::metadata(&path).unwrap().uid();
        GrantIssuer::from_key_file(key_id, &path, uid).unwrap()
    }
}
