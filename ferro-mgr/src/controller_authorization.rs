use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ferro_core::authorization::helper_grant::{
    GrantAction, GrantIssuer, GrantParameters, ResourceBinding,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    agent::netd_client::{GrantedEnvelope, NetdRequest, SignedEnvelope},
    proto::DesiredState,
};

#[derive(Clone, Debug)]
pub struct ControllerPolicy {
    allowed_nodes: BTreeSet<String>,
    resources: BTreeMap<String, ResourceBinding>,
}

impl ControllerPolicy {
    pub fn new(
        allowed_nodes: impl IntoIterator<Item = String>,
        resources: impl IntoIterator<Item = (String, ResourceBinding)>,
    ) -> Self {
        Self {
            allowed_nodes: allowed_nodes.into_iter().collect(),
            resources: resources.into_iter().collect(),
        }
    }
}

pub struct ControllerGrantIssuer {
    grants: GrantIssuer,
    envelope_key: SigningKey,
    issuer: String,
    boot_id: String,
    policy: ControllerPolicy,
}

impl ControllerGrantIssuer {
    pub fn new(
        grants: GrantIssuer,
        envelope_key: SigningKey,
        issuer: impl Into<String>,
        boot_id: impl Into<String>,
        policy: ControllerPolicy,
    ) -> Self {
        Self {
            grants,
            envelope_key,
            issuer: issuer.into(),
            boot_id: boot_id.into(),
            policy,
        }
    }

    pub fn issue_exact_diff(
        &self,
        desired: &DesiredState,
        node_id: &str,
        current: &[String],
        now_monotonic_millis: u64,
    ) -> Result<Vec<GrantedEnvelope>, ControllerAuthorizationError> {
        let prior = DesiredState {
            cluster_id: desired.cluster_id.clone(),
            cluster_epoch: desired.cluster_epoch,
            revision: desired.revision.saturating_sub(1),
            overlays: current
                .iter()
                .map(|overlay_id| crate::proto::OverlayState {
                    overlay_id: overlay_id.clone(),
                    routes: vec![],
                    peers: vec![],
                })
                .collect(),
            signature: vec![],
            lease_expires_unix: desired.lease_expires_unix,
        };
        self.issue_exact_diff_from_state(desired, node_id, Some(&prior), now_monotonic_millis)
    }

    pub fn issue_exact_diff_from_state(
        &self,
        desired: &DesiredState,
        node_id: &str,
        prior: Option<&DesiredState>,
        now_monotonic_millis: u64,
    ) -> Result<Vec<GrantedEnvelope>, ControllerAuthorizationError> {
        if !self.policy.allowed_nodes.contains(node_id) {
            return Err(ControllerAuthorizationError::Denied {
                resource: node_id.into(),
            });
        }
        let wanted: BTreeSet<_> = desired
            .overlays
            .iter()
            .map(|o| o.overlay_id.as_str())
            .collect();
        let current: BTreeSet<_> = prior
            .into_iter()
            .flat_map(|v| &v.overlays)
            .map(|v| v.overlay_id.as_str())
            .collect();
        let mut requests = Vec::new();
        for overlay in &desired.overlays {
            let peers = overlay.peers.iter().map(|peer| serde_json::json!({
                "node_id": peer.node_id,
                "public_key": base64::engine::general_purpose::STANDARD.encode(&peer.public_key),
                "endpoint": peer.endpoint,
                "allowed_ips": peer.allowed_ips,
            })).collect();
            requests.push(NetdRequest::ApplyOverlay {
                overlay_id: overlay.overlay_id.clone(),
                peers,
                routes: overlay.routes.clone(),
                addresses: Vec::new(),
            });
        }
        for overlay_id in current.difference(&wanted) {
            requests.push(NetdRequest::RemoveOverlay {
                overlay_id: (*overlay_id).into(),
            });
        }

        // Resolve every canonical resource before issuing anything: denial is explicit and atomic.
        for request in &requests {
            let overlay_id = request_overlay(request);
            if !self.policy.resources.contains_key(overlay_id) {
                return Err(ControllerAuthorizationError::Denied {
                    resource: overlay_id.into(),
                });
            }
        }
        requests
            .into_iter()
            .enumerate()
            .map(|(index, request)| {
                let prior_overlay = prior.and_then(|state| {
                    state
                        .overlays
                        .iter()
                        .find(|overlay| overlay.overlay_id == request_overlay(&request))
                });
                self.issue_one(
                    desired,
                    node_id,
                    request,
                    index,
                    prior_overlay,
                    now_monotonic_millis,
                )
            })
            .collect()
    }

    fn issue_one(
        &self,
        desired: &DesiredState,
        node_id: &str,
        request: NetdRequest,
        index: usize,
        prior_overlay: Option<&crate::proto::OverlayState>,
        now_monotonic_millis: u64,
    ) -> Result<GrantedEnvelope, ControllerAuthorizationError> {
        let overlay_id = request_overlay(&request);
        let resource = self
            .policy
            .resources
            .get(overlay_id)
            .cloned()
            .ok_or_else(|| ControllerAuthorizationError::Denied {
                resource: overlay_id.into(),
            })?;
        let (action, parameters) = parameters(&request)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| ControllerAuthorizationError::Random)?;
        if nonce == [0; 16] {
            return Err(ControllerAuthorizationError::Random);
        }
        let prior_canonical = prior_overlay.map(|overlay| serde_json::json!({
            "overlay_id": overlay.overlay_id,
            "routes": overlay.routes,
            "peers": overlay.peers.iter().map(|peer| serde_json::json!({
                "node_id": peer.node_id,
                "public_key": base64::engine::general_purpose::STANDARD.encode(&peer.public_key),
                "endpoint": peer.endpoint,
                "allowed_ips": peer.allowed_ips,
            })).collect::<Vec<_>>(),
            "addresses": Vec::<String>::new()
        }));
        let canonical = serde_json::to_vec(&(
            node_id,
            desired.cluster_epoch,
            desired.revision,
            &resource,
            &request,
            &prior_canonical,
        ))
        .map_err(|_| ControllerAuthorizationError::Encoding)?;
        let precondition_digest = Sha256::digest(
            [
                b"ferrocrate.controller-precondition.v1\0".as_slice(),
                &canonical,
            ]
            .concat(),
        )
        .into();
        let post_exists = matches!(request, NetdRequest::ApplyOverlay { .. });
        let inverse = if post_exists {
            "remove-overlay"
        } else {
            "restore-overlay"
        };
        let recovery_recipe_digest = Sha256::digest(
            [
                b"ferrocrate.controller-recovery.v1\0".as_slice(),
                &canonical,
                &[u8::from(post_exists)],
                inverse.as_bytes(),
            ]
            .concat(),
        )
        .into();
        let request_id = format!(
            "desired:{}:{}:{}",
            desired.revision,
            index,
            hex_prefix(&nonce)
        );
        let grant = self
            .grants
            .for_controller_overlay(
                &request_id,
                action,
                resource.clone(),
                &parameters,
                &self.boot_id,
                desired
                    .lease_expires_unix
                    .try_into()
                    .map_err(|_| ControllerAuthorizationError::Encoding)?,
                now_monotonic_millis.saturating_add(60_000),
                nonce,
                &self.issuer,
                precondition_digest,
                recovery_recipe_digest,
            )
            .map_err(|_| ControllerAuthorizationError::Grant)?;
        let mut envelope = SignedEnvelope {
            cluster_id: desired.cluster_id.clone(),
            node_id: node_id.into(),
            epoch: desired.cluster_epoch,
            revision: desired.revision,
            lease_expires_unix_secs: desired.lease_expires_unix as u64,
            request,
            signature: String::new(),
        };
        envelope.signature = base64::engine::general_purpose::STANDARD.encode(
            self.envelope_key
                .sign(
                    &serde_json::to_vec(&envelope)
                        .map_err(|_| ControllerAuthorizationError::Encoding)?,
                )
                .to_bytes(),
        );
        Ok(GrantedEnvelope {
            envelope,
            resource_uuid: resource.resource_uuid,
            resource_generation: resource.generation,
            grant,
        })
    }
}

fn request_overlay(request: &NetdRequest) -> &str {
    match request {
        NetdRequest::ApplyOverlay { overlay_id, .. }
        | NetdRequest::RemoveOverlay { overlay_id } => overlay_id,
        _ => unreachable!("controller only builds overlay operations"),
    }
}
fn parameters(
    request: &NetdRequest,
) -> Result<(GrantAction, GrantParameters), ControllerAuthorizationError> {
    let (action, name, fields) = match request {
        NetdRequest::ApplyOverlay {
            overlay_id,
            peers,
            routes,
            addresses,
        } => (
            GrantAction::NetworkCreate,
            "overlay.apply",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                (
                    "peers".into(),
                    serde_json::to_string(peers)
                        .map_err(|_| ControllerAuthorizationError::Encoding)?,
                ),
                (
                    "routes".into(),
                    serde_json::to_string(routes)
                        .map_err(|_| ControllerAuthorizationError::Encoding)?,
                ),
                (
                    "addresses".into(),
                    serde_json::to_string(addresses)
                        .map_err(|_| ControllerAuthorizationError::Encoding)?,
                ),
            ],
        ),
        NetdRequest::RemoveOverlay { overlay_id } => (
            GrantAction::NetworkDelete,
            "overlay.delete",
            vec![("overlay_id".into(), overlay_id.clone())],
        ),
        _ => return Err(ControllerAuthorizationError::Encoding),
    };
    Ok((
        action,
        GrantParameters::new(name, fields, vec![])
            .map_err(|_| ControllerAuthorizationError::Grant)?,
    ))
}
fn hex_prefix(nonce: &[u8; 16]) -> String {
    nonce[..4].iter().map(|v| format!("{v:02x}")).collect()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControllerAuthorizationError {
    #[error("controller policy denied resource {resource}")]
    Denied { resource: String },
    #[error("secure randomness unavailable")]
    Random,
    #[error("grant issuance failed")]
    Grant,
    #[error("authorization encoding failed")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{desired_state::DesiredStateBuilder, proto::OverlayState};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn missing_canonical_resource_denies_whole_diff() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        std::fs::write(&path, [7_u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let grants = GrantIssuer::from_key_file(
            "controller-1",
            &path,
            nix::unistd::Uid::effective().as_raw(),
        )
        .unwrap();
        let issuer = ControllerGrantIssuer::new(
            grants,
            SigningKey::from_bytes(&[8; 32]),
            "controller",
            "boot-a",
            ControllerPolicy::new(vec!["node-a".into()], Vec::new()),
        );
        let desired = DesiredStateBuilder::new("cluster-a", 1, vec![9; 32]).snapshot(
            1,
            vec![OverlayState {
                overlay_id: "overlay-a".into(),
                routes: vec![],
                peers: vec![],
            }],
            100,
        );
        assert_eq!(
            issuer.issue_exact_diff(&desired, "node-a", &[], 10),
            Err(ControllerAuthorizationError::Denied {
                resource: "overlay-a".into()
            })
        );
    }
}
