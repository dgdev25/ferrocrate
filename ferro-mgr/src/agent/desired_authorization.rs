use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ferro_core::authorization::helper_grant::{GrantAction, GrantParameters};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::netd_client::{GrantedEnvelope, NetdRequest};
use crate::proto::DesiredState;

pub const DESIRED_AUTHORIZATION_VERSION: u16 = 1;

/// Controller-signed, revision-bound collection of independently consumable netd grants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DesiredAuthorizationBundle {
    pub schema_version: u16,
    pub cluster_id: String,
    pub node_id: String,
    pub cluster_epoch: u64,
    pub revision: u64,
    pub lease_expires_unix: i64,
    pub desired_state_digest: [u8; 32],
    pub operations: Vec<GrantedEnvelope>,
    pub signature: String,
}

impl DesiredAuthorizationBundle {
    pub fn sign(
        desired: &DesiredState,
        node_id: impl Into<String>,
        operations: Vec<GrantedEnvelope>,
        key: &SigningKey,
    ) -> Result<Self, serde_json::Error> {
        let mut bundle = Self {
            schema_version: DESIRED_AUTHORIZATION_VERSION,
            cluster_id: desired.cluster_id.clone(),
            node_id: node_id.into(),
            cluster_epoch: desired.cluster_epoch,
            revision: desired.revision,
            lease_expires_unix: desired.lease_expires_unix,
            desired_state_digest: Sha256::digest(desired.encode_to_vec()).into(),
            operations,
            signature: String::new(),
        };
        bundle.signature = base64::engine::general_purpose::STANDARD
            .encode(key.sign(&bundle.signing_bytes()?).to_bytes());
        Ok(bundle)
    }

    pub fn decode_and_verify(
        encoded: &[u8],
        desired: &DesiredState,
        key: &VerifyingKey,
        now_unix: i64,
    ) -> Result<Self, BundleError> {
        let bundle: Self = serde_json::from_slice(encoded).map_err(|_| BundleError::Invalid)?;
        if bundle.schema_version != DESIRED_AUTHORIZATION_VERSION
            || bundle.cluster_id != desired.cluster_id
            || bundle.cluster_epoch != desired.cluster_epoch
            || bundle.revision != desired.revision
            || bundle.lease_expires_unix != desired.lease_expires_unix
            || bundle.lease_expires_unix <= now_unix
            || bundle.desired_state_digest != Sha256::digest(desired.encode_to_vec()).as_slice()
        {
            return Err(BundleError::Binding);
        }
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&bundle.signature)
            .ok()
            .and_then(|bytes| Signature::from_slice(&bytes).ok())
            .ok_or(BundleError::Invalid)?;
        key.verify(
            &bundle.signing_bytes().map_err(|_| BundleError::Invalid)?,
            &signature,
        )
        .map_err(|_| BundleError::Invalid)?;
        bundle.validate_envelope_bindings()?;
        Ok(bundle)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned)
    }

    fn validate_envelope_bindings(&self) -> Result<(), BundleError> {
        if self.operations.is_empty() {
            return Ok(());
        }
        for operation in &self.operations {
            if operation.envelope.cluster_id != self.cluster_id
                || operation.envelope.node_id != self.node_id
                || operation.envelope.epoch != self.cluster_epoch
                || operation.envelope.revision != self.revision
                || operation.envelope.lease_expires_unix_secs != self.lease_expires_unix as u64
                || operation.resource_uuid != operation.grant.claims.resource.resource_uuid
                || operation.resource_generation != operation.grant.claims.resource.generation
            {
                return Err(BundleError::Binding);
            }
            let (action, parameters) = operation_parameters(&operation.envelope.request)?;
            if operation.grant.claims.action != action
                || operation.grant.claims.parameter_digest != parameters.digest()
            {
                return Err(BundleError::Binding);
            }
        }
        Ok(())
    }

    pub fn validate_transition(
        &self,
        desired: &DesiredState,
        current: &[String],
    ) -> Result<(), BundleError> {
        use std::collections::BTreeSet;
        let wanted: BTreeSet<_> = desired
            .overlays
            .iter()
            .map(|value| value.overlay_id.as_str())
            .collect();
        let current: BTreeSet<_> = current.iter().map(String::as_str).collect();
        let mut applies = BTreeSet::new();
        let mut removals = BTreeSet::new();
        for operation in &self.operations {
            match &operation.envelope.request {
                NetdRequest::ApplyOverlay {
                    overlay_id,
                    peers,
                    routes,
                    addresses,
                } => {
                    let overlay = desired
                        .overlays
                        .iter()
                        .find(|value| value.overlay_id == *overlay_id)
                        .ok_or(BundleError::Binding)?;
                    let expected_peers = overlay.peers.iter().map(|peer| serde_json::json!({
                        "node_id": peer.node_id,
                        "public_key": base64::engine::general_purpose::STANDARD.encode(&peer.public_key),
                        "endpoint": peer.endpoint,
                        "allowed_ips": peer.allowed_ips,
                    })).collect::<Vec<_>>();
                    if peers != &expected_peers
                        || routes != &overlay.routes
                        || !addresses.is_empty()
                        || !applies.insert(overlay_id.as_str())
                    {
                        return Err(BundleError::Binding);
                    }
                }
                NetdRequest::RemoveOverlay { overlay_id } => {
                    if !removals.insert(overlay_id.as_str()) {
                        return Err(BundleError::Binding);
                    }
                }
                _ => return Err(BundleError::Binding),
            }
        }
        let expected_removals: BTreeSet<_> = current.difference(&wanted).copied().collect();
        if applies != wanted || removals != expected_removals {
            return Err(BundleError::Binding);
        }
        Ok(())
    }
}

fn operation_parameters(
    request: &NetdRequest,
) -> Result<(GrantAction, GrantParameters), BundleError> {
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
                    serde_json::to_string(peers).map_err(|_| BundleError::Invalid)?,
                ),
                (
                    "routes".into(),
                    serde_json::to_string(routes).map_err(|_| BundleError::Invalid)?,
                ),
                (
                    "addresses".into(),
                    serde_json::to_string(addresses).map_err(|_| BundleError::Invalid)?,
                ),
            ],
        ),
        NetdRequest::RemoveOverlay { overlay_id } => (
            GrantAction::NetworkDelete,
            "overlay.delete",
            vec![("overlay_id".into(), overlay_id.clone())],
        ),
        _ => return Err(BundleError::Binding),
    };
    GrantParameters::new(name, fields, vec![])
        .map(|parameters| (action, parameters))
        .map_err(|_| BundleError::Binding)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BundleError {
    Invalid,
    Binding,
}
