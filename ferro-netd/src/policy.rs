use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ferro_net::validate::validate_interface_name;
use ipnet::IpNet;

use crate::protocol::{NetdRequest, RejectionCode, SignedEnvelope, MAX_PEERS, MAX_ROUTES};

pub struct Policy { cluster: String, node: String, key: VerifyingKey, revisions: BTreeMap<String, (u64, u64)> }

impl Policy {
    pub fn new(cluster: String, node: String, key: &str) -> Result<Self, RejectionCode> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(key).map_err(|_| RejectionCode::InvalidSignature)?;
        let key = VerifyingKey::from_bytes(bytes.as_slice().try_into().map_err(|_| RejectionCode::InvalidSignature)?).map_err(|_| RejectionCode::InvalidSignature)?;
        Ok(Self { cluster, node, key, revisions: BTreeMap::new() })
    }

    pub fn validate(&mut self, envelope: &SignedEnvelope, now: u64) -> Result<(), RejectionCode> {
        if envelope.cluster_id != self.cluster || envelope.node_id != self.node { return Err(RejectionCode::PolicyViolation); }
        if envelope.lease_expires_unix_secs <= now { return Err(RejectionCode::ExpiredLease); }
        let mut unsigned = envelope.clone(); unsigned.signature.clear();
        let signature = base64::engine::general_purpose::STANDARD.decode(&envelope.signature).map_err(|_| RejectionCode::InvalidSignature)?;
        self.key.verify(&serde_json::to_vec(&unsigned).map_err(|_| RejectionCode::InvalidFrame)?, &Signature::from_slice(&signature).map_err(|_| RejectionCode::InvalidSignature)?).map_err(|_| RejectionCode::InvalidSignature)?;
        validate_request(&envelope.request)?;
        let overlay = overlay_id(&envelope.request).to_string();
        if let Some((epoch, revision)) = self.revisions.get(&overlay) {
            if envelope.epoch < *epoch || (envelope.epoch == *epoch && envelope.revision <= *revision) { return Err(RejectionCode::StaleRevision); }
        }
        self.revisions.insert(overlay, (envelope.epoch, envelope.revision));
        Ok(())
    }
}

fn validate_request(request: &NetdRequest) -> Result<(), RejectionCode> {
    let overlay = overlay_id(request);
    validate_interface_name(overlay).map_err(|_| RejectionCode::PolicyViolation)?;
    if let NetdRequest::ApplyOverlay { peers, routes, .. } = request {
        if peers.len() > MAX_PEERS || routes.len() > MAX_ROUTES { return Err(RejectionCode::PolicyViolation); }
        for route in routes { route.parse::<IpNet>().map_err(|_| RejectionCode::PolicyViolation)?; }
        for peer in peers {
            if peer.node_id.is_empty() || peer.allowed_ips.len() > MAX_ROUTES || peer.endpoint.parse::<std::net::SocketAddr>().is_err() { return Err(RejectionCode::PolicyViolation); }
            for route in &peer.allowed_ips { route.parse::<IpNet>().map_err(|_| RejectionCode::PolicyViolation)?; }
        }
    }
    if let NetdRequest::AttachEndpoint { overlay_id, endpoint_id } | NetdRequest::DetachEndpoint { overlay_id, endpoint_id } = request {
        validate_interface_name(overlay_id).map_err(|_| RejectionCode::PolicyViolation)?;
        validate_interface_name(endpoint_id).map_err(|_| RejectionCode::PolicyViolation)?;
        validate_interface_name(&format!("fc-{endpoint_id}")).map_err(|_| RejectionCode::PolicyViolation)?;
    }
    Ok(())
}

fn overlay_id(request: &NetdRequest) -> &str { match request { NetdRequest::ApplyOverlay { overlay_id, .. } | NetdRequest::RemoveOverlay { overlay_id } | NetdRequest::AttachEndpoint { overlay_id, .. } | NetdRequest::DetachEndpoint { overlay_id, .. } | NetdRequest::Inspect { overlay_id } => overlay_id } }
