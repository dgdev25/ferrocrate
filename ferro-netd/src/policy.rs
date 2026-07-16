use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ferro_net::validate::validate_interface_name;
use ipnet::IpNet;
use prost::Message;

use crate::protocol::{NetdRequest, RejectionCode, SignedEnvelope, MAX_PEERS, MAX_ROUTES};

#[derive(Clone, Message)]
pub(crate) struct WireDesiredState {
    #[prost(string, tag = "1")]
    pub(crate) cluster_id: String,
    #[prost(uint64, tag = "2")]
    pub(crate) cluster_epoch: u64,
    #[prost(uint64, tag = "3")]
    pub(crate) revision: u64,
    #[prost(message, repeated, tag = "4")]
    pub(crate) overlays: Vec<WireOverlay>,
    #[prost(bytes, tag = "5")]
    pub(crate) signature: Vec<u8>,
    #[prost(int64, tag = "6")]
    pub(crate) lease_expires_unix: i64,
}

#[derive(Clone, Message)]
pub(crate) struct WireOverlay {
    #[prost(string, tag = "1")]
    pub(crate) overlay_id: String,
    #[prost(string, repeated, tag = "2")]
    pub(crate) routes: Vec<String>,
    #[prost(message, repeated, tag = "3")]
    pub(crate) peers: Vec<WirePeer>,
}

#[derive(Clone, Message)]
pub(crate) struct WirePeer {
    #[prost(string, tag = "1")]
    pub(crate) node_id: String,
    #[prost(bytes, tag = "2")]
    pub(crate) public_key: Vec<u8>,
    #[prost(string, tag = "3")]
    pub(crate) endpoint: String,
    #[prost(string, repeated, tag = "4")]
    pub(crate) allowed_ips: Vec<String>,
}

pub struct Policy { cluster: String, node: String, key: VerifyingKey, revisions: BTreeMap<String, (u64, u64, u64)> }

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
        if let Some((epoch, revision, lease)) = self.revisions.get(&overlay) {
            if envelope.epoch < *epoch
                || (envelope.epoch == *epoch && (envelope.revision < *revision || (envelope.revision == *revision && envelope.lease_expires_unix_secs <= *lease)))
            { return Err(RejectionCode::StaleRevision); }
        }
        self.revisions.insert(overlay, (envelope.epoch, envelope.revision, envelope.lease_expires_unix_secs));
        Ok(())
    }

    pub fn validate_desired_state(&mut self, bytes: &[u8], node_id: &str, now: u64) -> Result<WireDesiredState, RejectionCode> {
        let state = WireDesiredState::decode(bytes).map_err(|_| RejectionCode::InvalidFrame)?;
        if state.cluster_id != self.cluster || (!node_id.is_empty() && node_id != self.node) { return Err(RejectionCode::PolicyViolation); }
        if state.lease_expires_unix <= now as i64 { return Err(RejectionCode::ExpiredLease); }
        let mut unsigned = state.clone();
        let signature = Signature::from_slice(&unsigned.signature).map_err(|_| RejectionCode::InvalidSignature)?;
        unsigned.signature.clear();
        self.key.verify(&bytes_for_state(&unsigned), &signature).map_err(|_| RejectionCode::InvalidSignature)?;
        if let Some((epoch, revision, lease)) = self.revisions.get("__desired_state") {
            if state.cluster_epoch < *epoch
                || (state.cluster_epoch == *epoch && (state.revision < *revision || (state.revision == *revision && state.lease_expires_unix as u64 <= *lease)))
            { return Err(RejectionCode::StaleRevision); }
        }
        for overlay in &state.overlays {
            validate_request(&NetdRequest::ApplyOverlay { overlay_id: overlay.overlay_id.clone(), peers: overlay.peers.iter().map(|peer| crate::protocol::PeerSpec { node_id: peer.node_id.clone(), public_key: String::from_utf8_lossy(&peer.public_key).into_owned(), endpoint: peer.endpoint.clone(), allowed_ips: peer.allowed_ips.clone() }).collect(), routes: overlay.routes.clone(), addresses: Vec::new() })?;
        }
        self.revisions.insert("__desired_state".into(), (state.cluster_epoch, state.revision, state.lease_expires_unix as u64));
        Ok(state)
    }

    pub fn rollback(&mut self, scope: &str, epoch: u64, revision: u64) {
        if matches!(self.revisions.get(scope), Some((current_epoch, current_revision, _)) if *current_epoch == epoch && *current_revision == revision) { self.revisions.remove(scope); }
    }
}

fn bytes_for_state(state: &WireDesiredState) -> Vec<u8> { state.encode_to_vec() }

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
    match request {
        NetdRequest::AttachEndpoint { overlay_id, endpoint_id, netns } => {
            validate_interface_name(overlay_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(endpoint_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(&format!("fc-{endpoint_id}")).map_err(|_| RejectionCode::PolicyViolation)?;
            if let Some(netns) = netns { ferro_net::validate::validate_netns_name(netns).map_err(|_| RejectionCode::PolicyViolation)?; }
        }
        NetdRequest::DetachEndpoint { overlay_id, endpoint_id } => {
            validate_interface_name(overlay_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(endpoint_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(&format!("fc-{endpoint_id}")).map_err(|_| RejectionCode::PolicyViolation)?;
        }
        _ => {}
    }
    Ok(())
}

fn overlay_id(request: &NetdRequest) -> &str { match request { NetdRequest::ApplyOverlay { overlay_id, .. } | NetdRequest::RemoveOverlay { overlay_id } | NetdRequest::AttachEndpoint { overlay_id, .. } | NetdRequest::DetachEndpoint { overlay_id, .. } | NetdRequest::Inspect { overlay_id } => overlay_id } }
