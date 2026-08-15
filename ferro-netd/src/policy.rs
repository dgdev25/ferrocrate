use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ferro_net::validate::validate_interface_name;
use ipnet::IpNet;

use crate::protocol::{
    DesiredStateEnvelope, NetdRequest, RejectionCode, SignedEnvelope, MAX_PEERS, MAX_ROUTES,
};

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
pub(crate) struct RevisionFloor {
    pub(crate) epoch: u64,
    pub(crate) revision: u64,
    pub(crate) lease_expires_unix_secs: u64,
}

pub struct Policy {
    cluster: String,
    node: String,
    key: VerifyingKey,
    revisions: BTreeMap<String, RevisionFloor>,
}

impl Policy {
    pub fn validate_desired(
        &mut self,
        envelope: &DesiredStateEnvelope,
        now: u64,
    ) -> Result<(), RejectionCode> {
        if envelope.cluster_id != self.cluster || envelope.node_id != self.node {
            return Err(RejectionCode::PolicyViolation);
        }
        if envelope.lease_expires_unix_secs <= now {
            return Err(RejectionCode::ExpiredLease);
        }
        let mut unsigned = envelope.clone();
        unsigned.signature.clear();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&envelope.signature)
            .map_err(|_| RejectionCode::InvalidSignature)?;
        self.key
            .verify(
                &serde_json::to_vec(&unsigned).map_err(|_| RejectionCode::InvalidFrame)?,
                &Signature::from_slice(&signature).map_err(|_| RejectionCode::InvalidSignature)?,
            )
            .map_err(|_| RejectionCode::InvalidSignature)?;
        let scope = "__desired__".to_string();
        if let Some(floor) = self.revisions.get(&scope) {
            if envelope.epoch < floor.epoch
                || (envelope.epoch == floor.epoch
                    && (envelope.revision < floor.revision
                        || (envelope.revision == floor.revision
                            && envelope.lease_expires_unix_secs <= floor.lease_expires_unix_secs)))
            {
                return Err(RejectionCode::StaleRevision);
            }
        }
        self.revisions.insert(
            scope,
            RevisionFloor {
                epoch: envelope.epoch,
                revision: envelope.revision,
                lease_expires_unix_secs: envelope.lease_expires_unix_secs,
            },
        );
        Ok(())
    }
    pub fn new(cluster: String, node: String, key: &str) -> Result<Self, RejectionCode> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| RejectionCode::InvalidSignature)?;
        let key = VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| RejectionCode::InvalidSignature)?,
        )
        .map_err(|_| RejectionCode::InvalidSignature)?;
        Ok(Self {
            cluster,
            node,
            key,
            revisions: BTreeMap::new(),
        })
    }

    pub fn validate(&mut self, envelope: &SignedEnvelope, now: u64) -> Result<(), RejectionCode> {
        if envelope.cluster_id != self.cluster || envelope.node_id != self.node {
            return Err(RejectionCode::PolicyViolation);
        }
        if envelope.lease_expires_unix_secs <= now {
            return Err(RejectionCode::ExpiredLease);
        }
        let mut unsigned = envelope.clone();
        unsigned.signature.clear();
        let signature = base64::engine::general_purpose::STANDARD
            .decode(&envelope.signature)
            .map_err(|_| RejectionCode::InvalidSignature)?;
        self.key
            .verify(
                &serde_json::to_vec(&unsigned).map_err(|_| RejectionCode::InvalidFrame)?,
                &Signature::from_slice(&signature).map_err(|_| RejectionCode::InvalidSignature)?,
            )
            .map_err(|_| RejectionCode::InvalidSignature)?;
        validate_request(&envelope.request)?;
        let overlay = overlay_id(&envelope.request).to_string();
        if let Some(floor) = self.revisions.get(&overlay) {
            if envelope.epoch < floor.epoch
                || (envelope.epoch == floor.epoch
                    && (envelope.revision < floor.revision
                        || (envelope.revision == floor.revision
                            && envelope.lease_expires_unix_secs <= floor.lease_expires_unix_secs)))
            {
                return Err(RejectionCode::StaleRevision);
            }
        }
        self.revisions.insert(
            overlay,
            RevisionFloor {
                epoch: envelope.epoch,
                revision: envelope.revision,
                lease_expires_unix_secs: envelope.lease_expires_unix_secs,
            },
        );
        Ok(())
    }

    pub fn rollback(&mut self, scope: &str, epoch: u64, revision: u64) {
        if matches!(self.revisions.get(scope), Some(floor) if floor.epoch == epoch && floor.revision == revision)
        {
            self.revisions.remove(scope);
        }
    }

    pub(crate) fn revision_floors(&self) -> BTreeMap<String, RevisionFloor> {
        self.revisions.clone()
    }

    pub(crate) fn restore_revision_floors(&mut self, floors: BTreeMap<String, RevisionFloor>) {
        self.revisions = floors;
    }
}

fn validate_request(request: &NetdRequest) -> Result<(), RejectionCode> {
    let overlay = overlay_id(request);
    validate_interface_name(overlay).map_err(|_| RejectionCode::PolicyViolation)?;
    if let NetdRequest::ApplyOverlay { peers, routes, .. } = request {
        if peers.len() > MAX_PEERS || routes.len() > MAX_ROUTES {
            return Err(RejectionCode::PolicyViolation);
        }
        for route in routes {
            route
                .parse::<IpNet>()
                .map_err(|_| RejectionCode::PolicyViolation)?;
        }
        for peer in peers {
            if peer.node_id.is_empty()
                || peer.allowed_ips.len() > MAX_ROUTES
                || peer.endpoint.parse::<std::net::SocketAddr>().is_err()
            {
                return Err(RejectionCode::PolicyViolation);
            }
            for route in &peer.allowed_ips {
                route
                    .parse::<IpNet>()
                    .map_err(|_| RejectionCode::PolicyViolation)?;
            }
        }
    }
    match request {
        NetdRequest::AttachEndpoint {
            overlay_id,
            endpoint_id,
            netns,
        } => {
            validate_interface_name(overlay_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(endpoint_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(&format!("fc-{endpoint_id}"))
                .map_err(|_| RejectionCode::PolicyViolation)?;
            if let Some(netns) = netns {
                ferro_net::validate::validate_netns_name(netns)
                    .map_err(|_| RejectionCode::PolicyViolation)?;
            }
        }
        NetdRequest::DetachEndpoint {
            overlay_id,
            endpoint_id,
        } => {
            validate_interface_name(overlay_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(endpoint_id).map_err(|_| RejectionCode::PolicyViolation)?;
            validate_interface_name(&format!("fc-{endpoint_id}"))
                .map_err(|_| RejectionCode::PolicyViolation)?;
        }
        _ => {}
    }
    Ok(())
}

fn overlay_id(request: &NetdRequest) -> &str {
    match request {
        NetdRequest::ApplyOverlay { overlay_id, .. }
        | NetdRequest::RemoveOverlay { overlay_id }
        | NetdRequest::AttachEndpoint { overlay_id, .. }
        | NetdRequest::DetachEndpoint { overlay_id, .. }
        | NetdRequest::Inspect { overlay_id } => overlay_id,
    }
}
