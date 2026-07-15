use serde::{Deserialize, Serialize};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_PEERS: usize = 255;
pub const MAX_ROUTES: usize = 512;

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
pub enum NetdRequest {
    ApplyOverlay { overlay_id: String, peers: Vec<PeerSpec>, routes: Vec<String> },
    RemoveOverlay { overlay_id: String },
    AttachEndpoint { overlay_id: String, endpoint_id: String },
    DetachEndpoint { overlay_id: String, endpoint_id: String },
    Inspect { overlay_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerSpec { pub node_id: String, pub public_key: String, pub endpoint: String, pub allowed_ips: Vec<String> }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RejectionCode { UnauthorizedPeer, OversizedFrame, InvalidFrame, InvalidSignature, ExpiredLease, StaleRevision, PolicyViolation, Busy }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetdResponse { Applied, Removed, Attached, Detached, Snapshot { overlay_id: String, revision: u64 }, Rejected { code: RejectionCode, reason: String } }

impl NetdResponse { pub fn code(&self) -> Option<RejectionCode> { match self { Self::Rejected { code, .. } => Some(code.clone()), _ => None } } }

pub fn frame(envelope: &SignedEnvelope) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(envelope)?;
    let mut output = (body.len() as u32).to_be_bytes().to_vec();
    output.extend(body);
    Ok(output)
}
