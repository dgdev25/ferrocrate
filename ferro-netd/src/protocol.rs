use ferro_core::authorization::helper_grant::HelperGrant;
use serde::{Deserialize, Serialize};

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_PEERS: usize = 255;
pub const MAX_ROUTES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceHandshake {
    pub mode: String,
    pub policy_digest: Option<[u8; 32]>,
    pub instance_boot: String,
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
pub struct DesiredStateEnvelope {
    pub handshake: ServiceHandshake,
    pub cluster_id: String,
    pub node_id: String,
    pub epoch: u64,
    pub revision: u64,
    pub lease_expires_unix_secs: u64,
    pub desired_state: Vec<u8>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantedEnvelope {
    pub handshake: ServiceHandshake,
    pub envelope: SignedEnvelope,
    pub resource_uuid: String,
    pub resource_generation: u64,
    pub grant: HelperGrant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantedDesiredStateEnvelope {
    pub envelope: DesiredStateEnvelope,
    pub resource_uuid: String,
    pub resource_generation: u64,
    pub grant: HelperGrant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetdRequest {
    ApplyOverlay {
        overlay_id: String,
        mode: OverlayMode,
        peers: Vec<PeerSpec>,
        routes: Vec<String>,
        #[serde(default)]
        addresses: Vec<String>,
    },
    RemoveOverlay {
        overlay_id: String,
    },
    AttachEndpoint {
        overlay_id: String,
        endpoint_id: String,
        #[serde(default)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverlayMode {
    WireGuard,
    BridgeOnly,
}
impl Default for OverlayMode {
    fn default() -> Self {
        Self::BridgeOnly
    }
}
impl OverlayMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WireGuard => "wireguard",
            Self::BridgeOnly => "bridge_only",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerSpec {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RejectionCode {
    UnauthorizedPeer,
    OversizedFrame,
    InvalidFrame,
    InvalidSignature,
    MissingGrant,
    InvalidGrant,
    GrantReplay,
    ExpiredLease,
    StaleRevision,
    PolicyViolation,
    Busy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetdResponse {
    Applied,
    Removed,
    Attached,
    Detached,
    Snapshot { overlay_id: String, revision: u64 },
    Rejected { code: RejectionCode, reason: String },
}

impl NetdResponse {
    pub fn code(&self) -> Option<RejectionCode> {
        match self {
            Self::Rejected { code, .. } => Some(code.clone()),
            _ => None,
        }
    }
}

pub fn frame(envelope: &SignedEnvelope) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(envelope)?;
    let mut output = (body.len() as u32).to_be_bytes().to_vec();
    output.extend(body);
    Ok(output)
}

pub fn desired_state_frame(envelope: &DesiredStateEnvelope) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(envelope)?;
    let mut output = (body.len() as u32).to_be_bytes().to_vec();
    output.extend(body);
    Ok(output)
}

pub fn response_frame(response: &NetdResponse) -> Result<Vec<u8>, serde_json::Error> {
    let body = serde_json::to_vec(response)?;
    let mut output = (body.len() as u32).to_be_bytes().to_vec();
    output.extend(body);
    Ok(output)
}
