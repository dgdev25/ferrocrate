use std::collections::{BTreeMap, BTreeSet};
use ferro_net::{bridge::{build_ip_link_set_master_cmd, create_bridge, destroy_bridge, BridgeConfig}, exec_cmd, veth::{create_veth_pair, destroy_veth_pair, VethConfig, VethPair}};
use crate::policy::Policy;
use crate::protocol::{NetdRequest, NetdResponse, RejectionCode, SignedEnvelope, MAX_FRAME_BYTES};

pub struct NetdServer { uid: u32, policy: Policy, overlays: BTreeSet<String>, endpoints: BTreeMap<String, String> }
impl NetdServer {
    pub fn new(uid: u32, policy: Policy) -> Self { Self { uid, policy, overlays: BTreeSet::new(), endpoints: BTreeMap::new() } }
    pub fn handle_peer(&mut self, uid: u32, frame: &[u8], now: u64) -> NetdResponse {
        if uid != self.uid { return reject(RejectionCode::UnauthorizedPeer, "unexpected Unix peer UID"); }
        if frame.len() > MAX_FRAME_BYTES + 4 { return reject(RejectionCode::OversizedFrame, "frame exceeds 1 MiB"); }
        if frame.len() < 4 { return reject(RejectionCode::InvalidFrame, "missing frame prefix"); }
        let length = u32::from_be_bytes(frame[..4].try_into().expect("prefix")) as usize;
        if length > MAX_FRAME_BYTES || length != frame.len() - 4 { return reject(RejectionCode::OversizedFrame, "invalid frame length"); }
        let envelope: SignedEnvelope = match serde_json::from_slice(&frame[4..]) { Ok(value) => value, Err(_) => return reject(RejectionCode::InvalidFrame, "invalid JSON") };
        if let Err(code) = self.policy.validate(&envelope, now) { return reject(code, "policy rejected request"); }
        match envelope.request {
            NetdRequest::ApplyOverlay { overlay_id, .. } => {
                if !self.overlays.contains(&overlay_id) && create_bridge(&BridgeConfig { name: overlay_id.clone(), cidr: String::new(), ipv6_cidr: None }).is_err() {
                    return reject(RejectionCode::Busy, "failed to create overlay bridge");
                }
                self.overlays.insert(overlay_id);
                NetdResponse::Applied
            }
            NetdRequest::RemoveOverlay { overlay_id } => {
                if self.overlays.remove(&overlay_id) { let _ = destroy_bridge(&overlay_id); }
                NetdResponse::Removed
            }
            NetdRequest::AttachEndpoint { overlay_id, endpoint_id } => {
                if self.endpoints.contains_key(&endpoint_id) { return NetdResponse::Attached; }
                let container = format!("fc-{endpoint_id}");
                let config = VethConfig { pair: VethPair { host: endpoint_id.clone(), container }, mtu: None, host_addr: None, container_addr: None };
                if create_veth_pair(&config).is_err() { return reject(RejectionCode::Busy, "failed to create endpoint veth"); }
                let master = match build_ip_link_set_master_cmd(&endpoint_id, &overlay_id) { Ok(command) => command, Err(_) => { let _ = destroy_veth_pair(&endpoint_id); return reject(RejectionCode::PolicyViolation, "invalid endpoint interface"); } };
                if exec_cmd(&master).is_err() { let _ = destroy_veth_pair(&endpoint_id); return reject(RejectionCode::Busy, "failed to attach endpoint veth"); }
                self.endpoints.insert(endpoint_id, overlay_id);
                NetdResponse::Attached
            }
            NetdRequest::DetachEndpoint { endpoint_id, .. } => { if self.endpoints.remove(&endpoint_id).is_some() { let _ = destroy_veth_pair(&endpoint_id); } NetdResponse::Detached }
            NetdRequest::Inspect { overlay_id } => NetdResponse::Snapshot { overlay_id, revision: envelope.revision },
        }
    }
}
fn reject(code: RejectionCode, reason: &str) -> NetdResponse { NetdResponse::Rejected { code, reason: reason.to_string() } }
