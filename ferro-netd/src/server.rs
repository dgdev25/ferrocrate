use std::collections::BTreeSet;
use crate::policy::Policy;
use crate::protocol::{NetdRequest, NetdResponse, RejectionCode, SignedEnvelope, MAX_FRAME_BYTES};

pub struct NetdServer { uid: u32, policy: Policy, overlays: BTreeSet<String> }
impl NetdServer {
    pub fn new(uid: u32, policy: Policy) -> Self { Self { uid, policy, overlays: BTreeSet::new() } }
    pub fn handle_peer(&mut self, uid: u32, frame: &[u8], now: u64) -> NetdResponse {
        if uid != self.uid { return reject(RejectionCode::UnauthorizedPeer, "unexpected Unix peer UID"); }
        if frame.len() > MAX_FRAME_BYTES + 4 { return reject(RejectionCode::OversizedFrame, "frame exceeds 1 MiB"); }
        if frame.len() < 4 { return reject(RejectionCode::InvalidFrame, "missing frame prefix"); }
        let length = u32::from_be_bytes(frame[..4].try_into().expect("prefix")) as usize;
        if length > MAX_FRAME_BYTES || length != frame.len() - 4 { return reject(RejectionCode::OversizedFrame, "invalid frame length"); }
        let envelope: SignedEnvelope = match serde_json::from_slice(&frame[4..]) { Ok(value) => value, Err(_) => return reject(RejectionCode::InvalidFrame, "invalid JSON") };
        if let Err(code) = self.policy.validate(&envelope, now) { return reject(code, "policy rejected request"); }
        match envelope.request { NetdRequest::ApplyOverlay { overlay_id, .. } => { self.overlays.insert(overlay_id); NetdResponse::Applied }, NetdRequest::RemoveOverlay { overlay_id } => { self.overlays.remove(&overlay_id); NetdResponse::Removed }, NetdRequest::AttachEndpoint { .. } => NetdResponse::Attached, NetdRequest::DetachEndpoint { .. } => NetdResponse::Detached, NetdRequest::Inspect { overlay_id } => NetdResponse::Snapshot { overlay_id, revision: envelope.revision } }
    }
}
fn reject(code: RejectionCode, reason: &str) -> NetdResponse { NetdResponse::Rejected { code, reason: reason.to_string() } }
