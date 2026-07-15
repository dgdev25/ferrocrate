use std::{collections::{BTreeMap, BTreeSet}, fs::{self, OpenOptions}, io::Write, os::unix::fs::PermissionsExt};
use serde::{Deserialize, Serialize};
use ferro_net::{bridge::{build_ip_link_set_master_cmd, create_bridge, destroy_bridge, BridgeConfig}, exec_cmd, netns::move_to_netns, veth::{create_veth_pair, destroy_veth_pair, VethConfig, VethPair}, WireGuardInterfaceConfig, WireGuardManager, WireGuardPeer};
use std::path::PathBuf;
use crate::policy::Policy;
use crate::protocol::{NetdRequest, NetdResponse, RejectionCode, SignedEnvelope, MAX_FRAME_BYTES};

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState { overlays: BTreeSet<String>, endpoints: BTreeMap<String, String> }

pub struct NetdServer { uid: u32, policy: Policy, overlays: BTreeSet<String>, endpoints: BTreeMap<String, String>, wireguard: Option<(WireGuardManager, PathBuf, u16)>, journal: Option<PathBuf> }
impl NetdServer {
    pub fn new(uid: u32, policy: Policy) -> Self { Self { uid, policy, overlays: BTreeSet::new(), endpoints: BTreeMap::new(), wireguard: None, journal: None } }
    pub fn with_wireguard(uid: u32, policy: Policy, private_key_path: PathBuf, listen_port: u16) -> Self { Self { uid, policy, overlays: BTreeSet::new(), endpoints: BTreeMap::new(), wireguard: Some((WireGuardManager::new(None), private_key_path, listen_port)), journal: None } }
    pub fn load_journal(mut self, path: PathBuf) -> Result<Self, String> {
        if path.exists() {
            let state: PersistedState = serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
            self.overlays = state.overlays;
            self.endpoints = state.endpoints;
        }
        self.journal = Some(path);
        Ok(self)
    }
    fn persist(&self) -> Result<(), String> {
        let Some(path) = &self.journal else { return Ok(()); };
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary).map_err(|error| error.to_string())?;
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|error| error.to_string())?;
        file.write_all(&serde_json::to_vec(&PersistedState { overlays: self.overlays.clone(), endpoints: self.endpoints.clone() }).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(temporary, path).map_err(|error| error.to_string())
    }
    pub fn handle_peer(&mut self, uid: u32, frame: &[u8], now: u64) -> NetdResponse {
        if uid != self.uid { return reject(RejectionCode::UnauthorizedPeer, "unexpected Unix peer UID"); }
        if frame.len() > MAX_FRAME_BYTES + 4 { return reject(RejectionCode::OversizedFrame, "frame exceeds 1 MiB"); }
        if frame.len() < 4 { return reject(RejectionCode::InvalidFrame, "missing frame prefix"); }
        let length = u32::from_be_bytes(frame[..4].try_into().expect("prefix")) as usize;
        if length > MAX_FRAME_BYTES || length != frame.len() - 4 { return reject(RejectionCode::OversizedFrame, "invalid frame length"); }
        let envelope: SignedEnvelope = match serde_json::from_slice(&frame[4..]) { Ok(value) => value, Err(_) => return reject(RejectionCode::InvalidFrame, "invalid JSON") };
        if let Err(code) = self.policy.validate(&envelope, now) { return reject(code, "policy rejected request"); }
        match envelope.request {
            NetdRequest::ApplyOverlay { overlay_id, peers, routes: _, addresses } => {
                if let Some((manager, private_key_path, listen_port)) = &self.wireguard {
                    let addresses = match addresses.iter().map(|address| address.parse()).collect::<Result<Vec<_>, _>>() { Ok(addresses) => addresses, Err(_) => return reject(RejectionCode::PolicyViolation, "invalid WireGuard interface address") };
                    let peers = match peers.iter().map(|peer| {
                        let endpoint = peer.endpoint.parse().map_err(|_| ());
                        let allowed_ips = peer.allowed_ips.iter().map(|route| route.parse().map_err(|_| ())).collect::<Result<Vec<_>, _>>();
                        match (endpoint, allowed_ips) { (Ok(endpoint), Ok(allowed_ips)) => Ok(WireGuardPeer::new(peer.node_id.clone(), peer.public_key.clone(), endpoint, allowed_ips)), _ => Err(()) }
                    }).collect::<Result<Vec<_>, _>>() { Ok(peers) => peers, Err(()) => return reject(RejectionCode::PolicyViolation, "invalid WireGuard peer") };
                    let config = WireGuardInterfaceConfig { name: overlay_id.clone(), private_key_path: private_key_path.clone(), listen_port: *listen_port, addresses };
                    if manager.apply(&config, &peers).is_err() { return reject(RejectionCode::Busy, "failed to apply WireGuard overlay"); }
                }
                if !self.overlays.contains(&overlay_id) && create_bridge(&BridgeConfig { name: overlay_id.clone(), cidr: String::new(), ipv6_cidr: None }).is_err() {
                    return reject(RejectionCode::Busy, "failed to create overlay bridge");
                }
                self.overlays.insert(overlay_id.clone());
                if self.persist().is_err() { self.overlays.remove(&overlay_id); let _ = destroy_bridge(&overlay_id); return reject(RejectionCode::Busy, "failed to persist overlay ownership"); }
                NetdResponse::Applied
            }
            NetdRequest::RemoveOverlay { overlay_id } => {
                if let Some((manager, private_key_path, listen_port)) = &self.wireguard { let _ = manager.remove(&WireGuardInterfaceConfig { name: overlay_id.clone(), private_key_path: private_key_path.clone(), listen_port: *listen_port, addresses: Vec::new() }); }
                if self.overlays.remove(&overlay_id) { let _ = destroy_bridge(&overlay_id); }
                let _ = self.persist();
                NetdResponse::Removed
            }
            NetdRequest::AttachEndpoint { overlay_id, endpoint_id, netns } => {
                if self.endpoints.contains_key(&endpoint_id) { return NetdResponse::Attached; }
                let container = format!("fc-{endpoint_id}");
                let config = VethConfig { pair: VethPair { host: endpoint_id.clone(), container }, mtu: None, host_addr: None, container_addr: None };
                if create_veth_pair(&config).is_err() { return reject(RejectionCode::Busy, "failed to create endpoint veth"); }
                let master = match build_ip_link_set_master_cmd(&endpoint_id, &overlay_id) { Ok(command) => command, Err(_) => { let _ = destroy_veth_pair(&endpoint_id); return reject(RejectionCode::PolicyViolation, "invalid endpoint interface"); } };
                if exec_cmd(&master).is_err() { let _ = destroy_veth_pair(&endpoint_id); return reject(RejectionCode::Busy, "failed to attach endpoint veth"); }
                if let Some(netns) = netns { if move_to_netns(&format!("fc-{endpoint_id}"), &netns).is_err() { let _ = destroy_veth_pair(&endpoint_id); return reject(RejectionCode::Busy, "failed to move endpoint into namespace"); } }
                self.endpoints.insert(endpoint_id.clone(), overlay_id);
                if self.persist().is_err() { let _ = self.endpoints.remove(&endpoint_id); let _ = destroy_veth_pair(&endpoint_id); return reject(RejectionCode::Busy, "failed to persist endpoint ownership"); }
                NetdResponse::Attached
            }
            NetdRequest::DetachEndpoint { endpoint_id, .. } => { if self.endpoints.remove(&endpoint_id).is_some() { let _ = destroy_veth_pair(&endpoint_id); } let _ = self.persist(); NetdResponse::Detached }
            NetdRequest::Inspect { overlay_id } => NetdResponse::Snapshot { overlay_id, revision: envelope.revision },
        }
    }
}
fn reject(code: RejectionCode, reason: &str) -> NetdResponse { NetdResponse::Rejected { code, reason: reason.to_string() } }
