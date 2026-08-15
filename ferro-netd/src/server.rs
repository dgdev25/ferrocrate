use crate::policy::Policy;
use crate::{
    grants::{GrantError, GrantVerifier},
    protocol::{
        DesiredStateEnvelope, GrantedDesiredStateEnvelope, GrantedEnvelope, NetdRequest,
        NetdResponse, RejectionCode, SignedEnvelope, MAX_FRAME_BYTES,
    },
};
use ferro_core::authorization::helper_grant::{GrantAction, GrantParameters};
use ferro_net::{
    bridge::{build_ip_link_set_master_cmd, create_bridge, destroy_bridge, BridgeConfig},
    exec_cmd, exec_cmd_capture,
    netns::move_to_netns,
    veth::{create_veth_pair, destroy_veth_pair, VethConfig, VethPair},
    WireGuardInterfaceConfig, WireGuardManager, WireGuardPeer,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
};

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    overlays: BTreeSet<String>,
    endpoints: BTreeMap<String, String>,
    #[serde(default)]
    routes: BTreeMap<String, Vec<String>>,
}

pub struct NetdServer {
    uid: u32,
    policy: Policy,
    grants: Option<GrantVerifier>,
    overlays: BTreeSet<String>,
    endpoints: BTreeMap<String, String>,
    routes: BTreeMap<String, Vec<String>>,
    wireguard: Option<(WireGuardManager, PathBuf, u16)>,
    journal: Option<PathBuf>,
}
impl NetdServer {
    pub fn new(uid: u32, policy: Policy) -> Self {
        Self {
            uid,
            policy,
            grants: None,
            overlays: BTreeSet::new(),
            endpoints: BTreeMap::new(),
            routes: BTreeMap::new(),
            wireguard: None,
            journal: None,
        }
    }
    pub fn with_grants(mut self, grants: GrantVerifier) -> Self {
        self.grants = Some(grants);
        self
    }
    pub fn with_wireguard(
        uid: u32,
        policy: Policy,
        private_key_path: PathBuf,
        listen_port: u16,
    ) -> Self {
        Self {
            uid,
            policy,
            grants: None,
            overlays: BTreeSet::new(),
            endpoints: BTreeMap::new(),
            routes: BTreeMap::new(),
            wireguard: Some((WireGuardManager::new(None), private_key_path, listen_port)),
            journal: None,
        }
    }
    pub fn load_journal(mut self, path: PathBuf) -> Result<Self, String> {
        if path.exists() {
            let state: PersistedState =
                serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            self.overlays = state.overlays;
            self.endpoints = state.endpoints;
            self.routes = state.routes;
        }
        self.journal = Some(path);
        self.overlays.retain(|overlay| {
            exec_cmd_capture(&vec![
                "ip".into(),
                "link".into(),
                "show".into(),
                "dev".into(),
                overlay.clone(),
            ])
            .is_ok()
        });
        self.endpoints.retain(|endpoint, _| {
            exec_cmd_capture(&vec![
                "ip".into(),
                "link".into(),
                "show".into(),
                "dev".into(),
                endpoint.clone(),
            ])
            .is_ok()
        });
        self.persist()?;
        Ok(self)
    }
    fn persist(&self) -> Result<(), String> {
        let Some(path) = &self.journal else {
            return Ok(());
        };
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        file.write_all(
            &serde_json::to_vec(&PersistedState {
                overlays: self.overlays.clone(),
                endpoints: self.endpoints.clone(),
                routes: self.routes.clone(),
            })
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(temporary, path).map_err(|error| error.to_string())
    }
    pub fn handle_peer(&mut self, uid: u32, frame: &[u8], now: u64) -> NetdResponse {
        if uid != self.uid {
            return reject(RejectionCode::UnauthorizedPeer, "unexpected Unix peer UID");
        }
        if frame.len() > MAX_FRAME_BYTES + 4 {
            return reject(RejectionCode::OversizedFrame, "frame exceeds 1 MiB");
        }
        if frame.len() < 4 {
            return reject(RejectionCode::InvalidFrame, "missing frame prefix");
        }
        let length = u32::from_be_bytes(frame[..4].try_into().expect("prefix")) as usize;
        if length > MAX_FRAME_BYTES || length != frame.len() - 4 {
            return reject(RejectionCode::OversizedFrame, "invalid frame length");
        }
        let granted_desired =
            serde_json::from_slice::<GrantedDesiredStateEnvelope>(&frame[4..]).ok();
        if granted_desired.is_some() {
            return reject(
                RejectionCode::PolicyViolation,
                "bulk desired-state grants are forbidden; submit one authorized mutation per resource",
            );
        }
        if let Some(granted) = granted_desired {
            let desired = granted.envelope;
            let state = match self.policy.validate_desired_state(
                &desired.desired_state,
                &desired.node_id,
                now,
            ) {
                Ok(state) => state,
                Err(code) => return reject(code, "desired state rejected"),
            };
            let params = match desired_parameters(&desired) {
                Ok(value) => value,
                Err(code) => return reject(code, "invalid normalized parameters"),
            };
            if let Err(code) = self.consume_grant(
                &granted.grant,
                GrantAction::NetworkCreate,
                &granted.resource_uuid,
                granted.resource_generation,
                &params,
                now,
            ) {
                self.policy
                    .rollback("__desired_state", state.cluster_epoch, state.revision);
                return reject(code, "authorization grant rejected");
            }
            let desired_overlays: BTreeSet<String> = state
                .overlays
                .iter()
                .map(|overlay| overlay.overlay_id.clone())
                .collect();
            for overlay in state.overlays {
                let request = NetdRequest::ApplyOverlay {
                    overlay_id: overlay.overlay_id,
                    peers: overlay
                        .peers
                        .into_iter()
                        .map(|peer| crate::protocol::PeerSpec {
                            node_id: peer.node_id,
                            public_key: base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                peer.public_key,
                            ),
                            endpoint: peer.endpoint,
                            allowed_ips: peer.allowed_ips,
                        })
                        .collect(),
                    routes: overlay.routes,
                    addresses: Vec::new(),
                };
                let NetdRequest::ApplyOverlay {
                    overlay_id,
                    peers,
                    routes,
                    addresses,
                } = request
                else {
                    unreachable!()
                };
                if let Some((manager, private_key_path, listen_port)) = &self.wireguard {
                    let peers = match peers
                        .iter()
                        .map(|peer| {
                            let endpoint = peer.endpoint.parse().map_err(|_| ());
                            let allowed_ips = peer
                                .allowed_ips
                                .iter()
                                .map(|route| route.parse().map_err(|_| ()))
                                .collect::<Result<Vec<_>, _>>();
                            match (endpoint, allowed_ips) {
                                (Ok(endpoint), Ok(allowed_ips)) => Ok(WireGuardPeer::new(
                                    peer.node_id.clone(),
                                    peer.public_key.clone(),
                                    endpoint,
                                    allowed_ips,
                                )),
                                _ => Err(()),
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(peers) => peers,
                        Err(()) => {
                            return reject(RejectionCode::PolicyViolation, "invalid WireGuard peer")
                        }
                    };
                    let addresses = match addresses
                        .iter()
                        .map(|address| address.parse())
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(addresses) => addresses,
                        Err(_) => {
                            return reject(
                                RejectionCode::PolicyViolation,
                                "invalid WireGuard interface address",
                            )
                        }
                    };
                    let config = WireGuardInterfaceConfig {
                        name: overlay_id.clone(),
                        private_key_path: private_key_path.clone(),
                        listen_port: *listen_port,
                        addresses,
                    };
                    if manager.apply(&config, &peers).is_err() {
                        return reject(RejectionCode::Busy, "failed to apply WireGuard overlay");
                    }
                }
                if !self.overlays.contains(&overlay_id)
                    && create_bridge(&BridgeConfig {
                        name: overlay_id.clone(),
                        cidr: String::new(),
                        ipv6_cidr: None,
                    })
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "failed to create overlay bridge");
                }
                if apply_overlay_routes(&overlay_id, &routes).is_err() {
                    self.policy
                        .rollback("__desired_state", state.cluster_epoch, state.revision);
                    return reject(RejectionCode::Busy, "failed to apply overlay routes");
                }
                self.overlays.insert(overlay_id.clone());
                self.routes.insert(overlay_id.clone(), routes);
            }
            let stale: Vec<String> = self
                .overlays
                .difference(&desired_overlays)
                .cloned()
                .collect();
            for overlay_id in stale {
                if let Some((manager, private_key_path, listen_port)) = &self.wireguard {
                    let _ = manager.remove(&WireGuardInterfaceConfig {
                        name: overlay_id.clone(),
                        private_key_path: private_key_path.clone(),
                        listen_port: *listen_port,
                        addresses: Vec::new(),
                    });
                }
                if let Some(routes) = self.routes.get(&overlay_id) {
                    if remove_overlay_routes(&overlay_id, routes).is_err() {
                        return reject(RejectionCode::Busy, "failed to remove overlay routes");
                    }
                }
                self.routes.remove(&overlay_id);
                self.overlays.remove(&overlay_id);
                let endpoints: Vec<String> = self
                    .endpoints
                    .iter()
                    .filter(|(_, overlay)| *overlay == &overlay_id)
                    .map(|(endpoint, _)| endpoint.clone())
                    .collect();
                for endpoint in endpoints {
                    self.endpoints.remove(&endpoint);
                    let _ = destroy_veth_pair(&endpoint);
                }
                let _ = destroy_bridge(&overlay_id);
            }
            if self.persist().is_err() {
                self.policy
                    .rollback("__desired_state", state.cluster_epoch, state.revision);
                return reject(RejectionCode::Busy, "failed to persist overlay ownership");
            }
            let response = NetdResponse::Applied;
            if self
                .record_grant_result(
                    &granted.grant.claims.request_id,
                    granted.grant.claims.nonce,
                    format!("desired-state:{}", state.revision),
                    "applied",
                )
                .is_err()
            {
                return reject(RejectionCode::Busy, "result witness unavailable");
            }
            return response;
        }
        let granted: GrantedEnvelope = match serde_json::from_slice(&frame[4..]) {
            Ok(value) => value,
            Err(_) => {
                let legacy: SignedEnvelope = match serde_json::from_slice(&frame[4..]) {
                    Ok(value) => value,
                    Err(_) => return reject(RejectionCode::InvalidFrame, "invalid JSON"),
                };
                if let Err(code) = self.policy.validate(&legacy, now) {
                    return reject(code, "policy rejected request");
                }
                return reject(
                    RejectionCode::MissingGrant,
                    "privileged request requires a grant",
                );
            }
        };
        let envelope = granted.envelope;
        if let Err(code) = self.policy.validate(&envelope, now) {
            return reject(code, "policy rejected request");
        }
        let (action, params) = match request_parameters(&envelope.request) {
            Ok(value) => value,
            Err(code) => return reject(code, "invalid normalized parameters"),
        };
        if let Err(code) = self.consume_grant(
            &granted.grant,
            action,
            &granted.resource_uuid,
            granted.resource_generation,
            &params,
            now,
        ) {
            self.policy.rollback(
                request_overlay_id(&envelope.request),
                envelope.epoch,
                envelope.revision,
            );
            return reject(code, "authorization grant rejected");
        }
        let request_id = granted.grant.claims.request_id.clone();
        let nonce = granted.grant.claims.nonce;
        match envelope.request {
            NetdRequest::ApplyOverlay {
                overlay_id,
                peers,
                routes,
                addresses,
            } => {
                if let Some((manager, private_key_path, listen_port)) = &self.wireguard {
                    let addresses = match addresses
                        .iter()
                        .map(|address| address.parse())
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(addresses) => addresses,
                        Err(_) => {
                            return reject(
                                RejectionCode::PolicyViolation,
                                "invalid WireGuard interface address",
                            )
                        }
                    };
                    let peers = match peers
                        .iter()
                        .map(|peer| {
                            let endpoint = peer.endpoint.parse().map_err(|_| ());
                            let allowed_ips = peer
                                .allowed_ips
                                .iter()
                                .map(|route| route.parse().map_err(|_| ()))
                                .collect::<Result<Vec<_>, _>>();
                            match (endpoint, allowed_ips) {
                                (Ok(endpoint), Ok(allowed_ips)) => Ok(WireGuardPeer::new(
                                    peer.node_id.clone(),
                                    peer.public_key.clone(),
                                    endpoint,
                                    allowed_ips,
                                )),
                                _ => Err(()),
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(peers) => peers,
                        Err(()) => {
                            return reject(RejectionCode::PolicyViolation, "invalid WireGuard peer")
                        }
                    };
                    let config = WireGuardInterfaceConfig {
                        name: overlay_id.clone(),
                        private_key_path: private_key_path.clone(),
                        listen_port: *listen_port,
                        addresses,
                    };
                    if manager.apply(&config, &peers).is_err() {
                        return reject(RejectionCode::Busy, "failed to apply WireGuard overlay");
                    }
                }
                if !self.overlays.contains(&overlay_id)
                    && create_bridge(&BridgeConfig {
                        name: overlay_id.clone(),
                        cidr: String::new(),
                        ipv6_cidr: None,
                    })
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "failed to create overlay bridge");
                }
                if apply_overlay_routes(&overlay_id, &routes).is_err() {
                    self.policy
                        .rollback(&overlay_id, envelope.epoch, envelope.revision);
                    return reject(RejectionCode::Busy, "failed to apply overlay routes");
                }
                self.overlays.insert(overlay_id.clone());
                self.routes.insert(overlay_id.clone(), routes);
                if self.persist().is_err() {
                    self.policy
                        .rollback(&overlay_id, envelope.epoch, envelope.revision);
                    self.overlays.remove(&overlay_id);
                    let _ = destroy_bridge(&overlay_id);
                    return reject(RejectionCode::Busy, "failed to persist overlay ownership");
                }
                if self
                    .record_grant_result(
                        &request_id,
                        nonce,
                        format!("overlay:{overlay_id}"),
                        "applied",
                    )
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "result witness unavailable");
                }
                NetdResponse::Applied
            }
            NetdRequest::RemoveOverlay { overlay_id } => {
                if let Some((manager, private_key_path, listen_port)) = &self.wireguard {
                    let _ = manager.remove(&WireGuardInterfaceConfig {
                        name: overlay_id.clone(),
                        private_key_path: private_key_path.clone(),
                        listen_port: *listen_port,
                        addresses: Vec::new(),
                    });
                }
                if self.overlays.contains(&overlay_id) {
                    if let Some(routes) = self.routes.get(&overlay_id) {
                        if remove_overlay_routes(&overlay_id, routes).is_err() {
                            return reject(RejectionCode::Busy, "failed to remove overlay routes");
                        }
                    }
                    self.routes.remove(&overlay_id);
                    self.overlays.remove(&overlay_id);
                    let _ = destroy_bridge(&overlay_id);
                }
                let _ = self.persist();
                if self
                    .record_grant_result(
                        &request_id,
                        nonce,
                        format!("overlay:{overlay_id}"),
                        "removed",
                    )
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "result witness unavailable");
                }
                NetdResponse::Removed
            }
            NetdRequest::AttachEndpoint {
                overlay_id,
                endpoint_id,
                netns,
            } => {
                if self.endpoints.contains_key(&endpoint_id) {
                    return NetdResponse::Attached;
                }
                let container = format!("fc-{endpoint_id}");
                let config = VethConfig {
                    pair: VethPair {
                        host: endpoint_id.clone(),
                        container,
                    },
                    mtu: None,
                    host_addr: None,
                    container_addr: None,
                };
                if create_veth_pair(&config).is_err() {
                    return reject(RejectionCode::Busy, "failed to create endpoint veth");
                }
                let master = match build_ip_link_set_master_cmd(&endpoint_id, &overlay_id) {
                    Ok(command) => command,
                    Err(_) => {
                        let _ = destroy_veth_pair(&endpoint_id);
                        return reject(
                            RejectionCode::PolicyViolation,
                            "invalid endpoint interface",
                        );
                    }
                };
                if exec_cmd(&master).is_err() {
                    let _ = destroy_veth_pair(&endpoint_id);
                    return reject(RejectionCode::Busy, "failed to attach endpoint veth");
                }
                if let Some(netns) = netns {
                    if move_to_netns(&format!("fc-{endpoint_id}"), &netns).is_err() {
                        let _ = destroy_veth_pair(&endpoint_id);
                        return reject(
                            RejectionCode::Busy,
                            "failed to move endpoint into namespace",
                        );
                    }
                }
                self.endpoints.insert(endpoint_id.clone(), overlay_id);
                if self.persist().is_err() {
                    let _ = self.endpoints.remove(&endpoint_id);
                    let _ = destroy_veth_pair(&endpoint_id);
                    return reject(RejectionCode::Busy, "failed to persist endpoint ownership");
                }
                if self
                    .record_grant_result(
                        &request_id,
                        nonce,
                        format!("endpoint:{endpoint_id}"),
                        "attached",
                    )
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "result witness unavailable");
                }
                NetdResponse::Attached
            }
            NetdRequest::DetachEndpoint { endpoint_id, .. } => {
                if self.endpoints.remove(&endpoint_id).is_some() {
                    let _ = destroy_veth_pair(&endpoint_id);
                }
                let _ = self.persist();
                if self
                    .record_grant_result(
                        &request_id,
                        nonce,
                        format!("endpoint:{endpoint_id}"),
                        "detached",
                    )
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "result witness unavailable");
                }
                NetdResponse::Detached
            }
            NetdRequest::Inspect { overlay_id } => {
                if self
                    .record_grant_result(
                        &request_id,
                        nonce,
                        format!("overlay:{overlay_id}"),
                        "inspected",
                    )
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "result witness unavailable");
                }
                NetdResponse::Snapshot {
                    overlay_id,
                    revision: envelope.revision,
                }
            }
        }
    }
    fn consume_grant(
        &mut self,
        grant: &ferro_core::authorization::helper_grant::HelperGrant,
        action: GrantAction,
        uuid: &str,
        generation: u64,
        params: &GrantParameters,
        now: u64,
    ) -> Result<(), RejectionCode> {
        let verifier = self.grants.as_mut().ok_or(RejectionCode::MissingGrant)?;
        let consumed = verifier
            .verify_and_consume(
                grant,
                action,
                uuid,
                generation,
                params,
                now,
                monotonic_millis(),
            )
            .map_err(map_grant_error)?;
        verifier.arm_effect(&consumed).map_err(map_grant_error)
    }
    fn record_grant_result(
        &mut self,
        request_id: &str,
        nonce: [u8; 16],
        identity: String,
        outcome: &str,
    ) -> Result<(), GrantError> {
        if let Some(verifier) = self.grants.as_mut() {
            let consumed = crate::grants::ConsumedGrant::restored(request_id, nonce);
            verifier.record_result(&consumed, identity, outcome)?;
        }
        Ok(())
    }
}

fn request_parameters(
    request: &NetdRequest,
) -> Result<(GrantAction, GrantParameters), RejectionCode> {
    let (action, operation, fields) = match request {
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
                    serde_json::to_string(peers).map_err(|_| RejectionCode::InvalidFrame)?,
                ),
                (
                    "routes".into(),
                    serde_json::to_string(routes).map_err(|_| RejectionCode::InvalidFrame)?,
                ),
                (
                    "addresses".into(),
                    serde_json::to_string(addresses).map_err(|_| RejectionCode::InvalidFrame)?,
                ),
            ],
        ),
        NetdRequest::RemoveOverlay { overlay_id } => (
            GrantAction::NetworkDelete,
            "overlay.delete",
            vec![("overlay_id".into(), overlay_id.clone())],
        ),
        NetdRequest::AttachEndpoint {
            overlay_id,
            endpoint_id,
            netns,
        } => (
            GrantAction::NetworkAttach,
            "endpoint.attach",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("endpoint_id".into(), endpoint_id.clone()),
                ("netns".into(), netns.clone().unwrap_or_default()),
            ],
        ),
        NetdRequest::DetachEndpoint {
            overlay_id,
            endpoint_id,
        } => (
            GrantAction::NetworkDetach,
            "endpoint.detach",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("endpoint_id".into(), endpoint_id.clone()),
            ],
        ),
        NetdRequest::Inspect { overlay_id } => (
            GrantAction::NetworkInspect,
            "overlay.inspect",
            vec![("overlay_id".into(), overlay_id.clone())],
        ),
    };
    GrantParameters::new(operation, fields, vec![])
        .map(|p| (action, p))
        .map_err(|_| RejectionCode::PolicyViolation)
}
fn request_overlay_id(request: &NetdRequest) -> &str {
    match request {
        NetdRequest::ApplyOverlay { overlay_id, .. }
        | NetdRequest::RemoveOverlay { overlay_id }
        | NetdRequest::AttachEndpoint { overlay_id, .. }
        | NetdRequest::DetachEndpoint { overlay_id, .. }
        | NetdRequest::Inspect { overlay_id } => overlay_id,
    }
}
fn desired_parameters(desired: &DesiredStateEnvelope) -> Result<GrantParameters, RejectionCode> {
    GrantParameters::new(
        "desired-state.apply",
        vec![
            ("cluster_id".into(), desired.cluster_id.clone()),
            ("node_id".into(), desired.node_id.clone()),
            (
                "desired_state".into(),
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &desired.desired_state,
                ),
            ),
        ],
        vec![],
    )
    .map_err(|_| RejectionCode::PolicyViolation)
}
fn monotonic_millis() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split('.').next()?.parse::<u64>().ok())
        .unwrap_or(u64::MAX)
        .saturating_mul(1000)
}
fn map_grant_error(error: GrantError) -> RejectionCode {
    match error {
        GrantError::Replay => RejectionCode::GrantReplay,
        GrantError::InvalidSignature => RejectionCode::InvalidSignature,
        _ => RejectionCode::InvalidGrant,
    }
}
fn apply_overlay_routes(interface: &str, routes: &[String]) -> Result<(), ()> {
    for route in routes {
        exec_cmd(&vec![
            "ip".into(),
            "route".into(),
            "replace".into(),
            route.clone(),
            "dev".into(),
            interface.to_string(),
        ])
        .map_err(|_| ())?;
    }
    Ok(())
}
fn remove_overlay_routes(interface: &str, routes: &[String]) -> Result<(), ()> {
    for route in routes {
        exec_cmd(&vec![
            "ip".into(),
            "route".into(),
            "del".into(),
            route.clone(),
            "dev".into(),
            interface.to_string(),
        ])
        .map_err(|_| ())?;
    }
    Ok(())
}
fn reject(code: RejectionCode, reason: &str) -> NetdResponse {
    NetdResponse::Rejected {
        code,
        reason: reason.to_string(),
    }
}
