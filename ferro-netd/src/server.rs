use crate::kernel_ops::{NetKernelOps, RealNetKernelOps};
use crate::policy::Policy;
use crate::request_binding::{request_overlay_id, request_parameters};
use crate::{
    grants::GrantVerifier,
    protocol::{
        GrantedDesiredStateEnvelope, GrantedEnvelope, NetdRequest, NetdResponse, RejectionCode,
        SignedEnvelope, MAX_FRAME_BYTES,
    },
};
use ferro_net::{
    bridge::build_ip_link_set_master_cmd,
    veth::{VethConfig, VethPair},
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
    pub(crate) grants: Option<GrantVerifier>,
    pub(crate) overlays: BTreeSet<String>,
    pub(crate) endpoints: BTreeMap<String, String>,
    pub(crate) routes: BTreeMap<String, Vec<String>>,
    journal: Option<PathBuf>,
    pub(crate) kernel: Box<dyn NetKernelOps>,
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) test_faults: crate::test_support::FaultHandle,
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
            journal: None,
            kernel: Box::new(RealNetKernelOps::new()),
            #[cfg(any(test, feature = "test-support"))]
            test_faults: Default::default(),
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
            journal: None,
            kernel: Box::new(RealNetKernelOps::with_wireguard(
                private_key_path,
                listen_port,
            )),
            #[cfg(any(test, feature = "test-support"))]
            test_faults: Default::default(),
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
        self.overlays
            .retain(|overlay| self.kernel.observe_link(overlay));
        self.endpoints
            .retain(|endpoint, _| self.kernel.observe_link(endpoint));
        self.persist()?;
        Ok(self)
    }
    fn persist(&self) -> Result<(), String> {
        #[cfg(any(test, feature = "test-support"))]
        if self
            .test_faults
            .take(crate::test_support::FaultPoint::StatePersist)
        {
            return Err("injected state persistence failure".into());
        }
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
        macro_rules! reject_effect {
            ($code:expr, $reason:expr, $identity:expr) => {{
                if self
                    .record_grant_failure(&request_id, nonce, $identity, $reason)
                    .is_err()
                {
                    return reject(RejectionCode::Busy, "failure witness unavailable");
                }
                return reject($code, $reason);
            }};
        }
        match envelope.request {
            NetdRequest::ApplyOverlay {
                overlay_id,
                peers,
                routes,
                addresses,
            } => {
                if self
                    .kernel
                    .apply_wireguard(&overlay_id, &addresses, &peers)
                    .is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to apply WireGuard overlay",
                        format!("overlay:{overlay_id}")
                    );
                }
                if !self.overlays.contains(&overlay_id)
                    && self.kernel.create_overlay(&overlay_id).is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to create overlay bridge",
                        format!("overlay:{overlay_id}")
                    );
                }
                if self.kernel.apply_routes(&overlay_id, &routes).is_err() {
                    self.policy
                        .rollback(&overlay_id, envelope.epoch, envelope.revision);
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to apply overlay routes",
                        format!("overlay:{overlay_id}")
                    );
                }
                self.overlays.insert(overlay_id.clone());
                self.routes.insert(overlay_id.clone(), routes);
                if self.persist().is_err() {
                    self.policy
                        .rollback(&overlay_id, envelope.epoch, envelope.revision);
                    self.overlays.remove(&overlay_id);
                    let _ = self.kernel.remove_overlay(&overlay_id);
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist overlay ownership",
                        format!("overlay:{overlay_id}")
                    );
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
                if self.kernel.remove_wireguard(&overlay_id).is_err() {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to remove WireGuard overlay",
                        format!("overlay:{overlay_id}")
                    );
                }
                if self.overlays.contains(&overlay_id) {
                    if let Some(routes) = self.routes.get(&overlay_id) {
                        if self.kernel.remove_routes(&overlay_id, routes).is_err() {
                            reject_effect!(
                                RejectionCode::Busy,
                                "failed to remove overlay routes",
                                format!("overlay:{overlay_id}")
                            );
                        }
                    }
                    self.routes.remove(&overlay_id);
                    self.overlays.remove(&overlay_id);
                    if self.kernel.remove_overlay(&overlay_id).is_err() {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to remove overlay bridge",
                            format!("overlay:{overlay_id}")
                        );
                    }
                }
                if self.persist().is_err() {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist overlay deletion",
                        format!("overlay:{overlay_id}")
                    );
                }
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
                if let Some(existing_overlay) = self.endpoints.get(&endpoint_id) {
                    if existing_overlay != &overlay_id || !self.kernel.observe_link(&endpoint_id) {
                        reject_effect!(
                            RejectionCode::PolicyViolation,
                            "endpoint identity conflict",
                            format!("endpoint:{endpoint_id}")
                        );
                    }
                    if self
                        .record_grant_result(
                            &request_id,
                            nonce,
                            format!("endpoint:{endpoint_id}"),
                            "attached_idempotent",
                        )
                        .is_err()
                    {
                        return reject(RejectionCode::Busy, "result witness unavailable");
                    }
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
                if self.kernel.create_endpoint(&config).is_err() {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to create endpoint veth",
                        format!("endpoint:{endpoint_id}")
                    );
                }
                if build_ip_link_set_master_cmd(&endpoint_id, &overlay_id).is_err() {
                    let _ = self.kernel.remove_endpoint(&endpoint_id);
                    return reject(RejectionCode::PolicyViolation, "invalid endpoint interface");
                }
                if self
                    .kernel
                    .attach_endpoint(&endpoint_id, &overlay_id)
                    .is_err()
                {
                    let _ = self.kernel.remove_endpoint(&endpoint_id);
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to attach endpoint veth",
                        format!("endpoint:{endpoint_id}")
                    );
                }
                if let Some(netns) = netns {
                    if self
                        .kernel
                        .move_endpoint(&format!("fc-{endpoint_id}"), &netns)
                        .is_err()
                    {
                        let _ = self.kernel.remove_endpoint(&endpoint_id);
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to move endpoint into namespace",
                            format!("endpoint:{endpoint_id}")
                        );
                    }
                }
                self.endpoints.insert(endpoint_id.clone(), overlay_id);
                if self.persist().is_err() {
                    let _ = self.endpoints.remove(&endpoint_id);
                    let _ = self.kernel.remove_endpoint(&endpoint_id);
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist endpoint ownership",
                        format!("endpoint:{endpoint_id}")
                    );
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
                if self.endpoints.remove(&endpoint_id).is_some()
                    && self.kernel.remove_endpoint(&endpoint_id).is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to destroy endpoint veth",
                        format!("endpoint:{endpoint_id}")
                    );
                }
                if self.persist().is_err() {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist endpoint deletion",
                        format!("endpoint:{endpoint_id}")
                    );
                }
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
}
fn reject(code: RejectionCode, reason: &str) -> NetdResponse {
    NetdResponse::Rejected {
        code,
        reason: reason.to_string(),
    }
}
