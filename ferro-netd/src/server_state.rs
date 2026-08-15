use crate::kernel_ops::LiveEffectObservation;
use crate::{grants_recovery::RecoveryObservation, server::NetdServer};
use ferro_core::authorization::AuthorizationServiceMode;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
};

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    overlays: BTreeSet<String>,
    endpoints: BTreeMap<String, String>,
    #[serde(default)]
    routes: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    addresses: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    effect_receipts: BTreeMap<String, crate::effect_receipt::EffectReceipt>,
    #[serde(default)]
    quarantined: BTreeSet<String>,
    #[serde(default)]
    overlay_intents: BTreeMap<String, OverlayMutationIntent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OverlayMutationIntent {
    pub(crate) operation_id: [u8; 16],
    pub(crate) action: String,
    pub(crate) prior: Option<crate::effect_receipt::EffectReceipt>,
    pub(crate) desired: crate::effect_receipt::EffectReceipt,
    pub(crate) phase: String,
    #[serde(default)]
    pub(crate) routes: Vec<String>,
    #[serde(default)]
    pub(crate) addresses: Vec<String>,
}

impl NetdServer {
    pub(crate) fn begin_overlay_intent(
        &mut self,
        operation_id: [u8; 16],
        action: &str,
        desired: crate::effect_receipt::EffectReceipt,
        routes: Vec<String>,
        addresses: Vec<String>,
    ) -> Result<(), String> {
        let identity = desired.identity();
        self.overlay_intents.insert(
            identity.clone(),
            OverlayMutationIntent {
                operation_id,
                action: action.into(),
                prior: self.effect_receipts.get(&identity).cloned(),
                desired,
                phase: "pending".into(),
                routes,
                addresses,
            },
        );
        self.persist()
    }
    pub(crate) fn mark_overlay_intent(
        &mut self,
        identity: &str,
        phase: &str,
    ) -> Result<(), String> {
        if let Some(intent) = self.overlay_intents.get_mut(identity) {
            intent.phase = phase.into();
        }
        self.persist()
    }
    pub(crate) fn validate_frame(
        &self,
        uid: u32,
        frame: &[u8],
    ) -> Result<(), crate::protocol::NetdResponse> {
        use crate::protocol::{RejectionCode, MAX_FRAME_BYTES};
        if uid != self.uid {
            return Err(crate::server_grants::reject(
                RejectionCode::UnauthorizedPeer,
                "unexpected Unix peer UID",
            ));
        }
        if frame.len() < 4 || frame.len() > MAX_FRAME_BYTES + 4 {
            return Err(crate::server_grants::reject(
                RejectionCode::OversizedFrame,
                "invalid frame length",
            ));
        }
        let length = u32::from_be_bytes(frame[..4].try_into().expect("prefix")) as usize;
        if length > MAX_FRAME_BYTES || length != frame.len() - 4 {
            return Err(crate::server_grants::reject(
                RejectionCode::OversizedFrame,
                "invalid frame length",
            ));
        }
        Ok(())
    }
    pub(crate) fn validate_granted_handshake(
        &self,
        handshake: &crate::protocol::ServiceHandshake,
    ) -> bool {
        let Some((expected, boot)) = &self.authorization_identity else {
            return true;
        };
        AuthorizationServiceMode::parse(&handshake.mode, handshake.policy_digest)
            .is_ok_and(|peer| expected.require_match(peer).is_ok())
            && handshake.instance_boot == *boot
    }

    pub(crate) fn request_is_quarantined(&self, request: &crate::protocol::NetdRequest) -> bool {
        self.overlay_is_quarantined(crate::request_binding::request_overlay_id(request))
            || match request {
                crate::protocol::NetdRequest::AttachEndpoint { endpoint_id, .. }
                | crate::protocol::NetdRequest::DetachEndpoint { endpoint_id, .. } => self
                    .quarantined
                    .contains(&format!("legacy-endpoint:{endpoint_id}")),
                _ => false,
            }
    }
    pub(crate) fn overlay_is_quarantined(&self, overlay: &str) -> bool {
        let suffix = format!("overlay:{overlay}");
        self.quarantined
            .iter()
            .any(|entry| entry.ends_with(&suffix))
    }
    pub(crate) fn finish_inspect(
        &mut self,
        request_id: &str,
        nonce: [u8; 16],
        overlay_id: String,
        revision: u64,
    ) -> crate::protocol::NetdResponse {
        if self
            .record_grant_result(
                request_id,
                nonce,
                format!("overlay:{overlay_id}"),
                "inspected",
            )
            .is_err()
        {
            return crate::protocol::NetdResponse::Rejected {
                code: crate::protocol::RejectionCode::Busy,
                reason: "result witness unavailable".into(),
            };
        }
        crate::protocol::NetdResponse::Snapshot {
            overlay_id,
            revision,
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
            self.addresses = state.addresses;
            self.effect_receipts = state.effect_receipts;
            self.quarantined = state.quarantined;
            self.overlay_intents = state.overlay_intents;
        }
        self.journal = Some(path);
        self.overlays.retain(|overlay| {
            let identity = format!("overlay:{overlay}");
            let verifiable = self
                .effect_receipts
                .get(&identity)
                .is_some_and(|receipt| !receipt.is_legacy_identity());
            if !verifiable {
                self.quarantined.insert(format!("legacy-{identity}"));
            }
            verifiable
        });
        self.endpoints.retain(|endpoint, _| {
            let identity = format!("endpoint:{endpoint}");
            let verifiable = self
                .effect_receipts
                .get(&identity)
                .is_some_and(|receipt| !receipt.is_legacy_identity());
            if !verifiable {
                self.quarantined.insert(format!("legacy-{identity}"));
            }
            verifiable
        });
        for (identity, receipt) in &self.effect_receipts {
            if self.kernel.observe_effect(receipt) != LiveEffectObservation::Exact {
                self.quarantined.insert(format!("ambiguous-{identity}"));
            }
        }
        for (identity, intent) in self.overlay_intents.clone() {
            if intent.phase == "succeeded" {
                continue;
            }
            let overlay = identity.strip_prefix("overlay:").unwrap_or("").to_string();
            match self.kernel.observe_effect(&intent.desired) {
                LiveEffectObservation::Exact => {
                    self.quarantined.retain(|entry| !entry.ends_with(&identity));
                    if intent.desired.expected_exists() {
                        self.overlays.insert(overlay.clone());
                        self.routes.insert(overlay.clone(), intent.routes);
                        self.addresses.insert(overlay, intent.addresses);
                        self.effect_receipts
                            .insert(identity.clone(), intent.desired);
                    } else {
                        self.overlays.remove(&overlay);
                        self.routes.remove(&overlay);
                        self.addresses.remove(&overlay);
                        self.effect_receipts.remove(&identity);
                    }
                    if let Some(value) = self.overlay_intents.get_mut(&identity) {
                        value.phase = "recovered".into();
                    }
                }
                _ if intent.prior.as_ref().is_some_and(|prior| {
                    self.kernel.observe_effect(prior) == LiveEffectObservation::Exact
                }) =>
                {
                    self.quarantined.retain(|entry| !entry.ends_with(&identity));
                    if let Some(prior) = intent.prior {
                        self.overlays.insert(overlay);
                        self.effect_receipts.insert(identity.clone(), prior);
                    }
                    if let Some(value) = self.overlay_intents.get_mut(&identity) {
                        value.phase = "not_applied".into();
                    }
                }
                _ => {
                    self.quarantined.insert(format!("ambiguous-{identity}"));
                    if let Some(value) = self.overlay_intents.get_mut(&identity) {
                        value.phase = "quarantined".into();
                    }
                }
            }
        }
        self.persist()?;
        if let Some(grants) = self.grants.as_mut() {
            let overlays = &self.overlays;
            let endpoints = &self.endpoints;
            let receipts = &self.effect_receipts;
            let kernel = &self.kernel;
            grants
                .reconcile_unknown(|receipt| {
                    let identity = receipt.identity();
                    let (name, owned) = identity
                        .strip_prefix("overlay:")
                        .map(|name| (name, overlays.contains(name)))
                        .or_else(|| {
                            identity
                                .strip_prefix("endpoint:")
                                .map(|name| (name, endpoints.contains_key(name)))
                        })
                        .unwrap_or(("", false));
                    let receipt_matches = if receipt.expected_exists() {
                        receipts.get(&identity) == Some(receipt)
                    } else {
                        !receipts.contains_key(&identity)
                    };
                    if name.is_empty() || !receipt_matches {
                        return RecoveryObservation::Conflict;
                    }
                    match kernel.observe_effect(receipt) {
                        LiveEffectObservation::Exact => {
                            RecoveryObservation::Consistent(receipt.expected_exists())
                        }
                        LiveEffectObservation::Absent if !owned => {
                            RecoveryObservation::Consistent(false)
                        }
                        LiveEffectObservation::Absent
                        | LiveEffectObservation::Mismatch
                        | LiveEffectObservation::Unknown => RecoveryObservation::Conflict,
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        Ok(self)
    }

    pub(crate) fn persist(&self) -> Result<(), String> {
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
                addresses: self.addresses.clone(),
                effect_receipts: self.effect_receipts.clone(),
                quarantined: self.quarantined.clone(),
                overlay_intents: self.overlay_intents.clone(),
            })
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(temporary, path).map_err(|error| error.to_string())
    }
}
