use crate::kernel_ops::LiveEffectObservation;
use crate::{grants_recovery::RecoveryObservation, server::NetdServer};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::PathBuf};

#[cfg(test)]
mod intent_tests {
    use super::*;
    use crate::{
        policy::Policy,
        protocol::{NetdRequest, OverlayMode},
    };

    #[test]
    fn phase_persist_fault_reopens_to_exact_desired_state() {
        let directory = tempfile::tempdir().unwrap();
        let kernel_path = directory.path().join("kernel.json");
        let journal = directory.path().join("ownership.json");
        let faults = crate::test_support::FaultHandle::default();
        let mut server = NetdServer::deterministic_with_faults(
            1,
            Policy::new(
                "c".into(),
                "n".into(),
                &base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
            )
            .unwrap(),
            kernel_path.clone(),
            faults.clone(),
        )
        .load_journal(journal.clone())
        .unwrap();
        let request = NetdRequest::ApplyOverlay {
            overlay_id: "overlay-a".into(),
            mode: OverlayMode::BridgeOnly,
            peers: vec![],
            routes: vec![],
            addresses: vec![],
        };
        let receipt = crate::effect_receipt::EffectReceipt::from_request(&request, 1, 1, 1);
        server
            .begin_overlay_intent([1; 16], "apply", receipt, vec![], vec![])
            .unwrap();
        let bridge = crate::interface_identity::overlay_interfaces("overlay-a").bridge;
        server.kernel.create_overlay(&bridge).unwrap();
        for phase in [
            "bridge_created",
            "wireguard_configured",
            "forwarding_enabled",
            "address_applied:0",
            "route_applied:0",
            "stale_route_removed:0",
            "stale_address_removed:0",
            "stale_wireguard_removed",
            "route_removed:0",
            "address_removed:0",
            "wireguard_removed",
            "bridge_removed",
            "endpoint_link_created",
            "endpoint_master_set",
            "endpoint_netns_moved",
            "endpoint_link_removed",
        ] {
            faults.fail_phase_once(phase);
            assert!(server
                .mark_overlay_intent("overlay:overlay-a", phase)
                .is_err());
        }
        drop(server);
        let reopened = NetdServer::deterministic(
            1,
            Policy::new(
                "c".into(),
                "n".into(),
                &base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
            )
            .unwrap(),
            kernel_path,
        )
        .load_journal(journal)
        .unwrap();
        assert!(reopened.overlays.contains("overlay-a"));
        assert_eq!(
            reopened.overlay_intents["overlay:overlay-a"].phase,
            "recovered"
        );
    }

    #[test]
    fn unresolved_intent_blocks_same_process_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let mut server = NetdServer::deterministic(
            1,
            Policy::new(
                "c".into(),
                "n".into(),
                &base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
            )
            .unwrap(),
            directory.path().join("kernel.json"),
        )
        .load_journal(directory.path().join("ownership.json"))
        .unwrap();
        let request = NetdRequest::ApplyOverlay {
            overlay_id: "overlay-a".into(),
            mode: OverlayMode::BridgeOnly,
            peers: vec![],
            routes: vec![],
            addresses: vec![],
        };
        server
            .begin_overlay_intent(
                [1; 16],
                "apply",
                crate::effect_receipt::EffectReceipt::from_request(&request, 1, 1, 1),
                vec![],
                vec![],
            )
            .unwrap();
        server
            .mark_overlay_intent("overlay:overlay-a", "outcome_unknown")
            .unwrap();

        assert!(server.request_is_quarantined(&request));
        assert!(server.overlay_is_quarantined("overlay-a"));
    }
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
    #[serde(default)]
    pub(crate) observed_phases: Vec<String>,
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
        let previous = self.overlay_intents.insert(
            identity.clone(),
            OverlayMutationIntent {
                operation_id,
                action: action.into(),
                prior: self.effect_receipts.get(&identity).cloned(),
                desired,
                phase: "pending".into(),
                routes,
                addresses,
                observed_phases: Vec::new(),
            },
        );
        if let Err(error) = self.persist() {
            match previous {
                Some(previous) => {
                    self.overlay_intents.insert(identity, previous);
                }
                None => {
                    self.overlay_intents.remove(&identity);
                }
            }
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn mark_overlay_intent(
        &mut self,
        identity: &str,
        phase: &str,
    ) -> Result<(), String> {
        #[cfg(any(test, feature = "test-support"))]
        if self
            .test_faults
            .take(crate::test_support::FaultPoint::PhasePersist(phase.into()))
        {
            return Err("injected mutation phase persistence failure".into());
        }
        if let Some(intent) = self.overlay_intents.get_mut(identity) {
            intent.phase = phase.into();
            intent.observed_phases.push(phase.into());
        }
        self.persist()
    }
    pub(crate) fn persist_ownership(&mut self) -> Result<(), String> {
        #[cfg(any(test, feature = "test-support"))]
        if self
            .test_faults
            .take(crate::test_support::FaultPoint::OwnershipPersist)
        {
            return Err("injected ownership persistence failure".into());
        }
        self.persist()
    }
    pub(crate) fn request_is_quarantined(&self, request: &crate::protocol::NetdRequest) -> bool {
        self.overlay_is_quarantined(crate::request_binding::request_overlay_id(request))
            || match request {
                crate::protocol::NetdRequest::AttachEndpoint { endpoint_id, .. }
                | crate::protocol::NetdRequest::DetachEndpoint { endpoint_id, .. } => {
                    let identity = format!("endpoint:{endpoint_id}");
                    self.quarantined
                        .iter()
                        .any(|entry| entry.ends_with(&identity))
                        || self.intent_is_unresolved(&identity)
                }
                _ => false,
            }
    }
    pub(crate) fn overlay_is_quarantined(&self, overlay: &str) -> bool {
        let suffix = format!("overlay:{overlay}");
        self.quarantined
            .iter()
            .any(|entry| entry.ends_with(&suffix))
            || self.intent_is_unresolved(&suffix)
    }
    fn intent_is_unresolved(&self, identity: &str) -> bool {
        self.overlay_intents.get(identity).is_some_and(|intent| {
            !matches!(
                intent.phase.as_str(),
                "succeeded" | "recovered" | "not_applied"
            )
        })
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
        use fs2::FileExt;
        let lock_path = path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|error| error.to_string())?;
        lock.try_lock_exclusive()
            .map_err(|_| "ownership journal already has a writer".to_string())?;
        self.journal_lock = Some(lock);
        #[cfg(any(test, feature = "test-support"))]
        let faults = self.test_faults.clone();
        let loaded = crate::ownership_journal::load(&path, |phase| {
            #[cfg(any(test, feature = "test-support"))]
            if faults.take(crate::test_support::FaultPoint::JournalPersist(
                phase.into(),
            )) {
                return Err(format!("injected journal {phase} failure"));
            }
            Ok(())
        })?;
        self.journal_id = loaded.journal_id;
        self.journal_generation = loaded.generation;
        if let Some(state) = loaded.state {
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
            let endpoint = identity.strip_prefix("endpoint:").map(str::to_owned);
            match self.kernel.observe_effect(&intent.desired) {
                LiveEffectObservation::Exact => {
                    self.quarantined.retain(|entry| !entry.ends_with(&identity));
                    if intent.desired.expected_exists() {
                        if let Some(endpoint) = endpoint.as_ref() {
                            if let Some(parent) = intent.desired.endpoint_overlay() {
                                self.endpoints.insert(endpoint.clone(), parent.into());
                            }
                        } else {
                            self.overlays.insert(overlay.clone());
                            self.routes.insert(overlay.clone(), intent.routes);
                            self.addresses.insert(overlay, intent.addresses);
                        }
                        self.effect_receipts
                            .insert(identity.clone(), intent.desired);
                    } else {
                        if let Some(endpoint) = endpoint.as_ref() {
                            self.endpoints.remove(endpoint);
                        }
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
                        if let Some(endpoint) = endpoint {
                            if let Some(parent) = prior.endpoint_overlay() {
                                self.endpoints.insert(endpoint, parent.into());
                            }
                        } else {
                            self.overlays.insert(overlay);
                        }
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

    pub(crate) fn persist(&mut self) -> Result<(), String> {
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
        let generation = self
            .journal_generation
            .checked_add(1)
            .ok_or("ownership journal generation exhausted")?;
        crate::ownership_journal::store(
            path,
            self.journal_id,
            generation,
            &crate::ownership_journal::PersistedState {
                overlays: self.overlays.clone(),
                endpoints: self.endpoints.clone(),
                routes: self.routes.clone(),
                addresses: self.addresses.clone(),
                effect_receipts: self.effect_receipts.clone(),
                quarantined: self.quarantined.clone(),
                overlay_intents: self.overlay_intents.clone(),
            },
            |phase| {
                #[cfg(any(test, feature = "test-support"))]
                if self
                    .test_faults
                    .take(crate::test_support::FaultPoint::JournalPersist(
                        phase.into(),
                    ))
                {
                    return Err(format!("injected journal {phase} failure"));
                }
                Ok(())
            },
        )?;
        self.journal_generation = generation;
        Ok(())
    }
}
