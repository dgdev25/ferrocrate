use crate::protocol::{GrantedEnvelope, NetdRequest, NetdResponse, RejectionCode, SignedEnvelope};
use crate::request_binding::{request_overlay_id, request_parameters};
pub use crate::server_config::NetdServer;
use crate::server_grants::reject;
use ferro_net::{
    bridge::build_ip_link_set_master_cmd,
    veth::{VethConfig, VethPair},
};
impl NetdServer {
    pub fn handle_peer(&mut self, uid: u32, frame: &[u8], now: u64) -> NetdResponse {
        if let Err(response) = self.validate_frame(uid, frame) {
            return response;
        }
        if let Some(response) = self.try_legacy_frame(&frame[4..], now) {
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
        if !self.validate_granted_handshake(&granted.handshake) {
            return reject(
                RejectionCode::PolicyViolation,
                "authorization service identity mismatch",
            );
        }
        let envelope = granted.envelope;
        if let Err(code) = self.policy.validate(&envelope, now) {
            return reject(code, "policy rejected request");
        }
        let (action, params) = match request_parameters(&envelope.request) {
            Ok(value) => value,
            Err(code) => return reject(code, "invalid normalized parameters"),
        };
        if self.request_is_quarantined(&envelope.request) {
            self.policy.rollback(
                request_overlay_id(&envelope.request),
                envelope.epoch,
                envelope.revision,
            );
            return reject(
                RejectionCode::PolicyViolation,
                "resource has unverifiable legacy ownership and requires operator reconciliation",
            );
        }
        let effect_receipt = crate::effect_receipt::EffectReceipt::from_request(
            &envelope.request,
            granted.resource_generation,
            envelope.epoch,
            envelope.revision,
        );
        if let Err(code) = self.consume_grant(
            &granted.grant,
            action,
            &granted.resource_uuid,
            granted.resource_generation,
            &params,
            effect_receipt.clone(),
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
        let operation_id = granted.grant.claims.operation_id;
        let nonce = granted.grant.claims.nonce;
        let mut effect_started = false;
        macro_rules! reject_effect {
            ($code:expr, $reason:expr, $identity:expr) => {{
                let failed_identity = $identity;
                let recorded = if effect_started {
                    let _ = self.mark_overlay_intent(&failed_identity, "outcome_unknown");
                    self.record_grant_unknown(nonce, failed_identity, effect_receipt.clone())
                } else {
                    self.record_grant_failure(&request_id, nonce, failed_identity, $reason)
                };
                if recorded.is_err() {
                    return reject(RejectionCode::Busy, "failure witness unavailable");
                }
                return reject($code, $reason);
            }};
        }
        match envelope.request {
            NetdRequest::ApplyOverlay {
                overlay_id,
                mode,
                peers,
                routes,
                addresses,
            } => {
                let interfaces = crate::interface_identity::overlay_interfaces(&overlay_id);
                let created_bridge = !self.overlays.contains(&overlay_id);
                let identity = format!("overlay:{overlay_id}");
                let previous_routes = self.routes.get(&overlay_id).cloned().unwrap_or_default();
                let previous_addresses =
                    self.addresses.get(&overlay_id).cloned().unwrap_or_default();
                let previous_receipt = self.effect_receipts.get(&identity).cloned();
                let previous_interface = previous_receipt
                    .as_ref()
                    .and_then(crate::effect_receipt::EffectReceipt::route_interface)
                    .map(str::to_owned);
                if self
                    .begin_overlay_intent(
                        operation_id,
                        "apply",
                        effect_receipt.clone(),
                        routes.clone(),
                        addresses.clone(),
                    )
                    .is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist overlay mutation intent",
                        identity.clone()
                    );
                }
                effect_started = true;
                if created_bridge {
                    if self.kernel.create_overlay(&interfaces.bridge).is_err() {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to create overlay bridge",
                            format!("overlay:{overlay_id}")
                        );
                    }
                }
                let route_interface = match mode {
                    crate::protocol::OverlayMode::WireGuard => {
                        if self
                            .kernel
                            .apply_wireguard(&interfaces.wireguard, &[], &peers)
                            .is_err()
                        {
                            if created_bridge {
                                let _ = self.kernel.remove_overlay(&interfaces.bridge);
                            }
                            reject_effect!(
                                RejectionCode::Busy,
                                "failed to apply required WireGuard overlay",
                                format!("overlay:{overlay_id}")
                            );
                        }
                        if self.kernel.ensure_forwarding().is_err() {
                            reject_effect!(
                                RejectionCode::Busy,
                                "failed to enable routed overlay forwarding",
                                identity.clone()
                            );
                        }
                        interfaces.wireguard.as_str()
                    }
                    crate::protocol::OverlayMode::BridgeOnly => interfaces.bridge.as_str(),
                };
                if self
                    .kernel
                    .apply_addresses(&interfaces.bridge, &addresses)
                    .is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to apply bridge gateway addresses",
                        identity.clone()
                    );
                }
                if self.kernel.apply_routes(route_interface, &routes).is_err() {
                    self.policy
                        .rollback(&overlay_id, envelope.epoch, envelope.revision);
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to apply overlay routes",
                        format!("overlay:{overlay_id}")
                    );
                }
                if let Some(previous_interface) = previous_interface.as_deref() {
                    let obsolete = if previous_interface == route_interface {
                        previous_routes
                            .iter()
                            .filter(|route| !routes.contains(route))
                            .cloned()
                            .collect::<Vec<_>>()
                    } else {
                        previous_routes.clone()
                    };
                    if self
                        .kernel
                        .remove_routes(previous_interface, &obsolete)
                        .is_err()
                    {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to remove obsolete overlay routes",
                            identity.clone()
                        );
                    }
                }
                let obsolete_addresses = previous_addresses
                    .iter()
                    .filter(|address| !addresses.contains(address))
                    .cloned()
                    .collect::<Vec<_>>();
                if self
                    .kernel
                    .remove_addresses(&interfaces.bridge, &obsolete_addresses)
                    .is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to remove obsolete bridge addresses",
                        identity.clone()
                    );
                }
                if previous_receipt
                    .as_ref()
                    .and_then(|receipt| receipt.overlay_mode())
                    == Some(crate::protocol::OverlayMode::WireGuard)
                    && mode == crate::protocol::OverlayMode::BridgeOnly
                    && self.kernel.remove_wireguard(&interfaces.wireguard).is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to remove obsolete WireGuard overlay",
                        identity.clone()
                    );
                }
                self.overlays.insert(overlay_id.clone());
                self.routes.insert(overlay_id.clone(), routes);
                self.addresses.insert(overlay_id.clone(), addresses);
                self.effect_receipts
                    .insert(identity.clone(), effect_receipt.clone());
                if let Some(intent) = self.overlay_intents.get_mut(&identity) {
                    intent.phase = "succeeded".into();
                }
                if self.persist().is_err() {
                    self.policy
                        .rollback(&overlay_id, envelope.epoch, envelope.revision);
                    if created_bridge {
                        self.overlays.remove(&overlay_id);
                        self.routes.remove(&overlay_id);
                        self.addresses.remove(&overlay_id);
                        self.effect_receipts.remove(&identity);
                        if mode == crate::protocol::OverlayMode::WireGuard {
                            let _ = self.kernel.remove_wireguard(&interfaces.wireguard);
                        }
                        let _ = self.kernel.remove_overlay(&interfaces.bridge);
                    } else {
                        self.overlays.insert(overlay_id.clone());
                        self.routes.insert(overlay_id.clone(), previous_routes);
                        self.addresses
                            .insert(overlay_id.clone(), previous_addresses);
                        if let Some(previous) = previous_receipt {
                            self.effect_receipts.insert(identity.clone(), previous);
                        }
                        self.quarantined.insert(format!("ambiguous-{identity}"));
                    }
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
                let interfaces = crate::interface_identity::overlay_interfaces(&overlay_id);
                let identity = format!("overlay:{overlay_id}");
                let owned_routes = self.routes.get(&overlay_id).cloned();
                let owned_addresses = self.addresses.get(&overlay_id).cloned();
                let owned_receipt = self.effect_receipts.get(&identity).cloned();
                let was_owned = self.overlays.contains(&overlay_id);
                if self
                    .begin_overlay_intent(
                        operation_id,
                        "remove",
                        effect_receipt.clone(),
                        vec![],
                        vec![],
                    )
                    .is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist overlay deletion intent",
                        identity.clone()
                    );
                }
                if was_owned {
                    effect_started = true;
                    if let Some(routes) = self.routes.get(&overlay_id) {
                        let route_interface = self
                            .effect_receipts
                            .get(&format!("overlay:{overlay_id}"))
                            .and_then(crate::effect_receipt::EffectReceipt::route_interface)
                            .unwrap_or(&interfaces.wireguard);
                        if self.kernel.remove_routes(route_interface, routes).is_err() {
                            reject_effect!(
                                RejectionCode::Busy,
                                "failed to remove overlay routes",
                                format!("overlay:{overlay_id}")
                            );
                        }
                    }
                    if let Some(addresses) = self.addresses.get(&overlay_id) {
                        if self
                            .kernel
                            .remove_addresses(&interfaces.bridge, addresses)
                            .is_err()
                        {
                            reject_effect!(
                                RejectionCode::Busy,
                                "failed to remove bridge addresses",
                                format!("overlay:{overlay_id}")
                            );
                        }
                    }
                    if self.kernel.observe_link(&interfaces.wireguard)
                        && self.kernel.remove_wireguard(&interfaces.wireguard).is_err()
                    {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to remove WireGuard overlay",
                            format!("overlay:{overlay_id}")
                        );
                    }
                    if self.kernel.remove_overlay(&interfaces.bridge).is_err() {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to remove overlay bridge",
                            format!("overlay:{overlay_id}")
                        );
                    }
                    self.routes.remove(&overlay_id);
                    self.addresses.remove(&overlay_id);
                    self.overlays.remove(&overlay_id);
                }
                self.effect_receipts.remove(&identity);
                if let Some(intent) = self.overlay_intents.get_mut(&identity) {
                    intent.phase = "succeeded".into();
                }
                if self.persist().is_err() {
                    if was_owned {
                        self.overlays.insert(overlay_id.clone());
                    }
                    if let Some(routes) = owned_routes {
                        self.routes.insert(overlay_id.clone(), routes);
                    }
                    if let Some(addresses) = owned_addresses {
                        self.addresses.insert(overlay_id.clone(), addresses);
                    }
                    if let Some(receipt) = owned_receipt {
                        self.effect_receipts.insert(identity.clone(), receipt);
                    }
                    self.quarantined.insert(format!("ambiguous-{identity}"));
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
                    let stored_receipt =
                        self.effect_receipts.get(&format!("endpoint:{endpoint_id}"));
                    if existing_overlay != &overlay_id
                        || stored_receipt != Some(&effect_receipt)
                        || self.kernel.observe_effect(&effect_receipt)
                            != crate::kernel_ops::LiveEffectObservation::Exact
                    {
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
                let bridge = crate::interface_identity::overlay_interfaces(&overlay_id).bridge;
                let config = VethConfig {
                    pair: VethPair {
                        host: endpoint_id.clone(),
                        container,
                    },
                    mtu: None,
                    host_addr: None,
                    container_addr: None,
                };
                effect_started = true;
                if self.kernel.create_endpoint(&config).is_err() {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to create endpoint veth",
                        format!("endpoint:{endpoint_id}")
                    );
                }
                if build_ip_link_set_master_cmd(&endpoint_id, &bridge).is_err() {
                    let _ = self.kernel.remove_endpoint(&endpoint_id);
                    reject_effect!(
                        RejectionCode::PolicyViolation,
                        "invalid endpoint interface",
                        format!("endpoint:{endpoint_id}")
                    );
                }
                if self.kernel.attach_endpoint(&endpoint_id, &bridge).is_err() {
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
                self.effect_receipts
                    .insert(format!("endpoint:{endpoint_id}"), effect_receipt.clone());
                if self.persist().is_err() {
                    let _ = self.endpoints.remove(&endpoint_id);
                    self.effect_receipts
                        .remove(&format!("endpoint:{endpoint_id}"));
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
                if self.endpoints.contains_key(&endpoint_id) {
                    effect_started = true;
                    if self.kernel.remove_endpoint(&endpoint_id).is_err() {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to destroy endpoint veth",
                            format!("endpoint:{endpoint_id}")
                        );
                    }
                    self.endpoints.remove(&endpoint_id);
                }
                self.effect_receipts
                    .remove(&format!("endpoint:{endpoint_id}"));
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
                self.finish_inspect(&request_id, nonce, overlay_id, envelope.revision)
            }
        }
    }
}
