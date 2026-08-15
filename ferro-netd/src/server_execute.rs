use crate::protocol::{NetdRequest, NetdResponse, RejectionCode};
pub use crate::server_config::NetdServer;
use crate::server_grants::reject;
use ferro_net::{
    bridge::build_ip_link_set_master_cmd,
    veth::{VethConfig, VethPair},
};
impl NetdServer {
    pub fn handle_peer(&mut self, uid: u32, frame: &[u8], now: u64) -> NetdResponse {
        let dispatch = match self.prepare_dispatch(uid, frame, now) {
            Ok(value) => value,
            Err(response) => return response,
        };
        let envelope = dispatch.envelope;
        let effect_receipt = dispatch.receipt;
        let request_id = dispatch.request_id;
        let operation_id = dispatch.operation_id;
        let nonce = dispatch.nonce;
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
        macro_rules! checkpoint {
            ($identity:expr, $phase:expr) => {
                if self.mark_overlay_intent($identity, $phase).is_err() {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist mutation phase",
                        $identity.to_string()
                    );
                }
            };
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
                    checkpoint!(&identity, "bridge_created");
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
                        checkpoint!(&identity, "wireguard_configured");
                        if self.kernel.ensure_forwarding().is_err() {
                            reject_effect!(
                                RejectionCode::Busy,
                                "failed to enable routed overlay forwarding",
                                identity.clone()
                            );
                        }
                        checkpoint!(&identity, "forwarding_enabled");
                        interfaces.wireguard.as_str()
                    }
                    crate::protocol::OverlayMode::BridgeOnly => interfaces.bridge.as_str(),
                };
                for (index, address) in addresses.iter().enumerate() {
                    if self
                        .kernel
                        .apply_addresses(&interfaces.bridge, std::slice::from_ref(address))
                        .is_err()
                    {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to apply bridge gateway address",
                            identity.clone()
                        );
                    }
                    checkpoint!(&identity, &format!("address_applied:{index}"));
                }
                for (index, route) in routes.iter().enumerate() {
                    if self
                        .kernel
                        .apply_routes(route_interface, std::slice::from_ref(route))
                        .is_err()
                    {
                        self.policy
                            .rollback(&overlay_id, envelope.epoch, envelope.revision);
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to apply overlay route",
                            identity.clone()
                        );
                    }
                    checkpoint!(&identity, &format!("route_applied:{index}"));
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
                    for (index, route) in obsolete.iter().enumerate() {
                        if self
                            .kernel
                            .remove_routes(previous_interface, std::slice::from_ref(route))
                            .is_err()
                        {
                            reject_effect!(
                                RejectionCode::Busy,
                                "failed to remove obsolete overlay route",
                                identity.clone()
                            );
                        }
                        checkpoint!(&identity, &format!("stale_route_removed:{index}"));
                    }
                }
                let obsolete_addresses = previous_addresses
                    .iter()
                    .filter(|address| !addresses.contains(address))
                    .cloned()
                    .collect::<Vec<_>>();
                for (index, address) in obsolete_addresses.iter().enumerate() {
                    if self
                        .kernel
                        .remove_addresses(&interfaces.bridge, std::slice::from_ref(address))
                        .is_err()
                    {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to remove obsolete bridge address",
                            identity.clone()
                        );
                    }
                    checkpoint!(&identity, &format!("stale_address_removed:{index}"));
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
                if previous_receipt
                    .as_ref()
                    .and_then(|receipt| receipt.overlay_mode())
                    == Some(crate::protocol::OverlayMode::WireGuard)
                    && mode == crate::protocol::OverlayMode::BridgeOnly
                {
                    checkpoint!(&identity, "stale_wireguard_removed");
                }
                self.overlays.insert(overlay_id.clone());
                self.routes.insert(overlay_id.clone(), routes);
                self.addresses.insert(overlay_id.clone(), addresses);
                self.effect_receipts
                    .insert(identity.clone(), effect_receipt.clone());
                if let Some(intent) = self.overlay_intents.get_mut(&identity) {
                    intent.phase = "succeeded".into();
                }
                if self.persist_ownership().is_err() {
                    self.policy
                        .rollback(&overlay_id, envelope.epoch, envelope.revision);
                    self.quarantined.insert(format!("ambiguous-{identity}"));
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
                            .unwrap_or(&interfaces.wireguard)
                            .to_string();
                        for (index, route) in routes.clone().iter().enumerate() {
                            if self
                                .kernel
                                .remove_routes(&route_interface, std::slice::from_ref(route))
                                .is_err()
                            {
                                reject_effect!(
                                    RejectionCode::Busy,
                                    "failed to remove overlay route",
                                    identity.clone()
                                );
                            }
                            checkpoint!(&identity, &format!("route_removed:{index}"));
                        }
                    }
                    if let Some(addresses) = self.addresses.get(&overlay_id) {
                        for (index, address) in addresses.clone().iter().enumerate() {
                            if self
                                .kernel
                                .remove_addresses(&interfaces.bridge, std::slice::from_ref(address))
                                .is_err()
                            {
                                reject_effect!(
                                    RejectionCode::Busy,
                                    "failed to remove bridge address",
                                    identity.clone()
                                );
                            }
                            checkpoint!(&identity, &format!("address_removed:{index}"));
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
                    if !self.kernel.observe_link(&interfaces.wireguard) {
                        checkpoint!(&identity, "wireguard_removed");
                    }
                    if self.kernel.remove_overlay(&interfaces.bridge).is_err() {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to remove overlay bridge",
                            format!("overlay:{overlay_id}")
                        );
                    }
                    checkpoint!(&identity, "bridge_removed");
                    self.routes.remove(&overlay_id);
                    self.addresses.remove(&overlay_id);
                    self.overlays.remove(&overlay_id);
                }
                self.effect_receipts.remove(&identity);
                if let Some(intent) = self.overlay_intents.get_mut(&identity) {
                    intent.phase = "succeeded".into();
                }
                if self.persist_ownership().is_err() {
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
                let identity = format!("endpoint:{endpoint_id}");
                if self
                    .begin_overlay_intent(
                        operation_id,
                        "attach",
                        effect_receipt.clone(),
                        vec![],
                        vec![],
                    )
                    .is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist endpoint mutation intent",
                        identity.clone()
                    );
                }
                effect_started = true;
                if self.kernel.create_endpoint(&config).is_err() {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to create endpoint veth",
                        format!("endpoint:{endpoint_id}")
                    );
                }
                checkpoint!(&identity, "endpoint_link_created");
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
                checkpoint!(&identity, "endpoint_master_set");
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
                    checkpoint!(&identity, "endpoint_netns_moved");
                }
                self.endpoints.insert(endpoint_id.clone(), overlay_id);
                self.effect_receipts
                    .insert(format!("endpoint:{endpoint_id}"), effect_receipt.clone());
                if let Some(intent) = self.overlay_intents.get_mut(&identity) {
                    intent.phase = "succeeded".into();
                }
                if self.persist_ownership().is_err() {
                    self.quarantined.insert(format!("ambiguous-{identity}"));
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
                let identity = format!("endpoint:{endpoint_id}");
                if self
                    .begin_overlay_intent(
                        operation_id,
                        "detach",
                        effect_receipt.clone(),
                        vec![],
                        vec![],
                    )
                    .is_err()
                {
                    reject_effect!(
                        RejectionCode::Busy,
                        "failed to persist endpoint deletion intent",
                        identity.clone()
                    );
                }
                if self.endpoints.contains_key(&endpoint_id) {
                    effect_started = true;
                    if self.kernel.remove_endpoint(&endpoint_id).is_err() {
                        reject_effect!(
                            RejectionCode::Busy,
                            "failed to destroy endpoint veth",
                            format!("endpoint:{endpoint_id}")
                        );
                    }
                    checkpoint!(&identity, "endpoint_link_removed");
                    self.endpoints.remove(&endpoint_id);
                }
                self.effect_receipts
                    .remove(&format!("endpoint:{endpoint_id}"));
                if let Some(intent) = self.overlay_intents.get_mut(&identity) {
                    intent.phase = "succeeded".into();
                }
                if self.persist_ownership().is_err() {
                    self.quarantined.insert(format!("ambiguous-{identity}"));
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
