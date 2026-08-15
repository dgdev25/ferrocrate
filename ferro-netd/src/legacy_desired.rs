use crate::{
    effect_receipt::EffectReceipt,
    protocol::{DesiredStateEnvelope, NetdRequest, NetdResponse, PeerSpec, RejectionCode},
    server::NetdServer,
};
use ferro_core::authorization::{AuthorizationMode, AuthorizationServiceMode};
use prost::Message;
use std::collections::BTreeSet;

#[derive(Clone, PartialEq, Message)]
struct DesiredState {
    #[prost(string, tag = "1")]
    cluster_id: String,
    #[prost(uint64, tag = "2")]
    cluster_epoch: u64,
    #[prost(uint64, tag = "3")]
    revision: u64,
    #[prost(message, repeated, tag = "4")]
    overlays: Vec<OverlayState>,
    #[prost(bytes, tag = "5")]
    signature: Vec<u8>,
    #[prost(int64, tag = "6")]
    lease_expires_unix: i64,
}

#[derive(Clone, PartialEq, Message)]
struct OverlayState {
    #[prost(string, tag = "1")]
    overlay_id: String,
    #[prost(string, repeated, tag = "2")]
    routes: Vec<String>,
    #[prost(message, repeated, tag = "3")]
    peers: Vec<Peer>,
    #[prost(bool, optional, tag = "4")]
    wireguard: Option<bool>,
    #[prost(string, repeated, tag = "5")]
    addresses: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct Peer {
    #[prost(string, tag = "1")]
    node_id: String,
    #[prost(bytes, tag = "2")]
    public_key: Vec<u8>,
    #[prost(string, tag = "3")]
    endpoint: String,
    #[prost(string, repeated, tag = "4")]
    allowed_ips: Vec<String>,
}

impl NetdServer {
    pub(crate) fn try_legacy_frame(&mut self, bytes: &[u8], now: u64) -> Option<NetdResponse> {
        if serde_json::from_slice::<crate::protocol::GrantedDesiredStateEnvelope>(bytes).is_ok() {
            return Some(crate::server_grants::reject(RejectionCode::PolicyViolation,
                "bulk desired-state grants are forbidden; submit one authorized mutation per resource"));
        }
        let desired = serde_json::from_slice::<DesiredStateEnvelope>(bytes).ok()?;
        let Some((expected, boot)) = &self.authorization_identity else {
            return Some(crate::server_grants::reject(
                RejectionCode::PolicyViolation,
                "service mode is not configured",
            ));
        };
        let peer = AuthorizationServiceMode::parse(
            &desired.handshake.mode,
            desired.handshake.policy_digest,
        )
        .ok();
        if expected.mode() != AuthorizationMode::Disabled
            || peer.is_none_or(|peer| expected.require_match(peer).is_err())
            || desired.handshake.instance_boot != *boot
        {
            return Some(crate::server_grants::reject(
                RejectionCode::PolicyViolation,
                "legacy desired state is available only on matching disabled service",
            ));
        }
        if let Err(code) = self.policy.validate_desired(&desired, now) {
            return Some(crate::server_grants::reject(
                code,
                "legacy desired signature or revision rejected",
            ));
        }
        Some(self.apply_legacy_desired(&desired).unwrap_or_else(|code| {
            crate::server_grants::reject(code, "legacy desired mutation failed")
        }))
    }

    pub(crate) fn apply_legacy_desired(
        &mut self,
        envelope: &DesiredStateEnvelope,
    ) -> Result<NetdResponse, RejectionCode> {
        let desired = DesiredState::decode(envelope.desired_state.as_slice())
            .map_err(|_| RejectionCode::InvalidFrame)?;
        if desired.cluster_id != envelope.cluster_id
            || desired.cluster_epoch != envelope.epoch
            || desired.revision != envelope.revision
            || desired.lease_expires_unix.max(0) as u64 != envelope.lease_expires_unix_secs
        {
            return Err(RejectionCode::PolicyViolation);
        }
        if desired
            .overlays
            .iter()
            .any(|overlay| overlay.wireguard.is_none())
        {
            return Err(RejectionCode::InvalidFrame);
        }
        if desired
            .overlays
            .iter()
            .any(|overlay| self.overlay_is_quarantined(&overlay.overlay_id))
        {
            return Err(RejectionCode::PolicyViolation);
        }
        let wanted = desired
            .overlays
            .iter()
            .map(|overlay| overlay.overlay_id.clone())
            .collect::<BTreeSet<_>>();
        for overlay in self
            .overlays
            .difference(&wanted)
            .cloned()
            .collect::<Vec<_>>()
        {
            let interfaces = crate::interface_identity::overlay_interfaces(&overlay);
            let delete_request = NetdRequest::RemoveOverlay {
                overlay_id: overlay.clone(),
            };
            let delete_receipt = EffectReceipt::from_request(
                &delete_request,
                envelope.revision,
                envelope.epoch,
                envelope.revision,
            );
            let mut operation_id = [0_u8; 16];
            operation_id[..8].copy_from_slice(&envelope.revision.to_be_bytes());
            self.begin_overlay_intent(
                operation_id,
                "legacy_remove",
                delete_receipt,
                vec![],
                vec![],
            )
            .map_err(|_| RejectionCode::Busy)?;
            if let Some(routes) = self.routes.get(&overlay) {
                let route_interface = self
                    .effect_receipts
                    .get(&format!("overlay:{overlay}"))
                    .and_then(EffectReceipt::route_interface)
                    .unwrap_or(&interfaces.wireguard);
                self.kernel
                    .remove_routes(route_interface, &routes)
                    .map_err(|_| RejectionCode::Busy)?;
            }
            if self.kernel.observe_link(&interfaces.wireguard) {
                self.kernel
                    .remove_wireguard(&interfaces.wireguard)
                    .map_err(|_| RejectionCode::Busy)?;
            }
            self.kernel
                .remove_overlay(&interfaces.bridge)
                .map_err(|_| RejectionCode::Busy)?;
            self.overlays.remove(&overlay);
            self.routes.remove(&overlay);
            self.addresses.remove(&overlay);
            self.effect_receipts.remove(&format!("overlay:{overlay}"));
            if let Some(intent) = self.overlay_intents.get_mut(&format!("overlay:{overlay}")) {
                intent.phase = "succeeded".into();
            }
        }
        for overlay in desired.overlays {
            let mode = if overlay.wireguard == Some(true) {
                crate::protocol::OverlayMode::WireGuard
            } else {
                crate::protocol::OverlayMode::BridgeOnly
            };
            let interfaces = crate::interface_identity::overlay_interfaces(&overlay.overlay_id);
            let peers = overlay
                .peers
                .into_iter()
                .map(|peer| PeerSpec {
                    node_id: peer.node_id,
                    public_key: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        peer.public_key,
                    ),
                    endpoint: peer.endpoint,
                    allowed_ips: peer.allowed_ips,
                })
                .collect::<Vec<_>>();
            let request = NetdRequest::ApplyOverlay {
                overlay_id: overlay.overlay_id.clone(),
                mode,
                peers: peers.clone(),
                routes: overlay.routes.clone(),
                addresses: overlay.addresses.clone(),
            };
            let desired_receipt = EffectReceipt::from_request(
                &request,
                envelope.revision,
                envelope.epoch,
                envelope.revision,
            );
            let mut operation_id = [0_u8; 16];
            operation_id[..8].copy_from_slice(&envelope.revision.to_be_bytes());
            self.begin_overlay_intent(
                operation_id,
                "legacy_apply",
                desired_receipt.clone(),
                overlay.routes.clone(),
                overlay.addresses.clone(),
            )
            .map_err(|_| RejectionCode::Busy)?;
            let previous_routes = self
                .routes
                .get(&overlay.overlay_id)
                .cloned()
                .unwrap_or_default();
            let previous_receipt = self
                .effect_receipts
                .get(&format!("overlay:{}", overlay.overlay_id))
                .cloned();
            let previous_route_interface = previous_receipt
                .as_ref()
                .and_then(EffectReceipt::route_interface)
                .map(str::to_owned);
            if !self.kernel.observe_link(&interfaces.bridge) {
                self.kernel
                    .create_overlay(&interfaces.bridge)
                    .map_err(|_| RejectionCode::Busy)?;
            }
            let route_interface = if overlay.wireguard == Some(true) {
                self.kernel
                    .apply_wireguard(&interfaces.wireguard, &[], &peers)
                    .map_err(|_| RejectionCode::Busy)?;
                self.kernel
                    .ensure_forwarding()
                    .map_err(|_| RejectionCode::Busy)?;
                &interfaces.wireguard
            } else {
                &interfaces.bridge
            };
            self.kernel
                .apply_addresses(&interfaces.bridge, &overlay.addresses)
                .map_err(|_| RejectionCode::Busy)?;
            let removed = if previous_route_interface.as_deref() == Some(route_interface) {
                previous_routes
                    .iter()
                    .filter(|route| !overlay.routes.contains(route))
                    .cloned()
                    .collect()
            } else {
                previous_routes
            };
            self.kernel
                .remove_routes(
                    previous_route_interface
                        .as_deref()
                        .unwrap_or(route_interface),
                    &removed,
                )
                .map_err(|_| RejectionCode::Busy)?;
            if previous_receipt
                .as_ref()
                .and_then(EffectReceipt::overlay_mode)
                == Some(crate::protocol::OverlayMode::WireGuard)
                && mode == crate::protocol::OverlayMode::BridgeOnly
            {
                self.kernel
                    .remove_wireguard(&interfaces.wireguard)
                    .map_err(|_| RejectionCode::Busy)?;
            }
            self.kernel
                .apply_routes(route_interface, &overlay.routes)
                .map_err(|_| RejectionCode::Busy)?;
            self.overlays.insert(overlay.overlay_id.clone());
            self.routes
                .insert(overlay.overlay_id.clone(), overlay.routes);
            self.effect_receipts
                .insert(format!("overlay:{}", overlay.overlay_id), desired_receipt);
            if let Some(intent) = self
                .overlay_intents
                .get_mut(&format!("overlay:{}", overlay.overlay_id))
            {
                intent.phase = "succeeded".into();
            }
        }
        self.persist().map_err(|_| RejectionCode::Busy)?;
        Ok(NetdResponse::Applied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{policy::Policy, protocol::ServiceHandshake};
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use ferro_core::authorization::{AuthorizationMode, AuthorizationServiceMode};

    #[test]
    fn disabled_signed_desired_applies_nonempty_then_empty() {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[44; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        let mut server = NetdServer::deterministic(
            1001,
            Policy::new("cluster".into(), "node".into(), &public).unwrap(),
            directory.path().join("kernel.json"),
        )
        .with_authorization_identity(
            AuthorizationServiceMode::new(AuthorizationMode::Disabled, None).unwrap(),
            "boot-a",
        )
        .load_journal(directory.path().join("ownership.json"))
        .unwrap();
        let desired = |revision, overlays| DesiredState {
            cluster_id: "cluster".into(),
            cluster_epoch: 1,
            revision,
            overlays,
            signature: Vec::new(),
            lease_expires_unix: 500,
        };
        let apply = desired(
            2,
            vec![OverlayState {
                overlay_id: "wg0".into(),
                routes: Vec::new(),
                peers: Vec::new(),
                wireguard: Some(true),
                addresses: vec!["10.0.0.1/24".into()],
            }],
        );
        let mut missing_mode = apply.clone();
        missing_mode.revision = 1;
        missing_mode.overlays[0].wireguard = None;
        assert_eq!(
            send(&mut server, &key, missing_mode),
            NetdResponse::Rejected {
                code: RejectionCode::InvalidFrame,
                reason: "legacy desired mutation failed".into(),
            }
        );
        assert_eq!(send(&mut server, &key, apply), NetdResponse::Applied);
        assert!(server.overlays.contains("wg0"));
        assert_eq!(
            send(&mut server, &key, desired(3, Vec::new())),
            NetdResponse::Applied
        );
        assert!(server.overlays.is_empty());
    }

    fn send(server: &mut NetdServer, key: &SigningKey, desired: DesiredState) -> NetdResponse {
        let mut envelope = DesiredStateEnvelope {
            handshake: ServiceHandshake {
                mode: "disabled".into(),
                policy_digest: None,
                instance_boot: "boot-a".into(),
            },
            cluster_id: "cluster".into(),
            node_id: "node".into(),
            epoch: desired.cluster_epoch,
            revision: desired.revision,
            lease_expires_unix_secs: desired.lease_expires_unix as u64,
            desired_state: desired.encode_to_vec(),
            signature: String::new(),
        };
        envelope.signature = base64::engine::general_purpose::STANDARD
            .encode(key.sign(&serde_json::to_vec(&envelope).unwrap()).to_bytes());
        let body = serde_json::to_vec(&envelope).unwrap();
        let mut frame = (body.len() as u32).to_be_bytes().to_vec();
        frame.extend(body);
        server.handle_peer(1001, &frame, 100)
    }
}
