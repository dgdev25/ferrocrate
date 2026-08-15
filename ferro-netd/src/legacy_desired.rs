use crate::{
    effect_receipt::EffectReceipt,
    protocol::{DesiredStateEnvelope, NetdRequest, NetdResponse, PeerSpec, RejectionCode},
    server::NetdServer,
};
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
            self.kernel
                .remove_wireguard(&overlay)
                .map_err(|_| RejectionCode::Busy)?;
            if let Some(routes) = self.routes.remove(&overlay) {
                self.kernel
                    .remove_routes(&overlay, &routes)
                    .map_err(|_| RejectionCode::Busy)?;
            }
            self.kernel
                .remove_overlay(&overlay)
                .map_err(|_| RejectionCode::Busy)?;
            self.overlays.remove(&overlay);
            self.effect_receipts.remove(&format!("overlay:{overlay}"));
        }
        for overlay in desired.overlays {
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
                peers: peers.clone(),
                routes: overlay.routes.clone(),
                addresses: Vec::new(),
            };
            self.kernel
                .apply_wireguard(&overlay.overlay_id, &[], &peers)
                .map_err(|_| RejectionCode::Busy)?;
            if !self.kernel.observe_link(&overlay.overlay_id) {
                self.kernel
                    .create_overlay(&overlay.overlay_id)
                    .map_err(|_| RejectionCode::Busy)?;
            }
            self.kernel
                .apply_routes(&overlay.overlay_id, &overlay.routes)
                .map_err(|_| RejectionCode::Busy)?;
            self.overlays.insert(overlay.overlay_id.clone());
            self.routes
                .insert(overlay.overlay_id.clone(), overlay.routes);
            self.effect_receipts.insert(
                format!("overlay:{}", overlay.overlay_id),
                EffectReceipt::from_request(
                    &request,
                    envelope.revision,
                    envelope.epoch,
                    envelope.revision,
                ),
            );
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
            1,
            vec![OverlayState {
                overlay_id: "wg0".into(),
                routes: Vec::new(),
                peers: Vec::new(),
            }],
        );
        assert_eq!(send(&mut server, &key, apply), NetdResponse::Applied);
        assert!(server.overlays.contains("wg0"));
        assert_eq!(
            send(&mut server, &key, desired(2, Vec::new())),
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
