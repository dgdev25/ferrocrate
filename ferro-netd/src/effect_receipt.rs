use crate::protocol::{NetdRequest, OverlayMode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "effect", deny_unknown_fields)]
pub(crate) enum EffectReceipt {
    Overlay {
        overlay_id: String,
        #[serde(default)]
        bridge_ifname: String,
        #[serde(default)]
        wireguard_ifname: Option<String>,
        #[serde(default)]
        mode: OverlayMode,
        #[serde(default = "legacy_true")]
        legacy_identity: bool,
        generation: u64,
        peer_digest: [u8; 32],
        address_digest: [u8; 32],
        route_digest: [u8; 32],
        policy_epoch: u64,
        policy_revision: u64,
        #[serde(default)]
        forwarding_required: bool,
        expected_exists: bool,
    },
    Endpoint {
        endpoint_id: String,
        overlay_id: String,
        generation: u64,
        netns_digest: [u8; 32],
        bridge_master_digest: [u8; 32],
        netns_name: Option<String>,
        netns_inode: Option<u64>,
        expected_exists: bool,
        #[serde(default = "legacy_true")]
        legacy_identity: bool,
    },
}

impl EffectReceipt {
    pub(crate) fn from_request(
        request: &NetdRequest,
        generation: u64,
        epoch: u64,
        revision: u64,
    ) -> Self {
        match request {
            NetdRequest::ApplyOverlay {
                overlay_id,
                mode,
                peers,
                routes,
                addresses,
            } => {
                let interfaces = crate::interface_identity::overlay_interfaces(overlay_id);
                Self::Overlay {
                    overlay_id: overlay_id.clone(),
                    bridge_ifname: interfaces.bridge,
                    wireguard_ifname: Some(interfaces.wireguard),
                    mode: *mode,
                    legacy_identity: false,
                    generation,
                    peer_digest: peer_digest(peers),
                    address_digest: digest_sorted(addresses),
                    route_digest: digest_sorted(routes),
                    policy_epoch: epoch,
                    policy_revision: revision,
                    forwarding_required: *mode == OverlayMode::WireGuard,
                    expected_exists: true,
                }
            }
            NetdRequest::RemoveOverlay { overlay_id } | NetdRequest::Inspect { overlay_id } => {
                let interfaces = crate::interface_identity::overlay_interfaces(overlay_id);
                Self::Overlay {
                    overlay_id: overlay_id.clone(),
                    bridge_ifname: interfaces.bridge,
                    // Deletion proves that neither topology link remains, irrespective of
                    // the mode of the overlay being removed.
                    wireguard_ifname: matches!(request, NetdRequest::RemoveOverlay { .. })
                        .then_some(interfaces.wireguard),
                    mode: OverlayMode::BridgeOnly,
                    legacy_identity: false,
                    generation,
                    peer_digest: [0; 32],
                    address_digest: [0; 32],
                    route_digest: [0; 32],
                    policy_epoch: epoch,
                    policy_revision: revision,
                    forwarding_required: false,
                    expected_exists: !matches!(request, NetdRequest::RemoveOverlay { .. }),
                }
            }
            NetdRequest::AttachEndpoint {
                overlay_id,
                endpoint_id,
                netns,
            } => Self::Endpoint {
                endpoint_id: endpoint_id.clone(),
                overlay_id: overlay_id.clone(),
                generation,
                netns_digest: digest(netns),
                bridge_master_digest: digest(
                    &crate::interface_identity::overlay_interfaces(overlay_id).bridge,
                ),
                netns_name: netns.clone(),
                netns_inode: netns.as_deref().and_then(netns_inode),
                expected_exists: true,
                legacy_identity: false,
            },
            NetdRequest::DetachEndpoint {
                overlay_id,
                endpoint_id,
            } => Self::Endpoint {
                endpoint_id: endpoint_id.clone(),
                overlay_id: overlay_id.clone(),
                generation,
                netns_digest: [0; 32],
                bridge_master_digest: digest(
                    &crate::interface_identity::overlay_interfaces(overlay_id).bridge,
                ),
                netns_name: None,
                netns_inode: None,
                expected_exists: false,
                legacy_identity: false,
            },
        }
    }

    pub(crate) fn route_interface(&self) -> Option<&str> {
        match self {
            Self::Overlay {
                bridge_ifname,
                wireguard_ifname,
                mode,
                ..
            } => Some(match mode {
                OverlayMode::WireGuard => wireguard_ifname.as_deref().unwrap_or(bridge_ifname),
                OverlayMode::BridgeOnly => bridge_ifname,
            }),
            Self::Endpoint { .. } => None,
        }
    }

    pub(crate) const fn overlay_mode(&self) -> Option<OverlayMode> {
        match self {
            Self::Overlay { mode, .. } => Some(*mode),
            Self::Endpoint { .. } => None,
        }
    }
    pub(crate) fn endpoint_overlay(&self) -> Option<&str> {
        match self {
            Self::Endpoint { overlay_id, .. } => Some(overlay_id),
            Self::Overlay { .. } => None,
        }
    }

    pub(crate) const fn is_legacy_identity(&self) -> bool {
        match self {
            Self::Overlay {
                legacy_identity, ..
            }
            | Self::Endpoint {
                legacy_identity, ..
            } => *legacy_identity,
        }
    }

    pub(crate) fn identity(&self) -> String {
        match self {
            Self::Overlay { overlay_id, .. } => format!("overlay:{overlay_id}"),
            Self::Endpoint { endpoint_id, .. } => format!("endpoint:{endpoint_id}"),
        }
    }

    pub(crate) const fn expected_exists(&self) -> bool {
        match self {
            Self::Overlay {
                expected_exists, ..
            }
            | Self::Endpoint {
                expected_exists, ..
            } => *expected_exists,
        }
    }
}

const fn legacy_true() -> bool {
    true
}

pub(crate) fn digest<T: Serialize>(value: &T) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(value).unwrap_or_default()).into()
}

pub(crate) fn peer_digest(peers: &[crate::protocol::PeerSpec]) -> [u8; 32] {
    let mut canonical = peers
        .iter()
        .map(|peer| {
            let mut allowed = peer.allowed_ips.clone();
            allowed.sort();
            (peer.public_key.clone(), peer.endpoint.clone(), allowed)
        })
        .collect::<Vec<_>>();
    canonical.sort();
    digest(&canonical)
}

pub(crate) fn digest_sorted(values: &[String]) -> [u8; 32] {
    let mut canonical = values.to_vec();
    canonical.sort();
    digest(&canonical)
}

fn netns_inode(name: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(format!("/var/run/netns/{name}"))
        .ok()
        .map(|metadata| metadata.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PeerSpec;

    #[test]
    fn partial_overlay_state_changes_the_expected_receipt() {
        let request = |routes: Vec<String>, key: &str| NetdRequest::ApplyOverlay {
            overlay_id: "wg0".into(),
            mode: OverlayMode::WireGuard,
            peers: vec![PeerSpec {
                node_id: "node-b".into(),
                public_key: key.into(),
                endpoint: "127.0.0.1:51820".into(),
                allowed_ips: vec!["10.0.0.0/24".into()],
            }],
            routes,
            addresses: vec!["10.0.0.1/24".into()],
        };
        let complete =
            EffectReceipt::from_request(&request(vec!["10.0.0.0/24".into()], "key-a"), 7, 1, 9);
        assert_ne!(
            complete,
            EffectReceipt::from_request(&request(vec![], "key-a"), 7, 1, 9)
        );
        assert_ne!(
            complete,
            EffectReceipt::from_request(&request(vec!["10.0.0.0/24".into()], "wrong-key"), 7, 1, 9)
        );
    }
}
