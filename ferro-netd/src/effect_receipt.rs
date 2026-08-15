use crate::protocol::NetdRequest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "effect", deny_unknown_fields)]
pub(crate) enum EffectReceipt {
    Overlay {
        overlay_id: String,
        generation: u64,
        peer_digest: [u8; 32],
        address_digest: [u8; 32],
        route_digest: [u8; 32],
        policy_epoch: u64,
        policy_revision: u64,
        expected_exists: bool,
    },
    Endpoint {
        endpoint_id: String,
        overlay_id: String,
        generation: u64,
        netns_digest: [u8; 32],
        bridge_master_digest: [u8; 32],
        netns_inode: Option<u64>,
        expected_exists: bool,
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
                peers,
                routes,
                addresses,
            } => Self::Overlay {
                overlay_id: overlay_id.clone(),
                generation,
                peer_digest: digest(peers),
                address_digest: digest(addresses),
                route_digest: digest(routes),
                policy_epoch: epoch,
                policy_revision: revision,
                expected_exists: true,
            },
            NetdRequest::RemoveOverlay { overlay_id } | NetdRequest::Inspect { overlay_id } => {
                Self::Overlay {
                    overlay_id: overlay_id.clone(),
                    generation,
                    peer_digest: [0; 32],
                    address_digest: [0; 32],
                    route_digest: [0; 32],
                    policy_epoch: epoch,
                    policy_revision: revision,
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
                bridge_master_digest: digest(overlay_id),
                netns_inode: netns.as_deref().and_then(netns_inode),
                expected_exists: true,
            },
            NetdRequest::DetachEndpoint {
                overlay_id,
                endpoint_id,
            } => Self::Endpoint {
                endpoint_id: endpoint_id.clone(),
                overlay_id: overlay_id.clone(),
                generation,
                netns_digest: [0; 32],
                bridge_master_digest: digest(overlay_id),
                netns_inode: None,
                expected_exists: false,
            },
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

fn digest<T: Serialize>(value: &T) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(value).unwrap_or_default()).into()
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
