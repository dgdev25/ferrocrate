use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
#[derive(Default, Deserialize, Serialize)]
struct DeterministicState {
    links: BTreeSet<String>,
    routes: BTreeMap<String, Vec<String>>,
    wireguard: BTreeMap<String, (Vec<String>, Vec<PeerSpec>)>,
    masters: BTreeMap<String, String>,
    netns: BTreeMap<String, String>,
    netns_inode: BTreeMap<String, u64>,
}
pub(crate) struct PersistentKernelOps {
    path: PathBuf,
    state: DeterministicState,
    faults: crate::test_support::FaultHandle,
}
impl PersistentKernelOps {
    pub(crate) fn open(path: PathBuf) -> Self {
        let bytes = std::fs::read(&path).ok();
        let state = bytes
            .as_deref()
            .and_then(|v| serde_json::from_slice(v).ok())
            .or_else(|| {
                bytes.as_deref().and_then(|v| {
                    serde_json::from_slice::<BTreeSet<String>>(v)
                        .ok()
                        .map(|links| DeterministicState {
                            links,
                            ..Default::default()
                        })
                })
            })
            .unwrap_or_default();
        Self {
            path,
            state,
            faults: Default::default(),
        }
    }
    pub(crate) fn with_faults(path: PathBuf, faults: crate::test_support::FaultHandle) -> Self {
        let mut value = Self::open(path);
        value.faults = faults;
        value
    }
    fn effect(&self) -> Result<(), String> {
        if self.faults.take(crate::test_support::FaultPoint::Effect) {
            Err("injected effect failure".into())
        } else {
            Ok(())
        }
    }
    fn save(&self) -> Result<(), String> {
        std::fs::write(
            &self.path,
            serde_json::to_vec(&self.state).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
}
impl NetKernelOps for PersistentKernelOps {
    fn observe_link(&self, name: &str) -> bool {
        self.state.links.contains(name)
    }
    fn observe_effect(
        &self,
        receipt: &crate::effect_receipt::EffectReceipt,
    ) -> LiveEffectObservation {
        use crate::effect_receipt::{digest_sorted, peer_digest, EffectReceipt};
        match receipt {
            EffectReceipt::Overlay {
                overlay_id,
                peer_digest: peers,
                address_digest,
                route_digest,
                expected_exists,
                ..
            } => {
                if !self.state.links.contains(overlay_id) {
                    return if *expected_exists {
                        LiveEffectObservation::Absent
                    } else {
                        LiveEffectObservation::Exact
                    };
                }
                if !expected_exists {
                    return LiveEffectObservation::Mismatch;
                }
                let (addresses, actual_peers) = self
                    .state
                    .wireguard
                    .get(overlay_id)
                    .cloned()
                    .unwrap_or_default();
                let routes = self
                    .state
                    .routes
                    .get(overlay_id)
                    .cloned()
                    .unwrap_or_default();
                if digest_sorted(&addresses) == *address_digest
                    && digest_sorted(&routes) == *route_digest
                    && peer_digest(&actual_peers) == *peers
                {
                    LiveEffectObservation::Exact
                } else {
                    LiveEffectObservation::Mismatch
                }
            }
            EffectReceipt::Endpoint {
                endpoint_id,
                overlay_id,
                netns_name,
                netns_inode,
                expected_exists,
                ..
            } => {
                if !self.state.links.contains(endpoint_id) {
                    return if *expected_exists {
                        LiveEffectObservation::Absent
                    } else {
                        LiveEffectObservation::Exact
                    };
                }
                if !expected_exists {
                    return LiveEffectObservation::Mismatch;
                }
                if self.state.masters.get(endpoint_id) == Some(overlay_id)
                    && netns_name
                        .as_ref()
                        .is_none_or(|name| self.state.netns.get(endpoint_id) == Some(name))
                    && netns_inode
                        .is_none_or(|inode| self.state.netns_inode.get(endpoint_id) == Some(&inode))
                {
                    LiveEffectObservation::Exact
                } else {
                    LiveEffectObservation::Mismatch
                }
            }
        }
    }
    fn create_overlay(&mut self, name: &str) -> Result<(), String> {
        self.effect()?;
        self.state.links.insert(name.into());
        self.save()
    }
    fn remove_overlay(&mut self, name: &str) -> Result<(), String> {
        self.effect()?;
        self.state.links.remove(name);
        self.state.routes.remove(name);
        self.state.wireguard.remove(name);
        self.save()
    }
    fn create_endpoint(&mut self, config: &VethConfig) -> Result<(), String> {
        self.effect()?;
        self.state.links.insert(config.pair.host.clone());
        self.save()
    }
    fn attach_endpoint(&mut self, endpoint: &str, overlay: &str) -> Result<(), String> {
        self.effect()?;
        self.state.masters.insert(endpoint.into(), overlay.into());
        self.save()
    }
    fn move_endpoint(&mut self, endpoint: &str, netns: &str) -> Result<(), String> {
        self.effect()?;
        self.state.netns.insert(
            endpoint.strip_prefix("fc-").unwrap_or(endpoint).into(),
            netns.into(),
        );
        use std::os::unix::fs::MetadataExt;
        if let Ok(metadata) = std::fs::metadata(format!("/var/run/netns/{netns}")) {
            self.state.netns_inode.insert(
                endpoint.strip_prefix("fc-").unwrap_or(endpoint).into(),
                metadata.ino(),
            );
        }
        self.save()
    }
    fn remove_endpoint(&mut self, endpoint: &str) -> Result<(), String> {
        self.effect()?;
        self.state.links.remove(endpoint);
        self.state.masters.remove(endpoint);
        self.state.netns.remove(endpoint);
        self.state.netns_inode.remove(endpoint);
        self.save()
    }
    fn apply_routes(&mut self, interface: &str, routes: &[String]) -> Result<(), String> {
        self.effect()?;
        self.state.routes.insert(interface.into(), routes.to_vec());
        self.save()
    }
    fn remove_routes(&mut self, interface: &str, routes: &[String]) -> Result<(), String> {
        self.effect()?;
        if let Some(current) = self.state.routes.get_mut(interface) {
            current.retain(|route| !routes.contains(route));
        }
        self.save()
    }
    fn apply_wireguard(
        &mut self,
        name: &str,
        addresses: &[String],
        peers: &[PeerSpec],
    ) -> Result<(), String> {
        self.effect()?;
        self.state
            .wireguard
            .insert(name.into(), (addresses.to_vec(), peers.to_vec()));
        self.save()
    }
    fn remove_wireguard(&mut self, name: &str) -> Result<(), String> {
        self.effect()?;
        self.state.wireguard.remove(name);
        self.save()
    }
}

#[test]
fn deterministic_backend_recovers_observed_links() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel.json");
    let mut first = PersistentKernelOps::open(path.clone());
    first.create_overlay("overlay-a").unwrap();
    drop(first);
    assert!(PersistentKernelOps::open(path).observe_link("overlay-a"));
}

#[test]
fn injected_effect_failure_is_one_shot() {
    let directory = tempfile::tempdir().unwrap();
    let faults = crate::test_support::FaultHandle::default();
    faults.fail_once(crate::test_support::FaultPoint::Effect);
    let mut kernel = PersistentKernelOps::with_faults(directory.path().join("kernel.json"), faults);
    assert!(kernel.create_overlay("overlay-a").is_err());
    kernel.create_overlay("overlay-a").unwrap();
    assert!(kernel.observe_link("overlay-a"));
}

#[test]
fn exact_receipts_reject_each_partial_kernel_field() {
    use crate::{effect_receipt::EffectReceipt, protocol::NetdRequest};
    let directory = tempfile::tempdir().unwrap();
    let mut kernel = PersistentKernelOps::open(directory.path().join("kernel.json"));
    let peers = vec![PeerSpec {
        node_id: "node-b".into(),
        public_key: "peer-key".into(),
        endpoint: "127.0.0.1:51820".into(),
        allowed_ips: vec!["10.1.0.0/24".into()],
    }];
    let routes = vec!["10.1.0.0/24".into()];
    let addresses = vec!["10.1.0.1/24".into()];
    let request = NetdRequest::ApplyOverlay {
        overlay_id: "wg0".into(),
        peers: peers.clone(),
        routes: routes.clone(),
        addresses: addresses.clone(),
    };
    let receipt = EffectReceipt::from_request(&request, 7, 1, 9);
    kernel.create_overlay("wg0").unwrap();
    kernel.apply_wireguard("wg0", &addresses, &peers).unwrap();
    kernel.apply_routes("wg0", &routes).unwrap();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Exact
    );
    kernel.state.wireguard.get_mut("wg0").unwrap().1.clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel
        .state
        .wireguard
        .insert("wg0".into(), (addresses.clone(), peers.clone()));
    kernel.state.wireguard.get_mut("wg0").unwrap().0.clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel
        .state
        .wireguard
        .insert("wg0".into(), (addresses, peers));
    kernel.state.routes.get_mut("wg0").unwrap().clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );

    let endpoint = EffectReceipt::from_request(
        &NetdRequest::AttachEndpoint {
            overlay_id: "wg0".into(),
            endpoint_id: "ep0".into(),
            netns: None,
        },
        8,
        1,
        10,
    );
    kernel.state.links.insert("ep0".into());
    kernel.state.masters.insert("ep0".into(), "wg0".into());
    assert_eq!(
        kernel.observe_effect(&endpoint),
        LiveEffectObservation::Exact
    );
    kernel.state.masters.insert("ep0".into(), "wrong".into());
    assert_eq!(
        kernel.observe_effect(&endpoint),
        LiveEffectObservation::Mismatch
    );
}
