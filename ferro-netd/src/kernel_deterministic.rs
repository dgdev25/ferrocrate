use super::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
#[derive(Default, Deserialize, Serialize)]
struct DeterministicState {
    links: BTreeSet<String>,
    kinds: BTreeMap<String, String>,
    routes: BTreeMap<String, Vec<String>>,
    wireguard: BTreeMap<String, (Vec<String>, Vec<PeerSpec>)>,
    addresses: BTreeMap<String, Vec<String>>,
    masters: BTreeMap<String, String>,
    netns: BTreeMap<String, String>,
    netns_inode: BTreeMap<String, u64>,
    #[serde(default)]
    events: Vec<String>,
    forwarding: bool,
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
                bridge_ifname,
                wireguard_ifname,
                mode,
                peer_digest: peers,
                address_digest,
                route_digest,
                forwarding_required,
                expected_exists,
                ..
            } => {
                let bridge_exists = self.state.links.contains(bridge_ifname);
                let wireguard_exists = wireguard_ifname
                    .as_ref()
                    .is_some_and(|name| self.state.links.contains(name));
                if !expected_exists {
                    return if !bridge_exists && !wireguard_exists {
                        LiveEffectObservation::Exact
                    } else {
                        LiveEffectObservation::Mismatch
                    };
                }
                if !bridge_exists {
                    return if *expected_exists {
                        LiveEffectObservation::Absent
                    } else {
                        LiveEffectObservation::Exact
                    };
                }
                if wireguard_ifname.as_ref().is_some_and(|name| {
                    name == bridge_ifname
                        || self.state.links.contains(name)
                            != (*mode == crate::protocol::OverlayMode::WireGuard)
                }) {
                    return LiveEffectObservation::Mismatch;
                }
                let route_interface = if *mode == crate::protocol::OverlayMode::WireGuard {
                    wireguard_ifname.as_deref().unwrap_or(bridge_ifname)
                } else {
                    bridge_ifname
                };
                let (addresses, actual_peers) = self
                    .state
                    .addresses
                    .get(bridge_ifname)
                    .cloned()
                    .map(|addresses| {
                        (
                            addresses,
                            self.state
                                .wireguard
                                .get(route_interface)
                                .map(|v| v.1.clone())
                                .unwrap_or_default(),
                        )
                    })
                    .unwrap_or_default();
                let routes = self
                    .state
                    .routes
                    .get(route_interface)
                    .cloned()
                    .unwrap_or_default();
                if digest_sorted(&addresses) == *address_digest
                    && digest_sorted(&routes) == *route_digest
                    && peer_digest(&actual_peers) == *peers
                    && (!*forwarding_required || self.state.forwarding)
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
                let bridge = crate::interface_identity::overlay_interfaces(overlay_id).bridge;
                if self.state.masters.get(endpoint_id) == Some(&bridge)
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
        if self.state.links.contains(name)
            && self.state.kinds.get(name).map(String::as_str) != Some("bridge")
        {
            return Err("link name is already owned by another kind".into());
        }
        self.state.links.insert(name.into());
        self.state.kinds.insert(name.into(), "bridge".into());
        self.state
            .events
            .push(format!("ip link add {name} type bridge"));
        self.save()
    }
    fn remove_overlay(&mut self, name: &str) -> Result<(), String> {
        self.effect()?;
        self.state.links.remove(name);
        self.state.kinds.remove(name);
        self.state.routes.remove(name);
        self.state.wireguard.remove(name);
        self.state.events.push(format!("ip link del {name}"));
        self.save()
    }
    fn create_endpoint(&mut self, config: &VethConfig) -> Result<(), String> {
        self.effect()?;
        if self.state.links.contains(&config.pair.host)
            && self.state.kinds.get(&config.pair.host).map(String::as_str) != Some("veth")
        {
            return Err("link name is already owned by another kind".into());
        }
        self.state.links.insert(config.pair.host.clone());
        self.state
            .kinds
            .insert(config.pair.host.clone(), "veth".into());
        self.state
            .events
            .push(format!("ip link add {} type veth", config.pair.host));
        self.save()
    }
    fn attach_endpoint(&mut self, endpoint: &str, overlay: &str) -> Result<(), String> {
        self.effect()?;
        if self.state.kinds.get(overlay).map(String::as_str) != Some("bridge") {
            return Err("endpoint master is not a bridge".into());
        }
        self.state.masters.insert(endpoint.into(), overlay.into());
        self.state
            .events
            .push(format!("ip link set {endpoint} master {overlay}"));
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
        self.state.kinds.remove(endpoint);
        self.state.masters.remove(endpoint);
        self.state.netns.remove(endpoint);
        self.state.netns_inode.remove(endpoint);
        self.save()
    }
    fn apply_addresses(&mut self, interface: &str, addresses: &[String]) -> Result<(), String> {
        self.effect()?;
        self.state
            .addresses
            .insert(interface.into(), addresses.to_vec());
        self.state
            .events
            .push(format!("ip address replace dev {interface}"));
        self.save()
    }
    fn remove_addresses(&mut self, interface: &str, addresses: &[String]) -> Result<(), String> {
        self.effect()?;
        if let Some(current) = self.state.addresses.get_mut(interface) {
            current.retain(|address| !addresses.contains(address));
        }
        self.save()
    }
    fn apply_routes(&mut self, interface: &str, routes: &[String]) -> Result<(), String> {
        self.effect()?;
        self.state.routes.insert(interface.into(), routes.to_vec());
        self.state
            .events
            .push(format!("ip route replace dev {interface}"));
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
        if self.state.links.contains(name)
            && self.state.kinds.get(name).map(String::as_str) != Some("wireguard")
        {
            return Err("link name is already owned by another kind".into());
        }
        self.state.links.insert(name.into());
        self.state.kinds.insert(name.into(), "wireguard".into());
        self.state
            .events
            .push(format!("ip link add {name} type wireguard"));
        self.state.events.push(format!("wg set {name}"));
        self.state
            .wireguard
            .insert(name.into(), (addresses.to_vec(), peers.to_vec()));
        self.save()
    }
    fn remove_wireguard(&mut self, name: &str) -> Result<(), String> {
        self.effect()?;
        self.state.wireguard.remove(name);
        self.state.links.remove(name);
        self.state.kinds.remove(name);
        self.save()
    }
    fn ensure_forwarding(&mut self) -> Result<(), String> {
        self.effect()?;
        self.state.forwarding = true;
        self.state
            .events
            .push("sysctl net.ipv4.ip_forward=1".into());
        self.save()
    }
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
        mode: crate::protocol::OverlayMode::WireGuard,
        peers: peers.clone(),
        routes: routes.clone(),
        addresses: addresses.clone(),
    };
    let receipt = EffectReceipt::from_request(&request, 7, 1, 9);
    let interfaces = crate::interface_identity::overlay_interfaces("wg0");
    kernel.create_overlay(&interfaces.bridge).unwrap();
    kernel
        .apply_wireguard(&interfaces.wireguard, &[], &peers)
        .unwrap();
    kernel
        .apply_addresses(&interfaces.bridge, &addresses)
        .unwrap();
    kernel.apply_routes(&interfaces.wireguard, &routes).unwrap();
    kernel.ensure_forwarding().unwrap();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Exact
    );
    kernel
        .state
        .wireguard
        .get_mut(&interfaces.wireguard)
        .unwrap()
        .1
        .clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel
        .state
        .wireguard
        .insert(interfaces.wireguard.clone(), (Vec::new(), peers.clone()));
    kernel
        .state
        .addresses
        .get_mut(&interfaces.bridge)
        .unwrap()
        .clear();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel
        .state
        .wireguard
        .insert(interfaces.wireguard.clone(), (Vec::new(), peers));
    kernel
        .state
        .addresses
        .insert(interfaces.bridge.clone(), addresses);
    kernel
        .state
        .routes
        .get_mut(&interfaces.wireguard)
        .unwrap()
        .clear();
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
    kernel
        .state
        .masters
        .insert("ep0".into(), interfaces.bridge.clone());
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
#[test]
fn topology_uses_distinct_link_kinds_and_bridge_master_in_order() {
    let directory = tempfile::tempdir().unwrap();
    let mut kernel = PersistentKernelOps::open(directory.path().join("kernel.json"));
    let interfaces = crate::interface_identity::overlay_interfaces("customer-overlay");
    kernel.create_overlay("same-name").unwrap();
    assert!(kernel.apply_wireguard("same-name", &[], &[]).is_err());
    kernel.create_overlay(&interfaces.bridge).unwrap();
    kernel
        .apply_wireguard(&interfaces.wireguard, &[], &[])
        .unwrap();
    kernel.ensure_forwarding().unwrap();
    kernel
        .apply_addresses(&interfaces.bridge, &["10.9.0.1/24".into()])
        .unwrap();
    kernel
        .apply_routes(&interfaces.wireguard, &["10.9.0.0/24".into()])
        .unwrap();
    kernel
        .create_endpoint(&VethConfig {
            pair: ferro_net::veth::VethPair {
                host: "ep-topology".into(),
                container: "fc-ep-topology".into(),
            },
            mtu: None,
            host_addr: None,
            container_addr: None,
        })
        .unwrap();
    kernel
        .attach_endpoint("ep-topology", &interfaces.bridge)
        .unwrap();
    assert_eq!(kernel.state.masters["ep-topology"], interfaces.bridge);
    let ordered = kernel.state.events.join(";");
    assert!(ordered.contains(&format!(
        "type bridge;ip link add {} type wireguard;wg set {};sysctl net.ipv4.ip_forward=1;ip address replace dev {};ip route replace dev {}",
        interfaces.wireguard, interfaces.wireguard, interfaces.bridge, interfaces.wireguard
    )));
}
#[test]
fn removal_receipt_requires_both_topology_links_absent() {
    use crate::{effect_receipt::EffectReceipt, protocol::NetdRequest};
    let directory = tempfile::tempdir().unwrap();
    let mut kernel = PersistentKernelOps::open(directory.path().join("kernel.json"));
    let interfaces = crate::interface_identity::overlay_interfaces("overlay-delete");
    let receipt = EffectReceipt::from_request(
        &NetdRequest::RemoveOverlay {
            overlay_id: "overlay-delete".into(),
        },
        3,
        2,
        4,
    );
    kernel
        .apply_wireguard(&interfaces.wireguard, &[], &[])
        .unwrap();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Mismatch
    );
    kernel.remove_wireguard(&interfaces.wireguard).unwrap();
    assert_eq!(
        kernel.observe_effect(&receipt),
        LiveEffectObservation::Exact
    );
}
