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
        let current = self.state.addresses.entry(interface.into()).or_default();
        for address in addresses {
            if !current.contains(address) {
                current.push(address.clone());
            }
        }
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
        let current = self.state.routes.entry(interface.into()).or_default();
        for route in routes {
            if !current.contains(route) {
                current.push(route.clone());
            }
        }
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

#[cfg(test)]
#[path = "kernel_deterministic_tests.rs"]
mod tests;
