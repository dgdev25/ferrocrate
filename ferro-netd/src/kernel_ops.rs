use crate::protocol::PeerSpec;
use ferro_net::{
    bridge::{create_bridge, destroy_bridge, BridgeConfig},
    exec_cmd, exec_cmd_capture,
    netns::move_to_netns,
    veth::{create_veth_pair, destroy_veth_pair, VethConfig},
    WireGuardInterfaceConfig, WireGuardManager, WireGuardPeer,
};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveEffectObservation {
    Exact,
    Absent,
    Mismatch,
    Unknown,
}

pub(crate) trait NetKernelOps: Send {
    fn observe_link(&self, name: &str) -> bool;
    fn observe_effect(
        &self,
        receipt: &crate::effect_receipt::EffectReceipt,
    ) -> LiveEffectObservation;
    fn create_overlay(&mut self, name: &str) -> Result<(), String>;
    fn remove_overlay(&mut self, name: &str) -> Result<(), String>;
    fn create_endpoint(&mut self, config: &VethConfig) -> Result<(), String>;
    fn attach_endpoint(&mut self, endpoint: &str, overlay: &str) -> Result<(), String>;
    fn move_endpoint(&mut self, endpoint: &str, netns: &str) -> Result<(), String>;
    fn remove_endpoint(&mut self, endpoint: &str) -> Result<(), String>;
    fn apply_routes(&mut self, interface: &str, routes: &[String]) -> Result<(), String>;
    fn remove_routes(&mut self, interface: &str, routes: &[String]) -> Result<(), String>;
    fn apply_wireguard(
        &mut self,
        name: &str,
        addresses: &[String],
        peers: &[PeerSpec],
    ) -> Result<(), String>;
    fn remove_wireguard(&mut self, name: &str) -> Result<(), String>;
}

pub(crate) struct RealNetKernelOps {
    wireguard: Option<(WireGuardManager, PathBuf, u16)>,
}
impl RealNetKernelOps {
    pub(crate) fn new() -> Self {
        Self { wireguard: None }
    }
    pub(crate) fn with_wireguard(path: PathBuf, port: u16) -> Self {
        Self {
            wireguard: Some((WireGuardManager::new(None), path, port)),
        }
    }
}
impl NetKernelOps for RealNetKernelOps {
    fn observe_link(&self, name: &str) -> bool {
        exec_cmd_capture(&vec![
            "ip".into(),
            "link".into(),
            "show".into(),
            "dev".into(),
            name.into(),
        ])
        .is_ok()
    }
    fn observe_effect(
        &self,
        receipt: &crate::effect_receipt::EffectReceipt,
    ) -> LiveEffectObservation {
        use crate::effect_receipt::{digest_sorted, peer_digest, EffectReceipt};
        match receipt {
            EffectReceipt::Overlay {
                overlay_id,
                peer_digest: expected_peers,
                address_digest,
                route_digest,
                expected_exists,
                ..
            } => {
                if !self.observe_link(overlay_id) {
                    return if *expected_exists {
                        LiveEffectObservation::Absent
                    } else {
                        LiveEffectObservation::Exact
                    };
                }
                if !expected_exists {
                    return LiveEffectObservation::Mismatch;
                }
                let routes = match observe_routes(overlay_id) {
                    Ok(value) => value,
                    Err(()) => return LiveEffectObservation::Unknown,
                };
                let addresses = match observe_addresses(overlay_id) {
                    Ok(value) => value,
                    Err(()) => return LiveEffectObservation::Unknown,
                };
                let peers = match observe_wireguard_peers(overlay_id) {
                    Ok(value) => value,
                    Err(()) => return LiveEffectObservation::Unknown,
                };
                if digest_sorted(&routes) == *route_digest
                    && digest_sorted(&addresses) == *address_digest
                    && peer_digest(&peers) == *expected_peers
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
                if !self.observe_link(endpoint_id) {
                    return if *expected_exists {
                        LiveEffectObservation::Absent
                    } else {
                        LiveEffectObservation::Exact
                    };
                }
                if !expected_exists {
                    return LiveEffectObservation::Mismatch;
                }
                match observe_endpoint(endpoint_id, overlay_id, netns_name.as_deref(), *netns_inode)
                {
                    Ok(true) => LiveEffectObservation::Exact,
                    Ok(false) => LiveEffectObservation::Mismatch,
                    Err(()) => LiveEffectObservation::Unknown,
                }
            }
        }
    }
    fn create_overlay(&mut self, name: &str) -> Result<(), String> {
        create_bridge(&BridgeConfig {
            name: name.into(),
            cidr: String::new(),
            ipv6_cidr: None,
        })
        .map_err(|e| e.to_string())
    }
    fn remove_overlay(&mut self, name: &str) -> Result<(), String> {
        destroy_bridge(name).map_err(|e| e.to_string())
    }
    fn create_endpoint(&mut self, config: &VethConfig) -> Result<(), String> {
        create_veth_pair(config).map_err(|e| e.to_string())
    }
    fn attach_endpoint(&mut self, endpoint: &str, overlay: &str) -> Result<(), String> {
        let command = ferro_net::bridge::build_ip_link_set_master_cmd(endpoint, overlay)
            .map_err(|e| e.to_string())?;
        exec_cmd(&command).map_err(|e| e.to_string())
    }
    fn move_endpoint(&mut self, endpoint: &str, netns: &str) -> Result<(), String> {
        move_to_netns(endpoint, netns).map_err(|e| e.to_string())
    }
    fn remove_endpoint(&mut self, endpoint: &str) -> Result<(), String> {
        destroy_veth_pair(endpoint).map_err(|e| e.to_string())
    }
    fn apply_routes(&mut self, interface: &str, routes: &[String]) -> Result<(), String> {
        for route in routes {
            exec_cmd(&vec![
                "ip".into(),
                "route".into(),
                "replace".into(),
                route.clone(),
                "dev".into(),
                interface.into(),
            ])
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    fn remove_routes(&mut self, interface: &str, routes: &[String]) -> Result<(), String> {
        for route in routes {
            exec_cmd(&vec![
                "ip".into(),
                "route".into(),
                "del".into(),
                route.clone(),
                "dev".into(),
                interface.into(),
            ])
            .map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    fn apply_wireguard(
        &mut self,
        name: &str,
        addresses: &[String],
        peers: &[PeerSpec],
    ) -> Result<(), String> {
        let Some((manager, key, port)) = &self.wireguard else {
            return Ok(());
        };
        let addresses = addresses
            .iter()
            .map(|v| v.parse().map_err(|e| format!("{e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let peers = peers
            .iter()
            .map(|p| {
                Ok(WireGuardPeer::new(
                    p.node_id.clone(),
                    p.public_key.clone(),
                    p.endpoint.parse().map_err(|e| format!("{e}"))?,
                    p.allowed_ips
                        .iter()
                        .map(|v| v.parse().map_err(|e| format!("{e}")))
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        manager
            .apply(
                &WireGuardInterfaceConfig {
                    name: name.into(),
                    private_key_path: key.clone(),
                    listen_port: *port,
                    addresses,
                },
                &peers,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn remove_wireguard(&mut self, name: &str) -> Result<(), String> {
        let Some((manager, key, port)) = &self.wireguard else {
            return Ok(());
        };
        manager
            .remove(&WireGuardInterfaceConfig {
                name: name.into(),
                private_key_path: key.clone(),
                listen_port: *port,
                addresses: vec![],
            })
            .map_err(|e| e.to_string())
    }
}

fn observe_routes(interface: &str) -> Result<Vec<String>, ()> {
    let output = exec_cmd_capture(&[
        "ip".into(),
        "-j".into(),
        "route".into(),
        "show".into(),
        "dev".into(),
        interface.into(),
    ])
    .map_err(|_| ())?;
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output).map_err(|_| ())?;
    Ok(rows
        .iter()
        .filter_map(|row| row.get("dst")?.as_str().map(str::to_owned))
        .collect())
}

fn observe_addresses(interface: &str) -> Result<Vec<String>, ()> {
    let output = exec_cmd_capture(&[
        "ip".into(),
        "-j".into(),
        "addr".into(),
        "show".into(),
        "dev".into(),
        interface.into(),
    ])
    .map_err(|_| ())?;
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output).map_err(|_| ())?;
    Ok(rows
        .iter()
        .flat_map(|row| {
            row.get("addr_info")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|address| {
            Some(format!(
                "{}/{}",
                address.get("local")?.as_str()?,
                address.get("prefixlen")?.as_u64()?
            ))
        })
        .collect())
}

fn observe_wireguard_peers(interface: &str) -> Result<Vec<PeerSpec>, ()> {
    let output = exec_cmd_capture(&["wg".into(), "show".into(), interface.into(), "dump".into()])
        .map_err(|_| ())?;
    Ok(output
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            (fields.len() >= 4).then(|| PeerSpec {
                node_id: String::new(),
                public_key: fields[0].to_owned(),
                endpoint: fields[2].to_owned(),
                allowed_ips: fields[3]
                    .split(',')
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .collect(),
            })
        })
        .collect())
}

fn observe_endpoint(
    endpoint: &str,
    overlay: &str,
    netns: Option<&str>,
    expected_inode: Option<u64>,
) -> Result<bool, ()> {
    let output = exec_cmd_capture(&[
        "ip".into(),
        "-j".into(),
        "link".into(),
        "show".into(),
        "dev".into(),
        endpoint.into(),
    ])
    .map_err(|_| ())?;
    let rows: Vec<serde_json::Value> = serde_json::from_str(&output).map_err(|_| ())?;
    let master_matches = rows
        .first()
        .and_then(|row| row.get("master"))
        .and_then(serde_json::Value::as_str)
        == Some(overlay);
    let Some(namespace) = netns else {
        return Ok(master_matches);
    };
    use std::os::unix::fs::MetadataExt;
    let inode = std::fs::metadata(format!("/var/run/netns/{namespace}"))
        .map_err(|_| ())?
        .ino();
    if expected_inode != Some(inode) {
        return Ok(false);
    }
    let peer = format!("fc-{endpoint}");
    let peer_exists = exec_cmd_capture(&[
        "ip".into(),
        "netns".into(),
        "exec".into(),
        namespace.into(),
        "ip".into(),
        "link".into(),
        "show".into(),
        "dev".into(),
        peer,
    ])
    .is_ok();
    Ok(master_matches && peer_exists)
}

#[cfg(any(test, feature = "test-support"))]
#[path = "kernel_deterministic.rs"]
pub(crate) mod deterministic;
