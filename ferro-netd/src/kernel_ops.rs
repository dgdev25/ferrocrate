use crate::protocol::PeerSpec;
use ferro_net::{
    bridge::{create_bridge, destroy_bridge, BridgeConfig},
    exec_cmd, exec_cmd_capture,
    netns::move_to_netns,
    veth::{create_veth_pair, destroy_veth_pair, VethConfig},
    WireGuardInterfaceConfig, WireGuardManager, WireGuardPeer,
};
use std::path::PathBuf;

pub(crate) trait NetKernelOps: Send {
    fn observe_link(&self, name: &str) -> bool;
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

#[cfg(any(test, feature = "test-support"))]
pub(crate) mod deterministic {
    use super::*;
    use std::{collections::BTreeSet, path::PathBuf};
    pub(crate) struct PersistentKernelOps {
        path: PathBuf,
        links: BTreeSet<String>,
        faults: crate::test_support::FaultHandle,
    }
    impl PersistentKernelOps {
        pub(crate) fn open(path: PathBuf) -> Self {
            let links = std::fs::read(&path)
                .ok()
                .and_then(|v| serde_json::from_slice(&v).ok())
                .unwrap_or_default();
            Self {
                path,
                links,
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
                serde_json::to_vec(&self.links).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())
        }
    }
    impl NetKernelOps for PersistentKernelOps {
        fn observe_link(&self, name: &str) -> bool {
            self.links.contains(name)
        }
        fn create_overlay(&mut self, name: &str) -> Result<(), String> {
            self.effect()?;
            self.links.insert(name.into());
            self.save()
        }
        fn remove_overlay(&mut self, name: &str) -> Result<(), String> {
            self.effect()?;
            self.links.remove(name);
            self.save()
        }
        fn create_endpoint(&mut self, config: &VethConfig) -> Result<(), String> {
            self.effect()?;
            self.links.insert(config.pair.host.clone());
            self.save()
        }
        fn attach_endpoint(&mut self, _: &str, _: &str) -> Result<(), String> {
            self.effect()
        }
        fn move_endpoint(&mut self, _: &str, _: &str) -> Result<(), String> {
            self.effect()
        }
        fn remove_endpoint(&mut self, endpoint: &str) -> Result<(), String> {
            self.effect()?;
            self.links.remove(endpoint);
            self.save()
        }
        fn apply_routes(&mut self, _: &str, _: &[String]) -> Result<(), String> {
            self.effect()
        }
        fn remove_routes(&mut self, _: &str, _: &[String]) -> Result<(), String> {
            self.effect()
        }
        fn apply_wireguard(&mut self, _: &str, _: &[String], _: &[PeerSpec]) -> Result<(), String> {
            self.effect()
        }
        fn remove_wireguard(&mut self, _: &str) -> Result<(), String> {
            self.effect()
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
        let mut kernel =
            PersistentKernelOps::with_faults(directory.path().join("kernel.json"), faults);
        assert!(kernel.create_overlay("overlay-a").is_err());
        kernel.create_overlay("overlay-a").unwrap();
        assert!(kernel.observe_link("overlay-a"));
    }
}
