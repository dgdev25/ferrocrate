use ferro_net::{
    bridge::{create_bridge, destroy_bridge, BridgeConfig},
    exec_cmd, exec_cmd_capture,
    netns::move_to_netns,
    veth::{create_veth_pair, destroy_veth_pair, VethConfig},
};

pub(crate) trait NetKernelOps: Send {
    fn observe_link(&self, name: &str) -> bool;
    fn create_overlay(&mut self, name: &str) -> Result<(), String>;
    fn remove_overlay(&mut self, name: &str) -> Result<(), String>;
    fn create_endpoint(&mut self, config: &VethConfig) -> Result<(), String>;
    fn attach_endpoint(&mut self, endpoint: &str, overlay: &str) -> Result<(), String>;
    fn move_endpoint(&mut self, endpoint: &str, netns: &str) -> Result<(), String>;
    fn remove_endpoint(&mut self, endpoint: &str) -> Result<(), String>;
}

pub(crate) struct RealNetKernelOps;
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
}

#[cfg(test)]
pub(crate) mod deterministic {
    use super::*;
    use std::{collections::BTreeSet, path::PathBuf};
    pub(crate) struct PersistentKernelOps {
        path: PathBuf,
        links: BTreeSet<String>,
    }
    impl PersistentKernelOps {
        pub(crate) fn open(path: PathBuf) -> Self {
            let links = std::fs::read(&path)
                .ok()
                .and_then(|v| serde_json::from_slice(&v).ok())
                .unwrap_or_default();
            Self { path, links }
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
            self.links.insert(name.into());
            self.save()
        }
        fn remove_overlay(&mut self, name: &str) -> Result<(), String> {
            self.links.remove(name);
            self.save()
        }
        fn create_endpoint(&mut self, config: &VethConfig) -> Result<(), String> {
            self.links.insert(config.pair.host.clone());
            self.save()
        }
        fn attach_endpoint(&mut self, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn move_endpoint(&mut self, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn remove_endpoint(&mut self, endpoint: &str) -> Result<(), String> {
            self.links.remove(endpoint);
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
}
