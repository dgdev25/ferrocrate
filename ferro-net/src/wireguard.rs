use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use thiserror::Error;

use crate::executor::{exec_cmd_capture, exec_cmd_status, exec_cmd_with_stdin, ExecError};
use crate::validate::validate_interface_name;

const MAX_PEERS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardInterfaceConfig {
    pub name: String,
    pub private_key_path: PathBuf,
    pub listen_port: u16,
    pub addresses: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardPeer {
    pub node_id: String,
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<IpNet>,
    pub persistent_keepalive_secs: Option<u16>,
}

impl WireGuardPeer {
    pub fn new(
        node_id: String,
        public_key: String,
        endpoint: SocketAddr,
        allowed_ips: Vec<IpNet>,
    ) -> Self {
        Self {
            node_id,
            public_key,
            endpoint,
            allowed_ips,
            persistent_keepalive_secs: None,
        }
    }

    pub fn validate(&self, assigned_subnets: &[IpNet]) -> Result<(), WireGuardError> {
        if self.node_id.is_empty() || self.node_id.len() > 128 {
            return Err(WireGuardError::InvalidPeer("invalid node id".to_string()));
        }
        validate_key(&self.public_key)?;
        if self.endpoint.port() == 0 || is_unspecified_or_multicast(self.endpoint.ip()) {
            return Err(WireGuardError::InvalidPeer("invalid endpoint".to_string()));
        }
        if self.allowed_ips.is_empty() {
            return Err(WireGuardError::InvalidPeer(
                "peer has no allowed IPs".to_string(),
            ));
        }
        for route in &self.allowed_ips {
            if !assigned_subnets
                .iter()
                .any(|assigned| subnet_contains(assigned, route))
            {
                return Err(WireGuardError::RouteOutsideAllocation(route.to_string()));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardSnapshot {
    pub interface_exists: bool,
    pub syncconf: Option<String>,
    pub routes: Vec<IpNet>,
}

#[derive(Debug, Error)]
pub enum WireGuardError {
    #[error("invalid WireGuard interface: {0}")]
    InvalidInterface(String),
    #[error("invalid WireGuard key: {0}")]
    InvalidKey(String),
    #[error("invalid WireGuard peer: {0}")]
    InvalidPeer(String),
    #[error("WireGuard route outside assigned allocation: {0}")]
    RouteOutsideAllocation(String),
    #[error("WireGuard private key path is not protected: {0}")]
    UnsafeKeyPath(String),
    #[error("WireGuard command failed: {0}")]
    Command(String),
    #[error("WireGuard rollback failed after {primary}: {rollback}")]
    Rollback { primary: String, rollback: String },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct WireGuardManager {
    namespace: Option<String>,
}

impl WireGuardManager {
    pub fn new(namespace: Option<String>) -> Self {
        Self { namespace }
    }

    pub fn apply(
        &self,
        config: &WireGuardInterfaceConfig,
        peers: &[WireGuardPeer],
    ) -> Result<WireGuardSnapshot, WireGuardError> {
        validate_config(config, peers)?;
        let snapshot = self.inspect(config)?;
        let created = !snapshot.interface_exists;
        let result = (|| {
            if created {
                self.run(&["ip", "link", "add", &config.name, "type", "wireguard"])?;
            }
            let syncconf = render_syncconf(config, peers)?;
            let apply =
                self.run_with_stdin(&["wg", "syncconf", &config.name, "/dev/stdin"], &syncconf);
            apply?;
            for address in &config.addresses {
                self.run(&[
                    "ip",
                    "address",
                    "replace",
                    &address.to_string(),
                    "dev",
                    &config.name,
                ])?;
            }
            self.run(&["ip", "link", "set", &config.name, "up"])?;
            for address in &config.addresses {
                let route = format!("{}/{}", address.network(), address.prefix_len());
                self.run(&["ip", "route", "replace", &route, "dev", &config.name])?;
            }
            Ok(())
        })();
        if let Err(primary) = result {
            let rollback = self.restore(config, &snapshot, created);
            return match rollback {
                Ok(()) => Err(primary),
                Err(rollback) => Err(WireGuardError::Rollback {
                    primary: primary.to_string(),
                    rollback: rollback.to_string(),
                }),
            };
        }
        let snapshot = self.inspect(config)?;
        self.verify_routes(config)?;
        Ok(snapshot)
    }

    pub fn inspect(
        &self,
        config: &WireGuardInterfaceConfig,
    ) -> Result<WireGuardSnapshot, WireGuardError> {
        validate_interface_name(&config.name)
            .map_err(|error| WireGuardError::InvalidInterface(error.to_string()))?;
        let exists = self.run_status(&["ip", "link", "show", "dev", &config.name])?;
        let syncconf = if exists {
            Some(self.run(&["wg", "showconf", &config.name])?)
        } else {
            None
        };
        Ok(WireGuardSnapshot {
            interface_exists: exists,
            syncconf,
            routes: config.addresses.clone(),
        })
    }

    pub fn remove(&self, config: &WireGuardInterfaceConfig) -> Result<(), WireGuardError> {
        validate_interface_name(&config.name)
            .map_err(|error| WireGuardError::InvalidInterface(error.to_string()))?;
        if self.run_status(&["ip", "link", "show", "dev", &config.name])? {
            self.run(&["ip", "link", "delete", &config.name])?;
        }
        if self.run_status(&["ip", "link", "show", "dev", &config.name])? {
            return Err(WireGuardError::Command(format!(
                "WireGuard interface {} remained after deletion",
                config.name
            )));
        }
        Ok(())
    }

    fn verify_routes(&self, config: &WireGuardInterfaceConfig) -> Result<(), WireGuardError> {
        let route_v4 = self.run(&["ip", "route", "show", "dev", &config.name])?;
        let route_v6 = self.run(&["ip", "-6", "route", "show", "dev", &config.name])?;
        for address in &config.addresses {
            let route = format!("{}/{}", address.network(), address.prefix_len());
            let output = if address.addr().is_ipv4() {
                &route_v4
            } else {
                &route_v6
            };
            if !output.lines().any(|line| {
                line.split_whitespace()
                    .next()
                    .is_some_and(|destination| destination == route)
            }) {
                return Err(WireGuardError::Command(format!(
                    "route read-back missing {route} on {}",
                    config.name
                )));
            }
        }
        Ok(())
    }

    pub fn write_private_key(&self, interface: &str, key: &str) -> Result<PathBuf, WireGuardError> {
        validate_key(key.trim())?;
        self.write_private_file(interface, "key", key.trim())
    }

    pub fn generate_private_key(&self, interface: &str) -> Result<PathBuf, WireGuardError> {
        let key = self.run(&["wg", "genkey"])?;
        self.write_private_key(interface, &key)
    }

    fn restore(
        &self,
        config: &WireGuardInterfaceConfig,
        snapshot: &WireGuardSnapshot,
        created: bool,
    ) -> Result<(), WireGuardError> {
        if created {
            return self.remove(config);
        }
        if let Some(syncconf) = &snapshot.syncconf {
            self.run_with_stdin(&["wg", "syncconf", &config.name, "/dev/stdin"], syncconf)?;
        }
        Ok(())
    }

    fn write_private_file(
        &self,
        interface: &str,
        extension: &str,
        contents: &str,
    ) -> Result<PathBuf, WireGuardError> {
        let path = std::env::temp_dir().join(format!(
            "ferrocrate-{interface}-{}.{}",
            std::process::id(),
            extension
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(path)
    }

    fn run(&self, args: &[&str]) -> Result<String, WireGuardError> {
        let command = self.command_args(args);
        exec_cmd_capture(&command)
            .map(|output| output.trim().to_string())
            .map_err(map_exec_error)
    }

    fn run_with_stdin(&self, args: &[&str], input: &str) -> Result<String, WireGuardError> {
        let command = self.command_args(args);
        exec_cmd_with_stdin(&command, input)
            .map(|output| output.trim().to_string())
            .map_err(map_exec_error)
    }

    fn run_status(&self, args: &[&str]) -> Result<bool, WireGuardError> {
        let command = self.command_args(args);
        exec_cmd_status(&command).map_err(map_exec_error)
    }

    fn command_args(&self, args: &[&str]) -> Vec<String> {
        if let Some(namespace) = &self.namespace {
            let mut command = vec![
                "ip".to_string(),
                "netns".to_string(),
                "exec".to_string(),
                namespace.clone(),
            ];
            command.extend(args.iter().map(|arg| (*arg).to_string()));
            command
        } else {
            args.iter().map(|arg| (*arg).to_string()).collect()
        }
    }
}

fn map_exec_error(error: ExecError) -> WireGuardError {
    WireGuardError::Command(error.to_string())
}

fn validate_config(
    config: &WireGuardInterfaceConfig,
    peers: &[WireGuardPeer],
) -> Result<(), WireGuardError> {
    validate_interface_name(&config.name)
        .map_err(|error| WireGuardError::InvalidInterface(error.to_string()))?;
    if config.listen_port == 0 || config.addresses.is_empty() {
        return Err(WireGuardError::InvalidInterface(
            "missing listen port or addresses".to_string(),
        ));
    }
    validate_private_key_path(&config.private_key_path)?;
    if peers.len() > MAX_PEERS {
        return Err(WireGuardError::InvalidPeer(
            "peer limit exceeded".to_string(),
        ));
    }
    let mut routes = std::collections::BTreeSet::new();
    for peer in peers {
        peer.validate(&config.addresses)?;
        for route in &peer.allowed_ips {
            if !routes.insert(route.to_string()) {
                return Err(WireGuardError::InvalidPeer(format!(
                    "duplicate allowed IP {route}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_private_key_path(path: &Path) -> Result<(), WireGuardError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        return Err(WireGuardError::UnsafeKeyPath(
            "WireGuard key validation requires a Unix host".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        let metadata = fs::metadata(path)
            .map_err(|_| WireGuardError::UnsafeKeyPath(path.display().to_string()))?;
        if !metadata.is_file()
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        {
            return Err(WireGuardError::UnsafeKeyPath(path.display().to_string()));
        }
        validate_key(fs::read_to_string(path)?.trim())
    }
}

fn validate_key(key: &str) -> Result<(), WireGuardError> {
    if key.len() != 44
        || !key.ends_with('=')
        || !key[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
    {
        return Err(WireGuardError::InvalidKey(
            "expected base64-encoded Curve25519 key".to_string(),
        ));
    }
    Ok(())
}

fn render_syncconf(
    config: &WireGuardInterfaceConfig,
    peers: &[WireGuardPeer],
) -> Result<String, WireGuardError> {
    let private_key = fs::read_to_string(&config.private_key_path)?;
    validate_key(private_key.trim())?;
    let mut rendered = format!(
        "[Interface]\nPrivateKey = {}\nListenPort = {}\n",
        private_key.trim(),
        config.listen_port
    );
    for peer in peers {
        rendered.push_str("\n[Peer]\n");
        rendered.push_str(&format!(
            "PublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\n",
            peer.public_key,
            peer.endpoint,
            peer.allowed_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        if let Some(keepalive) = peer.persistent_keepalive_secs {
            rendered.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
        }
    }
    Ok(rendered)
}

fn subnet_contains(outer: &IpNet, inner: &IpNet) -> bool {
    outer.contains(&inner.network()) && outer.contains(&inner.broadcast())
}

fn is_unspecified_or_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()
    }

    #[test]
    fn peer_rejects_default_route_when_not_authorized() {
        let peer = WireGuardPeer::new(
            "node-a".to_string(),
            key(),
            "198.51.100.7:51820".parse().unwrap(),
            vec!["0.0.0.0/0".parse().unwrap()],
        );
        let assigned = vec!["10.44.0.0/24".parse().unwrap()];
        assert!(matches!(
            peer.validate(&assigned),
            Err(WireGuardError::RouteOutsideAllocation(_))
        ));
    }

    #[test]
    fn peer_accepts_owned_subnet() {
        let peer = WireGuardPeer::new(
            "node-a".to_string(),
            key(),
            "198.51.100.7:51820".parse().unwrap(),
            vec!["10.44.0.2/32".parse().unwrap()],
        );
        assert!(peer.validate(&["10.44.0.0/24".parse().unwrap()]).is_ok());
    }
}
