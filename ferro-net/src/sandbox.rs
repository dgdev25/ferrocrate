//! Typed bridge/veth provisioning for a CRI pod sandbox namespace.
//!
//! The sandbox path deliberately owns only the bridge and veth it creates.
//! The caller owns the network namespace and must destroy it separately.

use crate::executor::{exec_cmd, ExecError, HostCapabilities, Transaction};
use crate::validate::{validate_cidr, validate_interface_name, validate_netns_name};
use std::net::Ipv4Addr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxNetworkConfig {
    pub namespace: String,
    pub bridge: String,
    pub host_veth: String,
    pub peer_veth: String,
    pub gateway: Ipv4Addr,
    pub container: Ipv4Addr,
    pub prefix: u8,
    pub mtu: Option<u32>,
}

fn cidr(address: Ipv4Addr, prefix: u8) -> String {
    format!("{address}/{prefix}")
}

fn exec_in_netns(namespace: &str, args: &[&str]) -> Result<Vec<String>, ExecError> {
    validate_netns_name(namespace).map_err(|error| ExecError::CommandFailed {
        cmd: "sandbox netns validation".into(),
        stderr: error.to_string(),
    })?;
    Ok(std::iter::once("ip".to_string())
        .chain(["netns", "exec"].into_iter().map(str::to_string))
        .chain(std::iter::once(namespace.to_string()))
        .chain(args.iter().map(|arg| (*arg).to_string()))
        .collect())
}

fn validate_namespace(config: &SandboxNetworkConfig) -> Result<(), ExecError> {
    validate_netns_name(&config.namespace).map_err(|error| ExecError::CommandFailed {
        cmd: "sandbox namespace validation".into(),
        stderr: error.to_string(),
    })?;
    Ok(())
}

fn validate_config(config: &SandboxNetworkConfig) -> Result<(), ExecError> {
    validate_namespace(config)?;
    for (kind, name) in [
        ("bridge", config.bridge.as_str()),
        ("host veth", config.host_veth.as_str()),
        ("peer veth", config.peer_veth.as_str()),
        ("peer veth", config.peer_veth.as_str()),
    ] {
        validate_interface_name(name).map_err(|error| ExecError::CommandFailed {
            cmd: format!("sandbox {kind} validation"),
            stderr: error.to_string(),
        })?;
    }
    if config.host_veth == config.peer_veth || config.bridge == config.host_veth {
        return Err(ExecError::CommandFailed {
            cmd: "sandbox network validation".into(),
            stderr: "sandbox link names must be distinct".into(),
        });
    }
    if !(1..=30).contains(&config.prefix) || config.gateway == config.container {
        return Err(ExecError::CommandFailed {
            cmd: "sandbox address validation".into(),
            stderr: "invalid or duplicate sandbox addresses".into(),
        });
    }
    validate_cidr(&cidr(config.gateway, config.prefix)).map_err(|error| {
        ExecError::CommandFailed {
            cmd: "sandbox gateway validation".into(),
            stderr: error.to_string(),
        }
    })?;
    validate_cidr(&cidr(config.container, config.prefix)).map_err(|error| {
        ExecError::CommandFailed {
            cmd: "sandbox address validation".into(),
            stderr: error.to_string(),
        }
    })?;
    if let Some(mtu) = config.mtu {
        if !(576..=65_535).contains(&mtu) {
            return Err(ExecError::CommandFailed {
                cmd: "sandbox mtu validation".into(),
                stderr: "MTU must be between 576 and 65535".into(),
            });
        }
    }
    Ok(())
}

fn preflight_new_resources(config: &SandboxNetworkConfig) -> Result<(), ExecError> {
    for (kind, name) in [
        ("bridge", config.bridge.as_str()),
        ("host veth", config.host_veth.as_str()),
    ] {
        if Path::new("/sys/class/net").join(name).exists() {
            return Err(ExecError::CommandFailed {
                cmd: format!("sandbox {kind} preflight"),
                stderr: format!("{kind} {name} already exists; refusing to mutate it"),
            });
        }
    }
    Ok(())
}

pub fn create_sandbox_network(config: &SandboxNetworkConfig) -> Result<(), ExecError> {
    HostCapabilities::probe().require_network_mutation()?;
    validate_config(config)?;
    preflight_new_resources(config)?;
    let bridge_cidr = cidr(config.gateway, config.prefix);
    let peer_cidr = cidr(config.container, config.prefix);
    let add_bridge = vec!["ip", "link", "add", &config.bridge, "type", "bridge"]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    let del_bridge = vec!["ip", "link", "del", &config.bridge]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    let add_bridge_addr = vec!["ip", "addr", "add", &bridge_cidr, "dev", &config.bridge]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    let add_veth = {
        let mut command = vec![
            "ip".into(),
            "link".into(),
            "add".into(),
            config.host_veth.clone(),
            "type".into(),
            "veth".into(),
            "peer".into(),
            "name".into(),
            config.peer_veth.clone(),
        ];
        if let Some(mtu) = config.mtu {
            command.extend(["mtu".into(), mtu.to_string()]);
        }
        command
    };
    let del_veth = vec!["ip", "link", "del", &config.host_veth]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>();
    let mut transaction = Transaction::new();
    transaction.add(add_bridge, del_bridge.clone())?;
    transaction.add(add_bridge_addr, Vec::new())?;
    transaction.add(
        vec!["ip", "link", "set", &config.bridge, "up"]
            .into_iter()
            .map(String::from)
            .collect(),
        Vec::new(),
    )?;
    transaction.add(add_veth, del_veth.clone())?;
    transaction.add(
        vec![
            "ip",
            "link",
            "set",
            &config.host_veth,
            "master",
            &config.bridge,
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        Vec::new(),
    )?;
    transaction.add(
        vec!["ip", "link", "set", &config.host_veth, "up"]
            .into_iter()
            .map(String::from)
            .collect(),
        Vec::new(),
    )?;
    transaction.add(
        vec![
            "ip",
            "link",
            "set",
            &config.peer_veth,
            "netns",
            &config.namespace,
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        Vec::new(),
    )?;
    transaction.add(
        exec_in_netns(
            &config.namespace,
            &["ip", "link", "set", &config.peer_veth, "name", "eth0"],
        )?,
        Vec::new(),
    )?;
    transaction.add(
        exec_in_netns(&config.namespace, &["ip", "link", "set", "lo", "up"])?,
        Vec::new(),
    )?;
    transaction.add(
        exec_in_netns(
            &config.namespace,
            &["ip", "addr", "add", &peer_cidr, "dev", "eth0"],
        )?,
        Vec::new(),
    )?;
    transaction.add(
        exec_in_netns(&config.namespace, &["ip", "link", "set", "eth0", "up"])?,
        Vec::new(),
    )?;
    transaction.add(
        exec_in_netns(
            &config.namespace,
            &[
                "ip",
                "route",
                "add",
                "default",
                "via",
                &config.gateway.to_string(),
            ],
        )?,
        Vec::new(),
    )?;
    transaction.commit();
    Ok(())
}

pub fn destroy_sandbox_network(config: &SandboxNetworkConfig) -> Result<(), ExecError> {
    HostCapabilities::probe().require_network_mutation()?;
    validate_config(config)?;
    let _ = exec_cmd(&[
        "ip".into(),
        "link".into(),
        "del".into(),
        config.host_veth.clone(),
    ]);
    exec_cmd(&[
        "ip".into(),
        "link".into(),
        "del".into(),
        config.bridge.clone(),
    ])
    .or_else(|error| match error {
        ExecError::CommandFailed { stderr, .. }
            if stderr.contains("Cannot find device") || stderr.contains("does not exist") =>
        {
            Ok(())
        }
        other => Err(other),
    })
}

#[cfg(test)]
mod tests {
    use super::{validate_config, SandboxNetworkConfig};
    use std::net::Ipv4Addr;

    fn config() -> SandboxNetworkConfig {
        SandboxNetworkConfig {
            namespace: "cri-test".into(),
            bridge: "fcb-test".into(),
            host_veth: "fch-test".into(),
            peer_veth: "fcp-test".into(),
            gateway: Ipv4Addr::new(10, 240, 0, 1),
            container: Ipv4Addr::new(10, 240, 0, 2),
            prefix: 30,
            mtu: Some(1500),
        }
    }

    #[test]
    fn validates_sandbox_network_config() {
        assert!(validate_config(&config()).is_ok());
    }

    #[test]
    fn rejects_duplicate_link_names() {
        let mut value = config();
        value.peer_veth = value.host_veth.clone();
        assert!(validate_config(&value).is_err());
    }
}
