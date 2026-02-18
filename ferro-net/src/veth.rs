use crate::executor::{ExecError, Transaction};
use crate::validate::{validate_cidr, validate_interface_name, ValidationError};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethPair {
    pub host: String,
    pub container: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethConfig {
    pub pair: VethPair,
    pub mtu: Option<u32>,
    pub host_addr: Option<IpAddr>,
    pub container_addr: Option<IpAddr>,
}

// ============================================================================
// Command builders (validation + command construction)
// ============================================================================

pub fn build_ip_link_add_veth_cmd(config: &VethConfig) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(&config.pair.host)?;
    validate_interface_name(&config.pair.container)?;
    let mut cmd = vec![
        "ip".into(),
        "link".into(),
        "add".into(),
        config.pair.host.clone(),
        "type".into(),
        "veth".into(),
        "peer".into(),
        "name".into(),
        config.pair.container.clone(),
    ];
    if let Some(mtu) = config.mtu {
        cmd.push("mtu".into());
        cmd.push(mtu.to_string());
    }
    Ok(cmd)
}

pub fn build_ip_link_del_cmd(link: &str) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    Ok(vec!["ip".into(), "link".into(), "del".into(), link.into()])
}

pub fn build_ip_link_set_up_cmd(link: &str) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    Ok(vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        link.into(),
        "up".into(),
    ])
}

pub fn build_ip_link_set_down_cmd(link: &str) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    Ok(vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        link.into(),
        "down".into(),
    ])
}

pub fn build_ip_addr_add_cmd(
    link: &str,
    addr: IpAddr,
    cidr: u8,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    let cidr_str = format!("{addr}/{cidr}");
    validate_cidr(&cidr_str)?;
    Ok(vec![
        "ip".into(),
        "addr".into(),
        "add".into(),
        cidr_str,
        "dev".into(),
        link.into(),
    ])
}

pub fn build_ip_addr_del_cmd(
    link: &str,
    addr: IpAddr,
    cidr: u8,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    let cidr_str = format!("{addr}/{cidr}");
    validate_cidr(&cidr_str)?;
    Ok(vec![
        "ip".into(),
        "addr".into(),
        "del".into(),
        cidr_str,
        "dev".into(),
        link.into(),
    ])
}

// ============================================================================
// Execution functions (with transaction support for atomic operations)
// ============================================================================

/// Create a veth pair (atomic with rollback).
///
/// Creates both ends of the veth pair and optionally assigns addresses.
pub fn create_veth_pair(config: &VethConfig) -> Result<(), ExecError> {
    let mut txn = Transaction::new();

    // Step 1: Create the veth pair
    txn.add(
        build_ip_link_add_veth_cmd(config).map_err(|e| ExecError::CommandFailed {
            cmd: format!("veth config validation: {}", e),
            stderr: String::new(),
        })?,
        // Deleting one end of the pair removes both
        build_ip_link_del_cmd(&config.pair.host).map_err(|e| ExecError::CommandFailed {
            cmd: format!("veth rollback validation: {}", e),
            stderr: String::new(),
        })?,
    )?;

    // Step 2: Bring up host end
    txn.add(
        build_ip_link_set_up_cmd(&config.pair.host).map_err(|e| ExecError::CommandFailed {
            cmd: format!("veth host up validation: {}", e),
            stderr: String::new(),
        })?,
        Vec::new(), // No rollback needed for link state
    )?;

    // Step 3: Bring up container end
    txn.add(
        build_ip_link_set_up_cmd(&config.pair.container).map_err(|e| ExecError::CommandFailed {
            cmd: format!("veth container up validation: {}", e),
            stderr: String::new(),
        })?,
        Vec::new(), // No rollback needed for link state
    )?;

    txn.commit();
    Ok(())
}

/// Destroy a veth pair by deleting one end.
pub fn destroy_veth_pair(name: &str) -> Result<(), ExecError> {
    // Bring down first (best effort)
    let _ = crate::executor::exec_cmd(&build_ip_link_set_down_cmd(name).map_err(|e| {
        ExecError::CommandFailed {
            cmd: format!("veth down validation: {}", e),
            stderr: String::new(),
        }
    })?);

    // Delete (removes both ends)
    crate::executor::exec_cmd(&build_ip_link_del_cmd(name).map_err(|e| {
        ExecError::CommandFailed {
            cmd: format!("veth del validation: {}", e),
            stderr: String::new(),
        }
    })?)
}

/// Assign an IP address to a veth interface.
pub fn assign_ip(link: &str, addr: IpAddr, cidr: u8) -> Result<(), ExecError> {
    crate::executor::exec_cmd(&build_ip_addr_add_cmd(link, addr, cidr).map_err(|e| {
        ExecError::CommandFailed {
            cmd: format!("veth addr validation: {}", e),
            stderr: String::new(),
        }
    })?)
}

#[cfg(test)]
mod tests {
    use super::{
        build_ip_addr_add_cmd, build_ip_link_add_veth_cmd, build_ip_link_set_up_cmd, VethConfig,
        VethPair,
    };
    use std::net::IpAddr;

    #[test]
    fn builds_veth_add_command() {
        let config = VethConfig {
            pair: VethPair {
                host: "veth-host".to_string(),
                container: "veth-cont".to_string(),
            },
            mtu: Some(1500),
            host_addr: None,
            container_addr: None,
        };

        assert_eq!(
            build_ip_link_add_veth_cmd(&config).unwrap(),
            vec![
                "ip",
                "link",
                "add",
                "veth-host",
                "type",
                "veth",
                "peer",
                "name",
                "veth-cont",
                "mtu",
                "1500"
            ]
        );
    }

    #[test]
    fn builds_link_up_and_addr_commands() {
        assert_eq!(
            build_ip_link_set_up_cmd("veth0").unwrap(),
            vec!["ip", "link", "set", "veth0", "up"]
        );

        let cmd =
            build_ip_addr_add_cmd("veth0", "10.0.0.2".parse::<IpAddr>().unwrap(), 24).unwrap();
        assert_eq!(
            cmd,
            vec!["ip", "addr", "add", "10.0.0.2/24", "dev", "veth0"]
        );
    }

    #[test]
    fn rejects_invalid_veth_names() {
        let config = VethConfig {
            pair: VethPair {
                host: "veth;rm".to_string(),
                container: "eth0".to_string(),
            },
            mtu: None,
            host_addr: None,
            container_addr: None,
        };
        assert!(build_ip_link_add_veth_cmd(&config).is_err());
    }
}
