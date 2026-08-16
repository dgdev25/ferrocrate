use crate::executor::{ExecError, Transaction};
use crate::validate::{validate_cidr, validate_interface_name, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    pub name: String,
    pub cidr: String,
    pub ipv6_cidr: Option<String>,
}

// ============================================================================
// Command builders (validation + command construction)
// ============================================================================

pub fn build_ip_link_add_bridge_cmd(name: &str) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(name)?;
    Ok(vec![
        "ip".into(),
        "link".into(),
        "add".into(),
        name.into(),
        "type".into(),
        "bridge".into(),
    ])
}

pub fn build_ip_link_del_cmd(name: &str) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(name)?;
    Ok(vec!["ip".into(), "link".into(), "del".into(), name.into()])
}

pub fn build_ip_link_set_master_cmd(
    link: &str,
    bridge: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    validate_interface_name(bridge)?;
    Ok(vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        link.into(),
        "master".into(),
        bridge.into(),
    ])
}

pub fn build_ip_addr_add_bridge_cmd(
    bridge: &str,
    cidr: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(bridge)?;
    validate_cidr(cidr)?;
    Ok(vec![
        "ip".into(),
        "addr".into(),
        "add".into(),
        cidr.into(),
        "dev".into(),
        bridge.into(),
    ])
}

pub fn build_ip_addr_del_bridge_cmd(
    bridge: &str,
    cidr: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(bridge)?;
    validate_cidr(cidr)?;
    Ok(vec![
        "ip".into(),
        "addr".into(),
        "del".into(),
        cidr.into(),
        "dev".into(),
        bridge.into(),
    ])
}

pub fn build_ip_addr_add_ipv6_bridge_cmd(
    bridge: &str,
    cidr: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(bridge)?;
    validate_cidr(cidr)?;
    Ok(vec![
        "ip".into(),
        "-6".into(),
        "addr".into(),
        "add".into(),
        cidr.into(),
        "dev".into(),
        bridge.into(),
        "nodad".into(),
    ])
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

// ============================================================================
// Execution functions (with transaction support for atomic operations)
// ============================================================================

/// Create a bridge with optional CIDR assignment (atomic with rollback).
///
/// This is a transactional operation - if any step fails, all previous
/// steps are rolled back automatically.
pub fn create_bridge(config: &BridgeConfig) -> Result<(), ExecError> {
    crate::executor::HostCapabilities::probe().require_network_mutation()?;
    let mut txn = Transaction::new();

    // Step 1: Create the bridge device
    txn.add(
        build_ip_link_add_bridge_cmd(&config.name).map_err(|e| ExecError::CommandFailed {
            cmd: format!("bridge config validation: {}", e),
            stderr: String::new(),
        })?,
        build_ip_link_del_cmd(&config.name).map_err(|e| ExecError::CommandFailed {
            cmd: format!("bridge rollback validation: {}", e),
            stderr: String::new(),
        })?,
    )?;

    // Step 2: Assign IP address (if CIDR provided)
    if !config.cidr.is_empty() {
        txn.add(
            build_ip_addr_add_bridge_cmd(&config.name, &config.cidr).map_err(|e| {
                ExecError::CommandFailed {
                    cmd: format!("bridge addr validation: {}", e),
                    stderr: String::new(),
                }
            })?,
            build_ip_addr_del_bridge_cmd(&config.name, &config.cidr).map_err(|e| {
                ExecError::CommandFailed {
                    cmd: format!("bridge addr rollback validation: {}", e),
                    stderr: String::new(),
                }
            })?,
        )?;
    }

    // Step 3: Assign IPv6 address (if provided)
    if let Some(ipv6_cidr) = config.ipv6_cidr.as_ref() {
        if !ipv6_cidr.is_empty() {
            txn.add(
                build_ip_addr_add_ipv6_bridge_cmd(&config.name, ipv6_cidr).map_err(|e| {
                    ExecError::CommandFailed {
                        cmd: format!("bridge ipv6 addr validation: {}", e),
                        stderr: String::new(),
                    }
                })?,
                // IPv6 removal reuses generic ip addr del form.
                build_ip_addr_del_bridge_cmd(&config.name, ipv6_cidr).map_err(|e| {
                    ExecError::CommandFailed {
                        cmd: format!("bridge ipv6 addr rollback validation: {}", e),
                        stderr: String::new(),
                    }
                })?,
            )?;
        }
    }

    // Step 4: Bring the bridge up
    txn.add(
        build_ip_link_set_up_cmd(&config.name).map_err(|e| ExecError::CommandFailed {
            cmd: format!("bridge up validation: {}", e),
            stderr: String::new(),
        })?,
        build_ip_link_set_down_cmd(&config.name).map_err(|e| ExecError::CommandFailed {
            cmd: format!("bridge down rollback validation: {}", e),
            stderr: String::new(),
        })?,
    )?;

    txn.commit();

    let observed = observe_bridge_identity(&config.name)?;
    if !observation_matches_config(observed.as_ref(), config) {
        let rollback = destroy_bridge(&config.name);
        let detail = match rollback {
            Ok(()) => "bridge was removed after read-back mismatch".to_string(),
            Err(error) => format!("bridge rollback also failed: {error}"),
        };
        return Err(ExecError::CommandFailed {
            cmd: format!("bridge read-back verification for {}", config.name),
            stderr: detail,
        });
    }
    Ok(())
}

fn observation_matches_config(observed: Option<&BridgeObservation>, config: &BridgeConfig) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    let expected_cidr = (!config.cidr.is_empty()).then_some(config.cidr.as_str());
    let expected_ipv6 = config.ipv6_cidr.as_deref().filter(|cidr| !cidr.is_empty());
    observed.cidr.as_deref() == expected_cidr && observed.ipv6_cidr.as_deref() == expected_ipv6
}

/// Destroy a bridge (bring down and delete).
pub fn destroy_bridge(name: &str) -> Result<(), ExecError> {
    crate::executor::HostCapabilities::probe().require_network_mutation()?;
    // Bring down first (best effort)
    let _ = crate::executor::exec_cmd(&build_ip_link_set_down_cmd(name).map_err(|e| {
        ExecError::CommandFailed {
            cmd: format!("bridge down validation: {}", e),
            stderr: String::new(),
        }
    })?);

    // Delete the bridge
    crate::executor::exec_cmd(&build_ip_link_del_cmd(name).map_err(|e| {
        ExecError::CommandFailed {
            cmd: format!("bridge del validation: {}", e),
            stderr: String::new(),
        }
    })?)
}

#[cfg(test)]
mod tests {
    use super::{
        build_ip_addr_add_bridge_cmd, build_ip_addr_add_ipv6_bridge_cmd,
        build_ip_link_add_bridge_cmd, build_ip_link_set_master_cmd, build_ip_link_set_up_cmd,
        observation_matches_config, BridgeConfig, BridgeObservation,
    };

    #[test]
    fn builds_bridge_commands() {
        assert_eq!(
            build_ip_link_add_bridge_cmd("ferro0").unwrap(),
            vec!["ip", "link", "add", "ferro0", "type", "bridge"]
        );
        assert_eq!(
            build_ip_addr_add_bridge_cmd("ferro0", "10.0.0.1/24").unwrap(),
            vec!["ip", "addr", "add", "10.0.0.1/24", "dev", "ferro0"]
        );
        assert_eq!(
            build_ip_addr_add_ipv6_bridge_cmd("ferro0", "fd00::1/64").unwrap(),
            vec![
                "ip",
                "-6",
                "addr",
                "add",
                "fd00::1/64",
                "dev",
                "ferro0",
                "nodad"
            ]
        );
        assert_eq!(
            build_ip_link_set_master_cmd("veth0", "ferro0").unwrap(),
            vec!["ip", "link", "set", "veth0", "master", "ferro0"]
        );
        assert_eq!(
            build_ip_link_set_up_cmd("ferro0").unwrap(),
            vec!["ip", "link", "set", "ferro0", "up"]
        );
    }

    #[test]
    fn rejects_invalid_interface_names() {
        assert!(build_ip_link_add_bridge_cmd("eth0;rm -rf /").is_err());
        assert!(build_ip_link_add_bridge_cmd("").is_err());
        assert!(build_ip_link_add_bridge_cmd("this_name_is_way_too_long_for_linux").is_err());
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(build_ip_addr_add_bridge_cmd("ferro0", "not-a-cidr").is_err());
        assert!(build_ip_addr_add_bridge_cmd("ferro0", "10.0.0.0/33").is_err());
        assert!(build_ip_addr_add_bridge_cmd("ferro0", "10.0.0.0/24;cat /etc/passwd").is_err());
    }

    #[test]
    fn bridge_config_supports_ipv6() {
        let cfg = BridgeConfig {
            name: "ferro0".to_string(),
            cidr: "10.0.0.1/24".to_string(),
            ipv6_cidr: Some("fd00::1/64".to_string()),
        };
        assert_eq!(cfg.ipv6_cidr.as_deref(), Some("fd00::1/64"));
    }

    #[test]
    fn readback_requires_exact_requested_addresses() {
        let config = BridgeConfig {
            name: "ferro0".into(),
            cidr: "10.0.0.1/24".into(),
            ipv6_cidr: Some("fd00::1/64".into()),
        };
        let observed = BridgeObservation {
            name: "ferro0".into(),
            ifindex: 7,
            cidr: Some("10.0.0.1/24".into()),
            ipv6_cidr: Some("fd00::1/64".into()),
        };
        assert!(observation_matches_config(Some(&observed), &config));
        assert!(!observation_matches_config(None, &config));
        assert!(!observation_matches_config(
            Some(&BridgeObservation {
                ipv6_cidr: Some("fd00::2/64".into()),
                ..observed
            }),
            &config
        ));
    }
}

// ============================================================================
// Read-only bridge observation (FCNET-101)
// ============================================================================

/// Read-only observed identity of an existing bridge. `ifindex` is the
/// kernel interface index, which changes when a bridge is recreated even
/// under an identical name/address configuration, so it is the anchor for
/// exact-identity lifecycle decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeObservation {
    pub name: String,
    pub ifindex: u32,
    pub cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
}

/// Observe a bridge via `ip -j addr show dev <name>`.
///
/// Returns `Ok(None)` when the bridge does not exist. This function never
/// mutates kernel state.
pub fn observe_bridge_identity(name: &str) -> Result<Option<BridgeObservation>, ExecError> {
    validate_interface_name(name).map_err(|e| ExecError::CommandFailed {
        cmd: format!("bridge observation validation: {}", e),
        stderr: String::new(),
    })?;
    let output = match crate::executor::exec_cmd_capture(&[
        "ip".to_string(),
        "-j".to_string(),
        "addr".to_string(),
        "show".to_string(),
        "dev".to_string(),
        name.to_string(),
    ]) {
        Ok(out) => out,
        // `ip` reports a missing device as a command failure; map that to
        // absence rather than an error.
        Err(e) if e.to_string().contains("does not exist") => return Ok(None),
        Err(e) => {
            return Err(e);
        }
    };
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(None);
    }
    let parsed: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|e| ExecError::CommandFailed {
            cmd: "parse `ip -j` output".to_string(),
            stderr: e.to_string(),
        })?;
    let entries = parsed.as_array().ok_or_else(|| ExecError::CommandFailed {
        cmd: "expected array from `ip -j`".to_string(),
        stderr: String::new(),
    })?;
    if entries.is_empty() {
        return Ok(None);
    }
    let ifindex = entries[0]
        .get("ifindex")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ExecError::CommandFailed {
            cmd: "missing ifindex from `ip -j`".to_string(),
            stderr: String::new(),
        })? as u32;
    let mut cidr = None;
    let mut ipv6_cidr = None;
    if let Some(addr_info) = entries[0].get("addr_info").and_then(|v| v.as_array()) {
        for addr in addr_info {
            let family = addr.get("family").and_then(|f| f.as_str()).unwrap_or("");
            let local = addr.get("local").and_then(|l| l.as_str()).unwrap_or("");
            let prefix = addr.get("prefixlen").and_then(|p| p.as_u64()).unwrap_or(0);
            if local.is_empty() || prefix == 0 {
                continue;
            }
            let cidr_str = format!("{}/{}", local, prefix);
            if family == "inet6" {
                if is_ipv6_link_local_cidr(&cidr_str) {
                    continue;
                }
                ipv6_cidr.get_or_insert(cidr_str);
            } else {
                cidr.get_or_insert(cidr_str);
            }
        }
    }
    Ok(Some(BridgeObservation {
        name: name.to_string(),
        ifindex,
        cidr,
        ipv6_cidr,
    }))
}

/// Automatic Linux IPv6 link-local (`fe80::/10`) is not create identity.
pub fn is_ipv6_link_local_cidr(cidr: &str) -> bool {
    let addr = cidr.split_once('/').map(|(a, _)| a).unwrap_or(cidr);
    addr.parse::<std::net::Ipv6Addr>()
        .map(|ip| ip.is_unicast_link_local())
        .unwrap_or(false)
}

#[cfg(test)]
mod observation_tests {
    use super::is_ipv6_link_local_cidr;

    #[test]
    fn link_local_cidr_covers_fe80_prefix() {
        assert!(is_ipv6_link_local_cidr("fe80::1/64"));
        assert!(is_ipv6_link_local_cidr("FE80::ABCD/64"));
        assert!(is_ipv6_link_local_cidr("fe80::42:c0ff:fea8:1/64"));
        assert!(!is_ipv6_link_local_cidr("fd00::1/64"));
        assert!(!is_ipv6_link_local_cidr("2001:db8::1/64"));
        assert!(!is_ipv6_link_local_cidr("fec0::1/64"));
        assert!(!is_ipv6_link_local_cidr("10.0.0.1/24"));
    }
}
