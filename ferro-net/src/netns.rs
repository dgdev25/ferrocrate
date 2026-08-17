use crate::executor::{exec_cmd, ExecError};
use crate::validate::{validate_interface_name, validate_netns_name, ValidationError};
#[cfg(target_os = "linux")]
use nix::sched::{setns, CloneFlags};
#[cfg(target_os = "linux")]
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetnsError {
    #[error("failed to open netns path {0}")]
    Open(PathBuf, #[source] std::io::Error),
    #[error("failed to enter network namespace: {0}")]
    Setns(#[from] nix::Error),
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),
    #[error("execution error: {0}")]
    Exec(#[from] ExecError),
}

pub fn netns_path(name: &str) -> PathBuf {
    PathBuf::from("/var/run/netns").join(name)
}

// ============================================================================
// Command builders (validation + command construction)
// ============================================================================

pub fn build_ip_netns_add_cmd(name: &str) -> Result<Vec<String>, ValidationError> {
    validate_netns_name(name)?;
    Ok(vec!["ip".into(), "netns".into(), "add".into(), name.into()])
}

pub fn build_ip_netns_del_cmd(name: &str) -> Result<Vec<String>, ValidationError> {
    validate_netns_name(name)?;
    Ok(vec!["ip".into(), "netns".into(), "del".into(), name.into()])
}

pub fn build_ip_link_set_netns_cmd(
    link: &str,
    netns: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    validate_netns_name(netns)?;
    Ok(vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        link.into(),
        "netns".into(),
        netns.into(),
    ])
}

/// Build the narrow command used to make a newly-created sandbox usable.
/// Keeping this operation allow-listed avoids exposing a generic shell-like
/// `ip netns exec` surface to callers.
pub fn build_ip_netns_set_loopback_up_cmd(name: &str) -> Result<Vec<String>, ValidationError> {
    validate_netns_name(name)?;
    Ok(vec![
        "ip".into(),
        "netns".into(),
        "exec".into(),
        name.into(),
        "ip".into(),
        "link".into(),
        "set".into(),
        "lo".into(),
        "up".into(),
    ])
}

// ============================================================================
// Execution functions
// ============================================================================

/// Create a network namespace.
pub fn create_netns(name: &str) -> Result<(), NetnsError> {
    exec_cmd(&build_ip_netns_add_cmd(name)?).map_err(NetnsError::from)
}

/// Delete a network namespace.
pub fn destroy_netns(name: &str) -> Result<(), NetnsError> {
    exec_cmd(&build_ip_netns_del_cmd(name)?).map_err(NetnsError::from)
}

/// Move a network interface into a namespace.
pub fn move_to_netns(link: &str, netns: &str) -> Result<(), NetnsError> {
    exec_cmd(&build_ip_link_set_netns_cmd(link, netns)?).map_err(NetnsError::from)
}

/// Bring loopback up in a namespace created for a pod sandbox.
pub fn set_loopback_up(name: &str) -> Result<(), NetnsError> {
    exec_cmd(&build_ip_netns_set_loopback_up_cmd(name)?).map_err(NetnsError::from)
}

/// Enter a network namespace by path (direct syscall, no shell-out).
#[cfg(target_os = "linux")]
pub fn enter_netns(path: &Path) -> Result<(), NetnsError> {
    let file = File::open(path).map_err(|err| NetnsError::Open(path.to_path_buf(), err))?;
    setns(file, CloneFlags::CLONE_NEWNET)?;
    Ok(())
}

/// Enter a network namespace by path - not available on macOS.
#[cfg(not(target_os = "linux"))]
pub fn enter_netns(_path: &Path) -> Result<(), NetnsError> {
    Err(NetnsError::Exec(ExecError::CommandFailed {
        cmd: "enter_netns".to_string(),
        stderr: "enter_netns is only available on Linux".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        build_ip_link_set_netns_cmd, build_ip_netns_add_cmd, build_ip_netns_del_cmd,
        build_ip_netns_set_loopback_up_cmd, netns_path,
    };

    #[test]
    fn builds_netns_paths() {
        let path = netns_path("c1");
        assert_eq!(path.to_string_lossy(), "/var/run/netns/c1");
    }

    #[test]
    fn builds_ip_netns_commands() {
        assert_eq!(
            build_ip_netns_add_cmd("c1").unwrap(),
            vec!["ip", "netns", "add", "c1"]
        );
        assert_eq!(
            build_ip_netns_del_cmd("c1").unwrap(),
            vec!["ip", "netns", "del", "c1"]
        );
        assert_eq!(
            build_ip_link_set_netns_cmd("veth0", "c1").unwrap(),
            vec!["ip", "link", "set", "veth0", "netns", "c1"]
        );
        assert_eq!(
            build_ip_netns_set_loopback_up_cmd("c1").unwrap(),
            vec!["ip", "netns", "exec", "c1", "ip", "link", "set", "lo", "up"]
        );
    }

    #[test]
    fn rejects_invalid_netns_names() {
        assert!(build_ip_netns_add_cmd("ns;rm -rf").is_err());
        assert!(build_ip_netns_add_cmd("").is_err());
    }

    #[test]
    fn accepts_long_container_netns_name() {
        // Regression: netns names (ferro-<32-hex-id> = 38 chars) are NOT interfaces
        // and must not be rejected by the 15-char IFNAMSIZ limit.
        let name = "ferro-73e7ef48de8bfe6fd1d552a7abb00cd5";
        assert_eq!(name.len(), 38);
        assert!(build_ip_netns_add_cmd(name).is_ok());
        assert!(build_ip_netns_del_cmd(name).is_ok());
        // The veth link param still enforces the interface limit.
        assert!(build_ip_link_set_netns_cmd("eth0", name).is_ok());
        assert!(build_ip_link_set_netns_cmd("this-iface-name-is-way-too-long", name).is_err());
    }
}
