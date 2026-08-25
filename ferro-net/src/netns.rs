use crate::executor::{exec_cmd, exec_cmd_capture, ExecError};
use crate::validate::{validate_interface_name, validate_netns_name, ValidationError};
#[cfg(target_os = "linux")]
use nix::sched::{setns, CloneFlags};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetnsError {
    #[error("failed to open netns path {0}")]
    Open(PathBuf, #[source] std::io::Error),
    #[error("failed to enter network namespace: {0}")]
    #[cfg(target_os = "linux")]
    Setns(#[from] nix::Error),
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),
    #[error("execution error: {0}")]
    Exec(#[from] ExecError),
}

const SYSTEM_NETNS_ROOT: &str = "/var/run/netns";

pub fn select_netns_root(
    rootless: bool,
    runtime_dir: Option<&Path>,
    system_root: &Path,
    system_root_usable: bool,
) -> PathBuf {
    if rootless {
        if let Some(runtime_dir) = runtime_dir {
            return runtime_dir.join("ferrocrate/netns");
        }
        if system_root_usable {
            return system_root.to_path_buf();
        }
    }
    system_root.to_path_buf()
}

#[cfg(target_os = "linux")]
fn root_mapped_user_namespace() -> bool {
    let Ok(uid_map) = fs::read_to_string("/proc/self/uid_map") else {
        return false;
    };
    let fields = uid_map
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    fields.len() >= 3 && !(fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295")
}

#[cfg(target_os = "linux")]
fn system_netns_root_usable(path: &Path) -> bool {
    path.is_dir() && nix::unistd::access(path, nix::unistd::AccessFlags::W_OK).is_ok()
}

pub fn netns_root() -> PathBuf {
    if let Some(explicit) = std::env::var_os("FERROCRATE_NETNS_ROOT") {
        return PathBuf::from(explicit);
    }
    #[cfg(not(target_os = "linux"))]
    {
        PathBuf::from(SYSTEM_NETNS_ROOT)
    }
    #[cfg(target_os = "linux")]
    {
        let rootless = !nix::unistd::Uid::effective().is_root() || root_mapped_user_namespace();
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .or_else(|| std::env::var_os("FERROCRATE_RUNTIME_DIR"))
            .map(PathBuf::from);
        let system_root = Path::new(SYSTEM_NETNS_ROOT);
        select_netns_root(
            rootless,
            runtime_dir.as_deref(),
            system_root,
            system_netns_root_usable(system_root),
        )
    }
}

pub fn netns_path(name: &str) -> PathBuf {
    netns_root().join(name)
}

pub fn build_netns_create_at_cmd(path: &Path) -> Vec<String> {
    vec![
        "unshare".into(),
        "--net".into(),
        "mount".into(),
        "--bind".into(),
        "/proc/self/ns/net".into(),
        path.display().to_string(),
    ]
}

pub fn build_netns_exec_at_cmd(path: &Path, args: &[&str]) -> Vec<String> {
    let mut command = vec![
        "nsenter".into(),
        format!("--net={}", path.display()),
        "--".into(),
    ];
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    command
}

pub fn build_netns_move_link_at_cmd(
    link: &str,
    path: &Path,
) -> Result<Vec<String>, ValidationError> {
    validate_interface_name(link)?;
    Ok(vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        link.into(),
        "netns".into(),
        path.display().to_string(),
    ])
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

pub fn build_ip_netns_loopback_observe_cmd(name: &str) -> Result<Vec<String>, ValidationError> {
    validate_netns_name(name)?;
    Ok(vec![
        "ip".into(),
        "-j".into(),
        "netns".into(),
        "exec".into(),
        name.into(),
        "ip".into(),
        "-j".into(),
        "link".into(),
        "show".into(),
        "dev".into(),
        "lo".into(),
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

pub fn loopback_is_up(name: &str) -> Result<bool, NetnsError> {
    let output =
        exec_cmd_capture(&build_ip_netns_loopback_observe_cmd(name)?).map_err(NetnsError::from)?;
    let rows = serde_json::from_str::<serde_json::Value>(&output).map_err(|error| {
        NetnsError::Exec(ExecError::CommandFailed {
            cmd: "ip -j netns exec ... ip -j link show dev lo".into(),
            stderr: format!("invalid loopback read-back: {error}"),
        })
    })?;
    Ok(rows
        .as_array()
        .and_then(|items| items.first())
        .is_some_and(|item| {
            item.get("operstate")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|state| state.eq_ignore_ascii_case("up"))
                || item
                    .get("flags")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|flags| {
                        flags.iter().any(|flag| {
                            flag.as_str()
                                .is_some_and(|value| value.eq_ignore_ascii_case("up"))
                        })
                    })
        }))
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
        stderr: "Linux engine required: network namespaces are unavailable on this host"
            .to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        build_ip_link_set_netns_cmd, build_ip_netns_add_cmd, build_ip_netns_del_cmd,
        build_ip_netns_loopback_observe_cmd, build_ip_netns_set_loopback_up_cmd,
        build_netns_create_at_cmd, build_netns_exec_at_cmd, build_netns_move_link_at_cmd,
        netns_path, select_netns_root,
    };
    use std::path::Path;

    #[test]
    fn builds_netns_paths() {
        let path = netns_path("c1");
        assert_eq!(path, super::netns_root().join("c1"));
    }

    #[test]
    fn root_mapped_user_namespace_prefers_private_runtime_netns_root() {
        assert_eq!(
            select_netns_root(
                true,
                Some(Path::new("/runtime/user")),
                Path::new("/run/netns"),
                true,
            ),
            Path::new("/runtime/user/ferrocrate/netns")
        );
        assert_eq!(
            select_netns_root(false, None, Path::new("/run/netns"), true),
            Path::new("/run/netns")
        );
    }

    #[test]
    fn custom_netns_commands_use_paths_instead_of_iproute_named_namespaces() {
        let path = Path::new("/runtime/user/ferrocrate/netns/c1");
        assert_eq!(
            build_netns_create_at_cmd(path),
            vec![
                "unshare",
                "--net",
                "mount",
                "--bind",
                "/proc/self/ns/net",
                "/runtime/user/ferrocrate/netns/c1"
            ]
        );
        assert_eq!(
            build_netns_exec_at_cmd(path, &["ip", "link", "set", "lo", "up"]),
            vec![
                "nsenter",
                "--net=/runtime/user/ferrocrate/netns/c1",
                "--",
                "ip",
                "link",
                "set",
                "lo",
                "up"
            ]
        );
        assert_eq!(
            build_netns_move_link_at_cmd("veth0", path).unwrap(),
            vec![
                "ip",
                "link",
                "set",
                "veth0",
                "netns",
                "/runtime/user/ferrocrate/netns/c1"
            ]
        );
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
        assert_eq!(
            build_ip_netns_loopback_observe_cmd("c1").unwrap(),
            vec!["ip", "-j", "netns", "exec", "c1", "ip", "-j", "link", "show", "dev", "lo"]
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
