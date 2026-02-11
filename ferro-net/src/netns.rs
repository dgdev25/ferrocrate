use nix::sched::{setns, CloneFlags};
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetnsError {
    #[error("failed to open netns path {0}")]
    Open(PathBuf, #[source] std::io::Error),
    #[error("failed to enter network namespace: {0}")]
    Setns(#[from] nix::Error),
}

pub fn netns_path(name: &str) -> PathBuf {
    PathBuf::from("/var/run/netns").join(name)
}

pub fn build_ip_netns_add_cmd(name: &str) -> Vec<String> {
    vec!["ip".into(), "netns".into(), "add".into(), name.into()]
}

pub fn build_ip_netns_del_cmd(name: &str) -> Vec<String> {
    vec!["ip".into(), "netns".into(), "del".into(), name.into()]
}

pub fn build_ip_link_set_netns_cmd(link: &str, netns: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        link.into(),
        "netns".into(),
        netns.into(),
    ]
}

pub fn enter_netns(path: &Path) -> Result<(), NetnsError> {
    let file = File::open(path).map_err(|err| NetnsError::Open(path.to_path_buf(), err))?;
    setns(file, CloneFlags::CLONE_NEWNET)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{build_ip_link_set_netns_cmd, build_ip_netns_add_cmd, build_ip_netns_del_cmd, netns_path};

    #[test]
    fn builds_netns_paths() {
        let path = netns_path("c1");
        assert_eq!(path.to_string_lossy(), "/var/run/netns/c1");
    }

    #[test]
    fn builds_ip_netns_commands() {
        assert_eq!(
            build_ip_netns_add_cmd("c1"),
            vec!["ip", "netns", "add", "c1"]
        );
        assert_eq!(
            build_ip_netns_del_cmd("c1"),
            vec!["ip", "netns", "del", "c1"]
        );
        assert_eq!(
            build_ip_link_set_netns_cmd("veth0", "c1"),
            vec!["ip", "link", "set", "veth0", "netns", "c1"]
        );
    }
}
