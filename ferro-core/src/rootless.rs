use crate::linux_namespaces::{NamespaceError, NamespaceType, create_namespaces};
use nix::unistd::{Gid, Uid, User};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdRange {
    pub start: u32,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

impl RootlessMapping {
    pub fn as_uid_map_entry(&self) -> String {
        format!("{} {} {}\n", self.container_id, self.host_id, self.size)
    }

    pub fn as_gid_map_entry(&self) -> String {
        self.as_uid_map_entry()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessConfig {
    pub username: String,
    pub uid_mapping: RootlessMapping,
    pub gid_mapping: RootlessMapping,
}

#[derive(Debug, Error)]
pub enum RootlessError {
    #[error("failed to resolve current user")]
    CurrentUserUnavailable,
    #[error("failed to read subordinate id file {path}: {source}")]
    ReadSubId { path: PathBuf, source: io::Error },
    #[error("failed to parse subordinate id line: {0}")]
    InvalidSubIdLine(String),
    #[error("failed to prepare rootless namespaces: {0}")]
    Namespace(#[from] NamespaceError),
    #[error("failed to write mapping file {path}: {source}")]
    WriteMapping { path: PathBuf, source: io::Error },
}

impl RootlessConfig {
    /// Build rootless mapping from /etc/subuid and /etc/subgid, with fallback
    /// to a 1:1 mapping of the current host uid/gid.
    pub fn from_system() -> Result<Self, RootlessError> {
        let uid = Uid::current();
        let gid = Gid::current();
        let user = User::from_uid(uid)
            .map_err(|_| RootlessError::CurrentUserUnavailable)?
            .ok_or(RootlessError::CurrentUserUnavailable)?;

        let username = user.name;
        let uid_range = first_subid_range(Path::new("/etc/subuid"), &username)?;
        let gid_range = first_subid_range(Path::new("/etc/subgid"), &username)?;

        let uid_mapping = uid_range
            .map(|range| RootlessMapping {
                container_id: 0,
                host_id: range.start,
                size: range.count,
            })
            .unwrap_or(RootlessMapping {
                container_id: 0,
                host_id: uid.as_raw(),
                size: 1,
            });

        let gid_mapping = gid_range
            .map(|range| RootlessMapping {
                container_id: 0,
                host_id: range.start,
                size: range.count,
            })
            .unwrap_or(RootlessMapping {
                container_id: 0,
                host_id: gid.as_raw(),
                size: 1,
            });

        Ok(Self {
            username,
            uid_mapping,
            gid_mapping,
        })
    }
}

/// Enable rootless namespaces for a container process.
pub fn create_rootless_user_namespaces() -> Result<(), RootlessError> {
    create_namespaces(&[
        NamespaceType::User,
        NamespaceType::Pid,
        NamespaceType::Mount,
        NamespaceType::Ipc,
        NamespaceType::Uts,
        NamespaceType::Network,
    ])?;
    Ok(())
}

/// Apply user namespace mappings for a specific pid under procfs.
pub fn apply_user_namespace_mappings(
    proc_root: &Path,
    pid: u32,
    config: &RootlessConfig,
) -> Result<(), RootlessError> {
    let proc_pid_dir = proc_root.join(pid.to_string());

    write_file(
        &proc_pid_dir.join("setgroups"),
        b"deny\n",
        true,
    )?;
    write_file(
        &proc_pid_dir.join("uid_map"),
        config.uid_mapping.as_uid_map_entry().as_bytes(),
        false,
    )?;
    write_file(
        &proc_pid_dir.join("gid_map"),
        config.gid_mapping.as_gid_map_entry().as_bytes(),
        false,
    )?;

    Ok(())
}

fn write_file(path: &Path, content: &[u8], allow_missing: bool) -> Result<(), RootlessError> {
    match fs::write(path, content) {
        Ok(()) => Ok(()),
        Err(err) if allow_missing && err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RootlessError::WriteMapping {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn first_subid_range(path: &Path, username: &str) -> Result<Option<IdRange>, RootlessError> {
    let raw = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RootlessError::ReadSubId {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let parsed = parse_subid_line(line)?;
        if parsed.0 == username {
            return Ok(Some(IdRange {
                start: parsed.1,
                count: parsed.2,
            }));
        }
    }

    Ok(None)
}

fn parse_subid_line(line: &str) -> Result<(String, u32, u32), RootlessError> {
    let mut parts = line.split(':');
    let name = parts
        .next()
        .ok_or_else(|| RootlessError::InvalidSubIdLine(line.to_string()))?;
    let start = parts
        .next()
        .ok_or_else(|| RootlessError::InvalidSubIdLine(line.to_string()))?
        .parse::<u32>()
        .map_err(|_| RootlessError::InvalidSubIdLine(line.to_string()))?;
    let count = parts
        .next()
        .ok_or_else(|| RootlessError::InvalidSubIdLine(line.to_string()))?
        .parse::<u32>()
        .map_err(|_| RootlessError::InvalidSubIdLine(line.to_string()))?;

    if parts.next().is_some() {
        return Err(RootlessError::InvalidSubIdLine(line.to_string()));
    }

    Ok((name.to_string(), start, count))
}

#[cfg(test)]
mod tests {
    use super::{
        RootlessConfig, RootlessMapping, apply_user_namespace_mappings, parse_subid_line,
    };
    use std::fs;
    const DEFAULT_SUBID_SIZE: u32 = 65_536;

    #[test]
    fn parses_subuid_line() {
        let parsed = parse_subid_line("lyle:100000:65536").expect("line parses");
        assert_eq!(parsed.0, "lyle");
        assert_eq!(parsed.1, 100_000);
        assert_eq!(parsed.2, DEFAULT_SUBID_SIZE);
    }

    #[test]
    fn rejects_invalid_subuid_line() {
        let err = parse_subid_line("lyle:not-a-number:65536").expect_err("invalid line");
        assert!(err.to_string().contains("failed to parse subordinate id line"));
    }

    #[test]
    fn writes_namespace_mapping_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let proc_root = temp.path();
        let pid_dir = proc_root.join("4242");
        fs::create_dir_all(&pid_dir).expect("create pid dir");
        fs::write(pid_dir.join("setgroups"), "").expect("seed setgroups");

        let cfg = RootlessConfig {
            username: "tester".to_string(),
            uid_mapping: RootlessMapping {
                container_id: 0,
                host_id: 100_000,
                size: DEFAULT_SUBID_SIZE,
            },
            gid_mapping: RootlessMapping {
                container_id: 0,
                host_id: 100_000,
                size: DEFAULT_SUBID_SIZE,
            },
        };

        apply_user_namespace_mappings(proc_root, 4242, &cfg).expect("mapping applied");

        assert_eq!(
            fs::read_to_string(pid_dir.join("setgroups")).expect("setgroups"),
            "deny\n"
        );
        assert_eq!(
            fs::read_to_string(pid_dir.join("uid_map")).expect("uid_map"),
            "0 100000 65536\n"
        );
        assert_eq!(
            fs::read_to_string(pid_dir.join("gid_map")).expect("gid_map"),
            "0 100000 65536\n"
        );
    }
}
