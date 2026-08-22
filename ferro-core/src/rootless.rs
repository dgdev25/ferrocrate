use crate::authorization::{
    surface::{
        SurfaceAuthorization, SurfaceAuthorizationError, SurfaceExecutionError, SurfacePermit,
    },
    Action, ResourceKind,
};
use crate::linux_namespaces::{create_namespaces, NamespaceError, NamespaceType};
use nix::unistd::{Gid, Uid, User};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
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

/// Probe whether this process can create the mapped user namespace used by
/// rootless launchers without changing the caller's namespace. Use the
/// trusted `unshare --map-root-user` helper instead of manually writing map
/// files: distributions may require `newuidmap`/`newgidmap` or other policy
/// handling that the helper performs for us.
pub fn user_namespace_available() -> bool {
    let Some(unshare) = trusted_executable_path("unshare") else {
        return false;
    };
    Command::new(unshare)
        .args(["--user", "--map-root-user", "--fork", "--", "true"])
        .status()
        .is_ok_and(|status| status.success())
}

/// Probe the mapped user namespace that the rootless launcher requires and
/// return a bounded operator-facing reason when the host rejects it.
pub fn user_namespace_diagnostic() -> Result<(), String> {
    if let Ok(value) = fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        let value = value.trim();
        if value != "1" {
            return Err(format!(
                "kernel.unprivileged_userns_clone={value:?}; unprivileged user namespaces are disabled"
            ));
        }
    }
    if user_namespace_available() {
        Ok(())
    } else {
        Err(
            "user namespace creation or UID/GID mapping was denied by host policy; check kernel, LSM, and outer-container namespace restrictions"
                .to_string(),
        )
    }
}

/// Probe whether the caller can create the user+mount namespace pair required
/// for rootless bind/tmpfs/read-only-rootfs execution. The probe is isolated
/// in a short-lived `unshare` child and never changes the caller's namespaces.
///
/// Unlike [`user_namespace_available`], this returns a bounded diagnostic so
/// CLI/operator surfaces can distinguish an absent helper, a host policy
/// denial, and a non-zero helper exit without exposing unbounded stderr.
pub fn mount_namespace_diagnostic() -> Result<(), String> {
    let unshare = trusted_executable_path("unshare").ok_or_else(|| {
        "unshare executable is unavailable or not a trusted root-owned executable".to_string()
    })?;
    let output = Command::new(unshare)
        .args([
            "--user",
            "--mount",
            "--fork",
            "--propagation",
            "unchanged",
            "true",
        ])
        .output()
        .map_err(|error| format!("could not launch unshare: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(240)
        .collect::<String>();
    if detail.is_empty() {
        Err(format!("unshare exited with {}", output.status))
    } else {
        Err(format!("unshare exited with {}: {detail}", output.status))
    }
}

/// Return whether the bubblewrap helper required for rootless rootfs and
/// mounted workloads is available as a regular executable.
pub fn bubblewrap_available() -> bool {
    bubblewrap_path().is_some()
}

/// Report a bounded operator-facing bubblewrap prerequisite diagnostic without
/// executing anything discovered through `PATH`.
pub fn bubblewrap_diagnostic() -> Result<(), String> {
    bubblewrap_path()
        .map(|_| ())
        .ok_or_else(|| {
            "bubblewrap (bwrap) executable is unavailable; rootless rootfs and mounted workloads require it"
                .to_string()
        })
}

/// Probe the bubblewrap execution path used for every rootless rootfs.
///
/// Merely finding `bwrap` is insufficient: some hosts expose the executable
/// but deny the user-namespace mapping it needs.  Run a minimal, bounded
/// read-only rootfs probe so callers can fail before creating partial state.
pub fn bubblewrap_execution_diagnostic() -> Result<(), String> {
    let bwrap = bubblewrap_path().ok_or_else(|| {
        "bubblewrap (bwrap) executable is unavailable; rootless rootfs execution requires it"
            .to_string()
    })?;
    let output = Command::new(&bwrap)
        .args(["--ro-bind", "/", "/", "true"])
        .output()
        .map_err(|error| format!("could not launch rootless rootfs probe: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(240)
        .collect::<String>();
    Err(if detail.is_empty() {
        format!("rootless rootfs probe exited with {}", output.status)
    } else {
        format!(
            "rootless rootfs probe exited with {}: {detail}",
            output.status
        )
    })
}

/// Identity of the bwrap executable a probe result was recorded for. Any
/// change to the binary invalidates the cached probe.
pub(crate) fn bwrap_probe_identity(bwrap: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    match fs::metadata(bwrap) {
        Ok(metadata) => format!(
            "{}.{}.{}.{}",
            metadata.dev(),
            metadata.ino(),
            metadata.mtime(),
            metadata.size()
        ),
        Err(_) => String::new(),
    }
}

pub(crate) fn read_bwrap_probe_cache(cache_path: &Path) -> Option<String> {
    fs::read_to_string(cache_path).ok()
}

pub(crate) fn write_bwrap_probe_cache(cache_path: &Path, identity: &str) {
    if let Err(error) = crate::fs_atomic::write_atomic(cache_path, identity.as_bytes()) {
        log::debug!("failed to cache bwrap probe result: {error}");
    }
}

/// Cached [`bubblewrap_execution_diagnostic`]. The probe spawns a full bwrap
/// child with a user namespace (~tens of ms); the result is memoized per
/// runtime directory keyed by the bwrap binary identity. A cached success
/// only skips the pre-flight diagnostic: if the host later denies the
/// mapping, the launch itself still fails closed.
pub fn bubblewrap_execution_diagnostic_cached(cache_path: &Path) -> Result<(), String> {
    let bwrap = bubblewrap_path().ok_or_else(|| {
        "bubblewrap (bwrap) executable is unavailable; rootless rootfs execution requires it"
            .to_string()
    })?;
    let identity = bwrap_probe_identity(&bwrap);
    if !identity.is_empty() && read_bwrap_probe_cache(cache_path).as_deref() == Some(&identity) {
        return Ok(());
    }
    let result = bubblewrap_execution_diagnostic();
    if result.is_ok() && !identity.is_empty() {
        write_bwrap_probe_cache(cache_path, &identity);
    }
    result
}

/// Probe the combined user/network namespace plus bubblewrap path used by
/// rootless bridge workloads. This catches hosts where a standalone mount
/// namespace is allowed but nested user namespaces are denied.
pub fn nested_bubblewrap_diagnostic() -> Result<(), String> {
    let bwrap = bubblewrap_path().ok_or_else(|| {
        "bubblewrap (bwrap) executable is unavailable; rootless bridge workloads require it"
            .to_string()
    })?;
    let unshare = trusted_executable_path("unshare").ok_or_else(|| {
        "unshare executable is unavailable or not a trusted root-owned executable".to_string()
    })?;
    let output = Command::new(unshare)
        // Map the caller to root inside the newly-created user namespace.
        // Without this explicit mapping, bubblewrap attempts a second user
        // namespace and is rejected by otherwise-capable hosts.
        .args(["--user", "--map-root-user", "--net", "--fork", "--"])
        .arg(bwrap)
        .args(["--ro-bind", "/", "/", "true"])
        .output()
        .map_err(|error| format!("could not launch rootless bridge probe: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr)
        .trim()
        .chars()
        .take(240)
        .collect::<String>();
    Err(if detail.is_empty() {
        format!("rootless bridge probe exited with {}", output.status)
    } else {
        format!(
            "rootless bridge probe exited with {}: {detail}",
            output.status
        )
    })
}

/// Report the subordinate-ID prerequisite for rootless ID mappings. Return
/// the exact per-file remediation for whichever range is missing so operators
/// can distinguish a missing `/etc/subuid` entry from a missing `/etc/subgid`
/// entry instead of debugging a silent single-ID mapping fallback.
pub fn subid_diagnostic() -> Result<(), String> {
    let uid = Uid::current();
    let gid = Gid::current();
    let username = User::from_uid(uid)
        .ok()
        .flatten()
        .map(|user| user.name)
        .unwrap_or_default();
    let has_subuid = first_subid_range(Path::new("/etc/subuid"), &username, uid.as_raw())
        .map(|range| range.is_some())
        .unwrap_or(false);
    let has_subgid = first_subid_range(Path::new("/etc/subgid"), &username, gid.as_raw())
        .map(|range| range.is_some())
        .unwrap_or(false);
    subid_prerequisite_message(&username, has_subuid, has_subgid).map_or(Ok(()), Err)
}

/// Select the prerequisite message for the missing subordinate-ID ranges.
/// `None` means both ranges are present and rootless mappings are complete.
pub(crate) fn subid_prerequisite_message(
    username: &str,
    has_subuid: bool,
    has_subgid: bool,
) -> Option<String> {
    if has_subuid && has_subgid {
        return None;
    }
    let mut missing = Vec::new();
    if !has_subuid {
        missing.push(format!(
            "no subordinate UID range for user {username} in /etc/subuid; run: sudo usermod --add-subuids 100000-165535 {username}"
        ));
    }
    if !has_subgid {
        missing.push(format!(
            "no subordinate GID range for user {username} in /etc/subgid; run: sudo usermod --add-subgids 100000-165535 {username}"
        ));
    }
    Some(format!(
        "{}; without subordinate ranges rootless containers fall back to a single-ID mapping, which cannot chown files or run multi-user workloads",
        missing.join("; ")
    ))
}

/// Report whether cgroup v2 controllers are delegated to the caller. Rootful
/// callers do not need delegation and always pass.
pub fn cgroup_delegation_diagnostic() -> Result<(), String> {
    if Uid::effective().is_root() {
        return Ok(());
    }
    if let Some(custom) = std::env::var_os("FERROCRATE_CGROUP_ROOT") {
        return cgroup_delegation_probe(&PathBuf::from(custom));
    }
    let Some(relative) = self_cgroup_relative_path() else {
        return Err(
            "could not read this process's cgroup from /proc/self/cgroup; rootless cgroup delegation cannot be verified"
                .to_string(),
        );
    };
    cgroup_delegation_probe(&Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')))
}

fn self_cgroup_relative_path() -> Option<String> {
    let content = fs::read_to_string("/proc/self/cgroup").ok()?;
    let line = content.lines().next()?;
    let path = line.strip_prefix("0::")?;
    Some(path.trim().to_string())
}

/// Probe one cgroup subtree for the delegated write access that rootless
/// controller configuration requires. Opening `cgroup.subtree_control` for
/// write never mutates the hierarchy by itself.
pub(crate) fn cgroup_delegation_probe(cgroup_root: &Path) -> Result<(), String> {
    if !cgroup_root.join("cgroup.controllers").exists() {
        return Err(format!(
            "cgroup v2 hierarchy is unavailable at {}; rootless resource limits require cgroup v2 with delegated controllers",
            cgroup_root.display()
        ));
    }
    let subtree_control = cgroup_root.join("cgroup.subtree_control");
    match fs::OpenOptions::new().write(true).open(&subtree_control) {
        Ok(_) => Ok(()),
        Err(_) => Err(cgroup_not_delegated_message(&subtree_control)),
    }
}

pub(crate) fn cgroup_not_delegated_message(probed: &Path) -> String {
    format!(
        "cgroup controllers are not delegated to this user (probed {}); run `sudo loginctl enable-linger $USER` and `sudo systemctl set-property user-$(id -u).slice Delegate=yes`, or set FERROCRATE_CGROUP_ROOT to a caller-owned delegated hierarchy",
        probed.display()
    )
}

fn bubblewrap_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join("bwrap"))
        .chain([
            PathBuf::from("/usr/local/bin/bwrap"),
            PathBuf::from("/usr/bin/bwrap"),
            PathBuf::from("/bin/bwrap"),
        ])
        .find(|candidate| {
            let Ok(metadata) = fs::metadata(candidate) else {
                return false;
            };
            if !metadata.is_file() {
                return false;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                metadata.uid() == 0
                    && metadata.permissions().mode() & 0o111 != 0
                    && metadata.permissions().mode() & 0o022 == 0
            }
            #[cfg(not(unix))]
            {
                true
            }
        })
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
    #[error("failed to launch {helper} for rootless mapping: {source}")]
    LaunchMappingHelper {
        helper: &'static str,
        source: io::Error,
    },
    #[error("{helper} rejected rootless mapping")]
    MappingHelperRejected { helper: &'static str },
    #[error("rootless mapping authorization failed: {0}")]
    Authorization(#[from] SurfaceAuthorizationError),
    #[error("rootless mapping permit does not bind this mapping: {0}")]
    Permit(#[from] SurfaceExecutionError),
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
        let uid_range = first_subid_range(Path::new("/etc/subuid"), &username, uid.as_raw())?;
        let gid_range = first_subid_range(Path::new("/etc/subgid"), &username, gid.as_raw())?;

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
/// Apply mappings only while consuming an exact `rootless.mapping` permit.
///
/// The raw procfs writer is private: callers must first acquire a permit for
/// the canonical mapping resource and this function rejects permits for any
/// other action, resource, or generation before opening a mapping file.
pub fn apply_user_namespace_mappings_authorized(
    proc_root: &Path,
    pid: u32,
    config: &RootlessConfig,
    canonical_name: &str,
    generation: u64,
    permit: SurfacePermit,
) -> Result<(), RootlessError> {
    SurfaceAuthorization::validate_execution(
        &permit,
        Action::RootlessMapping,
        ResourceKind::RootlessMapping,
        canonical_name,
        generation,
    )?;
    let result = apply_user_namespace_mappings(proc_root, pid, config);
    permit.finish(result.is_ok())?;
    result
}

fn apply_user_namespace_mappings(
    proc_root: &Path,
    pid: u32,
    config: &RootlessConfig,
) -> Result<(), RootlessError> {
    let proc_pid_dir = proc_root.join(pid.to_string());

    write_setgroups(&proc_pid_dir.join("setgroups"))?;
    write_id_mapping(
        &proc_pid_dir.join("uid_map"),
        pid,
        &config.uid_mapping,
        "newuidmap",
    )?;
    write_id_mapping(
        &proc_pid_dir.join("gid_map"),
        pid,
        &config.gid_mapping,
        "newgidmap",
    )?;

    Ok(())
}

fn write_setgroups(path: &Path) -> Result<(), RootlessError> {
    match fs::write(path, b"deny\n") {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        // An unprivileged parent cannot always write this control before the
        // namespace's setuid `newgidmap` helper takes ownership. The helper
        // applies the kernel-required transition with the gid map below.
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(source) => Err(RootlessError::WriteMapping {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Write a single mapping directly when the kernel permits it. Subordinate-ID
/// mappings require the setuid helper on ordinary unprivileged hosts; using it
/// here keeps the production mapping path pointed at the real procfs target.
fn write_id_mapping(
    path: &Path,
    pid: u32,
    mapping: &RootlessMapping,
    helper: &'static str,
) -> Result<(), RootlessError> {
    match fs::write(path, mapping.as_uid_map_entry()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let helper_path = trusted_executable_path(helper).ok_or_else(|| {
                RootlessError::LaunchMappingHelper {
                    helper,
                    source: io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{helper} is unavailable or not a trusted root-owned executable"),
                    ),
                }
            })?;
            let status = Command::new(helper_path)
                .args([
                    pid.to_string(),
                    mapping.container_id.to_string(),
                    mapping.host_id.to_string(),
                    mapping.size.to_string(),
                ])
                .status()
                .map_err(|source| RootlessError::LaunchMappingHelper { helper, source })?;
            if status.success() {
                Ok(())
            } else {
                Err(RootlessError::MappingHelperRejected { helper })
            }
        }
        Err(source) => Err(RootlessError::WriteMapping {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Resolve mapping helpers without trusting an attacker-controlled PATH entry.
/// The setuid helpers must be regular, executable, root-owned files that are
/// not writable by group or other users.
pub(crate) fn trusted_executable_path(helper: &str) -> Option<PathBuf> {
    let mut candidates = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(helper))
                .collect::<Vec<_>>()
        })
        .chain([
            PathBuf::from("/usr/local/bin").join(helper),
            PathBuf::from("/usr/bin").join(helper),
            PathBuf::from("/usr/sbin").join(helper),
            PathBuf::from("/bin").join(helper),
            PathBuf::from("/sbin").join(helper),
        ]);
    candidates.find(|candidate| {
        let Ok(metadata) = fs::metadata(candidate) else {
            return false;
        };
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            metadata.uid() == 0
                && metadata.permissions().mode() & 0o111 != 0
                && metadata.permissions().mode() & 0o022 == 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    })
}

fn first_subid_range(
    path: &Path,
    username: &str,
    numeric_id: u32,
) -> Result<Option<IdRange>, RootlessError> {
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

    first_subid_range_in(&raw, username, numeric_id)
}

/// Resolve the caller's first subordinate range from file contents so
/// installer flows can plan against fixture content without reading `/etc`.
pub(crate) fn first_subid_range_in(
    raw: &str,
    username: &str,
    numeric_id: u32,
) -> Result<Option<IdRange>, RootlessError> {
    let numeric_id = numeric_id.to_string();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let parsed = parse_subid_line(line)?;
        if parsed.0 == username || parsed.0 == numeric_id {
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

    // SEC-07: Prevent integer overflow - validate ranges are reasonable
    // start should be well below u32::MAX to prevent overflow in start + count
    if start > u32::MAX - 1_000_000 {
        return Err(RootlessError::InvalidSubIdLine(format!(
            "start value {} is too large",
            start
        )));
    }
    // count should be reasonably bounded (max ~1M subuids)
    if count > 1_000_000 {
        return Err(RootlessError::InvalidSubIdLine(format!(
            "count value {} is too large",
            count
        )));
    }
    // Verify start + count doesn't overflow
    if start.checked_add(count).is_none() {
        return Err(RootlessError::InvalidSubIdLine(format!(
            "start + count would overflow: {} + {}",
            start, count
        )));
    }

    Ok((name.to_string(), start, count))
}

#[cfg(test)]
mod tests {
    use super::{
        apply_user_namespace_mappings, first_subid_range, parse_subid_line,
        trusted_executable_path, RootlessConfig, RootlessMapping,
    };
    use std::fs;
    use std::path::Path;
    const DEFAULT_SUBID_SIZE: u32 = 65_536;

    #[test]
    fn bwrap_probe_cache_round_trip_and_invalidation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let binary = temp.path().join("bwrap");
        fs::write(&binary, b"#!/bin/sh\ntrue\n").expect("write fake bwrap");
        let cache = temp.path().join("probe-cache");

        let identity = super::bwrap_probe_identity(&binary);
        assert!(!identity.is_empty());
        assert!(super::read_bwrap_probe_cache(&cache).is_none());

        super::write_bwrap_probe_cache(&cache, &identity);
        assert_eq!(
            super::read_bwrap_probe_cache(&cache).as_deref(),
            Some(identity.as_str())
        );

        // Replace the binary: size (and likely mtime) change, so the cached
        // identity must no longer match.
        fs::write(&binary, b"#!/bin/sh\nexit 1\n").expect("rewrite fake bwrap");
        assert_ne!(super::bwrap_probe_identity(&binary), identity);
    }

    #[test]
    fn bwrap_probe_identity_missing_binary_is_empty() {
        assert!(super::bwrap_probe_identity(Path::new("/nonexistent/bwrap")).is_empty());
    }

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
        assert!(err
            .to_string()
            .contains("failed to parse subordinate id line"));
    }

    #[test]
    fn resolves_numeric_subordinate_id_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("subuid");
        fs::write(&path, "4242:200000:65536\n").expect("write subuid");

        let range = first_subid_range(&path, "tester", 4242)
            .expect("numeric owner parses")
            .expect("numeric owner matches");
        assert_eq!(
            range,
            super::IdRange {
                start: 200_000,
                count: 65_536
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_untrusted_mapping_helper_from_path() {
        let _env_guard = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let helper = temp.path().join("newuidmap");
        fs::write(&helper, "#!/bin/sh\nexit 0\n").expect("write helper");
        use std::os::unix::fs::PermissionsExt;
        // Keep the fixture untrusted even when the test suite runs as root:
        // temporary files are root-owned in that case, so ownership alone
        // would otherwise satisfy the production trust predicate.
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o777)).expect("executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", temp.path());
        let resolved = trusted_executable_path("newuidmap");
        assert!(resolved.as_deref() != Some(helper.as_path()));
        match old_path {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_untrusted_bubblewrap_from_path() {
        let _env_guard = crate::test_support::acquire_env_lock();
        let temp = tempfile::tempdir().expect("tempdir");
        let bwrap = temp.path().join("bwrap");
        fs::write(&bwrap, "#!/bin/sh\nexit 0\n").expect("write bwrap");
        use std::os::unix::fs::PermissionsExt;
        // A root-owned temporary 0755 helper is trusted when tests run under
        // sudo.  Group/other write permission makes this fixture untrusted in
        // both rootful and unprivileged test environments.
        fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o777)).expect("executable");
        let old_path = std::env::var_os("PATH");
        std::env::set_var("PATH", temp.path());
        let resolved = super::bubblewrap_path();
        assert!(resolved.as_deref() != Some(bwrap.as_path()));
        match old_path {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn subid_message_selection_matches_each_missing_prerequisite() {
        assert!(super::subid_prerequisite_message("tester", true, true).is_none());

        let missing_subuid =
            super::subid_prerequisite_message("tester", false, true).expect("subuid message");
        assert!(missing_subuid.contains("/etc/subuid"));
        assert!(missing_subuid.contains("--add-subuids 100000-165535 tester"));
        assert!(!missing_subuid.contains("--add-subgids"));

        let missing_subgid =
            super::subid_prerequisite_message("tester", true, false).expect("subgid message");
        assert!(missing_subgid.contains("/etc/subgid"));
        assert!(missing_subgid.contains("--add-subgids 100000-165535 tester"));
        assert!(!missing_subgid.contains("--add-subuids"));

        let missing_both =
            super::subid_prerequisite_message("tester", false, false).expect("both message");
        assert!(missing_both.contains("--add-subuids"));
        assert!(missing_both.contains("--add-subgids"));
        assert!(missing_both.contains("single-ID mapping"));
    }

    #[test]
    fn cgroup_probe_reports_missing_v2_hierarchy_with_probed_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let error = super::cgroup_delegation_probe(temp.path()).expect_err("no v2 hierarchy");
        let message = error.to_string();
        assert!(message.contains("cgroup v2 hierarchy is unavailable"));
        assert!(message.contains(temp.path().display().to_string().as_str()));
    }

    #[test]
    fn cgroup_probe_accepts_delegated_subtree() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("cgroup.controllers"), "cpu memory pids")
            .expect("seed controllers");
        fs::write(temp.path().join("cgroup.subtree_control"), "").expect("seed subtree control");
        super::cgroup_delegation_probe(temp.path()).expect("delegated subtree passes");
    }

    #[cfg(unix)]
    #[test]
    fn cgroup_probe_reports_undelegated_subtree_with_exact_commands() {
        if nix::unistd::Uid::effective().is_root() {
            // Root bypasses file permissions, so an undelegated fixture
            // cannot be simulated reliably.
            return;
        }
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("cgroup.controllers"), "cpu memory pids")
            .expect("seed controllers");
        let subtree = temp.path().join("cgroup.subtree_control");
        fs::write(&subtree, "").expect("seed subtree control");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&subtree, fs::Permissions::from_mode(0o444))
            .expect("read-only subtree control");
        let error = super::cgroup_delegation_probe(temp.path()).expect_err("undelegated subtree");
        let message = error.to_string();
        assert!(message.contains("not delegated"));
        assert!(message.contains("loginctl enable-linger"));
        assert!(message.contains("systemctl set-property user-$(id -u).slice Delegate=yes"));
        assert!(message.contains("FERROCRATE_CGROUP_ROOT"));
        assert!(message.contains(subtree.display().to_string().as_str()));
    }

    #[test]
    fn cgroup_not_delegated_message_names_the_probed_file() {
        let message = super::cgroup_not_delegated_message(Path::new(
            "/sys/fs/cgroup/user.slice/cgroup.subtree_control",
        ));
        assert!(message.contains("probed /sys/fs/cgroup/user.slice/cgroup.subtree_control"));
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
