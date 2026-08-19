use serde::Serialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

const CGROUP_CONTROLLERS: &str = "cgroup.controllers";
const CGROUP_SUBTREE_CONTROL: &str = "cgroup.subtree_control";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceLimits {
    pub memory_max: Option<u64>,
    pub cpu_max: Option<CpuMax>,
    pub pids_max: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuMax {
    pub quota: u64,
    pub period: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct CgroupStats {
    pub memory_current: Option<u64>,
    pub memory_max: Option<u64>,
    pub pids_current: Option<u64>,
    /// Number of times this cgroup hit its `pids.max` ceiling.
    pub pids_limit_reached: Option<u64>,
    pub cpu_usage_usec: Option<u64>,
    pub cpu_user_usec: Option<u64>,
    pub cpu_system_usec: Option<u64>,
}

#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("path is not a cgroups v2 hierarchy: {0}")]
    NotV2(PathBuf),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct CgroupV2Manager {
    root: PathBuf,
}

impl CgroupV2Manager {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn ensure_v2_available(&self) -> Result<(), CgroupError> {
        if self.root.join(CGROUP_CONTROLLERS).exists() {
            if !nix::unistd::Uid::effective().is_root()
                && self.root.starts_with("/sys/fs/cgroup")
                && fs::OpenOptions::new()
                    .write(true)
                    .open(self.root.join(CGROUP_SUBTREE_CONTROL))
                    .is_err()
            {
                return Err(CgroupError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "rootless cgroup path is not delegated: {}; launch under a delegated user scope or set FERROCRATE_CGROUP_ROOT",
                        self.root.display()
                    ),
                )));
            }
            Ok(())
        } else {
            Err(CgroupError::NotV2(self.root.clone()))
        }
    }

    pub fn create_group(&self, name: &str) -> Result<PathBuf, CgroupError> {
        self.ensure_v2_available()?;

        // Security: Validate cgroup name to prevent path traversal
        // Allow subdirectories (e.g., "containers/test") but prevent escape
        if name.is_empty() || name.starts_with('/') || name.contains("..") || name.contains('\0') {
            return Err(CgroupError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid cgroup name: contains path traversal or invalid characters",
            )));
        }
        // Reject backslashes and check each path segment
        if name.contains('\\') {
            return Err(CgroupError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid cgroup name: backslashes not allowed",
            )));
        }
        // Validate each segment (between slashes) is non-empty and valid
        for segment in name.split('/') {
            if segment.is_empty() {
                return Err(CgroupError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid cgroup name: empty path segment",
                )));
            }
        }

        let group_path = self.root.join(name);
        fs::create_dir_all(&group_path).map_err(|error| {
            io::Error::new(error.kind(), format!("{}: {error}", group_path.display()))
        })?;
        Ok(group_path)
    }

    pub fn apply_limits(
        &self,
        group_path: impl AsRef<Path>,
        limits: &ResourceLimits,
    ) -> Result<(), CgroupError> {
        let group_path = group_path.as_ref();

        let mut controllers = Vec::new();
        if limits.memory_max.is_some() {
            controllers.push("memory");
        }
        if limits.cpu_max.is_some() {
            controllers.push("cpu");
        }
        if limits.pids_max.is_some() {
            controllers.push("pids");
        }
        if !controllers.is_empty() {
            let parent = group_path
                .parent()
                .filter(|path| path.join(CGROUP_CONTROLLERS).exists())
                .unwrap_or(&self.root);
            let available = fs::read_to_string(parent.join(CGROUP_CONTROLLERS)).unwrap_or_default();
            if controllers
                .iter()
                .any(|controller| !available.split_whitespace().any(|item| item == *controller))
            {
                return Err(CgroupError::Io(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!(
                        "requested cgroup controller is unavailable below {}",
                        parent.display()
                    ),
                )));
            }
            let subtree_control = parent.join(CGROUP_SUBTREE_CONTROL);
            if subtree_control.exists() {
                let enable = controllers
                    .iter()
                    .map(|controller| format!("+{controller}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                write_cgroup_file(&subtree_control, format!("{enable}\n"))?;
            }
        }

        if let Some(memory_max) = limits.memory_max {
            write_cgroup_file(&group_path.join("memory.max"), memory_max.to_string())?;
        }

        if let Some(cpu_max) = &limits.cpu_max {
            write_cgroup_file(
                group_path.join("cpu.max"),
                format!("{} {}", cpu_max.quota, cpu_max.period),
            )?;
        }

        if let Some(pids_max) = limits.pids_max {
            write_cgroup_file(&group_path.join("pids.max"), pids_max.to_string())?;
        }

        Ok(())
    }

    /// Replace the complete resource-limit contract for an existing group.
    ///
    /// Unlike [`Self::apply_limits`], which is intentionally launch-oriented
    /// and only writes requested controllers, this operation also clears a
    /// previously configured controller when its new value is `None`.  That
    /// distinction is required by Docker-compatible live resource updates:
    /// omitted limits mean "unlimited", not "leave the old limit in place".
    /// Controller availability and path validation still happen before any
    /// requested limit is written.
    pub fn replace_limits(
        &self,
        group_path: impl AsRef<Path>,
        limits: &ResourceLimits,
    ) -> Result<(), CgroupError> {
        let group_path = group_path.as_ref();
        if !group_path.is_dir() {
            return Err(CgroupError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("cgroup group does not exist: {}", group_path.display()),
            )));
        }

        // Reuse the launch path for controller admission and requested values.
        // It performs the availability check before writing any requested
        // controller, preserving fail-closed behavior on delegated cgroups.
        self.apply_limits(group_path, limits)?;

        if limits.memory_max.is_none() {
            let path = group_path.join("memory.max");
            if path.exists() {
                fs::write(path, "max")?;
            }
        }

        if limits.cpu_max.is_none() {
            let path = group_path.join("cpu.max");
            if path.exists() {
                // cgroup v2 requires a period even for an unlimited quota.
                // Preserve the current period when possible, otherwise use
                // the kernel's conventional 100ms period.
                let period = fs::read_to_string(&path)
                    .ok()
                    .and_then(|value| value.split_whitespace().nth(1)?.parse::<u64>().ok())
                    .filter(|period| *period > 0)
                    .unwrap_or(100_000);
                fs::write(path, format!("max {period}"))?;
            }
        }

        if limits.pids_max.is_none() {
            let path = group_path.join("pids.max");
            if path.exists() {
                fs::write(path, "max")?;
            }
        }

        Ok(())
    }

    pub fn add_pid(&self, group_path: impl AsRef<Path>, pid: u32) -> Result<(), CgroupError> {
        let group_path = group_path.as_ref();
        let procs_path = group_path.join("cgroup.procs");
        if !procs_path.exists() {
            fs::write(&procs_path, "")?;
        }
        fs::write(procs_path, pid.to_string())?;
        Ok(())
    }

    pub fn freeze(&self, group_path: impl AsRef<Path>) -> Result<(), CgroupError> {
        let group_path = group_path.as_ref();
        fs::write(group_path.join("cgroup.freeze"), "1")?;
        Ok(())
    }

    pub fn thaw(&self, group_path: impl AsRef<Path>) -> Result<(), CgroupError> {
        let group_path = group_path.as_ref();
        fs::write(group_path.join("cgroup.freeze"), "0")?;
        Ok(())
    }

    pub fn read_stats(&self, group_path: impl AsRef<Path>) -> Result<CgroupStats, CgroupError> {
        let group_path = group_path.as_ref();
        let memory_current = read_u64(group_path.join("memory.current"))?;
        let memory_max = read_u64_allow_max(group_path.join("memory.max"))?;
        let pids_current = read_u64(group_path.join("pids.current"))?;
        let pids_limit_reached = read_event_counter(group_path.join("pids.events"), "max")?;
        let (cpu_usage_usec, cpu_user_usec, cpu_system_usec) =
            read_cpu_stat(group_path.join("cpu.stat"))?;

        Ok(CgroupStats {
            memory_current,
            memory_max,
            pids_current,
            pids_limit_reached,
            cpu_usage_usec,
            cpu_user_usec,
            cpu_system_usec,
        })
    }

    /// Adjust the memory limit for a cgroup (Task 5.1 - OOM Prevention).
    ///
    /// This can be used to dynamically increase memory limits when OOM is predicted.
    /// The new limit must be >= current usage to avoid immediate OOM.
    pub fn adjust_memory_limit(
        &self,
        group_path: impl AsRef<Path>,
        new_limit: u64,
    ) -> Result<(), CgroupError> {
        let group_path = group_path.as_ref();
        let memory_max_path = group_path.join("memory.max");

        // Ensure the cgroup exists
        if !memory_max_path.exists() {
            return Err(CgroupError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cgroup memory.max not found",
            )));
        }

        // Read current usage to validate
        if let Some(current) = read_u64(group_path.join("memory.current"))? {
            if new_limit < current {
                return Err(CgroupError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("new limit {} is below current usage {}", new_limit, current),
                )));
            }
        }

        fs::write(memory_max_path, new_limit.to_string())?;
        Ok(())
    }

    /// Check whether runtime AI inference is enabled.
    ///
    /// Inference defaults to enabled, matching `AiConfig::from_env`; setting
    /// `FERROCRATE_AI=0` or `FERROCRATE_AI=false` opts out.
    pub fn is_ai_enabled() -> bool {
        ferro_mind::ai::config::AiConfig::from_env().enabled
    }
}

/// Preserve the kernel path in cgroup setup failures.  A bare `Permission
/// denied` is not actionable on delegated hierarchies because the controller
/// enable, limit write, and process attach operations have different remedies.
fn write_cgroup_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    fs::write(path, contents)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))
}

fn read_u64(path: PathBuf) -> Result<Option<u64>, CgroupError> {
    if !path.exists() {
        return Ok(None);
    }
    let value = fs::read_to_string(path)?;
    let parsed = value.trim().parse::<u64>().ok();
    Ok(parsed)
}

fn read_u64_allow_max(path: PathBuf) -> Result<Option<u64>, CgroupError> {
    if !path.exists() {
        return Ok(None);
    }
    let value = fs::read_to_string(path)?;
    let trimmed = value.trim();
    if trimmed == "max" {
        return Ok(None);
    }
    Ok(trimmed.parse::<u64>().ok())
}

fn read_event_counter(path: PathBuf, key: &str) -> Result<Option<u64>, CgroupError> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some(key) {
            continue;
        }
        let value = fields.next().ok_or_else(|| {
            CgroupError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing {key} counter in {}", path.display()),
            ))
        })?;
        let parsed = value.parse::<u64>().map_err(|error| {
            CgroupError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid {key} counter in {}: {error}", path.display()),
            ))
        })?;
        return Ok(Some(parsed));
    }
    Ok(None)
}

type CpuStat = (Option<u64>, Option<u64>, Option<u64>);

fn read_cpu_stat(path: PathBuf) -> Result<CpuStat, CgroupError> {
    if !path.exists() {
        return Ok((None, None, None));
    }
    let content = fs::read_to_string(path)?;
    let mut usage = None;
    let mut user = None;
    let mut system = None;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        let parsed = value.parse::<u64>().ok();
        match key {
            "usage_usec" => usage = parsed,
            "user_usec" => user = parsed,
            "system_usec" => system = parsed,
            _ => {}
        }
    }
    Ok((usage, user, system))
}

#[cfg(test)]
mod tests {
    use super::{CgroupStats, CgroupV2Manager, CpuMax, ResourceLimits};
    use std::fs;
    use std::sync::{Mutex, OnceLock};

    fn ai_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn creates_group_and_applies_limits() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();

        fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager
            .create_group("containers/test")
            .expect("group created");

        let limits = ResourceLimits {
            memory_max: Some(536_870_912),
            cpu_max: Some(CpuMax {
                quota: 100_000,
                period: 100_000,
            }),
            pids_max: Some(256),
        };

        manager
            .apply_limits(&group, &limits)
            .expect("limits applied");

        assert_eq!(
            fs::read_to_string(group.join("memory.max")).expect("memory.max"),
            "536870912"
        );
        assert_eq!(
            fs::read_to_string(group.join("cpu.max")).expect("cpu.max"),
            "100000 100000"
        );
        assert_eq!(
            fs::read_to_string(group.join("pids.max")).expect("pids.max"),
            "256"
        );
    }

    #[test]
    fn replaces_limits_and_restores_unlimited_controllers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager
            .create_group("containers/update")
            .expect("group created");
        manager
            .apply_limits(
                &group,
                &ResourceLimits {
                    memory_max: Some(64 * 1024 * 1024),
                    cpu_max: Some(CpuMax {
                        quota: 50_000,
                        period: 100_000,
                    }),
                    pids_max: Some(32),
                },
            )
            .expect("initial limits applied");

        manager
            .replace_limits(
                &group,
                &ResourceLimits {
                    memory_max: None,
                    cpu_max: None,
                    pids_max: Some(64),
                },
            )
            .expect("replacement limits applied");

        assert_eq!(fs::read_to_string(group.join("memory.max")).unwrap(), "max");
        assert_eq!(
            fs::read_to_string(group.join("cpu.max")).unwrap(),
            "max 100000"
        );
        assert_eq!(fs::read_to_string(group.join("pids.max")).unwrap(), "64");
    }

    #[test]
    fn enables_only_requested_available_controllers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        fs::write(root.join("cgroup.controllers"), "memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager
            .create_group("containers/test")
            .expect("group created");
        manager
            .apply_limits(
                &group,
                &ResourceLimits {
                    memory_max: Some(1024),
                    cpu_max: None,
                    pids_max: Some(4),
                },
            )
            .expect("available limits applied");
        assert_eq!(
            fs::read_to_string(root.join("cgroup.subtree_control")).unwrap(),
            "+memory +pids\n"
        );
    }

    #[test]
    fn rejects_unavailable_requested_controller_before_writing_limits() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        fs::write(root.join("cgroup.controllers"), "memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager
            .create_group("containers/test")
            .expect("group created");
        let error = manager
            .apply_limits(
                &group,
                &ResourceLimits {
                    memory_max: None,
                    cpu_max: Some(CpuMax {
                        quota: 1,
                        period: 1,
                    }),
                    pids_max: None,
                },
            )
            .expect_err("unavailable CPU must fail closed");
        assert!(error.to_string().contains("controller is unavailable"));
    }

    #[test]
    fn adds_pid_to_group() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();

        fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager
            .create_group("containers/test")
            .expect("group created");

        manager.add_pid(&group, 4242).expect("add pid");
        assert_eq!(
            fs::read_to_string(group.join("cgroup.procs")).expect("read cgroup.procs"),
            "4242"
        );
    }

    #[test]
    fn freezes_and_thaws_group() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();

        fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager
            .create_group("containers/test")
            .expect("group created");

        manager.freeze(&group).expect("freeze");
        assert_eq!(
            fs::read_to_string(group.join("cgroup.freeze")).expect("read freeze"),
            "1"
        );

        manager.thaw(&group).expect("thaw");
        assert_eq!(
            fs::read_to_string(group.join("cgroup.freeze")).expect("read freeze"),
            "0"
        );
    }

    #[test]
    fn rejects_non_v2_hierarchy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = CgroupV2Manager::new(temp.path());

        let err = manager.ensure_v2_available().expect_err("should fail");
        assert!(err.to_string().contains("not a cgroups v2 hierarchy"));
    }

    #[test]
    fn reads_stats() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let group = root.join("ferrocrate/test");
        fs::create_dir_all(&group).expect("group dir");

        fs::write(group.join("memory.current"), "123").expect("memory.current");
        fs::write(group.join("memory.max"), "max").expect("memory.max");
        fs::write(group.join("pids.current"), "7").expect("pids.current");
        fs::write(group.join("pids.events"), "max 3\n").expect("pids.events");
        fs::write(
            group.join("cpu.stat"),
            "usage_usec 100\nuser_usec 40\nsystem_usec 60\n",
        )
        .expect("cpu.stat");

        let manager = CgroupV2Manager::new(root);
        let stats = manager.read_stats(&group).expect("stats");

        let expected = CgroupStats {
            memory_current: Some(123),
            memory_max: None,
            pids_current: Some(7),
            pids_limit_reached: Some(3),
            cpu_usage_usec: Some(100),
            cpu_user_usec: Some(40),
            cpu_system_usec: Some(60),
        };
        assert_eq!(stats, expected);
    }

    #[test]
    fn ai_enablement_matches_runtime_default_and_opt_out() {
        let _guard = ai_env_lock().lock().expect("AI env lock");
        let previous = std::env::var("FERROCRATE_AI").ok();
        unsafe {
            std::env::remove_var("FERROCRATE_AI");
        }
        assert!(CgroupV2Manager::is_ai_enabled());
        unsafe {
            std::env::set_var("FERROCRATE_AI", "0");
        }
        assert!(!CgroupV2Manager::is_ai_enabled());
        match previous {
            Some(value) => unsafe { std::env::set_var("FERROCRATE_AI", value) },
            None => unsafe { std::env::remove_var("FERROCRATE_AI") },
        }
    }
}
