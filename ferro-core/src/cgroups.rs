use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use serde::Serialize;
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
            Ok(())
        } else {
            Err(CgroupError::NotV2(self.root.clone()))
        }
    }

    pub fn create_group(&self, name: &str) -> Result<PathBuf, CgroupError> {
        self.ensure_v2_available()?;

        let group_path = self.root.join(name);
        fs::create_dir_all(&group_path)?;

        let subtree_control = self.root.join(CGROUP_SUBTREE_CONTROL);
        if subtree_control.exists() {
            let _ = fs::write(subtree_control, "+memory +cpu +pids\n");
        }

        Ok(group_path)
    }

    pub fn apply_limits(
        &self,
        group_path: impl AsRef<Path>,
        limits: &ResourceLimits,
    ) -> Result<(), CgroupError> {
        let group_path = group_path.as_ref();

        if let Some(memory_max) = limits.memory_max {
            fs::write(group_path.join("memory.max"), memory_max.to_string())?;
        }

        if let Some(cpu_max) = &limits.cpu_max {
            fs::write(
                group_path.join("cpu.max"),
                format!("{} {}", cpu_max.quota, cpu_max.period),
            )?;
        }

        if let Some(pids_max) = limits.pids_max {
            fs::write(group_path.join("pids.max"), pids_max.to_string())?;
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
        let (cpu_usage_usec, cpu_user_usec, cpu_system_usec) =
            read_cpu_stat(group_path.join("cpu.stat"))?;

        Ok(CgroupStats {
            memory_current,
            memory_max,
            pids_current,
            cpu_usage_usec,
            cpu_user_usec,
            cpu_system_usec,
        })
    }
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

fn read_cpu_stat(path: PathBuf) -> Result<(Option<u64>, Option<u64>, Option<u64>), CgroupError> {
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

    #[test]
    fn creates_group_and_applies_limits() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();

        fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager.create_group("containers/test").expect("group created");

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
    fn adds_pid_to_group() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();

        fs::write(root.join("cgroup.controllers"), "cpu memory pids").expect("seed controllers");
        fs::write(root.join("cgroup.subtree_control"), "").expect("seed subtree control");

        let manager = CgroupV2Manager::new(root);
        let group = manager.create_group("containers/test").expect("group created");

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
        let group = manager.create_group("containers/test").expect("group created");

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
            cpu_usage_usec: Some(100),
            cpu_user_usec: Some(40),
            cpu_system_usec: Some(60),
        };
        assert_eq!(stats, expected);
    }
}
