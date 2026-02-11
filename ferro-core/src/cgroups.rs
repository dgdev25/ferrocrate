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
}

#[cfg(test)]
mod tests {
    use super::{CgroupV2Manager, CpuMax, ResourceLimits};
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
    fn rejects_non_v2_hierarchy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let manager = CgroupV2Manager::new(temp.path());

        let err = manager.ensure_v2_available().expect_err("should fail");
        assert!(err.to_string().contains("not a cgroups v2 hierarchy"));
    }
}
