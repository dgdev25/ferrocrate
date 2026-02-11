use nix::mount::{MsFlags, mount};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Error)]
pub enum MountError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mount error: {0}")]
    Mount(#[from] nix::Error),
}

pub fn apply_bind_mounts(rootfs: &Path, mounts: &[BindMount]) -> Result<(), MountError> {
    for mount_spec in mounts {
        let target = rootfs.join(&mount_spec.target);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            std::fs::create_dir_all(&target)?;
        }

        mount(
            Some(&mount_spec.source),
            &target,
            Some("bind"),
            MsFlags::MS_BIND,
            None::<&str>,
        )?;

        if mount_spec.read_only {
            mount(
                Some(&mount_spec.source),
                &target,
                Some("bind"),
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None::<&str>,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BindMount, apply_bind_mounts};
    use std::fs;

    #[test]
    fn bind_mount_struct_is_constructible() {
        let mount = BindMount {
            source: "/tmp/source".into(),
            target: "/data".into(),
            read_only: true,
        };
        assert_eq!(mount.source, std::path::PathBuf::from("/tmp/source"));
    }

    #[test]
    #[ignore]
    fn apply_bind_mounts_smoke() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(&rootfs).expect("rootfs");

        let source = temp.path().join("source");
        fs::create_dir_all(&source).expect("source");

        let mounts = vec![BindMount {
            source: source.clone(),
            target: "data".into(),
            read_only: false,
        }];

        apply_bind_mounts(&rootfs, &mounts).expect("bind mount");
    }
}
