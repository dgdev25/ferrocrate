use nix::mount::{MsFlags, mount};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmpfsMount {
    pub target: PathBuf,
    pub size: Option<String>,
}

#[derive(Debug, Error)]
pub enum MountError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mount error: {0}")]
    Mount(#[from] nix::Error),
    #[error("invalid source path: {0}")]
    InvalidSource(String),
}

pub fn apply_bind_mounts(rootfs: &Path, mounts: &[BindMount]) -> Result<(), MountError> {
    for mount_spec in mounts {
        // Security: Canonicalize source path to resolve symlinks
        // This prevents symlink-based attacks where an attacker could create
        // a symlink to escape the rootfs
        let source = mount_spec.source.canonicalize()
            .map_err(|e| MountError::InvalidSource(
                format!("failed to canonicalize source {:?}: {}", mount_spec.source, e)
            ))?;

        let target = rootfs.join(&mount_spec.target);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            std::fs::create_dir_all(&target)?;
        }

        mount(
            Some(&source),
            &target,
            Some("bind"),
            MsFlags::MS_BIND,
            None::<&str>,
        )?;

        if mount_spec.read_only {
            mount(
                Some(&source),
                &target,
                Some("bind"),
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None::<&str>,
            )?;
        }
    }
    Ok(())
}

pub fn apply_tmpfs_mounts(rootfs: &Path, mounts: &[TmpfsMount]) -> Result<(), MountError> {
    for mount_spec in mounts {
        let target = rootfs.join(&mount_spec.target);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !target.exists() {
            std::fs::create_dir_all(&target)?;
        }

        let data = mount_spec.size.as_ref().map(|size| format!("size={size}"));
        mount(
            None::<&Path>,
            &target,
            Some("tmpfs"),
            MsFlags::empty(),
            data.as_deref(),
        )?;
    }
    Ok(())
}

pub fn apply_readonly_rootfs(rootfs: &Path) -> Result<(), MountError> {
    mount(
        Some(rootfs),
        rootfs,
        Some("bind"),
        MsFlags::MS_BIND,
        None::<&str>,
    )?;
    mount(
        Some(rootfs),
        rootfs,
        Some("bind"),
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BindMount, TmpfsMount, apply_bind_mounts};
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
    fn tmpfs_mount_struct_is_constructible() {
        let mount = TmpfsMount {
            target: "/tmp".into(),
            size: Some("64m".to_string()),
        };
        assert_eq!(mount.target, std::path::PathBuf::from("/tmp"));
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
