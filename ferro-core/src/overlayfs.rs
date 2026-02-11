use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct OverlayMountConfig {
    pub lowerdirs: Vec<PathBuf>,
    pub upperdir: PathBuf,
    pub workdir: PathBuf,
    pub merged_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum OverlayFsError {
    #[error("invalid overlay mount config: {0}")]
    InvalidConfig(&'static str),
    #[error("filesystem setup failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("overlayfs mount failed: {0}")]
    Mount(#[from] nix::Error),
    #[error("overlayfs mount denied. rootless overlayfs needs kernel 5.11+ or FUSE fallback")]
    RootlessKernelUnsupported,
}

pub struct OverlayFsManager;

impl OverlayFsManager {
    pub fn mount_rootless(config: &OverlayMountConfig) -> Result<(), OverlayFsError> {
        validate_config(config)?;
        fs::create_dir_all(&config.upperdir)?;
        fs::create_dir_all(&config.workdir)?;
        fs::create_dir_all(&config.merged_dir)?;

        let options = build_mount_options(config);
        match mount(
            Some("overlay"),
            &config.merged_dir,
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        ) {
            Ok(()) => Ok(()),
            Err(err)
                if err == Errno::EPERM
                    || err == Errno::EINVAL
                    || err == Errno::ENODEV
                    || err == Errno::EOPNOTSUPP => Err(OverlayFsError::RootlessKernelUnsupported),
            Err(err) => Err(OverlayFsError::Mount(err)),
        }
    }

    pub fn unmount(merged_dir: &Path) -> Result<(), OverlayFsError> {
        umount2(merged_dir, MntFlags::MNT_DETACH)?;
        Ok(())
    }
}

pub fn build_mount_options(config: &OverlayMountConfig) -> String {
    let lower = config
        .lowerdirs
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":");

    format!(
        "lowerdir={},upperdir={},workdir={}",
        lower,
        config.upperdir.display(),
        config.workdir.display()
    )
}

fn validate_config(config: &OverlayMountConfig) -> Result<(), OverlayFsError> {
    if config.lowerdirs.is_empty() {
        return Err(OverlayFsError::InvalidConfig(
            "at least one lowerdir is required",
        ));
    }

    if config.upperdir == config.workdir {
        return Err(OverlayFsError::InvalidConfig(
            "upperdir and workdir must be different",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{OverlayMountConfig, build_mount_options, validate_config};
    use std::path::PathBuf;

    fn sample_config() -> OverlayMountConfig {
        OverlayMountConfig {
            lowerdirs: vec![PathBuf::from("/layers/l1"), PathBuf::from("/layers/l0")],
            upperdir: PathBuf::from("/run/containers/c1/upper"),
            workdir: PathBuf::from("/run/containers/c1/work"),
            merged_dir: PathBuf::from("/run/containers/c1/rootfs"),
        }
    }

    #[test]
    fn builds_overlay_mount_options() {
        let config = sample_config();
        let options = build_mount_options(&config);
        assert_eq!(
            options,
            "lowerdir=/layers/l1:/layers/l0,upperdir=/run/containers/c1/upper,workdir=/run/containers/c1/work"
        );
    }

    #[test]
    fn rejects_invalid_overlay_config() {
        let mut config = sample_config();
        config.lowerdirs.clear();
        let err = validate_config(&config).expect_err("must reject empty lowerdirs");
        assert!(err.to_string().contains("at least one lowerdir"));
    }
}
