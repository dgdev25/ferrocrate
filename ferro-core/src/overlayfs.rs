use nix::errno::Errno;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
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
    #[error("fuse-overlayfs binary not found in PATH")]
    FuseOverlayBinaryMissing,
    #[error("fuse-overlayfs mount failed with status {status}: {stderr}")]
    FuseOverlayFailed { status: i32, stderr: String },
    #[error("fuse-overlayfs command timed out after {0:?}")]
    Timeout(Duration),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayBackend {
    KernelOverlayFs,
    FuseOverlayFs,
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

    /// Mount rootfs and automatically fallback to fuse-overlayfs when kernel overlayfs is unavailable.
    pub fn mount_with_fallback(config: &OverlayMountConfig) -> Result<OverlayBackend, OverlayFsError> {
        match Self::mount_rootless(config) {
            Ok(()) => Ok(OverlayBackend::KernelOverlayFs),
            Err(OverlayFsError::RootlessKernelUnsupported) => {
                Self::mount_with_fuse_overlayfs(config)?;
                Ok(OverlayBackend::FuseOverlayFs)
            }
            Err(err) => Err(err),
        }
    }

    // SEC-05: Default timeout for fuse-overlayfs mount (30 seconds)
    const FUSE_OVERLAY_TIMEOUT: Duration = Duration::from_secs(30);

    fn mount_with_fuse_overlayfs(config: &OverlayMountConfig) -> Result<(), OverlayFsError> {
        validate_config(config)?;

        // SEC-04: Canonicalize and validate all paths before use
        let upperdir = config.upperdir.canonicalize()
            .map_err(OverlayFsError::Io)?;
        let workdir = config.workdir.canonicalize()
            .map_err(OverlayFsError::Io)?;
        let merged_dir = config.merged_dir.canonicalize()
            .map_err(OverlayFsError::Io)?;

        // Check for null bytes in paths
        check_path_null_bytes(&upperdir)?;
        check_path_null_bytes(&workdir)?;
        check_path_null_bytes(&merged_dir)?;

        fs::create_dir_all(&upperdir)?;
        fs::create_dir_all(&workdir)?;
        fs::create_dir_all(&merged_dir)?;

        let args = build_fuse_overlayfs_args(config);

        // SEC-05: Execute fuse-overlayfs with timeout to prevent hanging
        let output = Self::execute_fuse_command_with_timeout("fuse-overlayfs", &args, Self::FUSE_OVERLAY_TIMEOUT)?;

        if !output.status.success() {
            return Err(OverlayFsError::FuseOverlayFailed {
                status: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }

        Ok(())
    }

    /// SEC-05: Execute fuse-overlayfs command with timeout to prevent blocking indefinitely
    fn execute_fuse_command_with_timeout(
        binary: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<std::process::Output, OverlayFsError> {
        let mut child = Command::new(binary)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    OverlayFsError::FuseOverlayBinaryMissing
                } else {
                    OverlayFsError::Io(e)
                }
            })?;

        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(OverlayFsError::Io)? {
                // Process completed - collect output
                let mut stdout = child.stdout.take().ok_or_else(|| {
                    OverlayFsError::Io(std::io::Error::other(
                        "failed to capture stdout",
                    ))
                })?;
                let mut stderr = child.stderr.take().ok_or_else(|| {
                    OverlayFsError::Io(std::io::Error::other(
                        "failed to capture stderr",
                    ))
                })?;

                use std::io::Read;
                let mut stdout_buf = Vec::new();
                let mut stderr_buf = Vec::new();
                stdout.read_to_end(&mut stdout_buf).map_err(OverlayFsError::Io)?;
                stderr.read_to_end(&mut stderr_buf).map_err(OverlayFsError::Io)?;

                return Ok(std::process::Output {
                    status,
                    stdout: stdout_buf,
                    stderr: stderr_buf,
                });
            }

            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(OverlayFsError::Timeout(timeout));
            }

            std::thread::sleep(Duration::from_millis(10));
        }
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

pub fn build_fuse_overlayfs_args(config: &OverlayMountConfig) -> Vec<String> {
    vec![
        "-o".to_string(),
        build_mount_options(config),
        config.merged_dir.display().to_string(),
    ]
}

/// SEC-04: Check for null bytes in path to prevent injection
fn check_path_null_bytes(path: &Path) -> Result<(), OverlayFsError> {
    if path.to_str().is_some_and(|s| s.contains('\0')) {
        return Err(OverlayFsError::InvalidConfig("path contains null byte"));
    }
    Ok(())
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
    use super::{
        OverlayMountConfig, build_fuse_overlayfs_args, build_mount_options, validate_config,
    };
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

    #[test]
    fn builds_fuse_overlayfs_args() {
        let config = sample_config();
        let args = build_fuse_overlayfs_args(&config);
        assert_eq!(args[0], "-o");
        assert_eq!(
            args[1],
            "lowerdir=/layers/l1:/layers/l0,upperdir=/run/containers/c1/upper,workdir=/run/containers/c1/work"
        );
        assert_eq!(args[2], "/run/containers/c1/rootfs");
    }
}
