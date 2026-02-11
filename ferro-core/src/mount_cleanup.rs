use crate::overlayfs::OverlayFsManager;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MountCleanupError {
    #[error("failed to clean container mount state: {0}")]
    Io(#[from] std::io::Error),
}

/// Cleanup mount-related paths for a container.
/// This attempts unmount first and then removes mount state directories.
pub fn cleanup_container_mount(runtime_dir: &Path, container_id: &str) -> Result<(), MountCleanupError> {
    let container_dir = runtime_dir.join("containers").join(container_id);
    let merged = container_dir.join("rootfs");

    if merged.exists() {
        let _ = OverlayFsManager::unmount(&merged);
    }

    remove_if_exists(&container_dir.join("rootfs"))?;
    remove_if_exists(&container_dir.join("upper"))?;
    remove_if_exists(&container_dir.join("work"))?;

    if container_dir.exists() && fs::read_dir(&container_dir)?.next().is_none() {
        fs::remove_dir(&container_dir)?;
    }

    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), MountCleanupError> {
    if !path.exists() {
        return Ok(());
    }

    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::cleanup_container_mount;
    use std::fs;

    #[test]
    fn removes_container_mount_directories() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = temp.path();
        let container_dir = runtime.join("containers").join("c123");

        fs::create_dir_all(container_dir.join("rootfs")).expect("create rootfs");
        fs::create_dir_all(container_dir.join("upper")).expect("create upper");
        fs::create_dir_all(container_dir.join("work")).expect("create work");

        cleanup_container_mount(runtime, "c123").expect("cleanup should succeed");

        assert!(!container_dir.join("rootfs").exists());
        assert!(!container_dir.join("upper").exists());
        assert!(!container_dir.join("work").exists());
        assert!(!container_dir.exists());
    }

    #[test]
    fn cleanup_is_idempotent_for_missing_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        cleanup_container_mount(temp.path(), "missing").expect("cleanup should succeed");
    }
}
