//! Test isolation utilities for ensuring clean test environments.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;

/// Guard for temporary directory cleanup
pub struct TempDirGuard {
    temp_dir: TempDir,
}

impl TempDirGuard {
    pub fn new() -> std::io::Result<Self> {
        Ok(Self {
            temp_dir: tempfile::tempdir()?,
        })
    }

    pub fn path(&self) -> &Path {
        self.temp_dir.path()
    }

    pub fn into_path(self) -> PathBuf {
        self.temp_dir.into_path()
    }
}

impl Default for TempDirGuard {
    fn default() -> Self {
        Self::new().expect("Failed to create temp directory")
    }
}

/// Guard for container cleanup
pub struct ContainerGuard {
    container_id: String,
    cleaned: bool,
}

impl ContainerGuard {
    pub fn new(container_id: impl Into<String>) -> Self {
        Self {
            container_id: container_id.into(),
            cleaned: false,
        }
    }

    /// Mark container as cleaned (prevent double cleanup)
    pub fn mark_cleaned(&mut self) {
        self.cleaned = true;
    }
}

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            // Implementation would stop/remove container
            // ferro_core::container::stop(&self.container_id).ok();
        }
    }
}

/// Guard for network cleanup
pub struct NetworkGuard {
    network_name: String,
    cleaned: bool,
}

impl NetworkGuard {
    pub fn new(network_name: impl Into<String>) -> Self {
        Self {
            network_name: network_name.into(),
            cleaned: false,
        }
    }

    pub fn mark_cleaned(&mut self) {
        self.cleaned = true;
    }
}

impl Drop for NetworkGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            // Implementation would remove network
            // ferro_net::network::remove(&self.network_name).ok();
        }
    }
}

/// Guard for image cleanup
pub struct ImageGuard {
    image_id: String,
    cleaned: bool,
}

impl ImageGuard {
    pub fn new(image_id: impl Into<String>) -> Self {
        Self {
            image_id: image_id.into(),
            cleaned: false,
        }
    }

    pub fn mark_cleaned(&mut self) {
        self.cleaned = true;
    }
}

impl Drop for ImageGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            // Implementation would remove image
            // ferro_core::image::remove(&self.image_id).ok();
        }
    }
}

/// Composite guard for multiple resources
pub struct CompositeGuard {
    guards: Vec<Box<dyn Send + Drop>>,
}

impl CompositeGuard {
    pub fn new() -> Self {
        Self { guards: Vec::new() }
    }

    pub fn add<G: Send + Drop + 'static>(&mut self, guard: G) {
        self.guards.push(Box::new(guard));
    }
}

impl Default for CompositeGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_dir_guard_creates_directory() {
        let guard = TempDirGuard::new().expect("create temp dir");
        assert!(guard.path().exists());
        assert!(guard.path().is_dir());
    }

    #[test]
    fn container_guard_tracks_cleanup() {
        let mut guard = ContainerGuard::new("test-container");
        assert!(!guard.cleaned);
        guard.mark_cleaned();
        assert!(guard.cleaned);
    }
}
