//! FerroCrate Core - AI-native container runtime library.
//!
//! This crate provides the core container runtime functionality including:
//! - Container lifecycle management (creation, execution, stopping)
//! - Image handling (pull, store, layer management)
//! - Security (capabilities, seccomp, entitlements)
//! - AI runtime integration (anomaly detection, OOM prediction)
//!
//! ## Feature Flags
//!
//! - `linux` (enabled by default on Linux targets): Full container runtime support
//!
//! ## Example
//!
//! ```ignore
//! use ferro_core::runtime::FerroRuntime;
//!
//! let runtime = FerroRuntime::new()?;
//! runtime.create_container("my-container", config)?;
//! ```

pub mod ai_runtime;
pub mod authorization;
pub mod cgroups;
#[cfg(target_os = "linux")]
pub mod container_exec;
pub mod container_store;
pub mod docker_auth;
#[cfg(target_os = "linux")]
pub mod dockerfile_build;
#[cfg(not(target_os = "linux"))]
#[path = "dockerfile_build_non_linux.rs"]
pub mod dockerfile_build;
pub mod entitlements;
#[cfg(target_os = "linux")]
pub mod ferrofile_build;
pub mod fs_atomic;
pub mod image_config;
pub mod image_fetch;
pub mod image_manifest;
pub mod image_security;
pub mod image_store;
pub mod image_tagging;
pub mod installer;
pub mod layer_cache;
pub mod layer_compression;
#[cfg(target_os = "linux")]
pub mod layer_mount;
pub mod mac_profiles;
pub mod managed_overlay;
#[cfg(target_os = "linux")]
pub mod mount_cleanup;
#[cfg(target_os = "linux")]
pub mod mounts;
pub mod observability;
#[cfg(target_os = "linux")]
pub mod overlayfs;
pub mod plugin_contract;
pub mod plugin_runtime;
#[cfg(target_os = "linux")]
pub mod process_lifecycle;
#[cfg(target_os = "linux")]
pub mod pty;
pub mod registry;
pub mod runtime_config;
pub mod rvf_image;
pub mod rvf_launcher;
pub mod sqlite_container_store;
pub mod volume_store;
pub mod witness;

// Unit tests that exercise environment-driven capability discovery must share
// one process-wide lock. Rust test threads otherwise race while changing PATH
// and FERROCRATE_* variables, producing order-dependent false failures.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard, PoisonError};

    pub static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub fn acquire_env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(target_os = "linux")]
pub mod capabilities;
#[cfg(target_os = "linux")]
pub mod linux_namespaces;
#[cfg(target_os = "linux")]
pub mod rootfs;
#[cfg(target_os = "linux")]
pub mod rootfs_diff;
#[cfg(target_os = "linux")]
pub mod rootfs_prep;
#[cfg(target_os = "linux")]
pub mod rootless;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod seccomp;
