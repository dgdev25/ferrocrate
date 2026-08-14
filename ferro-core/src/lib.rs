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
pub mod layer_compression;
pub mod managed_overlay;
#[cfg(target_os = "linux")]
pub mod layer_mount;
pub mod mac_profiles;
#[cfg(target_os = "linux")]
pub mod mount_cleanup;
#[cfg(target_os = "linux")]
pub mod mounts;
pub mod observability;
#[cfg(target_os = "linux")]
pub mod overlayfs;
#[cfg(target_os = "linux")]
pub mod process_lifecycle;
pub mod registry;
pub mod runtime_config;
pub mod rvf_image;
pub mod volume_store;
pub mod witness;

#[cfg(target_os = "linux")]
pub mod capabilities;
#[cfg(target_os = "linux")]
pub mod linux_namespaces;
#[cfg(target_os = "linux")]
pub mod rootfs;
#[cfg(target_os = "linux")]
pub mod rootfs_prep;
#[cfg(target_os = "linux")]
pub mod rootless;
#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod seccomp;
