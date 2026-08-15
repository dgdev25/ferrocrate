#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod authorization_surfaces;

#[cfg(target_os = "linux")]
pub mod authorization_admin;
