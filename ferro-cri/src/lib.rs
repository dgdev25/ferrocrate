//! FerroCrate CRI - Kubernetes Container Runtime Interface implementation.
//!
//! Provides a CRI-compatible server for Kubernetes integration, implementing
//! the v1 runtime API for container and pod management.

pub mod runtime {
    tonic::include_proto!("runtime.v1");
}

pub mod server;
