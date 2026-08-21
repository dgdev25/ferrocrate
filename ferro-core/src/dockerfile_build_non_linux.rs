//! Non-Linux Dockerfile-build boundary.
//!
//! The production layer builder is Linux-specific because it materializes
//! rootfs layers and applies kernel filesystem controls. This small typed
//! boundary keeps shared planning/inspection code and the CLI dependency graph
//! compilable on foreign targets while returning explicit unsupported errors
//! for execution.

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[error("Dockerfile builds require a Linux runtime")]
pub struct DockerfileBuildError;

#[derive(Clone, Debug)]
pub struct ImageBuildPlan {
    canonical_tag: String,
    plan_digest: [u8; 32],
    generation: u64,
}

impl ImageBuildPlan {
    pub fn canonical_tag(&self) -> &str {
        &self.canonical_tag
    }

    pub fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

pub fn layer_blob_path(runtime_dir: &Path, digest: &str) -> PathBuf {
    runtime_dir.join("layers").join(digest.replace(':', "-"))
}
