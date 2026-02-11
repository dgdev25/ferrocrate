use crate::overlayfs::{OverlayBackend, OverlayFsManager, OverlayMountConfig};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LayerMountError {
    #[error("at least one layer directory is required")]
    EmptyLayerSet,
    #[error("overlay mount failed: {0}")]
    Overlay(#[from] crate::overlayfs::OverlayFsError),
}

#[derive(Debug, Clone)]
pub struct LayerMountPlan {
    pub lowerdirs: Vec<PathBuf>,
    pub upperdir: PathBuf,
    pub workdir: PathBuf,
    pub merged_dir: PathBuf,
}

impl LayerMountPlan {
    pub fn to_overlay_config(&self) -> OverlayMountConfig {
        OverlayMountConfig {
            lowerdirs: self.lowerdirs.clone(),
            upperdir: self.upperdir.clone(),
            workdir: self.workdir.clone(),
            merged_dir: self.merged_dir.clone(),
        }
    }
}

/// Build a container-specific overlay mount plan from ordered layer directories.
/// Input `layer_dirs` should be base->top order; overlay lowerdir is generated top->base.
pub fn build_layer_mount_plan(
    runtime_dir: &Path,
    container_id: &str,
    layer_dirs: &[PathBuf],
) -> Result<LayerMountPlan, LayerMountError> {
    if layer_dirs.is_empty() {
        return Err(LayerMountError::EmptyLayerSet);
    }

    let lowerdirs = layer_dirs.iter().rev().cloned().collect::<Vec<_>>();
    let container_root = runtime_dir.join("containers").join(container_id);

    Ok(LayerMountPlan {
        lowerdirs,
        upperdir: container_root.join("upper"),
        workdir: container_root.join("work"),
        merged_dir: container_root.join("rootfs"),
    })
}

pub fn mount_layer_stack(plan: &LayerMountPlan) -> Result<OverlayBackend, LayerMountError> {
    let config = plan.to_overlay_config();
    Ok(OverlayFsManager::mount_with_fallback(&config)?)
}

#[cfg(test)]
mod tests {
    use super::build_layer_mount_plan;
    use std::path::PathBuf;

    #[test]
    fn builds_layer_mount_plan_with_overlay_ordering() {
        let runtime_dir = PathBuf::from("/var/lib/ferrocrate");
        let layers = vec![
            PathBuf::from("/store/layers/base"),
            PathBuf::from("/store/layers/mid"),
            PathBuf::from("/store/layers/top"),
        ];

        let plan = build_layer_mount_plan(&runtime_dir, "abc123", &layers).expect("plan builds");

        assert_eq!(
            plan.lowerdirs,
            vec![
                PathBuf::from("/store/layers/top"),
                PathBuf::from("/store/layers/mid"),
                PathBuf::from("/store/layers/base"),
            ]
        );
        assert_eq!(
            plan.upperdir,
            PathBuf::from("/var/lib/ferrocrate/containers/abc123/upper")
        );
        assert_eq!(
            plan.merged_dir,
            PathBuf::from("/var/lib/ferrocrate/containers/abc123/rootfs")
        );
    }

    #[test]
    fn rejects_empty_layer_mount_plan() {
        let runtime_dir = PathBuf::from("/var/lib/ferrocrate");
        let err = build_layer_mount_plan(&runtime_dir, "abc123", &[]).expect_err("must fail");
        assert!(err.to_string().contains("at least one layer directory"));
    }
}
