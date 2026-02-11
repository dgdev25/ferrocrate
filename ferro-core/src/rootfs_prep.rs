use crate::layer_mount::{LayerMountError, LayerMountPlan, build_layer_mount_plan};
use crate::rootfs::{RootfsError, apply_layer_tar};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RootfsPreparationError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("layer extraction failed: {0}")]
    Rootfs(#[from] RootfsError),
    #[error("layer mount plan failed: {0}")]
    MountPlan(#[from] LayerMountError),
}

#[derive(Debug, Clone)]
pub struct RootfsPreparation {
    pub container_id: String,
    pub extracted_layer_dirs: Vec<PathBuf>,
    pub mount_plan: LayerMountPlan,
}

/// Prepare container rootfs by extracting layer archives and creating an overlay mount plan.
pub fn prepare_container_rootfs(
    runtime_dir: &Path,
    container_id: &str,
    layer_archives: &[PathBuf],
) -> Result<RootfsPreparation, RootfsPreparationError> {
    let layer_root = runtime_dir.join("layers").join(container_id);
    fs::create_dir_all(&layer_root)?;

    let mut extracted_layers = Vec::new();
    for (idx, archive) in layer_archives.iter().enumerate() {
        let layer_dir = layer_root.join(format!("layer-{idx:04}"));
        fs::create_dir_all(&layer_dir)?;
        apply_layer_tar(&layer_dir, archive)?;
        extracted_layers.push(layer_dir);
    }

    let mount_plan = build_layer_mount_plan(runtime_dir, container_id, &extracted_layers)?;

    Ok(RootfsPreparation {
        container_id: container_id.to_string(),
        extracted_layer_dirs: extracted_layers,
        mount_plan,
    })
}

#[cfg(test)]
mod tests {
    use super::prepare_container_rootfs;
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use tar::{Builder, Header};

    #[test]
    fn prepares_layer_dirs_and_mount_plan() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime_dir = temp.path().join("runtime");

        let l1 = temp.path().join("l1.tar");
        let l2 = temp.path().join("l2.tar");
        create_tar(&l1, &["etc/base.txt", "usr/bin/tool"]);
        create_tar(&l2, &["etc/top.txt"]);

        let prep = prepare_container_rootfs(
            &runtime_dir,
            "c123",
            &[l1.clone(), l2.clone()],
        )
        .expect("prep should succeed");

        assert_eq!(prep.extracted_layer_dirs.len(), 2);
        assert!(prep.extracted_layer_dirs[0].join("etc/base.txt").exists());
        assert!(prep.extracted_layer_dirs[1].join("etc/top.txt").exists());
        assert_eq!(prep.mount_plan.lowerdirs.len(), 2);
        assert_eq!(
            prep.mount_plan.upperdir,
            runtime_dir.join("containers").join("c123").join("upper")
        );
    }

    fn create_tar(path: &Path, files: &[&str]) {
        let file = fs::File::create(path).expect("create tar");
        let mut builder = Builder::new(file);

        for file_path in files {
            let content = format!("{file_path}\n");
            let mut header = Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, PathBuf::from(file_path), Cursor::new(content))
                .expect("append tar entry");
        }

        builder.finish().expect("finish tar");
    }
}
