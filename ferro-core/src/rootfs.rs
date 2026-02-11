use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use tar::Archive;
use thiserror::Error;

const OCI_WHITEOUT_PREFIX: &str = ".wh.";
const OCI_OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

#[derive(Debug, Error)]
pub enum RootfsError {
    #[error("failed to open layer archive {path}: {source}")]
    OpenLayer { path: PathBuf, source: io::Error },
    #[error("failed to read layer archive: {0}")]
    ReadLayer(#[from] io::Error),
    #[error("unsafe layer path in tar entry: {0}")]
    UnsafePath(String),
}

/// Construct a root filesystem by applying OCI layers in order.
pub fn construct_rootfs(rootfs_dir: &Path, layers: &[PathBuf]) -> Result<(), RootfsError> {
    fs::create_dir_all(rootfs_dir)?;
    for layer in layers {
        apply_layer_tar(rootfs_dir, layer)?;
    }
    Ok(())
}

/// Apply a single tar layer to an existing rootfs directory.
pub fn apply_layer_tar(rootfs_dir: &Path, layer_tar_path: &Path) -> Result<(), RootfsError> {
    let file = fs::File::open(layer_tar_path).map_err(|source| RootfsError::OpenLayer {
        path: layer_tar_path.to_path_buf(),
        source,
    })?;

    let mut archive = Archive::new(file);

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_path = entry.path()?;
        let normalized = sanitize_archive_path(&entry_path)?;

        let file_name = normalized
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        if file_name == OCI_OPAQUE_WHITEOUT {
            let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
            clear_directory(&rootfs_dir.join(parent))?;
            continue;
        }

        if let Some(target_name) = file_name.strip_prefix(OCI_WHITEOUT_PREFIX) {
            let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
            let target = rootfs_dir.join(parent).join(target_name);
            remove_path_if_exists(&target)?;
            continue;
        }

        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(rootfs_dir.join(&normalized))?;
            continue;
        }

        let destination = rootfs_dir.join(&normalized);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }

        entry.unpack(&destination)?;
    }

    Ok(())
}

fn sanitize_archive_path(path: &Path) -> Result<PathBuf, RootfsError> {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => cleaned.push(part),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                return Err(RootfsError::UnsafePath(path.display().to_string()));
            }
        }
    }
    Ok(cleaned)
}

fn clear_directory(dir: &Path) -> Result<(), RootfsError> {
    if !dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        remove_path_if_exists(&path)?;
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), RootfsError> {
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
    use super::construct_rootfs;
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use tar::{Builder, Header};

    #[test]
    fn applies_layers_and_respects_whiteouts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");

        let layer1 = temp.path().join("layer1.tar");
        let layer2 = temp.path().join("layer2.tar");

        create_tar(
            &layer1,
            &[
                ("etc/hello.txt", b"base".as_slice()),
                ("var/log/app.log", b"logline".as_slice()),
            ],
        );

        create_tar(
            &layer2,
            &[
                ("etc/.wh.hello.txt", b"".as_slice()),
                ("etc/new.txt", b"fresh".as_slice()),
            ],
        );

        construct_rootfs(&rootfs, &[layer1, layer2]).expect("rootfs should construct");

        assert!(!rootfs.join("etc/hello.txt").exists());
        assert_eq!(
            fs::read_to_string(rootfs.join("etc/new.txt")).expect("new file"),
            "fresh"
        );
        assert_eq!(
            fs::read_to_string(rootfs.join("var/log/app.log")).expect("existing file"),
            "logline"
        );
    }

    #[test]
    fn applies_opaque_whiteout_to_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");

        let layer1 = temp.path().join("layer1.tar");
        let layer2 = temp.path().join("layer2.tar");

        create_tar(
            &layer1,
            &[
                ("opt/data/one.txt", b"one".as_slice()),
                ("opt/data/two.txt", b"two".as_slice()),
            ],
        );

        create_tar(
            &layer2,
            &[
                ("opt/data/.wh..wh..opq", b"".as_slice()),
                ("opt/data/three.txt", b"three".as_slice()),
            ],
        );

        construct_rootfs(&rootfs, &[layer1, layer2]).expect("rootfs should construct");

        assert!(!rootfs.join("opt/data/one.txt").exists());
        assert!(!rootfs.join("opt/data/two.txt").exists());
        assert_eq!(
            fs::read_to_string(rootfs.join("opt/data/three.txt")).expect("new file"),
            "three"
        );
    }

    fn create_tar(path: &Path, entries: &[(&str, &[u8])]) {
        let file = fs::File::create(path).expect("create tar");
        let mut builder = Builder::new(file);

        for (entry_path, content) in entries {
            append_data(&mut builder, entry_path, content);
        }

        builder.finish().expect("finish tar");
    }

    fn append_data(builder: &mut Builder<fs::File>, path: &str, content: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, PathBuf::from(path), Cursor::new(content))
            .expect("append data");
    }
}
