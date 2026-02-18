use crate::layer_compression::{open_decompressed_layer_reader, LayerCompressionError};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tar::Archive;
use thiserror::Error;

const OCI_WHITEOUT_PREFIX: &str = ".wh.";
const OCI_OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

#[derive(Debug, Error)]
pub enum RootfsError {
    #[error("layer decompression failed: {0}")]
    Decompression(#[from] LayerCompressionError),
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

/// Construct a root filesystem with file-level deduplication across layers.
pub fn construct_rootfs_with_dedup(
    rootfs_dir: &Path,
    layers: &[PathBuf],
    cas_root: &Path,
) -> Result<(), RootfsError> {
    fs::create_dir_all(rootfs_dir)?;
    fs::create_dir_all(cas_root)?;
    for layer in layers {
        apply_layer_tar_with_dedup(rootfs_dir, layer, cas_root)?;
    }
    Ok(())
}

/// Apply a single tar layer to an existing rootfs directory.
pub fn apply_layer_tar(rootfs_dir: &Path, layer_tar_path: &Path) -> Result<(), RootfsError> {
    let reader = open_decompressed_layer_reader(layer_tar_path)?;
    let mut archive = Archive::new(reader);

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
            ensure_no_symlink_components(rootfs_dir, &normalized)?;
            fs::create_dir_all(rootfs_dir.join(&normalized))?;
            continue;
        }

        let destination = rootfs_dir.join(&normalized);
        ensure_no_symlink_components(rootfs_dir, &normalized)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }

        entry.unpack(&destination)?;
    }

    Ok(())
}

fn apply_layer_tar_with_dedup(
    rootfs_dir: &Path,
    layer_tar_path: &Path,
    cas_root: &Path,
) -> Result<(), RootfsError> {
    let reader = open_decompressed_layer_reader(layer_tar_path)?;
    let mut archive = Archive::new(reader);

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
            ensure_no_symlink_components(rootfs_dir, &normalized)?;
            fs::create_dir_all(rootfs_dir.join(&normalized))?;
            continue;
        }

        let destination = rootfs_dir.join(&normalized);
        ensure_no_symlink_components(rootfs_dir, &normalized)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }

        entry.unpack(&destination)?;
        if entry.header().entry_type().is_file() {
            dedup_file(&destination, cas_root)?;
        }
    }

    Ok(())
}

fn dedup_file(path: &Path, cas_root: &Path) -> Result<(), RootfsError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(());
    }
    let hash = hex::encode(rvf_crypto::shake256_256(&bytes));
    let cas_path = cas_root.join(hash);
    let metadata = fs::metadata(path)?;
    let mode = metadata.permissions().mode();

    if cas_path.exists() {
        let cas_mode = fs::metadata(&cas_path)?.permissions().mode();
        if cas_mode != mode {
            return Ok(());
        }
    } else {
        fs::write(&cas_path, &bytes)?;
        fs::set_permissions(&cas_path, metadata.permissions())?;
    }

    let _ = fs::remove_file(path);
    if fs::hard_link(&cas_path, path).is_err() {
        fs::copy(&cas_path, path)?;
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

    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        fs::remove_file(path)?;
    } else if md.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }

    Ok(())
}

fn ensure_no_symlink_components(rootfs_dir: &Path, rel_path: &Path) -> Result<(), RootfsError> {
    let mut current = rootfs_dir.to_path_buf();
    let parent = rel_path.parent().unwrap_or_else(|| Path::new(""));
    for component in parent.components() {
        if let Component::Normal(part) = component {
            current.push(part);
            if let Ok(md) = fs::symlink_metadata(&current) {
                if md.file_type().is_symlink() {
                    return Err(RootfsError::UnsafePath(rel_path.display().to_string()));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{construct_rootfs, construct_rootfs_with_dedup};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::fs;
    use std::io::{Cursor, Write};
    use std::os::unix::fs::MetadataExt;
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

    #[test]
    fn dedups_identical_files_across_layers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");
        let cas_root = temp.path().join("cas");

        let layer1 = temp.path().join("layer1.tar");
        let layer2 = temp.path().join("layer2.tar");

        create_tar(&layer1, &[("etc/dup.txt", b"same".as_slice())]);
        create_tar(&layer2, &[("opt/dup.txt", b"same".as_slice())]);

        construct_rootfs_with_dedup(&rootfs, &[layer1, layer2], &cas_root)
            .expect("rootfs should construct");

        let first = fs::metadata(rootfs.join("etc/dup.txt")).expect("first");
        let second = fs::metadata(rootfs.join("opt/dup.txt")).expect("second");
        assert!(first.nlink() >= 2);
        assert_eq!(first.ino(), second.ino());
    }

    #[test]
    fn supports_gzip_and_zstd_compressed_layers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");

        let layer_plain = temp.path().join("layer_plain.tar");
        let layer_gz = temp.path().join("layer_gz.tar.gz");
        let layer_zstd = temp.path().join("layer_zstd.tar.zst");

        create_tar(&layer_plain, &[("usr/bin/tool", b"v1".as_slice())]);
        gzip_file(&layer_plain, &layer_gz);
        zstd_file(&layer_plain, &layer_zstd);

        construct_rootfs(&rootfs, &[layer_gz]).expect("gzip layer should apply");
        assert_eq!(
            fs::read_to_string(rootfs.join("usr/bin/tool")).expect("file from gzip layer"),
            "v1"
        );

        fs::remove_dir_all(&rootfs).expect("cleanup rootfs");
        construct_rootfs(&rootfs, &[layer_zstd]).expect("zstd layer should apply");
        assert_eq!(
            fs::read_to_string(rootfs.join("usr/bin/tool")).expect("file from zstd layer"),
            "v1"
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

    fn gzip_file(input: &Path, output: &Path) {
        let data = fs::read(input).expect("read tar");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&data).expect("write gzip data");
        let compressed = encoder.finish().expect("finalize gzip");
        fs::write(output, compressed).expect("write gzip file");
    }

    fn zstd_file(input: &Path, output: &Path) {
        let data = fs::read(input).expect("read tar");
        let compressed = zstd::stream::encode_all(&data[..], 0).expect("encode zstd");
        fs::write(output, compressed).expect("write zstd file");
    }
}
