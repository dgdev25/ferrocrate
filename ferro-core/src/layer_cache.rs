//! Cached layer materialization for rootfs construction.
//!
//! Cold runs extract a layer tar into the container rootfs and register every
//! regular file in the shared content-addressed store (CAS) exactly like
//! [`crate::rootfs::construct_rootfs_with_dedup`]. While extracting, the
//! sanitized entry stream is recorded as a manifest keyed by the shake256
//! digest of the raw layer blob. Warm runs skip tar decompression, the
//! per-file read-back, and hashing: they re-materialize the entry stream
//! with hard links from the CAS. Any manifest or CAS miss falls back to the
//! cold path, so a cached rootfs is never less correct than an extracted one.

use crate::rootfs::{
    ensure_no_symlink_components, sanitize_archive_path, RootfsError, OCI_OPAQUE_WHITEOUT,
    OCI_WHITEOUT_PREFIX,
};
use nix::fcntl::AT_FDCWD;
use nix::sys::stat::{utimensat, UtimensatFlags};
use nix::sys::time::{TimeSpec, TimeValLike};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::Archive;

const MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum CachedEntryKind {
    Directory,
    File { hash: String },
    Symlink { target: String },
    HardLink { target: String },
    Whiteout,
    OpaqueWhiteout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedLayerEntry {
    /// Sanitized archive path of the entry, whiteout marker included.
    path: PathBuf,
    mode: u32,
    mtime_sec: i64,
    kind: CachedEntryKind,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedLayerManifest {
    schema: u32,
    key: String,
    entries: Vec<CachedLayerEntry>,
}

/// Construct a rootfs from `layers`, reusing per-layer manifests in
/// `cache_root` and file contents in `cas_root`.
pub fn construct_rootfs_cached(
    rootfs_dir: &Path,
    layers: &[PathBuf],
    cas_root: &Path,
    cache_root: &Path,
) -> Result<(), RootfsError> {
    fs::create_dir_all(rootfs_dir)?;
    fs::create_dir_all(cas_root)?;
    fs::create_dir_all(cache_root)?;
    for layer in layers {
        apply_layer_cached(rootfs_dir, layer, cas_root, cache_root)?;
    }
    Ok(())
}

fn apply_layer_cached(
    rootfs_dir: &Path,
    layer_tar_path: &Path,
    cas_root: &Path,
    cache_root: &Path,
) -> Result<(), RootfsError> {
    let key = layer_cache_key(layer_tar_path)?;
    let manifest_path = cache_root.join(format!("{key}.json"));
    if let Some(manifest) = read_manifest(&manifest_path, &key)? {
        if materialize_layer(rootfs_dir, &manifest, cas_root)? {
            return Ok(());
        }
    }
    let entries = extract_layer_recording(rootfs_dir, layer_tar_path, cas_root)?;
    let manifest = CachedLayerManifest {
        schema: MANIFEST_SCHEMA,
        key,
        entries,
    };
    let bytes =
        serde_json::to_vec(&manifest).map_err(|error| RootfsError::ReadLayer(error.into()))?;
    crate::fs_atomic::write_atomic(&manifest_path, &bytes).map_err(RootfsError::ReadLayer)?;
    Ok(())
}

/// Cache identity of a layer blob: the shake256 digest of the raw bytes.
/// A same-jiffy replacement of a digest-named blob with equal size would be
/// invisible to metadata-based keys, so the key always binds to content.
fn layer_cache_key(layer_tar_path: &Path) -> Result<String, RootfsError> {
    use std::io::Read;
    let mut file = fs::File::open(layer_tar_path).map_err(|error| RootfsError::OpenLayer {
        path: layer_tar_path.to_path_buf(),
        source: error,
    })?;
    let mut bytes = Vec::with_capacity(file.metadata()?.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(hex::encode(rvf_crypto::shake256_256(&bytes)))
}

fn read_manifest(
    path: &Path,
    expected_key: &str,
) -> Result<Option<CachedLayerManifest>, RootfsError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(RootfsError::ReadLayer(error)),
    };
    let manifest: CachedLayerManifest =
        serde_json::from_slice(&bytes).map_err(|error| RootfsError::ReadLayer(error.into()))?;
    if manifest.schema != MANIFEST_SCHEMA || manifest.key != expected_key {
        return Ok(None);
    }
    Ok(Some(manifest))
}

/// Materialize `manifest` into `rootfs_dir`. Returns `false` when a required
/// CAS entry is missing and the caller must fall back to cold extraction.
/// The check runs before any filesystem mutation, so a `false` return leaves
/// the rootfs untouched by this layer.
fn materialize_layer(
    rootfs_dir: &Path,
    manifest: &CachedLayerManifest,
    cas_root: &Path,
) -> Result<bool, RootfsError> {
    for entry in &manifest.entries {
        if let CachedEntryKind::File { hash } = &entry.kind {
            let cas_path = cas_root.join(hash);
            match fs::symlink_metadata(&cas_path) {
                Ok(metadata) if metadata.is_file() => {}
                _ => return Ok(false),
            }
        }
    }

    for entry in &manifest.entries {
        let normalized = sanitize_archive_path(&entry.path)?;
        let file_name = normalized
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let destination = rootfs_dir.join(&normalized);

        match &entry.kind {
            CachedEntryKind::OpaqueWhiteout => {
                ensure_no_symlink_components(rootfs_dir, &normalized)?;
                let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
                clear_directory_shim(&rootfs_dir.join(parent))?;
            }
            CachedEntryKind::Whiteout => {
                ensure_no_symlink_components(rootfs_dir, &normalized)?;
                let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
                let target_name = file_name
                    .strip_prefix(OCI_WHITEOUT_PREFIX)
                    .unwrap_or(&file_name);
                let target = rootfs_dir.join(parent).join(target_name);
                remove_path_shim(&target)?;
            }
            CachedEntryKind::Directory => {
                ensure_no_symlink_components(rootfs_dir, &normalized)?;
                fs::create_dir_all(&destination)?;
                set_entry_times(&destination, entry.mtime_sec, false)?;
            }
            CachedEntryKind::Symlink { target } => {
                ensure_no_symlink_components(rootfs_dir, &normalized)?;
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                if fs::symlink_metadata(&destination).is_ok() {
                    fs::remove_file(&destination)?;
                }
                std::os::unix::fs::symlink(target, &destination)?;
                set_entry_times(&destination, entry.mtime_sec, true)?;
            }
            CachedEntryKind::HardLink { target } => {
                ensure_no_symlink_components(rootfs_dir, &normalized)?;
                let link_target = sanitize_archive_path(Path::new(target))?;
                ensure_no_symlink_components(rootfs_dir, &link_target)?;
                let source = rootfs_dir.join(&link_target);
                if fs::symlink_metadata(&destination).is_ok() {
                    fs::remove_file(&destination)?;
                }
                if fs::hard_link(&source, &destination).is_err() {
                    fs::copy(&source, &destination)?;
                }
            }
            CachedEntryKind::File { hash } => {
                ensure_no_symlink_components(rootfs_dir, &normalized)?;
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                if fs::symlink_metadata(&destination).is_ok() {
                    fs::remove_file(&destination)?;
                }
                let cas_path = cas_root.join(hash);
                let cas_mode = fs::metadata(&cas_path)?.permissions().mode() & 0o7777;
                if cas_mode == entry.mode {
                    if fs::hard_link(&cas_path, &destination).is_err() {
                        fs::copy(&cas_path, &destination)?;
                    }
                } else {
                    // The CAS inode is shared; do not mutate its mode for one
                    // consumer. Break the link and keep a private copy.
                    fs::copy(&cas_path, &destination)?;
                    fs::set_permissions(&destination, fs::Permissions::from_mode(entry.mode))?;
                }
                set_entry_times(&destination, entry.mtime_sec, false)?;
            }
        }
    }
    Ok(true)
}

fn set_entry_times(path: &Path, mtime_sec: i64, no_follow: bool) -> Result<(), RootfsError> {
    let time = TimeSpec::seconds(mtime_sec);
    let flags = if no_follow {
        UtimensatFlags::NoFollowSymlink
    } else {
        UtimensatFlags::FollowSymlink
    };
    utimensat(AT_FDCWD, path, &time, &time, flags)
        .map_err(|error| RootfsError::ReadLayer(error.into()))?;
    Ok(())
}

/// Cold path: extract `layer_tar_path` exactly like
/// `rootfs::apply_layer_tar_with_dedup` while recording the entry stream.
fn extract_layer_recording(
    rootfs_dir: &Path,
    layer_tar_path: &Path,
    cas_root: &Path,
) -> Result<Vec<CachedLayerEntry>, RootfsError> {
    let reader = crate::layer_compression::open_decompressed_layer_reader(layer_tar_path)?;
    let mut archive = Archive::new(reader);
    let mut entries = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let entry_path = entry.path()?;
        let normalized = sanitize_archive_path(&entry_path)?;
        let file_name = normalized
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();

        let header = entry.header();
        let mode = header.mode().unwrap_or(0o644) & 0o7777;
        let mtime_sec = header.mtime().unwrap_or(0) as i64;
        let entry_type = header.entry_type();

        let record = |kind: CachedEntryKind| CachedLayerEntry {
            path: normalized.clone(),
            mode,
            mtime_sec,
            kind,
        };

        if file_name == OCI_OPAQUE_WHITEOUT {
            ensure_no_symlink_components(rootfs_dir, &normalized)?;
            let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
            clear_directory_shim(&rootfs_dir.join(parent))?;
            entries.push(record(CachedEntryKind::OpaqueWhiteout));
            continue;
        }

        if let Some(whiteout_target) = file_name.strip_prefix(OCI_WHITEOUT_PREFIX) {
            ensure_no_symlink_components(rootfs_dir, &normalized)?;
            let parent = normalized.parent().unwrap_or_else(|| Path::new(""));
            let target = rootfs_dir.join(parent).join(whiteout_target);
            remove_path_shim(&target)?;
            entries.push(record(CachedEntryKind::Whiteout));
            continue;
        }

        if entry_type.is_dir() {
            ensure_no_symlink_components(rootfs_dir, &normalized)?;
            fs::create_dir_all(rootfs_dir.join(&normalized))?;
            entries.push(record(CachedEntryKind::Directory));
            continue;
        }

        let destination = rootfs_dir.join(&normalized);
        ensure_no_symlink_components(rootfs_dir, &normalized)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }

        if entry_type.is_hard_link() {
            let link = entry
                .link_name()?
                .ok_or_else(|| RootfsError::InvalidHardLink("missing target".to_string()))?;
            let link_target = sanitize_archive_path(&link)?;
            ensure_no_symlink_components(rootfs_dir, &link_target)?;
            let source = rootfs_dir.join(&link_target);
            if fs::symlink_metadata(&destination).is_ok() {
                fs::remove_file(&destination)?;
            }
            if fs::hard_link(&source, &destination).is_err() {
                fs::copy(&source, &destination)?;
            }
            entries.push(record(CachedEntryKind::HardLink {
                target: link_target.display().to_string(),
            }));
            continue;
        }

        entry.unpack(&destination)?;
        if entry_type.is_symlink() {
            let target = fs::read_link(&destination)?;
            entries.push(record(CachedEntryKind::Symlink {
                target: target.display().to_string(),
            }));
        } else {
            let hash = dedup_file_shim(&destination, cas_root)?;
            entries.push(record(CachedEntryKind::File { hash }));
        }
    }

    Ok(entries)
}

// Thin wrappers so this module does not reach into private rootfs helpers it
// does not own; behavior is identical to the rootfs equivalents.
fn clear_directory_shim(dir: &Path) -> Result<(), RootfsError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        remove_path_shim(&path)?;
    }
    Ok(())
}

fn remove_path_shim(path: &Path) -> Result<(), RootfsError> {
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

/// Register `path` in the CAS and return its content hash. Empty files keep
/// their own inode (no CAS entry) and hash to the empty marker.
fn dedup_file_shim(path: &Path, cas_root: &Path) -> Result<String, RootfsError> {
    let bytes = fs::read(path)?;
    let hash = hex::encode(rvf_crypto::shake256_256(&bytes));
    if bytes.is_empty() {
        return Ok(hash);
    }
    let cas_path = cas_root.join(&hash);
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    if cas_path.exists() {
        let cas_mode = fs::metadata(&cas_path)?.permissions().mode();
        if cas_mode != permissions.mode() {
            return Ok(hash);
        }
    } else {
        fs::write(&cas_path, &bytes)?;
        fs::set_permissions(&cas_path, permissions)?;
    }

    let _ = fs::remove_file(path);
    if fs::hard_link(&cas_path, path).is_err() {
        fs::copy(&cas_path, path)?;
    }
    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::construct_rootfs_cached;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use tar::{Builder, Header};

    fn append_file(builder: &mut Builder<fs::File>, path: &str, contents: &[u8], mode: u32) {
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(mode);
        header.set_mtime(1_700_000_000);
        header.set_cksum();
        builder
            .append_data(&mut header, path, contents)
            .expect("append");
    }

    fn append_dir(builder: &mut Builder<fs::File>, path: &str, mode: u32) {
        let mut header = Header::new_gnu();
        header.set_size(0);
        header.set_mode(mode);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mtime(1_700_000_000);
        header.set_cksum();
        builder
            .append_data(&mut header, path, std::io::empty())
            .expect("append dir");
    }

    fn append_symlink(builder: &mut Builder<fs::File>, path: &str, target: &str) {
        let mut header = Header::new_gnu();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mtime(1_700_000_000);
        header.set_link_name(target).expect("set link name");
        header.set_path(path).expect("set path");
        header.set_cksum();
        builder
            .append(&header, std::io::empty())
            .expect("append symlink");
    }

    fn write_layer(path: &Path, build: impl FnOnce(&mut Builder<fs::File>)) {
        let file = fs::File::create(path).expect("create layer");
        let mut builder = Builder::new(file);
        build(&mut builder);
        builder.finish().expect("finish layer");
    }

    fn gzip_file(input: &Path, output: &Path) {
        let mut encoder = GzEncoder::new(
            fs::File::create(output).expect("create gz"),
            Compression::default(),
        );
        encoder
            .write_all(&fs::read(input).expect("read input"))
            .expect("gzip");
        encoder.finish().expect("finish gz");
    }

    /// Snapshot a tree: relative path -> (kind, mode, content or link target).
    fn snapshot(root: &Path) -> BTreeMap<String, (String, u32, Vec<u8>)> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                let rel = path.strip_prefix(root).expect("rel").display().to_string();
                let md = fs::symlink_metadata(&path).expect("metadata");
                let kind = if md.file_type().is_symlink() {
                    "symlink"
                } else if md.is_dir() {
                    "dir"
                } else {
                    "file"
                };
                let content = if md.file_type().is_symlink() {
                    fs::read_link(&path)
                        .expect("read_link")
                        .to_string_lossy()
                        .as_bytes()
                        .to_vec()
                } else if md.is_dir() {
                    Vec::new()
                } else {
                    fs::read(&path).expect("read file")
                };
                out.insert(rel, (kind.to_string(), md.mode() & 0o7777, content));
                if md.is_dir() {
                    stack.push(path);
                }
            }
        }
        out
    }

    #[test]
    fn warm_materialization_matches_cold_extraction() {
        let temp = tempfile::tempdir().expect("tempdir");
        let layer1 = temp.path().join("layer1.tar");
        write_layer(&layer1, |b| {
            append_dir(b, "etc", 0o755);
            append_file(b, "etc/config", b"config-v1", 0o644);
            append_file(b, "bin/tool", b"#!/bin/sh\n", 0o755);
            append_symlink(b, "bin/tool-link", "tool");
        });
        let layer2 = temp.path().join("layer2.tar");
        write_layer(&layer2, |b| {
            append_file(b, "etc/config", b"config-v2-longer", 0o600);
            append_file(b, "etc/.wh.gone", b"", 0o644);
            append_dir(b, "var/lib", 0o755);
        });

        let cas = temp.path().join("cas");
        let cache = temp.path().join("cache");
        let cold = temp.path().join("cold-rootfs");
        let warm = temp.path().join("warm-rootfs");

        construct_rootfs_cached(&cold, &[layer1.clone(), layer2.clone()], &cas, &cache)
            .expect("cold construct");
        construct_rootfs_cached(&warm, &[layer1, layer2], &cas, &cache).expect("warm construct");

        assert_eq!(snapshot(&cold), snapshot(&warm));
        // The whiteout removed nothing here (nothing to remove) but layer2's
        // overwrite must win in both trees.
        assert_eq!(
            fs::read(warm.join("etc/config")).expect("read config"),
            b"config-v2-longer"
        );
    }

    #[test]
    fn warm_materialization_falls_back_when_cas_entry_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let layer = temp.path().join("layer.tar");
        write_layer(&layer, |b| {
            append_dir(b, "bin", 0o755);
            append_file(b, "bin/data", b"payload", 0o644);
        });

        let cas = temp.path().join("cas");
        let cache = temp.path().join("cache");
        let first = temp.path().join("first-rootfs");
        construct_rootfs_cached(&first, std::slice::from_ref(&layer), &cas, &cache)
            .expect("cold construct");
        let manifest = fs::read_dir(&cache)
            .expect("cache dir")
            .next()
            .expect("manifest exists")
            .expect("entry")
            .path();
        assert!(manifest.extension().is_some_and(|ext| ext == "json"));

        // Remove every CAS entry so the warm path must fall back to extraction.
        for entry in fs::read_dir(&cas).expect("cas dir") {
            fs::remove_file(entry.expect("entry").path()).expect("remove cas entry");
        }

        let second = temp.path().join("second-rootfs");
        construct_rootfs_cached(&second, &[layer], &cas, &cache).expect("fallback construct");
        assert_eq!(
            fs::read(second.join("bin/data")).expect("read data"),
            b"payload"
        );
        // The fallback repopulated the CAS.
        assert!(fs::read_dir(&cas).expect("cas dir").next().is_some());
    }

    #[test]
    fn manifest_key_binds_to_layer_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let layer = temp.path().join("layer.tar");
        write_layer(&layer, |b| {
            append_file(b, "a", b"one", 0o644);
        });
        let cas = temp.path().join("cas");
        let cache = temp.path().join("cache");
        let rootfs = temp.path().join("rootfs");
        construct_rootfs_cached(&rootfs, std::slice::from_ref(&layer), &cas, &cache)
            .expect("cold construct");

        // Different content, same on-disk shape: cache must not be consulted.
        write_layer(&layer, |b| {
            append_file(b, "a", b"two", 0o644);
        });
        let second = temp.path().join("second-rootfs");
        construct_rootfs_cached(&second, &[layer], &cas, &cache).expect("cold construct 2");
        assert_eq!(fs::read(second.join("a")).expect("read a"), b"two");
    }

    #[test]
    fn content_addressed_blob_replacement_invalidates_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        // A digest-named blob as stored under images/blobs. The cache key
        // binds to content, not the name: a same-jiffy replacement under an
        // unchanged digest name and equal size must still miss the cache.
        let layer = temp
            .path()
            .join("sha256_55afa1ecc21d2bb5e5045f32dafee56272ffd89860bac26f6c32123439af26a4");
        write_layer(&layer, |b| {
            append_file(b, "a", b"v1", 0o644);
        });
        let cas = temp.path().join("cas");
        let cache = temp.path().join("cache");
        let first = temp.path().join("first");
        construct_rootfs_cached(&first, std::slice::from_ref(&layer), &cas, &cache).expect("cold");

        write_layer(&layer, |b| {
            append_file(b, "a", b"v2-different-length", 0o644);
        });
        let second = temp.path().join("second");
        construct_rootfs_cached(&second, &[layer], &cas, &cache).expect("replaced");
        assert_eq!(
            fs::read(second.join("a")).expect("read a"),
            b"v2-different-length"
        );
    }

    #[test]
    fn hardlink_entries_materialize_on_warm_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let layer = temp.path().join("layer.tar");
        write_layer(&layer, |b| {
            append_file(b, "bin/busybox", b"applets", 0o755);
            let mut header = Header::new_gnu();
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Link);
            header.set_mtime(1_700_000_000);
            header.set_cksum();
            b.append_link(&mut header, "bin/ls", "bin/busybox")
                .expect("append link");
        });
        let cas = temp.path().join("cas");
        let cache = temp.path().join("cache");
        let cold = temp.path().join("cold");
        let warm = temp.path().join("warm");
        construct_rootfs_cached(&cold, std::slice::from_ref(&layer), &cas, &cache).expect("cold");
        construct_rootfs_cached(&warm, &[layer], &cas, &cache).expect("warm");

        assert_eq!(snapshot(&cold), snapshot(&warm));
        let cold_md = fs::metadata(cold.join("bin/ls")).expect("cold ls");
        let warm_md = fs::metadata(warm.join("bin/ls")).expect("warm ls");
        assert_eq!(cold_md.nlink(), warm_md.nlink());
    }

    #[test]
    fn gzip_layers_cache_by_raw_blob_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let raw = temp.path().join("raw.tar");
        write_layer(&raw, |b| {
            append_file(b, "etc/os-release", b"alpine", 0o644);
        });
        let gz = temp.path().join("layer.tar.gz");
        gzip_file(&raw, &gz);

        let cas = temp.path().join("cas");
        let cache = temp.path().join("cache");
        let cold = temp.path().join("cold");
        let warm = temp.path().join("warm");
        construct_rootfs_cached(&cold, std::slice::from_ref(&gz), &cas, &cache).expect("cold");
        construct_rootfs_cached(&warm, &[gz], &cas, &cache).expect("warm");
        assert_eq!(snapshot(&cold), snapshot(&warm));
    }
}
