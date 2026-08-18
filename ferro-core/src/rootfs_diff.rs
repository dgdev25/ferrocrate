//! Bounded filesystem baselines for Docker-compatible container change views.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const MAX_ENTRIES: usize = 100_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DIGEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootfsEntry {
    pub kind: u8,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    #[serde(default)]
    pub digest: Option<String>,
}

pub type RootfsSnapshot = BTreeMap<String, RootfsEntry>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RootfsChange {
    pub path: String,
    /// Docker's change kinds: 0 modified, 1 added, 2 deleted.
    pub kind: u8,
}

pub fn capture(root: &Path, excluded: &[PathBuf]) -> io::Result<RootfsSnapshot> {
    let mut snapshot = BTreeMap::new();
    walk(root, root, excluded, &mut snapshot)?;
    Ok(snapshot)
}

pub fn write_baseline(path: &Path, snapshot: &RootfsSnapshot) -> io::Result<()> {
    let bytes = serde_json::to_vec(snapshot)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)
}

pub fn read_baseline(path: &Path) -> io::Result<RootfsSnapshot> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn diff(
    root: &Path,
    baseline_path: &Path,
    excluded: &[PathBuf],
) -> io::Result<Vec<RootfsChange>> {
    let baseline = read_baseline(baseline_path)?;
    let current = capture(root, excluded)?;
    let paths = baseline
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    for path in paths {
        match (baseline.get(path), current.get(path)) {
            (Some(_), None) => changes.push(RootfsChange {
                path: path.clone(),
                kind: 2,
            }),
            (None, Some(_)) => changes.push(RootfsChange {
                path: path.clone(),
                kind: 1,
            }),
            (Some(before), Some(after)) if before != after => changes.push(RootfsChange {
                path: path.clone(),
                kind: 0,
            }),
            _ => {}
        }
    }
    Ok(changes)
}

fn walk(
    root: &Path,
    directory: &Path,
    excluded: &[PathBuf],
    output: &mut RootfsSnapshot,
) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        if output.len() >= MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rootfs snapshot exceeds entry bound",
            ));
        }
        let entry = entry?;
        let path = entry.path();
        if excluded.iter().any(|excluded| path.starts_with(excluded)) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative.len() > MAX_PATH_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "rootfs snapshot path exceeds bound",
            ));
        }
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            2
        } else if file_type.is_symlink() {
            3
        } else {
            1
        };
        let digest = if file_type.is_file() && metadata.size() <= MAX_DIGEST_BYTES {
            Some(file_digest(&path)?)
        } else {
            None
        };
        output.insert(
            relative,
            RootfsEntry {
                kind,
                size: metadata.size(),
                mode: metadata.mode(),
                mtime: metadata.mtime(),
                digest,
            },
        );
        if file_type.is_dir() {
            walk(root, &path, excluded, output)?;
        }
    }
    Ok(())
}

fn file_digest(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_diff_reports_add_modify_delete_and_excludes_mounts() {
        let root = tempfile::tempdir().expect("root");
        fs::write(root.path().join("stable"), b"same").expect("stable");
        fs::write(root.path().join("modify"), b"old").expect("modify");
        fs::write(root.path().join("delete"), b"gone").expect("delete");
        fs::create_dir(root.path().join("mount")).expect("mount");
        fs::write(root.path().join("mount/ignored"), b"ignored").expect("ignored");
        let baseline = capture(root.path(), &[root.path().join("mount")]).expect("snapshot");
        let baseline_path = root.path().parent().unwrap().join("baseline.json");
        write_baseline(&baseline_path, &baseline).expect("write baseline");
        fs::write(root.path().join("modify"), b"new").expect("modify");
        fs::remove_file(root.path().join("delete")).expect("delete");
        fs::write(root.path().join("added"), b"added").expect("added");
        fs::write(root.path().join("mount/changed"), b"ignored").expect("ignored");
        let changes =
            diff(root.path(), &baseline_path, &[root.path().join("mount")]).expect("diff");
        assert_eq!(
            changes,
            vec![
                RootfsChange {
                    path: "added".into(),
                    kind: 1
                },
                RootfsChange {
                    path: "delete".into(),
                    kind: 2
                },
                RootfsChange {
                    path: "modify".into(),
                    kind: 0
                },
            ]
        );
    }
}
