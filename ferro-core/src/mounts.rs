use nix::mount::{mount, MsFlags};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TmpfsMount {
    pub target: PathBuf,
    pub size: Option<String>,
}

#[derive(Debug, Error)]
pub enum MountError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mount error: {0}")]
    Mount(#[from] nix::Error),
    #[error("invalid source path: {0}")]
    InvalidSource(String),
    #[error("invalid mount target: {0}")]
    InvalidTarget(String),
}

pub(crate) fn normalize_mount_target(target: &Path) -> Result<PathBuf, MountError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = target.as_os_str().as_bytes();
    if bytes.is_empty()
        || bytes[0] == b'/'
        || bytes
            .iter()
            .any(|byte| *byte == 0 || byte.is_ascii_control())
        || bytes
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(MountError::InvalidTarget(
            "target must contain only clean relative components".into(),
        ));
    }
    Ok(target.to_path_buf())
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub(crate) fn open_mount_target_beneath(rootfs: &Path, target: &Path) -> Result<File, MountError> {
    open_mount_target_beneath_inner(rootfs, target, true, true)
}

/// Open or create a bind target with the same kind as its source. Regular-file
/// bind mounts must not be pre-created as directories, because bubblewrap and
/// the kernel reject a file source mounted over a directory target.
pub(crate) fn open_mount_target_beneath_for_source(
    rootfs: &Path,
    target: &Path,
    source_is_dir: bool,
) -> Result<File, MountError> {
    open_mount_target_beneath_inner(rootfs, target, true, source_is_dir)
}

pub(crate) fn open_existing_mount_target_beneath(
    rootfs: &Path,
    target: &Path,
) -> Result<File, MountError> {
    open_mount_target_beneath_inner(rootfs, target, false, true)
}

fn open_mount_target_beneath_inner(
    rootfs: &Path,
    target: &Path,
    create: bool,
    final_is_dir: bool,
) -> Result<File, MountError> {
    let target = normalize_mount_target(target)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC);
    let mut directory = options.open(rootfs)?;
    for component in target.components() {
        let name = CString::new(component.as_os_str().as_encoded_bytes())
            .map_err(|_| MountError::InvalidTarget("NUL in target".into()))?;
        let is_final = component == target.components().next_back().expect("non-empty target");
        let open_flags = nix::libc::O_PATH
            | nix::libc::O_CLOEXEC
            | if !is_final || final_is_dir {
                nix::libc::O_DIRECTORY
            } else {
                0
            };
        let how = OpenHow {
            flags: open_flags as u64,
            mode: 0,
            // linux/openat2.h: NO_MAGICLINKS | NO_SYMLINKS | BENEATH.
            resolve: 0x02 | 0x04 | 0x08,
        };
        let mut fd = unsafe {
            nix::libc::syscall(
                nix::libc::SYS_openat2,
                directory.as_raw_fd(),
                name.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            ) as i32
        };
        if create
            && fd < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::ENOENT)
        {
            let created = if !is_final || final_is_dir {
                unsafe { nix::libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) }
            } else {
                unsafe {
                    nix::libc::openat(
                        directory.as_raw_fd(),
                        name.as_ptr(),
                        nix::libc::O_CREAT
                            | nix::libc::O_EXCL
                            | nix::libc::O_WRONLY
                            | nix::libc::O_CLOEXEC,
                        0o600,
                    )
                }
            };
            if created < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::EEXIST)
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if created >= 0 && !(!is_final || final_is_dir) {
                unsafe { nix::libc::close(created) };
            }
            fd = unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_openat2,
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    &how,
                    std::mem::size_of::<OpenHow>(),
                ) as i32
            };
        }
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}

pub(crate) fn open_mount_source_beneath(root: &Path, relative: &Path) -> Result<File, MountError> {
    let relative = normalize_mount_target(relative)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC);
    let root = options.open(root)?;
    let name = CString::new(relative.as_os_str().as_encoded_bytes())
        .map_err(|_| MountError::InvalidTarget("NUL in source".into()))?;
    let how = OpenHow {
        flags: (nix::libc::O_PATH | nix::libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x02 | 0x04 | 0x08,
    };
    let fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as i32
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub fn apply_bind_mounts(rootfs: &Path, mounts: &[BindMount]) -> Result<(), MountError> {
    apply_bind_mounts_inner(rootfs, mounts, false)
}

pub(crate) fn apply_authorized_bind_mounts(
    rootfs: &Path,
    mounts: &[BindMount],
) -> Result<(), MountError> {
    apply_bind_mounts_inner(rootfs, mounts, true)
}

fn apply_bind_mounts_inner(
    rootfs: &Path,
    mounts: &[BindMount],
    allow_runtime_fd: bool,
) -> Result<(), MountError> {
    for mount_spec in mounts {
        if !allow_runtime_fd && mount_spec.source.starts_with("/proc/self/fd/") {
            return Err(MountError::InvalidSource(
                "caller-supplied runtime fd source is forbidden".into(),
            ));
        }
        // Security: Canonicalize source path to resolve symlinks
        // This prevents symlink-based attacks where an attacker could create
        // a symlink to escape the rootfs
        let source = if allow_runtime_fd && mount_spec.source.starts_with("/proc/self/fd/") {
            mount_spec.source.clone()
        } else {
            mount_spec.source.canonicalize().map_err(|e| {
                MountError::InvalidSource(format!(
                    "failed to canonicalize source {:?}: {}",
                    mount_spec.source, e
                ))
            })?
        };

        let source_is_dir = std::fs::metadata(&source)?.is_dir();
        let target_handle =
            open_mount_target_beneath_for_source(rootfs, &mount_spec.target, source_is_dir)?;
        let target = PathBuf::from(format!("/proc/self/fd/{}", target_handle.as_raw_fd()));

        mount(
            Some(&source),
            &target,
            Some("bind"),
            MsFlags::MS_BIND,
            None::<&str>,
        )?;

        if mount_spec.read_only {
            mount(
                Some(&source),
                &target,
                Some("bind"),
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None::<&str>,
            )?;
        }
    }
    Ok(())
}

pub fn apply_tmpfs_mounts(rootfs: &Path, mounts: &[TmpfsMount]) -> Result<(), MountError> {
    for mount_spec in mounts {
        let target_handle = open_mount_target_beneath(rootfs, &mount_spec.target)?;
        let target = PathBuf::from(format!("/proc/self/fd/{}", target_handle.as_raw_fd()));

        let data = mount_spec.size.as_ref().map(|size| format!("size={size}"));
        mount(
            None::<&Path>,
            &target,
            Some("tmpfs"),
            MsFlags::empty(),
            data.as_deref(),
        )?;
    }
    Ok(())
}

pub fn apply_readonly_rootfs(rootfs: &Path) -> Result<(), MountError> {
    mount(
        Some(rootfs),
        rootfs,
        Some("bind"),
        MsFlags::MS_BIND,
        None::<&str>,
    )?;
    mount(
        Some(rootfs),
        rootfs,
        Some("bind"),
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_bind_mounts, normalize_mount_target, open_mount_target_beneath,
        open_mount_target_beneath_for_source, BindMount, TmpfsMount,
    };
    use std::fs;
    use std::path::Path;

    #[test]
    fn bind_mount_struct_is_constructible() {
        let mount = BindMount {
            source: "/tmp/source".into(),
            target: "/data".into(),
            read_only: true,
        };
        assert_eq!(mount.source, std::path::PathBuf::from("/tmp/source"));
    }

    #[test]
    fn tmpfs_mount_struct_is_constructible() {
        let mount = TmpfsMount {
            target: "/tmp".into(),
            size: Some("64m".to_string()),
        };
        assert_eq!(mount.target, std::path::PathBuf::from("/tmp"));
    }

    #[test]
    fn mount_target_accepts_only_clean_relative_components() {
        assert_eq!(
            normalize_mount_target(Path::new("var/lib/data")).unwrap(),
            Path::new("var/lib/data")
        );
        for invalid in [
            "",
            "/etc",
            ".",
            "../etc",
            "var/../etc",
            "var/./data",
            "var//data",
            "var/\nsecret",
        ] {
            assert!(
                normalize_mount_target(Path::new(invalid)).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn public_mount_api_rejects_proc_fd_sources_explicitly() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(&rootfs).expect("rootfs");
        let source = std::fs::File::open(temp.path()).expect("open source");
        use std::os::fd::AsRawFd;
        let mounts = [BindMount {
            source: format!("/proc/self/fd/{}", source.as_raw_fd()).into(),
            target: "data".into(),
            read_only: false,
        }];
        let error = apply_bind_mounts(&rootfs, &mounts).expect_err("public fd source accepted");
        assert!(error.to_string().contains("runtime fd"));
    }

    #[test]
    fn mount_target_resolution_rejects_symlink_escape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(rootfs.join("safe")).expect("rootfs");
        std::os::unix::fs::symlink(temp.path(), rootfs.join("safe/link")).expect("symlink");
        assert!(open_mount_target_beneath(&rootfs, Path::new("safe/link/escape")).is_err());
        assert!(!temp.path().join("escape").exists());
    }

    #[test]
    fn file_bind_target_is_created_as_a_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(&rootfs).expect("rootfs");
        let handle =
            open_mount_target_beneath_for_source(&rootfs, Path::new("run/secrets/token"), false)
                .expect("file target");
        assert!(!handle.metadata().expect("target metadata").is_dir());
        assert!(rootfs.join("run/secrets/token").is_file());
    }

    #[test]
    #[ignore]
    fn apply_bind_mounts_smoke() {
        let temp = tempfile::tempdir().expect("tempdir");
        let rootfs = temp.path().join("rootfs");
        fs::create_dir_all(&rootfs).expect("rootfs");

        let source = temp.path().join("source");
        fs::create_dir_all(&source).expect("source");

        let mounts = vec![BindMount {
            source: source.clone(),
            target: "data".into(),
            read_only: false,
        }];

        apply_bind_mounts(&rootfs, &mounts).expect("bind mount");
    }
}

/// Copy `source` into an empty `destination`, preserving file types
/// (symlinks stay symlinks; never followed), modes, and mtimes. Used for
/// Docker-compatible first-use copy-up into named volumes.
pub(crate) fn copy_tree_preserving(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        let target = destination.join(entry.file_name());
        if metadata.file_type().is_symlink() {
            let link = std::fs::read_link(entry.path())?;
            std::os::unix::fs::symlink(&link, &target)?;
        } else if metadata.is_dir() {
            copy_tree_preserving(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
        // fs::copy preserves mode for regular files; dirs and links need an
        // explicit chmod from the source metadata.
        let permissions = metadata.permissions();
        let _ = std::fs::set_permissions(&target, permissions);
    }
    Ok(())
}

/// Docker-compatible named-volume copy-up: an empty volume mounted over a
/// path where the image already has content receives that content before the
/// mount, so the image's files are visible inside the volume instead of a
/// fresh empty directory hiding them. Bind mounts are never copied; a volume
/// that already holds data is never overwritten.
pub(crate) fn volume_copy_up_if_empty(
    volumes_root: &Path,
    mount: &BindMount,
    rootfs_dir: &Path,
) -> Result<(), String> {
    let source = Path::new(&mount.source);
    if !source.starts_with(volumes_root) {
        return Ok(());
    }
    let empty = match std::fs::read_dir(source) {
        Ok(mut entries) => entries.next().is_none(),
        Err(_) => return Ok(()),
    };
    if !empty {
        return Ok(());
    }
    let image_path = rootfs_dir.join(&mount.target);
    let metadata = match std::fs::symlink_metadata(&image_path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(()),
    };
    if !metadata.is_dir() {
        return Ok(());
    }
    copy_tree_preserving(&image_path, source)
        .map_err(|error| format!("volume copy-up into {} failed: {error}", source.display()))
}
