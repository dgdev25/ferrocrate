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
    let target = normalize_mount_target(target)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC);
    let mut directory = options.open(rootfs)?;
    for component in target.components() {
        let name = CString::new(component.as_os_str().as_encoded_bytes())
            .map_err(|_| MountError::InvalidTarget("NUL in target".into()))?;
        let how = OpenHow {
            flags: (nix::libc::O_PATH | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC) as u64,
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
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::ENOENT) {
            let created =
                unsafe { nix::libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) };
            if created < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::EEXIST)
            {
                return Err(std::io::Error::last_os_error().into());
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

        let target_handle = open_mount_target_beneath(rootfs, &mount_spec.target)?;
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
        apply_bind_mounts, normalize_mount_target, open_mount_target_beneath, BindMount, TmpfsMount,
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
