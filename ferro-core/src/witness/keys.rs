use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyId(pub [u8; 32]);

impl KeyId {
    pub fn from_public_key(key: &VerifyingKey) -> Self {
        Self(Sha256::digest(key.as_bytes()).into())
    }
}

pub struct KeyMaterial(SigningKey);

impl KeyMaterial {
    pub fn signing_key(&self) -> &SigningKey {
        &self.0
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
    pub fn key_id(&self) -> KeyId {
        KeyId::from_public_key(&self.verifying_key())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("invalid key name")]
    InvalidName,
    #[error("key path is not a protected regular file")]
    InsecureFile,
    #[error("key already exists")]
    AlreadyExists,
    #[error("key I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

pub struct KeyStore {
    root: PathBuf,
}

impl KeyStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_owned(),
        }
    }

    pub fn create(&self, name: &str) -> Result<KeyMaterial, KeyStoreError> {
        validate_name(name)?;
        if !self.root.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&self.root)?;
            }
            #[cfg(not(unix))]
            fs::create_dir(&self.root)?;
        }
        let root = secure_root(&self.root)?;
        let filename = format!("{name}.key");
        let temporary = format!(".{name}.{}.tmp", rand::random::<u64>());
        let bytes = rand::random::<[u8; 32]>();
        let mut file = secure_create_at(&root, &temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        match secure_link_at(&root, &temporary, &filename) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = secure_unlink_at(&root, &temporary);
                return Err(KeyStoreError::AlreadyExists);
            }
            Err(error) => {
                let _ = secure_unlink_at(&root, &temporary);
                return Err(error.into());
            }
        }
        secure_unlink_at(&root, &temporary)?;
        File::from(root).sync_all()?;
        Ok(KeyMaterial(SigningKey::from_bytes(&bytes)))
    }

    pub fn load(&self, name: &str) -> Result<KeyMaterial, KeyStoreError> {
        validate_name(name)?;
        let root = secure_root(&self.root)?;
        let mut file = secure_open_at(&root, &format!("{name}.key"))?;
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.file_type().is_file()
                || metadata.mode() & 0o777 != 0o600
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.nlink() != 1
            {
                return Err(KeyStoreError::InsecureFile);
            }
        }
        if metadata.len() != 32 {
            return Err(KeyStoreError::InsecureFile);
        }
        let mut bytes = [0; 32];
        file.read_exact(&mut bytes)?;
        Ok(KeyMaterial(SigningKey::from_bytes(&bytes)))
    }
}

#[cfg(unix)]
fn secure_root(root: &Path) -> Result<OwnedFd, KeyStoreError> {
    use nix::{
        fcntl::{open, OFlag},
        sys::stat::Mode,
    };
    use std::os::unix::fs::MetadataExt;
    let fd = open(
        root,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let metadata = File::from(fd.try_clone()?).metadata()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(KeyStoreError::InsecureFile);
    }
    Ok(fd)
}
#[cfg(not(unix))]
fn secure_root(root: &Path) -> Result<File, KeyStoreError> {
    Ok(File::open(root)?)
}

fn validate_name(name: &str) -> Result<(), KeyStoreError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(KeyStoreError::InvalidName);
    }
    Ok(())
}

#[cfg(unix)]
fn secure_create_at(root: &OwnedFd, name: &str) -> Result<File, std::io::Error> {
    use nix::{
        fcntl::{openat, OFlag},
        sys::stat::Mode,
    };
    openat(
        root,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::from_bits_truncate(0o600),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}
#[cfg(not(unix))]
fn secure_create_at(_root: &File, path: &str) -> Result<File, std::io::Error> {
    use std::fs::OpenOptions;
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn secure_open_at(root: &OwnedFd, name: &str) -> Result<File, std::io::Error> {
    use nix::{
        fcntl::{openat, OFlag},
        sys::stat::Mode,
    };
    openat(
        root,
        name,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(std::io::Error::from)
}
#[cfg(not(unix))]
fn secure_open_at(_root: &File, path: &str) -> Result<File, std::io::Error> {
    use std::fs::OpenOptions;
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn secure_link_at(root: &OwnedFd, old: &str, new: &str) -> Result<(), std::io::Error> {
    nix::unistd::linkat(root, old, root, new, nix::fcntl::AtFlags::empty())
        .map_err(std::io::Error::from)
}
#[cfg(unix)]
fn secure_unlink_at(root: &OwnedFd, name: &str) -> Result<(), std::io::Error> {
    nix::unistd::unlinkat(root, name, nix::unistd::UnlinkatFlags::NoRemoveDir)
        .map_err(std::io::Error::from)
}
#[cfg(not(unix))]
fn secure_link_at(_root: &File, _old: &str, _new: &str) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "descriptor-relative key publication unsupported",
    ))
}
#[cfg(not(unix))]
fn secure_unlink_at(_root: &File, _name: &str) -> Result<(), std::io::Error> {
    Ok(())
}
