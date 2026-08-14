use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
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
        fs::create_dir_all(&self.root)?;
        reject_symlink_root(&self.root)?;
        let path = self.path(name);
        let temporary = self
            .root
            .join(format!(".{name}.{}.tmp", rand::random::<u64>()));
        let bytes = rand::random::<[u8; 32]>();
        let mut file = secure_create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temporary);
                return Err(KeyStoreError::AlreadyExists);
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        fs::remove_file(&temporary)?;
        sync_directory(&self.root)?;
        Ok(KeyMaterial(SigningKey::from_bytes(&bytes)))
    }

    pub fn load(&self, name: &str) -> Result<KeyMaterial, KeyStoreError> {
        validate_name(name)?;
        reject_symlink_root(&self.root)?;
        let mut file = secure_open(&self.path(name))?;
        let metadata = file.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !metadata.file_type().is_file()
                || metadata.mode() & 0o777 != 0o600
                || metadata.uid() != fs::metadata(&self.root)?.uid()
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

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.key"))
    }
}

fn reject_symlink_root(root: &Path) -> Result<(), KeyStoreError> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(KeyStoreError::InsecureFile);
    }
    Ok(())
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
fn secure_create(path: &Path) -> Result<File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
}
#[cfg(not(unix))]
fn secure_create(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn secure_open(path: &Path) -> Result<File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
}
#[cfg(not(unix))]
fn secure_open(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new().read(true).open(path)
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}
