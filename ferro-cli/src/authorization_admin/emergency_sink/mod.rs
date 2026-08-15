mod client;
mod protocol;
mod server;

pub use client::UnixAppendOnlySink;
pub use protocol::{SinkReceipt, SinkRequest, MAX_FRAME_BYTES};
pub use server::{serve, serve_one, SinkServeConfig, UnixSinkStore};

use ed25519_dalek::VerifyingKey;
use std::path::{Path, PathBuf};

/// Explicit production selection for a separately administered Unix sink.
#[derive(Clone, Debug)]
pub struct UnixSinkConfig {
    pub socket: PathBuf,
    pub receipt_key: VerifyingKey,
    pub journal_id: [u8; 16],
    pub server_uid: u32,
}

impl UnixSinkConfig {
    pub fn from_cli(
        endpoint: &str,
        key_path: &Path,
        journal_id: [u8; 16],
        server_uid: u32,
    ) -> Result<Self, String> {
        let socket = endpoint
            .strip_prefix("unix:")
            .ok_or("Unix sink endpoint must use unix:/absolute/path")?;
        let socket = PathBuf::from(socket);
        if !socket.is_absolute() {
            return Err("Unix sink socket path must be absolute".into());
        }
        let file =
            ferro_core::authorization::open_path_no_symlinks(key_path, nix::libc::O_RDONLY, 0)
                .map_err(|e| e.to_string())?;
        let metadata = file.metadata().map_err(|e| e.to_string())?;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() != 32
        {
            return Err("sink receipt key is not an owner-only 32-byte single-link file".into());
        }
        use std::io::Read;
        let mut bytes = [0; 32];
        (&file).read_exact(&mut bytes).map_err(|e| e.to_string())?;
        let receipt_key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid sink receipt public key")?;
        Ok(Self {
            socket,
            receipt_key,
            journal_id,
            server_uid,
        })
    }

    pub fn connect(&self) -> Result<UnixAppendOnlySink, String> {
        UnixAppendOnlySink::open(&self.socket, self.server_uid, self.receipt_key)
    }

    pub fn from_pinned(
        socket: PathBuf,
        receipt_key: [u8; 32],
        journal_id: [u8; 16],
        server_uid: u32,
    ) -> Result<Self, String> {
        Ok(Self {
            socket,
            receipt_key: VerifyingKey::from_bytes(&receipt_key)
                .map_err(|_| "invalid pinned sink receipt public key")?,
            journal_id,
            server_uid,
        })
    }
}
