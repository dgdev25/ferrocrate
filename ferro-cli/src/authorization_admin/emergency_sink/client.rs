use super::protocol::{read_frame, write_frame, SinkReceipt, SinkRequest};
use ed25519_dalek::VerifyingKey;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::{
    fs::Metadata,
    os::unix::{fs::MetadataExt, net::UnixStream},
    path::{Path, PathBuf},
};

pub struct UnixAppendOnlySink {
    socket: PathBuf,
    socket_identity: (u64, u64),
    server_uid: u32,
    key: VerifyingKey,
}

impl UnixAppendOnlySink {
    pub fn open(socket: &Path, server_uid: u32, key: VerifyingKey) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(socket).map_err(|e| e.to_string())?;
        validate_socket(&metadata, server_uid)?;
        Ok(Self {
            socket: socket.into(),
            socket_identity: (metadata.dev(), metadata.ino()),
            server_uid,
            key,
        })
    }

    pub fn append(&self, request: &SinkRequest) -> Result<SinkReceipt, String> {
        let metadata = std::fs::symlink_metadata(&self.socket).map_err(|e| e.to_string())?;
        validate_socket(&metadata, self.server_uid)?;
        if (metadata.dev(), metadata.ino()) != self.socket_identity {
            return Err("emergency sink socket identity changed".into());
        }
        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|e| format!("emergency sink unavailable: {e}"))?;
        let peer = getsockopt(&stream, PeerCredentials).map_err(|e| e.to_string())?;
        if peer.uid() != self.server_uid {
            return Err("unexpected emergency sink server UID".into());
        }
        write_frame(&mut stream, request)?;
        let receipt: SinkReceipt = read_frame(&mut stream)?;
        receipt.verify(&self.key)?;
        if receipt.journal_id != request.journal_id
            || receipt.emergency_nonce != request.emergency_nonce
            || receipt.operation_id != request.operation_id
            || receipt.record_hash != request.record_hash
            || receipt.sequence != request.expected_sequence
        {
            return Err("emergency sink receipt binding mismatch".into());
        }
        Ok(receipt)
    }
}

fn validate_socket(metadata: &Metadata, uid: u32) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt;
    if !metadata.file_type().is_socket() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        return Err("emergency sink socket is not trusted".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization_admin::emergency_sink::{serve_one, UnixSinkStore};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::{fs::PermissionsExt, net::UnixListener},
        thread,
    };

    #[test]
    fn authenticates_real_socket_server_and_rejects_socket_replacement() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("sink.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let key = SigningKey::from_bytes(&[8; 32]);
        let uid = nix::unistd::geteuid().as_raw();
        let client = UnixAppendOnlySink::open(&socket, uid, key.verifying_key()).unwrap();
        let handle = thread::spawn(move || {
            let mut store =
                UnixSinkStore::open(tempfile::tempfile().unwrap(), [3; 16], key).unwrap();
            serve_one(&listener, &mut store, uid).unwrap();
        });
        let record = b"intent".to_vec();
        let request = SinkRequest {
            version: 1,
            journal_id: [3; 16],
            expected_sequence: 0,
            expected_head: [0; 32],
            emergency_nonce: "nonce".into(),
            operation_id: [4; 16],
            record_hash: Sha256::digest(&record).into(),
            record,
        };
        assert_eq!(client.append(&request).unwrap().sequence, 0);
        handle.join().unwrap();
        std::fs::remove_file(&socket).unwrap();
        let replacement = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(client
            .append(&request)
            .unwrap_err()
            .contains("identity changed"));
        drop(replacement);
    }
}
