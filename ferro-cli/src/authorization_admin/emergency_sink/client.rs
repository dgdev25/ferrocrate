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
    socket_identity: SocketIdentity,
    server_uid: u32,
    key: VerifyingKey,
}

#[cfg(target_env = "gnu")]
type SocketIdentity = (u64, u64);

#[cfg(not(target_env = "gnu"))]
type SocketIdentity = (u64, u64, i64, i64);

fn socket_identity(metadata: &Metadata) -> SocketIdentity {
    #[cfg(target_env = "gnu")]
    {
        (metadata.dev(), metadata.ino())
    }
    #[cfg(not(target_env = "gnu"))]
    {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    }
}

impl UnixAppendOnlySink {
    pub fn open(socket: &Path, server_uid: u32, key: VerifyingKey) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(socket).map_err(|e| e.to_string())?;
        validate_socket(&metadata, server_uid)?;
        Ok(Self {
            socket: socket.into(),
            socket_identity: socket_identity(&metadata),
            server_uid,
            key,
        })
    }

    pub fn append(&self, request: &SinkRequest) -> Result<SinkReceipt, String> {
        if request.query_head {
            return Err("head query is not an append".into());
        }
        self.exchange(request, false)
    }

    pub fn head(&self, journal_id: [u8; 16]) -> Result<(u64, [u8; 32]), String> {
        let request = SinkRequest {
            version: 1,
            query_head: true,
            journal_id,
            expected_sequence: 0,
            expected_head: [0; 32],
            emergency_nonce: String::new(),
            operation_id: [0; 16],
            record: Vec::new(),
            record_hash: [0; 32],
        };
        let receipt = self.exchange(&request, true)?;
        Ok((receipt.sequence, receipt.head))
    }

    fn exchange(&self, request: &SinkRequest, query: bool) -> Result<SinkReceipt, String> {
        let metadata = std::fs::symlink_metadata(&self.socket).map_err(|e| e.to_string())?;
        validate_socket(&metadata, self.server_uid)?;
        if socket_identity(&metadata) != self.socket_identity {
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
            || (!query && receipt.emergency_nonce != request.emergency_nonce)
            || (!query && receipt.operation_id != request.operation_id)
            || (!query && receipt.record_hash != request.record_hash)
            || (!query && receipt.sequence != request.expected_sequence)
            || (query
                && (!receipt.emergency_nonce.is_empty()
                    || receipt.operation_id != [0; 16]
                    || receipt.record_hash != [0; 32]))
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
        let record = br#"{"schema":1,"type":"activate","boot_id":"boot","deadline_uptime_ns":10,"action":"container.stop","resource":"container:x","emergency_nonce":"nonce","operation_id":null,"terminal_event_id":null,"succeeded":null}"#.to_vec();
        let operation_digest = Sha256::digest([&[0; 16][..], &[0], b"activate"].concat());
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&operation_digest[..16]);
        let request = SinkRequest {
            version: 1,
            query_head: false,
            journal_id: [3; 16],
            expected_sequence: 0,
            expected_head: [0; 32],
            emergency_nonce: "nonce".into(),
            operation_id,
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
