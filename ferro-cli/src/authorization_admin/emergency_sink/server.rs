use super::protocol::{read_frame, write_frame, SinkReceipt, SinkRequest};
use ed25519_dalek::SigningKey;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixListener,
    },
    path::Path,
};

pub struct SinkServeConfig<'a> {
    pub socket: &'a Path,
    pub store: &'a Path,
    pub signing_key: &'a Path,
    pub journal_id: [u8; 16],
    pub expected_uid: u32,
    pub requests: Option<u64>,
}

pub struct UnixSinkStore {
    file: File,
    journal_id: [u8; 16],
    next_sequence: u64,
    head: [u8; 32],
    receipts: BTreeMap<String, SinkReceipt>,
    key: SigningKey,
}

impl UnixSinkStore {
    pub fn open(mut file: File, journal_id: [u8; 16], key: SigningKey) -> Result<Self, String> {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let mut offset = 0usize;
        let mut next_sequence = 0;
        let mut head = [0; 32];
        let mut receipts = BTreeMap::new();
        while offset < bytes.len() {
            if bytes.len() - offset < 4 {
                return Err("truncated emergency sink store".into());
            }
            let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if length > super::protocol::MAX_FRAME_BYTES || bytes.len() - offset < length {
                return Err("invalid emergency sink store frame".into());
            }
            let receipt: SinkReceipt = serde_json::from_slice(&bytes[offset..offset + length])
                .map_err(|e| e.to_string())?;
            receipt.verify(&key.verifying_key())?;
            if receipt.journal_id != journal_id || receipt.sequence != next_sequence {
                return Err("emergency sink store chain mismatch".into());
            }
            let mut expected = Sha256::new();
            expected.update(head);
            expected.update(receipt.record_hash);
            let expected_head: [u8; 32] = expected.finalize().into();
            if receipt.head != expected_head {
                return Err("emergency sink store head mismatch".into());
            }
            if receipts
                .insert(receipt.emergency_nonce.clone(), receipt.clone())
                .is_some()
            {
                return Err("duplicate emergency nonce in sink store".into());
            }
            head = receipt.head;
            next_sequence += 1;
            offset += length;
        }
        Ok(Self {
            file,
            journal_id,
            next_sequence,
            head,
            receipts,
            key,
        })
    }

    pub fn append(&mut self, request: SinkRequest) -> Result<SinkReceipt, String> {
        request.validate()?;
        if request.journal_id != self.journal_id {
            return Err("sink journal substitution".into());
        }
        if let Some(receipt) = self.receipts.get(&request.emergency_nonce) {
            if receipt.operation_id == request.operation_id
                && receipt.record_hash == request.record_hash
            {
                return Ok(receipt.clone());
            }
            return Err("emergency nonce replay fork".into());
        }
        if request.expected_sequence != self.next_sequence {
            return Err("sink sequence fork".into());
        }
        let mut hash = Sha256::new();
        hash.update(self.head);
        hash.update(request.record_hash);
        let head: [u8; 32] = hash.finalize().into();
        let mut receipt = SinkReceipt {
            version: 1,
            journal_id: self.journal_id,
            sequence: self.next_sequence,
            emergency_nonce: request.emergency_nonce.clone(),
            operation_id: request.operation_id,
            record_hash: request.record_hash,
            head,
            signature: Vec::new(),
        };
        receipt.sign(&self.key)?;
        let durable = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        self.file
            .write_all(&(durable.len() as u32).to_be_bytes())
            .and_then(|_| self.file.write_all(&durable))
            .and_then(|_| self.file.sync_all())
            .map_err(|e| e.to_string())?;
        self.next_sequence += 1;
        self.head = head;
        self.receipts
            .insert(request.emergency_nonce, receipt.clone());
        Ok(receipt)
    }
}

pub fn serve_one(
    listener: &UnixListener,
    store: &mut UnixSinkStore,
    expected_uid: u32,
) -> Result<(), String> {
    let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
    let peer = getsockopt(&stream, PeerCredentials).map_err(|e| e.to_string())?;
    if peer.uid() != expected_uid {
        return Err("unexpected emergency sink client UID".into());
    }
    let request: SinkRequest = read_frame(&mut stream)?;
    let receipt = store.append(request)?;
    write_frame(&mut stream, &receipt)
}

pub fn serve(config: SinkServeConfig<'_>) -> Result<(), String> {
    let parent = config.socket.parent().ok_or("sink socket has no parent")?;
    validate_admin_directory(parent)?;
    if config.socket.exists() {
        return Err("sink socket path already exists".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .mode(0o600)
        .open(config.store)
        .map_err(|e| format!("open sink store: {e}"))?;
    validate_owner_file(&file)?;
    let mut raw_key = Vec::new();
    let key_file = OpenOptions::new()
        .read(true)
        .open(config.signing_key)
        .map_err(|e| format!("open sink signing key: {e}"))?;
    validate_owner_file(&key_file)?;
    if key_file.metadata().map_err(|e| e.to_string())?.len() != 32 {
        return Err("sink signing key must contain exactly 32 raw bytes".into());
    }
    key_file
        .take(32)
        .read_to_end(&mut raw_key)
        .map_err(|e| e.to_string())?;
    if raw_key.len() != 32 {
        return Err("sink signing key must contain exactly 32 raw bytes".into());
    }
    let key = SigningKey::from_bytes(
        raw_key
            .as_slice()
            .try_into()
            .map_err(|_| "invalid sink signing key")?,
    );
    let listener = UnixListener::bind(config.socket).map_err(|e| e.to_string())?;
    std::fs::set_permissions(config.socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let mut store = UnixSinkStore::open(file, config.journal_id, key)?;
    let count = config.requests.unwrap_or(u64::MAX);
    let result = (0..count).try_for_each(|_| serve_one(&listener, &mut store, config.expected_uid));
    let _ = std::fs::remove_file(config.socket);
    result
}

fn validate_admin_directory(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err("sink socket parent is not administrator controlled".into());
    }
    Ok(())
}

fn validate_owner_file(file: &File) -> Result<(), String> {
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err("sink file is not an owner-only single-link regular file".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn request(nonce: &str, sequence: u64, body: &[u8]) -> SinkRequest {
        SinkRequest {
            version: 1,
            journal_id: [1; 16],
            expected_sequence: sequence,
            emergency_nonce: nonce.into(),
            operation_id: [2; 16],
            record: body.into(),
            record_hash: Sha256::digest(body).into(),
        }
    }

    #[test]
    fn signs_idempotent_receipts_and_rejects_replay_forks() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let path = named.path().to_owned();
        let file = named.reopen().unwrap();
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut store = UnixSinkStore::open(file, [1; 16], key.clone()).unwrap();
        let first = store.append(request("n", 0, b"intent")).unwrap();
        first.verify(&key.verifying_key()).unwrap();
        assert_eq!(store.append(request("n", 0, b"intent")).unwrap(), first);
        assert!(store
            .append(request("n", 1, b"different"))
            .unwrap_err()
            .contains("replay fork"));
        assert!(store
            .append(request("next", 9, b"outcome"))
            .unwrap_err()
            .contains("sequence fork"));
        drop(store);
        let restart_file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .unwrap();
        let mut restarted = UnixSinkStore::open(restart_file, [1; 16], key).unwrap();
        assert_eq!(restarted.append(request("n", 0, b"intent")).unwrap(), first);
        assert!(restarted.append(request("n", 1, b"different")).is_err());
    }
}
