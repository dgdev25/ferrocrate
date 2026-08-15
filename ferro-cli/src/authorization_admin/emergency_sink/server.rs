use super::protocol::{read_frame, write_frame, SinkReceipt, SinkRequest};
use ed25519_dalek::SigningKey;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::Path,
};

const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;
const FRAME_MAGIC: &[u8; 8] = b"FRCSF001";
const FRAME_COMMIT: &[u8; 8] = b"FRCMT001";

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
    lifecycles: BTreeMap<String, LifecycleState>,
    key: SigningKey,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSinkEntry {
    version: u8,
    record: Vec<u8>,
    receipt: SinkReceipt,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRecord {
    schema: u8,
    #[serde(rename = "type")]
    record_type: String,
    boot_id: String,
    deadline_uptime_ns: u64,
    action: String,
    resource: String,
    emergency_nonce: String,
    operation_id: Option<String>,
    terminal_event_id: Option<String>,
    succeeded: Option<bool>,
}

#[derive(Clone)]
struct LifecycleState {
    boot_id: String,
    deadline: u64,
    action: String,
    resource: String,
    operation_id: Option<String>,
    stage: String,
}

fn apply_lifecycle(
    states: &mut BTreeMap<String, LifecycleState>,
    record: &CanonicalRecord,
) -> Result<(), String> {
    match record.record_type.as_str() {
        "activate"
            if record.operation_id.is_none()
                && record.terminal_event_id.is_none()
                && record.succeeded.is_none() =>
        {
            if states.contains_key(&record.emergency_nonce) {
                return Err("emergency nonce lifecycle fork".into());
            }
            states.insert(
                record.emergency_nonce.clone(),
                LifecycleState {
                    boot_id: record.boot_id.clone(),
                    deadline: record.deadline_uptime_ns,
                    action: record.action.clone(),
                    resource: record.resource.clone(),
                    operation_id: None,
                    stage: "activate".into(),
                },
            );
        }
        next => {
            let state = states
                .get_mut(&record.emergency_nonce)
                .ok_or("emergency lifecycle lacks activation")?;
            if state.boot_id != record.boot_id
                || state.deadline != record.deadline_uptime_ns
                || state.action != record.action
                || state.resource != record.resource
            {
                return Err("emergency lifecycle immutable binding fork".into());
            }
            match (state.stage.as_str(), next) {
                ("activate", "intent")
                    if record.operation_id.is_some()
                        && record.terminal_event_id.is_none()
                        && record.succeeded.is_none() =>
                {
                    state.operation_id = record.operation_id.clone();
                    state.stage = "intent".into();
                }
                ("intent", "outcome")
                    if record.operation_id == state.operation_id
                        && record.terminal_event_id.is_some()
                        && record.succeeded.is_some() =>
                {
                    state.stage = "outcome".into()
                }
                ("intent", "quarantine")
                    if record.operation_id == state.operation_id
                        && record.terminal_event_id.is_some()
                        && record.succeeded.is_none() =>
                {
                    state.stage = "quarantine".into()
                }
                ("outcome", "reconcile") | ("quarantine", "reconcile")
                    if record.operation_id == state.operation_id
                        && record.terminal_event_id.is_some()
                        && record.succeeded.is_none() =>
                {
                    state.stage = "reconcile".into()
                }
                _ => return Err("emergency lifecycle transition fork".into()),
            }
        }
    }
    Ok(())
}

fn validate_canonical_record(
    bytes: &[u8],
    nonce: &str,
    sink_operation: [u8; 16],
) -> Result<CanonicalRecord, String> {
    let record: CanonicalRecord =
        serde_json::from_slice(bytes).map_err(|_| "invalid canonical emergency sink record")?;
    let mut base = [0; 16];
    if let Some(operation) = record.operation_id.as_deref() {
        if operation.len() != 32 || !operation.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid canonical emergency operation ID".into());
        }
        for (index, byte) in base.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&operation[index * 2..index * 2 + 2], 16)
                .map_err(|_| "invalid canonical emergency operation ID")?;
        }
    }
    let mut operation_input = base.to_vec();
    operation_input.push(0);
    operation_input.extend_from_slice(record.record_type.as_bytes());
    let digest = Sha256::digest(&operation_input);
    if record.schema != 1
        || !matches!(
            record.record_type.as_str(),
            "activate" | "intent" | "outcome" | "quarantine" | "reconcile"
        )
        || record.emergency_nonce != nonce
        || record.action.is_empty()
        || record.action.len() > 64
        || record.resource.is_empty()
        || record.resource.len() > 256
        || serde_json::to_vec(&record).map_err(|e| e.to_string())? != bytes
        || sink_operation != digest[..16]
    {
        return Err("invalid canonical emergency sink record binding".into());
    }
    Ok(record)
}

impl UnixSinkStore {
    pub fn open(mut file: File, journal_id: [u8; 16], key: SigningKey) -> Result<Self, String> {
        if file.metadata().map_err(|e| e.to_string())?.len() > MAX_STORE_BYTES {
            return Err("emergency sink store exceeds bounded restart size".into());
        }
        let mut reader = file.try_clone().map_err(|e| e.to_string())?;
        reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut offset = 0u64;
        let mut next_sequence = 0;
        let mut head = [0; 32];
        let mut receipts = BTreeMap::new();
        let mut lifecycles = BTreeMap::new();
        loop {
            let frame_start = offset;
            let mut magic = [0; FRAME_MAGIC.len()];
            match reader.read(&mut magic[..1]) {
                Ok(0) => break,
                Ok(1) => {}
                Ok(_) => unreachable!(),
                Err(error) => return Err(error.to_string()),
            }
            let mut length_bytes = [0; 4];
            let mut header_checksum = [0; 32];
            let header_incomplete = reader.read_exact(&mut magic[1..]).is_err()
                || reader.read_exact(&mut length_bytes).is_err()
                || reader.read_exact(&mut header_checksum).is_err();
            if header_incomplete {
                file.set_len(frame_start)
                    .and_then(|_| file.sync_all())
                    .map_err(|e| e.to_string())?;
                break;
            }
            let expected_header = Sha256::digest([magic.as_slice(), &length_bytes].concat());
            if &magic != FRAME_MAGIC || header_checksum != expected_header[..] {
                return Err("committed emergency sink frame header mismatch".into());
            }
            let length = u32::from_be_bytes(length_bytes) as usize;
            if length > super::protocol::MAX_FRAME_BYTES {
                return Err("invalid emergency sink store frame".into());
            }
            let mut body = vec![0; length];
            let mut checksum = [0; 32];
            let mut commit = [0; FRAME_COMMIT.len()];
            let incomplete = reader.read_exact(&mut body).is_err()
                || reader.read_exact(&mut checksum).is_err()
                || reader.read_exact(&mut commit).is_err();
            if incomplete {
                file.set_len(frame_start)
                    .and_then(|_| file.sync_all())
                    .map_err(|e| e.to_string())?;
                break;
            }
            if checksum != Sha256::digest(&body)[..] || &commit != FRAME_COMMIT {
                return Err("committed emergency sink frame checksum mismatch".into());
            }
            let entry: StoredSinkEntry =
                serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            if entry.version != 1
                || Sha256::digest(&entry.record).as_slice() != entry.receipt.record_hash
            {
                return Err("emergency sink stored record hash mismatch".into());
            }
            let canonical = validate_canonical_record(
                &entry.record,
                &entry.receipt.emergency_nonce,
                entry.receipt.operation_id,
            )?;
            apply_lifecycle(&mut lifecycles, &canonical)?;
            let receipt = entry.receipt;
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
                .insert(
                    receipt_key(&receipt.emergency_nonce, receipt.operation_id),
                    receipt.clone(),
                )
                .is_some()
            {
                return Err("duplicate emergency nonce in sink store".into());
            }
            head = receipt.head;
            next_sequence += 1;
            offset +=
                FRAME_MAGIC.len() as u64 + 4 + 32 + length as u64 + 32 + FRAME_COMMIT.len() as u64;
        }
        file.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        Ok(Self {
            file,
            journal_id,
            next_sequence,
            head,
            receipts,
            lifecycles,
            key,
        })
    }

    pub fn append(&mut self, request: SinkRequest) -> Result<SinkReceipt, String> {
        request.validate()?;
        if request.query_head {
            return Err("head query is not an append".into());
        }
        let canonical = validate_canonical_record(
            &request.record,
            &request.emergency_nonce,
            request.operation_id,
        )?;
        if request.journal_id != self.journal_id {
            return Err("sink journal substitution".into());
        }
        let idempotency_key = receipt_key(&request.emergency_nonce, request.operation_id);
        if let Some(receipt) = self.receipts.get(&idempotency_key) {
            if receipt.operation_id == request.operation_id
                && receipt.record_hash == request.record_hash
            {
                return Ok(receipt.clone());
            }
            return Err("emergency nonce replay fork".into());
        }
        if request.expected_sequence != self.next_sequence || request.expected_head != self.head {
            return Err("sink sequence fork".into());
        }
        let mut lifecycle = self.lifecycles.clone();
        apply_lifecycle(&mut lifecycle, &canonical)?;
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
        let durable = serde_json::to_vec(&StoredSinkEntry {
            version: 1,
            record: request.record,
            receipt: receipt.clone(),
        })
        .map_err(|e| e.to_string())?;
        let length = (durable.len() as u32).to_be_bytes();
        let header_checksum = Sha256::digest([FRAME_MAGIC.as_slice(), &length].concat());
        self.file
            .write_all(FRAME_MAGIC)
            .and_then(|_| self.file.write_all(&length))
            .and_then(|_| self.file.write_all(&header_checksum))
            .and_then(|_| self.file.write_all(&durable))
            .and_then(|_| self.file.write_all(&Sha256::digest(&durable)))
            .and_then(|_| self.file.write_all(FRAME_COMMIT))
            .and_then(|_| self.file.sync_all())
            .map_err(|e| e.to_string())?;
        self.next_sequence += 1;
        self.head = head;
        self.receipts.insert(idempotency_key, receipt.clone());
        self.lifecycles = lifecycle;
        Ok(receipt)
    }

    fn head_receipt(&self, request: &SinkRequest) -> Result<SinkReceipt, String> {
        request.validate()?;
        if !request.query_head || request.journal_id != self.journal_id {
            return Err("invalid sink head query".into());
        }
        let mut receipt = SinkReceipt {
            version: 1,
            journal_id: self.journal_id,
            sequence: self.next_sequence,
            emergency_nonce: String::new(),
            operation_id: [0; 16],
            record_hash: [0; 32],
            head: self.head,
            signature: Vec::new(),
        };
        receipt.sign(&self.key)?;
        Ok(receipt)
    }
}

fn receipt_key(nonce: &str, operation_id: [u8; 16]) -> String {
    let operation = operation_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{nonce}:{operation}")
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
    let receipt = if request.query_head {
        store.head_receipt(&request)?
    } else {
        store.append(request)?
    };
    write_frame(&mut stream, &receipt)
}

pub fn serve(config: SinkServeConfig<'_>) -> Result<(), String> {
    let parent = config.socket.parent().ok_or("sink socket has no parent")?;
    validate_admin_directory(parent)?;
    if config.socket.exists() {
        return Err("sink socket path already exists".into());
    }
    let file = ferro_core::authorization::open_path_no_symlinks(
        config.store,
        nix::libc::O_RDWR | nix::libc::O_APPEND,
        0,
    )
    .map_err(|e| format!("open sink store: {e}"))?;
    validate_owner_file(&file)?;
    let mut raw_key = Vec::new();
    let key_file = ferro_core::authorization::open_path_no_symlinks(
        config.signing_key,
        nix::libc::O_RDONLY,
        0,
    )
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
        let record_type = if sequence == 0 { "activate" } else { "intent" };
        let body = serde_json::to_vec(&CanonicalRecord {
            schema: 1,
            record_type: record_type.into(),
            boot_id: "boot".into(),
            deadline_uptime_ns: 10,
            action: "container.stop".into(),
            resource: String::from_utf8_lossy(body).into_owned(),
            emergency_nonce: nonce.into(),
            operation_id: None,
            terminal_event_id: None,
            succeeded: None,
        })
        .unwrap();
        let operation_digest =
            Sha256::digest([&[0; 16][..], &[0], record_type.as_bytes()].concat());
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&operation_digest[..16]);
        SinkRequest {
            version: 1,
            query_head: false,
            journal_id: [1; 16],
            expected_sequence: sequence,
            expected_head: if sequence == 0 { [0; 32] } else { [9; 32] },
            emergency_nonce: nonce.into(),
            operation_id,
            record_hash: Sha256::digest(&body).into(),
            record: body,
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
            .contains("fork"));
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

    #[test]
    fn restart_rejects_a_stored_record_that_does_not_match_its_signed_receipt() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let path = named.path().to_owned();
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut store = UnixSinkStore::open(named.reopen().unwrap(), [1; 16], key.clone()).unwrap();
        store.append(request("n", 0, b"intent")).unwrap();
        drop(store);

        let bytes = std::fs::read(&path).unwrap();
        let length = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let mut entry: StoredSinkEntry = serde_json::from_slice(&bytes[44..44 + length]).unwrap();
        entry.record[0] ^= 1;
        let body = serde_json::to_vec(&entry).unwrap();
        let length = (body.len() as u32).to_be_bytes();
        let mut corrupt = FRAME_MAGIC.to_vec();
        corrupt.extend_from_slice(&length);
        corrupt.extend_from_slice(&Sha256::digest([FRAME_MAGIC.as_slice(), &length].concat()));
        corrupt.extend_from_slice(&body);
        corrupt.extend_from_slice(&Sha256::digest(&body));
        corrupt.extend_from_slice(FRAME_COMMIT);
        std::fs::write(&path, corrupt).unwrap();

        let file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .unwrap();
        assert!(UnixSinkStore::open(file, [1; 16], key)
            .err()
            .unwrap()
            .contains("stored record hash mismatch"));
    }

    #[test]
    fn restart_rejects_oversized_store_without_allocating_it() {
        let named = tempfile::NamedTempFile::new().unwrap();
        named.as_file().set_len(MAX_STORE_BYTES + 1).unwrap();
        assert!(UnixSinkStore::open(
            named.reopen().unwrap(),
            [1; 16],
            SigningKey::from_bytes(&[7; 32])
        )
        .err()
        .unwrap()
        .contains("bounded restart size"));
    }

    #[test]
    fn restart_truncates_only_an_incomplete_uncommitted_tail() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let path = named.path().to_owned();
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut store = UnixSinkStore::open(named.reopen().unwrap(), [1; 16], key.clone()).unwrap();
        store.append(request("n", 0, b"resource")).unwrap();
        drop(store);
        let committed = std::fs::metadata(&path).unwrap().len();
        let committed_bytes = std::fs::read(&path).unwrap();
        let length = 10_u32.to_be_bytes();
        let header = [
            FRAME_MAGIC.as_slice(),
            &length,
            &Sha256::digest([FRAME_MAGIC.as_slice(), &length].concat()),
        ]
        .concat();
        for tail in [
            FRAME_MAGIC[..3].to_vec(),
            [header.as_slice(), b"short"].concat(),
            [header.as_slice(), b"0123456789", &[1; 12]].concat(),
            [
                header.as_slice(),
                b"0123456789",
                Sha256::digest(b"0123456789").as_slice(),
                &FRAME_COMMIT[..3],
            ]
            .concat(),
        ] {
            let mut bytes = committed_bytes.clone();
            bytes.extend_from_slice(&tail);
            std::fs::write(&path, bytes).unwrap();
            let file = std::fs::OpenOptions::new()
                .read(true)
                .append(true)
                .open(&path)
                .unwrap();
            UnixSinkStore::open(file, [1; 16], key.clone()).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().len(), committed);
        }

        let mut corrupt = committed_bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        std::fs::write(&path, corrupt).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .unwrap();
        assert!(UnixSinkStore::open(file, [1; 16], key)
            .err()
            .unwrap()
            .contains("checksum mismatch"));
    }

    #[test]
    fn restart_rejects_committed_upward_length_corruption() {
        let named = tempfile::NamedTempFile::new().unwrap();
        let path = named.path().to_owned();
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut store = UnixSinkStore::open(named.reopen().unwrap(), [1; 16], key.clone()).unwrap();
        store.append(request("n", 0, b"resource")).unwrap();
        drop(store);
        let mut bytes = std::fs::read(&path).unwrap();
        let length = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        bytes[8..12].copy_from_slice(&length.saturating_add(1024).to_be_bytes());
        std::fs::write(&path, bytes).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(path)
            .unwrap();
        assert!(UnixSinkStore::open(file, [1; 16], key)
            .err()
            .unwrap()
            .contains("header mismatch"));
    }

    #[test]
    fn lifecycle_rejects_cross_transition_binding_and_shape_forks() {
        let mut states = BTreeMap::new();
        let mut record = CanonicalRecord {
            schema: 1,
            record_type: "activate".into(),
            boot_id: "boot".into(),
            deadline_uptime_ns: 10,
            action: "container.stop".into(),
            resource: "container:x".into(),
            emergency_nonce: "nonce".into(),
            operation_id: None,
            terminal_event_id: None,
            succeeded: None,
        };
        apply_lifecycle(&mut states, &record).unwrap();
        record.record_type = "intent".into();
        record.operation_id = Some("11".repeat(16));
        record.resource = "container:fork".into();
        assert!(apply_lifecycle(&mut states, &record)
            .unwrap_err()
            .contains("immutable binding fork"));
        record.resource = "container:x".into();
        apply_lifecycle(&mut states, &record).unwrap();
        record.record_type = "outcome".into();
        record.succeeded = Some(true);
        assert!(apply_lifecycle(&mut states, &record)
            .unwrap_err()
            .contains("transition fork"));
    }

    #[test]
    fn service_rejects_symlinked_or_writable_store_and_signing_key() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = root.path().join("store");
        let key = root.path().join("key");
        std::fs::write(&store, b"").unwrap();
        std::fs::write(&key, [7; 32]).unwrap();
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store_link = root.path().join("store-link");
        std::os::unix::fs::symlink(&store, &store_link).unwrap();
        let socket = root.path().join("socket");
        let uid = nix::unistd::geteuid().as_raw();
        assert!(serve(SinkServeConfig {
            socket: &socket,
            store: &store_link,
            signing_key: &key,
            journal_id: [1; 16],
            expected_uid: uid,
            requests: Some(0)
        })
        .is_err());
        let key_link = root.path().join("key-link");
        std::os::unix::fs::symlink(&key, &key_link).unwrap();
        assert!(serve(SinkServeConfig {
            socket: &socket,
            store: &store,
            signing_key: &key_link,
            journal_id: [1; 16],
            expected_uid: uid,
            requests: Some(0)
        })
        .is_err());
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(serve(SinkServeConfig {
            socket: &socket,
            store: &store,
            signing_key: &key,
            journal_id: [1; 16],
            expected_uid: uid,
            requests: Some(0)
        })
        .is_err());
    }
}
