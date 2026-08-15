use crate::{effect_receipt::EffectReceipt, server_state::OverlayMutationIntent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAGIC: &[u8; 8] = b"FRONJNL1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 16 + 8 + 4;
const CHECKSUM_LEN: usize = 32;
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct PersistedState {
    pub(crate) overlays: BTreeSet<String>,
    pub(crate) endpoints: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) routes: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub(crate) addresses: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub(crate) effect_receipts: BTreeMap<String, EffectReceipt>,
    #[serde(default)]
    pub(crate) quarantined: BTreeSet<String>,
    #[serde(default)]
    pub(crate) overlay_intents: BTreeMap<String, OverlayMutationIntent>,
}

pub(crate) struct LoadedJournal {
    pub(crate) state: Option<PersistedState>,
    pub(crate) journal_id: [u8; 16],
    pub(crate) generation: u64,
}

pub(crate) fn load(path: &Path) -> Result<LoadedJournal, String> {
    quarantine_stale_temps(path)?;
    if !path.exists() {
        return Ok(LoadedJournal {
            state: None,
            journal_id: new_journal_id()?,
            generation: 0,
        });
    }
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() as usize > HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN {
        return Err("ownership journal exceeds maximum frame size".into());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let (journal_id, generation, state) = decode(&bytes)?;
    Ok(LoadedJournal {
        state: Some(state),
        journal_id,
        generation,
    })
}

pub(crate) fn store(
    path: &Path,
    journal_id: [u8; 16],
    generation: u64,
    state: &PersistedState,
) -> Result<(), String> {
    static TEMP_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let bytes = encode(journal_id, generation, state)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("invalid journal path")?;
    let temporary = path.with_file_name(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn encode(id: [u8; 16], generation: u64, state: &PersistedState) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(state).map_err(|error| error.to_string())?;
    if payload.len() > MAX_PAYLOAD {
        return Err("ownership journal payload exceeds limit".into());
    }
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len() + CHECKSUM_LEN);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&VERSION.to_be_bytes());
    frame.extend_from_slice(&id);
    frame.extend_from_slice(&generation.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&Sha256::digest(&frame));
    Ok(frame)
}

fn decode(bytes: &[u8]) -> Result<([u8; 16], u64, PersistedState), String> {
    if bytes.len() < HEADER_LEN + CHECKSUM_LEN || &bytes[..8] != MAGIC {
        return Err("invalid ownership journal frame".into());
    }
    if u16::from_be_bytes(bytes[8..10].try_into().expect("version")) != VERSION {
        return Err("unsupported ownership journal version".into());
    }
    let mut id = [0; 16];
    id.copy_from_slice(&bytes[10..26]);
    let generation = u64::from_be_bytes(bytes[26..34].try_into().expect("generation"));
    let payload_len = u32::from_be_bytes(bytes[34..38].try_into().expect("length")) as usize;
    if payload_len > MAX_PAYLOAD || bytes.len() != HEADER_LEN + payload_len + CHECKSUM_LEN {
        return Err("invalid ownership journal payload length".into());
    }
    let checksum_at = HEADER_LEN + payload_len;
    if Sha256::digest(&bytes[..checksum_at]).as_slice() != &bytes[checksum_at..] {
        return Err("ownership journal checksum mismatch".into());
    }
    let state = serde_json::from_slice(&bytes[HEADER_LEN..checksum_at])
        .map_err(|error| error.to_string())?;
    Ok((id, generation, state))
}

fn quarantine_stale_temps(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("journal has no parent directory")?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("invalid journal path")?;
    let prefix = format!(".{file_name}.tmp.");
    for entry in fs::read_dir(parent).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        let bounded = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(entry.path())
            .map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        bounded
            .take((HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        let digest = Sha256::digest(&bytes)[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let quarantine = path.with_file_name(format!(".{file_name}.quarantine.{digest}"));
        fs::rename(entry.path(), quarantine).map_err(|error| error.to_string())?;
    }
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    fs::File::open(path.parent().ok_or("journal has no parent directory")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

fn new_journal_id() -> Result<[u8; 16], String> {
    let mut id = [0; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut id))
        .map_err(|error| error.to_string())?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_rejects_partial_or_modified_primary() {
        let state = PersistedState::default();
        let mut bytes = encode([7; 16], 4, &state).unwrap();
        bytes[HEADER_LEN] ^= 1;
        assert!(decode(&bytes).unwrap_err().contains("checksum"));
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    }
}
