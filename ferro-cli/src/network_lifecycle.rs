//! Durable named-network lifecycle core (FCNET-101).
//!
//! Crate-private lifecycle state machine, durable operation journal, and
//! recovery driver for named bridge networks. Not wired to any public CLI or
//! Docker-compatible handler in this ticket.
//!
//! Safety properties:
//! - An intent is durably journaled (file fsync + atomic rename + parent
//!   directory fsync) before any kernel effect is requested.
//! - A corrupt or unreadable journal is never overwritten: all writers fail
//!   closed so on-disk evidence survives for manual recovery.
//! - Kernel identities are anchored on the observed `ifindex`, so a bridge
//!   recreated under the same name/CIDRs cannot be mistaken for the
//!   original.
//! - Ambiguous or unmarked state is quarantined (journaled, never destroyed).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ferro_core::authorization::surface::{SurfaceAuthorization, SurfacePermit};
use ferro_core::authorization::{Action as AuthorizationAction, ResourceKind};
use ferro_core::container_store::ContainerRecord;
use ferro_net::BridgeObservation;

// ---------------------------------------------------------------------------
// Identity and records
// ---------------------------------------------------------------------------

/// Observable kernel identity of a bridge. `ifindex` is present only for
/// identities that have actually been observed from the kernel; the intended
/// identity of a create is fully determined by the record and carries no
/// ifindex until observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BridgeIdentity {
    pub name: String,
    pub ifindex: Option<u32>,
    pub cidr: Option<String>,
    pub ipv6_cidr: Option<String>,
}

impl BridgeIdentity {
    /// Exact-identity comparison for delete: the observed `ifindex` must
    /// match. A same-name/same-CIDR bridge with a different ifindex was
    /// recreated and must not be deleted as if it were the original.
    fn matches_exactly(&self, observed: &BridgeIdentity) -> bool {
        self.ifindex.is_some() && self == observed
    }
}

impl From<BridgeObservation> for BridgeIdentity {
    fn from(o: BridgeObservation) -> Self {
        BridgeIdentity {
            name: o.name,
            ifindex: Some(o.ifindex),
            cidr: o.cidr,
            ipv6_cidr: o.ipv6_cidr,
        }
    }
}

/// Snapshot of the validated create record, persisted with each operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecordSnapshot {
    pub record: NetworkRecord,
}

/// Fully specified create intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkCreateRecord {
    config: ferro_net::BridgeConfig,
    record: NetworkRecord,
}

impl NetworkCreateRecord {
    /// Convert an exact `NetworkRecord` into a create intent.
    ///
    /// `BridgeConfig` is built only from `bridge_name` / `bridge_cidr`.
    /// The original record is retained unmodified for journal snapshot and
    /// store publication. Logical `record.name` is not the kernel identity.
    pub(crate) fn from_record(record: NetworkRecord) -> Result<Self, NetworkLifecycleError> {
        let config = ferro_net::BridgeConfig {
            name: record.bridge_name.clone(),
            cidr: record.bridge_cidr.clone(),
            ipv6_cidr: None,
        };
        validate_bridge_config(&config)?;
        Ok(NetworkCreateRecord { config, record })
    }

    pub(crate) fn intended_identity(&self) -> BridgeIdentity {
        BridgeIdentity {
            name: self.config.name.clone(),
            ifindex: None,
            cidr: if self.config.cidr.is_empty() {
                None
            } else {
                Some(self.config.cidr.clone())
            },
            ipv6_cidr: match self.config.ipv6_cidr.as_deref() {
                Some(v) if !v.is_empty() => Some(v.to_string()),
                _ => None,
            },
        }
    }

    /// Logical resource name (journal resource binding / store key).
    fn logical_name(&self) -> &str {
        &self.record.name
    }

    /// Kernel bridge name (`BridgeConfig` / `BridgeIdentity`).
    fn bridge_name(&self) -> &str {
        &self.config.name
    }

    pub(crate) fn published_record(&self) -> &NetworkRecord {
        &self.record
    }

    fn snapshot(&self) -> RecordSnapshot {
        RecordSnapshot {
            record: self.record.clone(),
        }
    }
}

/// Validate bridge name and CIDRs by exercising ferro-net command builders.
fn validate_bridge_config(config: &ferro_net::BridgeConfig) -> Result<(), NetworkLifecycleError> {
    ferro_net::bridge::build_ip_link_add_bridge_cmd(&config.name)
        .map_err(|e| NetworkLifecycleError::InvalidRecord(e.to_string()))?;
    if !config.cidr.is_empty() {
        ferro_net::bridge::build_ip_addr_add_bridge_cmd(&config.name, &config.cidr)
            .map_err(|e| NetworkLifecycleError::InvalidRecord(e.to_string()))?;
    }
    if let Some(v6) = config.ipv6_cidr.as_deref() {
        if !v6.is_empty() {
            ferro_net::bridge::build_ip_addr_add_ipv6_bridge_cmd(&config.name, v6)
                .map_err(|e| NetworkLifecycleError::InvalidRecord(e.to_string()))?;
        }
    }
    Ok(())
}

/// Build a validated create record. Invalid names or CIDRs are rejected
/// before any journal entry is written.
///
/// When `bridge_name` is `None`, the logical name is also used as the kernel
/// bridge name (test convenience). Production callers with distinct logical
/// and bridge names should use [`NetworkCreateRecord::from_record`].
pub(crate) fn create_network_record(
    name: &str,
    cidr: Option<&str>,
    ipv6_cidr: Option<&str>,
) -> Result<NetworkCreateRecord, NetworkLifecycleError> {
    create_network_record_with_bridge(name, name, cidr, ipv6_cidr)
}

/// Build a validated create record with an explicit kernel bridge name.
pub(crate) fn create_network_record_with_bridge(
    logical_name: &str,
    bridge_name: &str,
    cidr: Option<&str>,
    ipv6_cidr: Option<&str>,
) -> Result<NetworkCreateRecord, NetworkLifecycleError> {
    let config = ferro_net::BridgeConfig {
        name: bridge_name.to_string(),
        cidr: cidr.unwrap_or("").to_string(),
        ipv6_cidr: ipv6_cidr.map(|c| c.to_string()),
    };
    validate_bridge_config(&config)?;

    let (subnet, gateway) = if !config.cidr.is_empty() {
        (config.cidr.clone(), config.cidr.clone())
    } else {
        ("0.0.0.0/0".to_string(), "0.0.0.0".to_string())
    };

    let record = NetworkRecord {
        name: logical_name.to_string(),
        driver: "bridge".to_string(),
        subnet,
        gateway,
        bridge_name: config.name.clone(),
        bridge_cidr: config.cidr.clone(),
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        generation: 1,
    };

    Ok(NetworkCreateRecord { config, record })
}

// ---------------------------------------------------------------------------
// Operation journal
// ---------------------------------------------------------------------------

/// Lifecycle phase of a journaled operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NetworkLifecyclePhase {
    /// The intent is durably recorded on disk (fsynced + atomically renamed).
    IntentDurable,
    /// The kernel effect completed and the observed identity is durably recorded.
    IdentityObserved,
    /// The observed record has been atomically published to networks.json.
    StoreCommitted,
    /// A delete intent for an exact identity is durably recorded.
    DeleteIntentDurable,
    /// The exact-identity delete completed; the bridge is confirmed absent.
    Removed,
    /// Manual intervention required: observed state does not match intent.
    Quarantined,
}

/// Journal action discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NetworkAction {
    Create,
    Delete,
}

/// Stable resource binding: every network owns a deterministic UUID, and
/// each operation advances a monotonic generation for that resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResourceBinding {
    pub name: String,
    pub uuid: String,
    pub generation: u64,
}

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NetworkOperation {
    /// Unique id of this operation.
    pub op_id: String,
    /// Create or delete.
    pub action: NetworkAction,
    /// Stable resource binding (uuid + generation).
    pub resource: ResourceBinding,
    /// Snapshot of the validated record at intent time.
    pub record: RecordSnapshot,
    pub phase: NetworkLifecyclePhase,
    pub intended: Option<BridgeIdentity>,
    pub observed: Option<BridgeIdentity>,
    /// Retained evidence when the result is ambiguous (e.g. observation error).
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NetworkRecord {
    pub name: String,
    pub driver: String,
    pub subnet: String,
    pub gateway: String,
    pub bridge_name: String,
    pub bridge_cidr: String,
    pub created_at_unix: u64,
    #[serde(default = "default_resource_generation")]
    pub generation: u64,
}

fn default_resource_generation() -> u64 {
    1
}

pub(crate) fn network_store_path(runtime_dir: &Path) -> std::path::PathBuf {
    runtime_dir.join("networks").join("networks.json")
}

pub(crate) fn load_networks(runtime_dir: &Path) -> Result<Vec<NetworkRecord>, String> {
    let path = network_store_path(runtime_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|err| format!("network: failed to read {}: {err}", path.display()))?;
    serde_json::from_str::<Vec<NetworkRecord>>(&content)
        .map_err(|err| format!("network: failed to parse {}: {err}", path.display()))
}

pub(crate) fn save_networks(runtime_dir: &Path, records: &[NetworkRecord]) -> Result<(), String> {
    let path = network_store_path(runtime_dir);
    let payload = serde_json::to_string_pretty(records)
        .map_err(|err| format!("network: failed to encode store: {err}"))?;
    ferro_core::fs_atomic::write_atomic(&path, payload.as_bytes())
        .map_err(|err| format!("network: failed to write {}: {err}", path.display()))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors surfaced by the lifecycle core.
#[derive(Debug)]
pub(crate) enum NetworkLifecycleError {
    InvalidRecord(String),
    /// The journal exists but cannot be decoded; fail closed, never rewrite.
    JournalCorrupt(String),
    /// Journal io failure.
    JournalIo(String),
    /// Another writer holds the journal lock.
    JournalBusy,
    /// Operation quarantined; the detail carries retained evidence.
    Quarantined(String),
    Kernel(NetworkKernelError),
    Authorization(String),
    Collision(String),
    InUse(String),
    /// A nonterminal lifecycle still owns the logical or bridge identity.
    Pending(String),
}

impl std::fmt::Display for NetworkLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkLifecycleError::InvalidRecord(m) => write!(f, "invalid network record: {}", m),
            NetworkLifecycleError::JournalCorrupt(m) => write!(
                f,
                "operation journal corrupt (refusing to overwrite): {}",
                m
            ),
            NetworkLifecycleError::JournalIo(m) => write!(f, "operation journal io: {}", m),
            NetworkLifecycleError::JournalBusy => write!(f, "operation journal is locked"),
            NetworkLifecycleError::Quarantined(m) => write!(f, "quarantined: {}", m),
            NetworkLifecycleError::Kernel(e) => write!(f, "kernel effect: {}", e),
            NetworkLifecycleError::Authorization(m) => write!(f, "authorization: {}", m),
            NetworkLifecycleError::Collision(m) => write!(f, "network: bridge name collision {}", m),
            NetworkLifecycleError::InUse(m) => {
                write!(f, "network: in use by extant container association {m}")
            }
            NetworkLifecycleError::Pending(m) => {
                write!(f, "network: pending lifecycle blocks replacement {m}")
            }
        }
    }
}

/// Errors reported by a kernel adapter.
#[derive(Debug)]
pub(crate) enum NetworkKernelError {
    /// The requested bridge does not exist.
    NotFound,
    /// The kernel effect failed.
    Failed(String),
}

impl std::fmt::Display for NetworkKernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkKernelError::NotFound => write!(f, "bridge not found"),
            NetworkKernelError::Failed(m) => write!(f, "kernel operation failed: {}", m),
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel abstraction
// ---------------------------------------------------------------------------

/// Private abstraction over kernel bridge effects so the lifecycle core can
/// be exercised with fake adapters (no root required).
pub(crate) trait NetworkKernel {
    fn create_bridge(&self, config: &ferro_net::BridgeConfig) -> Result<(), NetworkKernelError>;
    fn destroy_bridge(&self, identity: &BridgeIdentity) -> Result<(), NetworkKernelError>;
    fn observe_bridge(&self, name: &str) -> Result<Option<BridgeIdentity>, NetworkKernelError>;
}

/// Real kernel adapter. Observation is the read-only path exported by
/// `ferro-net`; mutation goes through the transactional bridge helpers.
pub(crate) struct SystemBridgeKernel;

impl NetworkKernel for SystemBridgeKernel {
    fn create_bridge(&self, config: &ferro_net::BridgeConfig) -> Result<(), NetworkKernelError> {
        ferro_net::bridge::create_bridge(config)
            .map_err(|e| NetworkKernelError::Failed(e.to_string()))
    }

    fn destroy_bridge(&self, identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
        let observed = ferro_net::bridge::observe_bridge_identity(&identity.name)
            .map_err(|e| NetworkKernelError::Failed(e.to_string()))?;
        match observed {
            Some(observed) if identity.matches_exactly(&observed.clone().into()) => {
                ferro_net::bridge::destroy_bridge(&identity.name)
                    .map_err(|e| NetworkKernelError::Failed(e.to_string()))
            }
            Some(_) => Err(NetworkKernelError::Failed(format!(
                "bridge {} exists with a different identity; refusing inexact delete",
                identity.name
            ))),
            None => Err(NetworkKernelError::NotFound),
        }
    }

    fn observe_bridge(&self, name: &str) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
        ferro_net::bridge::observe_bridge_identity(name)
            .map(|o| o.map(BridgeIdentity::from))
            .map_err(|e| NetworkKernelError::Failed(e.to_string()))
    }
}

/// Environment variable that selects the file-backed emulated kernel.
///
/// When set to a non-empty path, the daemon/CLI uses
/// [`FileBackedNetworkKernel`] instead of [`SystemBridgeKernel`]. Production
/// and unprivileged default paths leave this unset so the real kernel adapter
/// remains the default.
pub(crate) const NETWORK_KERNEL_STATE_ENV: &str = "FERROCRATE_NETWORK_KERNEL_STATE";

/// Persistent state for the file-backed emulated kernel.
///
/// Stores exact [`BridgeIdentity`] values (including observed `ifindex`) so a
/// daemon subprocess can create, observe, and delete across requests without
/// `CAP_NET_ADMIN`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FileBackedKernelState {
    #[serde(default = "default_next_ifindex")]
    pub next_ifindex: u32,
    #[serde(default)]
    pub effect_count: u32,
    #[serde(default)]
    pub bridges: BTreeMap<String, BridgeIdentity>,
}

fn default_next_ifindex() -> u32 {
    1
}

impl Default for FileBackedKernelState {
    fn default() -> Self {
        Self {
            next_ifindex: 1,
            effect_count: 0,
            bridges: BTreeMap::new(),
        }
    }
}

/// File-backed emulated [`NetworkKernel`] for deterministic Docker/CLI tests.
///
/// Enabled only when [`NETWORK_KERNEL_STATE_ENV`] points at a state file path.
/// Mutation methods increment `effect_count` and rewrite the full state file
/// with exact identities. Observation never counts as an effect.
pub(crate) struct FileBackedNetworkKernel {
    path: PathBuf,
    lock: Mutex<()>,
}

impl FileBackedNetworkKernel {
    pub(crate) fn open(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    /// Construct from `FERROCRATE_NETWORK_KERNEL_STATE` when explicitly set.
    pub(crate) fn from_env() -> Option<Self> {
        match std::env::var(NETWORK_KERNEL_STATE_ENV) {
            Ok(path) if !path.is_empty() => Some(Self::open(PathBuf::from(path))),
            _ => None,
        }
    }

    /// Load the current state file (or an empty state when absent).
    pub(crate) fn load_state(path: &Path) -> Result<FileBackedKernelState, NetworkKernelError> {
        if !path.exists() {
            return Ok(FileBackedKernelState::default());
        }
        let bytes = std::fs::read(path)
            .map_err(|e| NetworkKernelError::Failed(format!("read state {}: {e}", path.display())))?;
        if bytes.is_empty() {
            return Ok(FileBackedKernelState::default());
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            NetworkKernelError::Failed(format!("parse state {}: {e}", path.display()))
        })
    }

    fn store_state(&self, state: &FileBackedKernelState) -> Result<(), NetworkKernelError> {
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|e| NetworkKernelError::Failed(format!("encode state: {e}")))?;
        ferro_core::fs_atomic::write_atomic(&self.path, &bytes)
            .map_err(|e| NetworkKernelError::Failed(format!("write state {}: {e}", self.path.display())))
    }

    /// Apply a mutation and always rewrite the state file so effect counters
    /// and identity maps survive process boundaries even when the call fails.
    fn with_mut<R>(
        &self,
        f: impl FnOnce(&mut FileBackedKernelState) -> Result<R, NetworkKernelError>,
    ) -> Result<R, NetworkKernelError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| NetworkKernelError::Failed("kernel state lock poisoned".into()))?;
        let mut state = Self::load_state(&self.path)?;
        let result = f(&mut state);
        self.store_state(&state)?;
        result
    }
}

impl NetworkKernel for FileBackedNetworkKernel {
    fn create_bridge(&self, config: &ferro_net::BridgeConfig) -> Result<(), NetworkKernelError> {
        self.with_mut(|state| {
            let ifindex = state.next_ifindex;
            state.next_ifindex = state.next_ifindex.saturating_add(1).max(1);
            let identity = BridgeIdentity {
                name: config.name.clone(),
                ifindex: Some(ifindex),
                cidr: if config.cidr.is_empty() {
                    None
                } else {
                    Some(config.cidr.clone())
                },
                ipv6_cidr: match config.ipv6_cidr.as_deref() {
                    Some(v) if !v.is_empty() => Some(v.to_string()),
                    _ => None,
                },
            };
            state.bridges.insert(identity.name.clone(), identity);
            state.effect_count = state.effect_count.saturating_add(1);
            Ok(())
        })
    }

    fn destroy_bridge(&self, identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
        self.with_mut(|state| {
            state.effect_count = state.effect_count.saturating_add(1);
            match state.bridges.remove(&identity.name) {
                None => Err(NetworkKernelError::NotFound),
                Some(actual) if actual == *identity => Ok(()),
                Some(actual) => {
                    // Put the mismatched identity back; destroy must be exact.
                    state.bridges.insert(actual.name.clone(), actual);
                    Err(NetworkKernelError::Failed(
                        "identity mismatch at destroy time".into(),
                    ))
                }
            }
        })
    }

    fn observe_bridge(&self, name: &str) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| NetworkKernelError::Failed("kernel state lock poisoned".into()))?;
        let state = Self::load_state(&self.path)?;
        Ok(state.bridges.get(name).cloned())
    }
}

// ---------------------------------------------------------------------------
// Framed journal: bounded decode, exclusive writer lock, atomic durable append
// ---------------------------------------------------------------------------

const JOURNAL_MAGIC: &[u8; 8] = b"FCNETJ01";
/// Upper bound on a single frame payload.
const MAX_FRAME_LEN: usize = 64 * 1024;
/// Upper bound on decoded entries.
const MAX_FRAMES: usize = 4096;

fn journal_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("network-operations.journal")
}

fn lock_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("network-operations.lock")
}

/// Exclusive writer lock for the journal. Held only for the duration of one
/// append. Acquisition failure fails closed (`JournalBusy`).
struct JournalLock {
    _file: File,
    path: PathBuf,
}

impl JournalLock {
    fn acquire(runtime_dir: &Path) -> Result<Self, NetworkLifecycleError> {
        let path = lock_path(runtime_dir);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    NetworkLifecycleError::JournalBusy
                } else {
                    NetworkLifecycleError::JournalIo(format!("lock: {}", e))
                }
            })?;
        Ok(JournalLock { _file: file, path })
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Bounded framed decode. Any truncation, bad magic, oversized frame, or
/// malformed payload is a hard `JournalCorrupt` error: callers must fail
/// closed and never overwrite unreadable evidence.
fn decode_journal(bytes: &[u8]) -> Result<Vec<NetworkOperation>, NetworkLifecycleError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() < JOURNAL_MAGIC.len() || &bytes[..8] != JOURNAL_MAGIC {
        return Err(NetworkLifecycleError::JournalCorrupt(
            "bad magic".to_string(),
        ));
    }
    let mut ops = Vec::new();
    let mut pos = 8usize;
    while pos < bytes.len() {
        if bytes.len() - pos < 4 {
            return Err(NetworkLifecycleError::JournalCorrupt(
                "truncated frame header".to_string(),
            ));
        }
        let len = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
            as usize;
        pos += 4;
        if len == 0 || len > MAX_FRAME_LEN {
            return Err(NetworkLifecycleError::JournalCorrupt(format!(
                "frame length {} out of bounds",
                len
            )));
        }
        if bytes.len() - pos < len {
            return Err(NetworkLifecycleError::JournalCorrupt(
                "truncated frame body".to_string(),
            ));
        }
        let payload = &bytes[pos..pos + len];
        pos += len;
        let op: NetworkOperation = serde_json::from_slice(payload).map_err(|e| {
            NetworkLifecycleError::JournalCorrupt(format!("bad frame payload: {}", e))
        })?;
        ops.push(op);
        if ops.len() > MAX_FRAMES {
            return Err(NetworkLifecycleError::JournalCorrupt(
                "too many frames".to_string(),
            ));
        }
    }
    Ok(ops)
}

fn read_operations(runtime_dir: &Path) -> Result<Vec<NetworkOperation>, NetworkLifecycleError> {
    let journal = journal_path(runtime_dir);
    let bytes = match std::fs::read(&journal) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(NetworkLifecycleError::JournalIo(format!("read: {}", e))),
    };
    decode_journal(&bytes)
}

/// Rewrite the complete journal with the same durability contract as append.
/// The caller must hold `JournalLock` and must have decoded/validated `ops`.
fn write_operations_durable(
    runtime_dir: &Path,
    ops: &[NetworkOperation],
) -> Result<(), NetworkLifecycleError> {
    if ops.len() > MAX_FRAMES {
        return Err(NetworkLifecycleError::JournalCorrupt(
            "too many frames".to_string(),
        ));
    }

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(JOURNAL_MAGIC);
    for op in ops {
        let payload = serde_json::to_vec(op)
            .map_err(|e| NetworkLifecycleError::JournalIo(format!("serialize: {}", e)))?;
        if payload.len() > MAX_FRAME_LEN {
            return Err(NetworkLifecycleError::JournalIo(
                "serialized frame exceeds bound".to_string(),
            ));
        }
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&payload);
    }

    // Unique temp name (pid + monotonic nonce); O_EXCL via create_new and
    // O_NOFOLLOW so a pre-existing symlink cannot capture journal contents.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = journal_path(runtime_dir).with_file_name(format!(
        ".journal.{}.{}.tmp",
        std::process::id(),
        nonce
    ));
    let mut file = open_exclusive_nofollow(&tmp)
        .map_err(|e| NetworkLifecycleError::JournalIo(format!("create tmp: {}", e)))?;
    file.write_all(&body)
        .map_err(|e| NetworkLifecycleError::JournalIo(format!("write: {}", e)))?;
    file.sync_all()
        .map_err(|e| NetworkLifecycleError::JournalIo(format!("fsync file: {}", e)))?;
    drop(file);

    std::fs::rename(&tmp, journal_path(runtime_dir))
        .map_err(|e| NetworkLifecycleError::JournalIo(format!("rename: {}", e)))?;

    // fsync the parent directory so the rename is durable.
    let dir = File::open(runtime_dir)
        .map_err(|e| NetworkLifecycleError::JournalIo(format!("open dir: {}", e)))?;
    dir.sync_all()
        .map_err(|e| NetworkLifecycleError::JournalIo(format!("fsync dir: {}", e)))?;

    Ok(())
}

#[cfg(unix)]
fn open_exclusive_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(0o400000) // O_NOFOLLOW on Linux
        .open(path)
}

#[cfg(not(unix))]
fn open_exclusive_nofollow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Read operations whose latest per-network entry has not reached a
/// terminal phase.
pub(crate) fn read_pending_operations(
    runtime_dir: &Path,
) -> Result<Vec<NetworkOperation>, NetworkLifecycleError> {
    let operations = read_operations(runtime_dir)?;
    // Group by operation id + resource generation, never by bridge name. A
    // newer operation sharing a name must not hide an older operation.
    let latest = validate_operation_history(&operations)?;
    Ok(latest
        .into_values()
        .filter(|op| {
            !matches!(
                op.phase,
                NetworkLifecyclePhase::StoreCommitted
                    | NetworkLifecyclePhase::Removed
                    | NetworkLifecyclePhase::Quarantined
            )
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Resource binding (stable UUID + monotonic generation)
// ---------------------------------------------------------------------------

fn stable_resource_uuid(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ferro-net-resource-v1");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn next_generation(ops: &[NetworkOperation], name: &str) -> u64 {
    ops.iter()
        .filter(|op| op.resource.name == name)
        .map(|op| op.resource.generation)
        .max()
        .unwrap_or(0)
        + 1
}

fn is_initial_phase(action: NetworkAction, phase: &NetworkLifecyclePhase) -> bool {
    match action {
        NetworkAction::Create => matches!(phase, NetworkLifecyclePhase::IntentDurable),
        NetworkAction::Delete => matches!(
            phase,
            NetworkLifecyclePhase::DeleteIntentDurable | NetworkLifecyclePhase::Removed
        ),
    }
}

fn is_terminal_phase(phase: &NetworkLifecyclePhase) -> bool {
    matches!(
        phase,
        NetworkLifecyclePhase::StoreCommitted
            | NetworkLifecyclePhase::Removed
            | NetworkLifecyclePhase::Quarantined
    )
}

fn is_legal_transition(
    action: NetworkAction,
    from: &NetworkLifecyclePhase,
    to: &NetworkLifecyclePhase,
) -> bool {
    match (action, from, to) {
        (
            NetworkAction::Create,
            NetworkLifecyclePhase::IntentDurable,
            NetworkLifecyclePhase::IdentityObserved | NetworkLifecyclePhase::Quarantined,
        ) => true,
        (
            NetworkAction::Create,
            NetworkLifecyclePhase::IdentityObserved,
            NetworkLifecyclePhase::StoreCommitted | NetworkLifecyclePhase::Quarantined,
        ) => true,
        (
            NetworkAction::Delete,
            NetworkLifecyclePhase::DeleteIntentDurable,
            NetworkLifecyclePhase::Removed | NetworkLifecyclePhase::Quarantined,
        ) => true,
        _ => false,
    }
}

fn same_operation_binding(left: &NetworkOperation, right: &NetworkOperation) -> bool {
    left.op_id == right.op_id
        && left.action == right.action
        && left.resource == right.resource
        && left.record == right.record
        && left.intended == right.intended
}

/// Validate the complete identity lattice of a decoded journal.
///
/// Every operation id retains one immutable binding. Every resource UUID and
/// generation is owned by exactly one operation id. Journal phase sequences
/// must begin at a legal initial checkpoint and advance only through legal
/// transitions.
fn validate_operation_history(
    ops: &[NetworkOperation],
) -> Result<std::collections::HashMap<String, NetworkOperation>, NetworkLifecycleError> {
    let mut latest = std::collections::HashMap::new();
    let mut generation_owner = std::collections::HashMap::new();
    for op in ops {
        if op.op_id.is_empty()
            || op.resource.name.is_empty()
            || op.resource.uuid != stable_resource_uuid(&op.resource.name)
            || op.resource.name != op.record.record.name
            || op.record.record.bridge_name.is_empty()
            || op
                .intended
                .as_ref()
                .is_some_and(|identity| identity.name != op.record.record.bridge_name)
        {
            return Err(NetworkLifecycleError::JournalCorrupt(
                "invalid operation identity".to_string(),
            ));
        }

        let generation_key = (op.resource.uuid.clone(), op.resource.generation);
        match generation_owner.insert(generation_key, op.op_id.clone()) {
            Some(owner) if owner == op.op_id => {}
            Some(_) => {
                return Err(NetworkLifecycleError::JournalCorrupt(
                    "resource generation bound to multiple operations".to_string(),
                ));
            }
            None => {}
        }

        if let Some(previous) = latest.get(&op.op_id) {
            if !same_operation_binding(previous, op) {
                return Err(NetworkLifecycleError::JournalCorrupt(
                    "operation id reused with different binding".to_string(),
                ));
            }
            if !is_legal_transition(op.action, &previous.phase, &op.phase) {
                return Err(NetworkLifecycleError::JournalCorrupt(
                    "illegal journal phase transition".to_string(),
                ));
            }
        } else if !is_initial_phase(op.action, &op.phase) {
            return Err(NetworkLifecycleError::JournalCorrupt(
                "operation does not begin at an initial phase".to_string(),
            ));
        }
        latest.insert(op.op_id.clone(), op.clone());
    }
    Ok(latest)
}

fn fresh_op_id(name: &str, action: NetworkAction, generation: u64, seq: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ferro-net-op-v1");
    hasher.update(name.as_bytes());
    hasher.update(match action {
        NetworkAction::Create => b"C",
        NetworkAction::Delete => b"D",
    });
    hasher.update(generation.to_be_bytes());
    hasher.update((seq as u64).to_be_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn mint_operation(
    ops: &[NetworkOperation],
    name: &str,
    action: NetworkAction,
    snapshot: RecordSnapshot,
    phase: NetworkLifecyclePhase,
    intended: Option<BridgeIdentity>,
    observed: Option<BridgeIdentity>,
    detail: Option<String>,
) -> Result<NetworkOperation, NetworkLifecycleError> {
    let generation = next_generation(&ops, name);
    let op_id = fresh_op_id(name, action, generation, ops.len());
    if ops.iter().any(|op| op.op_id == op_id) {
        return Err(NetworkLifecycleError::JournalCorrupt(
            "fresh operation id collides with an existing operation".to_string(),
        ));
    }
    let operation = NetworkOperation {
        op_id,
        action,
        resource: ResourceBinding {
            name: name.to_string(),
            uuid: stable_resource_uuid(name),
            generation,
        },
        record: snapshot,
        phase,
        intended,
        observed,
        detail,
    };
    if operation.resource.name != operation.record.record.name
        || operation.record.record.bridge_name.is_empty()
        || operation
            .intended
            .as_ref()
            .is_some_and(|identity| identity.name != operation.record.record.bridge_name)
        || !is_initial_phase(action, &operation.phase)
    {
        return Err(NetworkLifecycleError::JournalCorrupt(
            "invalid initial lifecycle operation binding".to_string(),
        ));
    }
    Ok(operation)
}

/// Mint and durably append the sole first entry for an operation. Generation
/// and operation id are selected under the writer lock, then retained by every
/// later checkpoint.
fn append_lifecycle_entry(
    runtime_dir: &Path,
    name: &str,
    action: NetworkAction,
    snapshot: RecordSnapshot,
    phase: NetworkLifecyclePhase,
    intended: Option<BridgeIdentity>,
    observed: Option<BridgeIdentity>,
    detail: Option<String>,
) -> Result<NetworkOperation, NetworkLifecycleError> {
    let _lock = JournalLock::acquire(runtime_dir)?;
    let mut ops = read_operations(runtime_dir)?;
    validate_operation_history(&ops)?;
    let operation = mint_operation(
        &ops, name, action, snapshot, phase, intended, observed, detail,
    )?;
    ops.push(operation.clone());
    write_operations_durable(runtime_dir, &ops)?;
    Ok(operation)
}

/// Append a later checkpoint for an existing operation. The supplied entry is
/// authenticated against every journaled entry with that op id; only phase,
/// observed identity, and detail may differ.
fn append_lifecycle_checkpoint(
    runtime_dir: &Path,
    original: &NetworkOperation,
    phase: NetworkLifecyclePhase,
    observed: Option<BridgeIdentity>,
    detail: Option<String>,
) -> Result<(), NetworkLifecycleError> {
    if original.op_id.is_empty() || is_terminal_phase(&original.phase) {
        return Err(NetworkLifecycleError::JournalCorrupt(
            "checkpoint must extend a non-terminal journaled operation".to_string(),
        ));
    }

    let _lock = JournalLock::acquire(runtime_dir)?;
    let mut ops = read_operations(runtime_dir)?;
    let history = validate_operation_history(&ops)?;
    let prior = history.get(&original.op_id).ok_or_else(|| {
        NetworkLifecycleError::JournalCorrupt("checkpoint operation is not journaled".to_string())
    })?;
    if !same_operation_binding(prior, original)
        || prior.resource != original.resource
        || !is_legal_transition(original.action, &prior.phase, &phase)
    {
        return Err(NetworkLifecycleError::JournalCorrupt(
            "checkpoint binding or phase mismatch".to_string(),
        ));
    }

    let mut checkpoint = original.clone();
    checkpoint.phase = phase;
    checkpoint.observed = observed;
    checkpoint.detail = detail;
    ops.push(checkpoint);
    write_operations_durable(runtime_dir, &ops)
}

/// Test-only process fault injection. It is inert unless the explicit enable
/// gate and a matching checkpoint name are both present in the environment.
fn maybe_kill_after_checkpoint(phase: NetworkLifecyclePhase) {
    if std::env::var("FERROCRATE_ENABLE_TEST_FAULTS").as_deref() != Ok("1") {
        return;
    }
    let requested = match std::env::var("FERROCRATE_NETWORK_KILL_AT") {
        Ok(value) => value,
        Err(_) => return,
    };
    if requested != format!("{phase:?}") {
        return;
    }
    eprintln!("test fault injection: killing after {phase:?}");
    unsafe {
        nix::libc::kill(nix::libc::getpid(), nix::libc::SIGKILL);
    }
}

// ---------------------------------------------------------------------------
// Create lifecycle
// ---------------------------------------------------------------------------

/// Run the create lifecycle:
/// 1. durably record `IntentDurable` (with full intended identity and record
///    snapshot bound to a stable resource uuid + generation),
/// 2. apply the kernel effect,
/// 3. observe the actual identity (including ifindex),
/// 4. durably record the observed identity.
///
/// If the post-effect observation is absent or fails, the ambiguity is
/// durably quarantined (evidence retained) and an explicit error is
/// returned: never a false success.
fn is_intended_create_observation(intended: &BridgeIdentity, observed: &BridgeIdentity) -> bool {
    observed.name == intended.name
        && observed.cidr == intended.cidr
        && ipv6_observation_matches_intent(intended.ipv6_cidr.as_deref(), observed.ipv6_cidr.as_deref())
        && observed.ifindex.is_some_and(|ifindex| ifindex != 0)
}

/// Create identity for IPv6: an unrequested address may still be Linux
/// automatic link-local. Requested IPv6 must match exactly. Any other
/// observed IPv6 is a mismatch.
fn ipv6_observation_matches_intent(intended: Option<&str>, observed: Option<&str>) -> bool {
    match (intended, observed) {
        (None, None) => true,
        (None, Some(observed)) => ferro_net::bridge::is_ipv6_link_local_cidr(observed),
        (Some(intended), Some(observed)) => intended == observed,
        (Some(_), None) => false,
    }
}

pub(crate) fn run_network_create(
    runtime_dir: &Path,
    record: &NetworkCreateRecord,
    kernel: &dyn NetworkKernel,
) -> Result<BridgeIdentity, NetworkLifecycleError> {
    let intended = record.intended_identity();
    // Journal resource binding uses the logical network name.
    let logical_name = record.logical_name().to_string();
    // Kernel create/observe uses the bridge identity name.
    let bridge_name = record.bridge_name().to_string();
    let snapshot = record.snapshot();
    let intent = append_lifecycle_entry(
        runtime_dir,
        &logical_name,
        NetworkAction::Create,
        snapshot.clone(),
        NetworkLifecyclePhase::IntentDurable,
        Some(intended.clone()),
        None,
        None,
    )?;
    maybe_kill_after_checkpoint(NetworkLifecyclePhase::IntentDurable);

    if let Err(create_error) = kernel.create_bridge(&record.config) {
        let observed = kernel.observe_bridge(&bridge_name);
        let (observed, observation_detail) = match observed {
            Ok(Some(observed)) => (Some(observed.clone()), format!("observed {:?}", observed)),
            Ok(None) => (None, "bridge absent".to_string()),
            Err(observation_error) => (None, format!("observation failed: {}", observation_error)),
        };
        let detail = format!(
            "create_bridge failed after IntentDurable ({}); read-only outcome evidence: {}",
            create_error, observation_detail
        );
        append_lifecycle_checkpoint(
            runtime_dir,
            &intent,
            NetworkLifecyclePhase::Quarantined,
            observed,
            Some(detail.clone()),
        )?;
        return Err(NetworkLifecycleError::Quarantined(detail));
    }

    match kernel.observe_bridge(&bridge_name) {
        Ok(Some(observed)) => {
            if is_intended_create_observation(&intended, &observed) {
                append_lifecycle_checkpoint(
                    runtime_dir,
                    &intent,
                    NetworkLifecyclePhase::IdentityObserved,
                    Some(observed.clone()),
                    None,
                )?;
                maybe_kill_after_checkpoint(NetworkLifecyclePhase::IdentityObserved);
                Ok(observed)
            } else {
                let detail = format!(
                    "post-create observation mismatch: intended {:?}, observed {:?}",
                    intended, observed
                );
                append_lifecycle_checkpoint(
                    runtime_dir,
                    &intent,
                    NetworkLifecyclePhase::Quarantined,
                    Some(observed.clone()),
                    Some(detail.clone()),
                )?;
                Err(NetworkLifecycleError::Quarantined(detail))
            }
        }
        Ok(None) => {
            append_lifecycle_checkpoint(
                runtime_dir,
                &intent,
                NetworkLifecyclePhase::Quarantined,
                None,
                Some("bridge absent immediately after create".to_string()),
            )?;
            Err(NetworkLifecycleError::Quarantined(
                "bridge absent immediately after create".to_string(),
            ))
        }
        Err(e) => {
            let detail = format!("post-create observation failed: {}", e);
            append_lifecycle_checkpoint(
                runtime_dir,
                &intent,
                NetworkLifecyclePhase::Quarantined,
                None,
                Some(detail.clone()),
            )?;
            Err(NetworkLifecycleError::Quarantined(detail))
        }
    }
}

// ---------------------------------------------------------------------------
// Exact-identity delete lifecycle
// ---------------------------------------------------------------------------

/// Run the exact-identity delete lifecycle.
///
/// Journal resource binding uses `logical_name` (`resource.name`,
/// `stable_resource_uuid(logical_name)`, generation continuity). Kernel
/// observe/destroy use `expected_bridge_identity.name`.
///
/// - absent bridge => idempotent success with a durable `Removed` checkpoint,
/// - observed identity matches `expected_bridge_identity` exactly (including
///   observed ifindex) => durable delete intent, destroy, durable `Removed`,
/// - any mismatch (including a recreated bridge with the same name/CIDRs but
///   a different ifindex) => durable `Quarantined` evidence and a
///   non-success result,
/// - observation errors => durable `Quarantined` evidence and an error.
pub(crate) fn run_network_delete(
    runtime_dir: &Path,
    logical_name: &str,
    expected_bridge_identity: &BridgeIdentity,
    kernel: &dyn NetworkKernel,
) -> Result<(), NetworkLifecycleError> {
    let record = network_record_from_identity(logical_name, expected_bridge_identity);
    let snapshot = RecordSnapshot {
        record: record.clone(),
    };
    match kernel.observe_bridge(&expected_bridge_identity.name) {
        Ok(None) => {
            // Idempotent absence, with a durable Removed checkpoint.
            append_lifecycle_entry(
                runtime_dir,
                logical_name,
                NetworkAction::Delete,
                snapshot,
                NetworkLifecyclePhase::Removed,
                Some(expected_bridge_identity.clone()),
                None,
                Some("already absent".to_string()),
            )?;
            Ok(())
        }
        Ok(Some(observed)) if expected_bridge_identity.matches_exactly(&observed) => {
            let intent = append_lifecycle_entry(
                runtime_dir,
                logical_name,
                NetworkAction::Delete,
                snapshot.clone(),
                NetworkLifecyclePhase::DeleteIntentDurable,
                Some(expected_bridge_identity.clone()),
                Some(observed.clone()),
                None,
            )?;
            match kernel.destroy_bridge(expected_bridge_identity) {
                Ok(()) => {
                    append_lifecycle_checkpoint(
                        runtime_dir,
                        &intent,
                        NetworkLifecyclePhase::Removed,
                        None,
                        None,
                    )?;
                    maybe_kill_after_checkpoint(NetworkLifecyclePhase::Removed);
                    Ok(())
                }
                // Absent at destroy time: idempotent, still durable.
                Err(NetworkKernelError::NotFound) => {
                    append_lifecycle_checkpoint(
                        runtime_dir,
                        &intent,
                        NetworkLifecyclePhase::Removed,
                        None,
                        Some("absent at destroy time".to_string()),
                    )?;
                    maybe_kill_after_checkpoint(NetworkLifecyclePhase::Removed);
                    Ok(())
                }
                Err(e) => {
                    let detail = format!("destroy failed: {}", e);
                    append_lifecycle_checkpoint(
                        runtime_dir,
                        &intent,
                        NetworkLifecyclePhase::Quarantined,
                        None,
                        Some(detail.clone()),
                    )?;
                    Err(NetworkLifecycleError::Quarantined(detail))
                }
            }
        }
        Ok(Some(observed)) => {
            let detail = format!(
                "identity mismatch: expected {:?}, observed {:?}; refusing inexact delete",
                expected_bridge_identity, observed
            );
            let intent = append_lifecycle_entry(
                runtime_dir,
                logical_name,
                NetworkAction::Delete,
                snapshot,
                NetworkLifecyclePhase::DeleteIntentDurable,
                Some(expected_bridge_identity.clone()),
                Some(observed.clone()),
                None,
            )?;
            append_lifecycle_checkpoint(
                runtime_dir,
                &intent,
                NetworkLifecyclePhase::Quarantined,
                Some(observed),
                Some(detail.clone()),
            )?;
            Err(NetworkLifecycleError::Quarantined(detail))
        }
        Err(e) => {
            let detail = format!("pre-delete observation failed: {}", e);
            let intent = append_lifecycle_entry(
                runtime_dir,
                logical_name,
                NetworkAction::Delete,
                snapshot,
                NetworkLifecyclePhase::DeleteIntentDurable,
                Some(expected_bridge_identity.clone()),
                None,
                None,
            )?;
            append_lifecycle_checkpoint(
                runtime_dir,
                &intent,
                NetworkLifecyclePhase::Quarantined,
                None,
                Some(detail.clone()),
            )?;
            Err(NetworkLifecycleError::Quarantined(detail))
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery driver and report
// ---------------------------------------------------------------------------

/// Verdict for one recovered network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum NetworkRecoveryVerdict {
    /// Pending create intent, bridge absent: outcome is known-not-applied.
    /// Recovery never replays the mutation; the durable pending intent is
    /// retained for the caller to act on.
    NotApplied,
    /// Pending create intent, observed identity exactly matches intent.
    AppliedAndCommitted,
    /// Pending delete intent, confirmed absent: Removed checkpoint committed.
    RemovalCommitted,
    /// Quarantined; no destructive kernel action was taken.
    Quarantined,
}

/// One entry of the recovery report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NetworkRecoveryEntry {
    pub network: String,
    pub resource_uuid: String,
    pub generation: u64,
    pub verdict: NetworkRecoveryVerdict,
    /// True when a terminal journal checkpoint was durably committed.
    pub committed: bool,
    pub detail: Option<String>,
}

/// Durable recovery report, one entry per pending network lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NetworkRecoveryReport {
    pub entries: Vec<NetworkRecoveryEntry>,
}

fn network_record_from_snapshot(snapshot: &RecordSnapshot) -> Result<NetworkRecord, String> {
    Ok(snapshot.record.clone())
}

/// Build a minimal NetworkRecord for delete operations.
///
/// `logical_name` is the journal/store resource name. `identity.name` is the
/// kernel bridge name. They may differ.
fn network_record_from_identity(logical_name: &str, identity: &BridgeIdentity) -> NetworkRecord {
    let (subnet, gateway) = match identity.cidr.as_ref() {
        Some(cidr) if !cidr.is_empty() => (cidr.clone(), cidr.clone()),
        _ => ("0.0.0.0/0".to_string(), "0.0.0.0".to_string()),
    };

    NetworkRecord {
        name: logical_name.to_string(),
        driver: "bridge".to_string(),
        subnet,
        gateway,
        bridge_name: identity.name.clone(),
        bridge_cidr: identity.cidr.clone().unwrap_or_default(),
        created_at_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        generation: 1,
    }
}

fn publish_network_record(runtime_dir: &Path, record: &NetworkRecord) -> Result<(), String> {
    let mut records = load_networks(runtime_dir)?;
    if let Some(existing) = records.iter().find(|existing| existing.name == record.name) {
        if existing == record {
            return Ok(());
        }
        return Err(format!(
            "network: store conflict for {}: existing record differs",
            record.name
        ));
    }

    records.push(record.clone());
    records.sort_by(|a, b| a.name.cmp(&b.name));
    save_networks(runtime_dir, &records)
}

fn run_network_create_and_publish(
    runtime_dir: &Path,
    record: &NetworkCreateRecord,
    kernel: &dyn NetworkKernel,
) -> Result<BridgeIdentity, NetworkLifecycleError> {
    let observed = run_network_create(runtime_dir, record, kernel)?;
    let pending = read_pending_operations(runtime_dir)?;
    let operation = pending
        .iter()
        .rev()
        .find(|op| {
            op.action == NetworkAction::Create
                && op.phase == NetworkLifecyclePhase::IdentityObserved
                && op.observed.as_ref() == Some(&observed)
                && op.record == record.snapshot()
        })
        .ok_or_else(|| {
            NetworkLifecycleError::JournalCorrupt(
                "IdentityObserved checkpoint not found after create".to_string(),
            )
        })?;

    // Use the same original observed operation for all checkpoints and error handling
    let published = match network_record_from_snapshot(&operation.record) {
        Ok(published) => published,
        Err(error) => {
            let detail = format!("network record could not be prepared for publication: {error}");
            append_lifecycle_checkpoint(
                runtime_dir,
                operation,
                NetworkLifecyclePhase::Quarantined,
                Some(observed),
                Some(detail.clone()),
            )?;
            return Err(NetworkLifecycleError::Quarantined(detail));
        }
    };
    if let Err(error) = publish_network_record(runtime_dir, &published) {
        let detail = format!("network store publication failed after observation: {error}");
        // Semantic store conflict is terminal quarantine evidence.
        // Persistence faults keep IdentityObserved so recovery can finish
        // StoreCommitted; callers must finish_unknown() and refuse replacement.
        if error.contains("store conflict") {
            append_lifecycle_checkpoint(
                runtime_dir,
                operation,
                NetworkLifecyclePhase::Quarantined,
                Some(observed),
                Some(detail.clone()),
            )?;
            return Err(NetworkLifecycleError::Quarantined(detail));
        }
        return Err(NetworkLifecycleError::JournalIo(detail));
    }

    append_lifecycle_checkpoint(
        runtime_dir,
        operation,
        NetworkLifecyclePhase::StoreCommitted,
        Some(observed.clone()),
        None,
    )?;
    maybe_kill_after_checkpoint(NetworkLifecyclePhase::StoreCommitted);
    Ok(observed)
}

/// `fc-` plus a 12-hex digest of the canonical logical name (15 characters).
pub(crate) fn canonical_bridge_name(logical_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ferro-net-bridge-v1");
    hasher.update(logical_name.as_bytes());
    let digest = hasher.finalize();
    let suffix: String = digest.iter().take(6).map(|b| format!("{:02x}", b)).collect();
    format!("fc-{suffix}")
}

pub(crate) fn last_committed_bridge_identity(
    runtime_dir: &Path,
    logical_name: &str,
) -> Result<Option<BridgeIdentity>, NetworkLifecycleError> {
    let ops = read_operations(runtime_dir)?;
    Ok(ops.into_iter().rev().find_map(|op| {
        if op.resource.name == logical_name
            && op.action == NetworkAction::Create
            && op.phase == NetworkLifecyclePhase::StoreCommitted
        {
            op.observed
        } else {
            None
        }
    }))
}

fn finish_permit(
    permit: SurfacePermit,
    succeeded: bool,
) -> Result<(), NetworkLifecycleError> {
    permit
        .finish(succeeded)
        .map_err(|error| NetworkLifecycleError::Authorization(error.to_string()))
}

fn finish_permit_unknown(permit: SurfacePermit) -> Result<(), NetworkLifecycleError> {
    permit
        .finish_unknown()
        .map_err(|error| NetworkLifecycleError::Authorization(error.to_string()))
}

fn validate_network_permit(
    permit: &SurfacePermit,
    action: AuthorizationAction,
    name: &str,
    generation: u64,
) -> Result<(), NetworkLifecycleError> {
    SurfaceAuthorization::validate_execution(
        permit,
        action,
        ResourceKind::Network,
        name,
        generation,
    )
    .map_err(|error| NetworkLifecycleError::Authorization(error.to_string()))
}

/// Permit-consuming create executor. Collision and pending-lifecycle checks
/// run before any journal or kernel effect. Post-intent failures call
/// `finish_unknown()`.
pub(crate) fn create_authorized(
    runtime_dir: &Path,
    record: &NetworkCreateRecord,
    permit: SurfacePermit,
    kernel: &dyn NetworkKernel,
) -> Result<BridgeIdentity, NetworkLifecycleError> {
    let published = record.published_record();
    validate_network_permit(
        &permit,
        AuthorizationAction::NetworkCreate,
        &published.name,
        published.generation,
    )?;

    let pending = read_pending_operations(runtime_dir)?;
    if pending.iter().any(|op| {
        op.resource.name == published.name
            || op.record.record.bridge_name == published.bridge_name
    }) {
        finish_permit(permit, false)?;
        return Err(NetworkLifecycleError::Pending(published.name.clone()));
    }

    let stored = load_networks(runtime_dir).map_err(NetworkLifecycleError::JournalIo)?;
    if stored.iter().any(|existing| {
        existing.bridge_name == published.bridge_name && existing.name != published.name
    }) {
        finish_permit(permit, false)?;
        return Err(NetworkLifecycleError::Collision(published.bridge_name.clone()));
    }

    match run_network_create_and_publish(runtime_dir, record, kernel) {
        Ok(identity) => {
            finish_permit(permit, true)?;
            Ok(identity)
        }
        Err(error) => {
            finish_permit_unknown(permit)?;
            Err(error)
        }
    }
}

fn unpublish_network_record(runtime_dir: &Path, name: &str) -> Result<(), String> {
    let mut records = load_networks(runtime_dir)?;
    records.retain(|record| record.name != name);
    save_networks(runtime_dir, &records)
}

/// Permit-consuming exact-identity delete executor. Any extant
/// `ContainerRecord` that names the network is refused before kernel effects.
pub(crate) fn delete_authorized(
    runtime_dir: &Path,
    logical_name: &str,
    expected_bridge_identity: &BridgeIdentity,
    associations: &[ContainerRecord],
    generation: u64,
    permit: SurfacePermit,
    kernel: &dyn NetworkKernel,
) -> Result<(), NetworkLifecycleError> {
    validate_network_permit(
        &permit,
        AuthorizationAction::NetworkDelete,
        logical_name,
        generation,
    )?;

    if associations
        .iter()
        .any(|record| record.network_name.as_deref() == Some(logical_name))
    {
        finish_permit(permit, false)?;
        return Err(NetworkLifecycleError::InUse(logical_name.to_string()));
    }

    match run_network_delete(runtime_dir, logical_name, expected_bridge_identity, kernel) {
        Ok(()) => {
            if let Err(error) = unpublish_network_record(runtime_dir, logical_name) {
                finish_permit_unknown(permit)?;
                return Err(NetworkLifecycleError::JournalIo(error));
            }
            finish_permit(permit, true)?;
            Ok(())
        }
        Err(error) => {
            finish_permit_unknown(permit)?;
            Err(error)
        }
    }
}

#[cfg(test)]
pub(crate) fn reset_network_kernel_effect_count() {
    CLI_TEST_KERNEL.with(|kernel| kernel.reset());
}

#[cfg(test)]
pub(crate) fn network_kernel_effect_count() -> u32 {
    CLI_TEST_KERNEL.with(|kernel| kernel.effect_count())
}

#[cfg(test)]
thread_local! {
    static CLI_TEST_KERNEL: CliTestKernel = CliTestKernel::new();
}

#[cfg(test)]
pub(crate) struct CliTestKernel {
    state: std::sync::Mutex<std::collections::HashMap<String, BridgeIdentity>>,
    next_ifindex: std::sync::atomic::AtomicU32,
    effect_count: std::sync::atomic::AtomicU32,
}

#[cfg(test)]
impl CliTestKernel {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(std::collections::HashMap::new()),
            next_ifindex: std::sync::atomic::AtomicU32::new(1),
            effect_count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn reset(&self) {
        self.state.lock().expect("cli test kernel").clear();
        self.next_ifindex
            .store(1, std::sync::atomic::Ordering::SeqCst);
        self.effect_count
            .store(0, std::sync::atomic::Ordering::SeqCst);
    }

    fn effect_count(&self) -> u32 {
        self.effect_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn record_effect(&self) {
        self.effect_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn with_current<R>(f: impl FnOnce(&Self) -> R) -> R {
        CLI_TEST_KERNEL.with(f)
    }
}

#[cfg(test)]
impl NetworkKernel for CliTestKernel {
    fn create_bridge(
        &self,
        config: &ferro_net::BridgeConfig,
    ) -> Result<(), NetworkKernelError> {
        self.record_effect();
        let ifindex = self
            .next_ifindex
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let identity = BridgeIdentity {
            name: config.name.clone(),
            ifindex: Some(ifindex),
            cidr: if config.cidr.is_empty() {
                None
            } else {
                Some(config.cidr.clone())
            },
            ipv6_cidr: match config.ipv6_cidr.as_deref() {
                Some(v) if !v.is_empty() => Some(v.to_string()),
                _ => None,
            },
        };
        self.state
            .lock()
            .expect("cli test kernel")
            .insert(identity.name.clone(), identity);
        Ok(())
    }

    fn destroy_bridge(&self, identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
        self.record_effect();
        let mut state = self.state.lock().expect("cli test kernel");
        match state.remove(&identity.name) {
            None => Err(NetworkKernelError::NotFound),
            Some(actual) if actual == *identity => Ok(()),
            Some(_) => Err(NetworkKernelError::Failed(
                "identity mismatch at destroy time".into(),
            )),
        }
    }

    fn observe_bridge(&self, name: &str) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
        Ok(self.state.lock().expect("cli test kernel").get(name).cloned())
    }
}

/// Drive recovery for every pending network lifecycle and durably commit a
/// terminal checkpoint (or quarantine) for each.
///
/// Classification per pending operation:
/// - absent bridge => `NotApplied` (create intents are re-applied; delete
///   intents commit `Removed`),
/// - exact intended identity (bound to the observed ifindex) => `Applied`,
/// - anything ambiguous, mismatched, or unmarked => `Quarantined` with no
///   destructive kernel action.
pub(crate) fn recover_network_lifecycles(
    runtime_dir: &Path,
    kernel: &dyn NetworkKernel,
) -> Result<NetworkRecoveryReport, NetworkLifecycleError> {
    let pending = read_pending_operations(runtime_dir)?;
    let mut entries = Vec::new();

    for op in pending {
        // Recovery report keys on the logical resource name.
        let logical_name = op.resource.name.clone();
        // Kernel observation always uses the bridge identity name, never the
        // logical resource name (they may differ).
        let bridge_name = op.record.record.bridge_name.clone();
        let mut entry = NetworkRecoveryEntry {
            network: logical_name.clone(),
            resource_uuid: op.resource.uuid.clone(),
            generation: op.resource.generation,
            verdict: NetworkRecoveryVerdict::Quarantined,
            committed: false,
            detail: None,
        };

        // Unmarked intent: quarantine with no destroy, ever.
        let intended = match op.intended.clone() {
            Some(id) => id,
            None => {
                let detail = "unmarked intent: no intended identity recorded".to_string();
                append_lifecycle_checkpoint(
                    runtime_dir,
                    &op,
                    NetworkLifecyclePhase::Quarantined,
                    None,
                    Some(detail.clone()),
                )?;
                entry.detail = Some(detail);
                entry.committed = true;
                entries.push(entry);
                continue;
            }
        };

        match op.action {
            NetworkAction::Create => {
                let recorded_observation = op.observed.as_ref().filter(|observed| {
                    op.phase == NetworkLifecyclePhase::IdentityObserved
                        && is_intended_create_observation(&intended, observed)
                });
                let Some(recorded_observation) = recorded_observation else {
                    // Only an already recorded exact observation may be
                    // published. Recovery never adopts or replays a bare
                    // create intent. Observe by bridge name, not resource name.
                    match kernel.observe_bridge(&bridge_name) {
                        Ok(None) => {
                            entry.verdict = NetworkRecoveryVerdict::NotApplied;
                            entry.committed = false;
                            entry.detail =
                                Some("bridge absent; create not replayed by recovery".to_string());
                        }
                        other => {
                            let detail = format!(
                                "create lacks an exact IdentityObserved checkpoint: {:?}",
                                other.map(|o| o.map(|i| i.ifindex))
                            );
                            append_lifecycle_checkpoint(
                                runtime_dir,
                                &op,
                                NetworkLifecyclePhase::Quarantined,
                                None,
                                Some(detail.clone()),
                            )?;
                            entry.detail = Some(detail);
                            entry.committed = true;
                        }
                    }
                    entries.push(entry);
                    continue;
                };

                match kernel.observe_bridge(&bridge_name) {
                    // Publication must still reflect the exact identity that
                    // was recorded before the crash; a conflicting live bridge
                    // is evidence, not permission to overwrite the store.
                    // The store receives the original journaled NetworkRecord
                    // unmodified (logical name retained).
                    Ok(Some(observed)) if observed == *recorded_observation => {
                        let record = match network_record_from_snapshot(&op.record) {
                            Ok(record) => record,
                            Err(error) => {
                                let detail =
                                    format!("journaled record could not be decoded: {error}");
                                append_lifecycle_checkpoint(
                                    runtime_dir,
                                    &op,
                                    NetworkLifecyclePhase::Quarantined,
                                    Some(observed),
                                    Some(detail.clone()),
                                )?;
                                entry.detail = Some(detail);
                                entry.committed = true;
                                entries.push(entry);
                                continue;
                            }
                        };
                        if let Err(error) = publish_network_record(runtime_dir, &record) {
                            let detail = format!("recovery store publication conflict: {error}");
                            append_lifecycle_checkpoint(
                                runtime_dir,
                                &op,
                                NetworkLifecyclePhase::Quarantined,
                                Some(observed),
                                Some(detail.clone()),
                            )?;
                            entry.detail = Some(detail);
                            entry.committed = true;
                            entries.push(entry);
                            continue;
                        }

                        append_lifecycle_checkpoint(
                            runtime_dir,
                            &op,
                            NetworkLifecyclePhase::StoreCommitted,
                            Some(observed),
                            None,
                        )?;
                        entry.verdict = NetworkRecoveryVerdict::AppliedAndCommitted;
                        entry.committed = true;
                    }
                    other => {
                        let detail = format!(
                            "recorded observation no longer matches live state: {:?}",
                            other.map(|o| o.map(|i| i.ifindex))
                        );
                        append_lifecycle_checkpoint(
                            runtime_dir,
                            &op,
                            NetworkLifecyclePhase::Quarantined,
                            None,
                            Some(detail.clone()),
                        )?;
                        entry.detail = Some(detail);
                        entry.committed = true;
                    }
                }
            }
            NetworkAction::Delete => match kernel.observe_bridge(&bridge_name) {
                Ok(None) => {
                    append_lifecycle_checkpoint(
                        runtime_dir,
                        &op,
                        NetworkLifecyclePhase::Removed,
                        None,
                        Some("recovered: already absent".to_string()),
                    )?;
                    entry.verdict = NetworkRecoveryVerdict::RemovalCommitted;
                    entry.committed = true;
                }
                other => {
                    let detail = format!(
                        "pending delete with live or unobservable bridge: {:?}",
                        other.map(|o| o.map(|i| i.ifindex))
                    );
                    append_lifecycle_checkpoint(
                        runtime_dir,
                        &op,
                        NetworkLifecyclePhase::Quarantined,
                        None,
                        Some(detail.clone()),
                    )?;
                    entry.detail = Some(detail);
                    entry.committed = true;
                }
            },
        }
        entries.push(entry);
    }

    Ok(NetworkRecoveryReport { entries })
}

/// Single-network recovery classifier (thin wrapper over the report driver).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecoveryVerdict {
    NotApplied,
    Applied(BridgeIdentity),
    Quarantined,
}

pub(crate) fn classify_recovery(
    runtime_dir: &Path,
    network: &str,
    kernel: &dyn NetworkKernel,
) -> Result<RecoveryVerdict, NetworkLifecycleError> {
    let pending = read_pending_operations(runtime_dir)?;
    let intent = pending
        .iter()
        .rev()
        .find(|op| op.resource.name == network)
        .ok_or_else(|| {
            NetworkLifecycleError::JournalIo(format!("no pending intent for {}", network))
        })?;
    let intended = match intent.intended.clone() {
        Some(id) => id,
        None => return Ok(RecoveryVerdict::Quarantined),
    };
    match kernel.observe_bridge(&intended.name) {
        Ok(None) => Ok(RecoveryVerdict::NotApplied),
        Ok(Some(observed)) if observed == intended => Ok(RecoveryVerdict::Applied(observed)),
        Ok(Some(_)) | Err(_) => Ok(RecoveryVerdict::Quarantined),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_backed_kernel_persists_exact_identity_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("kernel-state.json");
        let config = ferro_net::BridgeConfig {
            name: "fc-aabbccddeeff".into(),
            cidr: "172.50.0.1/16".into(),
            ipv6_cidr: None,
        };

        {
            let kernel = FileBackedNetworkKernel::open(path.clone());
            kernel.create_bridge(&config).expect("create");
            let observed = kernel
                .observe_bridge(&config.name)
                .expect("observe")
                .expect("present");
            assert_eq!(observed.name, config.name);
            assert_eq!(observed.cidr.as_deref(), Some("172.50.0.1/16"));
            assert!(observed.ifindex.is_some_and(|idx| idx != 0));
        }

        // Fresh instance models a new process reading the same state file.
        let kernel = FileBackedNetworkKernel::open(path.clone());
        let state = FileBackedNetworkKernel::load_state(&path).expect("load");
        assert_eq!(state.effect_count, 1);
        let observed = kernel
            .observe_bridge(&config.name)
            .expect("observe after reopen")
            .expect("identity survives reopen");
        assert_eq!(state.bridges.get(&config.name), Some(&observed));
        assert!(observed.ifindex.is_some());
        kernel
            .destroy_bridge(&observed)
            .expect("exact-identity destroy after reopen");
        let after = FileBackedNetworkKernel::load_state(&path).expect("load after destroy");
        assert!(after.bridges.is_empty());
        assert_eq!(after.effect_count, 2);
    }

    #[test]
    fn file_backed_kernel_from_env_requires_explicit_path() {
        // Safety: this unit test process is single-threaded for env mutation here.
        let original = std::env::var_os(NETWORK_KERNEL_STATE_ENV);
        std::env::remove_var(NETWORK_KERNEL_STATE_ENV);
        assert!(FileBackedNetworkKernel::from_env().is_none());
        std::env::set_var(NETWORK_KERNEL_STATE_ENV, "");
        assert!(FileBackedNetworkKernel::from_env().is_none());
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("state.json");
        std::env::set_var(NETWORK_KERNEL_STATE_ENV, &path);
        let kernel = FileBackedNetworkKernel::from_env().expect("explicit path enables emulator");
        drop(kernel);
        match original {
            Some(value) => std::env::set_var(NETWORK_KERNEL_STATE_ENV, value),
            None => std::env::remove_var(NETWORK_KERNEL_STATE_ENV),
        }
    }

    /// Deterministic kernel adapter that fails the test if `create_bridge`
    /// is invoked before the operation journal durably records
    /// `IntentDurable` for the create operation.
    struct DurableIntentProbeKernel {
        runtime_dir: std::path::PathBuf,
        inner: FakeKernel,
    }

    impl NetworkKernel for DurableIntentProbeKernel {
        fn create_bridge(
            &self,
            _config: &ferro_net::BridgeConfig,
        ) -> Result<(), NetworkKernelError> {
            let pending = read_pending_operations(&self.runtime_dir)
                .expect("operation journal must be readable during the kernel effect");
            assert!(
                pending
                    .iter()
                    .any(|op| op.phase == NetworkLifecyclePhase::IntentDurable),
                "create_bridge called before IntentDurable was durably recorded"
            );
            self.inner.create_bridge(_config)
        }

        fn destroy_bridge(&self, _identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
            panic!("create probe must not destroy bridges");
        }

        fn observe_bridge(&self, name: &str) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
            self.inner.observe_bridge(name)
        }
    }

    #[test]
    fn network_create_intent_is_durable_before_kernel_effect() {
        let runtime_dir = tempfile::tempdir().expect("tempdir");
        let record = create_network_record("intent-probe", None, None).expect("valid record");
        let kernel = DurableIntentProbeKernel {
            runtime_dir: runtime_dir.path().to_path_buf(),
            inner: FakeKernel::with_next_ifindex(7),
        };
        run_network_create(runtime_dir.path(), &record, &kernel)
            .expect("create lifecycle must complete");
    }

    /// In-memory fake kernel: no root required. Hands out monotonically
    /// increasing ifindex values so recreated bridges differ.
    struct FakeKernel {
        state: std::sync::Mutex<std::collections::HashMap<String, BridgeIdentity>>,
        next_ifindex: std::sync::atomic::AtomicU32,
        destroy_calls: std::sync::atomic::AtomicU32,
        create_calls: std::sync::atomic::AtomicU32,
        fail_create: bool,
    }

    impl FakeKernel {
        fn new() -> Self {
            Self::with_next_ifindex(1)
        }
        fn with_next_ifindex(start: u32) -> Self {
            FakeKernel {
                state: std::sync::Mutex::new(std::collections::HashMap::new()),
                next_ifindex: std::sync::atomic::AtomicU32::new(start),
                destroy_calls: std::sync::atomic::AtomicU32::new(0),
                create_calls: std::sync::atomic::AtomicU32::new(0),
                fail_create: false,
            }
        }
        fn create_call_count(&self) -> u32 {
            self.create_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn destroy_call_count(&self) -> u32 {
            self.destroy_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl NetworkKernel for FakeKernel {
        fn create_bridge(
            &self,
            config: &ferro_net::BridgeConfig,
        ) -> Result<(), NetworkKernelError> {
            self.create_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.fail_create {
                return Err(NetworkKernelError::Failed(
                    "simulated create failure".into(),
                ));
            }
            let ifindex = self
                .next_ifindex
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let identity = BridgeIdentity {
                name: config.name.clone(),
                ifindex: Some(ifindex),
                cidr: if config.cidr.is_empty() {
                    None
                } else {
                    Some(config.cidr.clone())
                },
                ipv6_cidr: match config.ipv6_cidr.as_deref() {
                    Some(v) if !v.is_empty() => Some(v.to_string()),
                    _ => None,
                },
            };
            self.state
                .lock()
                .unwrap()
                .insert(identity.name.clone(), identity);
            Ok(())
        }

        fn destroy_bridge(&self, identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
            self.destroy_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut state = self.state.lock().unwrap();
            match state.remove(&identity.name) {
                None => Err(NetworkKernelError::NotFound),
                Some(actual) if actual == *identity => Ok(()),
                Some(_) => Err(NetworkKernelError::Failed(
                    "identity mismatch at destroy time".into(),
                )),
            }
        }

        fn observe_bridge(&self, name: &str) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
            Ok(self.state.lock().unwrap().get(name).cloned())
        }
    }

    /// Fake whose observation always errors: proves observation errors are
    /// durably quarantined instead of returning a false success.
    struct BlindKernel;

    impl NetworkKernel for BlindKernel {
        fn create_bridge(
            &self,
            _config: &ferro_net::BridgeConfig,
        ) -> Result<(), NetworkKernelError> {
            Ok(())
        }
        fn destroy_bridge(&self, _identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
            panic!("blind kernel must not be asked to destroy");
        }
        fn observe_bridge(
            &self,
            _name: &str,
        ) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
            Err(NetworkKernelError::Failed("observation unavailable".into()))
        }
    }

    fn expected_identity(name: &str) -> BridgeIdentity {
        BridgeIdentity {
            name: name.to_string(),
            ifindex: None,
            cidr: Some("10.0.0.1/24".to_string()),
            ipv6_cidr: None,
        }
    }

    /// Fake create effect whose post-create observation reports the requested
    /// bridge name with unintended address state.
    struct MisobservedAddressKernel {
        observed: BridgeIdentity,
    }

    impl NetworkKernel for MisobservedAddressKernel {
        fn create_bridge(
            &self,
            _config: &ferro_net::BridgeConfig,
        ) -> Result<(), NetworkKernelError> {
            Ok(())
        }

        fn destroy_bridge(&self, _identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
            panic!("create observation mismatch must not destroy anything");
        }

        fn observe_bridge(
            &self,
            _name: &str,
        ) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
            Ok(Some(self.observed.clone()))
        }
    }

    #[test]
    fn create_without_requested_ipv6_accepts_automatic_link_local() {
        let dir = tempfile::tempdir().unwrap();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        assert_eq!(record.intended_identity().ipv6_cidr, None);
        let observed = BridgeIdentity {
            name: "net0".to_string(),
            ifindex: Some(7),
            cidr: Some("10.0.0.1/24".to_string()),
            ipv6_cidr: Some("fe80::42:c0ff:fea8:1/64".to_string()),
        };
        let kernel = MisobservedAddressKernel {
            observed: observed.clone(),
        };

        let result = run_network_create(dir.path(), &record, &kernel);
        assert_eq!(result.unwrap(), observed);
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::IdentityObserved
                && op.observed.as_ref() == Some(&observed)));
        assert!(!ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::Quarantined));
    }

    #[test]
    fn create_without_requested_ipv6_quarantines_unexpected_global_ipv6() {
        let dir = tempfile::tempdir().unwrap();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let observed = BridgeIdentity {
            name: "net0".to_string(),
            ifindex: Some(7),
            cidr: Some("10.0.0.1/24".to_string()),
            ipv6_cidr: Some("fd00::1/64".to_string()),
        };
        let kernel = MisobservedAddressKernel {
            observed: observed.clone(),
        };

        let result = run_network_create(dir.path(), &record, &kernel);
        assert!(matches!(result, Err(NetworkLifecycleError::Quarantined(_))));
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::Quarantined
                && op.observed.as_ref() == Some(&observed)));
    }

    #[test]
    fn create_with_requested_ipv6_still_requires_exact_match() {
        let intended = BridgeIdentity {
            name: "net0".into(),
            ifindex: None,
            cidr: Some("10.0.0.1/24".into()),
            ipv6_cidr: Some("fd00::1/64".into()),
        };
        let matching = BridgeIdentity {
            name: "net0".into(),
            ifindex: Some(3),
            cidr: Some("10.0.0.1/24".into()),
            ipv6_cidr: Some("fd00::1/64".into()),
        };
        assert!(is_intended_create_observation(&intended, &matching));

        let dir = tempfile::tempdir().unwrap();
        let record =
            create_network_record("net0", Some("10.0.0.1/24"), Some("fd00::1/64")).unwrap();
        let observed = BridgeIdentity {
            name: "net0".to_string(),
            ifindex: Some(7),
            cidr: Some("10.0.0.1/24".to_string()),
            ipv6_cidr: Some("fe80::1/64".to_string()),
        };
        let kernel = MisobservedAddressKernel { observed };
        let result = run_network_create(dir.path(), &record, &kernel);
        assert!(
            matches!(result, Err(NetworkLifecycleError::Quarantined(_))),
            "requested IPv6 must not match automatic link-local"
        );
    }

    #[test]
    fn create_with_misobserved_addresses_is_quarantined_not_success() {
        let dir = tempfile::tempdir().unwrap();
        let record =
            create_network_record("net0", Some("10.0.0.1/24"), Some("fd00::1/64")).unwrap();
        let observed = BridgeIdentity {
            name: "net0".to_string(),
            ifindex: Some(7),
            cidr: Some("10.0.0.99/24".to_string()),
            ipv6_cidr: Some("fd00::99/64".to_string()),
        };
        let kernel = MisobservedAddressKernel {
            observed: observed.clone(),
        };

        let result = run_network_create(dir.path(), &record, &kernel);
        assert!(
            matches!(result, Err(NetworkLifecycleError::Quarantined(_))),
            "misobserved addresses must not be reported as success"
        );

        let ops = read_operations(dir.path()).unwrap();
        assert_eq!(ops.len(), 2, "create has intent and quarantine checkpoints");
        let intent = &ops[0];
        let quarantined = &ops[1];
        assert_eq!(intent.phase, NetworkLifecyclePhase::IntentDurable);
        assert_eq!(quarantined.phase, NetworkLifecyclePhase::Quarantined);
        assert_eq!(quarantined.op_id, intent.op_id);
        assert_eq!(quarantined.action, intent.action);
        assert_eq!(quarantined.resource, intent.resource);
        assert_eq!(quarantined.observed.as_ref(), Some(&observed));
        assert!(
            !ops.iter()
                .any(|op| op.phase == NetworkLifecyclePhase::IdentityObserved),
            "a mismatched observation must not receive a success checkpoint"
        );
    }

    #[test]
    fn create_records_observed_identity_after_success() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let observed = run_network_create_and_publish(dir.path(), &record, &kernel).unwrap();
        assert_eq!(observed.ifindex, Some(1));
        assert!(read_pending_operations(dir.path()).unwrap().is_empty());
        let ops = read_operations(dir.path()).unwrap();
        assert!(
            ops.iter()
                .any(|op| op.phase == NetworkLifecyclePhase::StoreCommitted
                    && op.observed.is_some())
        );
    }

    /// Fake whose effect mutates kernel state and then reports failure. This
    /// models a kernel that cannot tell whether its mutation was durable.
    struct PartialMutationKernel {
        state: std::sync::Mutex<std::collections::HashMap<String, BridgeIdentity>>,
        destroy_calls: std::sync::atomic::AtomicU32,
    }

    impl PartialMutationKernel {
        fn new() -> Self {
            Self {
                state: std::sync::Mutex::new(std::collections::HashMap::new()),
                destroy_calls: std::sync::atomic::AtomicU32::new(0),
            }
        }

        fn destroy_call_count(&self) -> u32 {
            self.destroy_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl NetworkKernel for PartialMutationKernel {
        fn create_bridge(
            &self,
            config: &ferro_net::BridgeConfig,
        ) -> Result<(), NetworkKernelError> {
            let identity = BridgeIdentity {
                name: config.name.clone(),
                ifindex: Some(9),
                cidr: if config.cidr.is_empty() {
                    None
                } else {
                    Some(config.cidr.clone())
                },
                ipv6_cidr: match config.ipv6_cidr.as_deref() {
                    Some(value) if !value.is_empty() => Some(value.to_string()),
                    _ => None,
                },
            };
            self.state
                .lock()
                .unwrap()
                .insert(identity.name.clone(), identity);
            Err(NetworkKernelError::Failed(
                "create failed after partial mutation".into(),
            ))
        }

        fn destroy_bridge(&self, _identity: &BridgeIdentity) -> Result<(), NetworkKernelError> {
            self.destroy_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(NetworkKernelError::Failed(
                "destroy unexpectedly requested".into(),
            ))
        }

        fn observe_bridge(&self, name: &str) -> Result<Option<BridgeIdentity>, NetworkKernelError> {
            Ok(self.state.lock().unwrap().get(name).cloned())
        }
    }

    #[test]
    fn create_effect_failure_is_quarantined_with_observed_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let observed = BridgeIdentity {
            name: "net0".to_string(),
            ifindex: Some(9),
            cidr: Some("10.0.0.1/24".to_string()),
            ipv6_cidr: None,
        };
        let kernel = PartialMutationKernel::new();

        let result = run_network_create(dir.path(), &record, &kernel);
        assert!(
            matches!(result, Err(NetworkLifecycleError::Quarantined(_))),
            "a failed create effect must be quarantined, not returned as a kernel failure"
        );
        assert_eq!(kernel.destroy_call_count(), 0);

        let ops = read_operations(dir.path()).unwrap();
        assert_eq!(
            ops.len(),
            2,
            "create failure has intent and quarantine evidence"
        );
        let intent = &ops[0];
        let quarantined = &ops[1];
        assert_eq!(intent.phase, NetworkLifecyclePhase::IntentDurable);
        assert_eq!(quarantined.phase, NetworkLifecyclePhase::Quarantined);
        assert_eq!(quarantined.op_id, intent.op_id);
        assert_eq!(quarantined.action, intent.action);
        assert_eq!(quarantined.resource.uuid, intent.resource.uuid);
        assert_eq!(
            quarantined.resource.generation, intent.resource.generation,
            "quarantine must retain the original resource generation"
        );
        assert_eq!(quarantined.observed.as_ref(), Some(&observed));
        assert!(quarantined.detail.is_some());
        assert!(
            !ops.iter()
                .any(|op| op.phase == NetworkLifecyclePhase::IdentityObserved),
            "an errored create effect must not receive a success checkpoint"
        );
    }

    #[test]
    fn operation_entries_carry_id_action_resource_and_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        run_network_create(dir.path(), &record, &kernel).unwrap();
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops.len() >= 2);
        for op in &ops {
            assert!(!op.op_id.is_empty(), "op_id must be set");
            assert_eq!(op.action, NetworkAction::Create);
            assert!(!op.resource.uuid.is_empty());
            assert!(op.resource.generation >= 1);
            assert_eq!(op.record.record.name, "net0");
        }
        let uuids: std::collections::HashSet<_> =
            ops.iter().map(|op| op.resource.uuid.clone()).collect();
        assert_eq!(uuids.len(), 1, "resource uuid must be stable");
    }

    #[test]
    fn create_checkpoint_preserves_operation_and_generation() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        run_network_create(dir.path(), &record, &kernel).unwrap();

        let ops = read_operations(dir.path()).unwrap();
        assert_eq!(ops.len(), 2, "create has intent and observed checkpoints");
        let intent = &ops[0];
        let observed = &ops[1];
        assert_eq!(intent.phase, NetworkLifecyclePhase::IntentDurable);
        assert_eq!(observed.phase, NetworkLifecyclePhase::IdentityObserved);
        assert_eq!(observed.op_id, intent.op_id);
        assert_eq!(observed.action, intent.action);
        assert_eq!(observed.resource, intent.resource);
        assert_eq!(observed.record, intent.record);
        assert_eq!(observed.intended, intent.intended);
    }

    #[test]
    fn delete_checkpoint_preserves_operation_and_generation() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let mut bridge = expected_identity("net0");
        bridge.ifindex = Some(9);
        kernel
            .state
            .lock()
            .unwrap()
            .insert("net0".into(), bridge.clone());

        run_network_delete(dir.path(), "net0", &bridge, &kernel).unwrap();
        let ops = read_operations(dir.path()).unwrap();
        assert_eq!(ops.len(), 2, "delete has intent and removed checkpoints");
        let intent = &ops[0];
        let removed = &ops[1];
        assert_eq!(intent.phase, NetworkLifecyclePhase::DeleteIntentDurable);
        assert_eq!(removed.phase, NetworkLifecyclePhase::Removed);
        assert_eq!(removed.op_id, intent.op_id);
        assert_eq!(removed.action, intent.action);
        assert_eq!(removed.resource, intent.resource);
        assert_eq!(removed.record, intent.record);
        assert_eq!(removed.intended, intent.intended);
    }

    #[test]
    fn recovery_checkpoint_preserves_original_operation_identity() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let mut intended = expected_identity("net0");
        intended.ifindex = Some(5);
        let record = network_record_from_identity("net0", &intended);
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Delete,
            RecordSnapshot {
                record: record.clone(),
            },
            NetworkLifecyclePhase::DeleteIntentDurable,
            Some(intended),
            None,
            None,
        )
        .unwrap();
        let intent = read_operations(dir.path()).unwrap().remove(0);

        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        assert_eq!(
            report.entries[0].verdict,
            NetworkRecoveryVerdict::RemovalCommitted
        );
        let terminal = read_operations(dir.path()).unwrap().remove(1);
        assert_eq!(terminal.op_id, intent.op_id);
        assert_eq!(terminal.action, intent.action);
        assert_eq!(terminal.resource, intent.resource);
        assert_eq!(terminal.record, intent.record);
        assert_eq!(terminal.intended, intent.intended);
    }

    #[test]
    fn same_name_later_operation_cannot_mask_older_pending_operation() {
        let dir = tempfile::tempdir().unwrap();
        let record = NetworkRecord {
            name: "net0".into(),
            driver: "bridge".to_string(),
            subnet: "10.0.0.1/24".to_string(),
            gateway: "10.0.0.1/24".to_string(),
            bridge_name: "net0".to_string(),
            bridge_cidr: "10.0.0.1/24".to_string(),
            created_at_unix: 0,
            generation: 1,
        };
        let snapshot = RecordSnapshot {
            record: record.clone(),
        };
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            snapshot.clone(),
            NetworkLifecyclePhase::IntentDurable,
            Some(expected_identity("net0")),
            None,
            None,
        )
        .unwrap();
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Delete,
            snapshot,
            NetworkLifecyclePhase::Removed,
            Some(expected_identity("net0")),
            None,
            Some("unrelated newer operation".into()),
        )
        .unwrap();

        let pending = read_pending_operations(dir.path()).unwrap();
        assert_eq!(pending.len(), 1, "the older operation must remain visible");
        assert_eq!(pending[0].action, NetworkAction::Create);
        assert_eq!(pending[0].phase, NetworkLifecyclePhase::IntentDurable);
        assert_eq!(pending[0].resource.generation, 1);
    }

    #[test]
    fn checkpoint_binding_mismatch_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let record = NetworkRecord {
            name: "net0".into(),
            driver: "bridge".to_string(),
            subnet: "10.0.0.1/24".to_string(),
            gateway: "10.0.0.1/24".to_string(),
            bridge_name: "net0".to_string(),
            bridge_cidr: "10.0.0.1/24".to_string(),
            created_at_unix: 0,
            generation: 1,
        };
        let snapshot = RecordSnapshot {
            record: record.clone(),
        };
        let intended = expected_identity("net0");
        let intent = append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            snapshot,
            NetworkLifecyclePhase::IntentDurable,
            Some(intended),
            None,
            None,
        )
        .unwrap();
        let before = std::fs::read(journal_path(dir.path())).unwrap();

        let mut forged = intent.clone();
        forged.resource.generation += 1;
        let result = append_lifecycle_checkpoint(
            dir.path(),
            &forged,
            NetworkLifecyclePhase::IdentityObserved,
            None,
            None,
        );

        assert!(matches!(
            result,
            Err(NetworkLifecycleError::JournalCorrupt(_))
        ));
        assert_eq!(std::fs::read(journal_path(dir.path())).unwrap(), before);
    }

    #[test]
    fn illegal_checkpoint_phase_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let intent = append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            record.snapshot(),
            NetworkLifecyclePhase::IntentDurable,
            Some(record.intended_identity()),
            None,
            None,
        )
        .unwrap();

        let result = append_lifecycle_checkpoint(
            dir.path(),
            &intent,
            NetworkLifecyclePhase::Removed,
            None,
            None,
        );
        assert!(matches!(
            result,
            Err(NetworkLifecycleError::JournalCorrupt(_))
        ));
        let pending = read_pending_operations(dir.path()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].phase, NetworkLifecyclePhase::IntentDurable);
    }

    #[test]
    fn invalid_records_are_rejected_before_journaling() {
        let dir = tempfile::tempdir().unwrap();
        assert!(create_network_record("bad name!", None, None).is_err());
        assert!(create_network_record("net0", Some("not-a-cidr"), None).is_err());
        assert!(read_operations(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn unconfirmable_create_is_durable_quarantine_not_false_success() {
        let dir = tempfile::tempdir().unwrap();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let result = run_network_create(dir.path(), &record, &BlindKernel);
        assert!(
            matches!(result, Err(NetworkLifecycleError::Quarantined(_))),
            "observation error must not be reported as success"
        );
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::Quarantined && op.detail.is_some()));
    }

    #[test]
    fn corrupt_journal_fails_closed_and_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        // Seed a valid entry, then corrupt the journal bytes.
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        run_network_create(dir.path(), &record, &kernel).unwrap();
        let journal = journal_path(dir.path());
        let original = std::fs::read(&journal).unwrap();
        std::fs::write(&journal, b"GARBAGE-NOT-A-JOURNAL").unwrap();

        let append = append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Delete,
            record.snapshot(),
            NetworkLifecyclePhase::DeleteIntentDurable,
            Some(expected_identity("net0")),
            None,
            None,
        )
        .map(|_| ());
        assert!(
            matches!(append, Err(NetworkLifecycleError::JournalCorrupt(_))),
            "append must fail closed on a corrupt journal"
        );
        // Evidence retained: the corrupt bytes are untouched.
        assert_eq!(std::fs::read(&journal).unwrap(), b"GARBAGE-NOT-A-JOURNAL");
        assert_ne!(original, b"GARBAGE-NOT-A-JOURNAL" as &[u8]);
    }

    #[test]
    fn truncated_journal_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", None, None).unwrap();
        run_network_create(dir.path(), &record, &kernel).unwrap();
        let journal = journal_path(dir.path());
        let bytes = std::fs::read(&journal).unwrap();
        // Drop the final bytes: truncated frame body.
        std::fs::write(&journal, &bytes[..bytes.len() - 3]).unwrap();
        assert!(matches!(
            read_operations(dir.path()),
            Err(NetworkLifecycleError::JournalCorrupt(_))
        ));
    }

    #[test]
    fn delete_is_exact_and_recreated_same_cidr_different_ifindex_refused() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let observed = run_network_create(dir.path(), &record, &kernel).unwrap();

        // Recreate: same name and CIDRs, new ifindex.
        kernel.state.lock().unwrap().remove("net0");
        let mut recreated = observed.clone();
        recreated.ifindex = Some(observed.ifindex.unwrap() + 99);
        kernel
            .state
            .lock()
            .unwrap()
            .insert("net0".into(), recreated.clone());

        let result = run_network_delete(dir.path(), "net0", &observed, &kernel);
        assert!(
            matches!(result, Err(NetworkLifecycleError::Quarantined(_))),
            "recreated bridge must not be deleted as the original"
        );
        assert_eq!(kernel.destroy_call_count(), 0, "no destroy may be issued");
        // Evidence retained.
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::Quarantined && op.observed.is_some()));
    }

    #[test]
    fn delete_is_idempotent_and_persists_removed_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let observed = run_network_create(dir.path(), &record, &kernel).unwrap();

        run_network_delete(dir.path(), "net0", &observed, &kernel).unwrap();
        assert_eq!(kernel.observe_bridge("net0").unwrap(), None);

        // Second delete on absent bridge: idempotent, with a durable Removed.
        run_network_delete(dir.path(), "net0", &observed, &kernel).unwrap();
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops
            .iter()
            .filter(|op| op.action == NetworkAction::Delete)
            .any(|op| op.phase == NetworkLifecyclePhase::Removed));
    }

    #[test]
    fn create_and_publish_commits_observed_then_store() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();

        let observed = run_network_create_and_publish(dir.path(), &record, &kernel).unwrap();

        let ops = read_operations(dir.path()).unwrap();
        let phases: Vec<_> = ops
            .iter()
            .filter(|op| op.action == NetworkAction::Create)
            .map(|op| op.phase.clone())
            .collect();
        let identity = phases
            .iter()
            .position(|phase| *phase == NetworkLifecyclePhase::IdentityObserved)
            .expect("IdentityObserved checkpoint");
        let committed = phases
            .iter()
            .position(|phase| *phase == NetworkLifecyclePhase::StoreCommitted)
            .expect("StoreCommitted checkpoint");
        assert!(identity < committed);
        let store_record = load_networks(dir.path())
            .unwrap()
            .into_iter()
            .find(|stored| stored.name == "net0")
            .expect("published network record");
        assert_eq!(
            store_record,
            network_record_from_snapshot(&record.snapshot()).unwrap()
        );
        assert_eq!(observed.ifindex, Some(1));
    }

    #[test]
    fn recovery_publishes_exact_identity_observed_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        // Simulate a crash after IdentityObserved and before store publication.
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let intended = BridgeIdentity {
            ifindex: Some(5),
            ..record.intended_identity()
        };
        let observed = intended.clone();
        kernel
            .state
            .lock()
            .unwrap()
            .insert("net0".into(), observed.clone());
        let intent = append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            record.snapshot(),
            NetworkLifecyclePhase::IntentDurable,
            Some(intended.clone()),
            None,
            None,
        )
        .unwrap();
        append_lifecycle_checkpoint(
            dir.path(),
            &intent,
            NetworkLifecyclePhase::IdentityObserved,
            Some(observed.clone()),
            None,
        )
        .unwrap();

        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        assert_eq!(report.entries.len(), 1);
        let e = &report.entries[0];
        assert_eq!(e.verdict, NetworkRecoveryVerdict::AppliedAndCommitted);
        assert!(e.committed);
        assert!(!e.resource_uuid.is_empty());

        // The durable checkpoint sequence ends in StoreCommitted and the
        // absent store is populated from the journaled record.
        let ops = read_operations(dir.path()).unwrap();
        let committed = ops
            .iter()
            .find(|op| op.phase == NetworkLifecyclePhase::StoreCommitted)
            .expect("recovery must commit StoreCommitted");
        assert_eq!(committed.observed.as_ref(), Some(&observed));
        let stored = load_networks(dir.path()).unwrap();
        assert_eq!(
            stored,
            vec![network_record_from_snapshot(&record.snapshot()).unwrap()]
        );
        assert!(read_pending_operations(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn recovery_store_conflict_is_quarantined_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        let intended = BridgeIdentity {
            ifindex: Some(5),
            ..record.intended_identity()
        };
        let mut conflicting = network_record_from_snapshot(&record.snapshot()).unwrap();
        conflicting.generation += 1;
        save_networks(dir.path(), &[conflicting.clone()]).unwrap();

        // Seed FakeKernel with the exact identity that will be observed
        kernel.state.lock().unwrap().insert("net0".into(), intended.clone());

        let intent = append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            record.snapshot(),
            NetworkLifecyclePhase::IntentDurable,
            Some(intended.clone()),
            None,
            None,
        )
        .unwrap();
        append_lifecycle_checkpoint(
            dir.path(),
            &intent,
            NetworkLifecyclePhase::IdentityObserved,
            Some(intended.clone()),
            None,
        )
        .unwrap();

        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();

        assert_eq!(
            report.entries[0].verdict,
            NetworkRecoveryVerdict::Quarantined
        );
        assert_eq!(load_networks(dir.path()).unwrap(), vec![conflicting]);
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::Quarantined));
        assert!(!ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::StoreCommitted));
    }

    #[test]
    fn recovery_absent_create_reports_not_applied_without_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let record = create_network_record("net0", Some("10.0.0.1/24"), None).unwrap();
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            record.snapshot(),
            NetworkLifecyclePhase::IntentDurable,
            Some(record.intended_identity()),
            None,
            None,
        )
        .unwrap();
        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        let e = &report.entries[0];
        assert_eq!(e.verdict, NetworkRecoveryVerdict::NotApplied);
        assert!(!e.committed, "recovery must not terminalize NotApplied");
        // No kernel mutation was replayed.
        assert_eq!(kernel.create_call_count(), 0);
        assert_eq!(kernel.destroy_call_count(), 0);
        assert!(kernel.observe_bridge("net0").unwrap().is_none());
        // Durable evidence retained: the pending intent is still journaled.
        assert!(!read_pending_operations(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn recovery_same_name_cidr_different_ifindex_quarantines_no_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        // Intent binds ifindex 5; the live bridge was recreated with 77
        // under the same name and CIDRs.
        let intended = BridgeIdentity {
            ifindex: Some(5),
            ..expected_identity("net0")
        };
        let mut recreated = intended.clone();
        recreated.ifindex = Some(77);
        kernel
            .state
            .lock()
            .unwrap()
            .insert("net0".into(), recreated);
        let record = network_record_from_identity("net0", &intended);
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            RecordSnapshot {
                record: record.clone(),
            },
            NetworkLifecyclePhase::IntentDurable,
            Some(intended),
            None,
            None,
        )
        .unwrap();
        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        let e = &report.entries[0];
        assert_eq!(e.verdict, NetworkRecoveryVerdict::Quarantined);
        assert_eq!(kernel.create_call_count(), 0);
        assert_eq!(kernel.destroy_call_count(), 0);
        // The recreated bridge is untouched.
        assert!(kernel.observe_bridge("net0").unwrap().is_some());
    }

    #[test]
    fn recovery_unmarked_intent_quarantines_with_no_destroy() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        kernel.state.lock().unwrap().insert(
            "net0".into(),
            BridgeIdentity {
                name: "net0".into(),
                ifindex: Some(3),
                cidr: None,
                ipv6_cidr: None,
            },
        );
        let record = network_record_from_identity(
            "net0",
            &BridgeIdentity {
                name: "net0".into(),
                ifindex: Some(3),
                cidr: None,
                ipv6_cidr: None,
            },
        );
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            RecordSnapshot {
                record: record.clone(),
            },
            NetworkLifecyclePhase::IntentDurable,
            None, // unmarked
            None,
            None,
        )
        .unwrap();

        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        assert_eq!(
            report.entries[0].verdict,
            NetworkRecoveryVerdict::Quarantined
        );
        assert_eq!(kernel.destroy_call_count(), 0, "no destroy may be issued");
        // The bridge survives untouched.
        assert!(kernel.observe_bridge("net0").unwrap().is_some());
        assert!(read_pending_operations(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn recovery_identity_mismatch_quarantines_with_no_destroy() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let mut drifted = expected_identity("net0");
        drifted.ifindex = Some(9);
        drifted.cidr = Some("10.9.9.1/24".into());
        kernel.state.lock().unwrap().insert("net0".into(), drifted);
        let record = NetworkRecord {
            name: "net0".into(),
            driver: "bridge".to_string(),
            subnet: "10.0.0.1/24".to_string(),
            gateway: "10.0.0.1/24".to_string(),
            bridge_name: "net0".to_string(),
            bridge_cidr: "10.0.0.1/24".to_string(),
            created_at_unix: 0,
            generation: 1,
        };
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Create,
            RecordSnapshot {
                record: record.clone(),
            },
            NetworkLifecyclePhase::IntentDurable,
            Some(expected_identity("net0")),
            None,
            None,
        )
        .unwrap();
        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        assert_eq!(
            report.entries[0].verdict,
            NetworkRecoveryVerdict::Quarantined
        );
        assert_eq!(kernel.destroy_call_count(), 0);
    }

    #[test]
    fn recovery_pending_delete_absent_commits_removed() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let mut intended = expected_identity("net0");
        intended.ifindex = Some(4);
        let record = network_record_from_identity("net0", &intended);
        append_lifecycle_entry(
            dir.path(),
            "net0",
            NetworkAction::Delete,
            RecordSnapshot {
                record: record.clone(),
            },
            NetworkLifecyclePhase::DeleteIntentDurable,
            Some(intended),
            None,
            None,
        )
        .unwrap();
        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        assert_eq!(
            report.entries[0].verdict,
            NetworkRecoveryVerdict::RemovalCommitted
        );
        assert!(read_pending_operations(dir.path()).unwrap().is_empty());
    }

    /// Exact NetworkRecord with distinct logical name and kernel bridge name.
    fn blue_net_record() -> NetworkRecord {
        NetworkRecord {
            name: "blue-net".into(),
            driver: "bridge".to_string(),
            subnet: "10.0.0.0/24".to_string(),
            gateway: "10.0.0.1".to_string(),
            bridge_name: "fc-blue-012345".to_string(),
            bridge_cidr: "10.0.0.1/24".to_string(),
            created_at_unix: 1_700_000_000,
            generation: 1,
        }
    }

    #[test]
    fn from_record_builds_bridge_config_and_retains_original() {
        let original = blue_net_record();
        let create = NetworkCreateRecord::from_record(original.clone()).unwrap();
        assert_eq!(create.config.name, "fc-blue-012345");
        assert_eq!(create.config.cidr, "10.0.0.1/24");
        assert_eq!(create.snapshot().record, original);
        assert_eq!(create.logical_name(), "blue-net");
        assert_eq!(create.bridge_name(), "fc-blue-012345");
        let intended = create.intended_identity();
        assert_eq!(intended.name, "fc-blue-012345");
        assert_eq!(intended.cidr.as_deref(), Some("10.0.0.1/24"));
    }

    #[test]
    fn logical_and_bridge_identity_are_distinct_through_create() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let original = blue_net_record();
        let create = NetworkCreateRecord::from_record(original.clone()).unwrap();

        let observed = run_network_create_and_publish(dir.path(), &create, &kernel).unwrap();

        assert_eq!(observed.name, "fc-blue-012345");
        assert_eq!(observed.cidr.as_deref(), Some("10.0.0.1/24"));
        assert!(observed.ifindex.is_some());
        // Kernel must not have a bridge named after the logical resource.
        assert!(kernel.observe_bridge("blue-net").unwrap().is_none());
        assert!(kernel
            .observe_bridge("fc-blue-012345")
            .unwrap()
            .is_some());

        let ops = read_operations(dir.path()).unwrap();
        assert!(!ops.is_empty());
        for op in &ops {
            assert_eq!(op.resource.name, "blue-net");
            assert_eq!(op.resource.uuid, stable_resource_uuid("blue-net"));
            assert_eq!(op.record.record, original);
            if let Some(intended) = &op.intended {
                assert_eq!(intended.name, "fc-blue-012345");
            }
        }
        assert!(ops.iter().any(|op| {
            op.phase == NetworkLifecyclePhase::IntentDurable
                && op.resource.name == "blue-net"
                && op.intended.as_ref().map(|i| i.name.as_str()) == Some("fc-blue-012345")
        }));
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::IdentityObserved
                && op.observed.as_ref().map(|o| o.name.as_str()) == Some("fc-blue-012345")));
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::StoreCommitted));

        let stored = load_networks(dir.path()).unwrap();
        assert_eq!(stored, vec![original]);
    }

    #[test]
    fn recovery_from_identity_observed_uses_bridge_name_and_commits_original() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let original = blue_net_record();
        let create = NetworkCreateRecord::from_record(original.clone()).unwrap();
        let intended = BridgeIdentity {
            ifindex: Some(5),
            ..create.intended_identity()
        };
        let observed = intended.clone();
        // Live bridge is under the kernel name only.
        kernel
            .state
            .lock()
            .unwrap()
            .insert("fc-blue-012345".into(), observed.clone());
        // A same-name bridge under the logical name must not mask recovery.
        kernel.state.lock().unwrap().insert(
            "blue-net".into(),
            BridgeIdentity {
                name: "blue-net".into(),
                ifindex: Some(99),
                cidr: Some("10.9.9.1/24".into()),
                ipv6_cidr: None,
            },
        );

        let intent = append_lifecycle_entry(
            dir.path(),
            "blue-net",
            NetworkAction::Create,
            create.snapshot(),
            NetworkLifecyclePhase::IntentDurable,
            Some(intended.clone()),
            None,
            None,
        )
        .unwrap();
        assert_eq!(intent.resource.name, "blue-net");
        assert_eq!(
            intent.intended.as_ref().map(|i| i.name.as_str()),
            Some("fc-blue-012345")
        );
        append_lifecycle_checkpoint(
            dir.path(),
            &intent,
            NetworkLifecyclePhase::IdentityObserved,
            Some(observed.clone()),
            None,
        )
        .unwrap();

        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].network, "blue-net");
        assert_eq!(
            report.entries[0].verdict,
            NetworkRecoveryVerdict::AppliedAndCommitted
        );
        assert!(report.entries[0].committed);

        let stored = load_networks(dir.path()).unwrap();
        assert_eq!(stored, vec![original]);
        let ops = read_operations(dir.path()).unwrap();
        assert!(ops
            .iter()
            .any(|op| op.phase == NetworkLifecyclePhase::StoreCommitted
                && op.resource.name == "blue-net"
                && op.observed.as_ref() == Some(&observed)));
        // Logical-name decoy bridge must remain untouched.
        assert_eq!(
            kernel.observe_bridge("blue-net").unwrap().unwrap().ifindex,
            Some(99)
        );
        assert_eq!(kernel.destroy_call_count(), 0);
    }

    #[test]
    fn same_name_bridge_does_not_mask_another_logical_resource() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let original = blue_net_record();
        let create = NetworkCreateRecord::from_record(original.clone()).unwrap();

        // Kernel has a bridge whose name equals the logical resource name,
        // but the intended kernel identity is fc-blue-012345 (absent).
        kernel.state.lock().unwrap().insert(
            "blue-net".into(),
            BridgeIdentity {
                name: "blue-net".into(),
                ifindex: Some(3),
                cidr: Some("10.0.0.1/24".into()),
                ipv6_cidr: None,
            },
        );

        append_lifecycle_entry(
            dir.path(),
            "blue-net",
            NetworkAction::Create,
            create.snapshot(),
            NetworkLifecyclePhase::IntentDurable,
            Some(create.intended_identity()),
            None,
            None,
        )
        .unwrap();

        let report = recover_network_lifecycles(dir.path(), &kernel).unwrap();
        assert_eq!(
            report.entries[0].verdict,
            NetworkRecoveryVerdict::NotApplied,
            "recovery must observe fc-blue-012345, not a decoy named blue-net"
        );
        assert!(!report.entries[0].committed);
        assert_eq!(kernel.create_call_count(), 0);
        assert_eq!(kernel.destroy_call_count(), 0);
        // Decoy survives; store is not published from the decoy.
        assert!(kernel.observe_bridge("blue-net").unwrap().is_some());
        assert!(load_networks(dir.path()).unwrap().is_empty());
        assert!(!read_pending_operations(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn delete_does_not_mistake_blue_net_decoy_for_fc_blue_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let expected = BridgeIdentity {
            name: "fc-blue-012345".into(),
            ifindex: Some(5),
            cidr: Some("10.0.0.1/24".into()),
            ipv6_cidr: None,
        };
        kernel
            .state
            .lock()
            .unwrap()
            .insert("fc-blue-012345".into(), expected.clone());
        kernel.state.lock().unwrap().insert(
            "blue-net".into(),
            BridgeIdentity {
                name: "blue-net".into(),
                ifindex: Some(99),
                cidr: Some("10.9.9.1/24".into()),
                ipv6_cidr: None,
            },
        );

        run_network_delete(dir.path(), "blue-net", &expected, &kernel).unwrap();

        assert_eq!(kernel.destroy_call_count(), 1);
        assert!(
            kernel.observe_bridge("fc-blue-012345").unwrap().is_none(),
            "delete must destroy the exact kernel bridge"
        );
        assert_eq!(
            kernel.observe_bridge("blue-net").unwrap().unwrap().ifindex,
            Some(99),
            "a bridge named blue-net must not be mistaken for fc-blue-012345"
        );
    }

    #[test]
    fn delete_journals_logical_name_while_targeting_kernel_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = FakeKernel::new();
        let original = blue_net_record();
        let create = NetworkCreateRecord::from_record(original.clone()).unwrap();
        let observed = run_network_create(dir.path(), &create, &kernel).unwrap();
        assert_eq!(observed.name, "fc-blue-012345");

        kernel.state.lock().unwrap().insert(
            "blue-net".into(),
            BridgeIdentity {
                name: "blue-net".into(),
                ifindex: Some(99),
                cidr: Some("10.9.9.1/24".into()),
                ipv6_cidr: None,
            },
        );

        run_network_delete(dir.path(), "blue-net", &observed, &kernel).unwrap();

        assert!(kernel.observe_bridge("fc-blue-012345").unwrap().is_none());
        assert!(
            kernel.observe_bridge("blue-net").unwrap().is_some(),
            "delete must target fc-blue-012345, not the logical-name decoy"
        );

        let ops = read_operations(dir.path()).unwrap();
        let create_generation = ops
            .iter()
            .filter(|op| op.action == NetworkAction::Create)
            .map(|op| op.resource.generation)
            .max()
            .expect("create journal entries");
        let delete_ops: Vec<_> = ops
            .iter()
            .filter(|op| op.action == NetworkAction::Delete)
            .collect();
        assert!(!delete_ops.is_empty());
        let delete_generations: std::collections::HashSet<_> =
            delete_ops.iter().map(|op| op.resource.generation).collect();
        assert_eq!(delete_generations.len(), 1);
        assert!(delete_generations.iter().all(|g| *g > create_generation));
        for op in delete_ops {
            assert_eq!(op.resource.name, "blue-net");
            assert_eq!(op.resource.uuid, stable_resource_uuid("blue-net"));
            assert_eq!(op.record.record.name, "blue-net");
            assert_eq!(op.record.record.bridge_name, "fc-blue-012345");
            assert_eq!(
                op.intended.as_ref().map(|i| i.name.as_str()),
                Some("fc-blue-012345")
            );
        }
    }
}
