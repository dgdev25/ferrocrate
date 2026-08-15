use super::{decode_hex, require_host_admin, secure_owner_file};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

const STATE_FILE: &str = "emergency-active.json";
const SINK_HEADER: &[u8] = b"FERROCRATE-EMERGENCY-SINK-V1\n";
const MAX_DURATION: u64 = 900;
const ALLOWED_ACTIONS: &[&str] = &["container.stop", "container.kill", "container.remove"];

#[derive(Clone, Copy)]
pub struct EmergencyActivate<'a> {
    pub origin: &'a str,
    pub state_dir: &'a Path,
    pub sink: &'a Path,
    pub recovery_public_key: &'a Path,
    pub recovery_approval: &'a Path,
    pub action: &'a str,
    pub resource: &'a str,
    pub nonce: &'a str,
    pub deadline_uptime_ns: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct EmergencyState {
    schema: u8,
    #[serde(default)]
    generation: u64,
    boot_id: String,
    activated_uptime_ns: u64,
    deadline_uptime_ns: u64,
    action: String,
    resource: String,
    nonce: String,
    sink: String,
    sink_device: u64,
    sink_inode: u64,
    status: EmergencyStatus,
    #[serde(default)]
    main_witness_first: Option<u64>,
    #[serde(default)]
    main_witness_last: Option<u64>,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    terminal_event_id: Option<String>,
    approval_payload: String,
    approval_signature: String,
    recovery_public_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EmergencyStatus {
    Activated,
    IntentDurable,
    Terminal,
    Unknown,
    Quarantined,
}

struct EmergencyPermit(EmergencyState);

struct EmergencyStateStore {
    directory: ferro_core::authorization::SecureDirectory,
}

impl EmergencyStateStore {
    fn open(path: &Path) -> Result<Self, String> {
        Ok(Self {
            directory: ferro_core::authorization::SecureDirectory::open(path)
                .map_err(|e| e.to_string())?,
        })
    }

    fn exists(&self) -> Result<bool, String> {
        self.directory.exists(STATE_FILE).map_err(|e| e.to_string())
    }

    fn read(&self) -> Result<EmergencyState, String> {
        serde_json::from_slice(
            &self
                .directory
                .read_bounded(STATE_FILE, 1024 * 1024)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }

    fn write_cas(&self, expected: Option<u64>, state: &mut EmergencyState) -> Result<(), String> {
        match expected {
            None if self.exists()? => return Err("emergency state already exists".into()),
            Some(generation) => {
                let current = self.read()?;
                if current.generation != generation {
                    return Err("emergency state generation changed concurrently".into());
                }
            }
            None => {}
        }
        state.generation = expected
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("emergency state generation overflow")?;
        self.directory
            .write_atomic(
                STATE_FILE,
                &serde_json::to_vec(state).map_err(|e| e.to_string())?,
                0o600,
            )
            .map_err(|e| e.to_string())
    }

    fn unlink_cas(&self, generation: u64) -> Result<(), String> {
        if self.read()?.generation != generation {
            return Err("emergency state generation changed concurrently".into());
        }
        self.directory.unlink(STATE_FILE).map_err(|e| e.to_string())
    }
}

pub trait AppendOnlySink {
    fn durable_append_capable(&self) -> bool;
    fn identity(&self) -> (u64, u64);
    fn append_durable(&mut self, receipt: &[u8]) -> Result<(), String>;
}

struct FsAppendOnlySink {
    file: fs::File,
    identity: (u64, u64),
}

impl AppendOnlySink for FsAppendOnlySink {
    fn durable_append_capable(&self) -> bool {
        ferro_core::authorization::file_is_kernel_append_only(&self.file).unwrap_or(false)
    }

    fn identity(&self) -> (u64, u64) {
        self.identity
    }

    fn append_durable(&mut self, receipt: &[u8]) -> Result<(), String> {
        let meta = validate_sink_file(&self.file)?;
        if (meta.dev(), meta.ino()) != self.identity {
            return Err("emergency sink descriptor identity changed".into());
        }
        #[cfg(not(test))]
        if !self.durable_append_capable() {
            return Err(
                "emergency sink backend cannot prove FS_APPEND_FL append-only durability".into(),
            );
        }
        let mut header = vec![0; SINK_HEADER.len()];
        (&self.file)
            .read_exact(&mut header)
            .map_err(|e| e.to_string())?;
        if header != SINK_HEADER {
            return Err("emergency sink has an invalid framing header".into());
        }
        (&self.file)
            .write_all(receipt)
            .and_then(|_| (&self.file).write_all(b"\n"))
            .and_then(|_| self.file.sync_all())
            .map_err(|e| format!("emergency sink unavailable: {e}"))
    }
}

#[cfg(test)]
struct DeterministicAppendOnlySink {
    capable: bool,
    receipts: Vec<Vec<u8>>,
}

#[cfg(test)]
impl AppendOnlySink for DeterministicAppendOnlySink {
    fn durable_append_capable(&self) -> bool {
        self.capable
    }
    fn identity(&self) -> (u64, u64) {
        (1, 1)
    }
    fn append_durable(&mut self, receipt: &[u8]) -> Result<(), String> {
        if !self.capable {
            return Err("append-only capability unavailable".into());
        }
        self.receipts.push(receipt.to_vec());
        Ok(())
    }
}

pub struct EmergencyAuthorityMaterial {
    pub signed_payload: Vec<u8>,
    pub signature: [u8; 64],
    pub recovery_key: [u8; 32],
    pub boot_id: String,
    pub deadline_uptime_ns: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    payload: String,
    signature: String,
}

pub fn activate_emergency(args: EmergencyActivate<'_>) -> Result<String, String> {
    if args.origin != "console" {
        return Err("emergency activation is local-console-only and unavailable through Docker, CRI, or remote APIs".into());
    }
    require_host_admin()?;
    require_console()?;
    require_preprovisioned_state_dir(args.state_dir)?;
    require_append_only_sink(args.sink)?;
    activate_verified(args)
}

fn activate_verified(args: EmergencyActivate<'_>) -> Result<String, String> {
    if !ALLOWED_ACTIONS.contains(&args.action) {
        return Err("emergency scope cannot disable the authorization gate or witness journal and is not an allowlisted safety operation".into());
    }
    if args.resource.is_empty()
        || args.resource.len() > 256
        || args.nonce.len() < 16
        || args.nonce.len() > 128
    {
        return Err("emergency scope, nonce, or deadline is invalid".into());
    }
    prepare_state_dir(args.state_dir)?;
    let store = EmergencyStateStore::open(args.state_dir)?;
    if store.exists()? {
        return Err("an emergency grant is already active or awaits reconciliation".into());
    }
    let boot_id = boot_id()?;
    let now = uptime_ns()?;
    let deadline = args.deadline_uptime_ns;
    if deadline <= now || deadline > now.saturating_add(MAX_DURATION * 1_000_000_000) {
        return Err(
            "emergency monotonic deadline is expired or exceeds the 15-minute maximum".into(),
        );
    }
    let payload = format!(
        "FERROCRATE-EMERGENCY-APPROVAL-V1\n{boot_id}\n{}\n{}\n{}\n{deadline}\n",
        args.action, args.resource, args.nonce
    );
    let (approval_signature, recovery_public_key) =
        verify_approval(args.recovery_public_key, args.recovery_approval, &payload)?;
    let nonce_marker = nonce_marker(args.state_dir, &boot_id, args.nonce);
    if secure_exists(&nonce_marker)? {
        return Err("emergency recovery approval nonce has already been consumed".into());
    }
    let sink =
        fs::canonicalize(args.sink).map_err(|e| format!("emergency sink unavailable: {e}"))?;
    let state_root = fs::canonicalize(args.state_dir).map_err(|e| e.to_string())?;
    if sink.starts_with(&state_root) {
        return Err(
            "emergency sink must be independently provisioned outside runtime state".into(),
        );
    }
    let sink_metadata = fs::metadata(&sink).map_err(|e| e.to_string())?;
    let state = EmergencyState {
        schema: 1,
        generation: 0,
        boot_id,
        activated_uptime_ns: now,
        deadline_uptime_ns: deadline,
        action: args.action.into(),
        resource: args.resource.into(),
        nonce: args.nonce.into(),
        sink: sink.display().to_string(),
        sink_device: sink_metadata.dev(),
        sink_inode: sink_metadata.ino(),
        status: EmergencyStatus::Activated,
        main_witness_first: None,
        main_witness_last: None,
        operation_id: None,
        terminal_event_id: None,
        approval_payload: payload,
        approval_signature: super::hex(&approval_signature),
        recovery_public_key: super::hex(&recovery_public_key),
    };
    let receipt = serde_json::json!({"type":"activate","schema":1,"boot_id":state.boot_id,"deadline_uptime_ns":deadline,"action":state.action,"resource":state.resource,"nonce":state.nonce});
    append_sink(
        &sink,
        &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
    )?;
    persist_nonce(&nonce_marker)?;
    let mut state = state;
    store.write_cas(None, &mut state)?;
    Ok(format!(
        "emergency active action={} resource={} deadline_uptime_ns={} reconciliation_required=true",
        state.action, state.resource, deadline
    ))
}

pub fn reconcile_emergency(state_dir: &Path, sink: &Path) -> Result<String, String> {
    require_host_admin()?;
    require_console()?;
    require_preprovisioned_state_dir(state_dir)?;
    require_append_only_sink(sink)?;
    reconcile_verified(state_dir, sink)
}

fn reconcile_verified(state_dir: &Path, sink: &Path) -> Result<String, String> {
    let store = EmergencyStateStore::open(state_dir)?;
    let state = store.read().map_err(|e| format!("emergency state: {e}"))?;
    if state.schema != 1 || state.boot_id != boot_id()? {
        return Err("emergency state is from another boot; operator recovery is required".into());
    }
    let canonical_sink =
        fs::canonicalize(sink).map_err(|e| format!("emergency sink unavailable: {e}"))?;
    if canonical_sink.display().to_string() != state.sink {
        return Err("reconciliation sink does not match the activation receipt sink".into());
    }
    validate_sink_identity(&canonical_sink, &state)?;
    if !matches!(
        state.status,
        EmergencyStatus::Terminal | EmergencyStatus::Quarantined
    ) {
        return Err(
            "emergency execution is not terminal or quarantined; reconciliation denied".into(),
        );
    }
    verify_main_witness(state_dir, &state)?;
    let receipt = serde_json::json!({"type":"reconcile","schema":1,"boot_id":state.boot_id,"action":state.action,"resource":state.resource,"nonce":state.nonce,"reconciled_uptime_ns":uptime_ns()?});
    append_sink(
        &canonical_sink,
        &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
    )?;
    store.unlink_cas(state.generation)?;
    Ok("emergency reconciled receipt_persisted=true normal_operations_allowed=true".into())
}

pub fn execute_emergency<F>(
    state_dir: &Path,
    sink: &Path,
    action: &str,
    resource: &str,
    execute: F,
) -> Result<String, String>
where
    F: FnOnce([u8; 16], EmergencyAuthorityMaterial) -> Result<(), String>,
{
    require_host_admin()?;
    require_console()?;
    require_preprovisioned_state_dir(state_dir)?;
    require_append_only_sink(sink)?;
    execute_verified(state_dir, sink, action, resource, execute)
}

fn execute_verified<F>(
    state_dir: &Path,
    sink: &Path,
    action: &str,
    resource: &str,
    execute: F,
) -> Result<String, String>
where
    F: FnOnce([u8; 16], EmergencyAuthorityMaterial) -> Result<(), String>,
{
    let store = EmergencyStateStore::open(state_dir)?;
    let mut permit = EmergencyPermit(store.read().map_err(|e| format!("emergency state: {e}"))?);
    let state = &mut permit.0;
    if state.boot_id != boot_id()? || uptime_ns()? >= state.deadline_uptime_ns {
        return Err("emergency permit boot or monotonic deadline is invalid".into());
    }
    if state.action != action
        || state.resource != resource
        || state.status != EmergencyStatus::Activated
    {
        return Err("emergency permit action/resource is out of scope or already consumed".into());
    }
    let canonical_sink =
        fs::canonicalize(sink).map_err(|e| format!("emergency sink unavailable: {e}"))?;
    validate_sink_identity(&canonical_sink, &state)?;
    let operation_digest = super::digest(
        format!(
            "FERROCRATE-EMERGENCY-OP-V1\0{}\0{}\0{}\0{}",
            state.boot_id, state.nonce, action, resource
        )
        .as_bytes(),
    );
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&operation_digest[..16]);
    state.operation_id = Some(super::hex(&operation_id));
    let intent = serde_json::json!({"type":"intent","schema":1,"boot_id":state.boot_id,"action":action,"resource":resource,"nonce":state.nonce,"operation_id":state.operation_id,"uptime_ns":uptime_ns()?});
    append_sink(
        &canonical_sink,
        &serde_json::to_vec(&intent).map_err(|e| e.to_string())?,
    )?;
    state.status = EmergencyStatus::IntentDurable;
    let expected = state.generation;
    store.write_cas(Some(expected), state)?;
    let before = main_witness_head(state_dir)?;
    let material = EmergencyAuthorityMaterial {
        signed_payload: state.approval_payload.as_bytes().to_vec(),
        signature: decode_hex::<64>(&state.approval_signature)?,
        recovery_key: decode_hex::<32>(&state.recovery_public_key)?,
        boot_id: state.boot_id.clone(),
        deadline_uptime_ns: state.deadline_uptime_ns,
    };
    let result = execute(operation_id, material);
    let after = main_witness_head(state_dir)?;
    if let (Some(before), Some(after)) = (before, after) {
        if after <= before {
            state.status = EmergencyStatus::Unknown;
            let expected = state.generation;
            store.write_cas(Some(expected), state)?;
            return Err(
                "emergency outcome is unknown because no main-journal evidence was published"
                    .into(),
            );
        }
        state.main_witness_first = Some(before.saturating_add(1));
        state.main_witness_last = Some(after);
        state.terminal_event_id = Some(find_terminal_event(state_dir, operation_id, action)?);
    }
    let outcome = serde_json::json!({"type":"outcome","schema":1,"boot_id":state.boot_id,"action":action,"resource":resource,"nonce":state.nonce,"operation_id":state.operation_id,"terminal_event_id":state.terminal_event_id,"succeeded":result.is_ok(),"uptime_ns":uptime_ns()?});
    if let Err(error) = append_sink(
        &canonical_sink,
        &serde_json::to_vec(&outcome).map_err(|e| e.to_string())?,
    ) {
        state.status = EmergencyStatus::Unknown;
        let expected = state.generation;
        store.write_cas(Some(expected), state)?;
        return Err(format!(
            "emergency outcome is unknown because the sink failed: {error}"
        ));
    }
    state.status = EmergencyStatus::Terminal;
    let expected = state.generation;
    store.write_cas(Some(expected), state)?;
    result?;
    Ok("emergency execution terminal=true reconciliation_required=true".into())
}

fn validate_sink_identity(path: &Path, state: &EmergencyState) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.dev() != state.sink_device || metadata.ino() != state.sink_inode {
        return Err("emergency sink device/inode changed after activation".into());
    }
    Ok(())
}

fn main_witness_head(state_dir: &Path) -> Result<Option<u64>, String> {
    let id_path = state_dir.join("journal-id");
    if !secure_exists(&id_path)? {
        return Ok(None);
    }
    secure_owner_file(&id_path)?;
    let id_text = String::from_utf8(secure_read(&id_path, 4096)?).map_err(|e| e.to_string())?;
    let id = decode_hex::<16>(id_text.trim())?;
    let mut reader =
        ferro_core::witness::WitnessReader::open_read_only(state_dir.join("witness-journal"), id)
            .map_err(|e| e.to_string())?;
    let mut head = 0;
    while let Some(bytes) = reader.next_record().map_err(|e| e.to_string())? {
        head = ferro_core::witness::decode_record(&bytes)
            .map_err(|e| e.to_string())?
            .sequence();
    }
    reader.finish().map_err(|e| e.to_string())?;
    Ok(Some(head))
}

fn verify_main_witness(state_dir: &Path, state: &EmergencyState) -> Result<(), String> {
    let (Some(first), Some(last)) = (state.main_witness_first, state.main_witness_last) else {
        // Recovery-only unit/offline mode has no configured main journal. A
        // production activation with journal-id always records the range.
        return if secure_exists(&state_dir.join("journal-id"))? {
            Err("emergency state lacks its main-journal correlation range".into())
        } else {
            Ok(())
        };
    };
    let id_text = String::from_utf8(secure_read(&state_dir.join("journal-id"), 4096)?)
        .map_err(|e| e.to_string())?;
    let id = decode_hex::<16>(id_text.trim())?;
    let expected = emergency_witness_action(&state.action)?;
    let operation_id = decode_hex::<16>(
        state
            .operation_id
            .as_deref()
            .ok_or("emergency state lacks operation ID")?,
    )?;
    let terminal_event_id = decode_hex::<16>(
        state
            .terminal_event_id
            .as_deref()
            .ok_or("emergency state lacks terminal event ID")?,
    )?;
    let mut reader =
        ferro_core::witness::WitnessReader::open_read_only(state_dir.join("witness-journal"), id)
            .map_err(|e| e.to_string())?;
    let mut terminal = false;
    while let Some(bytes) = reader.next_record().map_err(|e| e.to_string())? {
        let record = ferro_core::witness::decode_record(&bytes).map_err(|e| e.to_string())?;
        terminal |= record.sequence() >= first
            && record.sequence() <= last
            && record.action() == expected
            && record.request_id() == operation_id
            && record.event_id() == terminal_event_id
            && record.stage() == ferro_core::witness::WitnessStage::Outcome;
    }
    reader.finish().map_err(|e| e.to_string())?;
    terminal.then_some(()).ok_or_else(|| {
        "independent sink and main journal do not contain matching terminal evidence".into()
    })
}

fn find_terminal_event(
    state_dir: &Path,
    operation_id: [u8; 16],
    action: &str,
) -> Result<String, String> {
    let expected = emergency_witness_action(action)?;
    let id_text = String::from_utf8(secure_read(&state_dir.join("journal-id"), 4096)?)
        .map_err(|e| e.to_string())?;
    let id = decode_hex::<16>(id_text.trim())?;
    let mut reader =
        ferro_core::witness::WitnessReader::open_read_only(state_dir.join("witness-journal"), id)
            .map_err(|e| e.to_string())?;
    let mut terminal = None;
    while let Some(bytes) = reader.next_record().map_err(|e| e.to_string())? {
        let record = ferro_core::witness::decode_record(&bytes).map_err(|e| e.to_string())?;
        if record.request_id() == operation_id
            && record.action() == expected
            && record.stage() == ferro_core::witness::WitnessStage::Outcome
        {
            if terminal.replace(record.event_id()).is_some() {
                return Err("multiple terminal events exist for the emergency operation ID".into());
            }
        }
    }
    reader.finish().map_err(|e| e.to_string())?;
    terminal
        .map(|event| super::hex(&event))
        .ok_or_else(|| "main journal lacks exact terminal evidence for emergency operation".into())
}

fn emergency_witness_action(action: &str) -> Result<ferro_core::witness::WitnessAction, String> {
    match action {
        "container.stop" => Ok(ferro_core::witness::WitnessAction::ContainerStop),
        "container.kill" => Ok(ferro_core::witness::WitnessAction::ContainerKill),
        "container.remove" => Ok(ferro_core::witness::WitnessAction::ContainerDelete),
        _ => Err("emergency action has no correlatable main-journal action".into()),
    }
}

pub fn ensure_reconciled(state_dir: &Path) -> Result<(), String> {
    if state_dir.join(STATE_FILE).exists() {
        Err("normal operations denied: emergency receipt reconciliation is required".into())
    } else {
        Ok(())
    }
}

fn verify_approval(
    key_path: &Path,
    approval_path: &Path,
    expected: &str,
) -> Result<([u8; 64], [u8; 32]), String> {
    let mut key_file = open_secure_owner_file(key_path)?;
    let mut key_text = String::new();
    key_file
        .read_to_string(&mut key_text)
        .map_err(|e| e.to_string())?;
    let key_bytes = decode_hex::<32>(key_text.trim())?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| "invalid recovery public key")?;
    let mut approval_file = open_secure_owner_file(approval_path)?;
    let mut approval_bytes = Vec::new();
    approval_file
        .read_to_end(&mut approval_bytes)
        .map_err(|e| e.to_string())?;
    let approval: Approval = serde_json::from_slice(&approval_bytes).map_err(|e| e.to_string())?;
    if approval.payload != expected {
        return Err(
            "recovery approval is not bound to this boot, scope, nonce, and monotonic deadline"
                .into(),
        );
    }
    let signature_bytes = decode_hex::<64>(&approval.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify(expected.as_bytes(), &signature)
        .map_err(|_| "invalid offline recovery approval".to_string())?;
    Ok((signature_bytes, key_bytes))
}

fn open_secure_owner_file(path: &Path) -> Result<fs::File, String> {
    let file = ferro_core::authorization::open_path_no_symlinks(path, nix::libc::O_RDONLY, 0)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.mode() & 0o077 != 0
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.nlink() != 1
    {
        return Err(format!(
            "{} is not an owner-only single-link regular file",
            path.display()
        ));
    }
    Ok(file)
}

fn require_append_only_sink(path: &Path) -> Result<(), String> {
    let file = ferro_core::authorization::open_path_no_symlinks(
        path,
        nix::libc::O_RDWR | nix::libc::O_APPEND,
        0,
    )
    .map_err(|e| format!("emergency sink unavailable: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(
            "emergency sink descriptor owner, mode, type, or link count is insecure".into(),
        );
    }
    if !ferro_core::authorization::file_is_kernel_append_only(&file).unwrap_or(false) {
        return Err(
            "emergency sink backend cannot prove FS_APPEND_FL append-only durability".into(),
        );
    }
    Ok(())
}

fn append_sink(path: &Path, receipt: &[u8]) -> Result<(), String> {
    let file = ferro_core::authorization::open_path_no_symlinks(
        path,
        nix::libc::O_RDWR | nix::libc::O_APPEND,
        0,
    )
    .map_err(|e| format!("emergency sink unavailable: {e}"))?;
    let meta = validate_sink_file(&file)?;
    if meta.len() < SINK_HEADER.len() as u64 {
        return Err("emergency sink is not pre-provisioned".into());
    }
    let mut sink = FsAppendOnlySink {
        file,
        identity: (meta.dev(), meta.ino()),
    };
    if sink.identity() != (meta.dev(), meta.ino()) {
        return Err("emergency sink descriptor identity changed".into());
    }
    sink.append_durable(receipt)
}

fn validate_sink_file(file: &fs::File) -> Result<fs::Metadata, String> {
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(
            "emergency sink descriptor owner, mode, type, or link count is insecure".into(),
        );
    }
    Ok(meta)
}

fn prepare_state_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let m = fs::metadata(path).map_err(|e| e.to_string())?;
    if !m.is_dir() || m.uid() != nix::unistd::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err("emergency state directory is insecure".into());
    }
    Ok(())
}

fn require_preprovisioned_state_dir(path: &Path) -> Result<(), String> {
    let directory = ferro_core::authorization::open_path_no_symlinks(
        path,
        nix::libc::O_RDONLY | nix::libc::O_DIRECTORY,
        0,
    )
    .map_err(|e| format!("emergency state directory must be preprovisioned: {e}"))?;
    let metadata = directory.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err("emergency state directory is insecure".into());
    }
    Ok(())
}

fn write_state(path: &Path, state: &EmergencyState) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|e| e.to_string())?;
    let (directory, name) = secure_parent(path)?;
    directory
        .write_atomic(&name, &bytes, 0o600)
        .map_err(|e| e.to_string())
}

fn nonce_marker(state_dir: &Path, boot_id: &str, nonce: &str) -> PathBuf {
    let value = super::digest(format!("{boot_id}\0{nonce}").as_bytes());
    state_dir.join(format!("emergency-nonce-{}", super::hex(&value)))
}

fn persist_nonce(path: &Path) -> Result<(), String> {
    let (directory, name) = secure_parent(path)?;
    directory
        .create_exclusive(&name, b"FERROCRATE-EMERGENCY-NONCE-V1\n", 0o600)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "emergency recovery approval nonce has already been consumed".to_string()
            } else {
                format!("cannot persist emergency nonce: {error}")
            }
        })
}

fn secure_parent(
    path: &Path,
) -> Result<(ferro_core::authorization::SecureDirectory, String), String> {
    let parent = path.parent().ok_or("secure path has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("secure path has invalid name")?;
    Ok((
        ferro_core::authorization::SecureDirectory::open(parent).map_err(|e| e.to_string())?,
        name.to_owned(),
    ))
}

fn secure_read(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let (directory, name) = secure_parent(path)?;
    directory
        .read_bounded(&name, maximum)
        .map_err(|e| e.to_string())
}

fn secure_exists(path: &Path) -> Result<bool, String> {
    let (directory, name) = secure_parent(path)?;
    directory.exists(&name).map_err(|e| e.to_string())
}

fn require_console() -> Result<(), String> {
    if !std::io::stdin().is_terminal() {
        return Err("emergency activation is local-console-only (stdin is not a terminal)".into());
    }
    let terminal = fs::read_link("/proc/self/fd/0").map_err(|e| e.to_string())?;
    let name = terminal.to_string_lossy();
    if !(name == "/dev/console" || name.starts_with("/dev/tty")) {
        return Err(
            "emergency activation is local-console-only (remote pseudo-terminal rejected)".into(),
        );
    }
    Ok(())
}

fn boot_id() -> Result<String, String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|v| v.trim().to_owned())
        .map_err(|e| e.to_string())
}
fn uptime_ns() -> Result<u64, String> {
    let text = fs::read_to_string("/proc/uptime").map_err(|e| e.to_string())?;
    let value: f64 = text
        .split_whitespace()
        .next()
        .ok_or("missing monotonic uptime")?
        .parse()
        .map_err(|_| "invalid monotonic uptime")?;
    if !value.is_finite() || value < 0.0 {
        return Err("invalid monotonic uptime".into());
    }
    Ok((value * 1_000_000_000.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn protected(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn activation_is_sink_first_replay_safe_and_reconciliation_gated() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        let sink = temp.path().join("sink");
        protected(&sink, SINK_HEADER);
        let key = SigningKey::from_bytes(&[7; 32]);
        let key_path = temp.path().join("recovery.pub");
        protected(
            &key_path,
            super::super::hex(key.verifying_key().as_bytes()).as_bytes(),
        );
        let deadline = uptime_ns().unwrap() + 60_000_000_000;
        let nonce = "0123456789abcdef";
        let payload = format!("FERROCRATE-EMERGENCY-APPROVAL-V1\n{}\ncontainer.stop\ncontainer:abc\n{nonce}\n{deadline}\n", boot_id().unwrap());
        let signature = key.sign(payload.as_bytes());
        let approval = temp.path().join("approval.json");
        protected(&approval, serde_json::to_vec(&serde_json::json!({"payload":payload,"signature":super::super::hex(&signature.to_bytes())})).unwrap().as_slice());
        let args = || EmergencyActivate {
            origin: "console",
            state_dir: &state_dir,
            sink: &sink,
            recovery_public_key: &key_path,
            recovery_approval: &approval,
            action: "container.stop",
            resource: "container:abc",
            nonce,
            deadline_uptime_ns: deadline,
        };
        activate_verified(args()).unwrap();
        assert!(ensure_reconciled(&state_dir).is_err());
        assert!(activate_verified(args())
            .unwrap_err()
            .contains("already active"));
        let state_path = state_dir.join(STATE_FILE);
        let mut persisted: EmergencyState =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        let original_boot = persisted.boot_id.clone();
        persisted.boot_id = "replayed-on-another-boot".into();
        write_state(&state_path, &persisted).unwrap();
        assert!(reconcile_verified(&state_dir, &sink)
            .unwrap_err()
            .contains("another boot"));
        persisted.boot_id = original_boot;
        write_state(&state_path, &persisted).unwrap();
        execute_verified(
            &state_dir,
            &sink,
            "container.stop",
            "container:abc",
            |_, _| Ok(()),
        )
        .unwrap();
        reconcile_verified(&state_dir, &sink).unwrap();
        assert!(ensure_reconciled(&state_dir).is_ok());
        assert!(activate_verified(args())
            .unwrap_err()
            .contains("nonce has already been consumed"));
        let receipts = fs::read_to_string(&sink).unwrap();
        assert!(receipts.contains("\"type\":\"activate\""));
        assert!(receipts.contains("\"type\":\"reconcile\""));
    }

    #[test]
    fn invalid_scope_expired_deadline_and_unavailable_sink_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing-sink");
        let placeholder = temp.path().join("placeholder");
        protected(&placeholder, b"x");
        let state = temp.path().join("state");
        let base = EmergencyActivate {
            origin: "console",
            state_dir: &state,
            sink: &missing,
            recovery_public_key: &placeholder,
            recovery_approval: &placeholder,
            action: "gate.disable",
            resource: "host",
            nonce: "0123456789abcdef",
            deadline_uptime_ns: uptime_ns().unwrap() + 10_000_000_000,
        };
        assert!(activate_verified(base)
            .unwrap_err()
            .contains("cannot disable"));
        let expired = EmergencyActivate {
            action: "container.stop",
            deadline_uptime_ns: 1,
            ..base
        };
        assert!(activate_verified(expired).unwrap_err().contains("deadline"));

        let key = SigningKey::from_bytes(&[9; 32]);
        protected(
            &placeholder,
            super::super::hex(key.verifying_key().as_bytes()).as_bytes(),
        );
        let approval = temp.path().join("approval");
        let deadline = uptime_ns().unwrap() + 30_000_000_000;
        let payload = format!("FERROCRATE-EMERGENCY-APPROVAL-V1\n{}\ncontainer.stop\ncontainer:x\n0123456789abcdef\n{deadline}\n", boot_id().unwrap());
        protected(&approval, serde_json::to_vec(&serde_json::json!({"payload":payload,"signature":super::super::hex(&key.sign(payload.as_bytes()).to_bytes())})).unwrap().as_slice());
        let unavailable = EmergencyActivate {
            action: "container.stop",
            resource: "container:x",
            deadline_uptime_ns: deadline,
            recovery_approval: &approval,
            ..base
        };
        assert!(activate_verified(unavailable)
            .unwrap_err()
            .contains("sink unavailable"));
        assert!(!state.join(STATE_FILE).exists());
    }

    #[test]
    fn production_sink_requires_kernel_proven_append_only_flag() {
        let temp = tempfile::tempdir().unwrap();
        let sink = temp.path().join("sink");
        protected(&sink, SINK_HEADER);

        assert!(require_append_only_sink(&sink)
            .unwrap_err()
            .contains("FS_APPEND_FL"));
    }

    #[test]
    fn deterministic_append_only_backend_advertises_and_enforces_capability() {
        let mut sink = DeterministicAppendOnlySink {
            capable: true,
            receipts: Vec::new(),
        };
        assert!(sink.durable_append_capable());
        sink.append_durable(b"intent").unwrap();
        assert_eq!(sink.receipts, vec![b"intent".to_vec()]);
        let mut unavailable = DeterministicAppendOnlySink {
            capable: false,
            receipts: Vec::new(),
        };
        assert!(unavailable.append_durable(b"intent").is_err());
    }

    #[test]
    fn secure_emergency_file_open_rejects_symlink_ancestors_and_final_links() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        let key = real.join("key");
        protected(&key, b"protected");
        let ancestor = temp.path().join("ancestor");
        std::os::unix::fs::symlink(&real, &ancestor).unwrap();
        assert!(open_secure_owner_file(&ancestor.join("key")).is_err());
        let final_link = temp.path().join("key-link");
        std::os::unix::fs::symlink(&key, &final_link).unwrap();
        assert!(open_secure_owner_file(&final_link).is_err());
    }

    #[test]
    fn retained_state_dirfd_survives_path_replacement_without_redirecting_write() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("state");
        let attacker = temp.path().join("attacker");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&attacker).unwrap();
        let directory = ferro_core::authorization::SecureDirectory::open(&state).unwrap();
        let retained = temp.path().join("retained");
        fs::rename(&state, &retained).unwrap();
        std::os::unix::fs::symlink(&attacker, &state).unwrap();

        directory
            .write_atomic("state.json", b"safe", 0o600)
            .unwrap();

        assert_eq!(fs::read(retained.join("state.json")).unwrap(), b"safe");
        assert!(!attacker.join("state.json").exists());
    }

    #[test]
    fn emergency_state_store_rejects_stale_generation_transition() {
        let temp = tempfile::tempdir().unwrap();
        let state_dir = temp.path().join("state");
        fs::create_dir(&state_dir).unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let store = EmergencyStateStore::open(&state_dir).unwrap();
        let mut state = EmergencyState {
            schema: 1,
            generation: 0,
            boot_id: "boot".into(),
            activated_uptime_ns: 1,
            deadline_uptime_ns: 2,
            action: "container.stop".into(),
            resource: "container:x".into(),
            nonce: "0123456789abcdef".into(),
            sink: "/sink".into(),
            sink_device: 1,
            sink_inode: 2,
            status: EmergencyStatus::Activated,
            main_witness_first: None,
            main_witness_last: None,
            operation_id: None,
            terminal_event_id: None,
            approval_payload: "payload".into(),
            approval_signature: "signature".into(),
            recovery_public_key: "key".into(),
        };
        store.write_cas(None, &mut state).unwrap();
        let stale = state.generation;
        let mut concurrent = store.read().unwrap();
        store.write_cas(Some(stale), &mut concurrent).unwrap();
        assert!(store.write_cas(Some(stale), &mut state).is_err());
    }
}
