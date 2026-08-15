use super::{decode_hex, require_host_admin, secure_owner_file};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const STATE_FILE: &str = "emergency-active.json";
const SINK_HEADER: &[u8] = b"FERROCRATE-EMERGENCY-SINK-V1\n";
const MAX_DURATION: u64 = 900;
const ALLOWED_ACTIONS: &[&str] = &[
    "container.stop",
    "container.kill",
    "container.remove",
    "network.detach",
    "volume.unmount",
];

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
    boot_id: String,
    activated_uptime_ns: u64,
    deadline_uptime_ns: u64,
    action: String,
    resource: String,
    nonce: String,
    sink: String,
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
    let state_path = args.state_dir.join(STATE_FILE);
    if state_path.exists() {
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
    verify_approval(args.recovery_public_key, args.recovery_approval, &payload)?;
    let nonce_marker = nonce_marker(args.state_dir, &boot_id, args.nonce);
    if nonce_marker.exists() {
        return Err("emergency recovery approval nonce has already been consumed".into());
    }
    let sink =
        fs::canonicalize(args.sink).map_err(|e| format!("emergency sink unavailable: {e}"))?;
    let state = EmergencyState {
        schema: 1,
        boot_id,
        activated_uptime_ns: now,
        deadline_uptime_ns: deadline,
        action: args.action.into(),
        resource: args.resource.into(),
        nonce: args.nonce.into(),
        sink: sink.display().to_string(),
    };
    let receipt = serde_json::json!({"type":"activate","schema":1,"boot_id":state.boot_id,"deadline_uptime_ns":deadline,"action":state.action,"resource":state.resource,"nonce":state.nonce});
    append_sink(
        &sink,
        &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
    )?;
    persist_nonce(&nonce_marker)?;
    write_state(&state_path, &state)?;
    Ok(format!(
        "emergency active action={} resource={} deadline_uptime_ns={} reconciliation_required=true",
        state.action, state.resource, deadline
    ))
}

pub fn reconcile_emergency(state_dir: &Path, sink: &Path) -> Result<String, String> {
    require_host_admin()?;
    require_console()?;
    reconcile_verified(state_dir, sink)
}

fn reconcile_verified(state_dir: &Path, sink: &Path) -> Result<String, String> {
    let path = state_dir.join(STATE_FILE);
    let state: EmergencyState =
        serde_json::from_slice(&fs::read(&path).map_err(|e| format!("emergency state: {e}"))?)
            .map_err(|e| format!("emergency state: {e}"))?;
    if state.schema != 1 || state.boot_id != boot_id()? {
        return Err("emergency state is from another boot; operator recovery is required".into());
    }
    let canonical_sink =
        fs::canonicalize(sink).map_err(|e| format!("emergency sink unavailable: {e}"))?;
    if canonical_sink.display().to_string() != state.sink {
        return Err("reconciliation sink does not match the activation receipt sink".into());
    }
    let receipt = serde_json::json!({"type":"reconcile","schema":1,"boot_id":state.boot_id,"action":state.action,"resource":state.resource,"nonce":state.nonce,"reconciled_uptime_ns":uptime_ns()?});
    append_sink(
        &canonical_sink,
        &serde_json::to_vec(&receipt).map_err(|e| e.to_string())?,
    )?;
    fs::remove_file(&path).map_err(|e| e.to_string())?;
    fs::File::open(state_dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok("emergency reconciled receipt_persisted=true normal_operations_allowed=true".into())
}

pub fn ensure_reconciled(state_dir: &Path) -> Result<(), String> {
    if state_dir.join(STATE_FILE).exists() {
        Err("normal operations denied: emergency receipt reconciliation is required".into())
    } else {
        Ok(())
    }
}

fn verify_approval(key_path: &Path, approval_path: &Path, expected: &str) -> Result<(), String> {
    secure_owner_file(key_path)?;
    secure_owner_file(approval_path)?;
    let key_text = fs::read_to_string(key_path).map_err(|e| e.to_string())?;
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(key_text.trim())?)
        .map_err(|_| "invalid recovery public key")?;
    let approval: Approval =
        serde_json::from_slice(&fs::read(approval_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if approval.payload != expected {
        return Err(
            "recovery approval is not bound to this boot, scope, nonce, and monotonic deadline"
                .into(),
        );
    }
    let signature = Signature::from_bytes(&decode_hex::<64>(&approval.signature)?);
    key.verify(expected.as_bytes(), &signature)
        .map_err(|_| "invalid offline recovery approval".into())
}

fn append_sink(path: &Path, receipt: &[u8]) -> Result<(), String> {
    secure_owner_file(path)?;
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() < SINK_HEADER.len() as u64 {
        return Err("emergency sink is not pre-provisioned".into());
    }
    let mut check = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut header = vec![0; SINK_HEADER.len()];
    check.read_exact(&mut header).map_err(|e| e.to_string())?;
    if header != SINK_HEADER {
        return Err("emergency sink has an invalid framing header".into());
    }
    let mut file = OpenOptions::new()
        .append(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("emergency sink unavailable: {e}"))?;
    file.write_all(receipt)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("emergency sink unavailable: {e}"))
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

fn write_state(path: &Path, state: &EmergencyState) -> Result<(), String> {
    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec(state).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&temp, path).map_err(|e| e.to_string())?;
    fs::File::open(path.parent().ok_or("invalid state path")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

fn nonce_marker(state_dir: &Path, boot_id: &str, nonce: &str) -> PathBuf {
    let value = super::digest(format!("{boot_id}\0{nonce}").as_bytes());
    state_dir.join(format!("emergency-nonce-{}", super::hex(&value)))
}

fn persist_nonce(path: &Path) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "emergency recovery approval nonce has already been consumed".to_string()
            } else {
                format!("cannot persist emergency nonce: {error}")
            }
        })?;
    file.write_all(b"FERROCRATE-EMERGENCY-NONCE-V1\n")
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("cannot persist emergency nonce: {error}"))?;
    fs::File::open(path.parent().ok_or("invalid nonce path")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot persist emergency nonce: {error}"))
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
}
