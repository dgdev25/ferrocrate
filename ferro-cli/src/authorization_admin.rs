#![forbid(unsafe_code)]

mod emergency;
mod witness;

pub use emergency::{
    activate_emergency, ensure_reconciled, reconcile_emergency, EmergencyActivate,
};
pub use witness::{
    checkpoint, rotate_key, show, verify, CheckpointArgs, RotateArgs, ShowArgs, VerifyArgs,
};

use ferro_core::authorization::policy::PolicyStore;
use ferro_core::authorization::{
    surface::{SurfaceAuthorization, SurfacePermit},
    Action, ResourceKind,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub fn policy_check(path: &Path) -> Result<String, String> {
    let snapshot = PolicyStore::load(path)
        .map_err(|error| format!("policy-check: {error}"))?
        .snapshot();
    Ok(format!(
        "allowed=true reason=policy-valid rule=policy.schema policy_version={} policy_digest={}",
        snapshot.generation,
        hex(&snapshot.digest)
    ))
}

pub fn policy_reload(
    candidate: &Path,
    active: &Path,
    rollback: Option<&Path>,
    permit: &SurfacePermit,
    action: Action,
    canonical_name: &str,
) -> Result<String, String> {
    require_host_admin()?;
    let next = PolicyStore::load(candidate)
        .map_err(|error| format!("policy-reload: {error}"))?
        .snapshot();
    SurfaceAuthorization::validate_execution(
        permit,
        action,
        ResourceKind::Policy,
        canonical_name,
        next.generation,
    )
    .map_err(|error| format!("policy-reload authorization binding: {error}"))?;
    let current = if active.exists() {
        Some(
            PolicyStore::load(active)
                .map_err(|error| format!("policy-reload active: {error}"))?
                .snapshot(),
        )
    } else {
        None
    };
    if let Some(current) = &current {
        if next.generation < current.generation {
            let approval = rollback.ok_or_else(|| format!(
                "allowed=false reason=policy-generation-rollback rule=policy.monotonic policy_version={} policy_digest={}",
                current.generation, hex(&current.digest)))?;
            verify_rollback_approval(approval, current.generation, next.generation, &next.digest)?;
        }
    }
    atomic_replace(candidate, active)?;
    Ok(format!(
        "allowed=true reason=policy-reloaded rule=policy.atomic-reload policy_version={} policy_digest={}",
        next.generation, hex(&next.digest)))
}

fn verify_rollback_approval(
    path: &Path,
    current: u64,
    candidate: u64,
    digest: &[u8; 32],
) -> Result<(), String> {
    secure_owner_file(path)?;
    let expected = format!(
        "FERROCRATE-POLICY-ROLLBACK-V1\n{current}\n{candidate}\n{}\n",
        hex(digest)
    );
    let actual = fs::read_to_string(path).map_err(|e| format!("rollback approval: {e}"))?;
    if actual != expected {
        return Err("rollback approval is not bound to this exact policy transition".into());
    }
    Ok(())
}

fn atomic_replace(source: &Path, target: &Path) -> Result<(), String> {
    if fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("active policy path is a symbolic link".into());
    }
    let parent = target.parent().ok_or("active policy has no parent")?;
    let parent_meta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !parent_meta.is_dir()
        || parent_meta.uid() != nix::unistd::geteuid().as_raw()
        || parent_meta.mode() & 0o022 != 0
    {
        return Err("active policy parent directory is not administrator-controlled".into());
    }
    let bytes = fs::read(source).map_err(|e| e.to_string())?;
    let temp = parent.join(format!(".policy.{}.tmp", std::process::id()));
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    out.write_all(&bytes)
        .and_then(|_| out.sync_all())
        .map_err(|e| e.to_string())?;
    fs::rename(&temp, target).map_err(|e| e.to_string())?;
    fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub(crate) fn require_host_admin() -> Result<(), String> {
    let real = nix::unistd::getuid().as_raw();
    let effective = nix::unistd::geteuid().as_raw();
    if real != 0 || effective != 0 {
        return Err(format!(
            "host-administrator authentication failed (real_uid={real}, effective_uid={effective})"
        ));
    }
    let self_ns = fs::metadata("/proc/self/ns/user")
        .map_err(|e| e.to_string())?
        .ino();
    let init_ns = fs::metadata("/proc/1/ns/user")
        .map_err(|e| e.to_string())?
        .ino();
    if self_ns != init_ns {
        return Err("host-administrator authentication failed (non-initial user namespace)".into());
    }
    Ok(())
}

pub(crate) fn secure_owner_file(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file()
        || meta.mode() & 0o077 != 0
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.nlink() != 1
    {
        return Err(format!(
            "{} is not an owner-only regular file",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected {} hexadecimal characters", N * 2));
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid hexadecimal value")?;
    }
    Ok(out)
}

pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
