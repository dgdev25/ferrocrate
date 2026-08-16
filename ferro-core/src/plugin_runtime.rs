//! Authorization-bound plugin execution.
//!
//! This layer is intentionally narrow: it verifies an admitted manifest and
//! detached signature before launching the declared executable, bounds the
//! wall-clock lifetime and captured output, and kills timed-out children. A
//! deployment that needs memory/PID isolation must additionally place the
//! applies the manifest's address-space limit through the host's `prlimit`
//! helper where available. Process-count limits and descendant-wide
//! isolation still require a dedicated cgroup/sandbox at deployment time.

use crate::plugin_contract::{verify_plugin_signature, PluginManifest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginExecutionResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

/// Signed parent authorization context for one plugin child mutation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginDelegation {
    pub parent_operation_id: [u8; 16],
    pub parent_action: String,
    pub parent_resource: String,
    pub child_operation_id: [u8; 16],
    pub expires_at_unix: u64,
    pub signature: String,
}

impl PluginDelegation {
    pub fn signed(
        parent_operation_id: [u8; 16],
        parent_action: impl Into<String>,
        parent_resource: impl Into<String>,
        child_operation_id: [u8; 16],
        expires_at_unix: u64,
        signer: &SigningKey,
    ) -> Result<Self, PluginExecutionError> {
        let mut delegation = Self {
            parent_operation_id,
            parent_action: parent_action.into(),
            parent_resource: parent_resource.into(),
            child_operation_id,
            expires_at_unix,
            signature: String::new(),
        };
        let payload = serde_json::to_vec(&delegation)
            .map_err(|error| PluginExecutionError::Delegation(error.to_string()))?;
        delegation.signature = format!("ed25519:{}", hex::encode(signer.sign(&payload).to_bytes()));
        Ok(delegation)
    }

    fn verify(&self, key: &VerifyingKey) -> Result<(), PluginExecutionError> {
        if self.parent_operation_id == [0; 16]
            || self.child_operation_id == [0; 16]
            || self.parent_action.is_empty()
            || self.parent_action.len() > 128
            || self.parent_resource.is_empty()
            || self.parent_resource.len() > 256
        {
            return Err(PluginExecutionError::Delegation(
                "parent delegation bounds are invalid".to_string(),
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.expires_at_unix < now {
            return Err(PluginExecutionError::Delegation(
                "parent delegation has expired".to_string(),
            ));
        }
        let encoded = self
            .signature
            .strip_prefix("ed25519:")
            .ok_or_else(|| PluginExecutionError::Delegation("invalid signature encoding".into()))?;
        let bytes = hex::decode(encoded)
            .map_err(|_| PluginExecutionError::Delegation("invalid signature encoding".into()))?;
        let signature = Signature::from_slice(&bytes)
            .map_err(|_| PluginExecutionError::Delegation("invalid signature encoding".into()))?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        let payload = serde_json::to_vec(&unsigned)
            .map_err(|error| PluginExecutionError::Delegation(error.to_string()))?;
        key.verify(&payload, &signature)
            .map_err(|_| PluginExecutionError::Delegation("parent signature rejected".into()))
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
enum PluginLifecycleStage {
    Intent,
    Effect,
    Cleanup,
}

#[derive(Debug, Serialize)]
struct PluginLifecycleRecord<'a> {
    schema: u8,
    stage: PluginLifecycleStage,
    timestamp_unix: u64,
    parent_operation_id: [u8; 16],
    child_operation_id: [u8; 16],
    parent_action: &'a str,
    parent_resource: &'a str,
    plugin: &'a str,
    manifest_digest: String,
    result_digest: Option<String>,
    succeeded: Option<bool>,
    error: Option<String>,
}

/// Append-only, fsynced plugin lifecycle provenance.
pub struct PluginLifecycleJournal {
    path: PathBuf,
    lock: Mutex<()>,
}

impl PluginLifecycleJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PluginExecutionError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| PluginExecutionError::Journal(error.to_string()))?;
        }
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.file_type().is_file() {
                return Err(PluginExecutionError::Journal(
                    "plugin lifecycle journal must be a regular file".into(),
                ));
            }
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }

    fn append(&self, record: &PluginLifecycleRecord<'_>) -> Result<(), PluginExecutionError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| PluginExecutionError::Journal("journal lock poisoned".into()))?;
        let bytes = serde_json::to_vec(record)
            .map_err(|error| PluginExecutionError::Journal(error.to_string()))?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| PluginExecutionError::Journal(error.to_string()))?;
        file.write_all(&bytes)
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_data())
            .map_err(|error| PluginExecutionError::Journal(error.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum PluginExecutionError {
    #[error("plugin signature verification failed: {0}")]
    Signature(String),
    #[error("plugin entrypoint is not a regular executable file")]
    Entrypoint,
    #[error("plugin execution io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("plugin resource limits are unavailable: {0}")]
    ResourceLimits(String),
    #[error("plugin cgroup isolation failed: {0}")]
    Cgroup(String),
    #[error("plugin delegation rejected: {0}")]
    Delegation(String),
    #[error("plugin lifecycle journal failed: {0}")]
    Journal(String),
    #[error("plugin output exceeded the declared limit")]
    OutputLimit,
}

fn read_bounded<R: Read>(reader: R, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut output)?;
    Ok(output)
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: R,
    limit: u64,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || read_bounded(reader, limit))
}

fn plugin_command(
    manifest: &PluginManifest,
    args: &[String],
) -> Result<Command, PluginExecutionError> {
    #[cfg(unix)]
    {
        // `pre_exec` cannot be used here because ferrocrate forbids unsafe
        // code. util-linux's prlimit provides an RLIMIT_AS boundary without
        // shell interpretation or interpolation. RLIMIT_NPROC is per-user on
        // Linux (not per-plugin), so it cannot safely represent the manifest's
        // process budget; deployment cgroups enforce that budget instead.
        let probe = Command::new("prlimit").arg("--version").output();
        match probe {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                return Err(PluginExecutionError::ResourceLimits(format!(
                    "prlimit exited with {}",
                    output.status
                )));
            }
            Err(error) => {
                return Err(PluginExecutionError::ResourceLimits(error.to_string()));
            }
        }
        let mut command = Command::new("prlimit");
        command
            .arg(format!("--as={}", manifest.limits.memory_bytes))
            .arg("--")
            .arg(&manifest.entrypoint)
            .args(args);
        return Ok(command);
    }

    #[cfg(not(unix))]
    {
        let mut command = Command::new(&manifest.entrypoint);
        command.args(args);
        Ok(command)
    }
}

/// Verify and execute a plugin entrypoint with bounded timeout and output.
///
/// The manifest signature is checked over the exact canonical manifest before
/// any process is started. Arguments are passed directly to `execve` semantics
/// and are never interpreted by a shell.
pub fn execute_plugin(
    manifest: &PluginManifest,
    trust_root: &VerifyingKey,
    args: &[String],
    stdin: &[u8],
) -> Result<PluginExecutionResult, PluginExecutionError> {
    execute_plugin_inner(manifest, trust_root, args, stdin, None)
}

/// Verify and execute a plugin inside a dedicated cgroup-v2 subtree.
///
/// `cgroup_root` must be a pre-provisioned writable cgroup-v2 directory. The
/// executor creates a per-invocation child, applies the manifest's memory and
/// PID limits, moves the child into it before waiting, and kills the entire
/// subtree during timeout or cleanup. A missing/unwritable cgroup boundary
/// fails closed instead of silently degrading to per-process limits.
pub fn execute_plugin_with_cgroup(
    manifest: &PluginManifest,
    trust_root: &VerifyingKey,
    args: &[String],
    stdin: &[u8],
    cgroup_root: &Path,
) -> Result<PluginExecutionResult, PluginExecutionError> {
    execute_plugin_inner(manifest, trust_root, args, stdin, Some(cgroup_root))
}

/// Execute a plugin as a signed child of a parent authorization decision and
/// persist intent/effect/cleanup provenance. Output bytes are represented only
/// by digests in the journal.
pub fn execute_plugin_delegated(
    manifest: &PluginManifest,
    trust_root: &VerifyingKey,
    delegation: &PluginDelegation,
    journal: &PluginLifecycleJournal,
    args: &[String],
    stdin: &[u8],
) -> Result<PluginExecutionResult, PluginExecutionError> {
    delegation.verify(trust_root)?;
    let manifest_digest = digest_json(manifest)?;
    let intent = PluginLifecycleRecord {
        schema: 1,
        stage: PluginLifecycleStage::Intent,
        timestamp_unix: now_unix(),
        parent_operation_id: delegation.parent_operation_id,
        child_operation_id: delegation.child_operation_id,
        parent_action: &delegation.parent_action,
        parent_resource: &delegation.parent_resource,
        plugin: &manifest.name,
        manifest_digest: manifest_digest.clone(),
        result_digest: None,
        succeeded: None,
        error: None,
    };
    journal.append(&intent)?;

    let result = execute_plugin_inner(manifest, trust_root, args, stdin, None);
    let (result_digest, succeeded, error) = match &result {
        Ok(value) => (
            Some(digest_bytes(&[&value.stdout, &value.stderr])?),
            Some(true),
            None,
        ),
        Err(error) => (None, Some(false), Some(error.to_string())),
    };
    let effect = PluginLifecycleRecord {
        schema: 1,
        stage: PluginLifecycleStage::Effect,
        timestamp_unix: now_unix(),
        parent_operation_id: delegation.parent_operation_id,
        child_operation_id: delegation.child_operation_id,
        parent_action: &delegation.parent_action,
        parent_resource: &delegation.parent_resource,
        plugin: &manifest.name,
        manifest_digest: manifest_digest.clone(),
        result_digest,
        succeeded,
        error,
    };
    let effect_error = journal.append(&effect).err();
    let cleanup = PluginLifecycleRecord {
        schema: 1,
        stage: PluginLifecycleStage::Cleanup,
        timestamp_unix: now_unix(),
        parent_operation_id: delegation.parent_operation_id,
        child_operation_id: delegation.child_operation_id,
        parent_action: &delegation.parent_action,
        parent_resource: &delegation.parent_resource,
        plugin: &manifest.name,
        manifest_digest,
        result_digest: None,
        succeeded: Some(true),
        error: None,
    };
    let cleanup_error = journal.append(&cleanup).err();
    if let Some(error) = effect_error.or(cleanup_error) {
        return Err(error);
    }
    result
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, PluginExecutionError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| PluginExecutionError::Journal(error.to_string()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn digest_bytes(parts: &[&[u8]]) -> Result<String, PluginExecutionError> {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    Ok(hex::encode(digest.finalize()))
}

fn execute_plugin_inner(
    manifest: &PluginManifest,
    trust_root: &VerifyingKey,
    args: &[String],
    stdin: &[u8],
    cgroup_root: Option<&Path>,
) -> Result<PluginExecutionResult, PluginExecutionError> {
    verify_plugin_signature(manifest, trust_root)
        .map_err(|error| PluginExecutionError::Signature(error.to_string()))?;
    let metadata = std::fs::symlink_metadata(&manifest.entrypoint)?;
    if !metadata.file_type().is_file() {
        return Err(PluginExecutionError::Entrypoint);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err(PluginExecutionError::Entrypoint);
        }
    }

    let cgroup = cgroup_root.map(|root| prepare_plugin_cgroup(root, manifest));
    let cgroup = cgroup.transpose()?;
    let mut command = match plugin_command(manifest, args) {
        Ok(command) => command,
        Err(error) => {
            if let Some(path) = cgroup.as_ref() {
                cleanup_plugin_cgroup(path);
            }
            return Err(error);
        }
    };
    let mut child = match command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            if let Some(path) = cgroup.as_ref() {
                cleanup_plugin_cgroup(path);
            }
            return Err(PluginExecutionError::Io(error));
        }
    };
    if let Some(path) = cgroup.as_ref() {
        if let Err(error) = fs::write(path.join("cgroup.procs"), child.id().to_string()) {
            let _ = child.kill();
            let _ = child.wait();
            cleanup_plugin_cgroup(path);
            return Err(PluginExecutionError::Cgroup(format!(
                "move child into cgroup: {error}"
            )));
        }
    }
    if let Some(mut pipe) = child.stdin.take() {
        pipe.write_all(stdin)?;
    }
    let stdout = spawn_reader(
        child
            .stdout
            .take()
            .ok_or(PluginExecutionError::Entrypoint)?,
        manifest.limits.max_output_bytes,
    );
    let stderr = spawn_reader(
        child
            .stderr
            .take()
            .ok_or(PluginExecutionError::Entrypoint)?,
        manifest.limits.max_output_bytes,
    );

    let deadline = Instant::now() + Duration::from_secs(manifest.limits.timeout_secs);
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = child.kill();
            if let Some(path) = cgroup.as_ref() {
                kill_plugin_cgroup(path);
            }
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = match stdout.join() {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            if let Some(path) = cgroup.as_ref() {
                cleanup_plugin_cgroup(path);
            }
            return Err(PluginExecutionError::Io(error));
        }
        Err(_) => {
            if let Some(path) = cgroup.as_ref() {
                cleanup_plugin_cgroup(path);
            }
            return Err(PluginExecutionError::Io(std::io::Error::other(
                "plugin stdout reader panicked",
            )));
        }
    };
    let stderr = match stderr.join() {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            if let Some(path) = cgroup.as_ref() {
                cleanup_plugin_cgroup(path);
            }
            return Err(PluginExecutionError::Io(error));
        }
        Err(_) => {
            if let Some(path) = cgroup.as_ref() {
                cleanup_plugin_cgroup(path);
            }
            return Err(PluginExecutionError::Io(std::io::Error::other(
                "plugin stderr reader panicked",
            )));
        }
    };
    if stdout.len() as u64 > manifest.limits.max_output_bytes
        || stderr.len() as u64 > manifest.limits.max_output_bytes
    {
        if let Some(path) = cgroup.as_ref() {
            cleanup_plugin_cgroup(path);
        }
        return Err(PluginExecutionError::OutputLimit);
    }
    if let Some(path) = cgroup.as_ref() {
        kill_plugin_cgroup(path);
        cleanup_plugin_cgroup(path);
    }
    Ok(PluginExecutionResult {
        exit_code: status.code().unwrap_or(-1),
        stdout,
        stderr,
        timed_out,
    })
}

fn prepare_plugin_cgroup(
    root: &Path,
    manifest: &PluginManifest,
) -> Result<PathBuf, PluginExecutionError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| PluginExecutionError::Cgroup(format!("open root: {error}")))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PluginExecutionError::Cgroup(
            "cgroup root must be a real directory".to_string(),
        ));
    }
    if !root.join("cgroup.controllers").is_file() {
        return Err(PluginExecutionError::Cgroup(
            "cgroup root is not a mounted cgroup-v2 hierarchy".to_string(),
        ));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = root.join(format!("plugin-{}-{stamp:x}", std::process::id()));
    fs::create_dir(&path)
        .map_err(|error| PluginExecutionError::Cgroup(format!("create subtree: {error}")))?;
    let result = (|| {
        fs::write(
            path.join("memory.max"),
            manifest.limits.memory_bytes.to_string(),
        )
        .map_err(|error| PluginExecutionError::Cgroup(format!("set memory.max: {error}")))?;
        fs::write(path.join("pids.max"), manifest.limits.pids.to_string())
            .map_err(|error| PluginExecutionError::Cgroup(format!("set pids.max: {error}")))?;
        Ok(path.clone())
    })();
    if result.is_err() {
        cleanup_plugin_cgroup(&path);
    }
    result
}

fn kill_plugin_cgroup(path: &Path) {
    let kill = path.join("cgroup.kill");
    if kill.exists() {
        let _ = fs::write(kill, b"1");
    }
}

fn cleanup_plugin_cgroup(path: &Path) {
    kill_plugin_cgroup(path);
    let _ = fs::remove_dir(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_contract::{PluginKind, PluginLimits};
    use ed25519_dalek::{Signer, SigningKey};
    use std::os::unix::fs::PermissionsExt;

    fn signed_manifest(path: &str, limits: PluginLimits, key: &SigningKey) -> PluginManifest {
        let mut manifest = PluginManifest {
            api_version: "1".into(),
            name: "test-plugin".into(),
            version: "1.0.0".into(),
            kind: PluginKind::LogDriver,
            entrypoint: path.into(),
            permissions: vec!["read_logs".into()],
            limits,
            signature: String::new(),
        };
        let payload = serde_json::to_vec(&manifest).expect("canonical manifest");
        manifest.signature = format!("ed25519:{}", hex::encode(key.sign(&payload).to_bytes()));
        manifest
    }

    fn script(temp: &tempfile::TempDir, body: &str) -> String {
        let path = temp.path().join("plugin.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).expect("mode");
        path.display().to_string()
    }

    #[test]
    fn verifies_signature_and_passes_arguments_without_a_shell() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let manifest = signed_manifest(&script(&temp, "cat"), PluginLimits::default(), &key);
        let result = execute_plugin(&manifest, &key.verifying_key(), &["--arg".into()], b"ok")
            .expect("plugin");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, b"ok");
        assert!(!result.timed_out);
    }

    #[test]
    fn kills_timed_out_plugin_and_rejects_excess_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let mut limits = PluginLimits::default();
        limits.timeout_secs = 1;
        let manifest = signed_manifest(&script(&temp, "sleep 2"), limits, &key);
        let result = execute_plugin(&manifest, &key.verifying_key(), &[], b"").expect("timeout");
        assert!(result.timed_out);

        let mut limits = PluginLimits::default();
        limits.max_output_bytes = 4;
        let manifest = signed_manifest(&script(&temp, "printf 12345"), limits, &key);
        assert!(matches!(
            execute_plugin(&manifest, &key.verifying_key(), &[], b""),
            Err(PluginExecutionError::OutputLimit)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn applies_declared_address_space_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[6u8; 32]);
        let mut limits = PluginLimits::default();
        limits.memory_bytes = 64 * 1024 * 1024;
        let manifest = signed_manifest(&script(&temp, "ulimit -v"), limits, &key);
        let result =
            execute_plugin(&manifest, &key.verifying_key(), &[], b"").expect("limited plugin");
        let virtual_memory_kib: u64 = String::from_utf8_lossy(&result.stdout)
            .trim()
            .parse()
            .expect("ulimit output");
        assert!(virtual_memory_kib <= 65_536);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_or_group_writable_entrypoints() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let target = script(&temp, "printf ok");
        let link = temp.path().join("plugin-link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let manifest = signed_manifest(&link.display().to_string(), PluginLimits::default(), &key);
        assert!(matches!(
            execute_plugin(&manifest, &key.verifying_key(), &[], b""),
            Err(PluginExecutionError::Entrypoint)
        ));

        let writable = temp.path().join("plugin-writable");
        std::fs::copy(&target, &writable).expect("copy");
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770))
            .expect("writable mode");
        let manifest = signed_manifest(
            &writable.display().to_string(),
            PluginLimits::default(),
            &key,
        );
        assert!(matches!(
            execute_plugin(&manifest, &key.verifying_key(), &[], b""),
            Err(PluginExecutionError::Entrypoint)
        ));
    }

    #[test]
    fn cgroup_execution_fails_closed_when_subtree_controls_are_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let manifest = signed_manifest(&script(&temp, "printf ok"), PluginLimits::default(), &key);
        let cgroup_root = temp.path().join("cgroup");
        std::fs::create_dir(&cgroup_root).expect("cgroup root");
        let result =
            execute_plugin_with_cgroup(&manifest, &key.verifying_key(), &[], b"", &cgroup_root);
        assert!(
            matches!(result, Err(PluginExecutionError::Cgroup(_))),
            "unexpected cgroup result: {result:?}"
        );
        assert!(std::fs::read_dir(&cgroup_root)
            .expect("cgroup root entries")
            .next()
            .is_none());
    }

    #[test]
    fn delegated_plugin_execution_persists_intent_effect_and_cleanup_without_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let manifest = signed_manifest(
            &script(&temp, "printf secret-output"),
            PluginLimits::default(),
            &key,
        );
        let delegation = PluginDelegation::signed(
            [1; 16],
            "container.run",
            "container:abc",
            [2; 16],
            now_unix() + 60,
            &key,
        )
        .expect("delegation");
        let journal =
            PluginLifecycleJournal::open(temp.path().join("plugin.jsonl")).expect("journal");
        let result = execute_plugin_delegated(
            &manifest,
            &key.verifying_key(),
            &delegation,
            &journal,
            &[],
            b"",
        )
        .expect("delegated execution");
        assert_eq!(result.stdout, b"secret-output");
        let journal_text =
            std::fs::read_to_string(temp.path().join("plugin.jsonl")).expect("journal bytes");
        assert_eq!(journal_text.lines().count(), 3);
        assert!(!journal_text.contains("secret-output"));
        assert!(journal_text.contains("Intent"));
        assert!(journal_text.contains("Effect"));
        assert!(journal_text.contains("Cleanup"));
    }

    #[test]
    fn delegated_plugin_rejects_tampered_parent_receipt_before_launch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let manifest = signed_manifest(
            &script(&temp, "printf launched"),
            PluginLimits::default(),
            &key,
        );
        let mut delegation = PluginDelegation::signed(
            [3; 16],
            "container.run",
            "container:abc",
            [4; 16],
            now_unix() + 60,
            &key,
        )
        .expect("delegation");
        delegation.parent_resource = "container:tampered".into();
        let journal =
            PluginLifecycleJournal::open(temp.path().join("plugin.jsonl")).expect("journal");
        let error = execute_plugin_delegated(
            &manifest,
            &key.verifying_key(),
            &delegation,
            &journal,
            &[],
            b"",
        )
        .expect_err("tampered receipt must fail");
        assert!(matches!(error, PluginExecutionError::Delegation(_)));
        assert!(!temp.path().join("plugin.jsonl").exists());
    }
}
