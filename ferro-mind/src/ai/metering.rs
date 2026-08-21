//! Durable per-container metering for cognitive-container policy controls.
//!
//! Records token and model-state memory consumption plus provider failover
//! attempts as an append-only JSONL ledger. The durability pattern matches
//! `audit.rs`: create parent directories, take an advisory `flock` so
//! concurrent processes serialize, append one JSON object per line, `sync_data`
//! the file, and sync the parent directory so the entry survives a crash.

use crate::ai::routing::cost::{AttemptOutcome, ProviderAttemptRecord};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MeteringError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct MeteringLedger {
    path: PathBuf,
}

fn metering_write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(unix)]
fn acquire_process_lock(path: &Path) -> Result<Option<File>, MeteringError> {
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)?;
    // SAFETY: `lock` is an open regular file and remains alive until the
    // caller finishes its append, so the kernel releases the advisory lock
    // only after the complete record has been written and synced.
    let result =
        unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) };
    if result != 0 {
        return Err(MeteringError::Io(std::io::Error::last_os_error()));
    }
    Ok(Some(lock))
}

#[cfg(not(unix))]
fn acquire_process_lock(_path: &Path) -> Result<Option<File>, MeteringError> {
    Ok(None)
}

#[derive(Debug, Serialize)]
struct MeteringEntry {
    schema_version: &'static str,
    ts_unix: u64,
    container_id: String,
    kind: &'static str,
    tokens_delta: u64,
    memory_bytes_delta: u64,
    tokens_used_after: u64,
    memory_bytes_after: u64,
    provider: Option<String>,
    detail: Option<String>,
}

impl MeteringLedger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one durable metering entry. The write is flushed and synced
    /// before returning, so the entry survives a process restart.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        container_id: &str,
        kind: &'static str,
        tokens_delta: u64,
        memory_bytes_delta: u64,
        tokens_used_after: u64,
        memory_bytes_after: u64,
        provider: Option<&str>,
        detail: Option<String>,
    ) -> Result<(), MeteringError> {
        let entry = MeteringEntry {
            schema_version: "v1",
            ts_unix: now_unix(),
            container_id: container_id.to_string(),
            kind,
            tokens_delta,
            memory_bytes_delta,
            tokens_used_after,
            memory_bytes_after,
            provider: provider.map(str::to_string),
            detail,
        };
        let _guard = metering_write_lock()
            .lock()
            .map_err(|_| std::io::Error::other("AI metering ledger lock poisoned"))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _process_lock = acquire_process_lock(&self.path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut bytes = serde_json::to_vec(&entry)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        file.sync_data()?;
        if let Some(parent) = self.path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// Records one token/memory consumption event for a container.
    pub fn record_usage(
        &self,
        container_id: &str,
        tokens_delta: u64,
        memory_bytes_delta: u64,
        tokens_used_after: u64,
        memory_bytes_after: u64,
        provider: Option<&str>,
    ) -> Result<(), MeteringError> {
        self.append(
            container_id,
            "usage",
            tokens_delta,
            memory_bytes_delta,
            tokens_used_after,
            memory_bytes_after,
            provider,
            None,
        )
    }

    /// Records the deterministic provider failover attempts of one routed
    /// call, in attempt order, so the failover order is durable. The final
    /// budget state after the sequence is recorded with the last attempt.
    pub fn record_provider_attempts(
        &self,
        container_id: &str,
        attempts: &[ProviderAttemptRecord],
        tokens_used_after: u64,
    ) -> Result<(), MeteringError> {
        for (index, attempt) in attempts.iter().enumerate() {
            let (tokens_delta, detail) = match &attempt.outcome {
                AttemptOutcome::Failed(reason) => (0, format!("failed: {reason}")),
                AttemptOutcome::Succeeded { response_tokens } => {
                    (*response_tokens, format!("succeeded: {response_tokens} response tokens"))
                }
            };
            let used_after = if index + 1 == attempts.len() {
                tokens_used_after
            } else {
                0
            };
            self.append(
                container_id,
                "provider_attempt",
                tokens_delta,
                0,
                used_after,
                0,
                Some(&attempt.provider),
                Some(detail),
            )?;
        }
        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::MeteringLedger;
    use crate::ai::routing::cost::{AttemptOutcome, ProviderAttemptRecord};

    fn read_entries(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .expect("read ledger")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid JSON line"))
            .collect()
    }

    #[test]
    fn usage_record_contains_container_deltas_and_totals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("metering.jsonl");
        let ledger = MeteringLedger::new(&path);
        ledger
            .record_usage("container-7", 120, 4096, 120, 4096, Some("local-wasm"))
            .expect("record usage");

        let entries = read_entries(&path);
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry["schema_version"], "v1");
        assert_eq!(entry["kind"], "usage");
        assert_eq!(entry["container_id"], "container-7");
        assert_eq!(entry["provider"], "local-wasm");
        assert_eq!(entry["tokens_delta"], 120);
        assert_eq!(entry["memory_bytes_delta"], 4096);
        assert_eq!(entry["tokens_used_after"], 120);
        assert_eq!(entry["memory_bytes_after"], 4096);
    }

    #[test]
    fn usage_records_append_across_simulated_restarts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("metering.jsonl");
        let mut expected_total = 0u64;
        for session in 0..3 {
            // A new ledger per "process" must append, not truncate, so
            // consumption history stays durable across restarts.
            let ledger = MeteringLedger::new(&path);
            ledger
                .record_usage("container-7", 50, 0, expected_total + 50, 0, None)
                .expect("record usage");
            expected_total += 50;
        }
        let entries = read_entries(&path);
        assert_eq!(entries.len(), 3);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry["tokens_used_after"], 50 * (index as u64 + 1));
        }
    }

    #[test]
    fn provider_attempts_are_recorded_in_attempt_order_with_outcomes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("metering.jsonl");
        let ledger = MeteringLedger::new(&path);
        let attempts = vec![
            ProviderAttemptRecord {
                provider: "preferred".to_string(),
                outcome: AttemptOutcome::Failed("provider command exited with status 9".into()),
            },
            ProviderAttemptRecord {
                provider: "fallback".to_string(),
                outcome: AttemptOutcome::Succeeded {
                    response_tokens: 12,
                },
            },
        ];
        ledger
            .record_provider_attempts("container-9", &attempts, 24)
            .expect("record attempts");

        let entries = read_entries(&path);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["kind"], "provider_attempt");
        assert_eq!(entries[0]["provider"], "preferred");
        assert!(entries[0]["detail"]
            .as_str()
            .expect("detail")
            .starts_with("failed:"));
        assert_eq!(entries[1]["provider"], "fallback");
        assert_eq!(entries[1]["tokens_delta"], 12);
        // Only the last attempt carries the post-sequence budget state.
        assert_eq!(entries[0]["tokens_used_after"], 0);
        assert_eq!(entries[1]["tokens_used_after"], 24);
    }

    #[test]
    fn concurrent_usage_records_remain_line_delimited_and_durable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("metering.jsonl");
        let ledger = std::sync::Arc::new(MeteringLedger::new(&path));
        let mut workers = Vec::new();
        for index in 0..8 {
            let ledger = ledger.clone();
            workers.push(std::thread::spawn(move || {
                ledger
                    .record_usage("container-concurrent", 1, 1, index, index, None)
                    .expect("record usage");
            }));
        }
        for worker in workers {
            worker.join().expect("worker");
        }
        let entries = read_entries(&path);
        assert_eq!(entries.len(), 8);
        assert!(entries
            .iter()
            .all(|entry| entry["container_id"] == "container-concurrent"));
    }

    // Composed production path: a deterministic recorded failover sequence is
    // persisted to the metering ledger and survives a reopen (simulated
    // restart), keeping the failover order and budget state auditable.
    #[cfg(unix)]
    #[test]
    fn recorded_failover_sequence_is_durable_in_the_ledger_across_reopen() {
        use crate::ai::routing::cost::{
            execute_routed_prompt_metered_failover_recorded, ProviderAdapter, ProviderEndpoint,
            Provider, RoutingPolicy, TokenBudget,
        };
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let failing = temp.path().join("failing.sh");
        let healthy = temp.path().join("healthy.sh");
        std::fs::write(&failing, "#!/bin/sh\nexit 9\n").expect("failing script");
        std::fs::write(&healthy, "#!/bin/sh\nread prompt\nprintf 'ok'\n").expect("healthy script");
        for path in [&failing, &healthy] {
            let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions).expect("permissions");
        }
        let make = |name: &str, quality: f32, command| {
            ProviderAdapter::Command(ProviderEndpoint {
                provider: Provider {
                    name: name.into(),
                    cost_per_1k_tokens: 0.0,
                    quality,
                    avg_latency_ms: 1,
                    local: true,
                },
                command,
                args: Vec::new(),
            })
        };
        let adapters = vec![
            make("preferred", 0.99, failing),
            make("fallback", 0.80, healthy),
        ];

        let ledger_path = temp.path().join("nested").join("metering.jsonl");
        let budget = TokenBudget::new(100);
        let (result, attempts) = execute_routed_prompt_metered_failover_recorded(
            &adapters,
            &RoutingPolicy::default(),
            "hello",
            std::time::Duration::from_secs(5),
            &budget,
            2,
        );
        let (_, _, tokens_used) = result.expect("fallback response");
        MeteringLedger::new(&ledger_path)
            .record_provider_attempts("container-16", &attempts, tokens_used)
            .expect("persist attempts");

        // A new ledger instance over the same file (simulated restart) still
        // sees the recorded attempt order and the final budget state.
        let reopened = MeteringLedger::new(&ledger_path);
        let entries = read_entries(&ledger_path);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["container_id"], "container-16");
        assert_eq!(entries[0]["kind"], "provider_attempt");
        assert_eq!(entries[0]["provider"], "preferred");
        assert_eq!(entries[1]["provider"], "fallback");
        assert_eq!(entries[1]["tokens_used_after"], tokens_used);
        // Appending after the reopen keeps the history intact.
        reopened
            .record_usage("container-16", 0, 0, tokens_used, 0, None)
            .expect("post-restart usage");
        assert_eq!(read_entries(&ledger_path).len(), 3);
    }
}
