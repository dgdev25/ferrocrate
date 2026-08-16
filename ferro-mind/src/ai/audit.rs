use crate::ai::config::AiConfig;
use crate::ai::explain::DecisionTrace;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encode error: {0}")]
    Encode(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct AuditLogger {
    path: PathBuf,
}

fn audit_write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(unix)]
fn acquire_process_lock(path: &Path) -> Result<Option<File>, AuditError> {
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
        return Err(AuditError::Io(std::io::Error::last_os_error()));
    }
    Ok(Some(lock))
}

#[cfg(not(unix))]
fn acquire_process_lock(_path: &Path) -> Result<Option<File>, AuditError> {
    Ok(None)
}

impl AuditLogger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn from_env() -> Option<Self> {
        let config = AiConfig::from_env();
        if !config.enabled {
            return None;
        }
        std::env::var("FERROCRATE_AI_AUDIT_LOG").ok().map(Self::new)
    }

    pub fn log(&self, action: impl Into<String>, trace: &DecisionTrace) -> Result<(), AuditError> {
        let _guard = audit_write_lock()
            .lock()
            .map_err(|_| std::io::Error::other("AI audit log lock poisoned"))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _process_lock = acquire_process_lock(&self.path)?;
        let entry = DecisionAuditEntry {
            schema_version: "v2",
            ts_unix: now_unix(),
            action: action.into(),
            actor: std::env::var("FERROCRATE_AUDIT_ACTOR")
                .unwrap_or_else(|_| "ferrocrate-ai".to_string()),
            component: std::env::var("FERROCRATE_AUDIT_COMPONENT")
                .unwrap_or_else(|_| default_component_name()),
            process_id: process::id(),
            hostname: std::env::var("HOSTNAME").ok(),
            trace_id: trace.id.clone(),
            summary: trace.summary.clone(),
            model: trace.model.clone(),
            model_version: trace.model_version.clone(),
            decision: trace.decision.clone(),
            evidence_keys: trace.evidence.keys().cloned().collect(),
            evidence_count: trace.evidence.len(),
            evidence: trace.evidence.clone(),
            confidence: parse_confidence(&trace.evidence),
        };
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
}

#[derive(Debug, Serialize)]
struct DecisionAuditEntry {
    schema_version: &'static str,
    ts_unix: u64,
    action: String,
    actor: String,
    component: String,
    process_id: u32,
    hostname: Option<String>,
    trace_id: String,
    summary: String,
    model: Option<String>,
    model_version: Option<String>,
    decision: Option<String>,
    evidence_keys: Vec<String>,
    evidence_count: usize,
    evidence: BTreeMap<String, String>,
    confidence: Option<f64>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_component_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| "ferrocrate".to_string())
}

fn parse_confidence(evidence: &BTreeMap<String, String>) -> Option<f64> {
    evidence
        .get("confidence")
        .and_then(|value| value.parse::<f64>().ok())
}

#[cfg(test)]
mod tests {
    use super::AuditLogger;
    use crate::ai::explain::DecisionTrace;

    #[test]
    fn audit_entry_includes_operational_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("ai-audit.jsonl");
        let logger = AuditLogger::new(&path);

        let trace = DecisionTrace::new("trace-1", "test summary")
            .with_model("test-model", "v1")
            .with_decision("observe")
            .with_evidence("confidence", "0.87")
            .with_evidence("container_id", "abc123");
        logger.log("test_action", &trace).expect("log");

        let line = std::fs::read_to_string(path).expect("read");
        let entry: serde_json::Value = serde_json::from_str(line.trim()).expect("json");
        assert_eq!(entry["schema_version"], "v2");
        assert_eq!(entry["action"], "test_action");
        assert!(entry.get("component").is_some());
        assert!(entry.get("process_id").is_some());
        assert_eq!(entry["evidence_count"], 2);
        assert_eq!(entry["confidence"], 0.87);
        assert_eq!(entry["model"], "test-model");
        assert_eq!(entry["model_version"], "v1");
        assert_eq!(entry["decision"], "observe");
    }

    #[test]
    fn concurrent_container_decisions_remain_line_delimited_and_durable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("ai-audit.jsonl");
        let logger = std::sync::Arc::new(AuditLogger::new(&path));
        let mut workers = Vec::new();
        for index in 0..8 {
            let logger = logger.clone();
            workers.push(std::thread::spawn(move || {
                let trace = DecisionTrace::new(
                    format!("trace-{index}"),
                    format!("container decision {index}"),
                )
                .with_evidence("container_id", format!("container-{index}"));
                logger.log("ai_restart_decision", &trace).expect("log");
            }));
        }
        for worker in workers {
            worker.join().expect("worker");
        }

        let contents = std::fs::read_to_string(&path).expect("read audit log");
        let entries = contents
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("valid JSON line"))
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 8);
        assert!(entries.iter().all(|entry| entry["schema_version"] == "v2"));
        assert!(entries.iter().all(|entry| {
            entry["evidence"]["container_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("container-"))
        }));
    }
}
