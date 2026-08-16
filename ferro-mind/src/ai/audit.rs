use crate::ai::config::AiConfig;
use crate::ai::explain::DecisionTrace;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process;
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
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
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
    }
}
