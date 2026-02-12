use crate::ai::explain::DecisionTrace;
use crate::ai::config::AiConfig;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
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
            ts_unix: now_unix(),
            action: action.into(),
            trace_id: trace.id.clone(),
            summary: trace.summary.clone(),
            evidence: trace.evidence.clone(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut bytes = serde_json::to_vec(&entry)?;
        bytes.push(b'\n');
        file.write_all(&bytes)?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct DecisionAuditEntry {
    ts_unix: u64,
    action: String,
    trace_id: String,
    summary: String,
    evidence: BTreeMap<String, String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
