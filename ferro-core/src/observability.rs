use crate::container_store::now_unix;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct LogEvent<'a> {
    pub ts_unix: u64,
    pub action: &'a str,
    pub container_id: Option<&'a str>,
    pub image: Option<&'a str>,
    pub status: Option<&'a str>,
    pub message: Option<&'a str>,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent<'a> {
    pub ts_unix: u64,
    pub action: &'a str,
    pub actor: &'a str,
    pub container_id: Option<&'a str>,
    pub image: Option<&'a str>,
    pub status: Option<&'a str>,
    pub message: Option<&'a str>,
}

pub fn log_event(runtime_dir: &Path, event: LogEvent<'_>) -> Result<(), std::io::Error> {
    let log_dir = runtime_dir.join("logs");
    fs::create_dir_all(&log_dir)?;
    let log_path = log_dir.join("ferrocrate.jsonl");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let mut value = serde_json::to_vec(&event)?;
    value.push(b'\n');
    file.write_all(&value)?;
    let _ = export_trace("event", &event);
    Ok(())
}

pub fn log_audit_event(runtime_dir: &Path, event: AuditEvent<'_>) -> Result<(), std::io::Error> {
    let log_dir = runtime_dir.join("logs");
    fs::create_dir_all(&log_dir)?;
    let log_path = log_dir.join("ferrocrate-audit.jsonl");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let mut value = serde_json::to_vec(&event)?;
    value.push(b'\n');
    file.write_all(&value)?;
    let _ = export_trace("audit", &event);
    Ok(())
}

pub fn make_event<'a>(
    action: &'a str,
    container_id: Option<&'a str>,
    image: Option<&'a str>,
    status: Option<&'a str>,
    message: Option<&'a str>,
) -> LogEvent<'a> {
    LogEvent {
        ts_unix: now_unix(),
        action,
        container_id,
        image,
        status,
        message,
    }
}

pub fn make_audit_event<'a>(
    action: &'a str,
    actor: &'a str,
    container_id: Option<&'a str>,
    image: Option<&'a str>,
    status: Option<&'a str>,
    message: Option<&'a str>,
) -> AuditEvent<'a> {
    AuditEvent {
        ts_unix: now_unix(),
        action,
        actor,
        container_id,
        image,
        status,
        message,
    }
}

fn export_trace<T: Serialize>(kind: &str, payload: &T) -> Result<(), std::io::Error> {
    let endpoint = match std::env::var("FERROCRATE_OTEL_ENDPOINT") {
        Ok(val) => val,
        Err(_) => return Ok(()),
    };
    let body = serde_json::json!({
        "kind": kind,
        "payload": payload,
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
    let _ = client
        .post(endpoint)
        .json(&body)
        .send()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
    Ok(())
}
