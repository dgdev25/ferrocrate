use crate::container_store::now_unix;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct LogEvent<'a> {
    pub ts_unix: u64,
    pub action: &'a str,
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
