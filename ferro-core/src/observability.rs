use crate::container_store::now_unix;
use rand::Rng;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

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
    let Some(config) = load_trace_export_config() else {
        return Ok(());
    };
    let body = serde_json::json!({
        "resource": {
            "service.name": config.service_name,
            "service.namespace": config.service_namespace,
        },
        "trace": {
            "trace_id": random_hex(16),
            "span_id": random_hex(8),
            "kind": kind,
            "ts_unix": now_unix(),
            "payload": payload,
        }
    });
    let client = reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    let mut attempts = 0_u32;
    let deadline = Instant::now() + config.timeout.saturating_mul(config.retries + 1);
    loop {
        attempts = attempts.saturating_add(1);
        let mut request = client.post(config.endpoint.clone()).json(&body);
        for (key, value) in &config.headers {
            request = request.header(key, value);
        }
        match request.send() {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                if attempts > config.retries {
                    return Err(std::io::Error::other(
                        format!("trace export failed with status {}", response.status()),
                    ));
                }
            }
            Err(err) => {
                if attempts > config.retries || Instant::now() >= deadline {
                    return Err(std::io::Error::other(err.to_string()));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Debug)]
struct TraceExportConfig {
    endpoint: String,
    timeout: Duration,
    retries: u32,
    service_name: String,
    service_namespace: String,
    headers: Vec<(String, String)>,
}

fn load_trace_export_config() -> Option<TraceExportConfig> {
    let endpoint = std::env::var("FERROCRATE_OTEL_ENDPOINT").ok()?;
    let enabled = std::env::var("FERROCRATE_OTEL_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    if !enabled {
        return None;
    }
    let timeout_ms = std::env::var("FERROCRATE_OTEL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2000);
    let retries = std::env::var("FERROCRATE_OTEL_RETRIES")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(2);
    let service_name =
        std::env::var("FERROCRATE_OTEL_SERVICE_NAME").unwrap_or_else(|_| "ferrocrate".to_string());
    let service_namespace =
        std::env::var("FERROCRATE_OTEL_SERVICE_NAMESPACE").unwrap_or_else(|_| "runtime".to_string());
    let headers = parse_otel_headers(std::env::var("FERROCRATE_OTEL_HEADERS").ok().as_deref());
    Some(TraceExportConfig {
        endpoint,
        timeout: Duration::from_millis(timeout_ms.max(100)),
        retries,
        service_name,
        service_namespace,
        headers,
    })
}

fn parse_otel_headers(raw: Option<&str>) -> Vec<(String, String)> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split(',')
        .filter_map(|entry| {
            let (key, value) = entry.split_once('=')?;
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() || value.is_empty() {
                return None;
            }
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn random_hex(bytes_len: usize) -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(bytes_len * 2);
    for b in (0..bytes_len).map(|_| rng.random::<u8>()) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{parse_otel_headers, random_hex};

    #[test]
    fn parse_otel_headers_skips_invalid_entries() {
        let headers = parse_otel_headers(Some("Authorization=Bearer abc,X-Token=123,broken"));
        assert_eq!(
            headers,
            vec![
                ("Authorization".to_string(), "Bearer abc".to_string()),
                ("X-Token".to_string(), "123".to_string())
            ]
        );
    }

    #[test]
    fn random_hex_uses_expected_length() {
        let trace_id = random_hex(16);
        let span_id = random_hex(8);
        assert_eq!(trace_id.len(), 32);
        assert_eq!(span_id.len(), 16);
        assert!(trace_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(span_id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
