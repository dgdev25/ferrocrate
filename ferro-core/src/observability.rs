use crate::container_store::now_unix;
use rand::Rng;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A closed, allocation-free authorization metric vocabulary. Callers cannot
/// attach principal, resource, request, or policy values as labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionMetric {
    WouldDeny,
    EnforcedDenial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalMetric {
    AppendFailure,
    FlushFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMetric {
    OutcomeUnknown,
    Recovered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationMetric {
    Attributed,
    UnknownPrincipal,
    Decision(DecisionMetric),
    BypassDetected,
    Journal(JournalMetric),
    PendingIntent,
    Recovery(RecoveryMetric),
    VerificationFailure,
}

/// Process-local operational counters. Security decisions and witness writes
/// never depend on this best-effort telemetry object.
#[derive(Default)]
pub struct AuthorizationMetrics {
    attributed: AtomicU64,
    unknown_principal: AtomicU64,
    would_deny: AtomicU64,
    enforced_denial: AtomicU64,
    bypass_detected: AtomicU64,
    bypass_probe: AtomicU64,
    successful_bypass: AtomicU64,
    append_failure: AtomicU64,
    flush_failure: AtomicU64,
    pending_intent: AtomicU64,
    outcome_unknown: AtomicU64,
    recovered: AtomicU64,
    verification_failure: AtomicU64,
    checkpoint_age_seconds: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct AuthorizationMetricsSnapshot {
    pub attributed_total: u64,
    pub unknown_principal_total: u64,
    pub would_deny_total: u64,
    pub enforced_denial_total: u64,
    pub bypass_detected_total: u64,
    pub bypass_probe_total: u64,
    pub successful_bypass_total: u64,
    pub append_failure_total: u64,
    pub flush_failure_total: u64,
    pub pending_intent_total: u64,
    pub outcome_unknown_total: u64,
    pub recovered_total: u64,
    pub verification_failure_total: u64,
    pub checkpoint_age_seconds: u64,
}

static AUTHORIZATION_METRICS: OnceLock<AuthorizationMetrics> = OnceLock::new();

pub fn authorization_metrics() -> &'static AuthorizationMetrics {
    AUTHORIZATION_METRICS.get_or_init(AuthorizationMetrics::new)
}

pub fn authorization_metrics_snapshot() -> AuthorizationMetricsSnapshot {
    authorization_metrics().snapshot()
}

impl AuthorizationMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, metric: AuthorizationMetric) {
        let counter = match metric {
            AuthorizationMetric::Attributed => &self.attributed,
            AuthorizationMetric::UnknownPrincipal => &self.unknown_principal,
            AuthorizationMetric::Decision(DecisionMetric::WouldDeny) => &self.would_deny,
            AuthorizationMetric::Decision(DecisionMetric::EnforcedDenial) => &self.enforced_denial,
            AuthorizationMetric::BypassDetected => &self.bypass_detected,
            AuthorizationMetric::Journal(JournalMetric::AppendFailure) => &self.append_failure,
            AuthorizationMetric::Journal(JournalMetric::FlushFailure) => &self.flush_failure,
            AuthorizationMetric::PendingIntent => &self.pending_intent,
            AuthorizationMetric::Recovery(RecoveryMetric::OutcomeUnknown) => &self.outcome_unknown,
            AuthorizationMetric::Recovery(RecoveryMetric::Recovered) => &self.recovered,
            AuthorizationMetric::VerificationFailure => &self.verification_failure,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_checkpoint_age_seconds(&self, seconds: u64) {
        self.checkpoint_age_seconds
            .store(seconds, Ordering::Relaxed);
    }

    pub fn record_bypass_probe(&self, rejected: bool) {
        self.bypass_probe.fetch_add(1, Ordering::Relaxed);
        if rejected {
            self.bypass_detected.fetch_add(1, Ordering::Relaxed);
        } else {
            self.successful_bypass.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn snapshot(&self) -> AuthorizationMetricsSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        AuthorizationMetricsSnapshot {
            attributed_total: load(&self.attributed),
            unknown_principal_total: load(&self.unknown_principal),
            would_deny_total: load(&self.would_deny),
            enforced_denial_total: load(&self.enforced_denial),
            bypass_detected_total: load(&self.bypass_detected),
            bypass_probe_total: load(&self.bypass_probe),
            successful_bypass_total: load(&self.successful_bypass),
            append_failure_total: load(&self.append_failure),
            flush_failure_total: load(&self.flush_failure),
            pending_intent_total: load(&self.pending_intent),
            outcome_unknown_total: load(&self.outcome_unknown),
            recovered_total: load(&self.recovered),
            verification_failure_total: load(&self.verification_failure),
            checkpoint_age_seconds: load(&self.checkpoint_age_seconds),
        }
    }

    pub fn export_json(&self, path: &Path) -> Result<(), std::io::Error> {
        let bytes = serde_json::to_vec(&self.snapshot())?;
        crate::fs_atomic::write_atomic(path, &bytes)
    }

    /// Renders a deliberately label-free Prometheus text snapshot.
    pub fn render_prometheus(&self) -> String {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        format!(
            concat!(
                "ferro_authorization_attributed_total {}\n",
                "ferro_authorization_unknown_principal_total {}\n",
                "ferro_authorization_would_deny_total {}\n",
                "ferro_authorization_enforced_denial_total {}\n",
                "ferro_authorization_bypass_detected_total {}\n",
                "ferro_authorization_bypass_probe_total {}\n",
                "ferro_authorization_successful_bypass_total {}\n",
                "ferro_witness_append_failure_total {}\n",
                "ferro_witness_flush_failure_total {}\n",
                "ferro_witness_pending_intent_total {}\n",
                "ferro_witness_outcome_unknown_total {}\n",
                "ferro_witness_recovered_total {}\n",
                "ferro_witness_verification_failure_total {}\n",
                "ferro_witness_checkpoint_age_seconds {}\n"
            ),
            load(&self.attributed),
            load(&self.unknown_principal),
            load(&self.would_deny),
            load(&self.enforced_denial),
            load(&self.bypass_detected),
            load(&self.bypass_probe),
            load(&self.successful_bypass),
            load(&self.append_failure),
            load(&self.flush_failure),
            load(&self.pending_intent),
            load(&self.outcome_unknown),
            load(&self.recovered),
            load(&self.verification_failure),
            load(&self.checkpoint_age_seconds),
        )
    }
}

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
                    return Err(std::io::Error::other(format!(
                        "trace export failed with status {}",
                        response.status()
                    )));
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
    let service_namespace = std::env::var("FERROCRATE_OTEL_SERVICE_NAMESPACE")
        .unwrap_or_else(|_| "runtime".to_string());
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
