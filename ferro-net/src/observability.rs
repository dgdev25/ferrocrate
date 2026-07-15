#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMetrics {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackEvent {
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub state: String,
}

pub fn format_metrics(metrics: &NetworkMetrics) -> String {
    format!(
        "bytes_in={} bytes_out={} packets_in={} packets_out={}",
        metrics.bytes_in, metrics.bytes_out, metrics.packets_in, metrics.packets_out
    )
}

pub fn format_conntrack_event(event: &ConntrackEvent) -> String {
    format!(
        "conntrack src={} dst={} proto={} state={}",
        event.src, event.dst, event.protocol, event.state
    )
}

pub fn format_backend_metrics(metrics: &BackendMetrics) -> String {
    format!(
        "backend_requested={} backend_active={} fallback_rejections={} load_failures={} attach_failures={} map_capacity_failures={} packets_forwarded={} packets_translated={} policy_drops={} malformed_drops={} conntrack_evictions={}",
        metrics.requested,
        metrics.active,
        metrics.fallback_rejections,
        metrics.load_failures,
        metrics.attach_failures,
        metrics.map_capacity_failures,
        metrics.packets_forwarded,
        metrics.packets_translated,
        metrics.policy_drops,
        metrics.malformed_drops,
        metrics.conntrack_evictions,
    )
}

#[cfg(test)]
mod tests {
    use super::{format_backend_metrics, format_conntrack_event, format_metrics, BackendMetrics, ConntrackEvent, NetworkMetrics};
    use crate::NetworkBackend;

    #[test]
    fn backend_metrics_report_requested_and_active_identity() {
        let metrics = BackendMetrics::new(NetworkBackend::Ebpf, NetworkBackend::Ebpf);
        assert_eq!(metrics.requested, metrics.active);
        assert_eq!(metrics.fallback_rejections, 0);
        assert!(format_backend_metrics(&metrics).contains("backend_active=ebpf"));
    }

    #[test]
    fn formats_metrics() {
        let metrics = NetworkMetrics {
            bytes_in: 10,
            bytes_out: 20,
            packets_in: 1,
            packets_out: 2,
        };
        let output = format_metrics(&metrics);
        assert!(output.contains("bytes_in=10"));
        assert!(output.contains("packets_out=2"));
    }

    #[test]
    fn formats_conntrack_event() {
        let event = ConntrackEvent {
            src: "10.0.0.2".to_string(),
            dst: "10.0.0.1".to_string(),
            protocol: "tcp".to_string(),
            state: "ESTABLISHED".to_string(),
        };
        let output = format_conntrack_event(&event);
        assert!(output.contains("conntrack src=10.0.0.2"));
        assert!(output.contains("state=ESTABLISHED"));
    }
}
use crate::NetworkBackend;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendMetrics {
    pub requested: NetworkBackend,
    pub active: NetworkBackend,
    pub fallback_rejections: u64,
    pub load_failures: u64,
    pub attach_failures: u64,
    pub map_capacity_failures: u64,
    pub packets_forwarded: u64,
    pub packets_translated: u64,
    pub policy_drops: u64,
    pub malformed_drops: u64,
    pub conntrack_evictions: u64,
}

impl BackendMetrics {
    pub fn new(requested: NetworkBackend, active: NetworkBackend) -> Self {
        Self {
            requested,
            active,
            fallback_rejections: 0,
            load_failures: 0,
            attach_failures: 0,
            map_capacity_failures: 0,
            packets_forwarded: 0,
            packets_translated: 0,
            policy_drops: 0,
            malformed_drops: 0,
            conntrack_evictions: 0,
        }
    }
}
