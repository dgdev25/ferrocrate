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

#[cfg(test)]
mod tests {
    use super::{ConntrackEvent, NetworkMetrics, format_conntrack_event, format_metrics};

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
