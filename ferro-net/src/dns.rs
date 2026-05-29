#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search: Vec<String>,
}

pub fn render_resolv_conf(config: &DnsConfig) -> String {
    let mut lines = Vec::new();
    for server in &config.servers {
        lines.push(format!("nameserver {server}"));
    }
    if !config.search.is_empty() {
        lines.push(format!("search {}", config.search.join(" ")));
    }
    lines.join("\n") + "\n"
}

/// Render an `/etc/hosts` body: loopback first, then `(name, ip)` entries.
pub fn render_hosts_file(entries: &[(String, String)]) -> String {
    let mut out = String::from("127.0.0.1\tlocalhost\n");
    for (name, ip) in entries {
        out.push_str(&format!("{ip}\t{name}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{render_resolv_conf, DnsConfig};

    #[test]
    fn renders_resolv_conf() {
        let config = DnsConfig {
            servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            search: vec!["example.local".to_string()],
        };
        let output = render_resolv_conf(&config);
        assert!(output.contains("nameserver 1.1.1.1"));
        assert!(output.contains("nameserver 8.8.8.8"));
        assert!(output.contains("search example.local"));
    }

    #[test]
    fn renders_hosts_file() {
        let entries = vec![
            ("web".to_string(), "10.0.0.2".to_string()),
            ("db".to_string(), "10.0.0.3".to_string()),
        ];
        let out = super::render_hosts_file(&entries);
        assert!(out.starts_with("127.0.0.1\tlocalhost\n"));
        assert!(out.contains("10.0.0.2\tweb\n"));
        assert!(out.contains("10.0.0.3\tdb\n"));
    }
}
