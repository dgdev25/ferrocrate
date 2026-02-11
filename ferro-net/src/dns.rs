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

#[cfg(test)]
mod tests {
    use super::{DnsConfig, render_resolv_conf};

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
}
