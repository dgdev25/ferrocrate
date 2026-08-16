use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search: Vec<String>,
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS resolver I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("DNS resolver read-back mismatch at {0}")]
    Readback(String),
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

/// Atomically publish resolver configuration and verify the exact bytes that
/// became visible. The caller owns the target path; this function never edits
/// a symlink target and refuses to replace one.
pub fn write_resolv_conf(path: &Path, config: &DnsConfig) -> Result<(), DnsError> {
    if path.is_symlink() {
        return Err(DnsError::Readback(path.display().to_string()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("resolv.conf"),
        std::process::id()
    ));
    let contents = render_resolv_conf(config);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        let directory = OpenOptions::new().read(true).open(parent)?;
        directory.sync_all()?;
        let visible = fs::read_to_string(path)?;
        if visible != contents {
            return Err(DnsError::Readback(path.display().to_string()));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{render_resolv_conf, write_resolv_conf, DnsConfig};

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
    fn writes_resolver_configuration_atomically_and_reads_it_back() {
        let directory =
            std::env::temp_dir().join(format!("ferrocrate-dns-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("resolv.conf");
        let config = DnsConfig {
            servers: vec!["127.0.0.53".into()],
            search: vec!["example.local".into()],
        };
        write_resolv_conf(&path, &config).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            render_resolv_conf(&config)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
