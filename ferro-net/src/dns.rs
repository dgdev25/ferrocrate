use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

static RESOLVER_STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search: Vec<String>,
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS resolver I/O failed during {operation} on {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("DNS resolver read-back mismatch at {0}")]
    Readback(String),
}

fn path_io<'a>(
    operation: &'static str,
    path: &'a Path,
) -> impl FnOnce(std::io::Error) -> DnsError + 'a {
    move |source| DnsError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
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
    fs::create_dir_all(parent).map_err(path_io("create resolver parent directory", parent))?;
    let contents = render_resolv_conf(config);
    let (temp, mut file) = loop {
        let sequence = RESOLVER_STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.{}.{sequence}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("resolv.conf"),
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o644);
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(path_io("create resolver staging file", &candidate)(error)),
        }
    };
    let result = (|| -> Result<(), DnsError> {
        file.write_all(contents.as_bytes())
            .map_err(path_io("write resolver staging file", &temp))?;
        file.sync_all()
            .map_err(path_io("sync resolver staging file", &temp))?;
        drop(file);
        fs::rename(&temp, path).map_err(path_io("publish resolver file", path))?;
        let directory = OpenOptions::new()
            .read(true)
            .open(parent)
            .map_err(path_io("open resolver parent directory", parent))?;
        directory
            .sync_all()
            .map_err(path_io("sync resolver parent directory", parent))?;
        let visible =
            fs::read_to_string(path).map_err(path_io("read published resolver file", path))?;
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
    use std::sync::{Arc, Barrier};

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

    #[test]
    fn concurrent_resolver_publications_own_distinct_staging_files() {
        let directory = tempfile::tempdir().expect("resolver directory");
        let path = directory.path().join("resolv.conf");
        let config = DnsConfig {
            servers: vec!["10.0.2.3".into()],
            search: vec!["ferro.local".into()],
        };
        let barrier = Arc::new(Barrier::new(16));
        let writers = (0..16)
            .map(|_| {
                let path = path.clone();
                let config = config.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    write_resolv_conf(&path, &config)
                })
            })
            .collect::<Vec<_>>();

        for writer in writers {
            writer
                .join()
                .expect("resolver writer thread")
                .expect("concurrent resolver publication");
        }
        assert_eq!(
            std::fs::read_to_string(&path).expect("published resolver"),
            "nameserver 10.0.2.3\nsearch ferro.local\n"
        );
        assert!(std::fs::read_dir(directory.path())
            .expect("resolver directory entries")
            .all(|entry| !entry
                .expect("resolver directory entry")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
    }

    #[test]
    fn resolver_io_error_names_operation_and_path() {
        let directory = tempfile::tempdir().expect("resolver directory");
        let parent = directory.path().join("not-a-directory");
        std::fs::write(&parent, b"file").expect("blocking file");
        let path = parent.join("resolv.conf");
        let error = write_resolv_conf(
            &path,
            &DnsConfig {
                servers: vec!["1.1.1.1".into()],
                search: Vec::new(),
            },
        )
        .expect_err("file parent must fail");
        let message = error.to_string();
        assert!(
            message.contains("create resolver parent directory"),
            "{message}"
        );
        assert!(message.contains("not-a-directory"), "{message}");
    }
}
