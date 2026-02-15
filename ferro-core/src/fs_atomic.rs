use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Atomically write bytes to `path` by writing a temp file in the same
/// directory and then renaming it into place.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("atomic-write"),
        std::process::id(),
        nanos
    );
    let tmp_path = parent.join(tmp_name);

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_atomic;

    #[test]
    fn write_atomic_replaces_file_contents() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("config.json");

        write_atomic(&path, br#"{"v":1}"#).expect("initial write");
        write_atomic(&path, br#"{"v":2}"#).expect("replace write");

        let actual = std::fs::read_to_string(path).expect("read");
        assert_eq!(actual, r#"{"v":2}"#);
    }
}
