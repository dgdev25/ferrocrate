use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::FleetRole;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "message")]
pub enum AuditResult {
    Succeeded,
    Denied,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub created_at: i64,
    pub principal: String,
    pub role: FleetRole,
    pub action: String,
    pub request_digest: String,
    pub result: AuditResult,
}

pub struct AuditJournal {
    path: PathBuf,
    append_lock: Mutex<()>,
}

impl AuditJournal {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create fleet audit directory: {error}"))?;
        }
        let file = open_append(&path)?;
        validate_file(&file)?;
        Ok(Self {
            path,
            append_lock: Mutex::new(()),
        })
    }

    pub fn append(
        &self,
        principal: &str,
        role: FleetRole,
        action: &str,
        request: &Value,
        result: AuditResult,
        created_at: i64,
    ) -> Result<(), String> {
        if principal.trim().is_empty() || action.trim().is_empty() {
            return Err("fleet audit identity and action are required".into());
        }
        let _guard = self
            .append_lock
            .lock()
            .map_err(|_| "fleet audit lock poisoned".to_string())?;
        let mut file = open_append(&self.path)?;
        validate_file(&file)?;
        let entry = AuditEntry {
            created_at,
            principal: principal.into(),
            role,
            action: action.into(),
            request_digest: request_digest(request),
            result,
        };
        serde_json::to_writer(&mut file, &entry)
            .map_err(|error| format!("failed to encode fleet audit entry: {error}"))?;
        file.write_all(b"\n")
            .and_then(|()| file.sync_data())
            .map_err(|error| format!("failed to append fleet audit entry: {error}"))
    }

    pub fn read_all(&self) -> Result<Vec<AuditEntry>, String> {
        let file = File::open(&self.path)
            .map_err(|error| format!("failed to open fleet audit journal: {error}"))?;
        validate_file(&file)?;
        BufReader::new(file)
            .lines()
            .map(|line| {
                let line = line.map_err(|error| format!("failed to read fleet audit: {error}"))?;
                serde_json::from_str(&line)
                    .map_err(|error| format!("invalid fleet audit entry: {error}"))
            })
            .collect()
    }
}

pub fn request_digest(request: &Value) -> String {
    let canonical = canonical_json(request);
    hex(&Sha256::digest(canonical.as_bytes()))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let entries = keys
                .into_iter()
                .map(|key| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("JSON key"),
                        canonical_json(&map[key])
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{entries}}}")
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).expect("JSON value"),
    }
}

fn open_append(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("failed to open fleet audit journal: {error}"))
}

fn validate_file(file: &File) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect fleet audit journal: {error}"))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("fleet audit journal must be an owned mode-0600 regular file".into());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
