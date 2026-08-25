//! Durable Docker-compatible lifecycle event journal.
//!
//! The runtime, rather than an HTTP handler, owns this journal so a workload
//! that exits without an API request is still observable through `/events`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerEvent {
    pub id: u64,
    pub time: u64,
    #[serde(default)]
    pub time_nano: u64,
    pub event_type: String,
    pub action: String,
    pub scope: String,
    pub resource: Option<String>,
    pub status: u16,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

pub struct DockerEventJournal {
    path: PathBuf,
}

impl DockerEventJournal {
    /// Open the standard journal in a runtime directory.
    pub fn open(runtime_dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(runtime_dir).map_err(|error| error.to_string())?;
        Ok(Self {
            path: runtime_dir.join("events.jsonl"),
        })
    }

    pub fn append_container<I, K, V>(
        &mut self,
        action: &str,
        id: &str,
        image: &str,
        attributes: I,
    ) -> Result<(), String>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut fields = BTreeMap::new();
        fields.insert("image".to_string(), image.to_string());
        fields.extend(
            attributes
                .into_iter()
                .map(|(key, value)| (key.as_ref().to_string(), value.as_ref().to_string())),
        );
        self.append("container", action, Some(id), 0, fields)
    }

    pub fn append(
        &mut self,
        event_type: &str,
        action: &str,
        resource: Option<&str>,
        status: u16,
        attributes: BTreeMap<String, String>,
    ) -> Result<(), String> {
        let lock_path = self.path.with_extension("jsonl.lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|error| error.to_string())?;
        #[cfg(unix)]
        #[allow(deprecated)]
        nix::fcntl::flock(lock.as_raw_fd(), nix::fcntl::FlockArg::LockExclusive)
            .map_err(|error| error.to_string())?;
        let next_id = self
            .read()
            .unwrap_or_default()
            .into_iter()
            .map(|event| event.id.saturating_add(1))
            .max()
            .unwrap_or(0);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let event = DockerEvent {
            id: next_id,
            time: timestamp.as_secs(),
            time_nano: timestamp.as_nanos().min(u64::MAX as u128) as u64,
            event_type: event_type.to_string(),
            action: action.to_string(),
            scope: "local".to_string(),
            resource: resource.map(str::to_string),
            status,
            attributes,
        };
        let bytes = serde_json::to_vec(&event).map_err(|error| error.to_string())?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.write_all(b"\n").map_err(|error| error.to_string())?;
        file.sync_data().map_err(|error| error.to_string())
    }

    pub fn read(&self) -> Result<Vec<DockerEvent>, String> {
        let contents = fs::read_to_string(&self.path).unwrap_or_default();
        contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                serde_json::from_str(line)
                    .map_err(|error| format!("event journal contains malformed record: {error}"))
            })
            .collect()
    }
}
