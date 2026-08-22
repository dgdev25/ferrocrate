//! Append-only lifecycle journal.
//!
//! Every supervisor mutation is recorded as an intent before its effect and
//! an outcome after it. On restart, intents without outcomes are ambiguous:
//! the supervisor asks the executor what actually happened and closes the
//! record, then converges. This mirrors the CRI recovery journal contract
//! (see `docs/evidence/cri/2026-08-21-recovery-fault-injection.md`).

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::executor::MutationAction;

const MAX_JOURNAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_JOURNAL_ENTRIES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentRecord {
    pub seq: u64,
    pub action: MutationAction,
    pub instance_id: String,
    pub service: String,
    pub target_revision: u64,
    pub recorded_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeRecord {
    pub seq: u64,
    pub ok: bool,
    pub detail: String,
    pub recorded_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum JournalEntry {
    Intent(IntentRecord),
    Outcome(OutcomeRecord),
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal file error: {0}")]
    Io(#[from] std::io::Error),
    #[error("journal is invalid: {0}")]
    Invalid(String),
    #[error("journal exceeds the size or entry limit")]
    Oversized,
}

/// One intent whose outcome was never recorded — a crash boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbiguousIntent {
    pub record: IntentRecord,
}

pub struct LifecycleJournal {
    path: PathBuf,
}

impl LifecycleJournal {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Append an intent record and return its sequence number.
    pub fn append_intent(
        &self,
        action: MutationAction,
        instance_id: &str,
        service: &str,
        target_revision: u64,
        recorded_unix: i64,
    ) -> Result<u64, JournalError> {
        let entries = self.load()?;
        let seq = entries
            .last()
            .map(|entry| match entry {
                JournalEntry::Intent(record) => record.seq,
                JournalEntry::Outcome(record) => record.seq,
            })
            .unwrap_or(0)
            + 1;
        self.append(JournalEntry::Intent(IntentRecord {
            seq,
            action,
            instance_id: instance_id.into(),
            service: service.into(),
            target_revision,
            recorded_unix,
        }))?;
        Ok(seq)
    }

    /// Append the outcome for a previously recorded intent.
    pub fn append_outcome(
        &self,
        seq: u64,
        ok: bool,
        detail: &str,
        recorded_unix: i64,
    ) -> Result<(), JournalError> {
        self.append(JournalEntry::Outcome(OutcomeRecord {
            seq,
            ok,
            detail: detail.into(),
            recorded_unix,
        }))
    }

    /// Load and structurally validate the journal.
    pub fn load(&self) -> Result<Vec<JournalEntry>, JournalError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let metadata = fs::symlink_metadata(&self.path)?;
        if !metadata.file_type().is_file() {
            return Err(JournalError::Invalid(
                "journal is not a regular file".into(),
            ));
        }
        if metadata.len() > MAX_JOURNAL_BYTES as u64 {
            return Err(JournalError::Oversized);
        }
        let bytes = fs::read(&self.path)?;
        let mut entries = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let entry: JournalEntry = serde_json::from_slice(line)
                .map_err(|error| JournalError::Invalid(error.to_string()))?;
            entries.push(entry);
        }
        if entries.len() > MAX_JOURNAL_ENTRIES {
            return Err(JournalError::Oversized);
        }
        // Intent sequence numbers must be unique and strictly increasing.
        // Outcomes reuse the matching intent sequence and must follow it.
        let mut last_intent_seq = 0_u64;
        let mut intent_seqs = std::collections::BTreeSet::new();
        for entry in &entries {
            match entry {
                JournalEntry::Intent(record) => {
                    if record.instance_id.trim().is_empty() || record.service.trim().is_empty() {
                        return Err(JournalError::Invalid("empty identity in intent".into()));
                    }
                    if record.seq <= last_intent_seq || !intent_seqs.insert(record.seq) {
                        return Err(JournalError::Invalid(
                            "sequence numbers must increase".into(),
                        ));
                    }
                    last_intent_seq = record.seq;
                }
                JournalEntry::Outcome(record) => {
                    if !intent_seqs.contains(&record.seq) {
                        return Err(JournalError::Invalid(format!(
                            "outcome {} has no preceding intent",
                            record.seq
                        )));
                    }
                }
            }
        }
        Ok(entries)
    }

    /// Intents that never received an outcome.
    pub fn ambiguous(&self, entries: &[JournalEntry]) -> Vec<AmbiguousIntent> {
        let mut closed = std::collections::BTreeSet::new();
        for entry in entries {
            if let JournalEntry::Outcome(record) = entry {
                closed.insert(record.seq);
            }
        }
        entries
            .iter()
            .filter_map(|entry| match entry {
                JournalEntry::Intent(record) if !closed.contains(&record.seq) => {
                    Some(AmbiguousIntent {
                        record: record.clone(),
                    })
                }
                _ => None,
            })
            .collect()
    }

    fn append(&self, entry: JournalEntry) -> Result<(), JournalError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let mut line =
            serde_json::to_vec(&entry).map_err(|error| JournalError::Invalid(error.to_string()))?;
        line.push(b'\n');
        let metadata = fs::symlink_metadata(&self.path);
        let exists = metadata.is_ok() && metadata.unwrap().file_type().is_file();
        let mut file = if exists {
            let file = OpenOptions::new().append(true).open(&self.path)?;
            if file.metadata()?.len() + line.len() as u64 > MAX_JOURNAL_BYTES as u64 {
                return Err(JournalError::Oversized);
            }
            file
        } else {
            let file = OpenOptions::new()
                .append(true)
                .create_new(true)
                .open(&self.path)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file
        };
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_round_trips_intents_and_outcomes_in_order() {
        let directory = tempfile::tempdir().unwrap();
        let journal = LifecycleJournal::new(directory.path().join("journal.jsonl"));
        let first = journal
            .append_intent(MutationAction::Start, "web-r1-0", "web", 1, 100)
            .unwrap();
        let second = journal
            .append_intent(MutationAction::Stop, "web-r1-0", "web", 1, 101)
            .unwrap();
        assert_eq!((first, second), (1, 2));
        journal.append_outcome(first, true, "started", 102).unwrap();

        let entries = journal.load().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            JournalEntry::Intent(IntentRecord {
                seq: 1,
                action: MutationAction::Start,
                instance_id: "web-r1-0".into(),
                service: "web".into(),
                target_revision: 1,
                recorded_unix: 100,
            })
        );
    }

    #[test]
    fn ambiguous_intents_are_intents_without_outcomes() {
        let directory = tempfile::tempdir().unwrap();
        let journal = LifecycleJournal::new(directory.path().join("journal.jsonl"));
        let closed = journal
            .append_intent(MutationAction::Start, "a", "web", 1, 100)
            .unwrap();
        journal.append_outcome(closed, true, "ok", 101).unwrap();
        journal
            .append_intent(MutationAction::Stop, "b", "web", 1, 102)
            .unwrap();

        let entries = journal.load().unwrap();
        let ambiguous = journal.ambiguous(&entries);
        assert_eq!(ambiguous.len(), 1);
        assert_eq!(ambiguous[0].record.instance_id, "b");
    }

    #[test]
    fn outcomes_without_intents_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal.jsonl");
        let journal = LifecycleJournal::new(&path);
        let closed = journal
            .append_intent(MutationAction::Start, "a", "web", 1, 100)
            .unwrap();
        journal.append_outcome(closed, true, "ok", 101).unwrap();
        // Forge an outcome for a nonexistent intent.
        use std::fs::OpenOptions;
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(
            file,
            "{}",
            serde_json::to_string(&JournalEntry::Outcome(OutcomeRecord {
                seq: 99,
                ok: true,
                detail: String::new(),
                recorded_unix: 102
            }))
            .unwrap()
        )
        .unwrap();
        drop(file);
        assert!(matches!(journal.load(), Err(JournalError::Invalid(_))));
    }
}
