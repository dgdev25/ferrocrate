use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequenceValue {
    pub epoch: u64,
    pub revision: u64,
}

#[derive(Debug, Error)]
pub enum SequenceError {
    #[error("netd sequence I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("netd sequence is corrupt")]
    Corrupt,
    #[error("netd sequence revision overflow")]
    Overflow,
}

#[derive(Clone)]
pub struct NetdSequence {
    inner: Arc<Mutex<SequenceState>>,
}
struct SequenceState {
    path: Option<PathBuf>,
    value: SequenceValue,
}

impl NetdSequence {
    pub fn memory(initial: SequenceValue) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SequenceState {
                path: None,
                value: initial,
            })),
        }
    }
    pub fn open(path: PathBuf, initial: SequenceValue) -> Result<Self, SequenceError> {
        let persisted = if path.exists() {
            serde_json::from_slice::<SequenceValue>(&fs::read(&path)?)
                .map_err(|_| SequenceError::Corrupt)?
        } else {
            initial
        };
        let value = if (persisted.epoch, persisted.revision) >= (initial.epoch, initial.revision) {
            persisted
        } else {
            initial
        };
        let sequence = Self {
            inner: Arc::new(Mutex::new(SequenceState {
                path: Some(path),
                value,
            })),
        };
        sequence.persist()?;
        Ok(sequence)
    }
    pub fn advance_controller(&self, value: SequenceValue) -> Result<(), SequenceError> {
        let mut state = self.inner.lock().map_err(|_| SequenceError::Corrupt)?;
        if (value.epoch, value.revision) > (state.value.epoch, state.value.revision) {
            state.value = value;
            persist_locked(&state)?;
        }
        Ok(())
    }
    pub fn reserve_child(&self) -> Result<SequenceValue, SequenceError> {
        let mut state = self.inner.lock().map_err(|_| SequenceError::Corrupt)?;
        state.value.revision = state
            .value
            .revision
            .checked_add(1)
            .ok_or(SequenceError::Overflow)?;
        persist_locked(&state)?;
        Ok(state.value)
    }
    pub fn current(&self) -> Result<SequenceValue, SequenceError> {
        self.inner
            .lock()
            .map(|state| state.value)
            .map_err(|_| SequenceError::Corrupt)
    }
    fn persist(&self) -> Result<(), SequenceError> {
        let state = self.inner.lock().map_err(|_| SequenceError::Corrupt)?;
        persist_locked(&state)
    }
}

fn persist_locked(state: &SequenceState) -> Result<(), SequenceError> {
    let Some(path) = &state.path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec(&state.value).map_err(|_| SequenceError::Corrupt)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NetdSequence, SequenceValue};
    #[test]
    fn reservations_are_unique_under_concurrency_and_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sequence.json");
        let sequence = NetdSequence::open(
            path.clone(),
            SequenceValue {
                epoch: 4,
                revision: 9,
            },
        )
        .unwrap();
        let mut workers = Vec::new();
        for _ in 0..16 {
            let sequence = sequence.clone();
            workers.push(std::thread::spawn(move || {
                sequence.reserve_child().unwrap().revision
            }));
        }
        let mut revisions = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        revisions.sort_unstable();
        revisions.dedup();
        assert_eq!(revisions.len(), 16);
        drop(sequence);
        assert_eq!(
            NetdSequence::open(
                path,
                SequenceValue {
                    epoch: 1,
                    revision: 0
                }
            )
            .unwrap()
            .current()
            .unwrap(),
            SequenceValue {
                epoch: 4,
                revision: 25
            }
        );
    }

    #[test]
    fn controller_local_controller_local_sequence_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sequence.json");
        let sequence = NetdSequence::open(
            path.clone(),
            SequenceValue {
                epoch: 3,
                revision: 0,
            },
        )
        .unwrap();
        sequence
            .advance_controller(SequenceValue {
                epoch: 3,
                revision: 1,
            })
            .unwrap();
        assert_eq!(sequence.reserve_child().unwrap().revision, 2);
        sequence
            .advance_controller(SequenceValue {
                epoch: 3,
                revision: 3,
            })
            .unwrap();
        assert_eq!(sequence.reserve_child().unwrap().revision, 4);
        drop(sequence);
        let restarted = NetdSequence::open(
            path,
            SequenceValue {
                epoch: 3,
                revision: 1,
            },
        )
        .unwrap();
        assert_eq!(
            restarted.current().unwrap(),
            SequenceValue {
                epoch: 3,
                revision: 4
            }
        );
        assert_eq!(restarted.reserve_child().unwrap().revision, 5);
    }
}
