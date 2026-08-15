use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ParentGrantKey {
    pub request_id: String,
    pub operation_id: [u8; 16],
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildIdentity {
    pub request_id: String,
    pub nonce: [u8; 16],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ClaimOutcome {
    Fresh(ChildIdentity),
    InProgress(ChildIdentity),
    Completed {
        child: ChildIdentity,
        response: Vec<u8>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum PersistedClaim {
    InProgress(ChildIdentity),
    Completed {
        child: ChildIdentity,
        response: Vec<u8>,
    },
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedLedger {
    claims: Vec<(ParentGrantKey, PersistedClaim)>,
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("delegation ledger already has a writer")]
    Locked,
    #[error("delegation ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("delegation ledger is corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
    #[error("parent delegation was not claimed")]
    NotClaimed,
    #[error("delegation result exceeds the local API limit")]
    Oversized,
}

pub struct DelegationLedger {
    path: PathBuf,
    _lock: File,
    state: PersistedLedger,
}

impl DelegationLedger {
    pub fn open(path: PathBuf) -> Result<Self, LedgerError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        nix::fcntl::fcntl(
            &lock,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )
        .map_err(std::io::Error::other)?;
        lock.try_lock_exclusive().map_err(|_| LedgerError::Locked)?;
        let state = if path.exists() {
            serde_json::from_slice(&fs::read(&path)?)?
        } else {
            PersistedLedger::default()
        };
        let mut ledger = Self {
            path,
            _lock: lock,
            state,
        };
        if !ledger.path.exists() {
            ledger.persist()?;
        }
        Ok(ledger)
    }

    pub fn claim(
        &mut self,
        parent: ParentGrantKey,
        proposed: ChildIdentity,
    ) -> Result<ClaimOutcome, LedgerError> {
        if let Some((_, existing)) = self.state.claims.iter().find(|(key, _)| key == &parent) {
            return Ok(match existing {
                PersistedClaim::InProgress(child) => ClaimOutcome::InProgress(child.clone()),
                PersistedClaim::Completed { child, response } => ClaimOutcome::Completed {
                    child: child.clone(),
                    response: response.clone(),
                },
            });
        }
        self.state
            .claims
            .push((parent, PersistedClaim::InProgress(proposed.clone())));
        self.persist()?;
        Ok(ClaimOutcome::Fresh(proposed))
    }

    pub fn complete(
        &mut self,
        parent: &ParentGrantKey,
        response: Vec<u8>,
    ) -> Result<(), LedgerError> {
        if response.len() > 256 * 1024 {
            return Err(LedgerError::Oversized);
        }
        let position = self
            .state
            .claims
            .iter()
            .position(|(key, _)| key == parent)
            .ok_or(LedgerError::NotClaimed)?;
        let child = match &self.state.claims[position].1 {
            PersistedClaim::InProgress(child) | PersistedClaim::Completed { child, .. } => {
                child.clone()
            }
        };
        self.state.claims[position].1 = PersistedClaim::Completed { child, response };
        self.persist()
    }

    fn persist(&mut self) -> Result<(), LedgerError> {
        let temporary = self.path.with_extension("tmp");
        if temporary.exists() {
            fs::remove_file(&temporary)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(&self.state)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        sync_parent(&self.path)?;
        Ok(())
    }
}

fn sync_parent(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ChildIdentity, ClaimOutcome, DelegationLedger, LedgerError, ParentGrantKey};

    fn parent() -> ParentGrantKey {
        ParentGrantKey {
            request_id: "parent-1".into(),
            operation_id: [2; 16],
            nonce: [3; 16],
        }
    }

    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        GUARD
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap()
    }

    #[test]
    fn claim_is_durable_and_replay_never_gets_a_fresh_child() {
        let _guard = test_guard();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delegations.json");
        let child = ChildIdentity {
            request_id: "child-1".into(),
            nonce: [4; 16],
        };
        let mut first = DelegationLedger::open(path.clone()).unwrap();
        assert_eq!(
            first.claim(parent(), child.clone()).unwrap(),
            ClaimOutcome::Fresh(child.clone())
        );
        drop(first);
        let mut reopened = DelegationLedger::open(path).unwrap();
        assert_eq!(
            reopened
                .claim(
                    parent(),
                    ChildIdentity {
                        request_id: "child-2".into(),
                        nonce: [5; 16]
                    }
                )
                .unwrap(),
            ClaimOutcome::InProgress(child)
        );
    }

    #[test]
    fn completed_result_is_returned_after_restart() {
        let _guard = test_guard();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delegations.json");
        let child = ChildIdentity {
            request_id: "child-1".into(),
            nonce: [4; 16],
        };
        let mut first = DelegationLedger::open(path.clone()).unwrap();
        first.claim(parent(), child.clone()).unwrap();
        first
            .complete(&parent(), br#"{"Attached":{"container_id":"c1"}}"#.to_vec())
            .unwrap();
        drop(first);
        let mut reopened = DelegationLedger::open(path).unwrap();
        assert_eq!(
            reopened
                .claim(
                    parent(),
                    ChildIdentity {
                        request_id: "different".into(),
                        nonce: [6; 16]
                    }
                )
                .unwrap(),
            ClaimOutcome::Completed {
                child,
                response: br#"{"Attached":{"container_id":"c1"}}"#.to_vec()
            }
        );
    }

    #[test]
    fn a_second_process_writer_is_rejected() {
        let _guard = test_guard();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("delegations.json");
        let first = DelegationLedger::open(path.clone()).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "agent::delegation_ledger::tests::ledger_lock_probe",
            ])
            .env("FERROCRATE_LEDGER_LOCK_PROBE", &path)
            .status()
            .unwrap();
        assert!(status.success());
        drop(first);
    }

    #[test]
    fn ledger_lock_probe() {
        let Some(path) = std::env::var_os("FERROCRATE_LEDGER_LOCK_PROBE") else {
            return;
        };
        assert!(matches!(
            DelegationLedger::open(path.into()),
            Err(LedgerError::Locked)
        ));
    }
}
