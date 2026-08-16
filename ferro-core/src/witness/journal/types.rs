use super::super::OperationId;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalMode {
    Disabled,
    Required,
}

/// Closed result of inspecting external state during startup reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryClassification {
    Recovered,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlushBoundary {
    Reserve,
    Received,
    Decision,
    Outcome,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FaultPoint {
    BeforeTransaction(FlushBoundary),
    Transaction(FlushBoundary),
    BeforeFlush(FlushBoundary),
    DuringFlush(FlushBoundary),
    AfterFlush(FlushBoundary),
    RotationSeal,
    CheckpointBindingRejected,
}

#[derive(Clone, Default)]
pub struct JournalFaults(Arc<Mutex<HashSet<FaultPoint>>>);

impl JournalFaults {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn fail_ambiguous_once(&self, boundary: FlushBoundary) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(FaultPoint::AfterFlush(boundary));
    }
    pub fn fail_once(&self, point: FaultPoint) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(point);
    }
    /// Inject an ENOSPC-equivalent storage failure at an exact visibility or
    /// flush boundary without invoking the real database flush.
    pub fn fail_enospc_once(&self, point: FaultPoint) {
        self.fail_once(point);
    }
    pub(super) fn take(&self, point: FaultPoint) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&point)
    }
}

#[derive(Clone, Debug)]
pub struct JournalConfig {
    pub(super) root: PathBuf,
    pub(super) journal_id: [u8; 16],
    pub(super) mode: JournalMode,
    pub(super) cleanup_reserve_bytes: u64,
    pub(super) max_journal_bytes: u64,
    pub(super) segment_bytes: u64,
}

impl JournalConfig {
    pub fn new(root: impl AsRef<Path>, journal_id: [u8; 16], mode: JournalMode) -> Self {
        Self {
            root: root.as_ref().to_owned(),
            journal_id,
            mode,
            cleanup_reserve_bytes: 64 * 1024,
            max_journal_bytes: 64 * 1024 * 1024,
            segment_bytes: 8 * 1024 * 1024,
        }
    }
    pub fn cleanup_reserve_bytes(mut self, bytes: u64) -> Self {
        self.cleanup_reserve_bytes = bytes;
        self
    }
    pub fn max_journal_bytes(mut self, bytes: u64) -> Self {
        self.max_journal_bytes = bytes;
        self
    }
    pub fn segment_bytes(mut self, bytes: u64) -> Self {
        self.segment_bytes = bytes.max(1);
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("legacy witness journal detected; reopen with the `legacy-sled-importers` feature")]
    LegacyMigrationRequired,
    #[error("witness journal storage schema is unsupported; migrate or start a new epoch")]
    UnsupportedVersion,
    #[error("witness journal is owned by another append coordinator")]
    Locked,
    #[error("configured journal identity does not match durable storage")]
    JournalMismatch,
    #[error("operation ID already exists")]
    DuplicateOperation,
    #[error("witness event ID already exists")]
    DuplicateEvent,
    #[error("operation is not pending")]
    NotPending,
    #[error("operation already has a terminal outcome")]
    AlreadyComplete,
    #[error("durable intent does not belong to this journal or epoch")]
    ProofMismatch,
    #[error("witness lifecycle binding does not match the durable operation")]
    BindingMismatch,
    #[error("witness durability is indeterminate; recover by operation ID")]
    Indeterminate { operation_id: OperationId },
    #[error("automated state changes stopped because cleanup reserve is not durable")]
    AutomationStopped,
    #[error("journal quota reached before reserved cleanup capacity")]
    QuotaExceeded,
    #[error("single witness record exceeds the configured segment bound")]
    OversizedRecord,
    #[error("segment maintenance failed before record visibility")]
    RotationUnavailable,
    #[error("journal storage unavailable before record visibility")]
    UnavailableBeforeVisibility,
    #[error("witness journal is disabled")]
    Disabled,
    #[error("invalid witness stage for journal transition")]
    InvalidStage,
    #[error("corrupt witness journal metadata")]
    Corrupt,
    #[error("witness read mirror is stale and requires explicit maintenance repair")]
    ReaderStale,
    #[error("witness journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("witness journal storage failed: {0}")]
    Storage(#[from] sled::Error),
    #[error("witness journal sqlite storage failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("witness record failed validation: {0}")]
    Record(#[from] super::super::WitnessError),
}

#[derive(Debug)]
pub struct DurableIntent {
    pub(super) journal_id: [u8; 16],
    pub(super) epoch: u64,
    pub(super) operation_id: OperationId,
    pub(super) execution_generation: u64,
    pub(super) pending_generation: u64,
    pub(super) decision_id: [u8; 16],
    pub(super) decision_digest: [u8; 32],
    pub(super) request_digest: [u8; 32],
    pub(super) precondition_digest: [u8; 32],
    pub(super) recovery_recipe_digest: [u8; 32],
}

impl DurableIntent {
    /// ```compile_fail
    /// use ferro_core::witness::DurableIntent;
    /// fn duplicate(value: DurableIntent) { let _ = value.clone(); }
    /// ```
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    pub const fn execution_generation(&self) -> u64 {
        self.execution_generation
    }
    pub(crate) const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
    pub(crate) const fn precondition_digest(&self) -> [u8; 32] {
        self.precondition_digest
    }
    pub(crate) const fn recovery_recipe_digest(&self) -> [u8; 32] {
        self.recovery_recipe_digest
    }
}
