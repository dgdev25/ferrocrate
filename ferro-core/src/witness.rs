//! Canonical, bounded security-witness records.
//!
//! This is the stored format. JSON and telemetry are views and must not be
//! re-serialized to establish integrity.
//!
//! Version 2 field order is: format `u8`, hash algorithm `u8`, journal ID
//! `[u8;16]`, epoch `u64`, globally monotonic sequence `u64`, previous hash `[u8;32]`, four 16-byte event,
//! request, runtime, and boot IDs, principal digest `[u8;32]`, invocation,
//! action and resource-kind `u8`s, resource digest `[u8;32]`, generation
//! `u64`, policy version `u64`, policy digest, optional decision ID, optional
//! 16-byte rule ID, optional bool decision, optional reason-code `u8`, request
//! digest, optional result digest, wall
//! time `i64`, monotonic time `u64`, stage `u8`, outcome `u8`, optional
//! recovery event ID, optional path and device disclosure classes, and optional
//! correlation digest. Integers are big-endian. Version 1 contains no text
//! fields. Optional values use tag 0 (absent) or 1 (present), except optional bool,
//! whose canonical byte is 0 (absent), 1 (false), or 2 (true).

mod checkpoint;
mod checkpoint_coordinator;
mod checkpoint_evidence;
mod encoding;
mod journal;
mod keys;
mod merkle;
mod reader;
mod recovery;
mod validation;
mod verify;

pub use checkpoint::{
    Checkpoint, CheckpointError, CheckpointKind, CheckpointVerifier, FlushedHead, TrustBundle,
};
pub use checkpoint_coordinator::{
    CheckpointCoordinator, PendingBinding, PendingState, PublicationOutcome, Recoverability,
};
pub use encoding::{decode_record, encode_record, hash_record, pseudonymize};
pub use journal::JournalHead;
pub use journal::{
    DurableIntent, FaultPoint, FlushBoundary, JournalConfig, JournalError, JournalFaults,
    JournalMode, RecoveryClassification, WitnessJournal,
};
pub use keys::{KeyId, KeyMaterial, KeyStore};
pub use merkle::{
    consistency_proof as merkle_consistency_proof,
    frontier_consistency_proof as merkle_frontier_consistency_proof, prove as merkle_prove,
    root as merkle_root, verify as merkle_verify, verify_consistency as merkle_verify_consistency,
    verify_frontier_consistency as merkle_verify_frontier_consistency, MerkleConsistencyProof,
    MerkleError, MerkleFrontierConsistencyProof, MerkleProof,
};
pub use reader::WitnessReader;
pub(crate) use recovery::RecoveryEvidence;
pub use recovery::{
    ObservationDigest, ObservationHandle, OperationId, PendingOperation, RecoveryRecipe,
    RecoveryRecipeError, RecoveryTruthStrategy, RECOVERY_RECIPE_SCHEMA_VERSION,
};
pub use verify::{verify_stream, StreamTrust, VerificationReport};

use std::fmt;

pub const FORMAT_VERSION: u8 = 2;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    Current,
    Stale,
    UnknownTail,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointAge {
    Current { seconds: u64 },
    Stale { seconds: u64 },
}
pub const HASH_ALGORITHM_SHA256: u8 = 1;
pub const HASH_DOMAIN: &[u8] = b"FERROCRATE-WITNESS-V2";
pub const PSEUDONYM_DOMAIN: &[u8] = b"FERROCRATE-PSEUDONYM-V1";
pub const MAX_RECORD_BYTES: usize = 8 * 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Invocation {
    Cli = 1,
    DockerUnix = 2,
    Compose = 3,
    Cri = 4,
    Manager = 5,
    InternalCleanup = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessStage {
    RequestReceived = 1,
    Decision = 2,
    Denied = 3,
    Outcome = 4,
    Recovery = 5,
    CheckpointPublished = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessOutcome {
    None = 0,
    Denied = 1,
    Succeeded = 2,
    Failed = 3,
    OutcomeUnknown = 4,
    Recovered = 5,
    Quarantined = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DisclosureClass {
    RuntimeManaged = 1,
    ReadOnlyHost = 2,
    Ephemeral = 3,
    BlockDevice = 4,
    CharacterDevice = 5,
    Accelerator = 6,
}

/// Closed mutation vocabulary persisted as the discriminants 1 through 33 in
/// declaration order. Unknown values are never carried forward.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessAction {
    ContainerCreate = 1,
    ContainerRun = 2,
    ContainerExec = 3,
    ContainerPause = 4,
    ContainerResume = 5,
    ContainerStop = 6,
    ContainerKill = 7,
    ContainerRestart = 8,
    ContainerDelete = 9,
    ImagePull = 10,
    ImageDelete = 11,
    VolumeCreate = 12,
    VolumeDelete = 13,
    VolumeMount = 14,
    VolumeUnmount = 15,
    NetworkCreate = 16,
    NetworkDelete = 17,
    NetworkAttach = 18,
    NetworkDetach = 19,
    DeviceUse = 20,
    PolicyReload = 21,
    PolicyRollback = 22,
    CheckpointPublish = 23,
    ImageBuild = 24,
    ImageTag = 25,
    ImageReferenceWrite = 26,
    CheckpointRecover = 27,
    KeyRotate = 28,
    RootlessMapping = 29,
    ContainerRename = 30,
    ContainerStart = 31,
    ContainerArchiveWrite = 32,
    ContainerUpdate = 33,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum WitnessResourceKind {
    Container = 1,
    Image = 2,
    Volume = 3,
    Network = 4,
    Device = 5,
    Policy = 6,
    Administrative = 7,
    RootlessMapping = 8,
}

/// Disclosure-safe, pseudonymous principal correlation value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalSummary([u8; 32]);

impl PrincipalSummary {
    /// Derive a principal pseudonym under the fixed principal purpose.
    ///
    /// Raw digest injection is intentionally unavailable:
    /// ```compile_fail
    /// use ferro_core::witness::PrincipalSummary;
    /// let _ = PrincipalSummary::from_digest([0; 32]);
    /// ```
    pub fn pseudonymize(key: &[u8], principal: &[u8]) -> Result<Self, WitnessError> {
        pseudonymize(b"witness/principal", key, principal).map(Self)
    }
    const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// Disclosure-safe, pseudonymous canonical resource correlation value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceSummary([u8; 32]);

impl ResourceSummary {
    /// Derive a resource pseudonym under the fixed resource purpose.
    ///
    /// Raw digest injection is intentionally unavailable:
    /// ```compile_fail
    /// use ferro_core::witness::ResourceSummary;
    /// let _ = ResourceSummary::from_digest([0; 32]);
    /// ```
    pub fn pseudonymize(key: &[u8], resource: &[u8]) -> Result<Self, WitnessError> {
        pseudonymize(b"witness/resource", key, resource).map(Self)
    }
    const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// Stable non-textual identifier for the matched policy rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleSummary([u8; 16]);

impl RuleSummary {
    pub const fn from_id(id: [u8; 16]) -> Self {
        Self(id)
    }
    const fn id(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ReasonCode {
    PolicyDenied = 1,
    ExecutionFailed = 2,
    RecoveryCompleted = 3,
    Quarantined = 4,
    EmergencyOverride = 5,
}

impl From<DisclosureClass> for u8 {
    fn from(value: DisclosureClass) -> Self {
        value as Self
    }
}

impl From<ReasonCode> for u8 {
    fn from(value: ReasonCode) -> Self {
        value as Self
    }
}

/// Allowlisted fields only. Raw paths, devices, environment values, command
/// contents, credentials and secret material have no representation here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessRecord {
    pub epoch: u64,
    pub sequence: u64,
    pub previous_hash: [u8; 32],
    pub event_id: [u8; 16],
    pub request_id: [u8; 16],
    pub runtime_instance_id: [u8; 16],
    pub boot_id: [u8; 16],
    pub principal: PrincipalSummary,
    pub invocation: Invocation,
    pub action: WitnessAction,
    pub resource_kind: WitnessResourceKind,
    pub resource: ResourceSummary,
    pub resource_generation: u64,
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub decision_id: Option<[u8; 16]>,
    pub rule: Option<RuleSummary>,
    pub decision: Option<bool>,
    pub reason: Option<ReasonCode>,
    pub request_digest: [u8; 32],
    pub result_digest: Option<[u8; 32]>,
    pub wall_time_ns: i64,
    pub monotonic_ns: u64,
    pub stage: WitnessStage,
    pub outcome: WitnessOutcome,
    pub recovery_link: Option<[u8; 16]>,
    pub path_class: Option<DisclosureClass>,
    pub device_class: Option<DisclosureClass>,
    pub correlation_digest: Option<[u8; 32]>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecordBytes {
    journal_id: [u8; 16],
    bytes: Vec<u8>,
}

impl AsRef<[u8]> for RecordBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for RecordBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordBytes")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Opaque view of untrusted, canonically parsed record bytes.
///
/// Decoded content cannot be recovered as an encodable record:
/// ```compile_fail
/// use ferro_core::witness::{decode_record, WitnessRecord};
/// let decoded = decode_record(&[]).unwrap();
/// let _: WitnessRecord = decoded.into();
/// ```
/// Nor can callers access the verifier's private parsed representation:
/// ```compile_fail
/// use ferro_core::witness::decode_record;
/// let decoded = decode_record(&[]).unwrap();
/// let _ = decoded.record();
/// ```
#[derive(Eq, PartialEq)]
pub struct DecodedRecord {
    journal_id: [u8; 16],
    record: ParsedRecord,
    bytes: RecordBytes,
}

impl DecodedRecord {
    pub fn journal_id(&self) -> &[u8; 16] {
        &self.journal_id
    }

    pub fn sequence(&self) -> u64 {
        self.record.sequence
    }
    pub fn epoch(&self) -> u64 {
        self.record.epoch
    }

    pub fn stage(&self) -> WitnessStage {
        self.record.stage
    }

    pub fn record_hash(&self) -> [u8; 32] {
        hash_record(&self.bytes)
    }
    pub fn previous_hash(&self) -> [u8; 32] {
        self.record.previous_hash
    }
    pub fn event_id(&self) -> [u8; 16] {
        self.record.event_id
    }
    pub fn request_id(&self) -> [u8; 16] {
        self.record.request_id
    }
    pub fn outcome(&self) -> WitnessOutcome {
        self.record.outcome
    }

    pub fn principal_pseudonym(&self) -> [u8; 32] {
        self.record.principal_digest
    }
    pub fn action(&self) -> WitnessAction {
        self.record.action
    }
    pub fn resource_kind(&self) -> WitnessResourceKind {
        self.record.resource_kind
    }
    pub fn resource_pseudonym(&self) -> [u8; 32] {
        self.record.resource_digest
    }
    pub fn resource_generation(&self) -> u64 {
        self.record.resource_generation
    }
    pub fn policy_generation(&self) -> u64 {
        self.record.policy_version
    }
    pub fn policy_digest(&self) -> [u8; 32] {
        self.record.policy_digest
    }
    pub fn decision(&self) -> Option<bool> {
        self.record.decision
    }
    pub fn reason(&self) -> Option<ReasonCode> {
        self.record.reason
    }
    pub fn rule_id(&self) -> Option<[u8; 16]> {
        self.record.rule.map(RuleSummary::id)
    }

    pub(super) fn record(&self) -> &ParsedRecord {
        &self.record
    }

    pub(super) fn bytes(&self) -> &RecordBytes {
        &self.bytes
    }
}

impl fmt::Debug for DecodedRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodedRecord")
            .field("journal_id", &self.journal_id)
            .field("sequence", &self.record.sequence)
            .field("stage", &self.record.stage)
            .field("length", &self.bytes.bytes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct ParsedRecord {
    pub epoch: u64,
    pub sequence: u64,
    pub previous_hash: [u8; 32],
    pub event_id: [u8; 16],
    pub request_id: [u8; 16],
    pub runtime_instance_id: [u8; 16],
    pub boot_id: [u8; 16],
    pub principal_digest: [u8; 32],
    pub invocation: Invocation,
    pub action: WitnessAction,
    pub resource_kind: WitnessResourceKind,
    pub resource_digest: [u8; 32],
    pub resource_generation: u64,
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub decision_id: Option<[u8; 16]>,
    pub rule: Option<RuleSummary>,
    pub decision: Option<bool>,
    pub reason: Option<ReasonCode>,
    pub request_digest: [u8; 32],
    pub result_digest: Option<[u8; 32]>,
    pub wall_time_ns: i64,
    pub monotonic_ns: u64,
    pub stage: WitnessStage,
    pub outcome: WitnessOutcome,
    pub recovery_link: Option<[u8; 16]>,
    pub path_class: Option<DisclosureClass>,
    pub device_class: Option<DisclosureClass>,
    pub correlation_digest: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum WitnessError {
    #[error("witness record exceeds its {field} bound")]
    BoundExceeded { field: &'static str },
    #[error("witness record is truncated")]
    Truncated,
    #[error("unsupported witness {field} discriminant")]
    UnknownDiscriminant { field: &'static str },
    #[error("witness text field is not canonical UTF-8")]
    NonCanonicalText,
    #[error("witness record has trailing or noncanonical bytes")]
    NonCanonicalEncoding,
    #[error("witness stream belongs to a different journal")]
    WrongJournal,
    #[error("witness stream belongs to a different epoch")]
    WrongEpoch,
    #[error("witness sequence is not contiguous")]
    SequenceGap,
    #[error("witness hash linkage is invalid")]
    BrokenLink,
    #[error("witness lifecycle transition is invalid")]
    InvalidLifecycle,
    #[error("witness verifier has too many open requests")]
    TooManyOpenRequests,
    #[error("witness verifier record limit exceeded")]
    TooManyRecords,
    #[error("pseudonymization purpose must be nonempty and bounded")]
    InvalidPurpose,
}
