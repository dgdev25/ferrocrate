//! Canonical, bounded security-witness records.
//!
//! This is the stored format. JSON and telemetry are views and must not be
//! re-serialized to establish integrity.
//!
//! Version 1 field order is: format `u8`, hash algorithm `u8`, journal ID
//! `[u8;16]`, sequence `u64`, previous hash `[u8;32]`, four 16-byte event,
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

mod encoding;
mod validation;
mod verify;

pub use encoding::{decode_record, encode_record, hash_record, pseudonymize};
pub use verify::{verify_stream, StreamTrust, VerificationReport};

use std::fmt;

pub const FORMAT_VERSION: u8 = 1;
pub const HASH_ALGORITHM_SHA256: u8 = 1;
pub const HASH_DOMAIN: &[u8] = b"FERROCRATE-WITNESS-V1";
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

/// Closed mutation vocabulary persisted as the discriminants 1 through 22 in
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
    pub(super) const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
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
    pub(super) const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedRecord {
    journal_id: [u8; 16],
    record: WitnessRecord,
    bytes: RecordBytes,
}

impl DecodedRecord {
    pub fn journal_id(&self) -> &[u8; 16] {
        &self.journal_id
    }

    pub fn record(&self) -> &WitnessRecord {
        &self.record
    }

    pub fn bytes(&self) -> &RecordBytes {
        &self.bytes
    }
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
    #[error("witness sequence is not contiguous")]
    SequenceGap,
    #[error("witness hash linkage is invalid")]
    BrokenLink,
    #[error("witness lifecycle transition is invalid")]
    InvalidLifecycle,
    #[error("witness verifier has too many open requests")]
    TooManyOpenRequests,
    #[error("pseudonymization purpose must be nonempty and bounded")]
    InvalidPurpose,
}
