//! Canonical, bounded security-witness records.
//!
//! This is the stored format. JSON and telemetry are views and must not be
//! re-serialized to establish integrity.
//!
//! Version 1 field order is: format `u8`, hash algorithm `u8`, journal ID
//! `[u8;16]`, sequence `u64`, previous hash `[u8;32]`, four 16-byte event,
//! request, runtime, and boot IDs, principal text, invocation `u8`, action
//! text, resource kind `u8`, resource text, generation `u64`, policy version
//! `u64`, policy digest, optional decision ID, optional rule, optional bool
//! decision, optional reason, request digest, optional result digest, wall
//! time `i64`, monotonic time `u64`, stage `u8`, outcome `u8`, optional
//! recovery event ID, optional path and device classes, and optional
//! correlation digest. Integers are big-endian. Text has a `u16` byte length.
//! Optional values use tag 0 (absent) or 1 (present), except optional bool,
//! whose canonical byte is 0 (absent), 1 (false), or 2 (true).

mod encoding;
mod verify;

pub use encoding::{decode_record, encode_record, hash_record, pseudonymize};
pub use verify::{verify_stream, StreamTrust, VerificationReport};

use std::fmt;

pub const FORMAT_VERSION: u8 = 1;
pub const HASH_ALGORITHM_SHA256: u8 = 1;
pub const HASH_DOMAIN: &[u8] = b"FERROCRATE-WITNESS-V1";
pub const PSEUDONYM_DOMAIN: &[u8] = b"FERROCRATE-PSEUDONYM-V1";
pub const MAX_RECORD_BYTES: usize = 8 * 1024;
pub const MAX_SHORT_TEXT: usize = 256;
pub const MAX_RESOURCE_ID: usize = 512;

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
    pub principal: String,
    pub invocation: Invocation,
    pub action: String,
    pub resource_kind: u8,
    pub resource_id: String,
    pub resource_generation: u64,
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub decision_id: Option<[u8; 16]>,
    pub rule: Option<String>,
    pub decision: Option<bool>,
    pub reason: Option<String>,
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
pub struct RecordBytes(Vec<u8>);

impl AsRef<[u8]> for RecordBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for RecordBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordBytes")
            .field("length", &self.0.len())
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
