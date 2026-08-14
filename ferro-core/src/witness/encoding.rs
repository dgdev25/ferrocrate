use sha2::{Digest, Sha256};

use super::{
    DecodedRecord, DisclosureClass, Invocation, ParsedRecord, ReasonCode, RecordBytes, RuleSummary,
    WitnessAction, WitnessError, WitnessOutcome, WitnessRecord, WitnessResourceKind, WitnessStage,
    FORMAT_VERSION, HASH_ALGORITHM_SHA256, HASH_DOMAIN, MAX_RECORD_BYTES, PSEUDONYM_DOMAIN,
};

pub fn encode_record(
    journal_id: [u8; 16],
    record: &WitnessRecord,
) -> Result<RecordBytes, WitnessError> {
    super::validation::validate_record(record)?;
    let mut out = Vec::with_capacity(512);
    put_u8(&mut out, FORMAT_VERSION);
    put_u8(&mut out, HASH_ALGORITHM_SHA256);
    out.extend_from_slice(&journal_id);
    put_u64(&mut out, record.sequence);
    out.extend_from_slice(&record.previous_hash);
    out.extend_from_slice(&record.event_id);
    out.extend_from_slice(&record.request_id);
    out.extend_from_slice(&record.runtime_instance_id);
    out.extend_from_slice(&record.boot_id);
    out.extend_from_slice(&record.principal.digest());
    put_u8(&mut out, record.invocation as u8);
    put_u8(&mut out, record.action as u8);
    put_u8(&mut out, record.resource_kind as u8);
    out.extend_from_slice(&record.resource.digest());
    put_u64(&mut out, record.resource_generation);
    put_u64(&mut out, record.policy_version);
    out.extend_from_slice(&record.policy_digest);
    put_fixed_optional(&mut out, record.decision_id.as_ref());
    put_fixed_optional(&mut out, record.rule.map(RuleSummary::id).as_ref());
    put_bool_optional(&mut out, record.decision);
    put_enum_optional(&mut out, record.reason);
    out.extend_from_slice(&record.request_digest);
    put_fixed_optional(&mut out, record.result_digest.as_ref());
    out.extend_from_slice(&record.wall_time_ns.to_be_bytes());
    put_u64(&mut out, record.monotonic_ns);
    put_u8(&mut out, record.stage as u8);
    put_u8(&mut out, record.outcome as u8);
    put_fixed_optional(&mut out, record.recovery_link.as_ref());
    put_enum_optional(&mut out, record.path_class);
    put_enum_optional(&mut out, record.device_class);
    put_fixed_optional(&mut out, record.correlation_digest.as_ref());
    if out.len() > MAX_RECORD_BYTES {
        return Err(WitnessError::BoundExceeded { field: "record" });
    }
    Ok(RecordBytes {
        journal_id,
        bytes: out,
    })
}

pub fn decode_record(bytes: &[u8]) -> Result<DecodedRecord, WitnessError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(WitnessError::BoundExceeded { field: "record" });
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.u8()? != FORMAT_VERSION {
        return Err(WitnessError::UnknownDiscriminant { field: "format" });
    }
    if decoder.u8()? != HASH_ALGORITHM_SHA256 {
        return Err(WitnessError::UnknownDiscriminant {
            field: "hash algorithm",
        });
    }
    let journal_id = decoder.fixed()?;
    let record = ParsedRecord {
        sequence: decoder.u64()?,
        previous_hash: decoder.fixed()?,
        event_id: decoder.fixed()?,
        request_id: decoder.fixed()?,
        runtime_instance_id: decoder.fixed()?,
        boot_id: decoder.fixed()?,
        principal_digest: decoder.fixed()?,
        invocation: invocation(decoder.u8()?)?,
        action: action(decoder.u8()?)?,
        resource_kind: resource_kind(decoder.u8()?)?,
        resource_digest: decoder.fixed()?,
        resource_generation: decoder.u64()?,
        policy_version: decoder.u64()?,
        policy_digest: decoder.fixed()?,
        decision_id: decoder.fixed_optional()?,
        rule: decoder.fixed_optional()?.map(RuleSummary::from_id),
        decision: decoder.bool_optional()?,
        reason: reason_optional(&mut decoder)?,
        request_digest: decoder.fixed()?,
        result_digest: decoder.fixed_optional()?,
        wall_time_ns: decoder.i64()?,
        monotonic_ns: decoder.u64()?,
        stage: stage(decoder.u8()?)?,
        outcome: outcome(decoder.u8()?)?,
        recovery_link: decoder.fixed_optional()?,
        path_class: disclosure_optional(&mut decoder)?,
        device_class: disclosure_optional(&mut decoder)?,
        correlation_digest: decoder.fixed_optional()?,
    };
    if !decoder.finished() {
        return Err(WitnessError::NonCanonicalEncoding);
    }
    super::validation::validate_record(&record)?;
    Ok(DecodedRecord {
        journal_id,
        record,
        bytes: RecordBytes {
            journal_id,
            bytes: bytes.to_vec(),
        },
    })
}

pub fn hash_record(record: &RecordBytes) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update([FORMAT_VERSION]);
    hasher.update(record.journal_id);
    hasher.update((record.bytes.len() as u64).to_be_bytes());
    hasher.update(&record.bytes);
    hasher.finalize().into()
}

/// HMAC-SHA256 with a distinct domain and caller-supplied purpose. Only the
/// digest is recordable; the purpose key and source value are not.
pub fn pseudonymize(purpose: &[u8], key: &[u8], value: &[u8]) -> Result<[u8; 32], WitnessError> {
    if purpose.is_empty() || purpose.len() > 128 || key.len() < 32 {
        return Err(WitnessError::InvalidPurpose);
    }
    let mut block = [0_u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = block;
    let mut outer_pad = block;
    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }
    for byte in &mut outer_pad {
        *byte ^= 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(PSEUDONYM_DOMAIN);
    inner.update((purpose.len() as u16).to_be_bytes());
    inner.update(purpose);
    inner.update(value);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    Ok(outer.finalize().into())
}

fn put_u8(out: &mut Vec<u8>, value: u8) {
    out.push(value);
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_fixed_optional<const N: usize>(out: &mut Vec<u8>, value: Option<&[u8; N]>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.extend_from_slice(value);
        }
    }
}

fn put_bool_optional(out: &mut Vec<u8>, value: Option<bool>) {
    out.push(match value {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
}

fn put_enum_optional<T: Copy + Into<u8>>(out: &mut Vec<u8>, value: Option<T>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.push(value.into());
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WitnessError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WitnessError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(WitnessError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, WitnessError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, WitnessError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn i64(&mut self) -> Result<i64, WitnessError> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], WitnessError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WitnessError::Truncated)
    }

    fn tag(&mut self) -> Result<bool, WitnessError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WitnessError::UnknownDiscriminant {
                field: "optional tag",
            }),
        }
    }

    fn fixed_optional<const N: usize>(&mut self) -> Result<Option<[u8; N]>, WitnessError> {
        if self.tag()? {
            Ok(Some(self.fixed()?))
        } else {
            Ok(None)
        }
    }

    fn bool_optional(&mut self) -> Result<Option<bool>, WitnessError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(false)),
            2 => Ok(Some(true)),
            _ => Err(WitnessError::UnknownDiscriminant {
                field: "optional bool",
            }),
        }
    }

    fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn invocation(value: u8) -> Result<Invocation, WitnessError> {
    match value {
        1 => Ok(Invocation::Cli),
        2 => Ok(Invocation::DockerUnix),
        3 => Ok(Invocation::Compose),
        4 => Ok(Invocation::Cri),
        5 => Ok(Invocation::Manager),
        6 => Ok(Invocation::InternalCleanup),
        _ => Err(WitnessError::UnknownDiscriminant {
            field: "invocation",
        }),
    }
}

fn action(value: u8) -> Result<WitnessAction, WitnessError> {
    use WitnessAction::*;
    let action = match value {
        1 => ContainerCreate,
        2 => ContainerRun,
        3 => ContainerExec,
        4 => ContainerPause,
        5 => ContainerResume,
        6 => ContainerStop,
        7 => ContainerKill,
        8 => ContainerRestart,
        9 => ContainerDelete,
        10 => ImagePull,
        11 => ImageDelete,
        12 => VolumeCreate,
        13 => VolumeDelete,
        14 => VolumeMount,
        15 => VolumeUnmount,
        16 => NetworkCreate,
        17 => NetworkDelete,
        18 => NetworkAttach,
        19 => NetworkDetach,
        20 => DeviceUse,
        21 => PolicyReload,
        22 => PolicyRollback,
        23 => CheckpointPublish,
        _ => return Err(WitnessError::UnknownDiscriminant { field: "action" }),
    };
    Ok(action)
}

fn resource_kind(value: u8) -> Result<WitnessResourceKind, WitnessError> {
    use WitnessResourceKind::*;
    match value {
        1 => Ok(Container),
        2 => Ok(Image),
        3 => Ok(Volume),
        4 => Ok(Network),
        5 => Ok(Device),
        6 => Ok(Policy),
        7 => Ok(Administrative),
        _ => Err(WitnessError::UnknownDiscriminant {
            field: "resource kind",
        }),
    }
}

fn stage(value: u8) -> Result<WitnessStage, WitnessError> {
    match value {
        1 => Ok(WitnessStage::RequestReceived),
        2 => Ok(WitnessStage::Decision),
        3 => Ok(WitnessStage::Denied),
        4 => Ok(WitnessStage::Outcome),
        5 => Ok(WitnessStage::Recovery),
        6 => Ok(WitnessStage::CheckpointPublished),
        _ => Err(WitnessError::UnknownDiscriminant { field: "stage" }),
    }
}

fn outcome(value: u8) -> Result<WitnessOutcome, WitnessError> {
    match value {
        0 => Ok(WitnessOutcome::None),
        1 => Ok(WitnessOutcome::Denied),
        2 => Ok(WitnessOutcome::Succeeded),
        3 => Ok(WitnessOutcome::Failed),
        4 => Ok(WitnessOutcome::OutcomeUnknown),
        5 => Ok(WitnessOutcome::Recovered),
        6 => Ok(WitnessOutcome::Quarantined),
        _ => Err(WitnessError::UnknownDiscriminant { field: "outcome" }),
    }
}

fn disclosure_optional(decoder: &mut Decoder<'_>) -> Result<Option<DisclosureClass>, WitnessError> {
    if !decoder.tag()? {
        return Ok(None);
    }
    let value = match decoder.u8()? {
        1 => DisclosureClass::RuntimeManaged,
        2 => DisclosureClass::ReadOnlyHost,
        3 => DisclosureClass::Ephemeral,
        4 => DisclosureClass::BlockDevice,
        5 => DisclosureClass::CharacterDevice,
        6 => DisclosureClass::Accelerator,
        _ => {
            return Err(WitnessError::UnknownDiscriminant {
                field: "disclosure class",
            })
        }
    };
    Ok(Some(value))
}

fn reason_optional(decoder: &mut Decoder<'_>) -> Result<Option<ReasonCode>, WitnessError> {
    if !decoder.tag()? {
        return Ok(None);
    }
    match decoder.u8()? {
        1 => Ok(Some(ReasonCode::PolicyDenied)),
        2 => Ok(Some(ReasonCode::ExecutionFailed)),
        3 => Ok(Some(ReasonCode::RecoveryCompleted)),
        4 => Ok(Some(ReasonCode::Quarantined)),
        _ => Err(WitnessError::UnknownDiscriminant { field: "reason" }),
    }
}
