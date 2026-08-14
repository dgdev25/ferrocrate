use super::super::WitnessRecord;
use sha2::{Digest, Sha256};

pub(super) const RECEIVED: u8 = 1;
pub(super) const ALLOWED: u8 = 2;
pub(super) const COMPLETE: u8 = 3;
pub(super) const UNKNOWN: u8 = 4;

#[derive(Clone, Debug)]
pub(super) struct OperationState {
    pub state: u8,
    pub execution_generation: u64,
    pub pending_generation: u64,
    pub request_id: [u8; 16],
    pub runtime_id: [u8; 16],
    pub boot_id: [u8; 16],
    pub principal: [u8; 32],
    pub invocation: u8,
    pub action: u8,
    pub resource_kind: u8,
    pub resource: [u8; 32],
    pub resource_generation: u64,
    pub policy_version: u64,
    pub policy_digest: [u8; 32],
    pub request_digest: [u8; 32],
    pub path_class: u8,
    pub device_class: u8,
    pub correlation_digest: Option<[u8; 32]>,
    pub decision_id: [u8; 16],
    pub decision_digest: [u8; 32],
    pub unknown_event_id: [u8; 16],
    pub binding_digest: [u8; 32],
}

impl OperationState {
    pub fn received(record: &WitnessRecord, execution_generation: u64) -> Self {
        Self {
            state: RECEIVED,
            execution_generation,
            pending_generation: 1,
            request_id: record.request_id,
            runtime_id: record.runtime_instance_id,
            boot_id: record.boot_id,
            principal: record.principal.digest(),
            invocation: record.invocation as u8,
            action: record.action as u8,
            resource_kind: record.resource_kind as u8,
            resource: record.resource.digest(),
            resource_generation: record.resource_generation,
            policy_version: record.policy_version,
            policy_digest: record.policy_digest,
            request_digest: record.request_digest,
            path_class: record.path_class.map_or(0, |value| value as u8),
            device_class: record.device_class.map_or(0, |value| value as u8),
            correlation_digest: record.correlation_digest,
            decision_id: [0; 16],
            decision_digest: [0; 32],
            unknown_event_id: [0; 16],
            binding_digest: request_binding_digest(record),
        }
    }

    pub fn binding_matches(&self, record: &WitnessRecord) -> bool {
        self.request_id == record.request_id
            && self.binding_digest == request_binding_digest(record)
    }

    pub fn terminal_matches(&self, record: &WitnessRecord) -> bool {
        self.binding_matches(record) && record.decision_id == Some(self.decision_id)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(343);
        out.push(self.state);
        out.extend_from_slice(&self.execution_generation.to_be_bytes());
        out.extend_from_slice(&self.pending_generation.to_be_bytes());
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.runtime_id);
        out.extend_from_slice(&self.boot_id);
        out.extend_from_slice(&self.principal);
        out.extend_from_slice(&[self.invocation, self.action, self.resource_kind]);
        out.extend_from_slice(&self.resource);
        out.extend_from_slice(&self.resource_generation.to_be_bytes());
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&[self.path_class, self.device_class]);
        match self.correlation_digest {
            Some(value) => {
                out.push(1);
                out.extend_from_slice(&value);
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0; 32]);
            }
        }
        out.extend_from_slice(&self.decision_id);
        out.extend_from_slice(&self.decision_digest);
        out.extend_from_slice(&self.unknown_event_id);
        out.extend_from_slice(&self.binding_digest);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 343 {
            return None;
        }
        let mut p = 0;
        macro_rules! take {
            ($n:expr) => {{
                let value = bytes.get(p..p + $n)?;
                p += $n;
                value
            }};
        }
        let state = take!(1)[0];
        let execution_generation = u64::from_be_bytes(take!(8).try_into().ok()?);
        let pending_generation = u64::from_be_bytes(take!(8).try_into().ok()?);
        let request_id = take!(16).try_into().ok()?;
        let runtime_id = take!(16).try_into().ok()?;
        let boot_id = take!(16).try_into().ok()?;
        let principal = take!(32).try_into().ok()?;
        let invocation = take!(1)[0];
        let action = take!(1)[0];
        let resource_kind = take!(1)[0];
        let resource = take!(32).try_into().ok()?;
        let resource_generation = u64::from_be_bytes(take!(8).try_into().ok()?);
        let policy_version = u64::from_be_bytes(take!(8).try_into().ok()?);
        let policy_digest = take!(32).try_into().ok()?;
        let request_digest = take!(32).try_into().ok()?;
        let path_class = take!(1)[0];
        let device_class = take!(1)[0];
        let correlation_digest = match take!(1)[0] {
            0 => {
                let padding = take!(32);
                if padding.iter().any(|byte| *byte != 0) {
                    return None;
                }
                None
            }
            1 => Some(take!(32).try_into().ok()?),
            _ => return None,
        };
        let decision_id = take!(16).try_into().ok()?;
        let decision_digest = take!(32).try_into().ok()?;
        let unknown_event_id = take!(16).try_into().ok()?;
        let binding_digest = take!(32).try_into().ok()?;
        if p != bytes.len() {
            return None;
        }
        Some(Self {
            state,
            execution_generation,
            pending_generation,
            request_id,
            runtime_id,
            boot_id,
            principal,
            invocation,
            action,
            resource_kind,
            resource,
            resource_generation,
            policy_version,
            policy_digest,
            request_digest,
            path_class,
            device_class,
            correlation_digest,
            decision_id,
            decision_digest,
            unknown_event_id,
            binding_digest,
        })
    }
}

fn request_binding_digest(record: &WitnessRecord) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"FERROCRATE-REQUEST-BINDING-V2");
    hash.update(record.epoch.to_be_bytes());
    hash.update(record.runtime_instance_id);
    hash.update(record.boot_id);
    hash.update(record.principal.digest());
    hash.update([
        record.invocation as u8,
        record.action as u8,
        record.resource_kind as u8,
    ]);
    hash.update(record.resource.digest());
    hash.update(record.resource_generation.to_be_bytes());
    hash.update(record.policy_version.to_be_bytes());
    hash.update(record.policy_digest);
    hash.update(record.request_digest);
    hash.update([
        record.path_class.map_or(0, |value| value as u8),
        record.device_class.map_or(0, |value| value as u8),
    ]);
    match record.correlation_digest {
        Some(value) => {
            hash.update([1]);
            hash.update(value);
        }
        None => hash.update([0]),
    }
    hash.finalize().into()
}
