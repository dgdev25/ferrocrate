use super::super::WitnessRecord;

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
    pub decision_id: [u8; 16],
    pub decision_digest: [u8; 32],
    pub unknown_event_id: [u8; 16],
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
            decision_id: [0; 16],
            decision_digest: [0; 32],
            unknown_event_id: [0; 16],
        }
    }

    pub fn binding_matches(&self, record: &WitnessRecord) -> bool {
        self.request_id == record.request_id
            && self.runtime_id == record.runtime_instance_id
            && self.boot_id == record.boot_id
            && self.principal == record.principal.digest()
            && self.invocation == record.invocation as u8
            && self.action == record.action as u8
            && self.resource_kind == record.resource_kind as u8
            && self.resource == record.resource.digest()
            && self.resource_generation == record.resource_generation
            && self.policy_version == record.policy_version
            && self.policy_digest == record.policy_digest
            && self.request_digest == record.request_digest
    }

    pub fn terminal_matches(&self, record: &WitnessRecord) -> bool {
        self.binding_matches(record) && record.decision_id == Some(self.decision_id)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(276);
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
        out.extend_from_slice(&self.decision_id);
        out.extend_from_slice(&self.decision_digest);
        out.extend_from_slice(&self.unknown_event_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 276 {
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
        let decision_id = take!(16).try_into().ok()?;
        let decision_digest = take!(32).try_into().ok()?;
        let unknown_event_id = take!(16).try_into().ok()?;
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
            decision_id,
            decision_digest,
            unknown_event_id,
        })
    }
}
