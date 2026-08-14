use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use sha2::{Digest, Sha256};

use super::gate::{
    AuthorizationGate, AuthorizedRequest, CanonicalRequest, ExecutionBindings, ImageBinding,
    MountHandleDescriptor,
};
use super::policy::PolicyStore;
use super::{Action, MountClass, RequestContext, RequestFacts, Resource, ResourceState};
use crate::container_store::ContainerRecord;
use crate::container_store::CreationProvenance;
use crate::witness::{
    DurableIntent, Invocation, ObservationDigest, ObservationHandle, OperationId, PrincipalSummary,
    ReasonCode, RecoveryRecipe, RecoveryTruthStrategy, ResourceSummary, RuleSummary, WitnessAction,
    WitnessJournal, WitnessOutcome, WitnessRecord, WitnessResourceKind, WitnessStage,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum MediationError {
    #[error("authorization denied: {0}")]
    Denied(String),
    #[error("witness journal failed: {0}")]
    Journal(#[from] crate::witness::JournalError),
    #[error("authorization binding is stale")]
    Stale,
    #[error("invalid runtime identity")]
    Identity,
}

pub(crate) struct RuntimeAuthorization {
    gate: Arc<AuthorizationGate>,
    journal: Option<Arc<WitnessJournal>>,
    runtime_id: [u8; 16],
    boot_id: [u8; 16],
    pseudonym_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct RunMountFact {
    pub class: MountClass,
    pub mount_id: u64,
    pub device_id: u64,
    pub inode: u64,
    pub open_flags: u64,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RunSecurityFacts {
    pub capabilities: Vec<String>,
    pub mounts: Vec<RunMountFact>,
    pub network_ids: Vec<String>,
    pub privileged: bool,
    pub readonly_rootfs: bool,
    pub no_new_privileges: bool,
}

pub(crate) struct MutationPermit {
    pub proof: AuthorizedRequest,
    pub intent: Option<DurableIntent>,
    operation: OperationId,
    decision_id: Option<[u8; 16]>,
    journal_id: Option<[u8; 16]>,
    template: WitnessRecord,
}

impl MutationPermit {
    pub(crate) fn execution_authority(&self) -> (&AuthorizedRequest, Option<&DurableIntent>) {
        (&self.proof, self.intent.as_ref())
    }

    pub(crate) fn creation_provenance(&self) -> CreationProvenance {
        CreationProvenance {
            runtime_instance_id: Some(self.template.runtime_instance_id),
            boot_id: Some(self.template.boot_id),
            journal_id: self.journal_id,
            resource_uuid: Some(self.proof.canonical().resource_id().to_owned()),
            resource_generation: self.proof.canonical().resource_generation(),
            creator_operation_id: Some(*self.operation.as_bytes()),
            image_digest: self.proof.canonical().image_digest().map(str::to_owned),
        }
    }

    pub(crate) fn operation_id(&self) -> [u8; 16] {
        *self.operation.as_bytes()
    }
}

impl RuntimeAuthorization {
    pub(crate) fn compatibility_with_id(runtime_id: [u8; 16]) -> Self {
        let policies = Arc::new(PolicyStore::compatibility_disabled());
        Self::new_with_id(Arc::new(AuthorizationGate::new(policies)), None, runtime_id)
    }

    pub(crate) fn new_with_id(
        gate: Arc<AuthorizationGate>,
        journal: Option<Arc<WitnessJournal>>,
        runtime_id: [u8; 16],
    ) -> Self {
        let mut rng = rand::rng();
        let journal =
            journal.filter(|journal| journal.mode() == crate::witness::JournalMode::Required);
        Self {
            gate,
            journal,
            runtime_id,
            boot_id: read_boot_id().unwrap_or_else(|| rng.random()),
            pseudonym_key: rng.random(),
        }
    }

    pub(crate) fn requires_provenance(&self) -> bool {
        self.journal
            .as_ref()
            .is_some_and(|journal| journal.mode() == crate::witness::JournalMode::Required)
    }

    pub(crate) fn journal(&self) -> Option<&WitnessJournal> {
        self.journal.as_deref()
    }

    pub(crate) fn provenance_matches(&self, record: &ContainerRecord) -> bool {
        let provenance = &record.creation_provenance;
        provenance.is_verifiable()
            && provenance.runtime_instance_id == Some(self.runtime_id)
            && provenance.boot_id == Some(self.boot_id)
            && provenance.resource_uuid.as_deref() == Some(canonical_uuid(&record.id).as_str())
            && provenance.resource_generation > 0
            && provenance.journal_id == self.journal.as_ref().map(|journal| journal.journal_id())
    }

    pub(crate) fn authorize(
        &self,
        action: Action,
        record: &ContainerRecord,
    ) -> Result<MutationPermit, MediationError> {
        self.authorize_with_facts(action, record, None)
    }

    pub(crate) fn authorize_run(
        &self,
        record: &ContainerRecord,
        facts: &RunSecurityFacts,
    ) -> Result<MutationPermit, MediationError> {
        self.authorize_with_facts(Action::ContainerRun, record, Some(facts))
    }

    fn authorize_with_facts(
        &self,
        action: Action,
        record: &ContainerRecord,
        run: Option<&RunSecurityFacts>,
    ) -> Result<MutationPermit, MediationError> {
        let resource_uuid = canonical_uuid(&record.id);
        let state = lifecycle_state(&record.status).ok_or(MediationError::Stale)?;
        let generation = record.mutation_generation.max(1);
        let image = pinned_image(&record.image).or_else(|| {
            record
                .creation_provenance
                .image_digest
                .as_ref()
                .map(|digest| {
                    (
                        format!(
                            "{}@{}",
                            record.image.split('@').next().unwrap_or(&record.image),
                            digest
                        ),
                        digest.clone(),
                    )
                })
        });
        let pin = self.gate.pin();
        let operation = OperationId::from_bytes(rand::rng().random());
        let request_id = uuid_from_bytes(*operation.as_bytes());
        let run = run.cloned().unwrap_or_default();
        let mount_handles = run
            .mounts
            .iter()
            .map(|mount| {
                MountHandleDescriptor::new(
                    mount.class,
                    mount.mount_id,
                    mount.device_id,
                    mount.inode,
                    mount.open_flags,
                )
            })
            .collect::<Vec<_>>();
        let facts = RequestFacts {
            image_digest: image.as_ref().map(|(_, digest)| digest.clone()),
            mounts: run.mounts.iter().map(|mount| mount.class).collect(),
            network_ids: run.network_ids,
            requested_capabilities: run.capabilities,
            privileged: run.privileged,
            lifecycle_state: Some(state),
            readonly_rootfs: run.readonly_rootfs,
            no_new_privileges: run.no_new_privileges,
            ..Default::default()
        };
        let resource = Resource::canonical(
            super::ResourceKind::Container,
            resource_uuid.clone(),
            None,
            generation,
        );
        let context = RequestContext::resolved(request_id, None, action, resource, facts);
        let image_binding = image.map(|(reference, digest)| ImageBinding::new(reference, digest));
        let bindings =
            ExecutionBindings::new(image_binding, generation, Some(state), None, mount_handles);
        let request = CanonicalRequest::new(context, pin, bindings.clone(), bindings);
        let template = self.record_template(&request, operation, action)?;

        if let Some(journal) = &self.journal {
            let witness_action = witness_action(action);
            let mut observation = Sha256::new();
            observation.update(b"ferrocrate/recovery-observation/v1");
            observation.update([witness_action as u8]);
            observation.update(record.id.as_bytes());
            observation.update(record.status.as_bytes());
            observation.update(record.pid.to_be_bytes());
            observation.update(generation.to_be_bytes());
            let recipe = RecoveryRecipe::for_original_with_observation(
                witness_action,
                WitnessResourceKind::Container,
                WitnessAction::ContainerDelete,
                template.request_digest,
                generation,
                RecoveryTruthStrategy::for_container_action(witness_action)
                    .ok_or(MediationError::Identity)?,
                ObservationDigest::from_bytes(observation.finalize().into()),
                ObservationHandle::from_bytes(*operation.as_bytes()),
            )
            .map_err(|_| MediationError::Identity)?;
            journal.append_received(
                operation,
                generation,
                recipe,
                at_stage(&template, WitnessStage::RequestReceived, 1),
            )?;
        }

        match self.gate.authorize(request) {
            Ok(proof) => {
                let mut decision_id = None;
                let intent = if let Some(journal) = &self.journal {
                    let mut decision = at_stage(&template, WitnessStage::Decision, 2);
                    decision.decision = Some(true);
                    let id = rand::rng().random();
                    decision.decision_id = Some(id);
                    decision_id = Some(id);
                    decision.rule = Some(rule_summary(proof.decision().matched_rule.as_bytes()));
                    Some(journal.append_decision(operation, decision)?)
                } else {
                    None
                };
                Ok(MutationPermit {
                    proof,
                    intent,
                    operation,
                    decision_id,
                    journal_id: self.journal.as_ref().map(|journal| journal.journal_id()),
                    template,
                })
            }
            Err(denial) => {
                if let Some(journal) = &self.journal {
                    let decision_id = rand::rng().random();
                    let mut decision = at_stage(&template, WitnessStage::Decision, 2);
                    decision.decision = Some(false);
                    decision.decision_id = Some(decision_id);
                    decision.rule = Some(rule_summary(b"policy.denied"));
                    decision.reason = Some(ReasonCode::PolicyDenied);
                    let mut denied = at_stage(&template, WitnessStage::Denied, 3);
                    denied.decision_id = Some(decision_id);
                    denied.reason = Some(ReasonCode::PolicyDenied);
                    denied.outcome = WitnessOutcome::Denied;
                    journal.deny(operation, decision, denied)?;
                }
                Err(MediationError::Denied(format!("{:?}", denial.code())))
            }
        }
    }

    pub(crate) fn revalidate(
        &self,
        permit: &MutationPermit,
        record: &ContainerRecord,
    ) -> Result<(), MediationError> {
        if permit.proof.canonical().resource_id() != canonical_uuid(&record.id)
            || permit.proof.canonical().resource_generation() != record.mutation_generation.max(1)
            || permit.proof.canonical().state_precondition() != lifecycle_state(&record.status)
        {
            return Err(MediationError::Stale);
        }
        Ok(())
    }

    pub(crate) fn complete(
        &self,
        permit: MutationPermit,
        succeeded: bool,
    ) -> Result<(), MediationError> {
        if let (Some(journal), Some(intent)) = (&self.journal, permit.intent) {
            let mut outcome = at_stage(&permit.template, WitnessStage::Outcome, 4);
            outcome.decision_id = permit.decision_id;
            outcome.outcome = if succeeded {
                WitnessOutcome::Succeeded
            } else {
                WitnessOutcome::Failed
            };
            outcome.result_digest = Some(Sha256::digest([u8::from(succeeded)]).into());
            if !succeeded {
                outcome.reason = Some(ReasonCode::ExecutionFailed);
            }
            journal.complete(intent, outcome)?;
        }
        Ok(())
    }

    fn record_template(
        &self,
        request: &CanonicalRequest,
        operation: OperationId,
        action: Action,
    ) -> Result<WitnessRecord, MediationError> {
        let request_bytes =
            serde_json::to_vec(request.context()).map_err(|_| MediationError::Identity)?;
        let resource =
            ResourceSummary::pseudonymize(&self.pseudonym_key, request.resource_id().as_bytes())
                .map_err(|_| MediationError::Identity)?;
        let principal = PrincipalSummary::pseudonymize(&self.pseudonym_key, b"local-unresolved")
            .map_err(|_| MediationError::Identity)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Ok(WitnessRecord {
            epoch: 1,
            sequence: 0,
            previous_hash: [0; 32],
            event_id: rand::rng().random(),
            request_id: *operation.as_bytes(),
            runtime_instance_id: self.runtime_id,
            boot_id: self.boot_id,
            principal,
            invocation: Invocation::Cli,
            action: witness_action(action),
            resource_kind: WitnessResourceKind::Container,
            resource,
            resource_generation: request.resource_generation(),
            policy_version: request.policy_generation(),
            policy_digest: *request.policy_digest(),
            decision_id: None,
            rule: None,
            decision: None,
            reason: None,
            request_digest: Sha256::digest(request_bytes).into(),
            result_digest: None,
            wall_time_ns: now.as_nanos().min(i64::MAX as u128) as i64,
            monotonic_ns: now.as_nanos().min(u64::MAX as u128) as u64,
            stage: WitnessStage::RequestReceived,
            outcome: WitnessOutcome::None,
            recovery_link: None,
            path_class: None,
            device_class: None,
            correlation_digest: None,
        })
    }
}

fn at_stage(template: &WitnessRecord, stage: WitnessStage, salt: u8) -> WitnessRecord {
    let mut record = template.clone();
    record.stage = stage;
    record.event_id[0] ^= salt;
    record
}

fn rule_summary(value: &[u8]) -> RuleSummary {
    RuleSummary::from_id(
        Sha256::digest(value)[..16]
            .try_into()
            .expect("digest length"),
    )
}

fn pinned_image(image: &str) -> Option<(String, String)> {
    let (_, digest) = image.rsplit_once('@')?;
    Some((image.to_owned(), digest.to_owned()))
}

fn lifecycle_state(status: &str) -> Option<ResourceState> {
    match status {
        "created" => Some(ResourceState::Created),
        "running" => Some(ResourceState::Running),
        "paused" => Some(ResourceState::Paused),
        "stopped" | "killed" | "exited" => Some(ResourceState::Stopped),
        _ => None,
    }
}

fn witness_action(action: Action) -> WitnessAction {
    match action {
        Action::ContainerCreate => WitnessAction::ContainerCreate,
        Action::ContainerRun => WitnessAction::ContainerRun,
        Action::ContainerExec => WitnessAction::ContainerExec,
        Action::ContainerPause => WitnessAction::ContainerPause,
        Action::ContainerResume => WitnessAction::ContainerResume,
        Action::ContainerStop => WitnessAction::ContainerStop,
        Action::ContainerKill => WitnessAction::ContainerKill,
        Action::ContainerRestart => WitnessAction::ContainerRestart,
        Action::ContainerDelete => WitnessAction::ContainerDelete,
        _ => unreachable!("runtime authorization only handles container lifecycle"),
    }
}

fn canonical_uuid(id: &str) -> String {
    let compact = id.replace('-', "");
    if compact.len() != 32 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let digest = Sha256::digest(id.as_bytes());
        return uuid_from_raw(&digest[..16]);
    }
    format!(
        "{}-{}-{}-{}-{}",
        &compact[..8],
        &compact[8..12],
        &compact[12..16],
        &compact[16..20],
        &compact[20..]
    )
}

fn uuid_from_bytes(bytes: [u8; 16]) -> String {
    uuid_from_raw(&bytes)
}

fn uuid_from_raw(bytes: &[u8]) -> String {
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn read_boot_id() -> Option<[u8; 16]> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let compact = value.trim().replace('-', "");
    let mut out = [0; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}
