use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use sha2::{Digest, Sha256};

use super::gate::{
    AuthorizationGate, AuthorizedRequest, CanonicalRequest, ExecutionBindings, ImageBinding,
    MountHandleDescriptor,
};
use super::policy::PolicyStore;
use super::{
    Action, MountClass, RequestContext, RequestFacts, RequestOrigin, Resource, ResourceState,
};
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
    #[error("authorization checkpoint is missing, invalid, or stale")]
    CheckpointStale,
}

pub(crate) struct RuntimeAuthorization {
    gate: Arc<AuthorizationGate>,
    journal: Option<Arc<WitnessJournal>>,
    runtime_id: [u8; 16],
    boot_id: [u8; 16],
    pseudonym_key: [u8; 32],
    origin: Option<RequestOrigin>,
    emergency: Option<Arc<super::emergency::EmergencyAuthority>>,
}

#[derive(Clone, Debug)]
pub(crate) struct RunMountFact {
    pub class: MountClass,
    pub mount_id: u64,
    pub device_id: u64,
    pub inode: u64,
    pub open_flags: u64,
    pub target_digest: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RunSecurityFacts {
    pub capabilities: Vec<String>,
    pub mounts: Vec<RunMountFact>,
    pub network_ids: Vec<String>,
    pub privileged: bool,
    pub readonly_rootfs: bool,
    pub no_new_privileges: bool,
    pub mount_sources_approved: Option<bool>,
    /// Digest of the complete normalized execution request, including image,
    /// command, environment, labels, annotations, mounts, limits, and network.
    /// Keeping it in the canonical facts makes the proof bind what will run,
    /// rather than only the container's mutable resource identity.
    pub execution_digest: Option<String>,
    /// Optional parent resource identity (for example a CRI pod sandbox).
    pub parent_resource_id: Option<String>,
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
    pub(crate) fn install_policy_candidate(
        &self,
        candidate: &super::policy::PolicyCandidate,
        rollback_authorized: bool,
    ) -> Result<super::policy::PolicySnapshot, super::policy::PolicyError> {
        self.gate
            .install_policy_candidate(candidate, rollback_authorized)
    }
    pub(crate) fn surface_authorization(
        &self,
    ) -> Result<super::surface::SurfaceAuthorization, super::surface::SurfaceAuthorizationError>
    {
        super::surface::SurfaceAuthorization::from_runtime(
            Arc::clone(&self.gate),
            self.journal.clone(),
            self.runtime_id,
            self.boot_id,
            self.pseudonym_key,
        )
    }
    pub(crate) fn request_origin(&self) -> Option<RequestOrigin> {
        self.origin.clone()
    }
    pub(crate) fn begin_internal_network_recovery(
        &self,
        container_id: &str,
    ) -> Result<Option<OperationId>, MediationError> {
        self.begin_internal_recovery(
            container_id,
            WitnessAction::NetworkAttach,
            WitnessAction::NetworkDetach,
            WitnessResourceKind::Network,
        )
    }

    pub(crate) fn begin_internal_container_recovery(
        &self,
        container_id: &str,
    ) -> Result<Option<OperationId>, MediationError> {
        self.begin_internal_recovery(
            container_id,
            WitnessAction::ContainerRun,
            WitnessAction::ContainerDelete,
            WitnessResourceKind::Container,
        )
    }

    fn begin_internal_recovery(
        &self,
        container_id: &str,
        original_action: WitnessAction,
        cleanup_action: WitnessAction,
        resource_kind: WitnessResourceKind,
    ) -> Result<Option<OperationId>, MediationError> {
        let Some(journal) = &self.journal else {
            return Ok(None);
        };
        let operation = OperationId::from_bytes(rand::rng().random());
        let request_digest: [u8; 32] = Sha256::digest(
            [
                b"ferrocrate/internal-network-recovery/v1".as_slice(),
                container_id.as_bytes(),
            ]
            .concat(),
        )
        .into();
        let resource = ResourceSummary::pseudonymize(
            &self.pseudonym_key,
            canonical_uuid(container_id).as_bytes(),
        )
        .map_err(|_| MediationError::Identity)?;
        let principal =
            PrincipalSummary::pseudonymize(&self.pseudonym_key, b"ferrocrate.internal-recovery")
                .map_err(|_| MediationError::Identity)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let template = WitnessRecord {
            epoch: 1,
            sequence: 0,
            previous_hash: [0; 32],
            event_id: rand::rng().random(),
            request_id: *operation.as_bytes(),
            runtime_instance_id: self.runtime_id,
            boot_id: self.boot_id,
            principal,
            invocation: Invocation::InternalCleanup,
            action: original_action,
            resource_kind,
            resource,
            resource_generation: 1,
            policy_version: 0,
            policy_digest: [0; 32],
            decision_id: None,
            rule: None,
            decision: None,
            reason: None,
            request_digest,
            result_digest: None,
            wall_time_ns: now.as_nanos().min(i64::MAX as u128) as i64,
            monotonic_ns: now.as_nanos().min(u64::MAX as u128) as u64,
            stage: WitnessStage::RequestReceived,
            outcome: WitnessOutcome::None,
            recovery_link: None,
            path_class: None,
            device_class: None,
            correlation_digest: None,
        };
        let recipe = RecoveryRecipe::for_original(
            original_action,
            resource_kind,
            cleanup_action,
            request_digest,
            1,
        )
        .map_err(|_| MediationError::Identity)?;
        journal.append_received(
            operation,
            1,
            recipe,
            at_stage(&template, WitnessStage::RequestReceived, 1),
        )?;
        let cleanup_authorization_action = match cleanup_action {
            WitnessAction::ContainerDelete => Action::ContainerDelete,
            WitnessAction::NetworkDetach => Action::NetworkDetach,
            WitnessAction::VolumeUnmount => Action::VolumeUnmount,
            _ => return Err(MediationError::Identity),
        };
        let canonical_resource = canonical_uuid(container_id);
        let authority = super::admission::ReservedCleanupAuthority::from_recovery_path(
            operation,
            canonical_resource.clone(),
            1,
            self.runtime_id,
            journal.journal_id(),
            self.boot_id,
            cleanup_authorization_action,
        );
        self.gate
            .admit_reserved_cleanup(
                cleanup_authorization_action,
                &authority,
                operation,
                &canonical_resource,
                1,
                self.runtime_id,
                journal.journal_id(),
                self.boot_id,
            )
            .map_err(|_| MediationError::CheckpointStale)?;
        let mut decision = at_stage(&template, WitnessStage::Decision, 2);
        decision.decision = Some(true);
        decision.decision_id = Some(rand::rng().random());
        decision.rule = Some(rule_summary(b"internal.recovery.owned-intent"));
        let _ = journal.append_decision(operation, decision)?;
        Ok(Some(operation))
    }

    pub(crate) fn finish_internal_recovery(
        &self,
        operation: Option<OperationId>,
        observation: ObservationDigest,
        recovered: bool,
    ) -> Result<(), MediationError> {
        if let (Some(journal), Some(operation)) = (&self.journal, operation) {
            let pending = journal.recover(operation)?;
            journal.reconcile_observed(crate::witness::RecoveryEvidence::verified(
                &pending,
                observation,
                recovered,
            ))?;
        }
        Ok(())
    }

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
            origin: None,
            emergency: None,
        }
    }

    pub(crate) fn with_origin(&self, origin: RequestOrigin) -> Self {
        Self {
            gate: Arc::clone(&self.gate),
            journal: self.journal.clone(),
            runtime_id: self.runtime_id,
            boot_id: self.boot_id,
            pseudonym_key: self.pseudonym_key,
            origin: Some(origin),
            emergency: self.emergency.clone(),
        }
    }

    pub(crate) fn with_emergency_authority(
        &self,
        authority: super::emergency::EmergencyAuthority,
    ) -> Self {
        Self {
            gate: Arc::clone(&self.gate),
            journal: self.journal.clone(),
            runtime_id: self.runtime_id,
            boot_id: self.boot_id,
            pseudonym_key: self.pseudonym_key,
            origin: self.origin.clone(),
            emergency: Some(Arc::new(authority)),
        }
    }

    pub(crate) fn requires_provenance(&self) -> bool {
        self.journal
            .as_ref()
            .is_some_and(|journal| journal.mode() == crate::witness::JournalMode::Required)
    }

    pub(crate) fn authorization_mode(&self) -> crate::authorization::AuthorizationMode {
        self.gate.mode()
    }

    pub(crate) fn policy_binding(&self) -> (u64, [u8; 32]) {
        let pin = self.gate.pin();
        (pin.generation(), pin.digest_bytes())
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

    pub(crate) fn provenance_value_matches(
        &self,
        provenance: &crate::container_store::CreationProvenance,
        container_id: &str,
    ) -> bool {
        provenance.is_verifiable()
            && provenance.runtime_instance_id == Some(self.runtime_id)
            && provenance.boot_id == Some(self.boot_id)
            && provenance.resource_uuid.as_deref() == Some(canonical_uuid(container_id).as_str())
            && provenance.resource_generation > 0
            && provenance.journal_id == self.journal.as_ref().map(|journal| journal.journal_id())
    }

    /// Legacy cleanup deliberately ignores the journal identifier, because old
    /// unwitnessed ledgers predate it. Runtime, boot, resource, and generation
    /// bindings remain mandatory.
    pub(crate) fn legacy_provenance_matches(
        &self,
        provenance: &crate::container_store::CreationProvenance,
        container_id: &str,
    ) -> bool {
        provenance.is_verifiable()
            && provenance.runtime_instance_id == Some(self.runtime_id)
            && provenance.boot_id == Some(self.boot_id)
            && provenance.resource_uuid.as_deref() == Some(canonical_uuid(container_id).as_str())
            && provenance.resource_generation > 0
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
        if !(self.emergency.is_some()
            && matches!(
                action,
                Action::ContainerStop | Action::ContainerKill | Action::ContainerDelete
            ))
        {
            self.gate
                .admit(action)
                .map_err(|_| MediationError::CheckpointStale)?;
        }
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
        let pinned_policy_digest = pin.digest_bytes();
        let origin = self.origin.as_ref();
        let operation = OperationId::from_bytes(
            origin
                .and_then(RequestOrigin::request_id)
                .unwrap_or_else(|| rand::rng().random()),
        );
        if origin.is_some_and(|origin| origin.revalidate_transport().is_err()) {
            return Err(MediationError::Identity);
        }
        if origin.is_some_and(|origin| !origin.fanout_integrity_valid()) {
            return Err(MediationError::Identity);
        }
        if let Some(fanout) = origin.and_then(RequestOrigin::fanout) {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u64::MAX as u128) as u64;
            if fanout.expected_action != action
                || record.name.as_deref() != Some(fanout.expected_resource.as_str())
                || now_ms > fanout.deadline_unix_ms
                || fanout.policy_generation != pin.generation()
                || fanout.policy_digest != pin.digest_bytes()
            {
                return Err(MediationError::Stale);
            }
            if matches!(action, Action::ContainerStop | Action::ContainerDelete)
                && !origin.is_some_and(|origin| {
                    origin.fanout_request_digest_matches(&super::compose_down_executor_digest(
                        record, action,
                    ))
                })
            {
                return Err(MediationError::Stale);
            }
        }
        let request_id = uuid_from_bytes(
            origin
                .and_then(RequestOrigin::request_id)
                .unwrap_or(*operation.as_bytes()),
        );
        let run = run.cloned().unwrap_or_default();
        let mount_handles = run
            .mounts
            .iter()
            .map(|mount| {
                MountHandleDescriptor::new_with_target(
                    mount.class,
                    mount.mount_id,
                    mount.device_id,
                    mount.inode,
                    mount.open_flags,
                    mount.target_digest,
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
            mount_sources_approved: run.mount_sources_approved,
            execution_digest: run.execution_digest,
            parent_resource_id: run.parent_resource_id,
            ..Default::default()
        };
        let resource = Resource::canonical(
            super::ResourceKind::Container,
            resource_uuid.clone(),
            None,
            generation,
        );
        let mut context = RequestContext::resolved(
            request_id,
            origin.map(|origin| origin.principal().clone()),
            action,
            resource,
            facts,
        );
        context.attach_fanout(origin.and_then(RequestOrigin::fanout).cloned());
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

        let emergency_override = self.gate.policy_would_deny(&request).unwrap_or(false)
            && self.emergency.as_ref().is_some_and(|authority| {
                origin.is_some_and(|origin| {
                    authority
                        .consume(
                            action,
                            &record.id,
                            generation,
                            origin.principal(),
                            pinned_policy_digest,
                            *operation.as_bytes(),
                        )
                        .is_ok()
                })
            });
        let authorization = if emergency_override {
            self.gate.authorize_emergency(request)
        } else {
            self.gate.authorize(request)
        };
        match authorization {
            Ok(proof) => {
                let mut decision_id = None;
                let intent = if let Some(journal) = &self.journal {
                    let mut decision = at_stage(&template, WitnessStage::Decision, 2);
                    decision.decision = Some(true);
                    let id = rand::rng().random();
                    decision.decision_id = Some(id);
                    decision_id = Some(id);
                    decision.rule = Some(rule_summary(proof.decision().matched_rule.as_bytes()));
                    if proof.decision().reason == super::ReasonCode::EmergencyOverride {
                        decision.reason = Some(ReasonCode::EmergencyOverride);
                    }
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

    pub(crate) fn complete_unknown(&self, permit: MutationPermit) -> Result<(), MediationError> {
        if let (Some(journal), Some(intent)) = (&self.journal, permit.intent) {
            let mut outcome = at_stage(&permit.template, WitnessStage::Outcome, 4);
            outcome.decision_id = permit.decision_id;
            outcome.outcome = WitnessOutcome::OutcomeUnknown;
            outcome.reason = Some(ReasonCode::ExecutionFailed);
            outcome.result_digest = Some(Sha256::digest(b"post-effect-persistence-unknown").into());
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
        let principal_bytes = self
            .origin
            .as_ref()
            .map_or(b"local-unresolved".as_slice(), |origin| {
                origin.principal().id().as_str().as_bytes()
            });
        let principal = PrincipalSummary::pseudonymize(&self.pseudonym_key, principal_bytes)
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
            invocation: self
                .origin
                .as_ref()
                .map_or(Invocation::Cli, RequestOrigin::invocation),
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod recovery_tests {
    use super::*;
    use crate::authorization::policy::PolicyStore;
    use crate::witness::{JournalConfig, JournalMode};

    #[test]
    fn internal_network_recovery_binds_attach_intent_to_network_detach_receipt() {
        let root = tempfile::tempdir().unwrap();
        let journal = Arc::new(
            WitnessJournal::open(JournalConfig::new(
                root.path(),
                [71; 16],
                JournalMode::Required,
            ))
            .unwrap(),
        );
        let gate = Arc::new(AuthorizationGate::new(Arc::new(
            PolicyStore::compatibility_disabled(),
        )));
        let authorization =
            RuntimeAuthorization::new_with_id(gate, Some(journal.clone()), [72; 16]);
        let operation = authorization
            .begin_internal_network_recovery("00112233445566778899aabbccddeeff")
            .unwrap()
            .unwrap();
        let pending = journal.recover(operation).unwrap();
        assert_eq!(
            pending.recipe().original_action(),
            WitnessAction::NetworkAttach
        );
        assert_eq!(pending.recipe().action(), WitnessAction::NetworkDetach);
        assert_eq!(
            pending.recipe().resource_kind(),
            WitnessResourceKind::Network
        );
        assert_eq!(journal.records().unwrap().len(), 2);
    }

    #[test]
    fn missing_or_stale_checkpoint_denies_user_cleanup_without_reserved_authority() {
        let root = tempfile::tempdir().unwrap();
        let gate = Arc::new(AuthorizationGate::with_admission(
            Arc::new(PolicyStore::compatibility_disabled()),
            crate::authorization::admission::MutationAdmission::checkpoint(
                root.path().join("missing-checkpoint.bin"),
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(5),
            ),
        ));

        assert!(gate.admit(Action::ContainerRun).is_err());
        assert!(gate.admit(Action::ContainerDelete).is_err());
        assert!(gate.admit(Action::ContainerStop).is_err());
        let operation = crate::witness::OperationId::from_bytes([1; 16]);
        let authority =
            crate::authorization::admission::ReservedCleanupAuthority::from_recovery_path(
                operation,
                "resource".into(),
                1,
                [2; 16],
                [3; 16],
                [4; 16],
                Action::ContainerDelete,
            );
        assert!(gate
            .admit_reserved_cleanup(
                Action::ContainerDelete,
                &authority,
                operation,
                "resource",
                1,
                [2; 16],
                [3; 16],
                [4; 16]
            )
            .is_ok());
        assert!(gate
            .admit_reserved_cleanup(
                Action::ContainerDelete,
                &authority,
                operation,
                "other",
                1,
                [2; 16],
                [3; 16],
                [4; 16]
            )
            .is_err());
        assert!(gate
            .admit_reserved_cleanup(
                Action::ContainerDelete,
                &authority,
                operation,
                "resource",
                2,
                [2; 16],
                [3; 16],
                [4; 16]
            )
            .is_err());
        assert!(gate
            .admit_reserved_cleanup(
                Action::ContainerDelete,
                &authority,
                operation,
                "resource",
                1,
                [9; 16],
                [3; 16],
                [4; 16]
            )
            .is_err());
        assert!(gate
            .admit_reserved_cleanup(
                Action::ContainerDelete,
                &authority,
                operation,
                "resource",
                1,
                [2; 16],
                [9; 16],
                [4; 16]
            )
            .is_err());
        assert!(gate
            .admit_reserved_cleanup(
                Action::ContainerDelete,
                &authority,
                operation,
                "resource",
                1,
                [2; 16],
                [3; 16],
                [9; 16]
            )
            .is_err());
        assert!(gate
            .admit_reserved_cleanup(
                Action::NetworkDetach,
                &authority,
                operation,
                "resource",
                1,
                [2; 16],
                [3; 16],
                [4; 16]
            )
            .is_err());
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
        Action::ContainerStart => WitnessAction::ContainerStart,
        Action::ContainerDelete => WitnessAction::ContainerDelete,
        Action::ContainerRename => WitnessAction::ContainerRename,
        Action::ContainerArchiveWrite => WitnessAction::ContainerArchiveWrite,
        Action::ContainerUpdate => WitnessAction::ContainerUpdate,
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

#[cfg(feature = "test-support")]
pub mod test_support {
    use super::{RunSecurityFacts, RuntimeAuthorization};
    use crate::{
        authorization::{
            gate::{AuthorizationGate, AuthorizedRequest},
            Action, RequestOrigin,
        },
        container_store::ContainerRecord,
        witness::{DurableIntent, WitnessJournal},
    };
    use std::sync::Arc;

    pub struct ManagedOverlayAuthority {
        proof: AuthorizedRequest,
        intent: DurableIntent,
    }

    impl ManagedOverlayAuthority {
        pub fn parts(&self) -> (&AuthorizedRequest, &DurableIntent) {
            (&self.proof, &self.intent)
        }
    }

    pub fn authorize_attach(
        gate: Arc<AuthorizationGate>,
        journal: Arc<WitnessJournal>,
        container_id: &str,
        resource_generation: u64,
        overlay_id: &str,
    ) -> Result<ManagedOverlayAuthority, String> {
        authorize(
            gate,
            journal,
            container_id,
            resource_generation,
            Some(overlay_id),
            Action::ContainerRun,
        )
    }

    pub fn authorize_cleanup(
        gate: Arc<AuthorizationGate>,
        journal: Arc<WitnessJournal>,
        container_id: &str,
        resource_generation: u64,
    ) -> Result<ManagedOverlayAuthority, String> {
        authorize(
            gate,
            journal,
            container_id,
            resource_generation,
            None,
            Action::ContainerDelete,
        )
    }

    fn authorize(
        gate: Arc<AuthorizationGate>,
        journal: Arc<WitnessJournal>,
        container_id: &str,
        resource_generation: u64,
        overlay_id: Option<&str>,
        action: Action,
    ) -> Result<ManagedOverlayAuthority, String> {
        let mut record = ContainerRecord::authorization_candidate(
            container_id.into(),
            "test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        );
        record.status = "stopped".into();
        record.mutation_generation = resource_generation;
        let runtime = RuntimeAuthorization::new_with_id(gate, Some(journal), [91; 16]).with_origin(
            RequestOrigin::cli_current()
                .map_err(|error| format!("fixture CLI identity unavailable: {error}"))?,
        );
        let permit = if let Some(overlay_id) = overlay_id {
            runtime.authorize_run(
                &record,
                &RunSecurityFacts {
                    network_ids: vec![overlay_id.into()],
                    ..Default::default()
                },
            )
        } else {
            runtime.authorize(action, &record)
        }
        .map_err(|error| error.to_string())?;
        Ok(ManagedOverlayAuthority {
            proof: permit.proof,
            intent: permit
                .intent
                .ok_or_else(|| "durable intent missing".to_string())?,
        })
    }
}
