//! Complete-mediation adapter for non-container entry-point mutations.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use sha2::{Digest, Sha256};

use super::gate::{
    AuthorizationGate, AuthorizedRequest, CanonicalRequest, Denial, ExecutionBindings,
};
#[cfg(test)]
use super::policy::PolicyStore;
use super::{
    Action, AuthorizationMode, RequestContext, RequestFacts, RequestOrigin, Resource, ResourceKind,
};
use crate::witness::{
    DurableIntent, ObservationDigest, ObservationHandle, OperationId, PendingOperation,
    PrincipalSummary, ReasonCode, RecoveryRecipe, RecoveryTruthStrategy, ResourceSummary,
    RuleSummary, WitnessAction, WitnessJournal, WitnessOutcome, WitnessRecord, WitnessResourceKind,
    WitnessStage,
};

#[derive(Debug, thiserror::Error)]
pub enum SurfaceAuthorizationError {
    #[error(transparent)]
    Admission(#[from] super::admission::MutationAdmissionError),
    #[error("request transport identity is stale: {0}")]
    StaleIdentity(#[from] super::PrincipalResolutionError),
    #[error(transparent)]
    Denied(#[from] Denial),
    #[error("witness journal failed: {0}")]
    Journal(#[from] crate::witness::JournalError),
    #[error("surface authorization binding is invalid")]
    InvalidBinding,
    #[error("enabled surface authorization requires the shared required witness journal")]
    JournalRequired,
    #[error("disabled surface authorization cannot be paired with a required witness journal")]
    UnexpectedJournal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SurfaceExecutionError {
    #[error("authorization permit action does not match executor")]
    ActionMismatch,
    #[error("authorization permit resource does not match executor")]
    ResourceMismatch,
    #[error("authorization permit generation does not match executor")]
    GenerationMismatch,
}

#[derive(Clone)]
pub struct SurfaceAuthorization {
    gate: Arc<AuthorizationGate>,
    durability: SurfaceDurability,
    runtime_id: [u8; 16],
    boot_id: [u8; 16],
    pseudonym_key: [u8; 32],
}

#[derive(Clone)]
enum SurfaceDurability {
    Disabled,
    Required(Arc<WitnessJournal>),
}

/// Single-use authority for exactly one canonical non-container mutation.
///
/// The durable intent is deliberately owned rather than cloneable. Executors
/// consume this value, preventing an allowed decision from authorizing a
/// second mutation.
pub struct SurfacePermit {
    proof: AuthorizedRequest,
    durability: SurfacePermitDurability,
    operation: OperationId,
    decision_id: Option<[u8; 16]>,
    template: WitnessRecord,
}

/// Crate-internal capability proving a raw surface helper is nested beneath a
/// live, non-clonable permit. Its field and constructor are private.
///
/// ```compile_fail
/// use ferro_core::authorization::surface::SurfaceMutationAuthority;
/// let _ = SurfaceMutationAuthority::default();
/// ```
pub(crate) struct SurfaceMutationAuthority<'a> {
    _permit: std::marker::PhantomData<&'a mut SurfacePermit>,
}

impl SurfacePermit {
    pub(crate) fn mutation_authority(&self) -> SurfaceMutationAuthority<'_> {
        SurfaceMutationAuthority {
            _permit: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
impl SurfaceMutationAuthority<'static> {
    pub(crate) fn for_test() -> Self {
        Self {
            _permit: std::marker::PhantomData,
        }
    }
}

enum SurfacePermitDurability {
    Disabled,
    Required {
        intent: Box<DurableIntent>,
        journal: Arc<WitnessJournal>,
    },
}

impl SurfacePermit {
    /// ```compile_fail
    /// use ferro_core::authorization::surface::SurfacePermit;
    /// fn duplicate(permit: SurfacePermit) { let _ = permit.clone(); }
    /// ```
    pub fn proof(&self) -> &AuthorizedRequest {
        &self.proof
    }

    pub fn durable_intent(&self) -> Option<&DurableIntent> {
        match &self.durability {
            SurfacePermitDurability::Disabled => None,
            SurfacePermitDurability::Required { intent, .. } => Some(intent.as_ref()),
        }
    }

    pub fn operation_id(&self) -> OperationId {
        self.operation
    }

    pub fn finish(self, succeeded: bool) -> Result<(), SurfaceAuthorizationError> {
        complete_permit(
            self,
            if succeeded {
                WitnessOutcome::Succeeded
            } else {
                WitnessOutcome::Failed
            },
        )
    }

    pub fn finish_unknown(self) -> Result<(), SurfaceAuthorizationError> {
        complete_permit(self, WitnessOutcome::OutcomeUnknown)
    }
}

impl SurfaceAuthorization {
    /// Construct the local administrative surface around an already-open
    /// required journal. This keeps authorization intent/outcome and the
    /// administrative mutation on one writer without reopening its lock.
    pub fn local_administrative(
        gate: Arc<AuthorizationGate>,
        journal: Arc<WitnessJournal>,
        runtime_id: [u8; 16],
    ) -> Self {
        let mut rng = rand::rng();
        Self {
            gate,
            durability: SurfaceDurability::Required(journal),
            runtime_id,
            boot_id: read_boot_id().unwrap_or_else(|| rng.random()),
            pseudonym_key: rng.random(),
        }
    }

    #[cfg(test)]
    pub(crate) fn compatibility() -> Self {
        let mut rng = rand::rng();
        Self {
            gate: Arc::new(AuthorizationGate::new(Arc::new(
                PolicyStore::compatibility_disabled(),
            ))),
            durability: SurfaceDurability::Disabled,
            runtime_id: rng.random(),
            boot_id: read_boot_id().unwrap_or_else(|| rng.random()),
            pseudonym_key: rng.random(),
        }
    }

    #[cfg(test)]
    fn with_journal(
        gate: Arc<AuthorizationGate>,
        journal: Arc<WitnessJournal>,
        runtime_id: [u8; 16],
    ) -> Self {
        let mut rng = rand::rng();
        Self {
            gate,
            durability: SurfaceDurability::Required(journal),
            runtime_id,
            boot_id: read_boot_id().unwrap_or_else(|| rng.random()),
            pseudonym_key: rng.random(),
        }
    }

    pub(crate) fn from_runtime(
        gate: Arc<AuthorizationGate>,
        journal: Option<Arc<WitnessJournal>>,
        runtime_id: [u8; 16],
        boot_id: [u8; 16],
        pseudonym_key: [u8; 32],
    ) -> Result<Self, SurfaceAuthorizationError> {
        let durability = match (gate.mode(), journal) {
            (AuthorizationMode::Disabled, None) => SurfaceDurability::Disabled,
            (AuthorizationMode::Disabled, Some(_)) => {
                return Err(SurfaceAuthorizationError::UnexpectedJournal)
            }
            (AuthorizationMode::Shadow | AuthorizationMode::Enforce, Some(journal))
                if journal.mode() == crate::witness::JournalMode::Required =>
            {
                SurfaceDurability::Required(journal)
            }
            (AuthorizationMode::Shadow | AuthorizationMode::Enforce, _) => {
                return Err(SurfaceAuthorizationError::JournalRequired)
            }
        };
        Ok(Self {
            gate,
            durability,
            runtime_id,
            boot_id,
            pseudonym_key,
        })
    }

    pub fn authorize_image_binding(
        &self,
        origin: &RequestOrigin,
        action: Action,
        canonical_name: &str,
        digest: &str,
        generation: u64,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        debug_assert!(matches!(action, Action::ImagePull | Action::ImageDelete));
        let resource_id = stable_resource_id(ResourceKind::Image, canonical_name);
        let pinned_reference = format!("{canonical_name}@{digest}");
        let resource =
            Resource::canonical(ResourceKind::Image, resource_id.clone(), None, generation);
        let facts = RequestFacts {
            image_digest: Some(digest.to_owned()),
            ..RequestFacts::default()
        };
        let context = RequestContext::resolved(
            request_id(&resource_id, action),
            Some(origin.principal().clone()),
            action,
            resource,
            facts,
        );
        let binding = super::gate::ImageBinding::new(pinned_reference, digest);
        let bindings = ExecutionBindings::new(Some(binding), generation, None, None, Vec::new());
        let request = CanonicalRequest::new(context, self.gate.pin(), bindings.clone(), bindings);
        self.authorize(origin, request, action, ResourceKind::Image)
    }

    pub fn authorize_image_fetch_plan(
        &self,
        origin: &RequestOrigin,
        plan: &crate::image_fetch::ImageFetchPlan,
        generation: u64,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        let canonical_name = plan.canonical_reference();
        let policy = self.gate.pin();
        validate_fanout_origin(
            origin,
            Action::ImagePull,
            canonical_name,
            plan.plan_digest(),
            policy.generation(),
            policy.digest_bytes(),
        )?;
        let resource_id = stable_resource_id(ResourceKind::Image, canonical_name);
        let resource =
            Resource::canonical(ResourceKind::Image, resource_id.clone(), None, generation);
        let facts = RequestFacts {
            image_digest: Some(plan.manifest_digest().to_owned()),
            ..RequestFacts::default()
        };
        let context = RequestContext::resolved(
            origin_request_id(origin, &resource_id, Action::ImagePull),
            Some(origin.principal().clone()),
            Action::ImagePull,
            resource,
            facts,
        );
        let binding = super::gate::ImageBinding::new_plan(
            plan.immutable_reference(),
            plan.manifest_digest(),
            plan.plan_digest(),
        );
        let bindings = ExecutionBindings::new(Some(binding), generation, None, None, Vec::new());
        let request = CanonicalRequest::new(context, policy, bindings.clone(), bindings);
        self.authorize(origin, request, Action::ImagePull, ResourceKind::Image)
    }

    pub fn authorize_named(
        &self,
        origin: &RequestOrigin,
        action: Action,
        kind: ResourceKind,
        canonical_name: &str,
        generation: u64,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        let resource_id = stable_resource_id(kind, canonical_name);
        let resource = Resource::canonical(kind, resource_id.clone(), None, generation);
        let context = RequestContext::resolved(
            request_id(&resource_id, action),
            Some(origin.principal().clone()),
            action,
            resource,
            RequestFacts::default(),
        );
        let bindings = ExecutionBindings::new(None, generation, None, None, Vec::new());
        let request = CanonicalRequest::new(context, self.gate.pin(), bindings.clone(), bindings);
        self.authorize(origin, request, action, kind)
    }

    pub fn authorize_volume_create_plan(
        &self,
        origin: &RequestOrigin,
        plan: &crate::volume_store::VolumeCreatePlan,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        let policy = self.gate.pin();
        validate_fanout_origin(
            origin,
            Action::VolumeCreate,
            plan.name(),
            plan.plan_digest(),
            policy.generation(),
            policy.digest_bytes(),
        )?;
        let resource_id = stable_resource_id(ResourceKind::Volume, plan.name());
        let resource = Resource::canonical(
            ResourceKind::Volume,
            resource_id.clone(),
            None,
            plan.generation(),
        );
        let context = RequestContext::resolved(
            origin_request_id(origin, &resource_id, Action::VolumeCreate),
            Some(origin.principal().clone()),
            Action::VolumeCreate,
            resource,
            RequestFacts::default(),
        );
        let bindings = ExecutionBindings::new(None, plan.generation(), None, None, Vec::new())
            .with_operation_plan_digest(plan.plan_digest());
        let request = CanonicalRequest::new(context, policy, bindings.clone(), bindings);
        self.authorize(origin, request, Action::VolumeCreate, ResourceKind::Volume)
    }

    pub fn authorize_image_build_plan(
        &self,
        origin: &RequestOrigin,
        plan: &crate::dockerfile_build::ImageBuildPlan,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        let policy = self.gate.pin();
        validate_fanout_origin(
            origin,
            Action::ImageBuild,
            plan.canonical_tag(),
            plan.plan_digest(),
            policy.generation(),
            policy.digest_bytes(),
        )?;
        let resource_id = stable_resource_id(ResourceKind::Image, plan.canonical_tag());
        let resource = Resource::canonical(
            ResourceKind::Image,
            resource_id.clone(),
            None,
            plan.generation(),
        );
        let context = RequestContext::resolved(
            origin_request_id(origin, &resource_id, Action::ImageBuild),
            Some(origin.principal().clone()),
            Action::ImageBuild,
            resource,
            RequestFacts::default(),
        );
        let bindings = ExecutionBindings::new(None, plan.generation(), None, None, Vec::new())
            .with_operation_plan_digest(plan.plan_digest());
        let request = CanonicalRequest::new(context, policy, bindings.clone(), bindings);
        self.authorize(origin, request, Action::ImageBuild, ResourceKind::Image)
    }

    pub fn authorize_image_tag_plan(
        &self,
        origin: &RequestOrigin,
        plan: &crate::image_tagging::ImageTagPlan,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        let policy = self.gate.pin();
        validate_fanout_origin(
            origin,
            Action::ImageTag,
            plan.target_reference(),
            plan.plan_digest(),
            policy.generation(),
            policy.digest_bytes(),
        )?;
        let resource_id = stable_resource_id(ResourceKind::Image, plan.target_reference());
        let resource = Resource::canonical(
            ResourceKind::Image,
            resource_id.clone(),
            None,
            plan.generation(),
        );
        let context = RequestContext::resolved(
            origin_request_id(origin, &resource_id, Action::ImageTag),
            Some(origin.principal().clone()),
            Action::ImageTag,
            resource,
            RequestFacts::default(),
        );
        let bindings = ExecutionBindings::new(None, plan.generation(), None, None, Vec::new())
            .with_operation_plan_digest(plan.plan_digest());
        let request = CanonicalRequest::new(context, policy, bindings.clone(), bindings);
        self.authorize(origin, request, Action::ImageTag, ResourceKind::Image)
    }

    pub fn authorize_image_reference_write_plan(
        &self,
        origin: &RequestOrigin,
        plan: &crate::image_store::ImageReferenceWritePlan,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        origin.revalidate_transport()?;
        let policy = self.gate.pin();
        validate_fanout_origin(
            origin,
            Action::ImageReferenceWrite,
            plan.canonical_reference(),
            plan.plan_digest(),
            policy.generation(),
            policy.digest_bytes(),
        )?;
        let resource_id = stable_resource_id(ResourceKind::Image, plan.canonical_reference());
        let resource = Resource::canonical(
            ResourceKind::Image,
            resource_id.clone(),
            None,
            plan.generation(),
        );
        let context = RequestContext::resolved(
            origin_request_id(origin, &resource_id, Action::ImageReferenceWrite),
            Some(origin.principal().clone()),
            Action::ImageReferenceWrite,
            resource,
            RequestFacts::default(),
        );
        let bindings = ExecutionBindings::new(None, plan.generation(), None, None, Vec::new())
            .with_operation_plan_digest(plan.plan_digest());
        let request = CanonicalRequest::new(context, policy, bindings.clone(), bindings);
        self.authorize(
            origin,
            request,
            Action::ImageReferenceWrite,
            ResourceKind::Image,
        )
    }

    pub fn validate_execution(
        permit: &SurfacePermit,
        action: Action,
        kind: ResourceKind,
        canonical_name: &str,
        generation: u64,
    ) -> Result<(), SurfaceExecutionError> {
        validate_execution_with_comparator(
            permit,
            action,
            kind,
            canonical_name,
            generation,
            std::convert::identity,
        )
    }

    fn authorize(
        &self,
        origin: &RequestOrigin,
        request: CanonicalRequest,
        action: Action,
        kind: ResourceKind,
    ) -> Result<SurfacePermit, SurfaceAuthorizationError> {
        self.gate.admit(action)?;
        let operation = OperationId::from_bytes(rand::rng().random());
        let template = self.record_template(origin, &request, operation, action, kind)?;
        if let Some(journal) = self.journal() {
            let witness_action = witness_action(action)?;
            let witness_kind = witness_kind(kind)?;
            let recipe = RecoveryRecipe::for_original_with_observation(
                witness_action,
                witness_kind,
                recovery_action(witness_action),
                template.request_digest,
                request.resource_generation(),
                RecoveryTruthStrategy::InversePrecondition,
                ObservationDigest::from_bytes(surface_observation_digest(
                    action,
                    kind,
                    request.resource_id(),
                    request.resource_generation(),
                )),
                ObservationHandle::from_bytes(surface_observation_handle(
                    kind,
                    request.resource_id(),
                )),
            )
            .map_err(|_| SurfaceAuthorizationError::InvalidBinding)?;
            journal.append_received(
                operation,
                request.resource_generation(),
                recipe,
                at_stage(&template, WitnessStage::RequestReceived, 1),
            )?;
        }
        match self.gate.authorize(request) {
            Ok(proof) => {
                let mut decision_id = None;
                let durability = if let Some(journal) = self.journal() {
                    let id = rand::rng().random();
                    decision_id = Some(id);
                    let mut decision = at_stage(&template, WitnessStage::Decision, 2);
                    decision.decision = Some(true);
                    decision.decision_id = Some(id);
                    decision.rule = Some(rule_summary(proof.decision().matched_rule.as_bytes()));
                    SurfacePermitDurability::Required {
                        intent: Box::new(journal.append_decision(operation, decision)?),
                        journal: Arc::clone(journal),
                    }
                } else {
                    SurfacePermitDurability::Disabled
                };
                Ok(SurfacePermit {
                    proof,
                    durability,
                    operation,
                    decision_id,
                    template,
                })
            }
            Err(denial) => {
                if let Some(journal) = self.journal() {
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
                Err(SurfaceAuthorizationError::Denied(denial))
            }
        }
    }

    pub fn complete(
        &self,
        permit: SurfacePermit,
        succeeded: bool,
    ) -> Result<(), SurfaceAuthorizationError> {
        complete_permit(
            permit,
            if succeeded {
                WitnessOutcome::Succeeded
            } else {
                WitnessOutcome::Failed
            },
        )
    }

    pub fn complete_unknown(&self, permit: SurfacePermit) -> Result<(), SurfaceAuthorizationError> {
        complete_permit(permit, WitnessOutcome::OutcomeUnknown)
    }

    /// Reconcile journal-pending surface mutations from action-specific live
    /// state. The observer can inspect the closed recipe but has no authority
    /// to replay the original operation.
    pub fn reconcile_pending(
        &self,
        mut observe: impl FnMut(&PendingOperation) -> (ObservationDigest, bool),
    ) -> Result<usize, SurfaceAuthorizationError> {
        let Some(journal) = self.journal() else {
            return Ok(0);
        };
        let pending = journal.pending()?;
        let count = pending.len();
        for operation in pending {
            let (digest, recovered) = observe(&operation);
            journal.reconcile_observed(crate::witness::RecoveryEvidence::verified(
                &operation, digest, recovered,
            ))?;
        }
        Ok(count)
    }

    fn journal(&self) -> Option<&Arc<WitnessJournal>> {
        match &self.durability {
            SurfaceDurability::Disabled => None,
            SurfaceDurability::Required(journal) => Some(journal),
        }
    }

    fn record_template(
        &self,
        origin: &RequestOrigin,
        request: &CanonicalRequest,
        operation: OperationId,
        action: Action,
        kind: ResourceKind,
    ) -> Result<WitnessRecord, SurfaceAuthorizationError> {
        let request_bytes = serde_json::to_vec(request.context())
            .map_err(|_| SurfaceAuthorizationError::InvalidBinding)?;
        let resource =
            ResourceSummary::pseudonymize(&self.pseudonym_key, request.resource_id().as_bytes())
                .map_err(|_| SurfaceAuthorizationError::InvalidBinding)?;
        let principal = PrincipalSummary::pseudonymize(
            &self.pseudonym_key,
            origin.principal().id().as_str().as_bytes(),
        )
        .map_err(|_| SurfaceAuthorizationError::InvalidBinding)?;
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
            invocation: origin.invocation(),
            action: witness_action(action)?,
            resource_kind: witness_kind(kind)?,
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

fn validate_execution_with_comparator<F>(
    permit: &SurfacePermit,
    action: Action,
    kind: ResourceKind,
    canonical_name: &str,
    generation: u64,
    comparator: F,
) -> Result<(), SurfaceExecutionError>
where
    F: FnOnce(Result<(), SurfaceExecutionError>) -> Result<(), SurfaceExecutionError>,
{
    validate_execution_with_comparator_with_metrics(
        permit,
        action,
        kind,
        canonical_name,
        generation,
        comparator,
        crate::observability::authorization_metrics(),
    )
}

fn validate_execution_with_comparator_with_metrics<F>(
    permit: &SurfacePermit,
    action: Action,
    kind: ResourceKind,
    canonical_name: &str,
    generation: u64,
    comparator: F,
    metrics: &crate::observability::AuthorizationMetrics,
) -> Result<(), SurfaceExecutionError>
where
    F: FnOnce(Result<(), SurfaceExecutionError>) -> Result<(), SurfaceExecutionError>,
{
    let proof = permit.proof();
    let expected_mismatch = proof.canonical().context().action() != action
        || proof.canonical().context().resource().kind() != kind
        || proof.canonical().resource_id() != stable_resource_id(kind, canonical_name)
        || proof.canonical().resource_generation() != generation;
    let actual = if proof.canonical().context().action() != action {
        Err(SurfaceExecutionError::ActionMismatch)
    } else if proof.canonical().context().resource().kind() != kind
        || proof.canonical().resource_id() != stable_resource_id(kind, canonical_name)
    {
        Err(SurfaceExecutionError::ResourceMismatch)
    } else if proof.canonical().resource_generation() != generation {
        Err(SurfaceExecutionError::GenerationMismatch)
    } else {
        Ok(())
    };
    let result = comparator(actual);
    if expected_mismatch {
        metrics.record_bypass_probe(result.is_err());
    }
    result
}

fn complete_permit(
    permit: SurfacePermit,
    outcome: WitnessOutcome,
) -> Result<(), SurfaceAuthorizationError> {
    match permit.durability {
        SurfacePermitDurability::Disabled => {}
        SurfacePermitDurability::Required { intent, journal } => {
            let mut record = at_stage(&permit.template, WitnessStage::Outcome, 4);
            record.decision_id = permit.decision_id;
            record.outcome = outcome;
            record.result_digest = Some(Sha256::digest([outcome as u8]).into());
            if matches!(
                outcome,
                WitnessOutcome::Failed | WitnessOutcome::OutcomeUnknown
            ) {
                record.reason = Some(ReasonCode::ExecutionFailed);
            }
            journal.complete(*intent, record)?;
        }
    }
    Ok(())
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

fn witness_action(action: Action) -> Result<WitnessAction, SurfaceAuthorizationError> {
    Ok(match action {
        Action::ImagePull => WitnessAction::ImagePull,
        Action::ImageDelete => WitnessAction::ImageDelete,
        Action::ImageBuild => WitnessAction::ImageBuild,
        Action::ImageTag => WitnessAction::ImageTag,
        Action::ImageReferenceWrite => WitnessAction::ImageReferenceWrite,
        Action::VolumeCreate => WitnessAction::VolumeCreate,
        Action::VolumeDelete => WitnessAction::VolumeDelete,
        Action::VolumeBackup => WitnessAction::VolumeBackup,
        Action::VolumeRestore => WitnessAction::VolumeRestore,
        Action::NetworkCreate => WitnessAction::NetworkCreate,
        Action::NetworkDelete => WitnessAction::NetworkDelete,
        Action::NetworkAttach => WitnessAction::NetworkAttach,
        Action::NetworkDetach => WitnessAction::NetworkDetach,
        Action::CheckpointPublish => WitnessAction::CheckpointPublish,
        Action::CheckpointRecover => WitnessAction::CheckpointRecover,
        Action::KeyRotate => WitnessAction::KeyRotate,
        Action::PolicyReload => WitnessAction::PolicyReload,
        Action::PolicyRollback => WitnessAction::PolicyRollback,
        Action::RootlessMapping => WitnessAction::RootlessMapping,
        _ => return Err(SurfaceAuthorizationError::InvalidBinding),
    })
}

fn witness_kind(kind: ResourceKind) -> Result<WitnessResourceKind, SurfaceAuthorizationError> {
    Ok(match kind {
        ResourceKind::Image => WitnessResourceKind::Image,
        ResourceKind::Volume => WitnessResourceKind::Volume,
        ResourceKind::Network => WitnessResourceKind::Network,
        ResourceKind::Policy | ResourceKind::Administrative => WitnessResourceKind::Administrative,
        ResourceKind::RootlessMapping => WitnessResourceKind::RootlessMapping,
        _ => return Err(SurfaceAuthorizationError::InvalidBinding),
    })
}

fn recovery_action(action: WitnessAction) -> WitnessAction {
    match action {
        WitnessAction::ImagePull
        | WitnessAction::ImageDelete
        | WitnessAction::ImageBuild
        | WitnessAction::ImageTag
        | WitnessAction::ImageReferenceWrite => WitnessAction::ImageDelete,
        WitnessAction::VolumeCreate
        | WitnessAction::VolumeDelete
        | WitnessAction::VolumeRestore => WitnessAction::VolumeDelete,
        // Backup is observational: recovery classifies the interrupted read
        // without ever deleting or replaying the volume.
        WitnessAction::VolumeBackup => WitnessAction::VolumeBackup,
        WitnessAction::NetworkCreate | WitnessAction::NetworkDelete => WitnessAction::NetworkDelete,
        WitnessAction::NetworkAttach | WitnessAction::NetworkDetach => WitnessAction::NetworkDetach,
        WitnessAction::RootlessMapping => WitnessAction::RootlessMapping,
        WitnessAction::CheckpointPublish | WitnessAction::CheckpointRecover => {
            WitnessAction::CheckpointRecover
        }
        WitnessAction::KeyRotate => WitnessAction::KeyRotate,
        WitnessAction::PolicyReload | WitnessAction::PolicyRollback => {
            WitnessAction::PolicyRollback
        }
        _ => action,
    }
}

fn stable_resource_id(kind: ResourceKind, canonical_name: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(
        [
            b"ferrocrate/surface-resource/v1".as_slice(),
            format!("{kind:?}").as_bytes(),
            canonical_name.as_bytes(),
        ]
        .concat(),
    )
    .into();
    uuid(&digest)
}

/// Canonical action-specific observation identity used by startup recovery.
/// Callers scan live state and compare this handle/digest pair; no mutation is
/// replayed by the reconciliation API.
pub fn recovery_observation(
    action: Action,
    kind: ResourceKind,
    canonical_name: &str,
    generation: u64,
) -> (ObservationHandle, ObservationDigest) {
    let resource_id = stable_resource_id(kind, canonical_name);
    (
        ObservationHandle::from_bytes(surface_observation_handle(kind, &resource_id)),
        ObservationDigest::from_bytes(surface_observation_digest(
            action,
            kind,
            &resource_id,
            generation,
        )),
    )
}

fn surface_observation_handle(kind: ResourceKind, resource_id: &str) -> [u8; 16] {
    Sha256::digest(
        [
            b"ferrocrate/surface-observation-handle/v1".as_slice(),
            format!("{kind:?}").as_bytes(),
            resource_id.as_bytes(),
        ]
        .concat(),
    )[..16]
        .try_into()
        .expect("digest length")
}

fn surface_observation_digest(
    action: Action,
    kind: ResourceKind,
    resource_id: &str,
    generation: u64,
) -> [u8; 32] {
    Sha256::digest(
        [
            b"ferrocrate/surface-observation/v1".as_slice(),
            format!("{action:?}/{kind:?}").as_bytes(),
            resource_id.as_bytes(),
            &generation.to_be_bytes(),
        ]
        .concat(),
    )
    .into()
}

fn request_id(resource_id: &str, action: Action) -> String {
    hex(&Sha256::digest(
        [
            b"ferrocrate/surface-request/v1".as_slice(),
            resource_id.as_bytes(),
            format!("{action:?}").as_bytes(),
        ]
        .concat(),
    )[..16])
}

fn origin_request_id(origin: &RequestOrigin, resource_id: &str, action: Action) -> String {
    origin
        .request_id()
        .map(|id| hex(&id))
        .unwrap_or_else(|| request_id(resource_id, action))
}

fn validate_fanout_origin(
    origin: &RequestOrigin,
    action: Action,
    resource: &str,
    request_digest: [u8; 32],
    policy_generation: u64,
    policy_digest: [u8; 32],
) -> Result<(), SurfaceAuthorizationError> {
    let Some(fanout) = origin.fanout() else {
        return Ok(());
    };
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64;
    if !origin.fanout_integrity_valid()
        || fanout.expected_action != action
        || fanout.expected_resource != resource
        || fanout.request_digest() != &request_digest
        || fanout.deadline_unix_ms() < now_ms
        || fanout.policy_generation() != policy_generation
        || fanout.policy_digest() != &policy_digest
    {
        return Err(SurfaceAuthorizationError::InvalidBinding);
    }
    Ok(())
}

fn uuid(bytes: &[u8; 32]) -> String {
    let value = hex(&bytes[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &value[..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..32]
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_boot_id() -> Option<[u8; 16]> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let compact = value.trim().replace('-', "");
    if compact.len() != 32 {
        return None;
    }
    let mut out = [0; 16];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn origin() -> RequestOrigin {
        RequestOrigin::cli_current().expect("current CLI identity")
    }

    #[test]
    fn image_authorization_binds_the_immutable_digest() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let proof = SurfaceAuthorization::compatibility()
            .authorize_image_binding(
                &origin(),
                Action::ImagePull,
                "registry.example/acme/app:latest",
                &digest,
                7,
            )
            .expect("authorized image");

        assert_eq!(
            proof.proof().canonical().image_digest(),
            Some(digest.as_str())
        );
        assert_eq!(proof.proof().canonical().resource_generation(), 7);
        assert_eq!(
            proof.proof().canonical().context().action(),
            Action::ImagePull
        );
    }

    #[test]
    fn named_resources_have_kind_separated_stable_ids() {
        let auth = SurfaceAuthorization::compatibility();
        let volume = auth
            .authorize_named(
                &origin(),
                Action::VolumeCreate,
                ResourceKind::Volume,
                "data",
                3,
            )
            .expect("authorized volume");
        let volume_again = auth
            .authorize_named(
                &origin(),
                Action::VolumeDelete,
                ResourceKind::Volume,
                "data",
                3,
            )
            .expect("authorized volume");
        let network = auth
            .authorize_named(
                &origin(),
                Action::NetworkCreate,
                ResourceKind::Network,
                "data",
                3,
            )
            .expect("authorized network");
        let backup = auth
            .authorize_named(
                &origin(),
                Action::VolumeBackup,
                ResourceKind::Volume,
                "data",
                3,
            )
            .expect("authorized backup");
        let restore = auth
            .authorize_named(
                &origin(),
                Action::VolumeRestore,
                ResourceKind::Volume,
                "data",
                3,
            )
            .expect("authorized restore");

        assert_eq!(
            volume.proof().canonical().resource_id(),
            volume_again.proof().canonical().resource_id()
        );
        assert_ne!(
            volume.proof().canonical().resource_id(),
            network.proof().canonical().resource_id()
        );
        assert_eq!(volume.proof().canonical().resource_generation(), 3);
        assert_eq!(
            backup.proof().canonical().context().action(),
            Action::VolumeBackup
        );
        assert_eq!(
            restore.proof().canonical().context().action(),
            Action::VolumeRestore
        );
        assert_eq!(
            backup.proof().canonical().resource_id(),
            volume.proof().canonical().resource_id()
        );
    }

    #[test]
    fn volume_archive_denials_keep_action_and_resource_attribution() {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.toml");
        std::fs::write(
            &policy,
            "schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let journal = Arc::new(
            crate::witness::WitnessJournal::open(crate::witness::JournalConfig::new(
                root.path().join("journal"),
                [93; 16],
                crate::witness::JournalMode::Required,
            ))
            .unwrap(),
        );
        let auth = SurfaceAuthorization::with_journal(
            Arc::new(AuthorizationGate::new(Arc::new(
                PolicyStore::load(&policy).unwrap(),
            ))),
            Arc::clone(&journal),
            [94; 16],
        );

        for (action, witness_action) in [
            (Action::VolumeBackup, WitnessAction::VolumeBackup),
            (Action::VolumeRestore, WitnessAction::VolumeRestore),
        ] {
            assert!(matches!(
                auth.authorize_named(&origin(), action, ResourceKind::Volume, "data", 1),
                Err(SurfaceAuthorizationError::Denied(_))
            ));
            let records = journal.records().unwrap();
            let denied = crate::witness::decode_record(records.last().unwrap()).unwrap();
            assert_eq!(denied.action(), witness_action);
            assert_eq!(denied.resource_kind(), WitnessResourceKind::Volume);
            assert_eq!(denied.outcome(), WitnessOutcome::Denied);
        }
    }

    #[test]
    fn volume_backup_recovery_is_observational_not_destructive() {
        assert_eq!(
            recovery_action(WitnessAction::VolumeBackup),
            WitnessAction::VolumeBackup
        );
        assert_eq!(
            recovery_action(WitnessAction::VolumeRestore),
            WitnessAction::VolumeDelete
        );
    }

    #[test]
    fn network_endpoint_mutations_have_surface_witness_bindings() {
        for (action, expected) in [
            (Action::NetworkAttach, WitnessAction::NetworkAttach),
            (Action::NetworkDetach, WitnessAction::NetworkDetach),
        ] {
            assert_eq!(
                witness_action(action).expect("endpoint witness action"),
                expected
            );
            let permit = SurfaceAuthorization::compatibility()
                .authorize_named(&origin(), action, ResourceKind::Network, "backend", 2)
                .expect("endpoint surface authorization");
            permit.finish(true).expect("complete endpoint permit");
        }
    }

    #[test]
    fn executor_binding_rejects_a_permit_for_another_resource() {
        let auth = SurfaceAuthorization::compatibility();
        let proof = auth
            .authorize_named(
                &origin(),
                Action::VolumeCreate,
                ResourceKind::Volume,
                "other",
                1,
            )
            .expect("authorized volume");

        let error = SurfaceAuthorization::validate_execution(
            &proof,
            Action::VolumeCreate,
            ResourceKind::Volume,
            "data",
            1,
        )
        .expect_err("resource substitution must fail");
        assert_eq!(error, SurfaceExecutionError::ResourceMismatch);
    }

    #[test]
    fn required_surface_decision_is_durable_before_permit_is_returned() {
        let root = tempfile::tempdir().unwrap();
        let journal = Arc::new(
            crate::witness::WitnessJournal::open(crate::witness::JournalConfig::new(
                root.path(),
                [81; 16],
                crate::witness::JournalMode::Required,
            ))
            .unwrap(),
        );
        let auth = SurfaceAuthorization::with_journal(
            Arc::new(AuthorizationGate::new(Arc::new(
                PolicyStore::compatibility_disabled(),
            ))),
            Arc::clone(&journal),
            [82; 16],
        );

        let permit = auth
            .authorize_named(
                &origin(),
                Action::VolumeCreate,
                ResourceKind::Volume,
                "data",
                1,
            )
            .unwrap();

        assert!(permit.durable_intent().is_some());
        assert_eq!(journal.records().unwrap().len(), 2);
        assert_eq!(journal.pending().unwrap().len(), 1);
    }

    #[test]
    fn production_surface_canary_is_absent_from_witness_mirror_errors_logs_and_metrics() {
        let canary = std::env::var("FERRO_AUTHORIZATION_QUALIFICATION_CANARY")
            .unwrap_or_else(|_| "surface-secret-canary-30c8".to_owned());
        let temporary = tempfile::tempdir().unwrap();
        let root = std::env::var_os("FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT")
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| temporary.path().to_path_buf());
        std::fs::create_dir_all(&root).unwrap();
        let metrics_before = crate::observability::authorization_metrics_snapshot();
        let journal = Arc::new(
            crate::witness::WitnessJournal::open(crate::witness::JournalConfig::new(
                root.join("journal"),
                [91; 16],
                crate::witness::JournalMode::Required,
            ))
            .unwrap(),
        );
        let auth = SurfaceAuthorization::with_journal(
            Arc::new(AuthorizationGate::new(Arc::new(
                PolicyStore::compatibility_disabled(),
            ))),
            Arc::clone(&journal),
            [92; 16],
        );
        let permit = auth
            .authorize_named(
                &origin(),
                Action::VolumeCreate,
                ResourceKind::Volume,
                &canary,
                1,
            )
            .unwrap();
        let error = SurfaceAuthorization::validate_execution(
            &permit,
            Action::VolumeCreate,
            ResourceKind::Volume,
            "different-resource",
            1,
        )
        .unwrap_err()
        .to_string();
        permit.finish(false).unwrap();
        crate::observability::authorization_metrics()
            .export_json(&root.join("metrics.json"))
            .unwrap();
        let evidence = crate::observability::AuthorizationFixtureEvidence::new(
            "runtime.surface.canary",
            crate::observability::FixtureClassification::ActualFixture,
            metrics_before,
            crate::observability::authorization_metrics_snapshot(),
        );
        std::fs::write(
            root.join("fixture-runtime-surface.json"),
            serde_json::to_vec(&evidence).unwrap(),
        )
        .unwrap();
        crate::observability::log_event(
            &root,
            crate::observability::make_event(
                "authorization.evaluate",
                None,
                None,
                Some("failed"),
                Some("attributes redacted"),
            ),
        )
        .unwrap();
        std::fs::write(root.join("captured-error.txt"), &error).unwrap();
        drop(journal);

        let mut stack = vec![root.clone()];
        while let Some(path) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(path) else {
                continue;
            };
            for entry in entries {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    stack.push(entry.path());
                } else {
                    let bytes = std::fs::read(entry.path()).unwrap();
                    assert!(!bytes
                        .windows(canary.len())
                        .any(|window| window == canary.as_bytes()));
                }
            }
        }
        assert!(!error.contains(&canary));
    }

    #[test]
    fn diagnostic_broken_comparator_records_a_successful_bypass() {
        let metrics = crate::observability::AuthorizationMetrics::new();
        let auth = SurfaceAuthorization::compatibility();
        let permit = auth
            .authorize_named(
                &origin(),
                Action::VolumeCreate,
                ResourceKind::Volume,
                "data",
                1,
            )
            .unwrap();
        let before = metrics.snapshot();
        let result = validate_execution_with_comparator_with_metrics(
            &permit,
            Action::VolumeCreate,
            ResourceKind::Volume,
            "attacker-substitution",
            1,
            |_| Ok(()),
            &metrics,
        );
        assert!(result.is_ok(), "fault seam intentionally accepts mismatch");
        let after = metrics.snapshot();
        assert_eq!(after.bypass_probe_total, before.bypass_probe_total + 1);
        assert_eq!(
            after.successful_bypass_total,
            before.successful_bypass_total + 1
        );
        if let Some(root) = std::env::var_os("FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT") {
            let evidence = crate::observability::AuthorizationFixtureEvidence::new(
                "negative-control.broken-comparator",
                crate::observability::FixtureClassification::ExpectedNegativeControl,
                before,
                after,
            );
            std::fs::write(
                std::path::Path::new(&root).join("fixture-negative-control.json"),
                serde_json::to_vec(&evidence).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn completing_surface_permit_clears_pending_recovery() {
        let root = tempfile::tempdir().unwrap();
        let journal = Arc::new(
            crate::witness::WitnessJournal::open(crate::witness::JournalConfig::new(
                root.path(),
                [83; 16],
                crate::witness::JournalMode::Required,
            ))
            .unwrap(),
        );
        let auth = SurfaceAuthorization::with_journal(
            Arc::new(AuthorizationGate::new(Arc::new(
                PolicyStore::compatibility_disabled(),
            ))),
            Arc::clone(&journal),
            [84; 16],
        );
        let permit = auth
            .authorize_named(
                &origin(),
                Action::NetworkCreate,
                ResourceKind::Network,
                "frontend",
                4,
            )
            .unwrap();

        auth.complete(permit, true).unwrap();

        assert!(journal.pending().unwrap().is_empty());
        assert_eq!(journal.records().unwrap().len(), 3);
    }

    #[test]
    fn crash_before_execution_reopens_as_pending_and_reconciles_without_replay() {
        for _ in 0..16 {
            let root = tempfile::tempdir().unwrap();
            let config = crate::witness::JournalConfig::new(
                root.path(),
                [85; 16],
                crate::witness::JournalMode::Required,
            );
            let journal = Arc::new(crate::witness::WitnessJournal::open(config.clone()).unwrap());
            let auth = SurfaceAuthorization::with_journal(
                Arc::new(AuthorizationGate::new(Arc::new(
                    PolicyStore::compatibility_disabled(),
                ))),
                Arc::clone(&journal),
                [86; 16],
            );
            let permit = auth
                .authorize_named(
                    &origin(),
                    Action::VolumeDelete,
                    ResourceKind::Volume,
                    "data",
                    9,
                )
                .unwrap();
            let operation = permit.operation_id();
            drop(permit);
            drop(auth);
            let journal = Arc::try_unwrap(journal)
                .unwrap_or_else(|_| panic!("surface shutdown retained a witness journal owner"));
            drop(journal);

            let reopened = Arc::new(crate::witness::WitnessJournal::open(config).unwrap());
            let auth = SurfaceAuthorization::with_journal(
                Arc::new(AuthorizationGate::new(Arc::new(
                    PolicyStore::compatibility_disabled(),
                ))),
                Arc::clone(&reopened),
                [86; 16],
            );
            assert_eq!(reopened.pending().unwrap()[0].operation_id(), operation);
            let mut observations = 0;
            assert_eq!(
                auth.reconcile_pending(|pending| {
                    observations += 1;
                    (*pending.recipe().observation_digest(), true)
                })
                .unwrap(),
                1
            );
            assert_eq!(observations, 1);
            assert!(reopened.pending().unwrap().is_empty());
        }
    }

    #[test]
    fn outcome_unknown_retains_surface_operation_for_startup_recovery() {
        let root = tempfile::tempdir().unwrap();
        let journal = Arc::new(
            crate::witness::WitnessJournal::open(crate::witness::JournalConfig::new(
                root.path(),
                [87; 16],
                crate::witness::JournalMode::Required,
            ))
            .unwrap(),
        );
        let auth = SurfaceAuthorization::with_journal(
            Arc::new(AuthorizationGate::new(Arc::new(
                PolicyStore::compatibility_disabled(),
            ))),
            Arc::clone(&journal),
            [88; 16],
        );
        let permit = auth
            .authorize_image_binding(
                &origin(),
                Action::ImageDelete,
                "registry.example/app:latest",
                &format!("sha256:{}", "a".repeat(64)),
                1,
            )
            .unwrap();
        let operation = permit.operation_id();

        permit.finish_unknown().unwrap();

        assert_eq!(journal.pending().unwrap()[0].operation_id(), operation);
        let records = journal.records().unwrap();
        let terminal = crate::witness::decode_record(records.last().unwrap()).unwrap();
        assert_eq!(terminal.record().outcome, WitnessOutcome::OutcomeUnknown);
    }

    #[test]
    fn enabled_runtime_factory_rejects_missing_shared_journal() {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.toml");
        std::fs::write(
            &policy,
            "schema_version = 1\ngeneration = 1\nmode = \"enforce\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let gate = Arc::new(AuthorizationGate::new(Arc::new(
            PolicyStore::load(&policy).unwrap(),
        )));

        assert!(matches!(
            SurfaceAuthorization::from_runtime(gate, None, [1; 16], [2; 16], [3; 32]),
            Err(SurfaceAuthorizationError::JournalRequired)
        ));
    }
}
