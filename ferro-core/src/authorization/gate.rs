//! Complete-mediation gate and executor-consumable authorization proof.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::policy::{PolicySnapshot, PolicyStore};
use super::{Decision, MountClass, ReasonCode, RequestContext, ResourceKind, ResourceState};

/// A policy snapshot pinned before request fan-out.
#[derive(Clone, Debug)]
pub struct PolicyPin {
    snapshot: PolicySnapshot,
}

/// The immutable identity of a resolved image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImageBinding {
    reference: String,
    digest: String,
}

impl ImageBinding {
    #[allow(dead_code)] // Used by the runtime canonicalizer introduced in the mediation task.
    pub(crate) fn new(reference: impl Into<String>, digest: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            digest: digest.into(),
        }
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Stable kernel identity for a device node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DeviceIdentity {
    class: String,
    major: u32,
    minor: u32,
    inode: u64,
}

impl DeviceIdentity {
    #[allow(dead_code)] // Used by the runtime canonicalizer introduced in the mediation task.
    pub(crate) fn new(class: impl Into<String>, major: u32, minor: u32, inode: u64) -> Self {
        Self {
            class: class.into(),
            major,
            minor,
            inode,
        }
    }

    pub fn class(&self) -> &str {
        &self.class
    }

    pub fn major(&self) -> u32 {
        self.major
    }

    pub fn minor(&self) -> u32 {
        self.minor
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }
}

/// Identity and constraints read from an already-open mount source handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MountHandleDescriptor {
    class: MountClass,
    mount_id: u64,
    device_id: u64,
    inode: u64,
    open_flags: u64,
}

impl MountHandleDescriptor {
    #[allow(dead_code)] // Used by the runtime canonicalizer introduced in the mediation task.
    pub(crate) fn new(
        class: MountClass,
        mount_id: u64,
        device_id: u64,
        inode: u64,
        open_flags: u64,
    ) -> Self {
        Self {
            class,
            mount_id,
            device_id,
            inode,
            open_flags,
        }
    }

    pub fn class(&self) -> MountClass {
        self.class
    }

    pub fn mount_id(&self) -> u64 {
        self.mount_id
    }

    pub fn device_id(&self) -> u64 {
        self.device_id
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }

    pub fn open_flags(&self) -> u64 {
        self.open_flags
    }
}

/// Immutable bindings expected by execution or observed during normalization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecutionBindings {
    image: Option<ImageBinding>,
    resource_generation: u64,
    state_precondition: Option<ResourceState>,
    device_identity: Option<DeviceIdentity>,
    mount_handles: Vec<MountHandleDescriptor>,
}

impl ExecutionBindings {
    #[allow(dead_code)] // Used by the runtime canonicalizer introduced in the mediation task.
    pub(crate) fn new(
        image: Option<ImageBinding>,
        resource_generation: u64,
        state_precondition: Option<ResourceState>,
        device_identity: Option<DeviceIdentity>,
        mount_handles: Vec<MountHandleDescriptor>,
    ) -> Self {
        Self {
            image,
            resource_generation,
            state_precondition,
            device_identity,
            mount_handles,
        }
    }
}

/// A trusted request after aliases have been resolved and execution facts opened.
#[derive(Debug)]
pub struct CanonicalRequest {
    context: RequestContext,
    policy: PolicyPin,
    policy_generation: u64,
    policy_digest: [u8; 32],
    expected: ExecutionBindings,
    observed: ExecutionBindings,
}

impl CanonicalRequest {
    #[allow(dead_code)] // Used by the runtime canonicalizer introduced in the mediation task.
    pub(crate) fn new(
        context: RequestContext,
        policy: PolicyPin,
        expected: ExecutionBindings,
        observed: ExecutionBindings,
    ) -> Self {
        let policy_generation = policy.snapshot.generation;
        let policy_digest = policy.snapshot.digest;
        Self {
            context,
            policy,
            policy_generation,
            policy_digest,
            expected,
            observed,
        }
    }

    pub fn request_id(&self) -> &str {
        self.context.request_id()
    }

    pub fn context(&self) -> &RequestContext {
        &self.context
    }

    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }

    pub fn image_digest(&self) -> Option<&str> {
        self.expected.image.as_ref().map(ImageBinding::digest)
    }

    pub fn image_reference(&self) -> Option<&str> {
        self.expected.image.as_ref().map(ImageBinding::reference)
    }

    pub fn resource_id(&self) -> &str {
        self.context.resource().id().as_str()
    }

    pub fn resource_generation(&self) -> u64 {
        self.expected.resource_generation
    }

    pub fn state_precondition(&self) -> Option<ResourceState> {
        self.expected.state_precondition
    }

    pub fn device_identity(&self) -> Option<&DeviceIdentity> {
        self.expected.device_identity.as_ref()
    }

    pub fn mount_handles(&self) -> &[MountHandleDescriptor] {
        &self.expected.mount_handles
    }
}

/// Stable machine-readable gate denial codes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DenialCode {
    PolicyDenied,
    PolicyGenerationMismatch,
    PolicyDigestMismatch,
    MutableImageReference,
    ImageDigestMismatch,
    NonCanonicalResource,
    ResourceGenerationMismatch,
    StatePreconditionMismatch,
    DeviceIdentityMismatch,
    MountHandleMismatch,
}

/// A structured failure that is safe to persist in a witness.
#[derive(Debug, Error, Serialize)]
#[error("authorization denied for {request_id}: {code:?}")]
pub struct Denial {
    code: DenialCode,
    request_id: String,
    policy_generation: u64,
    reason: Option<ReasonCode>,
}

impl Denial {
    fn new(request: &CanonicalRequest, code: DenialCode) -> Self {
        Self {
            code,
            request_id: request.request_id().to_owned(),
            policy_generation: request.policy_generation,
            reason: None,
        }
    }

    fn policy(request: &CanonicalRequest, decision: &Decision) -> Self {
        Self {
            code: DenialCode::PolicyDenied,
            request_id: request.request_id().to_owned(),
            policy_generation: decision.policy_generation,
            reason: Some(decision.reason),
        }
    }

    pub fn code(&self) -> DenialCode {
        self.code
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }

    pub fn reason(&self) -> Option<ReasonCode> {
        self.reason
    }
}

/// Proof that one canonical request passed the authorization gate.
///
/// Its fields and constructor are not available to external callers:
///
/// ```compile_fail
/// use ferro_core::authorization::gate::AuthorizedRequest;
/// let _constructor = AuthorizedRequest::new;
/// ```
#[derive(Debug)]
pub struct AuthorizedRequest {
    canonical: CanonicalRequest,
    decision: Decision,
}

impl AuthorizedRequest {
    fn new(canonical: CanonicalRequest, decision: Decision) -> Self {
        Self {
            canonical,
            decision,
        }
    }

    pub fn decision(&self) -> &Decision {
        &self.decision
    }

    pub fn canonical(&self) -> &CanonicalRequest {
        &self.canonical
    }
}

/// Runtime-owned gate that mints authorization proofs from validated policies.
#[derive(Debug)]
pub struct AuthorizationGate {
    policies: Arc<PolicyStore>,
}

impl AuthorizationGate {
    pub fn new(policies: Arc<PolicyStore>) -> Self {
        Self { policies }
    }

    /// Pin the active validated policy before canonicalization or request fan-out.
    pub fn pin(&self) -> PolicyPin {
        PolicyPin {
            snapshot: self.policies.snapshot(),
        }
    }

    /// Validate immutable bindings, evaluate the pinned policy, and mint a proof.
    pub fn authorize(&self, request: CanonicalRequest) -> Result<AuthorizedRequest, Denial> {
        validate_policy_binding(&request)?;
        validate_canonical_bindings(&request)?;

        let decision = request.policy.snapshot.document.evaluate(&request.context);
        if !decision.allowed {
            return Err(Denial::policy(&request, &decision));
        }
        Ok(AuthorizedRequest::new(request, decision))
    }
}

fn validate_policy_binding(request: &CanonicalRequest) -> Result<(), Denial> {
    if request.policy_generation != request.policy.snapshot.generation
        || request.policy_generation != request.policy.snapshot.document.generation
    {
        return Err(Denial::new(request, DenialCode::PolicyGenerationMismatch));
    }
    if request.policy_digest != request.policy.snapshot.digest {
        return Err(Denial::new(request, DenialCode::PolicyDigestMismatch));
    }
    Ok(())
}

fn validate_canonical_bindings(request: &CanonicalRequest) -> Result<(), Denial> {
    validate_resource_uuid(request)?;
    validate_image(request)?;
    if request.expected.resource_generation != request.context.resource().generation()
        || request.expected.resource_generation != request.observed.resource_generation
    {
        return Err(Denial::new(request, DenialCode::ResourceGenerationMismatch));
    }
    if (request.context.resource().kind() == ResourceKind::Container
        && request.expected.state_precondition.is_none())
        || request.expected.state_precondition != request.context.facts().lifecycle_state()
        || request.expected.state_precondition != request.observed.state_precondition
    {
        return Err(Denial::new(request, DenialCode::StatePreconditionMismatch));
    }
    if request.expected.device_identity != request.observed.device_identity
        || !device_binding_matches_facts(request)
    {
        return Err(Denial::new(request, DenialCode::DeviceIdentityMismatch));
    }
    if request.expected.mount_handles != request.observed.mount_handles
        || !mount_bindings_match_facts(request)
    {
        return Err(Denial::new(request, DenialCode::MountHandleMismatch));
    }
    Ok(())
}

fn device_binding_matches_facts(request: &CanonicalRequest) -> bool {
    match (
        request.context.facts().device_classes(),
        request.expected.device_identity.as_ref(),
    ) {
        ([], None) => true,
        ([class], Some(device)) => class == device.class(),
        _ => false,
    }
}

fn mount_bindings_match_facts(request: &CanonicalRequest) -> bool {
    let mut unmatched = request.context.facts().mounts().to_vec();
    for handle in &request.expected.mount_handles {
        let Some(index) = unmatched.iter().position(|class| *class == handle.class()) else {
            return false;
        };
        unmatched.swap_remove(index);
    }
    unmatched.is_empty()
}

fn validate_resource_uuid(request: &CanonicalRequest) -> Result<(), Denial> {
    let value = request.context.resource().id().as_str().as_bytes();
    let valid = value.len() == 36
        && value.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if valid {
        Ok(())
    } else {
        Err(Denial::new(request, DenialCode::NonCanonicalResource))
    }
}

fn validate_image(request: &CanonicalRequest) -> Result<(), Denial> {
    let (Some(expected), Some(observed)) = (&request.expected.image, &request.observed.image)
    else {
        return if request.expected.image.is_none()
            && request.observed.image.is_none()
            && request.context.facts().image_digest().is_none()
        {
            Ok(())
        } else {
            Err(Denial::new(request, DenialCode::ImageDigestMismatch))
        };
    };
    let digest = expected.digest.strip_prefix("sha256:");
    let valid_digest = digest
        .is_some_and(|hex| hex.len() == 64 && hex.as_bytes().iter().all(u8::is_ascii_hexdigit));
    let pinned = expected
        .reference
        .rsplit_once('@')
        .is_some_and(|(_, reference_digest)| reference_digest == expected.digest);
    if !valid_digest || !pinned {
        return Err(Denial::new(request, DenialCode::MutableImageReference));
    }
    if expected != observed || request.context.facts().image_digest() != Some(expected.digest()) {
        return Err(Denial::new(request, DenialCode::ImageDigestMismatch));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
