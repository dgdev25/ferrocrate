//! Typed authorization requests and native policy decisions.

use serde::{Deserialize, Serialize};

pub mod gate;
pub mod helper_grant;
mod helper_grant_encoding;
mod helper_grant_error;
pub mod inventory;
pub mod policy;
#[cfg(target_os = "linux")]
pub mod principal;
pub(crate) mod runtime;

#[cfg(target_os = "linux")]
pub use principal::{
    DelegatedPrincipal, DelegationPolicy, EffectivePrincipal, IdMapEntry, InvocationChannel,
    LinuxProcessIdentity, PrincipalResolutionError, PrincipalResolver, SupplementaryGroupPolicy,
    TransportPrincipal,
};

#[cfg(test)]
mod tests;

/// A stable, closed vocabulary for runtime mutations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Action {
    #[serde(rename = "container.create")]
    ContainerCreate,
    #[serde(rename = "container.run")]
    ContainerRun,
    #[serde(rename = "container.exec")]
    ContainerExec,
    #[serde(rename = "container.pause")]
    ContainerPause,
    #[serde(rename = "container.resume")]
    ContainerResume,
    #[serde(rename = "container.stop")]
    ContainerStop,
    #[serde(rename = "container.kill")]
    ContainerKill,
    #[serde(rename = "container.restart")]
    ContainerRestart,
    #[serde(rename = "container.delete")]
    ContainerDelete,
    #[serde(rename = "image.pull")]
    ImagePull,
    #[serde(rename = "image.delete")]
    ImageDelete,
    #[serde(rename = "volume.create")]
    VolumeCreate,
    #[serde(rename = "volume.delete")]
    VolumeDelete,
    #[serde(rename = "volume.mount")]
    VolumeMount,
    #[serde(rename = "volume.unmount")]
    VolumeUnmount,
    #[serde(rename = "network.create")]
    NetworkCreate,
    #[serde(rename = "network.delete")]
    NetworkDelete,
    #[serde(rename = "network.attach")]
    NetworkAttach,
    #[serde(rename = "network.detach")]
    NetworkDetach,
    #[serde(rename = "device.use")]
    DeviceUse,
    #[serde(rename = "policy.reload")]
    PolicyReload,
    #[serde(rename = "policy.rollback")]
    PolicyRollback,
}

/// The five roles supported by the native policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Role {
    #[serde(rename = "administrator")]
    Administrator,
    #[serde(rename = "operator")]
    Operator,
    #[serde(rename = "developer")]
    Developer,
    #[serde(rename = "auditor")]
    Auditor,
    #[serde(rename = "runtime-cleanup")]
    RuntimeCleanup,
}

/// The canonical kind of a protected resource.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Container,
    Image,
    Volume,
    Network,
    Device,
    Policy,
    Administrative,
}

/// An authenticated principal identifier minted by the resolver boundary.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    #[allow(dead_code)] // Used by the trusted resolver submodule added in Task 2.
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A resolver-produced principal with a trusted native role.
///
/// External callers cannot mint one:
///
/// ```compile_fail
/// use ferro_core::authorization::{ResolvedPrincipal, Role};
/// let _ = ResolvedPrincipal::new("caller-supplied", Role::Administrator);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedPrincipal {
    id: PrincipalId,
    role: Role,
}

impl ResolvedPrincipal {
    #[allow(dead_code)] // Used by the trusted resolver submodule added in Task 2.
    fn new(id: impl Into<String>, role: Role) -> Self {
        Self {
            id: PrincipalId::new(id),
            role,
        }
    }

    pub fn id(&self) -> &PrincipalId {
        &self.id
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn is_host_administrator(&self) -> bool {
        self.role == Role::Administrator
    }
}

/// An immutable resource identifier minted by canonicalization.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    #[allow(dead_code)] // Used by the trusted canonicalization submodule.
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An immutable resource identity used for a decision.
///
/// Resource canonicalization is restricted to the authorization boundary:
///
/// ```compile_fail
/// use ferro_core::authorization::{Resource, ResourceKind};
/// let _ = Resource::canonical(ResourceKind::Container, "raw-name", None, 1);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Resource {
    kind: ResourceKind,
    id: ResourceId,
    owner: Option<PrincipalId>,
    generation: u64,
}

impl Resource {
    #[allow(dead_code)] // Used by the trusted canonicalization submodule.
    fn canonical(
        kind: ResourceKind,
        id: impl Into<String>,
        owner: Option<PrincipalId>,
        generation: u64,
    ) -> Self {
        Self {
            kind,
            id: ResourceId::new(id),
            owner,
            generation,
        }
    }

    pub fn kind(&self) -> ResourceKind {
        self.kind
    }

    pub fn id(&self) -> &ResourceId {
        &self.id
    }

    pub fn owner(&self) -> Option<&PrincipalId> {
        self.owner.as_ref()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// A normalized mount category; raw host paths are not policy inputs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountClass {
    ReadOnly,
    Workspace,
    PersistentVolume,
    HostPath,
    Tmpfs,
}

/// A canonical lifecycle state at the time of authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceState {
    Absent,
    Created,
    Running,
    Paused,
    Stopped,
}

/// Normalized facts that can constrain a typed action.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RequestFacts {
    image_digest: Option<String>,
    mounts: Vec<MountClass>,
    network_ids: Vec<String>,
    requested_capabilities: Vec<String>,
    privileged: bool,
    device_classes: Vec<String>,
    lifecycle_state: Option<ResourceState>,
    readonly_rootfs: bool,
    no_new_privileges: bool,
    mount_sources_approved: Option<bool>,
}

impl RequestFacts {
    pub fn image_digest(&self) -> Option<&str> {
        self.image_digest.as_deref()
    }

    pub fn mounts(&self) -> &[MountClass] {
        &self.mounts
    }

    pub fn network_ids(&self) -> &[String] {
        &self.network_ids
    }

    pub fn requested_capabilities(&self) -> &[String] {
        &self.requested_capabilities
    }

    pub fn privileged(&self) -> bool {
        self.privileged
    }

    pub fn device_classes(&self) -> &[String] {
        &self.device_classes
    }

    pub fn lifecycle_state(&self) -> Option<ResourceState> {
        self.lifecycle_state
    }

    pub fn readonly_rootfs(&self) -> bool {
        self.readonly_rootfs
    }

    pub fn no_new_privileges(&self) -> bool {
        self.no_new_privileges
    }
}

/// The authenticated and normalized input to policy evaluation.
///
/// Trusted request contexts cannot be reconstructed from caller input:
///
/// ```compile_fail
/// use ferro_core::authorization::RequestContext;
/// let _: RequestContext = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequestContext {
    request_id: String,
    principal: Option<ResolvedPrincipal>,
    action: Action,
    resource: Resource,
    facts: RequestFacts,
}

impl RequestContext {
    #[allow(dead_code)] // Used by resolver/gate submodules, never external callers.
    fn resolved(
        request_id: impl Into<String>,
        principal: Option<ResolvedPrincipal>,
        action: Action,
        resource: Resource,
        facts: RequestFacts,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            principal,
            action,
            resource,
            facts,
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn principal(&self) -> Option<&ResolvedPrincipal> {
        self.principal.as_ref()
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    pub fn facts(&self) -> &RequestFacts {
        &self.facts
    }
}

/// Rollout behavior for authorization.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationMode {
    /// Preserve existing OCI and Docker-compatible behavior.
    #[default]
    Disabled,
    /// Evaluate the policy, but do not enforce a denial.
    Shadow,
    /// Apply the native policy decision.
    Enforce,
}

/// Stable machine-readable explanations for decisions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasonCode {
    AuthorizationDisabled,
    ShadowAllowed,
    RoleAllowed,
    UnknownPrincipal,
    ResourceOwnerMismatch,
    PrivilegedContainerDenied,
    RoleNotAuthorized,
    PolicyAdministrationDenied,
    CleanupActionDenied,
    MountSourceDenied,
}

/// An effective decision and, in shadow mode, its hypothetical denial.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: ReasonCode,
    pub matched_rule: String,
    pub policy_generation: u64,
    pub hypothetical_denial: Option<ReasonCode>,
}

/// A bounded, versioned native policy document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: u32,
    pub generation: u64,
    #[serde(default)]
    pub mode: AuthorizationMode,
}

impl PolicyDocument {
    /// Evaluate a request according to the configured rollout mode.
    pub fn evaluate(&self, request: &RequestContext) -> Decision {
        match self.mode {
            AuthorizationMode::Disabled => self.decision(
                true,
                ReasonCode::AuthorizationDisabled,
                "compatibility.disabled",
                None,
            ),
            AuthorizationMode::Shadow => {
                let hypothetical = self.enforced_decision(request);
                if hypothetical.allowed {
                    hypothetical
                } else {
                    self.decision(
                        true,
                        ReasonCode::ShadowAllowed,
                        "compatibility.shadow",
                        Some(hypothetical.reason),
                    )
                }
            }
            AuthorizationMode::Enforce => self.enforced_decision(request),
        }
    }

    fn enforced_decision(&self, request: &RequestContext) -> Decision {
        if request.facts.mount_sources_approved == Some(false) {
            return self.decision(
                false,
                ReasonCode::MountSourceDenied,
                "container.mount-source.approved-root",
                None,
            );
        }
        let Some(principal) = &request.principal else {
            return self.decision(
                false,
                ReasonCode::UnknownPrincipal,
                "principal.unknown",
                None,
            );
        };

        match principal.role {
            Role::Administrator => {
                self.decision(true, ReasonCode::RoleAllowed, "role.administrator", None)
            }
            Role::Operator if is_policy_administration(request.action) => self.decision(
                false,
                ReasonCode::PolicyAdministrationDenied,
                "role.operator.no-policy-admin",
                None,
            ),
            Role::Operator => self.decision(true, ReasonCode::RoleAllowed, "role.operator", None),
            Role::Developer
                if request.facts.privileged
                    && matches!(
                        request.action,
                        Action::ContainerCreate | Action::ContainerRun
                    ) =>
            {
                self.decision(
                    false,
                    ReasonCode::PrivilegedContainerDenied,
                    "role.developer.no-privileged-container",
                    None,
                )
            }
            Role::Developer if request.resource.owner.as_ref() != Some(&principal.id) => self
                .decision(
                    false,
                    ReasonCode::ResourceOwnerMismatch,
                    "role.developer.owner",
                    None,
                ),
            Role::Developer if is_policy_administration(request.action) => self.decision(
                false,
                ReasonCode::PolicyAdministrationDenied,
                "role.developer.no-policy-admin",
                None,
            ),
            Role::Developer => {
                self.decision(true, ReasonCode::RoleAllowed, "role.developer.owner", None)
            }
            Role::Auditor => self.decision(
                false,
                ReasonCode::RoleNotAuthorized,
                "role.auditor.read-only",
                None,
            ),
            Role::RuntimeCleanup if is_cleanup_action(request.action) => {
                self.decision(true, ReasonCode::RoleAllowed, "role.runtime-cleanup", None)
            }
            Role::RuntimeCleanup => self.decision(
                false,
                ReasonCode::CleanupActionDenied,
                "role.runtime-cleanup.deletion-only",
                None,
            ),
        }
    }

    fn decision(
        &self,
        allowed: bool,
        reason: ReasonCode,
        matched_rule: &str,
        hypothetical_denial: Option<ReasonCode>,
    ) -> Decision {
        Decision {
            allowed,
            reason,
            matched_rule: matched_rule.to_owned(),
            policy_generation: self.generation,
            hypothetical_denial,
        }
    }
}

fn is_policy_administration(action: Action) -> bool {
    matches!(action, Action::PolicyReload | Action::PolicyRollback)
}

fn is_cleanup_action(action: Action) -> bool {
    matches!(
        action,
        Action::ContainerDelete
            | Action::VolumeDelete
            | Action::VolumeUnmount
            | Action::NetworkDelete
            | Action::NetworkDetach
    )
}
