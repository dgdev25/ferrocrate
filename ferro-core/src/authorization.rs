//! Typed authorization requests and native policy decisions.

use serde::{Deserialize, Serialize};

pub mod policy;

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

/// An immutable resource identity used for a decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Resource {
    pub kind: ResourceKind,
    pub id: String,
    pub owner: Option<String>,
    pub generation: u64,
}

/// A normalized mount category; raw host paths are not policy inputs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountClass {
    ReadOnly,
    Workspace,
    PersistentVolume,
    HostPath,
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
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestFacts {
    pub image_digest: Option<String>,
    pub mounts: Vec<MountClass>,
    pub network_ids: Vec<String>,
    pub requested_capabilities: Vec<String>,
    pub privileged: bool,
    pub device_classes: Vec<String>,
    pub lifecycle_state: Option<ResourceState>,
}

/// The authenticated and normalized input to policy evaluation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RequestContext {
    pub request_id: String,
    pub principal: Option<String>,
    pub role: Option<Role>,
    pub action: Action,
    pub resource: Resource,
    pub facts: RequestFacts,
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
        let (Some(principal), Some(role)) = (&request.principal, request.role) else {
            return self.decision(
                false,
                ReasonCode::UnknownPrincipal,
                "principal.unknown",
                None,
            );
        };

        match role {
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
            Role::Developer if request.resource.owner.as_deref() != Some(principal.as_str()) => {
                self.decision(
                    false,
                    ReasonCode::ResourceOwnerMismatch,
                    "role.developer.owner",
                    None,
                )
            }
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
