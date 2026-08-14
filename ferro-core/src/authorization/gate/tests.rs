use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tempfile::TempDir;

use super::*;
use crate::authorization::policy::PolicyStore;
use crate::authorization::{
    Action, AuthorizationMode, MountClass, PrincipalId, ReasonCode, RequestContext, RequestFacts,
    ResolvedPrincipal, Resource, ResourceKind, ResourceState, Role,
};

const RESOURCE_UUID: &str = "74e6dc22-25df-4d2e-b8e4-e57c8a91a052";
const IMAGE_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    _dir: TempDir,
    gate: AuthorizationGate,
}

impl Fixture {
    fn new(mode: AuthorizationMode) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let path = write_policy(&dir, "policy.toml", 7, mode);
        let store = Arc::new(PolicyStore::load(path).expect("load policy"));
        Self {
            _dir: dir,
            gate: AuthorizationGate::new(store),
        }
    }

    fn request(
        &self,
        role: Option<Role>,
        privileged: bool,
        image_reference: &str,
    ) -> CanonicalRequest {
        let principal = role.map(|role| ResolvedPrincipal::new("alice", role));
        let resource = Resource::canonical(
            ResourceKind::Container,
            RESOURCE_UUID,
            Some(PrincipalId::new("alice")),
            12,
        );
        let facts = RequestFacts {
            image_digest: Some(IMAGE_DIGEST.to_owned()),
            mounts: vec![MountClass::Workspace],
            privileged,
            device_classes: vec!["block".to_owned()],
            lifecycle_state: Some(ResourceState::Stopped),
            ..RequestFacts::default()
        };
        let context = RequestContext::resolved(
            "request-7",
            principal,
            Action::ContainerRun,
            resource,
            facts,
        );
        let bindings = ExecutionBindings::new(
            Some(ImageBinding::new(image_reference, IMAGE_DIGEST)),
            12,
            Some(ResourceState::Stopped),
            Some(DeviceIdentity::new("block", 8, 1, 41)),
            vec![MountHandleDescriptor::new(
                MountClass::Workspace,
                33,
                2049,
                82,
                0,
            )],
        );
        let observed = ExecutionBindings::new(
            Some(ImageBinding::new(image_reference, IMAGE_DIGEST)),
            12,
            Some(ResourceState::Stopped),
            Some(DeviceIdentity::new("block", 8, 1, 41)),
            vec![MountHandleDescriptor::new(
                MountClass::Workspace,
                33,
                2049,
                82,
                0,
            )],
        );
        CanonicalRequest::new(context, self.gate.pin(), bindings, observed)
    }
}

#[test]
fn authorization_gate_disabled_mode_returns_an_immutable_proof() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let proof = fixture
        .gate
        .authorize(fixture.request(None, true, &format!("registry/app@{IMAGE_DIGEST}")))
        .expect("disabled compatibility mode allows");

    assert_eq!(proof.decision().reason, ReasonCode::AuthorizationDisabled);
    assert_eq!(proof.decision().policy_generation, 7);
    assert_eq!(proof.canonical().request_id(), "request-7");
}

#[test]
fn authorization_gate_shadow_mode_preserves_the_hypothetical_denial() {
    let fixture = Fixture::new(AuthorizationMode::Shadow);
    let proof = fixture
        .gate
        .authorize(fixture.request(
            Some(Role::Developer),
            true,
            &format!("registry/app@{IMAGE_DIGEST}"),
        ))
        .expect("shadow mode allows");

    assert_eq!(proof.decision().reason, ReasonCode::ShadowAllowed);
    assert_eq!(
        proof.decision().hypothetical_denial,
        Some(ReasonCode::PrivilegedContainerDenied)
    );
}

#[test]
fn shadow_mode_records_unapproved_mount_source_as_hypothetical_denial() {
    let fixture = Fixture::new(AuthorizationMode::Shadow);
    let mut request = fixture.request(
        Some(Role::Administrator),
        false,
        &format!("registry/app@{IMAGE_DIGEST}"),
    );
    request.context.facts.mount_sources_approved = Some(false);
    let proof = fixture
        .gate
        .authorize(request)
        .expect("shadow compatibility");
    assert_eq!(proof.decision().reason, ReasonCode::ShadowAllowed);
    assert_eq!(
        proof.decision().hypothetical_denial,
        Some(ReasonCode::MountSourceDenied)
    );
}

#[test]
fn authorization_gate_enforcement_returns_a_stable_denial() {
    let fixture = Fixture::new(AuthorizationMode::Enforce);
    let denial = fixture
        .gate
        .authorize(fixture.request(
            Some(Role::Auditor),
            false,
            &format!("registry/app@{IMAGE_DIGEST}"),
        ))
        .expect_err("auditor cannot mutate");

    assert_eq!(denial.code(), DenialCode::PolicyDenied);
    assert_eq!(denial.reason(), Some(ReasonCode::RoleNotAuthorized));
    assert_eq!(denial.request_id(), "request-7");
    assert_eq!(
        serde_json::to_string(&denial.code()).expect("serialize stable denial"),
        "\"policy-denied\""
    );
}

#[test]
fn authorization_gate_uses_the_policy_snapshot_pinned_by_the_request() {
    let dir = TempDir::new().expect("tempdir");
    let first = write_policy(&dir, "first.toml", 7, AuthorizationMode::Disabled);
    let second = write_policy(&dir, "second.toml", 8, AuthorizationMode::Enforce);
    let store = Arc::new(PolicyStore::load(first).expect("load first"));
    let gate = AuthorizationGate::new(Arc::clone(&store));
    let fixture = Fixture { _dir: dir, gate };
    let request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    let administrator = ResolvedPrincipal::new("root", Role::Administrator);
    store.reload(second, &administrator).expect("reload policy");

    let proof = fixture
        .gate
        .authorize(request)
        .expect("pinned disabled policy");

    assert_eq!(proof.decision().policy_generation, 7);
    assert_eq!(proof.decision().reason, ReasonCode::AuthorizationDisabled);
}

#[test]
fn authorization_gate_rejects_a_policy_generation_mismatch() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.policy_generation += 1;

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("mismatch denied");

    assert_eq!(denial.code(), DenialCode::PolicyGenerationMismatch);
}

#[test]
fn authorization_gate_rejects_a_policy_digest_mismatch() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.policy_digest[0] ^= 0xff;

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("mismatch denied");

    assert_eq!(denial.code(), DenialCode::PolicyDigestMismatch);
}

#[test]
fn authorization_gate_rejects_a_mutable_image_tag() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);

    let denial = fixture
        .gate
        .authorize(fixture.request(None, false, "registry/app:latest"))
        .expect_err("tag is mutable");

    assert_eq!(denial.code(), DenialCode::MutableImageReference);
}

#[test]
fn authorization_gate_rejects_an_image_digest_mismatch() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.observed.image.as_mut().expect("image").digest =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();

    let denial = fixture.gate.authorize(request).expect_err("image changed");

    assert_eq!(denial.code(), DenialCode::ImageDigestMismatch);
}

#[test]
fn authorization_gate_rejects_a_missing_image_binding() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.expected.image = None;
    request.observed.image = None;

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("context digest must have an execution binding");

    assert_eq!(denial.code(), DenialCode::ImageDigestMismatch);
}

#[test]
fn authorization_gate_rejects_a_non_uuid_resource_identity() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.context.resource.id.0 = "container-name".to_owned();

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("alias is not canonical");

    assert_eq!(denial.code(), DenialCode::NonCanonicalResource);
}

#[test]
fn authorization_gate_rejects_a_stale_resource_generation() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.observed.resource_generation = 13;

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("stale generation");

    assert_eq!(denial.code(), DenialCode::ResourceGenerationMismatch);
}

#[test]
fn authorization_gate_rejects_a_device_identity_mismatch() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.observed.device_identity = Some(DeviceIdentity::new("block", 8, 1, 42));

    let denial = fixture.gate.authorize(request).expect_err("device changed");

    assert_eq!(denial.code(), DenialCode::DeviceIdentityMismatch);
}

#[test]
fn authorization_gate_rejects_a_missing_required_lifecycle_state() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.context.facts.lifecycle_state = None;
    request.expected.state_precondition = None;
    request.observed.state_precondition = None;

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("execution state must be policy-visible");

    assert_eq!(denial.code(), DenialCode::StatePreconditionMismatch);
}

#[test]
fn authorization_gate_rejects_a_missing_required_device_binding() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.expected.device_identity = None;
    request.observed.device_identity = None;

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("policy-visible device must be bound");

    assert_eq!(denial.code(), DenialCode::DeviceIdentityMismatch);
}

#[test]
fn authorization_gate_rejects_a_device_class_mismatch() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.context.facts.device_classes = vec!["gpu".to_owned()];

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("device identity must match its policy-visible class");

    assert_eq!(denial.code(), DenialCode::DeviceIdentityMismatch);
}

#[test]
fn authorization_gate_rejects_multiple_classes_for_a_single_device_binding() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.context.facts.device_classes = vec!["block".to_owned(), "gpu".to_owned()];

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("every device class needs its own stable identity");

    assert_eq!(denial.code(), DenialCode::DeviceIdentityMismatch);
}

#[test]
fn authorization_gate_rejects_a_missing_required_mount_binding() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.expected.mount_handles.clear();
    request.observed.mount_handles.clear();

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("policy-visible mount must be bound");

    assert_eq!(denial.code(), DenialCode::MountHandleMismatch);
}

#[test]
fn authorization_gate_rejects_a_mount_class_mismatch() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.context.facts.mounts = vec![MountClass::HostPath];

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("mount handle must match its policy-visible class");

    assert_eq!(denial.code(), DenialCode::MountHandleMismatch);
}

#[test]
fn authorization_gate_rejects_an_extra_execution_mount() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    let extra = MountHandleDescriptor::new(MountClass::HostPath, 34, 2049, 83, 0);
    request.expected.mount_handles.push(extra.clone());
    request.observed.mount_handles.push(extra);

    let denial = fixture
        .gate
        .authorize(request)
        .expect_err("execution mount must be policy-visible");

    assert_eq!(denial.code(), DenialCode::MountHandleMismatch);
}

#[test]
fn authorization_gate_enforces_the_compare_and_swap_state() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.observed.state_precondition = Some(ResourceState::Running);

    let denial = fixture.gate.authorize(request).expect_err("state changed");

    assert_eq!(denial.code(), DenialCode::StatePreconditionMismatch);
}

#[test]
fn authorization_gate_rejects_an_open_mount_handle_mismatch() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let mut request = fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}"));
    request.observed.mount_handles[0] =
        MountHandleDescriptor::new(MountClass::Workspace, 33, 2049, 99, 0);

    let denial = fixture.gate.authorize(request).expect_err("handle changed");

    assert_eq!(denial.code(), DenialCode::MountHandleMismatch);
}

#[test]
fn authorization_gate_proof_binds_every_executor_safe_identity() {
    let fixture = Fixture::new(AuthorizationMode::Disabled);
    let proof = fixture
        .gate
        .authorize(fixture.request(None, false, &format!("registry/app@{IMAGE_DIGEST}")))
        .expect("canonical bindings are valid");
    let canonical = proof.canonical();

    assert_eq!(canonical.image_digest(), Some(IMAGE_DIGEST));
    assert_eq!(canonical.resource_id(), RESOURCE_UUID);
    assert_eq!(canonical.resource_generation(), 12);
    assert_eq!(canonical.state_precondition(), Some(ResourceState::Stopped));
    assert_eq!(
        canonical.device_identity(),
        Some(&DeviceIdentity::new("block", 8, 1, 41))
    );
    assert_eq!(
        canonical.device_identity().map(DeviceIdentity::class),
        Some("block")
    );
    assert_eq!(
        canonical.mount_handles(),
        &[MountHandleDescriptor::new(
            MountClass::Workspace,
            33,
            2049,
            82,
            0
        )]
    );
    assert_eq!(canonical.mount_handles()[0].class(), MountClass::Workspace);
}

fn write_policy(
    dir: &TempDir,
    name: &str,
    generation: u64,
    mode: AuthorizationMode,
) -> std::path::PathBuf {
    let mode = match mode {
        AuthorizationMode::Disabled => "disabled",
        AuthorizationMode::Shadow => "shadow",
        AuthorizationMode::Enforce => "enforce",
    };
    let path = dir.path().join(name);
    fs::write(
        &path,
        format!("schema_version = 1\ngeneration = {generation}\nmode = \"{mode}\"\n"),
    )
    .expect("write policy");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure policy mode");
    path
}
