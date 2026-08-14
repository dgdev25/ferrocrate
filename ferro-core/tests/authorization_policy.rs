use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

use ferro_core::authorization::policy::{PolicyError, PolicyStore, MAX_POLICY_BYTES};
use ferro_core::authorization::{
    Action, AuthorizationMode, PolicyDocument, ReasonCode, RequestContext, RequestFacts, Resource,
    ResourceKind, Role,
};
use tempfile::TempDir;

fn policy(generation: u64, mode: AuthorizationMode) -> PolicyDocument {
    PolicyDocument {
        schema_version: 1,
        generation,
        mode,
    }
}

fn request(action: Action, principal: Option<(&str, Role)>, owner: Option<&str>) -> RequestContext {
    RequestContext {
        request_id: "request-1".to_owned(),
        principal: principal.map(|(id, _)| id.to_owned()),
        role: principal.map(|(_, role)| role),
        action,
        resource: Resource {
            kind: ResourceKind::Container,
            id: "container-1".to_owned(),
            owner: owner.map(str::to_owned),
            generation: 3,
        },
        facts: RequestFacts::default(),
    }
}

fn write_policy(dir: &TempDir, name: &str, generation: u64, mode: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    fs::write(
        &path,
        format!("schema_version = 1\ngeneration = {generation}\nmode = \"{mode}\"\n"),
    )
    .expect("write policy");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure policy mode");
    path
}

#[test]
fn actions_have_stable_domain_serialization() {
    let cases = [
        (Action::ContainerRun, "\"container.run\""),
        (Action::ContainerExec, "\"container.exec\""),
        (Action::ImagePull, "\"image.pull\""),
        (Action::VolumeMount, "\"volume.mount\""),
        (Action::NetworkAttach, "\"network.attach\""),
        (Action::DeviceUse, "\"device.use\""),
        (Action::PolicyReload, "\"policy.reload\""),
    ];

    for (action, expected) in cases {
        assert_eq!(
            serde_json::to_string(&action).expect("serialize action"),
            expected
        );
        assert_eq!(
            serde_json::from_str::<Action>(expected).expect("deserialize action"),
            action
        );
    }
}

#[test]
fn the_five_policy_roles_have_stable_names() {
    let cases = [
        (Role::Administrator, "\"administrator\""),
        (Role::Operator, "\"operator\""),
        (Role::Developer, "\"developer\""),
        (Role::Auditor, "\"auditor\""),
        (Role::RuntimeCleanup, "\"runtime-cleanup\""),
    ];

    for (role, expected) in cases {
        assert_eq!(
            serde_json::to_string(&role).expect("serialize role"),
            expected
        );
        assert_eq!(
            serde_json::from_str::<Role>(expected).expect("deserialize role"),
            role
        );
    }
}

#[test]
fn the_five_roles_apply_the_native_domain_rules() {
    let policy = policy(1, AuthorizationMode::Enforce);
    let cases = [
        (
            Role::Administrator,
            Action::ContainerRun,
            true,
            ReasonCode::RoleAllowed,
        ),
        (
            Role::Operator,
            Action::ContainerRun,
            true,
            ReasonCode::RoleAllowed,
        ),
        (
            Role::Developer,
            Action::ContainerRun,
            true,
            ReasonCode::RoleAllowed,
        ),
        (
            Role::Auditor,
            Action::ContainerRun,
            false,
            ReasonCode::RoleNotAuthorized,
        ),
        (
            Role::RuntimeCleanup,
            Action::ContainerDelete,
            true,
            ReasonCode::RoleAllowed,
        ),
    ];

    for (role, action, allowed, reason) in cases {
        let decision = policy.evaluate(&request(action, Some(("alice", role)), Some("alice")));
        assert_eq!(decision.allowed, allowed, "unexpected result for {role:?}");
        assert_eq!(decision.reason, reason, "unexpected reason for {role:?}");
    }
}

#[test]
fn developer_access_is_scoped_to_owned_resources() {
    let policy = policy(1, AuthorizationMode::Enforce);

    let owned = policy.evaluate(&request(
        Action::ContainerRun,
        Some(("alice", Role::Developer)),
        Some("alice"),
    ));
    assert!(owned.allowed);
    assert_eq!(owned.reason, ReasonCode::RoleAllowed);

    let another_users = policy.evaluate(&request(
        Action::ContainerRun,
        Some(("alice", Role::Developer)),
        Some("bob"),
    ));
    assert!(!another_users.allowed);
    assert_eq!(another_users.reason, ReasonCode::ResourceOwnerMismatch);
}

#[test]
fn developer_cannot_run_privileged_container() {
    let policy = policy(1, AuthorizationMode::Enforce);
    let mut candidate = request(
        Action::ContainerRun,
        Some(("alice", Role::Developer)),
        Some("alice"),
    );
    candidate.facts.privileged = true;

    let decision = policy.evaluate(&candidate);

    assert!(!decision.allowed);
    assert_eq!(decision.reason, ReasonCode::PrivilegedContainerDenied);
    assert_eq!(decision.policy_generation, 1);
}

#[test]
fn enforcement_denies_an_unknown_principal() {
    let decision = policy(1, AuthorizationMode::Enforce).evaluate(&request(
        Action::ContainerRun,
        None,
        Some("alice"),
    ));

    assert!(!decision.allowed);
    assert_eq!(decision.reason, ReasonCode::UnknownPrincipal);
}

#[test]
fn disabled_mode_preserves_compatibility() {
    let mut candidate = request(Action::ContainerRun, None, None);
    candidate.facts.privileged = true;

    let decision = policy(1, AuthorizationMode::Disabled).evaluate(&candidate);

    assert!(decision.allowed);
    assert_eq!(decision.reason, ReasonCode::AuthorizationDisabled);
    assert_eq!(decision.hypothetical_denial, None);
}

#[test]
fn shadow_mode_allows_but_reports_the_hypothetical_denial() {
    let mut candidate = request(
        Action::ContainerRun,
        Some(("alice", Role::Developer)),
        Some("alice"),
    );
    candidate.facts.privileged = true;

    let decision = policy(1, AuthorizationMode::Shadow).evaluate(&candidate);

    assert!(decision.allowed);
    assert_eq!(decision.reason, ReasonCode::ShadowAllowed);
    assert_eq!(
        decision.hypothetical_denial,
        Some(ReasonCode::PrivilegedContainerDenied)
    );
}

#[test]
fn reload_rejects_generation_rollback_and_keeps_the_active_snapshot() {
    let dir = TempDir::new().expect("tempdir");
    let current = write_policy(&dir, "current.toml", 2, "enforce");
    let rollback = write_policy(&dir, "rollback.toml", 1, "disabled");
    let store = PolicyStore::load(&current).expect("load current policy");
    let original_digest = store.snapshot().digest;

    let error = store
        .reload(&rollback, "host-administrator")
        .expect_err("rollback must fail");

    assert!(matches!(
        error,
        PolicyError::Rollback {
            current: 2,
            candidate: 1
        }
    ));
    let retained = store.snapshot();
    assert_eq!(retained.generation, 2);
    assert_eq!(retained.digest, original_digest);
    assert_eq!(retained.document.mode, AuthorizationMode::Enforce);
}

#[test]
fn policy_snapshot_hashes_the_exact_validated_source() {
    let dir = TempDir::new().expect("tempdir");
    let path = write_policy(&dir, "policy.toml", 7, "shadow");
    let source = fs::read(&path).expect("read source");

    let snapshot = PolicyStore::load(&path).expect("load policy").snapshot();

    use sha2::{Digest, Sha256};
    let expected: [u8; 32] = Sha256::digest(&source).into();
    assert_eq!(snapshot.generation, 7);
    assert_eq!(snapshot.digest, expected);
    assert_eq!(snapshot.document.mode, AuthorizationMode::Shadow);
}

#[test]
fn policy_loader_rejects_symlinks() {
    let dir = TempDir::new().expect("tempdir");
    let target = write_policy(&dir, "target.toml", 1, "disabled");
    let link = dir.path().join("link.toml");
    symlink(&target, &link).expect("create symlink");

    let error = PolicyStore::load(&link).expect_err("symlink must fail");

    assert!(matches!(error, PolicyError::Symlink));
}

#[test]
fn policy_loader_validates_file_owner_and_mode() {
    let dir = TempDir::new().expect("tempdir");
    let path = write_policy(&dir, "policy.toml", 1, "disabled");
    PolicyStore::load(&path).expect("current owner with 0600 mode is valid");

    fs::set_permissions(&path, fs::Permissions::from_mode(0o622)).expect("change mode");
    let error = PolicyStore::load(&path).expect_err("writable-by-others policy must fail");

    assert!(matches!(error, PolicyError::UnsafeMode { mode: 0o622 }));
}

#[test]
fn policy_loader_rejects_sources_larger_than_one_mibibyte() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("oversize.toml");
    fs::write(&path, vec![b' '; MAX_POLICY_BYTES + 1]).expect("write oversized policy");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("secure mode");

    let error = PolicyStore::load(&path).expect_err("oversized policy must fail");

    assert!(matches!(
        error,
        PolicyError::TooLarge {
            maximum: MAX_POLICY_BYTES
        }
    ));
}
