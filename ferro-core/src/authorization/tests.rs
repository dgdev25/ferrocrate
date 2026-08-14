use super::{
    Action, AuthorizationMode, PolicyDocument, ReasonCode, RequestContext, RequestFacts,
    ResolvedPrincipal, Resource, ResourceKind, Role,
};

fn policy(mode: AuthorizationMode) -> PolicyDocument {
    PolicyDocument {
        schema_version: 1,
        generation: 1,
        mode,
    }
}

fn request(action: Action, principal: Option<(&str, Role)>, owner: Option<&str>) -> RequestContext {
    let principal = principal.map(|(id, role)| ResolvedPrincipal::new(id, role));
    let owner = owner.map(super::PrincipalId::new);
    let resource = Resource::canonical(ResourceKind::Container, "container-1", owner, 3);
    RequestContext::resolved(
        "request-1",
        principal,
        action,
        resource,
        RequestFacts::default(),
    )
}

#[test]
fn the_five_roles_apply_the_native_domain_rules() {
    let policy = policy(AuthorizationMode::Enforce);
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
    let policy = policy(AuthorizationMode::Enforce);

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
    let policy = policy(AuthorizationMode::Enforce);
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
    let decision = policy(AuthorizationMode::Enforce).evaluate(&request(
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

    let decision = policy(AuthorizationMode::Disabled).evaluate(&candidate);

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

    let decision = policy(AuthorizationMode::Shadow).evaluate(&candidate);

    assert!(decision.allowed);
    assert_eq!(decision.reason, ReasonCode::ShadowAllowed);
    assert_eq!(
        decision.hypothetical_denial,
        Some(ReasonCode::PrivilegedContainerDenied)
    );
}
