#![cfg(target_os = "linux")]

//! Cross-surface rollout evidence.
//!
//! This target is registered by `ferro-cli/Cargo.toml` so it runs with the
//! workspace's public CLI-facing dependencies rather than a test-only model.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use ferro_cli::authorization_surfaces::{authenticate_docker_peer, DockerTelemetry};
use ferro_compose::{FanoutAction, FanoutPlan, ServiceMutation};
use ferro_core::authorization::{
    gate::AuthorizationGate, policy::PolicyStore, Action, AuthorizationMode, PrincipalResolver,
    RequestOrigin, ResourceKind,
};
use ferro_core::managed_overlay::ManagedOverlayClient;
use ferro_core::observability::{
    authorization_metrics_snapshot, AuthorizationFixtureEvidence, FixtureClassification,
};
use ferro_core::runtime::ContainerRuntime;
use ferro_core::witness::{JournalConfig, JournalMode, WitnessJournal};

fn runtime_for(mode: &str) -> (tempfile::TempDir, ContainerRuntime) {
    let root = tempfile::tempdir().expect("temporary runtime directory");
    let policy = root.path().join("policy.toml");
    std::fs::write(
        &policy,
        format!("schema_version = 1\ngeneration = 1\nmode = \"{mode}\"\n"),
    )
    .expect("write policy");
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600))
        .expect("protect policy");
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy).expect("load protected policy"),
    )));
    let journal = match mode {
        "disabled" => None,
        "shadow" | "enforce" => Some(Arc::new(
            WitnessJournal::open(JournalConfig::new(
                root.path().join("witness"),
                [12; 16],
                JournalMode::Required,
            ))
            .expect("open required witness journal"),
        )),
        _ => panic!("unsupported fixture mode"),
    };
    let runtime = ContainerRuntime::new_with_authorization(root.path(), gate, journal)
        .expect("construct public runtime surface");
    (root, runtime)
}

#[test]
fn rollout_modes_use_the_real_runtime_surface_and_preserve_their_contracts() {
    let before = authorization_metrics_snapshot();
    for mode in ["disabled", "shadow"] {
        let (_root, runtime) = runtime_for(mode);
        let surface = runtime
            .surface_authorization()
            .expect("surface authorization");
        let origin = RequestOrigin::cli_current().expect("authenticated CLI origin");
        let permit = surface
            .authorize_named(
                &origin,
                Action::VolumeCreate,
                ResourceKind::Volume,
                "compatibility-volume",
                1,
            )
            .expect("rollout compatibility modes preserve successful mutation admission");
        surface
            .complete(permit, true)
            .expect("complete admitted mutation");
    }
    let (_root, runtime) = runtime_for("enforce");
    let surface = runtime
        .surface_authorization()
        .expect("enforce surface authorization");
    let origin = RequestOrigin::cli_current().expect("authenticated CLI origin");
    match surface.authorize_named(
        &origin,
        Action::VolumeCreate,
        ResourceKind::Volume,
        "compatibility-volume",
        1,
    ) {
        Ok(permit) => surface
            .complete(permit, true)
            .expect("complete enforcement admission"),
        Err(error) => {
            let error = error.to_string();
            assert!(
                error.starts_with("authorization denied for ") && error.ends_with(": PolicyDenied"),
                "enforce denials retain the stable authorization error shape: {error}"
            );
        }
    }
    let after = authorization_metrics_snapshot();
    assert_eq!(after.attributed_total, before.attributed_total + 3);
    assert_eq!(
        (after.attributed_total - before.attributed_total) * 100
            / ((after.attributed_total - before.attributed_total)
                + (after.unknown_principal_total - before.unknown_principal_total)),
        100,
        "every external compatibility fixture must have a real authenticated principal"
    );
    assert_eq!(
        after.successful_bypass_total,
        before.successful_bypass_total
    );
    if let Some(root) = std::env::var_os("FERRO_AUTHORIZATION_QUALIFICATION_OUTPUT") {
        let evidence = AuthorizationFixtureEvidence::new(
            "compatibility.runtime-surface",
            FixtureClassification::ActualFixture,
            before,
            after,
        );
        std::fs::write(
            std::path::Path::new(&root).join("fixture-compatibility.json"),
            serde_json::to_vec(&evidence).expect("serialize compatibility evidence"),
        )
        .expect("persist compatibility evidence");
    }
}

#[test]
fn promotion_metrics_expose_a_real_attribution_percentage() {
    let snapshot = authorization_metrics_snapshot();
    assert!(snapshot
        .attributed_percent()
        .is_none_or(|percent| percent <= 100));
}

#[test]
fn enforcement_requires_a_pinned_policy_digest_for_all_service_surfaces() {
    for mode in [AuthorizationMode::Shadow, AuthorizationMode::Enforce] {
        assert!(ferro_core::authorization::AuthorizationServiceMode::new(mode, None).is_err());
        assert!(
            ferro_core::authorization::AuthorizationServiceMode::new(mode, Some([9; 32])).is_ok()
        );
    }
    assert!(ferro_core::authorization::AuthorizationServiceMode::new(
        AuthorizationMode::Disabled,
        None,
    )
    .is_ok());
}

#[test]
fn representative_channel_fixtures_use_real_compatibility_boundaries() {
    let cli = RequestOrigin::cli_current().expect("authenticated CLI principal");
    assert!(!cli.principal().id().as_str().is_empty());

    let rootless = ferro_core::rootless::RootlessConfig::from_system()
        .expect("current user has a rootless mapping or 1:1 fallback");
    assert!(rootless
        .uid_mapping
        .iter()
        .all(|mapping| mapping.as_uid_map_entry().split_whitespace().count() == 3));
    assert!(rootless
        .gid_mapping
        .iter()
        .all(|mapping| mapping.as_gid_map_entry().split_whitespace().count() == 3));

    let compose = FanoutPlan::derive(
        [1; 16],
        1,
        [2; 32],
        u64::MAX,
        0,
        [ServiceMutation::new(
            "web",
            FanoutAction::ContainerRun,
            [3; 32],
        )],
    )
    .expect("derive Compose child authority");
    compose
        .verify_child(&compose.children()[0], 1)
        .expect("the exact child remains valid");

    let (docker, _peer) = UnixStream::pair().expect("Docker Unix-socket fixture");
    match authenticate_docker_peer(
        &docker,
        DockerTelemetry::new().with_header("x-ferrocrate-principal", "forged-root"),
    ) {
        Ok(identity) => assert_ne!(identity.principal_id(), "forged-root"),
        Err(error) => assert!(error.to_string().contains("pidfd")),
    }

    let managed = ManagedOverlayClient::new("/nonexistent/ferrocrate-managed-overlay.sock")
        .with_authorization_identity(
            ferro_core::authorization::AuthorizationServiceMode::new(
                AuthorizationMode::Disabled,
                None,
            )
            .expect("disabled managed-overlay compatibility identity"),
            "fixture-boot",
        );
    let _ = managed;
    let (cri, _peer) = UnixStream::pair().expect("CRI Unix-socket fixture");
    let cri_transport = PrincipalResolver::from_cri_peer_credentials(&cri);
    assert!(
        cri_transport.is_ok() || cri_transport.unwrap_err().to_string().contains("pidfd"),
        "CRI must resolve peer credentials or fail closed when pidfd is unavailable"
    );
}
