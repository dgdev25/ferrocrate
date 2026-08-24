#![cfg(target_os = "linux")]

#![cfg(target_os = "linux")]

#[path = "../../tests/support/qualification_fixture.rs"]
mod qualification_fixture;

use ferro_core::authorization::{Action, RequestOrigin, ResourceKind};
use ferro_core::rootless::{apply_user_namespace_mappings_authorized, RootlessConfig};
use ferro_core::runtime::ContainerRuntime;
use std::process::Command;

#[test]
fn resolves_rootless_config_from_system() {
    let config = RootlessConfig::from_system().expect("rootless config should resolve");
    assert!(config.uid_mapping.size > 0);
    assert!(config.gid_mapping.size > 0);
}

/// Uses the host's real `unshare(2)` launcher and `/proc/<pid>` mapping files,
/// with the production setuid mapping-helper fallback where needed. There is
/// no proc-shaped substitute. The surrounding production runtime obtains an
/// authenticated permit for the exact rootless mapping mutation.
#[test]
fn rootless_configuration_mutates_the_real_runtime_namespaces() {
    // A rootful qualification run resolves the caller as the trusted
    // administrator. Enforce mode must deny ordinary callers, but an
    // administrator is intentionally allowed to exercise the real mapping
    // path; do not turn that valid role distinction into a false failure.
    let trusted_administrator = nix::unistd::geteuid().is_root();
    for mode in ["disabled", "shadow", "enforce"] {
        let before = ferro_core::observability::authorization_metrics_snapshot();
        let runtime_dir = qualification_fixture::configured_runtime(mode);
        let origin = RequestOrigin::cli_current().expect("authenticated CLI origin");
        let runtime = ContainerRuntime::new(runtime_dir.path())
            .expect("construct production runtime")
            .with_request_origin(origin.clone());
        let surface = runtime
            .surface_authorization()
            .expect("surface authorization");
        let permit = surface.authorize_named(
            &origin,
            Action::RootlessMapping,
            ResourceKind::RootlessMapping,
            "rootless-namespace-fixture",
            1,
        );
        if mode == "enforce" && !trusted_administrator {
            let error = match permit {
                Ok(_) => panic!("enforce must deny before namespace mutation"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("PolicyDenied"),
                "stable enforce error: {error}"
            );
        } else {
            let permit = permit.unwrap_or_else(|error| {
                panic!("{mode} compatibility mode admits rootless mapping: {error}")
            });
            let config = RootlessConfig::from_system().expect("resolve production rootless config");
            let mut child = Command::new("unshare")
                .args(["--user", "--fork", "sleep", "30"])
                .spawn()
                .expect("launch the real rootless namespace runtime");
            let result = apply_user_namespace_mappings_authorized(
                std::path::Path::new("/proc"),
                child.id(),
                &config,
                "rootless-namespace-fixture",
                1,
                permit,
            );
            let _ = child.kill();
            let _ = child.wait();
            result.expect("apply production rootless mapping to real child procfs");
        }
        ferro_core::observability::persist_authorization_fixture_evidence(
            &format!("rootless-{mode}"),
            before,
            ferro_core::observability::authorization_metrics_snapshot(),
        )
        .expect("persist rootless qualification evidence");
    }
}
