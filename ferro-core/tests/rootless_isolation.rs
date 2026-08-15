#![cfg(target_os = "linux")]

#[path = "../../tests/support/qualification_fixture.rs"]
mod qualification_fixture;

use ferro_core::authorization::{Action, RequestOrigin, ResourceKind};
use ferro_core::rootless::{apply_user_namespace_mappings, RootlessConfig};
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
/// authenticated permit before the rootless mapping mutation.
#[test]
fn rootless_configuration_mutates_the_real_runtime_namespaces() {
    for mode in ["disabled", "shadow", "enforce"] {
        let before = ferro_core::observability::authorization_metrics_snapshot();
        let runtime_dir = qualification_fixture::configured_runtime(mode);
        let origin = RequestOrigin::cli_current().expect("authenticated CLI origin");
        let runtime = ContainerRuntime::new(runtime_dir.path())
            .expect("construct production runtime")
            .with_request_origin(origin.clone());
        let surface = runtime.surface_authorization().expect("surface authorization");
        let permit = surface.authorize_named(
            &origin, Action::VolumeCreate, ResourceKind::Volume, "rootless-namespace-fixture", 1,
        );
        if mode == "enforce" {
            let error = match permit {
                Ok(_) => panic!("enforce must deny before namespace mutation"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("PolicyDenied"), "stable enforce error: {error}");
        } else {
            let permit = permit.expect("compatibility mode admits rootless mapping");
            let config = RootlessConfig::from_system().expect("resolve production rootless config");
            let mut child = Command::new("unshare")
                .args(["--user", "--fork", "sleep", "30"])
                .spawn()
                .expect("launch the real rootless namespace runtime");
            let result = apply_user_namespace_mappings(std::path::Path::new("/proc"), child.id(), &config);
            let _ = child.kill();
            let _ = child.wait();
            permit.finish(result.is_ok()).expect("finish rootless permit");
            result.expect("apply production rootless mapping to real child procfs");
        }
        ferro_core::observability::persist_authorization_fixture_evidence(
            &format!("rootless-{mode}"), before,
            ferro_core::observability::authorization_metrics_snapshot(),
        ).expect("persist rootless qualification evidence");
    }
}
