#![cfg(target_os = "linux")]

use ferro_core::rootless::{apply_user_namespace_mappings, RootlessConfig, RootlessMapping};

#[test]
fn resolves_rootless_config_from_system() {
    let config = RootlessConfig::from_system().expect("rootless config should resolve");
    assert!(config.uid_mapping.size > 0);
    assert!(config.gid_mapping.size > 0);
}

#[test]
fn rootless_configuration_mutates_the_configured_runtime_proc_view() {
    let runtime = tempfile::tempdir().expect("configured rootless runtime");
    let pid = 4242;
    let proc_dir = runtime.path().join(pid.to_string());
    std::fs::create_dir(&proc_dir).expect("create runtime proc entry");
    std::fs::write(proc_dir.join("setgroups"), "").expect("seed setgroups control");
    let config = RootlessConfig {
        username: "qualification".into(),
        uid_mapping: RootlessMapping {
            container_id: 0,
            host_id: 120_000,
            size: 65_536,
        },
        gid_mapping: RootlessMapping {
            container_id: 0,
            host_id: 220_000,
            size: 65_536,
        },
    };
    apply_user_namespace_mappings(runtime.path(), pid, &config)
        .expect("apply production rootless mappings");
    assert_eq!(
        std::fs::read_to_string(proc_dir.join("setgroups")).unwrap(),
        "deny\n"
    );
    assert_eq!(
        std::fs::read_to_string(proc_dir.join("uid_map")).unwrap(),
        "0 120000 65536\n"
    );
    assert_eq!(
        std::fs::read_to_string(proc_dir.join("gid_map")).unwrap(),
        "0 220000 65536\n"
    );
}
