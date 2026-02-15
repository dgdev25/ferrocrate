#![cfg(target_os = "linux")]

use ferro_core::rootless::RootlessConfig;

#[test]
fn resolves_rootless_config_from_system() {
    let config = RootlessConfig::from_system().expect("rootless config should resolve");
    assert!(config.uid_mapping.size > 0);
    assert!(config.gid_mapping.size > 0);
}
