use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

use ferro_core::authorization::policy::{PolicyError, PolicyStore, MAX_POLICY_BYTES};
use ferro_core::authorization::{Action, AuthorizationMode, Role};
use tempfile::TempDir;

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
        (Action::ContainerCreate, "\"container.create\""),
        (Action::ContainerRun, "\"container.run\""),
        (Action::ContainerExec, "\"container.exec\""),
        (Action::ContainerPause, "\"container.pause\""),
        (Action::ContainerResume, "\"container.resume\""),
        (Action::ContainerStop, "\"container.stop\""),
        (Action::ContainerKill, "\"container.kill\""),
        (Action::ContainerRestart, "\"container.restart\""),
        (Action::ContainerDelete, "\"container.delete\""),
        (Action::ContainerRename, "\"container.rename\""),
        (Action::ImagePull, "\"image.pull\""),
        (Action::ImageDelete, "\"image.delete\""),
        (Action::VolumeCreate, "\"volume.create\""),
        (Action::VolumeDelete, "\"volume.delete\""),
        (Action::VolumeMount, "\"volume.mount\""),
        (Action::VolumeUnmount, "\"volume.unmount\""),
        (Action::NetworkCreate, "\"network.create\""),
        (Action::NetworkDelete, "\"network.delete\""),
        (Action::NetworkAttach, "\"network.attach\""),
        (Action::NetworkDetach, "\"network.detach\""),
        (Action::DeviceUse, "\"device.use\""),
        (Action::PolicyReload, "\"policy.reload\""),
        (Action::PolicyRollback, "\"policy.rollback\""),
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
