use ferro_mgr::agent::credentials::{CredentialError, CredentialStore};
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

#[test]
fn credentials_are_created_once_with_exact_length() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("node.key");
    let store = CredentialStore::new(&path);
    let first = store.load_or_generate().unwrap();
    let second = store.load_or_generate().unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 32);
}

#[test]
fn truncated_credentials_are_rejected() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("node.key");
    std::fs::write(&path, [1_u8; 4]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        CredentialStore::new(path).load_or_generate(),
        Err(CredentialError::Truncated)
    ));
}
