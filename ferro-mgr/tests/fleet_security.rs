#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;

use ferro_mgr::fleet::{
    certificate_principal, request_digest, AuditJournal, AuditResult, BrowserIdentity, FleetRole,
    SessionStore,
};
use serde_json::json;

#[test]
fn sessions_are_short_lived_and_bound_to_identity_and_role() {
    let sessions = SessionStore::new();
    let identity = BrowserIdentity {
        principal: "mtls:8a2f".into(),
        role: FleetRole::Operate,
    };
    let token = sessions.mint(identity.clone(), 1_000, 60).unwrap();

    assert_eq!(sessions.authenticate(&token, 1_059), Some(identity));
    assert_eq!(sessions.authenticate(&token, 1_060), None);
    assert_eq!(sessions.authenticate("wrong-token", 1_001), None);
}

#[test]
fn audit_is_append_only_and_records_denials_with_request_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fleet-audit.jsonl");
    let journal = AuditJournal::open(&path).unwrap();
    let request = json!({"node_id":"node-a","action":"run","image":"alpine"});
    let expected_digest = request_digest(&request);

    journal
        .append(
            "mtls:view-cert",
            FleetRole::View,
            "run_container",
            &request,
            AuditResult::Denied,
            1_000,
        )
        .unwrap();
    journal
        .append(
            "mtls:operator-cert",
            FleetRole::Operate,
            "run_container",
            &request,
            AuditResult::Succeeded,
            1_001,
        )
        .unwrap();

    let entries = journal.read_all().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].request_digest, expected_digest);
    assert_eq!(entries[0].result, AuditResult::Denied);
    assert_eq!(entries[1].result, AuditResult::Succeeded);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn canonical_request_digest_is_independent_of_object_key_order() {
    assert_eq!(
        request_digest(&json!({"node":"a","action":"stop"})),
        request_digest(&json!({"action":"stop","node":"a"}))
    );
}

#[test]
fn operator_certificate_principal_is_a_stable_sha256_fingerprint() {
    let authority = ferro_mgr::pki::CertificateAuthority::new("operator-root").unwrap();
    let certificate = authority.issue_admin_certificate("cluster-a").unwrap();
    let first = certificate_principal(certificate.certificate_pem.as_bytes()).unwrap();
    let second = certificate_principal(certificate.certificate_pem.as_bytes()).unwrap();
    assert_eq!(first, second);
    assert!(first.starts_with("mtls:"));
    assert_eq!(first.len(), "mtls:".len() + 32);
    assert!(certificate_principal(b"not pem").is_err());
}
