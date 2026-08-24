#![cfg(target_os = "linux")]

use ferro_mgr::{
    admin::{AdminAuthorizer, AuthError},
    pki::{CertificateAuthority, CertificateIdentity, CertificateRole, PkiError},
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};

#[test]
fn authority_issues_distinct_client_certificates() {
    let authority = CertificateAuthority::new("ferro-node-root").unwrap();
    let node = authority
        .issue_node_certificate("cluster-a", "node-a")
        .unwrap();
    let admin = authority.issue_admin_certificate("cluster-a").unwrap();
    assert!(authority
        .certificate_pem()
        .starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(node
        .certificate_pem
        .starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(admin
        .certificate_pem
        .starts_with("-----BEGIN CERTIFICATE-----"));
    assert_ne!(node.private_key_pem, admin.private_key_pem);
}

#[test]
fn authority_rejects_csr_without_client_auth() {
    let authority = CertificateAuthority::new("ferro-node-root").unwrap();
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    assert!(matches!(
        authority.sign_node_csr(&csr, "cluster-a", "node-a"),
        Err(PkiError::MissingClientAuth)
    ));
    let mut params = CertificateParams::default();
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    assert!(authority
        .sign_node_csr(&csr, "cluster-a", "node-a")
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn node_identity_cannot_use_admin_authorizer() {
    let authorizer = AdminAuthorizer::new("cluster-a");
    let certificate = CertificateIdentity {
        cluster_id: "cluster-a".into(),
        role: CertificateRole::Node {
            node_id: "node-a".into(),
        },
        expires_at: i64::MAX,
    };
    assert_eq!(
        authorizer.authorize(&certificate, "Inspect"),
        Err(AuthError::WrongRole)
    );
}

#[test]
fn admin_identity_is_limited_to_admin_methods() {
    let authorizer = AdminAuthorizer::new("cluster-a");
    let certificate = CertificateIdentity {
        cluster_id: "cluster-a".into(),
        role: CertificateRole::Administrator,
        expires_at: i64::MAX,
    };
    assert_eq!(
        authorizer.authorize(&certificate, "ControlStream"),
        Err(AuthError::MethodDenied)
    );
    assert!(authorizer.authorize(&certificate, "Inspect").is_ok());
}
