use ferro_mgr::{admin::{AdminAuthorizer, AuthError}, pki::{CertificateIdentity, CertificateRole}};

#[test]
fn node_identity_cannot_use_admin_authorizer() {
    let authorizer = AdminAuthorizer::new("cluster-a");
    let certificate = CertificateIdentity { cluster_id: "cluster-a".into(), role: CertificateRole::Node { node_id: "node-a".into() }, expires_at: i64::MAX };
    assert_eq!(authorizer.authorize(&certificate, "Inspect"), Err(AuthError::WrongRole));
}

#[test]
fn admin_identity_is_limited_to_admin_methods() {
    let authorizer = AdminAuthorizer::new("cluster-a");
    let certificate = CertificateIdentity { cluster_id: "cluster-a".into(), role: CertificateRole::Administrator, expires_at: i64::MAX };
    assert_eq!(authorizer.authorize(&certificate, "ControlStream"), Err(AuthError::MethodDenied));
    assert!(authorizer.authorize(&certificate, "Inspect").is_ok());
}
