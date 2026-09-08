#![cfg(target_os = "linux")]

use ferro_mgr::{
    admin::{AdminAuthorizer, AuthError},
    pki::{
        certificate_identity_from_der, CertificateAuthority, CertificateIdentity, CertificateRole,
        PkiError,
    },
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use rustls::pki_types::{pem::PemObject, CertificateDer};

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
fn authority_reloads_persisted_ca_for_enrollment_signing() {
    let authority = CertificateAuthority::new("ferro-node-root").unwrap();
    let certificate_pem = authority.certificate_pem().to_string();
    let key_pem = authority.private_key_pem();
    let reloaded = CertificateAuthority::from_pem(&certificate_pem, &key_pem).unwrap();
    let issued = reloaded
        .issue_node_certificate("cluster-a", "node-a")
        .unwrap();
    assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(reloaded.certificate_pem(), certificate_pem);
}

#[test]
fn issued_node_principal_round_trips_from_der() {
    let authority = CertificateAuthority::new("node-root").unwrap();
    let issued = authority
        .issue_node_certificate("cluster-a", "node-a")
        .unwrap();
    let mut reader = std::io::Cursor::new(issued.certificate_pem.as_bytes());
    let der = CertificateDer::pem_reader_iter(&mut reader).next().unwrap().unwrap();
    let identity = certificate_identity_from_der(der.as_ref()).unwrap();
    assert_eq!(identity.cluster_id, "cluster-a");
    assert_eq!(
        identity.role,
        CertificateRole::Node {
            node_id: "node-a".into()
        }
    );
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
