#![cfg(target_os = "linux")]

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ferro_mgr::{
    enrollment::EnrollmentService,
    pki::CertificateAuthority,
    store::{Enrollment, ManagerStore, ScopedToken},
};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use tempfile::tempdir;

#[test]
fn scoped_enrollment_signs_csr_and_consumes_token_once() {
    let directory = tempdir().unwrap();
    let store = Arc::new(ManagerStore::open(directory.path().join("manager.sqlite")).unwrap());
    let service = EnrollmentService::new("cluster-a", store.clone());
    let secret = [6; 32];
    let token = store
        .create_token(ScopedToken {
            secret,
            expected_node: "node-a".into(),
            approved_endpoint: "198.51.100.8:51820".into(),
            overlay_scope: "all".into(),
            expires_at: i64::MAX,
        })
        .unwrap();
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    let certificate = service
        .enroll_csr(
            &URL_SAFE_NO_PAD.encode(token.secret),
            Enrollment {
                node_id: "node-a".into(),
                public_key: vec![1; 32],
                endpoint: "198.51.100.8:51820".into(),
            },
            &csr,
            &CertificateAuthority::new("node-root").unwrap(),
        )
        .unwrap();
    assert!(certificate.starts_with("-----BEGIN CERTIFICATE-----"));
}

#[test]
fn enrolled_csr_gets_only_bounded_node_client_identity() {
    use x509_parser::{pem::parse_x509_pem, prelude::FromDer};
    let ca = CertificateAuthority::new("node-root").unwrap();
    // Exercise both newly generated and reloaded CA issuance.
    let reloaded =
        CertificateAuthority::from_pem(ca.certificate_pem(), &ca.private_key_pem()).unwrap();
    for authority in [&ca, &reloaded] {
        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(vec!["manager.example.test".into(), "127.0.0.1".into()])
                .unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
        ];
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let issued = authority
            .sign_node_csr(&csr, "cluster-a", "node-a")
            .unwrap();
        let (_, pem) = parse_x509_pem(issued.as_bytes()).unwrap();
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents).unwrap();
        let usage = cert.extended_key_usage().unwrap().unwrap().value;
        assert!(usage.client_auth);
        assert!(
            !usage.server_auth,
            "node certificates must never authenticate a manager server"
        );
        assert!(cert.subject_alternative_name().unwrap().is_none());
        assert!(!cert.is_ca());
        let usage = cert.key_usage().unwrap().unwrap().value;
        assert!(usage.digital_signature());
        assert!(!usage.key_cert_sign());
        let now = ferro_mgr::pki::unix_now();
        assert!(cert.validity().not_before.timestamp() <= now);
        assert!(cert.validity().not_after.timestamp() > now);
        assert!(cert.validity().not_after.timestamp() <= now + 24 * 60 * 60);
        assert_eq!(
            cert.subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap(),
            "ferrocrate/cluster-a/node-a"
        );
        assert_eq!(
            cert.public_key().subject_public_key.data.as_ref(),
            key.public_key_raw()
        );
    }
}
