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
