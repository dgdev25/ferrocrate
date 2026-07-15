use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRole {
    Node { node_id: String },
    Administrator,
}

#[derive(Debug, Error)]
pub enum PkiError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("certificate signing request does not request client authentication")]
    MissingClientAuth,
}

#[derive(Debug)]
pub struct IssuedCertificate {
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub role: CertificateRole,
}

pub struct CertificateAuthority {
    params: CertificateParams,
    key: KeyPair,
    certificate_pem: String,
}

impl CertificateAuthority {
    pub fn new(common_name: &str) -> Result<Self, PkiError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate()?;
        let certificate = params.self_signed(&key)?;
        Ok(Self { params, key, certificate_pem: certificate.pem() })
    }

    pub fn certificate_pem(&self) -> &str { &self.certificate_pem }

    pub fn issue_node_certificate(&self, cluster_id: &str, node_id: &str) -> Result<IssuedCertificate, PkiError> {
        self.issue(cluster_id, node_id, CertificateRole::Node { node_id: node_id.into() })
    }

    pub fn issue_admin_certificate(&self, cluster_id: &str) -> Result<IssuedCertificate, PkiError> {
        self.issue(cluster_id, "administrator", CertificateRole::Administrator)
    }

    pub fn sign_node_csr(&self, csr_pem: &str, cluster_id: &str, node_id: &str) -> Result<String, PkiError> {
        let request = CertificateSigningRequestParams::from_pem(csr_pem)?;
        if !request.params.extended_key_usages.contains(&ExtendedKeyUsagePurpose::ClientAuth) {
            return Err(PkiError::MissingClientAuth);
        }
        let mut params = request.params;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, format!("ferrocrate/{cluster_id}/{node_id}"));
        params.is_ca = IsCa::NoCa;
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        Ok(CertificateSigningRequestParams { params, public_key: request.public_key }.signed_by(&issuer)?.pem())
    }

    fn issue(&self, cluster_id: &str, subject: &str, role: CertificateRole) -> Result<IssuedCertificate, PkiError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, format!("ferrocrate/{cluster_id}/{subject}"));
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate()?;
        let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
        let certificate = params.signed_by(&key, &issuer)?;
        Ok(IssuedCertificate { certificate_pem: certificate.pem(), private_key_pem: key.serialize_pem(), role })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateIdentity {
    pub cluster_id: String,
    pub role: CertificateRole,
    pub expires_at: i64,
}

impl CertificateIdentity {
    pub fn is_valid_for(&self, cluster_id: &str, now_unix_secs: i64) -> bool {
        self.cluster_id == cluster_id && self.expires_at > now_unix_secs
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs() as i64)
}
