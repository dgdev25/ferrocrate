use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
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
    #[error("certificate PEM is invalid")]
    InvalidPem,
    #[error("certificate principal is invalid")]
    InvalidPrincipal,
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
    loaded: bool,
}

impl CertificateAuthority {
    pub fn new(common_name: &str) -> Result<Self, PkiError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate()?;
        let certificate = params.self_signed(&key)?;
        Ok(Self {
            params,
            key,
            certificate_pem: certificate.pem(),
            loaded: false,
        })
    }

    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn private_key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    pub fn from_pem(certificate_pem: &str, private_key_pem: &str) -> Result<Self, PkiError> {
        let key = KeyPair::from_pem(private_key_pem)?;
        let _ = Issuer::from_ca_cert_pem(certificate_pem, &key)?;
        Ok(Self {
            params: CertificateParams::default(),
            key,
            certificate_pem: certificate_pem.to_string(),
            loaded: true,
        })
    }

    pub fn issue_node_certificate(
        &self,
        cluster_id: &str,
        node_id: &str,
    ) -> Result<IssuedCertificate, PkiError> {
        self.issue(
            cluster_id,
            node_id,
            CertificateRole::Node {
                node_id: node_id.into(),
            },
        )
    }

    pub fn issue_admin_certificate(&self, cluster_id: &str) -> Result<IssuedCertificate, PkiError> {
        self.issue(cluster_id, "administrator", CertificateRole::Administrator)
    }

    pub fn sign_node_csr(
        &self,
        csr_pem: &str,
        cluster_id: &str,
        node_id: &str,
    ) -> Result<String, PkiError> {
        let request = CertificateSigningRequestParams::from_pem(csr_pem)?;
        if !request
            .params
            .extended_key_usages
            .contains(&ExtendedKeyUsagePurpose::ClientAuth)
        {
            return Err(PkiError::MissingClientAuth);
        }
        let mut params = request.params;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(
            DnType::CommonName,
            format!("ferrocrate/{cluster_id}/{node_id}"),
        );
        params.is_ca = IsCa::NoCa;
        let request = CertificateSigningRequestParams {
            params,
            public_key: request.public_key,
        };
        let certificate = if self.loaded {
            let issuer = Issuer::from_ca_cert_pem(&self.certificate_pem, &self.key)?;
            request.signed_by(&issuer)?
        } else {
            let issuer = Issuer::from_params(&self.params, &self.key);
            request.signed_by(&issuer)?
        };
        Ok(certificate.pem())
    }

    fn issue(
        &self,
        cluster_id: &str,
        subject: &str,
        role: CertificateRole,
    ) -> Result<IssuedCertificate, PkiError> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(
            DnType::CommonName,
            format!("ferrocrate/{cluster_id}/{subject}"),
        );
        params.is_ca = IsCa::NoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key = KeyPair::generate()?;
        let certificate = if self.loaded {
            let issuer = Issuer::from_ca_cert_pem(&self.certificate_pem, &self.key)?;
            params.signed_by(&key, &issuer)?
        } else {
            let issuer = Issuer::from_params(&self.params, &self.key);
            params.signed_by(&key, &issuer)?
        };
        Ok(IssuedCertificate {
            certificate_pem: certificate.pem(),
            private_key_pem: key.serialize_pem(),
            role,
        })
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

pub fn certificate_identity_from_der(der: &[u8]) -> Result<CertificateIdentity, PkiError> {
    use x509_parser::prelude::FromDer as _;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|_| PkiError::InvalidPem)?;
    let principal = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .ok_or(PkiError::InvalidPrincipal)?;
    let mut parts = principal.split('/');
    if parts.next() != Some("ferrocrate") {
        return Err(PkiError::InvalidPrincipal);
    }
    let cluster_id = parts.next().filter(|value| !value.is_empty());
    let subject = parts.next().filter(|value| !value.is_empty());
    if parts.next().is_some() {
        return Err(PkiError::InvalidPrincipal);
    }
    let (cluster_id, subject) = cluster_id.zip(subject).ok_or(PkiError::InvalidPrincipal)?;
    let role = if subject == "administrator" {
        CertificateRole::Administrator
    } else {
        CertificateRole::Node {
            node_id: subject.to_string(),
        }
    };
    Ok(CertificateIdentity {
        cluster_id: cluster_id.to_string(),
        role,
        expires_at: certificate.validity().not_after.timestamp(),
    })
}
