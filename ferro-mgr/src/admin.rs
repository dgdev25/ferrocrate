use thiserror::Error;

use crate::pki::{unix_now, CertificateIdentity, CertificateRole};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminIdentity {
    pub cluster_id: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("certificate is expired or for another cluster")]
    InvalidCertificate,
    #[error("node certificates cannot access the administrator listener")]
    WrongRole,
    #[error("administrator certificate is not authorized for this method")]
    MethodDenied,
}

pub struct AdminAuthorizer {
    cluster_id: String,
}

impl AdminAuthorizer {
    pub fn new(cluster_id: impl Into<String>) -> Self {
        Self {
            cluster_id: cluster_id.into(),
        }
    }

    pub fn authorize(
        &self,
        certificate: &CertificateIdentity,
        method: &str,
    ) -> Result<AdminIdentity, AuthError> {
        if !certificate.is_valid_for(&self.cluster_id, unix_now()) {
            return Err(AuthError::InvalidCertificate);
        }
        if !matches!(certificate.role, CertificateRole::Administrator) {
            return Err(AuthError::WrongRole);
        }
        if !(method.starts_with("Inspect")
            || method.starts_with("IssueToken")
            || method.starts_with("Revoke")
            || method == "PublishDesired")
        {
            return Err(AuthError::MethodDenied);
        }
        Ok(AdminIdentity {
            cluster_id: self.cluster_id.clone(),
        })
    }

    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }
}
