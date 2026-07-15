use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use thiserror::Error;

use crate::{pki::unix_now, store::{Enrollment, ManagerStore, ScopedToken, StoreError}};

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("enrollment token is malformed")]
    MalformedToken,
    #[error("enrollment token generation failed")]
    Entropy,
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub struct EnrollmentService {
    cluster_id: String,
    store: Arc<ManagerStore>,
}

impl EnrollmentService {
    pub fn new(cluster_id: impl Into<String>, store: Arc<ManagerStore>) -> Self {
        Self { cluster_id: cluster_id.into(), store }
    }

    pub fn create_scoped_token(&self, expected_node: String, endpoint: String, overlay_scope: String, expires_at: i64) -> Result<String, EnrollmentError> {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| EnrollmentError::Entropy)?;
        let token = self.store.create_token(ScopedToken { secret, expected_node, approved_endpoint: endpoint, overlay_scope, expires_at })?;
        Ok(URL_SAFE_NO_PAD.encode(token.secret))
    }

    pub fn enroll(&self, token: &str, enrollment: Enrollment) -> Result<(), EnrollmentError> {
        let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_| EnrollmentError::MalformedToken)?;
        let secret: [u8; 32] = bytes.try_into().map_err(|_| EnrollmentError::MalformedToken)?;
        self.store.register_node_with_token(&secret, enrollment, unix_now())?;
        Ok(())
    }

    pub fn cluster_id(&self) -> &str { &self.cluster_id }
}
