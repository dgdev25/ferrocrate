use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateRole {
    Node { node_id: String },
    Administrator,
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
