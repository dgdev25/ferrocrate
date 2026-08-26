#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedToken {
    pub secret: [u8; 32],
    pub expected_node: String,
    pub approved_endpoint: String,
    pub overlay_scope: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub secret: [u8; 32],
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub node_id: String,
    pub public_key: Vec<u8>,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlay {
    pub id: String,
    pub cidr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostObservation {
    pub node_id: String,
    pub last_seen_unix: i64,
    pub version: String,
    pub health: String,
    pub doctor_summary: String,
    pub containers_json: String,
    pub acknowledged_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRecord {
    pub node_id: String,
    pub endpoint: String,
    pub enrollment_state: String,
    pub revocation_reason: Option<String>,
    pub last_seen_unix: Option<i64>,
    pub version: Option<String>,
    pub health: Option<String>,
    pub doctor_summary: Option<String>,
    pub containers_json: String,
    pub acknowledged_revision: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetDeployment {
    pub deployment_id: String,
    pub revision: u64,
    pub name: String,
    pub image: String,
    pub command_json: String,
    pub node_ids_json: String,
    pub previous_deployment_id: Option<String>,
    pub status: String,
    pub progress_json: String,
    pub created_at: i64,
    pub rolled_back_at: Option<i64>,
}
