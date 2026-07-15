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
