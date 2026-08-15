use thiserror::Error;

pub const MAX_NODES: u16 = 256;
pub const MAX_OVERLAYS: u16 = 256;
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_PENDING_REVISIONS: usize = 64;
pub const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerLimits {
    pub max_nodes: u16,
    pub max_overlays: u16,
    pub max_message_bytes: usize,
    pub max_pending_revisions: usize,
    pub max_queued_bytes: usize,
}

impl Default for ManagerLimits {
    fn default() -> Self {
        Self {
            max_nodes: MAX_NODES,
            max_overlays: MAX_OVERLAYS,
            max_message_bytes: MAX_MESSAGE_BYTES,
            max_pending_revisions: MAX_PENDING_REVISIONS,
            max_queued_bytes: MAX_QUEUED_BYTES,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("configured {field} exceeds its compiled safety maximum")]
    Limit { field: &'static str },
}

impl ManagerLimits {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_nodes > MAX_NODES {
            return Err(ConfigError::Limit { field: "max_nodes" });
        }
        if self.max_overlays > MAX_OVERLAYS {
            return Err(ConfigError::Limit {
                field: "max_overlays",
            });
        }
        if self.max_message_bytes > MAX_MESSAGE_BYTES {
            return Err(ConfigError::Limit {
                field: "max_message_bytes",
            });
        }
        if self.max_pending_revisions > MAX_PENDING_REVISIONS {
            return Err(ConfigError::Limit {
                field: "max_pending_revisions",
            });
        }
        if self.max_queued_bytes > MAX_QUEUED_BYTES {
            return Err(ConfigError::Limit {
                field: "max_queued_bytes",
            });
        }
        Ok(())
    }
}
