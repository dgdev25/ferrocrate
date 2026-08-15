use crate::config::{MAX_MESSAGE_BYTES, MAX_PENDING_REVISIONS, MAX_QUEUED_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    pub max_pending_revisions: usize,
    pub max_queued_bytes: usize,
    pub max_message_bytes: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_pending_revisions: MAX_PENDING_REVISIONS,
            max_queued_bytes: MAX_QUEUED_BYTES,
            max_message_bytes: MAX_MESSAGE_BYTES,
        }
    }
}
