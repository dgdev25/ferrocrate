use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedOverlayRef(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManagedOverlayError {
    #[error("managed overlay reference must use managed:<overlay-id>")]
    InvalidReference,
    #[error("managed overlay id is empty")]
    EmptyId,
}

impl ManagedOverlayRef {
    pub fn parse(value: &str) -> Result<Self, ManagedOverlayError> {
        let id = value.strip_prefix("managed:").ok_or(ManagedOverlayError::InvalidReference)?;
        if id.is_empty() || id.len() > 15 || !id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') {
            return Err(ManagedOverlayError::EmptyId);
        }
        Ok(Self(id.to_string()))
    }

    pub fn id(&self) -> &str { &self.0 }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedOverlayAttachment {
    pub overlay_id: String,
    pub container_id: String,
    pub bridge: String,
    pub netns: String,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub gateway: String,
    pub mtu: u16,
}

#[cfg(test)]
mod tests {
    use super::{ManagedOverlayError, ManagedOverlayRef};

    #[test]
    fn parses_strict_managed_overlay_reference() {
        assert_eq!(ManagedOverlayRef::parse("managed:prod").unwrap().id(), "prod");
        assert_eq!(ManagedOverlayRef::parse("bridge"), Err(ManagedOverlayError::InvalidReference));
        assert_eq!(ManagedOverlayRef::parse("managed:"), Err(ManagedOverlayError::EmptyId));
        assert_eq!(ManagedOverlayRef::parse("managed/unsafe"), Err(ManagedOverlayError::InvalidReference));
    }
}
